//! A protocol-agnostic [`ApplicationOverQuic`] that turns the sans-IO quiche
//! worker loop into the handle-based async [`QuicConnection`] surface.
//!
//! This generalizes `wind-tuiche`'s `TuicheDriver`: instead of decoding TUIC
//! inside the worker, it exposes *raw* QUIC streams and datagrams through
//! channels. A [`QuicheConnection`](crate::quiche::conn::QuicheConnection)
//! handle talks to this driver over a command channel and per-stream byte
//! channels, so all protocol logic lives above the abstraction.
//!
//! ## Model
//!
//! tokio-quiche runs one worker task per connection and calls our methods
//! synchronously with `&mut quiche::Connection`:
//!
//! * [`process_reads`] drains readable streams / datagrams into per-stream
//!   inbound channels (and surfaces peer-initiated streams to the accept
//!   queues).
//! * [`process_writes`] flushes queued opens, datagrams, stream data + FINs,
//!   stream shutdowns, keying-material exports, and connection close.
//! * [`wait_for_data`] parks until a handle sends a command or a stream's
//!   outbound back-channel produces data.
//!
//! [`process_reads`]: ApplicationOverQuic::process_reads
//! [`process_writes`]: ApplicationOverQuic::process_writes
//! [`wait_for_data`]: ApplicationOverQuic::wait_for_data
//! [`QuicConnection`]: crate::traits::QuicConnection

use std::{
	collections::{HashMap, VecDeque},
	future::Future,
	net::SocketAddr,
	pin::Pin,
	sync::{
		Arc,
		atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
	},
	task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::sync::{mpsc, mpsc::error::TrySendError, oneshot};
use tokio_quiche::{
	ApplicationOverQuic, QuicResult,
	metrics::Metrics,
	quic::{HandshakeInfo, QuicheConnection},
	quiche::{self, Shutdown},
};
use tokio_util::sync::CancellationToken;
use tracing::{Span, debug, trace, warn};

use crate::quiche::{
	conn::QuicheConnection as Handle,
	stream::{QuicheRecv, QuicheSend},
};

/// Per-stream byte-channel capacity (chunks).
pub(crate) const STREAM_CHAN_CAP: usize = 64;
/// Worker scratch buffer size.
const READ_BUF_SIZE: usize = 64 * 1024;
/// Soft cap on buffered inbound bytes per stream before we stop draining the
/// QUIC stream (lets flow control back-pressure the peer).
const MAX_PENDING_IN: usize = 256 * 1024;
/// Soft cap on buffered *outbound* bytes per stream. Once `out_queue` reaches
/// this, the driver stops draining the handle's send back-channel until
/// `write_stream` flushes below the cap — so a slow/flow-controlled peer
/// back-pressures the local writer instead of letting `out_queue` grow without
/// bound (previously a single slow peer could OOM the process).
const MAX_PENDING_OUT: usize = 256 * 1024;
/// Hard cap on queued outbound datagrams. Datagrams are unreliable, so the
/// oldest are dropped past this — bounding memory when the app queues faster
/// than the peer drains (the command channel itself is unbounded).
const MAX_OUT_DATAGRAMS: usize = 2048;
/// Hard cap on queued *inbound* datagrams, the mirror of
/// [`MAX_OUT_DATAGRAMS`]: the handle's receive channel is bounded and the
/// driver drops the datagram that would grow it past this. The peer controls
/// how many datagrams it sends, so without a cap a local application that
/// stops calling `read_datagram` (e.g. a busy UDP relay) would let this queue
/// grow for as long as the peer keeps sending.
const MAX_IN_DATAGRAMS: usize = 2048;

/// An item delivered on a stream's inbound channel: either a chunk of peer
/// data, or `Err(code)` signaling the peer reset the stream (RESET_STREAM) so
/// the receiver can surface an error instead of a clean EOF. A clean FIN is
/// still signaled by the sender being dropped (channel closed).
pub(crate) type InboundItem = Result<Bytes, u64>;

/// Command channel sender from a handle to its driver.
pub(crate) type CmdTx = mpsc::UnboundedSender<DriverCommand>;
type AcceptBiTx = mpsc::UnboundedSender<(QuicheSend, QuicheRecv)>;
type AcceptUniTx = mpsc::UnboundedSender<QuicheRecv>;
type DgramInTx = mpsc::Sender<Bytes>;
/// A queued keying-material export request: `(out_len, label, context, reply)`.
type ExportReq = (usize, Vec<u8>, Vec<u8>, oneshot::Sender<Option<Vec<u8>>>);

/// A command issued by a [`QuicheConnection`](Handle) handle, executed by the
/// worker where it has `&mut quiche::Connection` access.
pub(crate) enum DriverCommand {
	/// Open a local bidirectional stream; reply with its halves.
	OpenBi(oneshot::Sender<(QuicheSend, QuicheRecv)>),
	/// Open a local unidirectional (send-only) stream; reply with its send
	/// half.
	OpenUni(oneshot::Sender<QuicheSend>),
	/// Queue a datagram for sending.
	SendDatagram(Bytes),
	/// Export keying material (RFC 5705).
	Export {
		out_len: usize,
		label: Vec<u8>,
		context: Vec<u8>,
		reply: oneshot::Sender<Option<Vec<u8>>>,
	},
	/// Read the current TLS resumption session (may be `None` until the
	/// server's NewSessionTicket has arrived and been processed).
	Session(oneshot::Sender<Option<Vec<u8>>>),
	/// Shut down one direction of a stream with an error code.
	StreamShutdown { sid: u64, write: bool, code: u64 },
	/// Close the connection.
	Close { code: u32, reason: Vec<u8> },
	/// Wake the worker so it re-flushes a stream's buffered inbound bytes after
	/// the handle drained its recv channel. Without this, buffered inbound
	/// data (and the FIN that follows it) could stall until some unrelated
	/// event happened to wake the worker — e.g. on a pure-upload stream with
	/// no reverse traffic.
	FlushInbound(u64),
}

/// State shared between a driver and its handle(s).
pub(crate) struct Shared {
	/// Max writable datagram length (0 == datagrams unavailable).
	pub max_dgram: AtomicUsize,
	/// Latched only after both final traffic counters have been published.
	pub closed: CancellationToken,
	/// Cumulative wire bytes the local endpoint has sent (server→client =
	/// download). Refreshed each worker pass and finalized in `on_conn_close`,
	/// so handles can read it without a driver round-trip and the final count
	/// survives connection close.
	pub sent_bytes: AtomicU64,
	/// Cumulative wire bytes received from the peer (client→server = upload).
	/// See [`sent_bytes`](Self::sent_bytes).
	pub recv_bytes: AtomicU64,
	/// BoringSSL `SSL_early_data_reason` captured once the handshake completes
	/// (0 = not sent, 1 = rejected, 2 = accepted, ...). See
	/// [`quiche::Connection::early_data_reason`].
	pub early_data_reason: AtomicU32,
	/// Cumulative inbound datagrams dropped because the bounded receive queue
	/// was full. Peer-driven, so this counts loss the application never asked
	/// for; exposed so the drop is observable instead of silent.
	pub dropped_in_datagrams: AtomicU64,
}

/// A pending terminal event follows all queued bytes. A reset takes precedence
/// over EOF until its code has been delivered to the reader.
#[derive(Clone, Copy)]
enum ReceivePhase {
	Open,
	FinPending,
	ResetPending(u64),
}

struct ReceiveHalf {
	tx: mpsc::Sender<InboundItem>,
	phase: ReceivePhase,
	pending: VecDeque<Bytes>,
	pending_len: usize,
}

impl ReceiveHalf {
	fn observe_fin(&mut self) {
		if matches!(self.phase, ReceivePhase::Open) {
			self.phase = ReceivePhase::FinPending;
		}
	}

	fn deliver_end(&self) -> bool {
		match self.phase {
			ReceivePhase::Open => false,
			ReceivePhase::FinPending => true,
			ReceivePhase::ResetPending(code) => !matches!(self.tx.try_send(Err(code)), Err(TrySendError::Full(_))),
		}
	}
}

#[derive(Debug)]
enum SendPhase {
	Absent,
	/// At the queue limit the driver parks the back-channel here until space is
	/// available.
	Open {
		parked: Option<mpsc::Receiver<Bytes>>,
	},
	Draining,
	Finished,
	/// A data write failed. The driver still attempts a best-effort FIN
	/// while the receive half lives, but the writer is already terminal.
	FailedPendingFin,
	Failed,
}

impl SendPhase {
	fn open() -> Self {
		Self::Open { parked: None }
	}

	fn writer_closed(&mut self) {
		if matches!(self, Self::Open { .. }) {
			*self = Self::Draining;
		}
	}

	fn needs_fin(&self) -> bool {
		matches!(self, Self::Draining | Self::FailedPendingFin)
	}

	fn finish_attempted(&mut self) {
		match self {
			Self::Draining => *self = Self::Finished,
			Self::FailedPendingFin => *self = Self::Failed,
			_ => {}
		}
	}

	fn is_terminal(&self) -> bool {
		matches!(self, Self::Absent | Self::Failed | Self::FailedPendingFin | Self::Finished)
	}
}

/// Per-stream bridge state held by the driver.
struct StreamIo {
	/// Driver → handle (peer's data). `None` once EOF/reset has been delivered.
	recv: Option<ReceiveHalf>,
	/// Handle → driver data awaiting `stream_send`.
	out_queue: VecDeque<Bytes>,
	/// Total bytes currently buffered in `out_queue` (for the outbound cap).
	out_queue_len: usize,
	send: SendPhase,
}

impl StreamIo {
	fn new(inbound_tx: Option<mpsc::Sender<InboundItem>>, send: SendPhase) -> Self {
		Self {
			recv: inbound_tx.map(|tx| ReceiveHalf {
				tx,
				phase: ReceivePhase::Open,
				pending: VecDeque::new(),
				pending_len: 0,
			}),
			out_queue: VecDeque::new(),
			out_queue_len: 0,
			send,
		}
	}
}

/// A pending local stream open awaiting the worker.
enum PendingOpen {
	Bi(oneshot::Sender<(QuicheSend, QuicheRecv)>),
	Uni(oneshot::Sender<QuicheSend>),
}

/// Future that resolves when a stream's outbound back-channel yields a chunk
/// (or closes), returning the receiver so the driver can re-arm it. Modeled on
/// `wind-tuiche`'s `WaitTcpBack`.
struct WaitOut {
	sid: u64,
	rx: Option<mpsc::Receiver<Bytes>>,
}

impl WaitOut {
	fn new(sid: u64, rx: mpsc::Receiver<Bytes>) -> Self {
		Self { sid, rx: Some(rx) }
	}
}

impl Future for WaitOut {
	type Output = (u64, Option<Bytes>, mpsc::Receiver<Bytes>);

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let sid = self.sid;
		let rx = self.rx.as_mut().expect("WaitOut polled after completion");
		match rx.poll_recv(cx) {
			Poll::Ready(data) => {
				let rx = self.rx.take().unwrap();
				Poll::Ready((sid, data, rx))
			}
			Poll::Pending => Poll::Pending,
		}
	}
}

enum HandshakeState {
	Negotiating { ready: oneshot::Sender<Handle>, handle: Handle },
	Established,
}

/// The protocol-agnostic quiche driver.
pub(crate) struct BridgeDriver {
	pub(crate) require_ech: bool,
	is_server: bool,
	span: Span,
	handshake: HandshakeState,
	buffer: Vec<u8>,

	streams: HashMap<u64, StreamIo>,
	waiters: FuturesUnordered<WaitOut>,
	next_bi: u64,
	next_uni: u64,

	cmd_rx: mpsc::UnboundedReceiver<DriverCommand>,
	cmd_tx_handles: CmdTx,
	accept_bi_tx: AcceptBiTx,
	accept_uni_tx: AcceptUniTx,
	dgram_in_tx: DgramInTx,

	out_datagrams: VecDeque<Bytes>,
	/// Whether an unsendable datagram has already been reported at `warn` for
	/// this connection (subsequent drops stay at `trace` to avoid log spam).
	dgram_drop_warned: bool,
	/// Same, for inbound datagrams dropped by the receive-queue cap.
	dgram_in_drop_warned: bool,
	pending_opens: VecDeque<PendingOpen>,
	pending_exports: VecDeque<ExportReq>,
	pending_sessions: VecDeque<oneshot::Sender<Option<Vec<u8>>>>,
	pending_shutdowns: VecDeque<(u64, bool, u64)>,
	pending_close: Option<(u32, Vec<u8>)>,

	shared: Arc<Shared>,
}

impl BridgeDriver {
	/// Build a driver and the receiver that yields the connection handle once
	/// the handshake completes.
	pub(crate) fn new(is_server: bool, peer_addr: SocketAddr, span: Span) -> (Self, oneshot::Receiver<Handle>) {
		let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
		let (accept_bi_tx, accept_bi_rx) = mpsc::unbounded_channel();
		let (accept_uni_tx, accept_uni_rx) = mpsc::unbounded_channel();
		let (dgram_in_tx, dgram_in_rx) = mpsc::channel(MAX_IN_DATAGRAMS);
		let shared = Arc::new(Shared {
			max_dgram: AtomicUsize::new(0),
			closed: CancellationToken::new(),
			sent_bytes: AtomicU64::new(0),
			recv_bytes: AtomicU64::new(0),
			early_data_reason: AtomicU32::new(0),
			dropped_in_datagrams: AtomicU64::new(0),
		});
		let handle = Handle::new(
			cmd_tx.clone(),
			accept_bi_rx,
			accept_uni_rx,
			dgram_in_rx,
			shared.clone(),
			peer_addr,
		);
		let (est_tx, est_rx) = oneshot::channel();
		let driver = Self {
			require_ech: false,
			is_server,
			span,
			handshake: HandshakeState::Negotiating { ready: est_tx, handle },
			buffer: vec![0u8; READ_BUF_SIZE],
			streams: HashMap::new(),
			waiters: FuturesUnordered::new(),
			next_bi: 0,
			next_uni: 0,
			cmd_rx,
			cmd_tx_handles: cmd_tx,
			accept_bi_tx,
			accept_uni_tx,
			dgram_in_tx,
			out_datagrams: VecDeque::new(),
			dgram_drop_warned: false,
			dgram_in_drop_warned: false,
			pending_opens: VecDeque::new(),
			pending_exports: VecDeque::new(),
			pending_sessions: VecDeque::new(),
			pending_shutdowns: VecDeque::new(),
			pending_close: None,
			shared,
		};
		(driver, est_rx)
	}

	/// Allocate the next locally-initiated stream id of the given
	/// directionality.
	///
	/// QUIC stream ids encode the initiator in bit 0 (0 = client, 1 = server)
	/// and directionality in bit 1 (0 = bidi, 1 = uni); the sequence number
	/// occupies the upper bits.
	fn alloc_id(&mut self, uni: bool) -> u64 {
		let init = if self.is_server { 1 } else { 0 };
		let dir = if uni { 2 } else { 0 };
		let seq = if uni {
			let s = self.next_uni;
			self.next_uni += 1;
			s
		} else {
			let s = self.next_bi;
			self.next_bi += 1;
			s
		};
		(seq << 2) | dir | init
	}

	fn is_peer_initiated(&self, sid: u64) -> bool {
		let init = if self.is_server { 1 } else { 0 };
		(sid & 1) != init
	}

	/// Queue one inbound datagram for the handle.
	///
	/// The receive channel is bounded ([`MAX_IN_DATAGRAMS`]), so the datagram
	/// that would grow it past the cap is dropped. Previously the channel was
	/// unbounded *and* [`process_reads`](ApplicationOverQuic::process_reads)
	/// drained every queued datagram into it, so a handle that stopped reading
	/// let peer-driven memory grow without bound. Datagrams are unreliable, so
	/// dropping is the accepted loss mode (the outbound queue drops its oldest
	/// past [`MAX_OUT_DATAGRAMS`] for the same reason); the counter keeps the
	/// loss observable.
	///
	/// Returns `false` when the datagram was dropped because the queue was
	/// full, so the caller can stop draining.
	fn accept_datagram(&mut self, data: Bytes) -> bool {
		match self.dgram_in_tx.try_send(data) {
			Ok(()) => true,
			Err(TrySendError::Full(_)) => {
				self.shared.dropped_in_datagrams.fetch_add(1, Ordering::Relaxed);
				if self.dgram_in_drop_warned {
					trace!("dropping inbound QUIC datagram: receive queue full");
				} else {
					self.dgram_in_drop_warned = true;
					warn!("dropping inbound QUIC datagrams: receive queue full; further drops at trace level");
				}
				false
			}
			// The handle is gone (connection teardown); nothing to deliver to.
			Err(TrySendError::Closed(_)) => false,
		}
	}

	fn open_local_bi(&mut self) -> (QuicheSend, QuicheRecv) {
		let sid = self.alloc_id(false);
		let (in_tx, in_rx) = mpsc::channel(STREAM_CHAN_CAP);
		let (out_tx, out_rx) = mpsc::channel(STREAM_CHAN_CAP);
		self.streams.insert(sid, StreamIo::new(Some(in_tx), SendPhase::open()));
		self.waiters.push(WaitOut::new(sid, out_rx));
		(
			QuicheSend::new(sid, self.cmd_tx_handles.clone(), out_tx),
			QuicheRecv::new(sid, self.cmd_tx_handles.clone(), in_rx),
		)
	}

	fn open_local_uni(&mut self) -> QuicheSend {
		let sid = self.alloc_id(true);
		let (out_tx, out_rx) = mpsc::channel(STREAM_CHAN_CAP);
		// Send-only: no inbound channel.
		self.streams.insert(sid, StreamIo::new(None, SendPhase::open()));
		self.waiters.push(WaitOut::new(sid, out_rx));
		QuicheSend::new(sid, self.cmd_tx_handles.clone(), out_tx)
	}

	/// Register a newly-observed peer-initiated stream and surface it to the
	/// matching accept queue.
	fn ensure_incoming(&mut self, sid: u64) {
		if self.streams.contains_key(&sid) {
			return;
		}
		let uni = sid & 2 != 0;
		let (in_tx, in_rx) = mpsc::channel(STREAM_CHAN_CAP);
		if uni {
			self.streams.insert(sid, StreamIo::new(Some(in_tx), SendPhase::Absent));
			let recv = QuicheRecv::new(sid, self.cmd_tx_handles.clone(), in_rx);
			let _ = self.accept_uni_tx.send(recv);
		} else {
			let (out_tx, out_rx) = mpsc::channel(STREAM_CHAN_CAP);
			self.streams.insert(sid, StreamIo::new(Some(in_tx), SendPhase::open()));
			self.waiters.push(WaitOut::new(sid, out_rx));
			let send = QuicheSend::new(sid, self.cmd_tx_handles.clone(), out_tx);
			let recv = QuicheRecv::new(sid, self.cmd_tx_handles.clone(), in_rx);
			let _ = self.accept_bi_tx.send((send, recv));
		}
	}

	fn read_stream(&mut self, qconn: &mut QuicheConnection, sid: u64) {
		loop {
			let over_cap = self
				.streams
				.get(&sid)
				.map(|st| st.recv.as_ref().is_some_and(|recv| recv.pending_len >= MAX_PENDING_IN))
				.unwrap_or(true);
			if over_cap {
				break;
			}
			match qconn.stream_recv(sid, &mut self.buffer) {
				Ok((n, fin)) => {
					if let Some(recv) = self.streams.get_mut(&sid).and_then(|st| st.recv.as_mut()) {
						if n > 0 {
							recv.pending.push_back(Bytes::copy_from_slice(&self.buffer[..n]));
							recv.pending_len += n;
						}
						if fin {
							recv.observe_fin();
						}
					}
					if fin {
						break;
					}
				}
				Err(quiche::Error::Done) => break,
				Err(quiche::Error::StreamReset(code)) => {
					// The peer aborted the stream. Record the code so the
					// handle sees an error after any already-buffered
					// bytes drain, rather than a clean EOF that would make
					// a truncated stream look complete.
					trace!(stream = sid, code, "stream reset by peer");
					if let Some(recv) = self.streams.get_mut(&sid).and_then(|st| st.recv.as_mut()) {
						recv.phase = ReceivePhase::ResetPending(code);
					}
					break;
				}
				Err(e) => {
					trace!(stream = sid, "stream_recv error: {e}");
					if let Some(recv) = self.streams.get_mut(&sid).and_then(|st| st.recv.as_mut()) {
						recv.observe_fin();
					}
					break;
				}
			}
		}
		self.flush_inbound(sid);
	}

	/// Move buffered inbound bytes into the handle's recv channel; drop the
	/// sender on EOF.
	fn flush_inbound(&mut self, sid: u64) {
		if let Some(st) = self.streams.get_mut(&sid)
			&& let Some(recv) = &mut st.recv
		{
			while let Some(chunk) = recv.pending.pop_front() {
				match recv.tx.try_reserve() {
					Ok(slot) => {
						recv.pending_len -= chunk.len();
						slot.send(Ok(chunk));
					}
					Err(TrySendError::Full(())) => {
						recv.pending.push_front(chunk);
						break;
					}
					Err(TrySendError::Closed(())) => {
						recv.pending.clear();
						recv.pending_len = 0;
						break;
					}
				}
			}
			if recv.pending.is_empty() && recv.deliver_end() {
				st.recv = None;
			}
		}
		self.maybe_cleanup(sid);
	}

	fn write_stream(&mut self, qconn: &mut QuicheConnection, sid: u64) {
		let mut rearm: Option<mpsc::Receiver<Bytes>> = None;
		if let Some(st) = self.streams.get_mut(&sid)
			&& !matches!(st.send, SendPhase::Absent)
		{
			while let Some(front) = st.out_queue.front_mut() {
				if front.is_empty() {
					st.out_queue.pop_front();
					continue;
				}
				match qconn.stream_send(sid, front.as_ref(), false) {
					Ok(0) => break,
					Ok(n) => {
						front.advance(n);
						st.out_queue_len -= n;
						if front.is_empty() {
							st.out_queue.pop_front();
						}
					}
					Err(quiche::Error::Done) => break,
					Err(e) => {
						// The peer refused our send half (STOP_SENDING) or the
						// stream is otherwise unwritable. Drop the queued
						// data and mark the send side failed so the
						// back-channel is closed rather than re-armed —
						// the local writer's next `poll_write` then fails
						// instead of silently succeeding into a black hole.
						debug!(stream = sid, "stream_send error: {e}");
						st.out_queue.clear();
						st.out_queue_len = 0;
						st.send = SendPhase::FailedPendingFin;
						break;
					}
				}
			}
			if st.send.needs_fin() && st.out_queue.is_empty() {
				match qconn.stream_send(sid, b"", true) {
					Ok(_) => st.send.finish_attempted(),
					Err(quiche::Error::Done) => {}
					Err(e) => {
						debug!(stream = sid, "stream_send fin error: {e}");
						st.send.finish_attempted();
					}
				}
			}
			// Resume draining the handle's back-channel now that we're back
			// under the outbound cap (see `MAX_PENDING_OUT`).
			if st.out_queue_len < MAX_PENDING_OUT
				&& let SendPhase::Open { parked } = &mut st.send
			{
				rearm = parked.take();
			}
		}
		if let Some(rx) = rearm {
			self.waiters.push(WaitOut::new(sid, rx));
		}
		self.maybe_cleanup(sid);
	}

	fn maybe_cleanup(&mut self, sid: u64) {
		let done = if let Some(st) = self.streams.get(&sid) {
			let recv_done = st.recv.is_none();
			let send_done = st.send.is_terminal();
			recv_done && send_done
		} else {
			false
		};
		if done {
			self.streams.remove(&sid);
		}
	}

	fn handle_cmd(&mut self, cmd: DriverCommand) {
		match cmd {
			DriverCommand::OpenBi(reply) => self.pending_opens.push_back(PendingOpen::Bi(reply)),
			DriverCommand::OpenUni(reply) => self.pending_opens.push_back(PendingOpen::Uni(reply)),
			DriverCommand::SendDatagram(b) => {
				self.out_datagrams.push_back(b);
				// Bound queued datagrams: drop the oldest past the cap
				// (datagrams are unreliable, and the command channel is
				// unbounded).
				while self.out_datagrams.len() > MAX_OUT_DATAGRAMS {
					self.out_datagrams.pop_front();
				}
			}
			// The wake itself is the work: `process_writes` re-flushes every
			// stream's pending bytes right after `wait_for_data` returns.
			DriverCommand::FlushInbound(_sid) => {}
			DriverCommand::Session(reply) => self.pending_sessions.push_back(reply),
			DriverCommand::Export {
				out_len,
				label,
				context,
				reply,
			} => self.pending_exports.push_back((out_len, label, context, reply)),
			DriverCommand::StreamShutdown { sid, write, code } => self.pending_shutdowns.push_back((sid, write, code)),
			DriverCommand::Close { code, reason } => self.pending_close = Some((code, reason)),
		}
	}
}

/// Recompute keying material (RFC 5705) from the live BoringSSL session.
///
/// quiche exposes the underlying `boring::ssl::SslRef` via `impl AsMut<SslRef>
/// for Connection` (tokio-quiche enables `boringssl-boring-crate`). We call the
/// BoringSSL FFI directly because the safe wrapper takes the label as `&str`,
/// while callers may use raw (non-UTF-8) label bytes.
fn export_keying_material(qconn: &mut QuicheConnection, out_len: usize, label: &[u8], context: &[u8]) -> Option<Vec<u8>> {
	use foreign_types_shared::ForeignTypeRef as _;

	let ssl: &mut boring::ssl::SslRef = qconn.as_mut();
	let mut out = vec![0u8; out_len];
	let mut scratch = 0u8;
	let out_ptr = export_out_ptr(&mut out, &mut scratch);
	// SAFETY: `ssl.as_ptr()` yields a valid `SSL*` for the borrow; `out_ptr` /
	// `label` / `context` are passed as (ptr, len) of valid slices and
	// BoringSSL does not retain them past the call.
	let rc = unsafe {
		boring_sys::SSL_export_keying_material(
			ssl.as_ptr(),
			out_ptr,
			out.len(),
			label.as_ptr() as *const core::ffi::c_char,
			label.len(),
			context.as_ptr(),
			context.len(),
			1, // use_context = true
		)
	};
	(rc == 1).then_some(out)
}

/// The `out` pointer to hand `SSL_export_keying_material` for an export of
/// `out.len()` bytes.
///
/// BoringSSL takes `out` as a pointer valid for `out_len` bytes. A
/// zero-capacity `Vec` has no allocation, so its `as_mut_ptr` is a dangling —
/// merely non-null — pointer that must not reach the FFI. A zero-length export
/// is backed by `scratch` instead; the exporter writes nothing at that length,
/// so the observable output is unchanged.
fn export_out_ptr(out: &mut [u8], scratch: &mut u8) -> *mut u8 {
	if out.is_empty() {
		core::ptr::from_mut(scratch)
	} else {
		out.as_mut_ptr()
	}
}

impl ApplicationOverQuic for BridgeDriver {
	fn on_conn_established(&mut self, qconn: &mut QuicheConnection, _info: &HandshakeInfo) -> QuicResult<()> {
		// Fail before delivering a handle or permitting any application data.
		// BoringSSL may ignore a list containing only unsupported ECH versions.
		if self.require_ech && !qconn.as_mut().ech_accepted() {
			return Err("ECH was required but was not accepted".into());
		}
		let span = self.span.clone();
		let _enter = span.enter();
		self.shared
			.max_dgram
			.store(qconn.dgram_max_writable_len().unwrap_or(0), Ordering::Relaxed);
		// Capture the early-data verdict now that the handshake has completed
		// (BoringSSL reports whether 0-RTT was accepted/rejected once the
		// handshake settles).
		self.shared
			.early_data_reason
			.store(qconn.early_data_reason(), Ordering::Relaxed);
		debug!(trace = qconn.trace_id(), "wind-quic quiche connection established");
		if let HandshakeState::Negotiating { ready, handle } =
			std::mem::replace(&mut self.handshake, HandshakeState::Established)
		{
			let _ = ready.send(handle);
		}
		Ok(())
	}

	fn should_act(&self) -> bool {
		matches!(self.handshake, HandshakeState::Established)
	}

	async fn wait_for_data(&mut self, _qconn: &mut QuicheConnection) -> QuicResult<()> {
		enum Ev {
			Out((u64, Option<Bytes>, mpsc::Receiver<Bytes>)),
			Cmd(DriverCommand),
		}
		let ev = {
			let waiters = &mut self.waiters;
			let cmd_rx = &mut self.cmd_rx;
			tokio::select! {
				// `biased`: drain commands before out-channel events. A `reset()`
				// enqueues a `StreamShutdown` command and then (on drop) closes the
				// out back-channel; the channel-close would otherwise be observed
				// first and emit a clean FIN that races the RESET. Command-first
				// ordering guarantees the reset is applied before the close.
				biased;
				Some(c) = cmd_rx.recv() => Ev::Cmd(c),
				Some(w) = waiters.next() => Ev::Out(w),
				// Keep the future pending (never resolving) when there is no app
				// event, rather than busy-looping. The worker still processes
				// inbound packets and timers in parallel.
				_ = std::future::pending::<()>() => unreachable!(),
			}
		};
		let span = self.span.clone();
		let _enter = span.enter();
		match ev {
			Ev::Out((sid, data, rx)) => match data {
				Some(b) => {
					// Buffer the chunk; re-arm the back-channel only while
					// under the outbound cap. At/over the cap we park `rx`
					// (stop draining) so the local writer back-pressures;
					// `write_stream` re-arms once the queue drains. If the
					// stream is gone or its send side has failed, drop
					// both `b` and `rx` — dropping `rx` closes the channel
					// so the writer's next `poll_write` fails.
					if let Some(st) = self.streams.get_mut(&sid)
						&& let SendPhase::Open { parked } = &mut st.send
					{
						st.out_queue_len += b.len();
						st.out_queue.push_back(b);
						if st.out_queue_len >= MAX_PENDING_OUT {
							*parked = Some(rx);
						} else {
							self.waiters.push(WaitOut::new(sid, rx));
						}
					}
				}
				None => {
					if let Some(st) = self.streams.get_mut(&sid) {
						st.send.writer_closed();
					}
				}
			},
			Ev::Cmd(cmd) => self.handle_cmd(cmd),
		}
		Ok(())
	}

	fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
		let span = self.span.clone();
		let _enter = span.enter();

		loop {
			match qconn.dgram_recv(&mut self.buffer) {
				Ok(n) => {
					// Bounded queue: the datagram that would overflow it is
					// dropped and the drain stops. Datagrams left unread stay
					// in quiche's own receive queue, so a handle that stops
					// reading no longer lets this path accumulate without
					// bound.
					if !self.accept_datagram(Bytes::copy_from_slice(&self.buffer[..n])) {
						break;
					}
				}
				Err(quiche::Error::Done) => break,
				Err(e) => {
					trace!("dgram_recv error: {e}");
					break;
				}
			}
		}
		self.shared
			.max_dgram
			.store(qconn.dgram_max_writable_len().unwrap_or(0), Ordering::Relaxed);

		let ids: Vec<u64> = qconn.readable().collect();
		for sid in ids {
			if self.is_peer_initiated(sid) {
				self.ensure_incoming(sid);
			}
			if self.streams.contains_key(&sid) {
				self.read_stream(qconn, sid);
			}
		}
		Ok(())
	}

	fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
		let span = self.span.clone();
		let _enter = span.enter();

		// Connection close (terminal — do it first).
		if let Some((code, reason)) = self.pending_close.take() {
			let _ = qconn.close(true, code as u64, &reason);
		}

		while let Some((out_len, label, context, reply)) = self.pending_exports.pop_front() {
			let res = export_keying_material(qconn, out_len, &label, &context);
			let _ = reply.send(res);
		}

		while let Some(reply) = self.pending_sessions.pop_front() {
			let _ = reply.send(qconn.session().map(|s| s.to_vec()));
		}

		// Cache cumulative wire byte counters into `shared` so handles read
		// them without a driver round-trip — and so the final counts survive
		// close.
		let stats = qconn.stats();
		self.shared.sent_bytes.store(stats.sent_bytes, Ordering::Relaxed);
		self.shared.recv_bytes.store(stats.recv_bytes, Ordering::Relaxed);

		while let Some(op) = self.pending_opens.pop_front() {
			match op {
				PendingOpen::Bi(reply) => {
					let pair = self.open_local_bi();
					let _ = reply.send(pair);
				}
				PendingOpen::Uni(reply) => {
					let send = self.open_local_uni();
					let _ = reply.send(send);
				}
			}
		}

		while let Some((sid, write, code)) = self.pending_shutdowns.pop_front() {
			let dir = if write { Shutdown::Write } else { Shutdown::Read };
			let _ = qconn.stream_shutdown(sid, dir, code);
			// A write-direction reset supersedes any pending FIN. Mark the send
			// side finished/failed so `write_stream` doesn't later emit a clean
			// FIN (which would race the RESET and could surface as a clean EOF
			// at the peer).
			if write && let Some(st) = self.streams.get_mut(&sid) {
				st.out_queue.clear();
				st.out_queue_len = 0;
				st.send = SendPhase::Failed;
			}
		}

		while let Some(dg) = self.out_datagrams.front() {
			match qconn.dgram_send(dg.as_ref()) {
				Ok(()) => {
					self.out_datagrams.pop_front();
				}
				Err(quiche::Error::Done) => break,
				Err(e) => {
					// The frame can never be delivered (the peer never
					// advertised DATAGRAM support, or the payload exceeds the
					// negotiated maximum), so drop it — but make the loss
					// visible. Silence here previously hid a total loss of
					// server→client UDP replies; only the first drop per
					// connection is reported at `warn` so a peer that keeps
					// failing cannot spam the log.
					if self.dgram_drop_warned {
						trace!("dgram_send error: {e}");
					} else {
						self.dgram_drop_warned = true;
						warn!("dropping unsendable QUIC datagram ({e}); further drops at trace level");
					}
					self.out_datagrams.pop_front();
				}
			}
		}

		let sids: Vec<u64> = self.streams.keys().copied().collect();
		for sid in &sids {
			self.write_stream(qconn, *sid);
		}
		// Re-flush inbound in case the handle drained its recv channels.
		for sid in &sids {
			self.flush_inbound(*sid);
		}
		Ok(())
	}

	fn on_conn_close<M: Metrics>(&mut self, qconn: &mut QuicheConnection, _metrics: &M, _result: &QuicResult<()>) {
		// Capture the final byte counts *before* waking `closed()` waiters: the
		// traffic sampler's close-path read runs after this worker loop has
		// exited, so this cached snapshot is its only source for the last
		// window.
		let stats = qconn.stats();
		self.shared.sent_bytes.store(stats.sent_bytes, Ordering::Relaxed);
		self.shared.recv_bytes.store(stats.recv_bytes, Ordering::Relaxed);
		self.shared.closed.cancel();
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn reset_waits_for_buffered_bytes_and_channel_capacity() {
		let (mut driver, _ready) = BridgeDriver::new(false, ([127, 0, 0, 1], 9).into(), Span::none());
		let (tx, mut rx) = mpsc::channel(1);
		let mut stream = StreamIo::new(Some(tx), SendPhase::Absent);
		let recv = stream.recv.as_mut().unwrap();
		recv.phase = ReceivePhase::ResetPending(17);
		recv.observe_fin(); // A later EOF cannot erase the reset.
		recv.pending.push_back(Bytes::from_static(b"abc"));
		recv.pending_len = 3;
		driver.streams.insert(2, stream);

		driver.flush_inbound(2);
		assert!(driver.streams.contains_key(&2));
		assert_eq!(rx.try_recv().unwrap(), Ok(Bytes::from_static(b"abc")));
		driver.flush_inbound(2);
		assert_eq!(rx.try_recv().unwrap(), Err(17));
		assert!(!driver.streams.contains_key(&2));
		assert!(matches!(rx.try_recv(), Err(mpsc::error::TryRecvError::Disconnected)));
	}

	#[test]
	fn closing_the_writer_preserves_abort_and_failed_write_semantics() {
		let mut phase = SendPhase::open();
		phase.writer_closed();
		assert!(phase.needs_fin());
		assert!(!phase.is_terminal());
		phase.finish_attempted();
		assert!(matches!(phase, SendPhase::Finished));

		let mut phase = SendPhase::FailedPendingFin;
		phase.writer_closed();
		assert!(phase.needs_fin());
		assert!(phase.is_terminal());
		phase.finish_attempted();
		phase.writer_closed();
		assert!(matches!(phase, SendPhase::Failed));
		assert!(!phase.needs_fin());
	}


	#[test]
	fn a_zero_length_export_does_not_pass_a_dangling_pointer() {
		// A zero-capacity `Vec` has no allocation, so `as_mut_ptr` is a
		// dangling (non-null) pointer; the pre-fix code handed exactly
		// that to `SSL_export_keying_material` whenever the caller
		// exported zero bytes.
		let mut out: Vec<u8> = Vec::new();
		let mut scratch = 0u8;
		let ptr = export_out_ptr(&mut out, &mut scratch);
		assert_eq!(
			ptr,
			core::ptr::from_mut(&mut scratch),
			"a zero-length export must hand BoringSSL a dereferenceable pointer"
		);
		assert_ne!(
			ptr,
			out.as_mut_ptr(),
			"the empty buffer's dangling pointer must never reach the FFI call"
		);
		// The pointer really is writable even though a zero-length export
		// writes nothing into it.
		unsafe { ptr.write(0xA5) };
		assert_eq!(scratch, 0xA5);
	}

	#[test]
	fn a_non_empty_export_still_uses_the_callers_own_buffer() {
		let mut out = [0u8; 32];
		let mut scratch = 0u8;
		assert_eq!(
			export_out_ptr(&mut out, &mut scratch),
			out.as_mut_ptr(),
			"a non-empty export must write into the caller's buffer"
		);
	}
}

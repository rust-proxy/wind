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
		atomic::{AtomicBool, AtomicUsize, Ordering},
	},
	task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::sync::{Notify, mpsc, mpsc::error::TrySendError, oneshot};
use tokio_quiche::{
	ApplicationOverQuic, QuicResult,
	metrics::Metrics,
	quic::{HandshakeInfo, QuicheConnection},
	quiche::{self, Shutdown},
};
use tracing::{Span, debug, trace};

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

/// Command channel sender from a handle to its driver.
pub(crate) type CmdTx = mpsc::UnboundedSender<DriverCommand>;
type AcceptBiTx = mpsc::UnboundedSender<(QuicheSend, QuicheRecv)>;
type AcceptUniTx = mpsc::UnboundedSender<QuicheRecv>;
type DgramInTx = mpsc::UnboundedSender<Bytes>;
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
	/// Shut down one direction of a stream with an error code.
	StreamShutdown { sid: u64, write: bool, code: u64 },
	/// Close the connection.
	Close { code: u32, reason: Vec<u8> },
}

/// State shared between a driver and its handle(s).
pub(crate) struct Shared {
	/// Max writable datagram length (0 == datagrams unavailable).
	pub max_dgram: AtomicUsize,
	/// Set once the connection has closed.
	pub closed: AtomicBool,
	/// Notified when `closed` transitions to true.
	pub closed_notify: Notify,
}

/// Per-stream bridge state held by the driver.
struct StreamIo {
	/// Driver → handle (peer's data). `None` once EOF has been delivered.
	inbound_tx: Option<mpsc::Sender<Bytes>>,
	/// Bytes read from the stream but not yet accepted by `inbound_tx`.
	pending_in: VecDeque<Bytes>,
	pending_in_len: usize,
	/// Peer FIN observed.
	in_fin: bool,
	/// Handle → driver data awaiting `stream_send`.
	out_queue: VecDeque<Bytes>,
	/// Handle closed its send half; emit a FIN once `out_queue` drains.
	out_done: bool,
	fin_sent: bool,
	/// Whether this stream has a local send half (bidi, or locally-opened uni).
	has_send: bool,
}

impl StreamIo {
	fn new(inbound_tx: Option<mpsc::Sender<Bytes>>, has_send: bool) -> Self {
		Self {
			inbound_tx,
			pending_in: VecDeque::new(),
			pending_in_len: 0,
			in_fin: false,
			out_queue: VecDeque::new(),
			out_done: false,
			fin_sent: false,
			has_send,
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

/// The protocol-agnostic quiche driver.
pub(crate) struct BridgeDriver {
	is_server: bool,
	span: Span,
	established: bool,
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
	pending_opens: VecDeque<PendingOpen>,
	pending_exports: VecDeque<ExportReq>,
	pending_shutdowns: VecDeque<(u64, bool, u64)>,
	pending_close: Option<(u32, Vec<u8>)>,

	shared: Arc<Shared>,
	established_tx: Option<oneshot::Sender<Handle>>,
	handle: Option<Handle>,
}

impl BridgeDriver {
	/// Build a driver and the receiver that yields the connection handle once
	/// the handshake completes.
	pub(crate) fn new(is_server: bool, peer_addr: SocketAddr, span: Span) -> (Self, oneshot::Receiver<Handle>) {
		let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
		let (accept_bi_tx, accept_bi_rx) = mpsc::unbounded_channel();
		let (accept_uni_tx, accept_uni_rx) = mpsc::unbounded_channel();
		let (dgram_in_tx, dgram_in_rx) = mpsc::unbounded_channel();
		let shared = Arc::new(Shared {
			max_dgram: AtomicUsize::new(0),
			closed: AtomicBool::new(false),
			closed_notify: Notify::new(),
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
			is_server,
			span,
			established: false,
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
			pending_opens: VecDeque::new(),
			pending_exports: VecDeque::new(),
			pending_shutdowns: VecDeque::new(),
			pending_close: None,
			shared,
			established_tx: Some(est_tx),
			handle: Some(handle),
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

	fn open_local_bi(&mut self) -> (QuicheSend, QuicheRecv) {
		let sid = self.alloc_id(false);
		let (in_tx, in_rx) = mpsc::channel(STREAM_CHAN_CAP);
		let (out_tx, out_rx) = mpsc::channel(STREAM_CHAN_CAP);
		self.streams.insert(sid, StreamIo::new(Some(in_tx), true));
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
		self.streams.insert(sid, StreamIo::new(None, true));
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
			self.streams.insert(sid, StreamIo::new(Some(in_tx), false));
			let recv = QuicheRecv::new(sid, self.cmd_tx_handles.clone(), in_rx);
			let _ = self.accept_uni_tx.send(recv);
		} else {
			let (out_tx, out_rx) = mpsc::channel(STREAM_CHAN_CAP);
			self.streams.insert(sid, StreamIo::new(Some(in_tx), true));
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
				.map(|st| st.pending_in_len >= MAX_PENDING_IN)
				.unwrap_or(true);
			if over_cap {
				break;
			}
			match qconn.stream_recv(sid, &mut self.buffer) {
				Ok((n, fin)) => {
					if let Some(st) = self.streams.get_mut(&sid) {
						if n > 0 && st.inbound_tx.is_some() {
							st.pending_in.push_back(Bytes::copy_from_slice(&self.buffer[..n]));
							st.pending_in_len += n;
						}
						if fin {
							st.in_fin = true;
						}
					}
					if fin {
						break;
					}
				}
				Err(quiche::Error::Done) => break,
				Err(e) => {
					trace!(stream = sid, "stream_recv error: {e}");
					if let Some(st) = self.streams.get_mut(&sid) {
						st.in_fin = true;
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
		if let Some(st) = self.streams.get_mut(&sid) {
			if let Some(tx) = st.inbound_tx.clone() {
				while let Some(front) = st.pending_in.front().cloned() {
					match tx.try_send(front) {
						Ok(()) => {
							let b = st.pending_in.pop_front().unwrap();
							st.pending_in_len -= b.len();
						}
						Err(TrySendError::Full(_)) => break,
						Err(TrySendError::Closed(_)) => {
							st.pending_in.clear();
							st.pending_in_len = 0;
							break;
						}
					}
				}
			}
			if st.in_fin && st.pending_in.is_empty() {
				st.inbound_tx = None;
			}
		}
		self.maybe_cleanup(sid);
	}

	fn write_stream(&mut self, qconn: &mut QuicheConnection, sid: u64) {
		if let Some(st) = self.streams.get_mut(&sid)
			&& st.has_send
		{
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
							if front.is_empty() {
								st.out_queue.pop_front();
							}
						}
						Err(quiche::Error::Done) => break,
						Err(e) => {
							debug!(stream = sid, "stream_send error: {e}");
							st.out_queue.clear();
							st.out_done = true;
							break;
						}
					}
				}
				if st.out_done && st.out_queue.is_empty() && !st.fin_sent {
					match qconn.stream_send(sid, b"", true) {
						Ok(_) => st.fin_sent = true,
						Err(quiche::Error::Done) => {}
						Err(e) => {
							debug!(stream = sid, "stream_send fin error: {e}");
							st.fin_sent = true;
						}
					}
				}
			}
		}
		self.maybe_cleanup(sid);
	}

	fn maybe_cleanup(&mut self, sid: u64) {
		let done = if let Some(st) = self.streams.get(&sid) {
			let recv_done = st.inbound_tx.is_none() && st.pending_in.is_empty();
			let send_done = !st.has_send || (st.out_done && st.out_queue.is_empty() && st.fin_sent);
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
			DriverCommand::SendDatagram(b) => self.out_datagrams.push_back(b),
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
	// SAFETY: `ssl.as_ptr()` yields a valid `SSL*` for the borrow; `out` /
	// `label` / `context` are passed as (ptr, len) of valid slices and
	// BoringSSL does not retain them past the call.
	let rc = unsafe {
		boring_sys::SSL_export_keying_material(
			ssl.as_ptr(),
			out.as_mut_ptr(),
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

impl ApplicationOverQuic for BridgeDriver {
	fn on_conn_established(&mut self, qconn: &mut QuicheConnection, _info: &HandshakeInfo) -> QuicResult<()> {
		let span = self.span.clone();
		let _enter = span.enter();
		self.established = true;
		self.shared
			.max_dgram
			.store(qconn.dgram_max_writable_len().unwrap_or(0), Ordering::Relaxed);
		debug!(trace = qconn.trace_id(), "wind-quic quiche connection established");
		if let (Some(tx), Some(handle)) = (self.established_tx.take(), self.handle.take()) {
			let _ = tx.send(handle);
		}
		Ok(())
	}

	fn should_act(&self) -> bool {
		self.established
	}

	fn buffer(&mut self) -> &mut [u8] {
		&mut self.buffer
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
				Some(w) = waiters.next() => Ev::Out(w),
				Some(c) = cmd_rx.recv() => Ev::Cmd(c),
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
					if let Some(st) = self.streams.get_mut(&sid) {
						st.out_queue.push_back(b);
					}
					self.waiters.push(WaitOut::new(sid, rx));
				}
				None => {
					if let Some(st) = self.streams.get_mut(&sid) {
						st.out_done = true;
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
					let _ = self.dgram_in_tx.send(Bytes::copy_from_slice(&self.buffer[..n]));
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
		}

		while let Some(dg) = self.out_datagrams.front() {
			match qconn.dgram_send(dg.as_ref()) {
				Ok(()) => {
					self.out_datagrams.pop_front();
				}
				Err(quiche::Error::Done) => break,
				Err(e) => {
					trace!("dgram_send error: {e}");
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

	fn on_conn_close<M: Metrics>(&mut self, _qconn: &mut QuicheConnection, _metrics: &M, _result: &QuicResult<()>) {
		self.shared.closed.store(true, Ordering::SeqCst);
		self.shared.closed_notify.notify_waiters();
	}
}

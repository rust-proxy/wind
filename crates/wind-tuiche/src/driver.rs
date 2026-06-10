//! [`ApplicationOverQuic`] implementation that drives the TUIC protocol on top
//! of a single `tokio-quiche` connection.
//!
//! `tokio-quiche` runs one worker task per connection and calls our methods
//! synchronously with `&mut quiche::Connection`. We translate between that
//! sans-IO model and the async `wind-core` relay callbacks using per-stream
//! channels:
//!
//! * **TCP CONNECT** (client bidi streams) → a [`QuicheStream`] handed to
//!   [`InboundCallback::handle_tcpstream`]. The worker pumps client→target
//!   bytes into the stream and drains target→client bytes back out.
//! * **UDP** (datagrams, native relay mode; also `Packet` on uni streams) → a
//!   per-association reassembly task (using the shared
//!   [`tuic_core::udp::FragmentReassemblyBuffer`]) feeding
//!   [`InboundCallback::handle_udpstream`]; responses are re-encoded as TUIC
//!   datagrams.
//! * **Auth / Heartbeat / Dissociate** are handled inline.
//!
//! ## Authentication
//!
//! TUIC authenticates with a token derived from the TLS keying-material
//! exporter (RFC 5705, label = UUID bytes, context = password). We recompute it
//! from the live BoringSSL session and compare in constant time, exactly like
//! the quinn backend. quiche exposes the underlying `boring::ssl::SslRef` via
//! `impl AsMut<SslRef> for Connection` when built with `boringssl-boring-crate`
//! (which tokio-quiche enables); see [`export_keying_material`].

use std::collections::{HashMap, VecDeque};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio_quiche::{
	ApplicationOverQuic, QuicResult,
	quic::{HandshakeInfo, QuicheConnection},
	quiche::{self, Shutdown},
};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{Instrument as _, Span, debug, trace, warn};
use tuic_core::{
	proto::{
		Address, AddressCodec, CmdCodec, CmdType, Command, Header, HeaderCodec, address_to_target, decode_address,
		decode_command, decode_header,
	},
	udp::{FragmentInfo, FragmentReassemblyBuffer},
};
use uuid::Uuid;
use wind_core::{
	InboundCallback,
	types::TargetAddr,
	udp::{UdpPacket, UdpStream as CoreUdpStream},
};

use crate::stream::{QuicheStream, TcpBack, WaitTcpBack};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

const READ_BUF_SIZE: usize = 64 * 1024;
const TCP_CHANNEL_CAP: usize = 64;
const UDP_OUTBOUND_CAP: usize = 256;
const UDP_RESP_CAP: usize = 256;
const UDP_FRAG_CAP: usize = 256;
/// Per-stream cap on buffered client→target bytes before we stop draining the
/// QUIC stream and let flow control backpressure the client.
const MAX_TCP_BUFFER: usize = 256 * 1024;
/// Cap on the unparsed CONNECT header+address prefix; anything larger is junk.
const MAX_HEADER_PREFIX: usize = 4 * 1024;
/// Cap on a single uni stream's buffered bytes (one Auth/Packet/Dissociate
/// cmd).
const MAX_UNI_BUFFER: usize = 70 * 1024;
const MAX_FRAGMENTS: u8 = 255;
const DEFAULT_MAX_DATAGRAM: usize = 1200;

fn boxed<E: std::error::Error + Send + Sync + 'static>(e: E) -> BoxErr {
	Box::new(e)
}

fn is_done(e: &quiche::Error) -> bool {
	matches!(e, quiche::Error::Done)
}

/// Recompute a TUIC auth token from the live BoringSSL session via the RFC 5705
/// keying-material exporter, returning the 32-byte token on success.
///
/// quiche exposes the underlying `boring::ssl::SslRef` through
/// `impl AsMut<SslRef> for Connection` when built with `boringssl-boring-crate`
/// (enabled by tokio-quiche). We call the BoringSSL FFI directly rather than
/// the safe `SslRef::export_keying_material`, because the safe wrapper takes
/// the label as `&str` while TUIC uses the raw (non-UTF-8) UUID bytes as the
/// label.
fn export_keying_material(qconn: &mut QuicheConnection, label: &[u8], context: &[u8]) -> Option<[u8; 32]> {
	use foreign_types_shared::ForeignTypeRef as _;

	let ssl: &mut boring::ssl::SslRef = qconn.as_mut();
	let mut out = [0u8; 32];
	// SAFETY: `ssl.as_ptr()` yields a valid `SSL*` for the duration of the
	// borrow; `out`/`label`/`context` are passed as (ptr, len) of valid slices
	// and BoringSSL does not retain any of them past the call.
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

/// Per bidirectional (TCP CONNECT) stream state.
struct TcpState {
	/// `false` until the CONNECT header+address is parsed and the relay starts.
	started: bool,
	/// Accumulates the CONNECT header+address prefix before the relay starts;
	/// after parsing, holds the leftover first payload until moved to the
	/// proxy.
	header_buf: BytesMut,
	/// Worker → proxy (client→target). `None` once the client's FIN is observed
	/// and the buffer is drained (signals EOF to the relay).
	to_proxy: Option<mpsc::Sender<Bytes>>,
	/// Client→target bytes not yet accepted by `to_proxy` (bounded channel
	/// full).
	to_proxy_buf: VecDeque<Bytes>,
	/// Target→client bytes pending `stream_send`.
	queued: BytesMut,
	client_fin: bool,
	proxy_done: bool,
	fin_sent: bool,
}

impl TcpState {
	fn new() -> Self {
		Self {
			started: false,
			header_buf: BytesMut::new(),
			to_proxy: None,
			to_proxy_buf: VecDeque::new(),
			queued: BytesMut::new(),
			client_fin: false,
			proxy_done: false,
			fin_sent: false,
		}
	}

	fn buffered_to_proxy(&self) -> usize {
		self.to_proxy_buf.iter().map(|b| b.len()).sum()
	}
}

/// Per UDP association state held by the worker.
struct UdpSession {
	/// Worker → reassembly task (raw decoded fragments).
	frag_tx: mpsc::Sender<FragmentInput>,
	/// Monotonic packet-id counter for server→client response datagrams.
	next_pkt_id: u16,
}

/// A decoded UDP fragment handed to the per-association reassembly task.
struct FragmentInput {
	assoc_id: u16,
	pkt_id: u16,
	frag_total: u8,
	frag_id: u8,
	target: TargetAddr,
	payload: Bytes,
}

enum ParseOutcome {
	NeedMore,
	Bad,
	Connect(TargetAddr),
}

pub struct TuicheDriver<C: InboundCallback> {
	callback: C,
	users: std::sync::Arc<HashMap<Uuid, Vec<u8>>>,
	/// Per-connection tracing span (`conn{peer=…}`). Entered in the
	/// `ApplicationOverQuic` callbacks so every inline log line is tagged with
	/// the peer, and used as the parent of the per-stream/per-association spans
	/// on the relay tasks we spawn.
	span: Span,
	established: bool,
	authed: bool,
	buffer: Vec<u8>,
	tcp: HashMap<u64, TcpState>,
	uni: HashMap<u64, BytesMut>,
	waiters: FuturesUnordered<WaitTcpBack>,
	out_datagrams: VecDeque<Bytes>,
	udp: HashMap<u16, UdpSession>,
	udp_resp_tx: mpsc::Sender<(u16, UdpPacket)>,
	udp_resp_rx: mpsc::Receiver<(u16, UdpPacket)>,
}

impl<C: InboundCallback> TuicheDriver<C> {
	pub fn new(callback: C, users: std::sync::Arc<HashMap<Uuid, Vec<u8>>>, span: Span) -> Self {
		let (udp_resp_tx, udp_resp_rx) = mpsc::channel(UDP_RESP_CAP);
		Self {
			callback,
			users,
			span,
			established: false,
			authed: false,
			buffer: vec![0u8; READ_BUF_SIZE],
			tcp: HashMap::new(),
			uni: HashMap::new(),
			waiters: FuturesUnordered::new(),
			out_datagrams: VecDeque::new(),
			udp: HashMap::new(),
			udp_resp_tx,
			udp_resp_rx,
		}
	}

	// ----- reads ---------------------------------------------------------

	fn drain_datagrams(&mut self, qconn: &mut QuicheConnection) {
		loop {
			match qconn.dgram_recv(&mut self.buffer) {
				Ok(n) => {
					let data = Bytes::copy_from_slice(&self.buffer[..n]);
					self.handle_datagram(data);
				}
				Err(quiche::Error::Done) => break,
				Err(e) => {
					trace!("dgram_recv error: {e}");
					break;
				}
			}
		}
	}

	fn handle_datagram(&mut self, data: Bytes) {
		let mut buf = data;
		let header = match decode_header(&mut buf, "datagram") {
			Ok(h) => h,
			Err(e) => {
				debug!("bad datagram header: {e}");
				return;
			}
		};
		match header.command {
			CmdType::Heartbeat => {}
			CmdType::Packet => {
				if !self.authed {
					return;
				}
				if let Some(input) = decode_packet(&mut buf) {
					self.dispatch_fragment(input);
				}
			}
			other => debug!("unexpected datagram command {other:?}"),
		}
	}

	fn read_tcp(&mut self, qconn: &mut QuicheConnection, sid: u64) -> QuicResult<()> {
		// Backpressure / admission.
		match self.tcp.get(&sid) {
			Some(st) if st.buffered_to_proxy() > MAX_TCP_BUFFER => return Ok(()),
			Some(_) => {}
			None => {
				if !self.authed {
					let _ = qconn.stream_shutdown(sid, Shutdown::Read, 0);
					let _ = qconn.stream_shutdown(sid, Shutdown::Write, 0);
					return Ok(());
				}
				self.tcp.insert(sid, TcpState::new());
			}
		}

		// Drain currently-available stream data.
		let mut incoming = BytesMut::new();
		let mut fin = false;
		loop {
			match qconn.stream_recv(sid, &mut self.buffer) {
				Ok((n, f)) => {
					if n > 0 {
						incoming.extend_from_slice(&self.buffer[..n]);
					}
					fin |= f;
					if f || incoming.len() > MAX_TCP_BUFFER {
						break;
					}
				}
				Err(e) if is_done(&e) => break,
				Err(e) => {
					debug!(stream = sid, "stream_recv error: {e}");
					self.tcp.remove(&sid);
					return Ok(());
				}
			}
		}

		let started = self.tcp.get(&sid).map(|s| s.started).unwrap_or(false);
		if started {
			if let Some(st) = self.tcp.get_mut(&sid) {
				if !incoming.is_empty() {
					st.to_proxy_buf.push_back(incoming.freeze());
				}
				if fin {
					st.client_fin = true;
				}
			}
			self.flush_to_proxy(sid);
		} else {
			// Still parsing the CONNECT prefix.
			let outcome = {
				let st = self.tcp.get_mut(&sid).expect("tcp state present");
				st.header_buf.extend_from_slice(&incoming);
				if fin {
					st.client_fin = true;
				}
				try_parse_connect(&mut st.header_buf)?
			};
			match outcome {
				ParseOutcome::NeedMore => {
					let st = self.tcp.get(&sid).expect("tcp state present");
					if st.header_buf.len() > MAX_HEADER_PREFIX || st.client_fin {
						let _ = qconn.stream_shutdown(sid, Shutdown::Read, 0);
						let _ = qconn.stream_shutdown(sid, Shutdown::Write, 0);
						self.tcp.remove(&sid);
					}
				}
				ParseOutcome::Bad => {
					let _ = qconn.stream_shutdown(sid, Shutdown::Read, 0);
					let _ = qconn.stream_shutdown(sid, Shutdown::Write, 0);
					self.tcp.remove(&sid);
				}
				ParseOutcome::Connect(target) => {
					debug!(stream = sid, target = %target, "tuiche TCP connect");
					self.begin_tcp_relay(sid, target);
				}
			}
		}
		Ok(())
	}

	fn begin_tcp_relay(&mut self, sid: u64, target: TargetAddr) {
		let (to_proxy_tx, to_proxy_rx) = mpsc::channel::<Bytes>(TCP_CHANNEL_CAP);
		let (from_proxy_tx, from_proxy_rx) = mpsc::channel::<Bytes>(TCP_CHANNEL_CAP);
		let qstream = QuicheStream::new(to_proxy_rx, from_proxy_tx);

		let cb = self.callback.clone();
		let span = tracing::debug_span!(parent: &self.span, "tcp", stream = sid, target = %target);
		tokio::spawn(
			async move {
				if let Err(e) = cb.handle_tcpstream(target, qstream).await {
					debug!("tuiche TCP relay ended: {e}");
				}
			}
			.instrument(span),
		);

		self.waiters.push(WaitTcpBack::new(sid, from_proxy_rx));

		if let Some(st) = self.tcp.get_mut(&sid) {
			st.started = true;
			let leftover = std::mem::take(&mut st.header_buf).freeze();
			if !leftover.is_empty() {
				st.to_proxy_buf.push_back(leftover);
			}
			st.to_proxy = Some(to_proxy_tx);
		}
		self.flush_to_proxy(sid);
	}

	fn read_uni(&mut self, qconn: &mut QuicheConnection, sid: u64) -> QuicResult<()> {
		let mut fin = false;
		let buf = self.uni.entry(sid).or_default();
		loop {
			match qconn.stream_recv(sid, &mut self.buffer) {
				Ok((n, f)) => {
					if n > 0 {
						buf.extend_from_slice(&self.buffer[..n]);
					}
					fin |= f;
					if f || buf.len() > MAX_UNI_BUFFER {
						break;
					}
				}
				Err(e) if is_done(&e) => break,
				Err(e) => {
					debug!(stream = sid, "uni stream_recv error: {e}");
					self.uni.remove(&sid);
					return Ok(());
				}
			}
		}

		if !fin {
			if self.uni.get(&sid).map(|b| b.len()).unwrap_or(0) > MAX_UNI_BUFFER {
				self.uni.remove(&sid);
			}
			return Ok(());
		}

		let data = self.uni.remove(&sid).unwrap_or_default();
		self.handle_uni_command(qconn, data.freeze());
		Ok(())
	}

	fn handle_uni_command(&mut self, qconn: &mut QuicheConnection, data: Bytes) {
		let mut buf = data;
		let header = match decode_header(&mut buf, "uni") {
			Ok(h) => h,
			Err(e) => {
				debug!("bad uni header: {e}");
				return;
			}
		};
		match header.command {
			CmdType::Auth => match decode_command(CmdType::Auth, &mut buf, "uni auth") {
				Ok(Command::Auth { uuid, token }) => self.handle_auth(qconn, uuid, token),
				_ => debug!("malformed auth command"),
			},
			CmdType::Heartbeat => {}
			CmdType::Dissociate => {
				if !self.authed {
					return;
				}
				if let Ok(Command::Dissociate { assoc_id }) = decode_command(CmdType::Dissociate, &mut buf, "uni dissociate") {
					self.udp.remove(&assoc_id);
					debug!(assoc_id, "dissociated UDP session");
				}
			}
			CmdType::Packet => {
				if !self.authed {
					return;
				}
				if let Some(input) = decode_packet(&mut buf) {
					self.dispatch_fragment(input);
				}
			}
			other => debug!("unexpected uni command {other:?}"),
		}
	}

	fn handle_auth(&mut self, qconn: &mut QuicheConnection, uuid: Uuid, token: [u8; 32]) {
		// TUIC's auth token is the RFC 5705 TLS keying-material exporter output
		// with label = the UUID bytes and context = the user's password. We
		// recompute it from the live BoringSSL session and compare in constant
		// time. To avoid a timing/Err oracle that reveals whether a UUID exists,
		// always run the exporter (against the real or a fixed dummy password)
		// and a constant-time comparison; every failure path returns the same
		// generic rejection. Mirrors `wind-tuic`'s `handle_auth`.
		const DUMMY_PASSWORD: &[u8] = b"\x00\x00\x00\x00\x00\x00\x00\x00";
		let (password, user_known): (&[u8], bool) = match self.users.get(&uuid) {
			Some(pw) => (pw.as_slice(), true),
			None => (DUMMY_PASSWORD, false),
		};

		let expected = export_keying_material(qconn, uuid.as_bytes(), password);

		let token_ok = match &expected {
			Some(exp) => {
				let mut diff = 0u8;
				for (a, b) in token.iter().zip(exp.iter()) {
					diff |= a ^ b;
				}
				diff == 0
			}
			None => false,
		};

		if user_known && token_ok {
			self.authed = true;
			debug!(%uuid, "tuiche authenticated");
		} else {
			warn!(%uuid, "tuiche auth rejected");
		}
	}

	// ----- UDP -----------------------------------------------------------

	fn dispatch_fragment(&mut self, input: FragmentInput) {
		let assoc_id = input.assoc_id;
		let frag_tx = self.udp_session(assoc_id);
		if let Err(e) = frag_tx.try_send(input) {
			match e {
				TrySendError::Full(_) => debug!(assoc_id, "UDP reassembly queue full; dropping fragment"),
				TrySendError::Closed(_) => {
					self.udp.remove(&assoc_id);
				}
			}
		}
	}

	/// Get (or lazily create) the reassembly channel for an association.
	fn udp_session(&mut self, assoc_id: u16) -> mpsc::Sender<FragmentInput> {
		if let Some(s) = self.udp.get(&assoc_id) {
			return s.frag_tx.clone();
		}

		let (frag_tx, frag_rx) = mpsc::channel::<FragmentInput>(UDP_FRAG_CAP);
		let (to_outbound_tx, to_outbound_rx) = mpsc::channel::<UdpPacket>(UDP_OUTBOUND_CAP);
		let (from_outbound_tx, from_outbound_rx) = mpsc::channel::<UdpPacket>(UDP_OUTBOUND_CAP);

		// All three per-association tasks share one `udp{assoc_id}` span parented
		// to the connection span, so their logs group under the connection's peer.
		let span = tracing::debug_span!(parent: &self.span, "udp", assoc_id);

		// Reassembly task: raw fragments -> complete packets -> outbound relay.
		tokio::spawn(udp_reassembly_task(assoc_id, frag_rx, to_outbound_tx).instrument(span.clone()));

		// Relay task: hand the UdpStream to the wind-core callback.
		let cb = self.callback.clone();
		let core_stream = CoreUdpStream {
			tx: from_outbound_tx,
			rx: to_outbound_rx,
		};
		tokio::spawn(
			async move {
				if let Err(e) = cb.handle_udpstream(core_stream).await {
					debug!(assoc_id, "tuiche UDP relay ended: {e}");
				}
			}
			.instrument(span.clone()),
		);

		// Forwarder: tag the callback's response packets with the association id
		// and funnel them to the worker's single response channel.
		let resp_tx = self.udp_resp_tx.clone();
		let mut from_outbound_rx = from_outbound_rx;
		tokio::spawn(
			async move {
				while let Some(pkt) = from_outbound_rx.recv().await {
					if resp_tx.send((assoc_id, pkt)).await.is_err() {
						break;
					}
				}
			}
			.instrument(span),
		);

		self.udp.insert(
			assoc_id,
			UdpSession {
				frag_tx: frag_tx.clone(),
				next_pkt_id: 0,
			},
		);
		frag_tx
	}

	/// Encode a server→client UDP response into one or more TUIC datagrams.
	fn enqueue_udp_response(&mut self, assoc_id: u16, packet: UdpPacket, max_datagram: usize) {
		let pkt_id = match self.udp.get_mut(&assoc_id) {
			Some(s) => {
				let id = s.next_pkt_id;
				s.next_pkt_id = s.next_pkt_id.wrapping_add(1);
				id
			}
			None => 0,
		};

		let target = packet.target;
		let payload = packet.payload;
		let addr_size = address_size(&target);
		let single_overhead = 2 + 8 + addr_size;

		if single_overhead + payload.len() <= max_datagram {
			self.out_datagrams
				.push_back(encode_packet(assoc_id, pkt_id, 1, 0, &target, &payload));
			return;
		}

		// Fragment: first fragment carries the address, the rest use Address::None.
		let first_max = max_datagram.saturating_sub(2 + 8 + addr_size);
		let sub_max = max_datagram.saturating_sub(2 + 8 + 1);
		if first_max == 0 || sub_max == 0 {
			debug!(assoc_id, "max datagram too small for UDP response header; dropping");
			return;
		}
		let frag_count = 1 + (payload.len() - first_max).div_ceil(sub_max);
		if frag_count > MAX_FRAGMENTS as usize {
			debug!(assoc_id, "UDP response too large to fragment; dropping");
			return;
		}
		let frag_total = frag_count as u8;

		let mut offset = 0usize;
		for frag_id in 0..frag_count {
			let max = if frag_id == 0 { first_max } else { sub_max };
			let end = (offset + max).min(payload.len());
			let chunk = payload.slice(offset..end);
			let dg = if frag_id == 0 {
				encode_packet(assoc_id, pkt_id, frag_total, 0, &target, &chunk)
			} else {
				encode_packet_no_addr(assoc_id, pkt_id, frag_total, frag_id as u8, &chunk)
			};
			self.out_datagrams.push_back(dg);
			offset = end;
		}
	}

	// ----- writes / backchannel -----------------------------------------

	fn handle_back(&mut self, back: TcpBack) {
		let TcpBack { stream_id, data, rx } = back;
		let Some(st) = self.tcp.get_mut(&stream_id) else {
			return;
		};
		match data {
			Some(bytes) => {
				st.queued.extend_from_slice(&bytes);
				// Re-arm the back-channel waiter.
				self.waiters.push(WaitTcpBack::new(stream_id, rx));
			}
			None => {
				st.proxy_done = true;
			}
		}
	}

	fn flush_to_proxy(&mut self, sid: u64) {
		let Some(st) = self.tcp.get_mut(&sid) else { return };
		let Some(tx) = st.to_proxy.clone() else { return };
		while st.to_proxy_buf.front().is_some() {
			match tx.try_reserve() {
				Ok(permit) => {
					let chunk = st.to_proxy_buf.pop_front().unwrap();
					permit.send(chunk);
				}
				Err(TrySendError::Full(())) => break,
				Err(TrySendError::Closed(())) => {
					st.to_proxy_buf.clear();
					st.to_proxy = None;
					return;
				}
			}
		}
		if st.client_fin && st.to_proxy_buf.is_empty() {
			// Drop the sender so the relay observes EOF on the read half.
			st.to_proxy = None;
		}
	}
}

impl<C: InboundCallback> ApplicationOverQuic for TuicheDriver<C> {
	fn on_conn_established(&mut self, qconn: &mut QuicheConnection, _info: &HandshakeInfo) -> QuicResult<()> {
		let span = self.span.clone();
		let _enter = span.enter();
		self.established = true;
		debug!(trace = qconn.trace_id(), "tuiche connection established");
		Ok(())
	}

	fn should_act(&self) -> bool {
		self.established
	}

	fn buffer(&mut self) -> &mut [u8] {
		&mut self.buffer
	}

	async fn wait_for_data(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
		enum Ev {
			Tcp(TcpBack),
			Udp((u16, UdpPacket)),
		}
		let ev = {
			let waiters = &mut self.waiters;
			let urx = &mut self.udp_resp_rx;
			tokio::select! {
				Some(b) = waiters.next() => Ev::Tcp(b),
				Some(u) = urx.recv() => Ev::Udp(u),
				_ = std::future::pending::<()>() => unreachable!(),
			}
		};
		// Enter the connection span only for the synchronous handling below; a
		// span guard must never be held across the `.await` in the select above.
		let span = self.span.clone();
		let _enter = span.enter();
		match ev {
			Ev::Tcp(b) => self.handle_back(b),
			Ev::Udp((assoc_id, packet)) => {
				let max = qconn.dgram_max_writable_len().unwrap_or(DEFAULT_MAX_DATAGRAM);
				self.enqueue_udp_response(assoc_id, packet, max);
			}
		}
		Ok(())
	}

	fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
		let span = self.span.clone();
		let _enter = span.enter();
		self.drain_datagrams(qconn);

		let ids: Vec<u64> = qconn.readable().collect();
		for sid in ids {
			// Bit 0x2 clear => bidirectional (TCP CONNECT); set => unidirectional.
			if sid & 0x2 == 0 {
				self.read_tcp(qconn, sid)?;
			} else {
				self.read_uni(qconn, sid)?;
			}
		}
		Ok(())
	}

	fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
		let span = self.span.clone();
		let _enter = span.enter();
		// Flush queued response datagrams.
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

		// Flush per-stream traffic.
		let sids: Vec<u64> = self.tcp.keys().copied().collect();
		for sid in sids {
			self.flush_to_proxy(sid);

			let mut remove = false;
			if let Some(st) = self.tcp.get_mut(&sid) {
				if !st.queued.is_empty() {
					match qconn.stream_send(sid, st.queued.as_ref(), false) {
						Ok(n) => {
							st.queued.advance(n);
						}
						Err(quiche::Error::Done) => {}
						Err(e) => {
							debug!(stream = sid, "stream_send error: {e}");
							remove = true;
						}
					}
				}
				if st.queued.is_empty() && st.proxy_done && !st.fin_sent {
					match qconn.stream_send(sid, b"", true) {
						Ok(_) => st.fin_sent = true,
						Err(quiche::Error::Done) => {}
						Err(e) => {
							debug!(stream = sid, "stream_send fin error: {e}");
							remove = true;
						}
					}
				}
				if st.fin_sent && st.to_proxy.is_none() && st.to_proxy_buf.is_empty() {
					remove = true;
				}
			}
			if remove {
				self.tcp.remove(&sid);
			}
		}
		Ok(())
	}
}

// ----- free helpers ------------------------------------------------------

/// Per-association reassembly: raw fragments → complete `UdpPacket`s.
async fn udp_reassembly_task(assoc_id: u16, mut frag_rx: mpsc::Receiver<FragmentInput>, to_outbound: mpsc::Sender<UdpPacket>) {
	let frag = FragmentReassemblyBuffer::new();
	while let Some(input) = frag_rx.recv().await {
		let packet = if input.frag_total <= 1 {
			Some(UdpPacket {
				source: None,
				target: input.target,
				payload: input.payload,
			})
		} else {
			frag.add_fragment(
				FragmentInfo {
					assoc_id,
					pkt_id: input.pkt_id,
					frag_total: input.frag_total,
					frag_id: input.frag_id,
					source: None,
					target: input.target,
				},
				input.payload,
			)
			.await
		};

		if let Some(packet) = packet
			&& to_outbound.send(packet).await.is_err()
		{
			break;
		}
	}
}

/// Decode a `Packet` body (command + address + payload) into a
/// [`FragmentInput`]. The header has already been consumed by the caller.
fn decode_packet(buf: &mut Bytes) -> Option<FragmentInput> {
	let cmd = decode_command(CmdType::Packet, buf, "packet").ok()?;
	let Command::Packet {
		assoc_id,
		pkt_id,
		frag_total,
		frag_id,
		size,
	} = cmd
	else {
		return None;
	};
	let addr = decode_address(buf, "packet addr").ok()?;
	let target = address_to_target(addr).unwrap_or(TargetAddr::IPv4(std::net::Ipv4Addr::UNSPECIFIED, 0));
	if buf.remaining() < size as usize {
		return None;
	}
	let payload = buf.copy_to_bytes(size as usize);
	Some(FragmentInput {
		assoc_id,
		pkt_id,
		frag_total,
		frag_id,
		target,
		payload,
	})
}

/// Try to parse a CONNECT header+address from the accumulated prefix.
///
/// Parses on a clone and only commits (`*buf = rest`) on success, so an
/// incomplete prefix is preserved for the next read. On success `buf` is left
/// holding the leftover first payload bytes.
fn try_parse_connect(buf: &mut BytesMut) -> QuicResult<ParseOutcome> {
	let mut tmp = buf.clone();

	let header = match HeaderCodec.decode(&mut tmp).map_err(boxed)? {
		Some(h) => h,
		None => return Ok(ParseOutcome::NeedMore),
	};
	if header.command != CmdType::Connect {
		return Ok(ParseOutcome::Bad);
	}
	// CONNECT carries no command body.
	if CmdCodec(CmdType::Connect).decode(&mut tmp).map_err(boxed)?.is_none() {
		return Ok(ParseOutcome::NeedMore);
	}
	let addr = match AddressCodec.decode(&mut tmp).map_err(boxed)? {
		Some(a) => a,
		None => return Ok(ParseOutcome::NeedMore),
	};
	let Ok(target) = address_to_target(addr) else {
		return Ok(ParseOutcome::Bad);
	};

	*buf = tmp;
	Ok(ParseOutcome::Connect(target))
}

fn address_size(target: &TargetAddr) -> usize {
	match target {
		TargetAddr::IPv4(..) => 1 + 4 + 2,
		TargetAddr::IPv6(..) => 1 + 16 + 2,
		TargetAddr::Domain(d, _) => 1 + 1 + d.len() + 2,
	}
}

fn encode_packet(assoc_id: u16, pkt_id: u16, frag_total: u8, frag_id: u8, target: &TargetAddr, payload: &[u8]) -> Bytes {
	let mut buf = BytesMut::with_capacity(2 + 8 + address_size(target) + payload.len());
	encode_packet_prefix(&mut buf, assoc_id, pkt_id, frag_total, frag_id, payload.len());
	AddressCodec.encode(target.clone().into(), &mut buf).expect("address encode");
	buf.extend_from_slice(payload);
	buf.freeze()
}

fn encode_packet_no_addr(assoc_id: u16, pkt_id: u16, frag_total: u8, frag_id: u8, payload: &[u8]) -> Bytes {
	let mut buf = BytesMut::with_capacity(2 + 8 + 1 + payload.len());
	encode_packet_prefix(&mut buf, assoc_id, pkt_id, frag_total, frag_id, payload.len());
	AddressCodec.encode(Address::None, &mut buf).expect("address encode");
	buf.extend_from_slice(payload);
	buf.freeze()
}

fn encode_packet_prefix(buf: &mut BytesMut, assoc_id: u16, pkt_id: u16, frag_total: u8, frag_id: u8, size: usize) {
	HeaderCodec.encode(Header::new(CmdType::Packet), buf).expect("header encode");
	CmdCodec(CmdType::Packet)
		.encode(
			Command::Packet {
				assoc_id,
				pkt_id,
				frag_total,
				frag_id,
				size: size as u16,
			},
			buf,
		)
		.expect("packet cmd encode");
}

#[cfg(test)]
mod tests {
	use std::net::Ipv4Addr;

	use super::*;

	fn connect_frame(target: &TargetAddr, payload: &[u8]) -> BytesMut {
		let mut buf = BytesMut::new();
		HeaderCodec.encode(Header::new(CmdType::Connect), &mut buf).unwrap();
		CmdCodec(CmdType::Connect).encode(Command::Connect, &mut buf).unwrap();
		AddressCodec.encode(target.clone().into(), &mut buf).unwrap();
		buf.extend_from_slice(payload);
		buf
	}

	#[test]
	fn parse_connect_full_frame_leaves_leftover_payload() {
		let target = TargetAddr::IPv4(Ipv4Addr::LOCALHOST, 443);
		let mut buf = connect_frame(&target, b"hello");

		match try_parse_connect(&mut buf).unwrap() {
			ParseOutcome::Connect(t) => assert_eq!(t, target),
			_ => panic!("expected Connect"),
		}
		// After a successful parse the buffer holds only the leftover payload.
		assert_eq!(&buf[..], b"hello");
	}

	#[test]
	fn parse_connect_domain_target() {
		let target = TargetAddr::Domain("example.com".to_string(), 8080);
		let mut buf = connect_frame(&target, b"");
		match try_parse_connect(&mut buf).unwrap() {
			ParseOutcome::Connect(t) => assert_eq!(t, target),
			_ => panic!("expected Connect"),
		}
		assert!(buf.is_empty());
	}

	#[test]
	fn parse_connect_partial_is_need_more_and_preserves_buffer() {
		let target = TargetAddr::IPv4(Ipv4Addr::LOCALHOST, 443);
		let full = connect_frame(&target, b"");
		// Feed every truncation; each must report NeedMore and leave the prefix
		// intact (parse is non-destructive until it succeeds).
		for cut in 1..full.len() {
			let mut buf = BytesMut::from(&full[..cut]);
			match try_parse_connect(&mut buf).unwrap() {
				ParseOutcome::NeedMore => assert_eq!(&buf[..], &full[..cut]),
				ParseOutcome::Connect(_) => panic!("unexpected Connect at cut {cut}"),
				ParseOutcome::Bad => panic!("unexpected Bad at cut {cut}"),
			}
		}
	}

	#[test]
	fn parse_connect_rejects_non_connect() {
		// A Heartbeat header on a bidi stream is not a valid CONNECT.
		let mut buf = BytesMut::new();
		HeaderCodec.encode(Header::new(CmdType::Heartbeat), &mut buf).unwrap();
		buf.extend_from_slice(&[0u8; 8]);
		assert!(matches!(try_parse_connect(&mut buf).unwrap(), ParseOutcome::Bad));
	}

	#[test]
	fn encode_decode_packet_roundtrip() {
		let target = TargetAddr::IPv4(Ipv4Addr::new(1, 2, 3, 4), 9000);
		let payload = b"udp-datagram-body";
		let frame = encode_packet(7, 42, 1, 0, &target, payload);

		let mut buf = frame;
		let header = decode_header(&mut buf, "t").unwrap();
		assert_eq!(header.command, CmdType::Packet);
		let input = decode_packet(&mut buf).expect("decode packet");
		assert_eq!(input.assoc_id, 7);
		assert_eq!(input.pkt_id, 42);
		assert_eq!(input.frag_total, 1);
		assert_eq!(input.frag_id, 0);
		assert_eq!(input.target, target);
		assert_eq!(&input.payload[..], payload);
	}

	#[test]
	fn encode_packet_no_addr_uses_none_address() {
		let frame = encode_packet_no_addr(7, 42, 3, 1, b"frag");
		let mut buf = frame;
		let header = decode_header(&mut buf, "t").unwrap();
		assert_eq!(header.command, CmdType::Packet);
		let input = decode_packet(&mut buf).expect("decode packet");
		// Address::None maps to the unspecified-address sentinel.
		assert_eq!(input.target, TargetAddr::IPv4(Ipv4Addr::UNSPECIFIED, 0));
		assert_eq!(input.frag_id, 1);
		assert_eq!(input.frag_total, 3);
		assert_eq!(&input.payload[..], b"frag");
	}
}

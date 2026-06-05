use std::{
	collections::HashMap,
	net::{SocketAddr, TcpListener as StdTcpListener},
	sync::{
		Arc,
		atomic::{AtomicU16, Ordering},
	},
};

use bytes::Bytes;
use once_cell::sync::OnceCell;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
	net::{TcpListener, UdpSocket},
	sync::RwLock as AsyncRwLock,
};
use tracing::{Instrument, debug, info, warn};
use wind_core::{
	AbstractOutbound,
	types::TargetAddr,
	udp::{UdpPacket, UdpStream},
};

use crate::{
	config::{TcpForward, UdpForward},
	error::Error,
	wind_adapter,
};

// Global UDP forward session registry
pub static UDP_SESSIONS: OnceCell<AsyncRwLock<HashMap<u16, ForwardUdpSession>>> = OnceCell::new();
static NEXT_ASSOC_ID: AtomicU16 = AtomicU16::new(0);

fn next_assoc_id() -> u16 {
	// Use high bit set to avoid collision with SOCKS5-generated assoc IDs
	0x8000 | (NEXT_ASSOC_ID.fetch_add(1, Ordering::Relaxed) & 0x7fff)
}

#[derive(Clone)]
pub struct ForwardUdpSession {
	socket: Arc<UdpSocket>,
	src_addr: SocketAddr,
	assoc_id: u16,
}

impl ForwardUdpSession {
	pub fn new(socket: Arc<UdpSocket>, src_addr: SocketAddr, assoc_id: u16) -> Self {
		Self {
			socket,
			src_addr,
			assoc_id,
		}
	}

	pub async fn send(&self, pkt: Bytes) -> Result<(), Error> {
		if let Err(err) = self.socket.send_to(&pkt, self.src_addr).await {
			warn!(
				"[forward-udp] [{assoc:#06x}] failed sending packet to {dst}: {err}",
				assoc = self.assoc_id,
				dst = self.src_addr,
			);
			return Err(Error::Io(err));
		}
		Ok(())
	}
}

pub async fn start(tcp: Vec<TcpForward>, udp: Vec<UdpForward>) {
	// Init UDP session map
	let _ = UDP_SESSIONS.set(AsyncRwLock::new(HashMap::new()));

	for entry in tcp {
		tokio::spawn(run_tcp_forwarder(entry));
	}
	for entry in udp {
		tokio::spawn(run_udp_forwarder(entry));
	}
}

async fn run_tcp_forwarder(entry: TcpForward) {
	let listener = match create_tcp_listener(entry.listen) {
		Ok(l) => l,
		Err(err) => {
			warn!("[forward-tcp] failed to bind listener: {err}");
			return;
		}
	};
	warn!(
		"[forward-tcp] listening on {listen} -> {remote:?}",
		listen = listener.local_addr().unwrap(),
		remote = entry.remote
	);
	loop {
		match listener.accept().await {
			Ok((inbound, peer)) => {
				let remote = entry.remote.clone();
				let span = tracing::info_span!("forward_tcp", peer = %peer);
				tokio::spawn(handle_tcp_conn(inbound, remote).instrument(span));
			}
			Err(err) => warn!("[forward-tcp] accept error: {err}"),
		}
	}
}

async fn handle_tcp_conn(inbound: tokio::net::TcpStream, remote: (String, u16)) {
	info!("connected");
	let result: Result<(), Error> = async {
		let adapter =
			wind_adapter::get_connection().ok_or_else(|| Error::Other(anyhow::anyhow!("wind adapter not initialized")))?;
		let target = TargetAddr::Domain(remote.0, remote.1);
		adapter
			.handle_tcp(target, inbound, None::<wind_adapter::TuicOutboundAdapter>)
			.await
			.map_err(|e| Error::Other(anyhow::anyhow!("{e}")))?;
		Ok(())
	}
	.await;
	if let Err(err) = result {
		warn!(error = %err, "error");
	}
	debug!("closed");
}

fn create_tcp_listener(addr: SocketAddr) -> Result<TcpListener, Error> {
	let domain = match addr {
		SocketAddr::V4(_) => Domain::IPV4,
		SocketAddr::V6(_) => Domain::IPV6,
	};
	let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
		.map_err(|err| Error::Socket("failed to create tcp forward socket", err))?;
	socket
		.set_reuse_address(true)
		.map_err(|err| Error::Socket("failed to set tcp forward socket reuse_address", err))?;
	socket
		.set_nonblocking(true)
		.map_err(|err| Error::Socket("failed setting tcp forward socket as non-blocking", err))?;
	socket
		.bind(&SockAddr::from(addr))
		.map_err(|err| Error::Socket("failed to bind tcp forward socket", err))?;
	socket
		.listen(i32::MAX)
		.map_err(|err| Error::Socket("failed to listen on tcp forward socket", err))?;
	TcpListener::from_std(StdTcpListener::from(socket)).map_err(|err| Error::Socket("failed to create tcp forward socket", err))
}

/// Per-`src_addr` UDP forwarder session. Holds a sender into a single,
/// persistent `UdpStream` that's bridged through `wind_adapter::handle_udp`,
/// plus an `Instant` of last activity used for idle expiry.
struct UdpForwardSession {
	assoc_id: u16,
	tx_to_out: tokio::sync::mpsc::Sender<UdpPacket>,
	last_seen: std::time::Instant,
}

async fn run_udp_forwarder(entry: UdpForward) {
	let socket = match UdpSocket::bind(entry.listen).await {
		Ok(s) => s,
		Err(err) => {
			warn!("[forward-udp] failed to bind {addr}: {err}", addr = entry.listen);
			return;
		}
	};
	let socket = Arc::new(socket);
	warn!(
		"[forward-udp] listening on {listen} -> {remote:?} timeout={timeout:?}",
		listen = entry.listen,
		remote = entry.remote,
		timeout = entry.timeout
	);

	let mut buf = vec![0u8; 65535];

	// Per-`src_addr` sessions. Previously every incoming UDP packet spawned a
	// fresh task that opened a one-shot TUIC `UdpStream`, sent the single
	// payload and closed — paying the entire stream-setup cost per datagram
	// and forfeiting NAT 5-tuple state on the remote. Now we keep one
	// `UdpForwardSession` per source address with a long-lived `UdpStream`
	// bridge and feed every subsequent packet from that source through the
	// same channel. Idle sessions are reaped on a coarse-grained interval.
	let mut sessions: HashMap<SocketAddr, UdpForwardSession> = HashMap::new();
	let mut gc_interval = tokio::time::interval(entry.timeout / 4);
	gc_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

	loop {
		tokio::select! {
			recv = socket.recv_from(&mut buf) => match recv {
				Ok((n, src_addr)) => {
					let pkt = Bytes::copy_from_slice(&buf[..n]);
					let target = TargetAddr::Domain(entry.remote.0.clone(), entry.remote.1);

					// Look up or create the session for this source.
					let session = sessions.entry(src_addr).or_insert_with(|| {
						let assoc_id = next_assoc_id();
						let socket_for_reply = socket.clone();
						let (tx_to_out, rx_from_local) = tokio::sync::mpsc::channel::<UdpPacket>(64);
						let (tx_to_local, mut rx_from_out) = tokio::sync::mpsc::channel::<UdpPacket>(64);
						let udp_stream = UdpStream { tx: tx_to_local, rx: rx_from_local };

						UDP_SESSIONS
							.get()
							.map(|s| s.try_write().map(|mut w| {
								w.insert(assoc_id, ForwardUdpSession::new(socket.clone(), src_addr, assoc_id));
							}))
							.and_then(|res| res.ok())
							.unwrap_or(());

						// Reply bridge: take packets coming back from the outbound
						// and write them to the original src_addr.
						tokio::spawn(async move {
							while let Some(reply_pkt) = rx_from_out.recv().await {
								if let Err(err) = socket_for_reply.send_to(&reply_pkt.payload, src_addr).await {
									warn!("[forward-udp] [{assoc_id:#06x}] reply send error: {err}");
								}
							}
						}.instrument(tracing::info_span!("forward_udp_reply", peer = %src_addr, assoc_id)));

						// One persistent `handle_udp` per session.
						tokio::spawn(async move {
							let Some(adapter) = wind_adapter::get_connection() else {
								warn!("[forward-udp] wind adapter not initialized");
								return;
							};
							if let Err(err) = adapter
								.handle_udp(udp_stream, None::<wind_adapter::TuicOutboundAdapter>)
								.await
							{
								warn!("[forward-udp] [{assoc_id:#06x}] relay error: {err}");
							}
						}.instrument(tracing::info_span!("forward_udp_relay", peer = %src_addr, assoc_id)));

						UdpForwardSession {
							assoc_id,
							tx_to_out,
							last_seen: std::time::Instant::now(),
						}
					});

					session.last_seen = std::time::Instant::now();
					let assoc_id = session.assoc_id;

					// Forward the packet through the existing session. A
					// `try_send` failure means the outbound side is saturated;
					// drop with a debug log rather than blocking the recv loop.
					match session.tx_to_out.try_send(UdpPacket {
						source: None,
						target,
						payload: pkt,
					}) {
						Ok(()) => {}
						Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
							debug!("[forward-udp] [{assoc_id:#06x}] outbound queue full; dropping packet from {src_addr}");
						}
						Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
							debug!("[forward-udp] [{assoc_id:#06x}] outbound closed; removing session for {src_addr}");
							sessions.remove(&src_addr);
							if let Some(reg) = UDP_SESSIONS.get() {
								let _ = reg.try_write().map(|mut w| w.remove(&assoc_id));
							}
						}
					}
				}
				Err(err) => warn!("[forward-udp] recv_from error: {err}"),
			},
			_ = gc_interval.tick() => {
				// Reap idle sessions. Dropping the entry drops `tx_to_out`,
				// which closes `rx_from_local` and lets the spawned relay
				// task exit cleanly.
				let now = std::time::Instant::now();
				sessions.retain(|src_addr, s| {
					if now.duration_since(s.last_seen) >= entry.timeout {
						debug!(
							"[forward-udp] [{assoc:#06x}] idle timeout; dropping session for {src_addr}",
							assoc = s.assoc_id
						);
						if let Some(reg) = UDP_SESSIONS.get() {
							let _ = reg.try_write().map(|mut w| w.remove(&s.assoc_id));
						}
						false
					} else {
						true
					}
				});
			}
		}
	}
}

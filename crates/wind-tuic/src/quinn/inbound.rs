//! TUIC inbound server implementation
//!
//! This module implements a TUIC (TCP/UDP over QUIC) server that can accept
//! incoming QUIC connections and handle TCP and UDP traffic relaying.
use std::{
	collections::HashMap,
	net::SocketAddr,
	pin::Pin,
	sync::Arc,
	task::{Context as TaskContext, Poll},
	time::Duration,
};

use arc_swap::ArcSwapOption;
use eyre::{Context, ContextCompat};
use moka::future::Cache;
use quinn::{Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TokioRuntime, TransportConfig, VarInt};
use rustls::{
	ServerConfig as RustlsServerConfig,
	pki_types::{CertificateDer, PrivateKeyDer},
};
use tokio::{
	io::{AsyncRead, AsyncWrite},
	sync::{Notify, mpsc},
};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use uuid::Uuid;
use wind_core::{
	AbstractInbound, AppContext, InboundCallback, error, info,
	udp::{UdpPacket, UdpStream as CoreUdpStream},
	warn,
};

use crate::proto::{CmdType, Command};

/// Spawn helper: await the future and log any error.
async fn spawn_logged(label: &str, fut: impl std::future::Future<Output = eyre::Result<()>>) {
	if let Err(err) = fut.await {
		error!("{label} error: {err:?}");
	}
}

/// Wrapper to combine quinn's SendStream and RecvStream into a single
/// bidirectional stream
struct QuicBidiStream {
	send: quinn::SendStream,
	recv: quinn::RecvStream,
}

impl AsyncRead for QuicBidiStream {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut TaskContext<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> Poll<std::io::Result<()>> {
		Pin::new(&mut self.recv).poll_read(cx, buf)
	}
}

impl AsyncWrite for QuicBidiStream {
	fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
		Pin::new(&mut self.send).poll_write(cx, buf).map_err(std::io::Error::other)
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
		Pin::new(&mut self.send).poll_flush(cx).map_err(std::io::Error::other)
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
		Pin::new(&mut self.send).poll_shutdown(cx).map_err(std::io::Error::other)
	}
}

pub struct TuicInboundOpts {
	/// Server bind address
	pub listen_addr: SocketAddr,

	/// TLS certificate path or PEM content
	pub certificate: Vec<CertificateDer<'static>>,

	/// TLS private key
	pub private_key: PrivateKeyDer<'static>,

	/// Certificate resolver (e.g. for ACME)
	pub cert_resolver: Option<Arc<dyn rustls::server::ResolvesServerCert>>,

	/// ALPN protocols
	pub alpn: Vec<String>,

	/// Authentication credentials: UUID -> password
	pub users: HashMap<Uuid, String>,

	/// Authentication timeout
	pub auth_timeout: Duration,

	/// Maximum idle timeout
	pub max_idle_time: Duration,

	/// Maximum concurrent bidirectional streams
	pub max_concurrent_bi_streams: u32,

	/// Maximum concurrent unidirectional streams  
	pub max_concurrent_uni_streams: u32,

	/// Send window size
	pub send_window: u64,

	/// Receive window size
	pub receive_window: u32,

	/// Enable 0-RTT
	pub zero_rtt: bool,

	/// Initial MTU
	pub initial_mtu: u16,

	/// Minimum MTU
	pub min_mtu: u16,

	/// Enable GSO (Generic Segmentation Offload)
	pub gso: bool,
}

impl Default for TuicInboundOpts {
	fn default() -> Self {
		Self {
			listen_addr: "0.0.0.0:443".parse().unwrap(),
			certificate: Vec::new(),
			private_key: PrivateKeyDer::Pkcs8(vec![].into()),
			cert_resolver: None,
			alpn: vec!["h3".to_string()],
			users: HashMap::new(),
			auth_timeout: Duration::from_secs(3),
			max_idle_time: Duration::from_secs(15),
			max_concurrent_bi_streams: 32,
			max_concurrent_uni_streams: 32,
			send_window: 8 * 1024 * 1024,    // 8MB
			receive_window: 8 * 1024 * 1024, // 8MB
			zero_rtt: false,
			initial_mtu: 1200,
			min_mtu: 1200,
			gso: true,
		}
	}
}

/// TUIC inbound server
pub struct TuicInbound {
	pub ctx: Arc<AppContext>,
	opts: TuicInboundOpts,
	cancel: CancellationToken,
}

impl TuicInbound {
	pub fn new(ctx: Arc<AppContext>, opts: TuicInboundOpts) -> Self {
		Self {
			opts,
			cancel: ctx.token.child_token(),
			ctx,
		}
	}

	fn create_server_config(&self) -> eyre::Result<ServerConfig> {
		// Setup TLS configuration
		let builder = RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]).with_no_client_auth();

		let mut crypto = if let Some(resolver) = &self.opts.cert_resolver {
			builder.with_cert_resolver(resolver.clone())
		} else {
			builder
				.with_single_cert(self.opts.certificate.clone(), self.opts.private_key.clone_key())
				.wrap_err("Failed to configure TLS certificate")?
		};

		crypto.alpn_protocols = self.opts.alpn.iter().map(|alpn| alpn.as_bytes().to_vec()).collect();

		// Enable 0-RTT if configured
		if self.opts.zero_rtt {
			crypto.max_early_data_size = u32::MAX;
			crypto.send_half_rtt_data = true;
		}

		let mut config = ServerConfig::with_crypto(Arc::new(
			quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
				.map_err(|e| eyre::eyre!("Failed to create QUIC server config: {}", e))?,
		));

		// Setup transport configuration
		let mut transport = TransportConfig::default();
		transport
			.max_concurrent_bidi_streams(VarInt::from(self.opts.max_concurrent_bi_streams))
			.max_concurrent_uni_streams(VarInt::from(self.opts.max_concurrent_uni_streams))
			.send_window(self.opts.send_window)
			.stream_receive_window(VarInt::from(self.opts.receive_window))
			.max_idle_timeout(Some(
				IdleTimeout::try_from(self.opts.max_idle_time).map_err(|_| eyre::eyre!("Invalid max idle time"))?,
			))
			.initial_mtu(self.opts.initial_mtu)
			.min_mtu(self.opts.min_mtu)
			.enable_segmentation_offload(self.opts.gso);

		config.transport_config(Arc::new(transport));

		Ok(config)
	}
}

impl AbstractInbound for TuicInbound {
	async fn listen(&self, cb: &impl InboundCallback) -> eyre::Result<()> {
		let config = self.create_server_config()?;

		// Bind socket
		let socket = std::net::UdpSocket::bind(self.opts.listen_addr)
			.with_context(|| format!("Failed to bind socket on {}", self.opts.listen_addr))?;

		// Create endpoint
		let endpoint = Endpoint::new(EndpointConfig::default(), Some(config), socket, Arc::new(TokioRuntime))
			.wrap_err("Failed to create QUIC endpoint")?;

		info!("TUIC server listening on {}", endpoint.local_addr().unwrap());

		// Share the user table across all connections via Arc so each accepted
		// connection only bumps a refcount instead of cloning the whole HashMap.
		let users = Arc::new(self.opts.users.clone());

		// Accept connections loop
		loop {
			tokio::select! {
				_ = self.cancel.cancelled() => {
					info!("TUIC server shutting down");
					break;
				}
				Some(incoming) = endpoint.accept() => {
					let opts = &self.opts;
					let users = users.clone();
					let auth_timeout = opts.auth_timeout;
					let zero_rtt = opts.zero_rtt;
					let cb = cb.clone();
					// Child token so cancelling the server propagates into every
					// in-flight connection handler and its spawned subtasks.
					let conn_cancel = self.cancel.child_token();
					let remote = incoming.remote_address();
					let span = tracing::info_span!("conn", peer = %remote);

					tokio::spawn(spawn_logged(
						"Connection handler",
						handle_connection(incoming, users, auth_timeout, zero_rtt, cb, conn_cancel),
					).instrument(span));
				}
			}
		}

		Ok(())
	}
}

/// Represents an authenticated connection
struct InboundCtx {
	conn: quinn::Connection,
	uuid: ArcSwapOption<Uuid>,
	auth_notify: Arc<Notify>,
	users: Arc<HashMap<Uuid, String>>,
	udp_sessions: Cache<u16, UdpSession>,
}

/// UDP session tracking
#[derive(Clone)]
struct UdpSession {
	/// Protocol stream for fragment reassembly and sending responses back via
	/// QUIC
	tuic_stream: Arc<crate::proto::UdpStream>,
}

async fn handle_connection<C: InboundCallback>(
	incoming: quinn::Incoming,
	users: Arc<HashMap<Uuid, String>>,
	auth_timeout: Duration,
	zero_rtt: bool,
	callback: C,
	cancel: CancellationToken,
) -> eyre::Result<()> {
	let remote_addr = incoming.remote_address();

	let connecting = match incoming.accept() {
		Err(e) => {
			error!("Failed to accept connection: {:?}", e);
			return Ok(());
		}
		Ok(conn) => conn,
	};

	// Bound the handshake with a timeout tied to `auth_timeout` so that a peer
	// who opens a QUIC connection but never completes the TLS handshake cannot
	// hold resources indefinitely. Quinn has its own idle timeout, but applying
	// an explicit bound here makes the handshake path fail-fast.
	let handshake_timeout = auth_timeout.saturating_mul(2);

	// Accept connection with optional 0-RTT
	let conn = if zero_rtt {
		match connecting.into_0rtt() {
			Ok((conn, _)) => {
				info!("Accepted 0-RTT connection from {}", remote_addr);
				conn
			}
			Err(connecting) => {
				let conn = tokio::time::timeout(handshake_timeout, connecting)
					.await
					.map_err(|_| eyre::eyre!("QUIC handshake timed out after {:?}", handshake_timeout))?
					.wrap_err("Failed to establish QUIC connection")?;
				info!("Accepted 1-RTT connection from {}", remote_addr);
				conn
			}
		}
	} else {
		let conn = tokio::time::timeout(handshake_timeout, connecting)
			.await
			.map_err(|_| eyre::eyre!("QUIC handshake timed out after {:?}", handshake_timeout))?
			.wrap_err("Failed to establish QUIC connection")?;
		info!("Accepted connection from {}", remote_addr);
		conn
	};

	let connection = Arc::new(InboundCtx {
		conn: conn.clone(),
		uuid: ArcSwapOption::empty(),
		auth_notify: Arc::new(Notify::new()),
		users,
		udp_sessions: Cache::new(u16::MAX.into()),
	});

	// Spawn authentication timeout task. If the server is shutting down or the
	// connection dies before the timeout expires we abandon the sleep.
	let conn_auth = connection.clone();
	let auth_cancel = cancel.clone();
	tokio::spawn(async move {
		tokio::select! {
			_ = tokio::time::sleep(auth_timeout) => {
				if conn_auth.uuid.load().is_none() {
					warn!("Connection from {} authentication timeout", remote_addr);
					conn_auth.conn.close(VarInt::from_u32(0), b"auth timeout");
				}
			}
			_ = auth_cancel.cancelled() => {}
			_ = conn_auth.conn.closed() => {}
		}
	});

	// Handle incoming streams and datagrams
	loop {
		tokio::select! {
			// Server shutdown: close the QUIC connection, which unblocks every
			// spawned sub-task waiting on it (accept_uni, accept_bi, datagrams,
			// send/recv), and drop out of the loop.
			_ = cancel.cancelled() => {
				connection.conn.close(VarInt::from_u32(0), b"server shutdown");
				info!("Connection from {} closed by server shutdown", remote_addr);
				break;
			}
			// Handle unidirectional streams
			result = connection.conn.accept_uni() => {
				let recv = match result {
					Err(e) => {
						error!("Accept uni error: {:?}", e);
						break;
					}
					Ok(recv) => recv,
				};

				let conn = connection.clone();
				let cb = callback.clone();
				tokio::spawn(spawn_logged(
					"Uni stream",
					handle_uni_stream(conn, recv, cb),
				).instrument(tracing::debug_span!("uni_stream")));
			}
			// Handle bidirectional streams
			result = connection.conn.accept_bi() => {
				let (send, recv) = match result {
					Err(e) => {
						error!("Accept bi error: {:?}", e);
						break;
					}
					Ok(streams) => streams,
				};

				let conn = connection.clone();
				let cb = callback.clone();
				tokio::spawn(spawn_logged(
					"Bi stream",
					handle_bi_stream(conn, send, recv, cb),
				).instrument(tracing::debug_span!("bi_stream")));
			}
			// Handle datagrams — processed inline to avoid per-datagram task
			// spawn overhead on the hot path. Datagrams are small and
			// decoding + dispatching is fast.
			result = connection.conn.read_datagram() => {
				let datagram = match result {
					Err(e) => {
						error!("Read datagram error: {:?}", e);
						break;
					}
					Ok(datagram) => datagram,
				};

				let conn = connection.clone();
				let cb = callback.clone();
				if let Err(e) = handle_datagram(conn, datagram, cb).await {
					error!("Datagram error: {e:?}");
				}
			}
		}
	}

	Ok(())
}

/// Handle unidirectional stream (Auth, Packet, Dissociate, Heartbeat).
///
/// Reads only as many bytes as the decoded command requires instead of
/// buffering the whole stream, so a misbehaving peer cannot force the server
/// to allocate up to 64 KiB per uni stream regardless of command type.
async fn handle_uni_stream<C: InboundCallback>(
	ctx: Arc<InboundCtx>,
	mut recv: quinn::RecvStream,
	callback: C,
) -> eyre::Result<()> {
	// Read header only (2 bytes): version + command type.
	let mut header_buf = [0u8; 2];
	recv.read_exact(&mut header_buf)
		.await
		.map_err(|e| eyre::eyre!("Failed to read uni stream header: {}", e))?;
	let header = crate::proto::decode_header(&mut &header_buf[..], "uni stream")?;

	match header.command {
		CmdType::Auth => {
			// Auth payload is fixed-size: 16 bytes UUID + 32 bytes token.
			let mut body = [0u8; 16 + 32];
			recv.read_exact(&mut body)
				.await
				.map_err(|e| eyre::eyre!("Failed to read auth body: {}", e))?;
			let cmd = crate::proto::decode_command(CmdType::Auth, &mut &body[..], "uni stream")?;
			if let Command::Auth { uuid, token } = cmd {
				handle_auth(&ctx, uuid, token).await?;
			}
		}
		CmdType::Packet => {
			// Packet command fields are fixed-size: 8 bytes.
			let mut cmd_body = [0u8; 8];
			recv.read_exact(&mut cmd_body)
				.await
				.map_err(|e| eyre::eyre!("Failed to read packet command: {}", e))?;
			let cmd = crate::proto::decode_command(CmdType::Packet, &mut &cmd_body[..], "uni stream")?;
			let Command::Packet {
				assoc_id,
				pkt_id,
				frag_total,
				frag_id,
				size,
			} = cmd
			else {
				unreachable!("decode_command(Packet, ..) must return Command::Packet");
			};

			// Address is variable-width but self-delimiting (capped at ~258 bytes).
			let addr = read_address_exact(&mut recv)
				.await
				.wrap_err("Failed to read uni stream packet address")?;

			// Payload is bounded by the advertised `size` (u16, ≤ 65535).
			let mut payload = vec![0u8; size as usize];
			if size > 0 {
				recv.read_exact(&mut payload)
					.await
					.map_err(|e| eyre::eyre!("Failed to read packet payload: {}", e))?;
			}
			let payload = bytes::Bytes::from(payload);

			let target_addr = match crate::proto::address_to_target(addr) {
				Ok(t) => t,
				Err(_) => wind_core::types::TargetAddr::IPv4(std::net::Ipv4Addr::UNSPECIFIED, 0),
			};
			handle_udp_packet(&ctx, assoc_id, pkt_id, frag_total, frag_id, target_addr, payload, &callback).await?;
		}
		CmdType::Dissociate => {
			// Dissociate payload: 2-byte assoc_id.
			let mut body = [0u8; 2];
			recv.read_exact(&mut body)
				.await
				.map_err(|e| eyre::eyre!("Failed to read dissociate body: {}", e))?;
			let cmd = crate::proto::decode_command(CmdType::Dissociate, &mut &body[..], "uni stream")?;
			if let Command::Dissociate { assoc_id } = cmd {
				handle_dissociate(&ctx, assoc_id).await?;
			}
		}
		CmdType::Heartbeat => {
			info!("Received heartbeat from {:?}", ctx.uuid.load());
		}
		other => {
			warn!("Unexpected command on uni stream: {:?}", other);
		}
	}

	Ok(())
}

/// Handle bidirectional stream (Connect for TCP relay)
async fn handle_bi_stream<C: InboundCallback>(
	connection: Arc<InboundCtx>,
	send: quinn::SendStream,
	mut recv: quinn::RecvStream,
	callback: C,
) -> eyre::Result<()> {
	// Check if authenticated - wait for auth if not yet done
	{
		if connection.uuid.load().is_none() {
			connection.auth_notify.notified().await;
			if connection.uuid.load().is_none() {
				warn!("Unauthenticated bi stream attempt");
				return Ok(());
			}
		}
	}

	// Read header and command
	let mut header_buf = [0u8; 2];
	recv.read_exact(&mut header_buf)
		.await
		.map_err(|e| eyre::eyre!("Failed to read header: {}", e))?;
	let mut buf = &header_buf[..];

	let header = crate::proto::decode_header(&mut buf, "bi stream")?;

	match header.command {
		CmdType::Connect => {
			// Decode command (Connect has no additional fields)
			let _cmd = crate::proto::decode_command(CmdType::Connect, &mut [].as_ref(), "bi stream")?;

			// Read exactly the address bytes, leaving the relay payload in `recv`
			// so that the same stream can be used for bidirectional data relay.
			let addr = read_address_exact(&mut recv)
				.await
				.wrap_err("Failed to read connect address")?;

			// Convert address to TargetAddr using helper function
			let target_addr = crate::proto::address_to_target(addr)?;

			info!(target = %target_addr, "TCP connect");

			// Create bidirectional stream from quinn's send/recv pair
			let stream = QuicBidiStream { send, recv };

			// Forward to callback for outbound handling
			callback.handle_tcpstream(target_addr, stream).await?;
		}
		_ => {
			warn!("Unexpected command on bi stream: {:?}", header.command);
		}
	}

	Ok(())
}

/// Handle datagram (for UDP packets)
async fn handle_datagram<C: InboundCallback>(connection: Arc<InboundCtx>, data: bytes::Bytes, callback: C) -> eyre::Result<()> {
	// Check if authenticated - wait for auth if not yet done
	{
		if connection.uuid.load().is_none() {
			connection.auth_notify.notified().await;
			if connection.uuid.load().is_none() {
				return Ok(());
			}
		}
	}

	let mut buf = data;

	// Decode header using helper function
	let header = crate::proto::decode_header(&mut buf, "datagram")?;

	match header.command {
		CmdType::Packet => {
			let cmd = crate::proto::decode_command(CmdType::Packet, &mut buf, "datagram")?;

			if let Command::Packet {
				assoc_id,
				pkt_id,
				frag_total,
				frag_id,
				size,
			} = cmd
			{
				let addr = crate::proto::decode_address(&mut buf, "datagram packet")?;
				let payload = buf.split_to(size as usize);

				// Convert address to TargetAddr, using placeholder for non-first fragments
				let target_addr = match crate::proto::address_to_target(addr) {
					Ok(t) => t,
					Err(_) => wind_core::types::TargetAddr::IPv4(std::net::Ipv4Addr::UNSPECIFIED, 0),
				};
				handle_udp_packet(
					&connection,
					assoc_id,
					pkt_id,
					frag_total,
					frag_id,
					target_addr,
					payload,
					&callback,
				)
				.await?;
			}
		}
		CmdType::Heartbeat => {
			// Acknowledge heartbeat
		}
		_ => {}
	}

	Ok(())
}

/// Handle authentication
async fn handle_auth(connection: &InboundCtx, uuid: Uuid, token: [u8; 32]) -> eyre::Result<()> {
	// Check if user exists
	let password = connection
		.users
		.get(&uuid)
		.with_context(|| format!("Unknown user: {}", uuid))?;

	// Verify token
	let mut expected_token = [0u8; 32];
	connection
		.conn
		.export_keying_material(&mut expected_token, uuid.as_bytes(), password.as_bytes())
		.map_err(|_| eyre::eyre!("Failed to export keying material"))?;

	if token != expected_token {
		return Err(eyre::eyre!("Invalid authentication token"));
	}

	// Mark as authenticated
	connection.uuid.store(Some(Arc::new(uuid)));
	connection.auth_notify.notify_waiters();
	info!(uuid = %uuid, "authenticated");

	Ok(())
}

/// Handle UDP packet with fragmentation support
#[allow(clippy::too_many_arguments)]
async fn handle_udp_packet<C: InboundCallback>(
	ctx: &Arc<InboundCtx>,
	assoc_id: u16,
	pkt_id: u16,
	frag_total: u8,
	frag_id: u8,
	target_addr: wind_core::types::TargetAddr,
	payload: bytes::Bytes,
	callback: &C,
) -> eyre::Result<()> {
	let tuic_stream = get_or_create_session(ctx, assoc_id, callback).await?;

	// Process the packet (with fragmentation support)
	if frag_total <= 1 {
		// Single-fragment packet, forward directly
		tuic_stream
			.receive_packet(UdpPacket {
				source: None,
				target: target_addr,
				payload,
			})
			.await?;
	} else {
		// Multi-fragment packet, reassemble first
		if let Some(complete) = tuic_stream
			.process_fragment(assoc_id, pkt_id, frag_total, frag_id, payload, None, target_addr)
			.await
		{
			tuic_stream.receive_packet(complete).await?;
		}
	}

	Ok(())
}

/// Get an existing UDP session or create a new one for the given assoc_id.
///
/// On first call for a given `assoc_id`, this creates the channel plumbing
/// between the QUIC connection and the outbound handler:
///
/// ```text
/// QUIC client ─► handle_udp_packet ─► proto::UdpStream (reassembly)
///                                          │ receive_packet()
///                                          ▼
///                                     crossfire channel
///                                          │ bridge task
///                                          ▼
///                                     mpsc channel ─► outbound handler
///                                                          │
///                                     mpsc channel ◄───────┘
///                                          │ response task
///                                          ▼
///                                     proto::UdpStream.send_packet()
///                                          │
///                                          ▼
///                                     QUIC client
/// ```
async fn get_or_create_session<C: InboundCallback>(
	ctx: &Arc<InboundCtx>,
	assoc_id: u16,
	callback: &C,
) -> eyre::Result<Arc<crate::proto::UdpStream>> {
	// Fast path: check the lock-free cache
	if let Some(session) = ctx.udp_sessions.get(&assoc_id).await {
		return Ok(session.tuic_stream.clone());
	}

	// Slow path: use entry API for atomic get-or-insert.
	// The moka cache `entry` API ensures only one caller creates the session
	// for a given assoc_id, avoiding the double-checked locking pattern.
	let cb = callback.clone();
	let conn = ctx.conn.clone();
	let session = ctx
		.udp_sessions
		.entry(assoc_id)
		.or_insert_with(async {
			info!("Creating new UDP session for assoc_id {}", assoc_id);

			// Channel for reassembled packets: proto::UdpStream -> bridge task -> outbound
			let (reassembled_tx, reassembled_rx) = crossfire::mpmc::bounded_async::<UdpPacket>(128);

			// Channels for the wind_core UdpStream (outbound handler <-> inbound)
			let (to_outbound_tx, to_outbound_rx) = mpsc::channel::<UdpPacket>(100);
			let (from_outbound_tx, mut from_outbound_rx) = mpsc::channel::<UdpPacket>(100);

			// Create proto::UdpStream for fragment reassembly and response sending
			let tuic_stream = Arc::new(crate::proto::UdpStream::new(conn, assoc_id, reassembled_tx));

			// UdpStream for the outbound handler
			let outbound_stream = CoreUdpStream {
				tx: from_outbound_tx,
				rx: to_outbound_rx,
			};

			// Task 1: Bridge reassembled packets (crossfire rx -> mpsc tx to outbound).
			tokio::spawn(async move {
				while let Ok(packet) = reassembled_rx.recv().await {
					match to_outbound_tx.try_send(packet) {
						Ok(()) => {}
						Err(mpsc::error::TrySendError::Full(_)) => {
							warn!("UDP outbound queue full (assoc {}), dropping packet", assoc_id);
						}
						Err(mpsc::error::TrySendError::Closed(_)) => break,
					}
				}
			});

			// Task 2: Forward outbound responses back to QUIC client
			{
				let response_stream = tuic_stream.clone();
				tokio::spawn(async move {
					while let Some(packet) = from_outbound_rx.recv().await {
						if let Err(e) = response_stream.send_packet(packet).await {
							warn!("Failed to send UDP response (assoc {}): {}", assoc_id, e);
							break;
						}
					}
				});
			}

			// Task 3: Hand off the UdpStream to the outbound via callback
			{
				tokio::spawn(async move {
					if let Err(e) = cb.handle_udpstream(outbound_stream).await {
						error!("UDP stream handler error (assoc {}): {}", assoc_id, e);
					}
				});
			}

			UdpSession { tuic_stream }
		})
		.await;

	Ok(session.into_value().tuic_stream.clone())
}

/// Read exactly the bytes for one TUIC address from a Quinn receive stream.
///
/// Unlike `read_to_end`, this function reads only as many bytes as the address
/// encoding requires, so the remaining bytes in `recv` are available as relay
/// payload after the address has been decoded.
async fn read_address_exact(recv: &mut quinn::RecvStream) -> eyre::Result<crate::proto::Address> {
	// Read address type byte first to determine how many more bytes are needed.
	let mut type_byte = [0u8; 1];
	recv.read_exact(&mut type_byte)
		.await
		.map_err(|e| eyre::eyre!("Failed to read address type: {}", e))?;

	match type_byte[0] {
		0xFF => Ok(crate::proto::Address::None),
		0x01 => {
			// AddressType::IPv4 — 4-byte address + 2-byte port
			let mut rest = [0u8; 6];
			recv.read_exact(&mut rest)
				.await
				.map_err(|e| eyre::eyre!("Failed to read IPv4 address: {}", e))?;
			let mut ip_bytes = [0u8; 4];
			ip_bytes.copy_from_slice(&rest[0..4]);
			let port = u16::from_be_bytes([rest[4], rest[5]]);
			Ok(crate::proto::Address::IPv4(std::net::Ipv4Addr::from(ip_bytes), port))
		}
		0x02 => {
			// AddressType::IPv6 — 16-byte address + 2-byte port
			let mut rest = [0u8; 18];
			recv.read_exact(&mut rest)
				.await
				.map_err(|e| eyre::eyre!("Failed to read IPv6 address: {}", e))?;
			let mut ip_bytes = [0u8; 16];
			ip_bytes.copy_from_slice(&rest[0..16]);
			let port = u16::from_be_bytes([rest[16], rest[17]]);
			Ok(crate::proto::Address::IPv6(std::net::Ipv6Addr::from(ip_bytes), port))
		}
		0x00 => {
			// AddressType::Domain — 1-byte length + <length> bytes + 2-byte port
			let mut len_byte = [0u8; 1];
			recv.read_exact(&mut len_byte)
				.await
				.map_err(|e| eyre::eyre!("Failed to read domain length: {}", e))?;
			let domain_len = len_byte[0] as usize;

			// Read directly into a Vec sized to the exact length so we can
			// hand it off to `String::from_utf8` without an extra copy.
			let mut domain = vec![0u8; domain_len];
			recv.read_exact(&mut domain)
				.await
				.map_err(|e| eyre::eyre!("Failed to read domain address: {}", e))?;

			let mut port_buf = [0u8; 2];
			recv.read_exact(&mut port_buf)
				.await
				.map_err(|e| eyre::eyre!("Failed to read domain port: {}", e))?;
			let port = u16::from_be_bytes(port_buf);

			let domain_str = String::from_utf8(domain).map_err(|_| eyre::eyre!("Invalid UTF-8 domain address"))?;
			Ok(crate::proto::Address::Domain(domain_str, port))
		}
		t => Err(eyre::eyre!("Unknown address type byte 0x{:02x}", t)),
	}
}

/// Handle UDP dissociate
async fn handle_dissociate(connection: &InboundCtx, assoc_id: u16) -> eyre::Result<()> {
	connection.udp_sessions.remove(&assoc_id).await;
	info!("Dissociated UDP session {}", assoc_id);
	Ok(())
}

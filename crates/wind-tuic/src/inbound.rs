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

use bytes::BytesMut;
use eyre::{Context, ContextCompat};
use quinn::{Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TokioRuntime, TransportConfig, VarInt};
use rustls::{
	ServerConfig as RustlsServerConfig,
	pki_types::{CertificateDer, PrivateKeyDer},
};
use tokio::{
	io::{AsyncRead, AsyncWrite},
	sync::{Notify, RwLock, mpsc},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use wind_core::{
	AbstractInbound, AppContext, InboundCallback, error, info, warn,
	udp::{UdpPacket, UdpStream as CoreUdpStream},
};

use crate::proto::{CmdType, Command};

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
		Pin::new(&mut self.send)
			.poll_write(cx, buf)
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
		Pin::new(&mut self.send)
			.poll_flush(cx)
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
		Pin::new(&mut self.send)
			.poll_shutdown(cx)
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
	}
}

pub struct TuicInboundOpts {
	/// Server bind address
	pub listen_addr: SocketAddr,

	/// TLS certificate path or PEM content
	pub certificate: Vec<CertificateDer<'static>>,

	/// TLS private key
	pub private_key: PrivateKeyDer<'static>,

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
		let mut crypto = RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
			.with_no_client_auth()
			.with_single_cert(self.opts.certificate.clone(), self.opts.private_key.clone_key())
			.wrap_err("Failed to configure TLS certificate")?;

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

		// Accept connections loop
		loop {
			tokio::select! {
				_ = self.cancel.cancelled() => {
					info!("TUIC server shutting down");
					break;
				}
				Some(incoming) = endpoint.accept() => {
					let opts = &self.opts;
					let users = opts.users.clone();
					let auth_timeout = opts.auth_timeout;
					let zero_rtt = opts.zero_rtt;
					let cb = cb.clone();

					tokio::spawn(async move {
						if let Err(err) = handle_connection(incoming, users, auth_timeout, zero_rtt, cb).await {
							error!("Connection handler error: {:?}", err);
						}
					});
				}
			}
		}

		Ok(())
	}
}

/// Represents an authenticated connection
struct InboundCtx {
	conn: quinn::Connection,
	uuid: Arc<RwLock<Option<Uuid>>>,
	auth_notify: Arc<Notify>,
	users: HashMap<Uuid, String>,
	udp_sessions: Arc<RwLock<HashMap<u16, UdpSession>>>,
}

/// UDP session tracking
struct UdpSession {
	/// Protocol stream for fragment reassembly and sending responses back via QUIC
	tuic_stream: Arc<crate::proto::UdpStream>,
}

async fn handle_connection<C: InboundCallback>(
	incoming: quinn::Incoming,
	users: HashMap<Uuid, String>,
	auth_timeout: Duration,
	zero_rtt: bool,
	callback: C,
) -> eyre::Result<()> {
	let remote_addr = incoming.remote_address();

	let connecting = match incoming.accept() {
		Err(e) => {
			error!("Failed to accept connection: {:?}", e);
			return Ok(());
		}
		Ok(conn) => conn,
	};

	// Accept connection with optional 0-RTT
	let conn = if zero_rtt {
		match connecting.into_0rtt() {
			Ok((conn, _)) => {
				info!("Accepted 0-RTT connection from {}", remote_addr);
				conn
			}
			Err(connecting) => {
				let conn = connecting.await.wrap_err("Failed to establish QUIC connection")?;
				info!("Accepted 1-RTT connection from {}", remote_addr);
				conn
			}
		}
	} else {
		let conn = connecting.await.wrap_err("Failed to establish QUIC connection")?;
		info!("Accepted connection from {}", remote_addr);
		conn
	};

	let connection = Arc::new(InboundCtx {
		conn: conn.clone(),
		uuid: Arc::new(RwLock::new(None)),
		auth_notify: Arc::new(Notify::new()),
		users,
		udp_sessions: Arc::new(RwLock::new(HashMap::new())),
	});

	// Spawn authentication timeout task
	let conn_auth = connection.clone();
	tokio::spawn(async move {
		tokio::time::sleep(auth_timeout).await;
		let uuid = conn_auth.uuid.read().await;
		if uuid.is_none() {
			warn!("Connection from {} authentication timeout", remote_addr);
			conn_auth.conn.close(VarInt::from_u32(0), b"auth timeout");
		}
	});

	// Handle incoming streams and datagrams
	loop {
		tokio::select! {
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
				tokio::spawn(async move {
					if let Err(e) = handle_uni_stream(conn, recv, cb).await {
						error!("Uni stream error: {:?}", e);
					}
				});
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
				tokio::spawn(async move {
					if let Err(e) = handle_bi_stream(conn, send, recv, cb).await {
						error!("Bi stream error: {:?}", e);
					}
				});
			}
			// Handle datagrams
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
				tokio::spawn(async move {
					if let Err(e) = handle_datagram(conn, datagram, cb).await {
						error!("Datagram error: {:?}", e);
					}
				});
			}
		}
	}

	Ok(())
}

/// Handle unidirectional stream (Auth, Packet, Dissociate, Heartbeat)
async fn handle_uni_stream<C: InboundCallback>(
	ctx: Arc<InboundCtx>,
	mut recv: quinn::RecvStream,
	callback: C,
) -> eyre::Result<()> {
	// Read all data from stream
	let data = recv
		.read_to_end(65536)
		.await
		.map_err(|e| eyre::eyre!("Failed to read stream: {}", e))?;
	let mut buf = BytesMut::from(&data[..]);

	// Decode header and command using helper functions
	let header = crate::proto::decode_header(&mut buf, "uni stream")?;
	let cmd = crate::proto::decode_command(header.command, &mut buf, "uni stream")?;

	match cmd {
		Command::Auth { uuid, token } => {
			handle_auth(&ctx, uuid, token).await?;
		}
		Command::Packet { assoc_id, pkt_id, frag_total, frag_id, size } => {
			// Decode address (may be Address::None for non-first fragments)
			let addr = crate::proto::decode_address(&mut buf, "uni stream packet")?;
			let payload = buf.split_to(size as usize).freeze();

			// Convert address to TargetAddr, using placeholder for non-first fragments
			let target_addr = match crate::proto::address_to_target(addr) {
				Ok(t) => t,
				Err(_) => wind_core::types::TargetAddr::IPv4(std::net::Ipv4Addr::UNSPECIFIED, 0),
			};
			handle_udp_packet(&ctx, assoc_id, pkt_id, frag_total, frag_id, target_addr, payload, &callback).await?;
		}
		Command::Dissociate { assoc_id } => {
			handle_dissociate(&ctx, assoc_id).await?;
		}
		Command::Heartbeat => {
			// Just acknowledge heartbeat
			info!("Received heartbeat from {:?}", ctx.uuid.read().await);
		}
		_ => {
			warn!("Unexpected command on uni stream: {:?}", cmd);
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
		let uuid = connection.uuid.read().await;
		if uuid.is_none() {
			drop(uuid);
			connection.auth_notify.notified().await;
			let uuid = connection.uuid.read().await;
			if uuid.is_none() {
				warn!("Unauthenticated bi stream attempt");
				return Ok(());
			}
		}
	}

	// Read header and command
	let mut header_buf = vec![0u8; 2];
	recv.read_exact(&mut header_buf)
		.await
		.map_err(|e| eyre::eyre!("Failed to read header: {}", e))?;
	let mut buf = BytesMut::from(&header_buf[..]);

	let header = crate::proto::decode_header(&mut buf, "bi stream")?;

	match header.command {
		CmdType::Connect => {
			// Decode command (Connect has no additional fields)
			let _cmd = crate::proto::decode_command(CmdType::Connect, &mut BytesMut::new(), "bi stream")?;

			// Read exactly the address bytes, leaving the relay payload in `recv`
			// so that the same stream can be used for bidirectional data relay.
			let addr = read_address_exact(&mut recv)
				.await
				.wrap_err("Failed to read connect address")?;

			// Convert address to TargetAddr using helper function
			let target_addr = crate::proto::address_to_target(addr)?;

			info!("TCP connect to {}", target_addr);

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
async fn handle_datagram<C: InboundCallback>(
	connection: Arc<InboundCtx>,
	data: bytes::Bytes,
	callback: C,
) -> eyre::Result<()> {
	// Check if authenticated - wait for auth if not yet done
	{
		let uuid = connection.uuid.read().await;
		if uuid.is_none() {
			drop(uuid);
			connection.auth_notify.notified().await;
			let uuid = connection.uuid.read().await;
			if uuid.is_none() {
				return Ok(());
			}
		}
	}

	let mut buf = BytesMut::from(data.as_ref());

	// Decode header using helper function
	let header = crate::proto::decode_header(&mut buf, "datagram")?;

	match header.command {
		CmdType::Packet => {
			let cmd = crate::proto::decode_command(CmdType::Packet, &mut buf, "datagram")?;

			if let Command::Packet { assoc_id, pkt_id, frag_total, frag_id, size } = cmd {
				let addr = crate::proto::decode_address(&mut buf, "datagram packet")?;
				let payload = buf.split_to(size as usize).freeze();

				// Convert address to TargetAddr, using placeholder for non-first fragments
				let target_addr = match crate::proto::address_to_target(addr) {
					Ok(t) => t,
					Err(_) => wind_core::types::TargetAddr::IPv4(std::net::Ipv4Addr::UNSPECIFIED, 0),
				};
				handle_udp_packet(&connection, assoc_id, pkt_id, frag_total, frag_id, target_addr, payload, &callback).await?;
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
	*connection.uuid.write().await = Some(uuid);
	connection.auth_notify.notify_waiters();
	info!("Connection authenticated as {}", uuid);

	Ok(())
}

/// Handle UDP packet with fragmentation support
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
		if let Some(complete) =
			tuic_stream
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
	// Fast path: check with read lock
	{
		let sessions = ctx.udp_sessions.read().await;
		if let Some(session) = sessions.get(&assoc_id) {
			return Ok(session.tuic_stream.clone());
		}
	}

	// Slow path: take write lock and double-check
	let mut sessions = ctx.udp_sessions.write().await;
	if let Some(session) = sessions.get(&assoc_id) {
		return Ok(session.tuic_stream.clone());
	}

	info!("Creating new UDP session for assoc_id {}", assoc_id);

	// Channel for reassembled packets: proto::UdpStream -> bridge task -> outbound
	let (reassembled_tx, reassembled_rx) = crossfire::mpmc::bounded_async::<UdpPacket>(128);

	// Channels for the wind_core UdpStream (outbound handler <-> inbound)
	let (to_outbound_tx, to_outbound_rx) = mpsc::channel::<UdpPacket>(100);
	let (from_outbound_tx, mut from_outbound_rx) = mpsc::channel::<UdpPacket>(100);

	// Create proto::UdpStream for fragment reassembly and response sending
	let tuic_stream = Arc::new(crate::proto::UdpStream::new(ctx.conn.clone(), assoc_id, reassembled_tx));

	// UdpStream for the outbound handler
	let outbound_stream = CoreUdpStream {
		tx: from_outbound_tx,
		rx: to_outbound_rx,
	};

	// Task 1: Bridge reassembled packets (crossfire rx -> mpsc tx to outbound)
	tokio::spawn(async move {
		loop {
			match reassembled_rx.recv().await {
				Ok(packet) => {
					if to_outbound_tx.send(packet).await.is_err() {
						break;
					}
				}
				Err(_) => break,
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
		let cb = callback.clone();
		tokio::spawn(async move {
			if let Err(e) = cb.handle_udpstream(outbound_stream).await {
				error!("UDP stream handler error (assoc {}): {}", assoc_id, e);
			}
		});
	}

	let stream = tuic_stream.clone();
	sessions.insert(assoc_id, UdpSession { tuic_stream: stream });

	Ok(tuic_stream)
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

	let mut buf = BytesMut::with_capacity(20);
	buf.extend_from_slice(&type_byte);

	match type_byte[0] {
		0xFF => {
			// AddressType::None — just the single type byte
		}
		0x01 => {
			// AddressType::IPv4 — 4-byte address + 2-byte port
			let mut rest = [0u8; 6];
			recv.read_exact(&mut rest)
				.await
				.map_err(|e| eyre::eyre!("Failed to read IPv4 address: {}", e))?;
			buf.extend_from_slice(&rest);
		}
		0x02 => {
			// AddressType::IPv6 — 16-byte address + 2-byte port
			let mut rest = [0u8; 18];
			recv.read_exact(&mut rest)
				.await
				.map_err(|e| eyre::eyre!("Failed to read IPv6 address: {}", e))?;
			buf.extend_from_slice(&rest);
		}
		0x00 => {
			// AddressType::Domain — 1-byte length + <length> bytes + 2-byte port
			let mut len_byte = [0u8; 1];
			recv.read_exact(&mut len_byte)
				.await
				.map_err(|e| eyre::eyre!("Failed to read domain length: {}", e))?;
			buf.extend_from_slice(&len_byte);
			let domain_len = len_byte[0] as usize;
			let mut rest = vec![0u8; domain_len + 2];
			recv.read_exact(&mut rest)
				.await
				.map_err(|e| eyre::eyre!("Failed to read domain address: {}", e))?;
			buf.extend_from_slice(&rest);
		}
		t => {
			return Err(eyre::eyre!("Unknown address type byte 0x{:02x}", t));
		}
	}

	crate::proto::decode_address(&mut buf, "bi stream connect")
}

/// Handle UDP dissociate
async fn handle_dissociate(connection: &InboundCtx, assoc_id: u16) -> eyre::Result<()> {
	let mut sessions = connection.udp_sessions.write().await;
	sessions.remove(&assoc_id);
	info!("Dissociated UDP session {}", assoc_id);
	Ok(())
}

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
use moka::future::Cache;
use quinn::{Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TokioRuntime, TransportConfig, VarInt};
use rustls::{
	ServerConfig as RustlsServerConfig,
	pki_types::{CertificateDer, PrivateKeyDer},
};
use tokio::{
	io::{AsyncRead, AsyncWrite},
	sync::RwLock,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use wind_core::{AbstractInbound, AppContext, InboundCallback, error, info, warn};

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

		// NOTE: Currently handles connections sequentially due to callback lifetime
		// constraints. Each QUIC connection runs in a loop processing
		// streams/datagrams until the connection closes. This means only one
		// connection can be active at a time, which is a limitation.
		//
		// To support concurrent connections, the InboundCallback trait would need to be
		// Clone + 'static, or the listen() method signature would need to change to
		// take ownership/Arc of the callback.

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

					// Handle connection directly (blocking until connection closes)
					// This limits the server to one active connection at a time
					match handle_connection(incoming, users, auth_timeout, zero_rtt, cb).await {
						Ok(_) => {}
						Err(err) => error!("Connection handler error: {:?}", err),
					}
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
	users: HashMap<Uuid, String>,
	udp_sessions: Arc<RwLock<HashMap<u16, UdpSession>>>,
}

/// UDP session tracking
#[allow(dead_code)]
struct UdpSession {
	assoc_id: u16,
	// Track packet fragments if needed
	fragments: Cache<u16, Vec<u8>>,
}

async fn handle_connection<C: InboundCallback>(
	incoming: quinn::Incoming,
	users: HashMap<Uuid, String>,
	auth_timeout: Duration,
	zero_rtt: bool,
	callback: &C,
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
				if let Err(e) = handle_uni_stream(conn, recv, callback).await {
					error!("Uni stream error: {:?}", e);
				}
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
				if let Err(e) = handle_bi_stream(conn, send, recv, callback).await {
					error!("Bi stream error: {:?}", e);
				}
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
				if let Err(e) = handle_datagram(conn, datagram, callback).await {
					error!("Datagram error: {:?}", e);
				}
			}
		}
	}

	Ok(())
}

/// Handle unidirectional stream (Auth, Packet, Dissociate, Heartbeat)
async fn handle_uni_stream<C: InboundCallback>(
	ctx: Arc<InboundCtx>,
	mut recv: quinn::RecvStream,
	callback: &C,
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
		Command::Packet { assoc_id, size, .. } => {
			// Decode address
			let addr = crate::proto::decode_address(&mut buf, "uni stream packet")?;
			let payload = buf.split_to(size as usize).freeze();

			// Convert address to TargetAddr using helper function
			let target_addr = crate::proto::address_to_target(addr)?;
			handle_udp_packet(&ctx, assoc_id, target_addr, payload, callback).await?;
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
	callback: &C,
) -> eyre::Result<()> {
	// Check if authenticated - guard clause
	let uuid = connection.uuid.read().await;
	if uuid.is_none() {
		warn!("Unauthenticated bi stream attempt");
		return Ok(());
	}
	drop(uuid);

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

			// Read address
			let addr_data = recv
				.read_to_end(512)
				.await
				.map_err(|e| eyre::eyre!("Failed to read address: {}", e))?;
			let mut addr_buf = BytesMut::from(&addr_data[..]);
			let addr = crate::proto::decode_address(&mut addr_buf, "bi stream")?;

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
	callback: &C,
) -> eyre::Result<()> {
	// Check if authenticated - guard clause
	let uuid = connection.uuid.read().await;
	if uuid.is_none() {
		return Ok(());
	}
	drop(uuid);

	let mut buf = BytesMut::from(data.as_ref());

	// Decode header using helper function
	let header = crate::proto::decode_header(&mut buf, "datagram")?;

	match header.command {
		CmdType::Packet => {
			let cmd = crate::proto::decode_command(CmdType::Packet, &mut buf, "datagram")?;

			if let Command::Packet { assoc_id, size, .. } = cmd {
				let addr = crate::proto::decode_address(&mut buf, "datagram packet")?;
				let payload = buf.split_to(size as usize).freeze();

				// Convert address to TargetAddr using helper function
				let target_addr = crate::proto::address_to_target(addr)?;
				handle_udp_packet(&connection, assoc_id, target_addr, payload, callback).await?;
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
	info!("Connection authenticated as {}", uuid);

	Ok(())
}

/// Handle UDP packet
async fn handle_udp_packet<C: InboundCallback>(
	_connection: &InboundCtx,
	assoc_id: u16,
	target_addr: wind_core::types::TargetAddr,
	payload: bytes::Bytes,
	_callback: &C,
) -> eyre::Result<()> {
	// TODO: Complete UDP packet handling
	// Full implementation requires:
	// 1. Creating a channel-based UDP stream that maps TUIC packets to UDP datagrams
	// 2. Handling bidirectional packet flow (inbound packets from client, outbound
	//    packets to client)
	// 3. Managing UDP sessions per assoc_id
	// 4. Handling packet fragmentation
	//
	// For now, we log the received packet
	info!(
		"Received UDP packet for session {} to {} ({} bytes)",
		assoc_id,
		target_addr,
		payload.len()
	);
	// callback.handle_udpstream(stream)
	// The proper implementation would involve creating a TuicUdpStream that
	// uses channel-based UdpPacket for communication
	warn!("UDP relay not yet fully implemented - packet received but not forwarded");
	Ok(())
}

/// Handle UDP dissociate
async fn handle_dissociate(connection: &InboundCtx, assoc_id: u16) -> eyre::Result<()> {
	let mut sessions = connection.udp_sessions.write().await;
	sessions.remove(&assoc_id);
	info!("Dissociated UDP session {}", assoc_id);
	Ok(())
}

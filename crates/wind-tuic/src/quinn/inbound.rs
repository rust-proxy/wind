//! TUIC inbound server implementation (TCP/UDP over QUIC).
use std::{
	collections::HashMap,
	net::SocketAddr,
	pin::Pin,
	sync::Arc,
	task::{Context as TaskContext, Poll},
	time::Duration,
};

use arc_swap::ArcSwapOption;
use eyre::Context;
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
use tracing::{Instrument, error, info, warn};
use uuid::Uuid;
use wind_core::{
	AbstractInbound, AppContext, InboundCallback,
	udp::{UdpPacket, UdpStream as CoreUdpStream},
};

use crate::proto::{CmdType, Command};

async fn spawn_logged(label: &str, fut: impl std::future::Future<Output = eyre::Result<()>>) {
	if let Err(err) = fut.await {
		error!("{label} error: {err:?}");
	}
}

/// Wait for the connection to be authenticated. Returns `true` once a UUID is
/// set; returns `false` if the auth timeout elapses first. Callers that get
/// `false` must drop the request.
async fn ensure_authed(ctx: &InboundCtx) -> bool {
	if ctx.uuid.load().is_some() {
		return true;
	}
	if tokio::time::timeout(ctx.auth_timeout, ctx.auth_notify.notified())
		.await
		.is_err()
	{
		return false;
	}
	ctx.uuid.load().is_some()
}

/// Drive an `accept`-style call in a loop until the connection errors or
/// `cancel` fires. Each accepted value is handed to `handle`; the loop
/// exits on connection error (logged) or cancellation (silent).
async fn acceptor_loop<A, AccFut, HFut, AccFn, HFn>(
	cancel: CancellationToken,
	label: &'static str,
	mut accept: AccFn,
	mut handle: HFn,
) where
	AccFn: FnMut() -> AccFut,
	HFn: FnMut(A) -> HFut,
	AccFut: std::future::Future<Output = Result<A, quinn::ConnectionError>>,
	HFut: std::future::Future<Output = ()>,
{
	loop {
		let result = tokio::select! {
			_ = cancel.cancelled() => return,
			r = accept() => r,
		};
		match result {
			Err(e) => {
				error!("{label} error: {e:?}");
				return;
			}
			Ok(v) => handle(v).await,
		}
	}
}

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
	pub listen_addr: SocketAddr,

	pub certificate: Vec<CertificateDer<'static>>,

	pub private_key: PrivateKeyDer<'static>,

	pub cert_resolver: Option<Arc<dyn rustls::server::ResolvesServerCert>>,

	pub alpn: Vec<String>,

	pub users: HashMap<Uuid, String>,

	pub auth_timeout: Duration,

	pub max_idle_time: Duration,

	pub max_concurrent_bi_streams: u32,

	pub max_concurrent_uni_streams: u32,

	pub send_window: u64,

	pub receive_window: u32,

	pub zero_rtt: bool,

	pub initial_mtu: u16,

	pub min_mtu: u16,

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
			send_window: 8 * 1024 * 1024,
			receive_window: 8 * 1024 * 1024,
			zero_rtt: false,
			initial_mtu: 1200,
			min_mtu: 1200,
			gso: true,
		}
	}
}

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
		let builder = RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]).with_no_client_auth();

		let mut crypto = if let Some(resolver) = &self.opts.cert_resolver {
			builder.with_cert_resolver(resolver.clone())
		} else {
			builder
				.with_single_cert(self.opts.certificate.clone(), self.opts.private_key.clone_key())
				.wrap_err("Failed to configure TLS certificate")?
		};

		crypto.alpn_protocols = self.opts.alpn.iter().map(|alpn| alpn.as_bytes().to_vec()).collect();

		if self.opts.zero_rtt {
			// 0-RTT is enabled at the TLS level so resumption handshakes are fast, but
			// TUIC has no application-layer replay protection (Connect/Packet commands
			// arriving as 0-RTT data are intrinsically replayable). We therefore:
			//   * cap `max_early_data_size` so a single TLS context cannot be used to
			//     replay an unbounded volume of application data, and
			//   * keep `send_half_rtt_data = false` so the server does not emit data before
			//     the client's Finished is verified.
			//
			// Operators wanting strict replay resistance should leave `zero_rtt`
			// disabled until application-layer nonce/anti-replay is implemented.
			warn!(
				"zero_rtt=true: 0-RTT early data is accepted (cap {} B). TUIC has no application-layer replay protection — \
				 Connect/Packet commands sent as 0-RTT can be replayed.",
				16 * 1024
			);
			crypto.max_early_data_size = 16 * 1024;
			crypto.send_half_rtt_data = false;
		} else {
			crypto.max_early_data_size = 0;
			crypto.send_half_rtt_data = false;
		}

		let mut config = ServerConfig::with_crypto(Arc::new(
			quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
				.map_err(|e| eyre::eyre!("Failed to create QUIC server config: {}", e))?,
		));

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

		let socket = std::net::UdpSocket::bind(self.opts.listen_addr)
			.with_context(|| format!("Failed to bind socket on {}", self.opts.listen_addr))?;

		let endpoint = Endpoint::new(EndpointConfig::default(), Some(config), socket, Arc::new(TokioRuntime))
			.wrap_err("Failed to create QUIC endpoint")?;

		info!("TUIC server listening on {}", endpoint.local_addr().unwrap());

		let users = Arc::new(self.opts.users.clone());

		loop {
			// `endpoint.accept()` returns `None` once the endpoint is shut down
			// (e.g. the underlying socket closed). Without an `else =>` arm the
			// `tokio::select!` macro panics when every branch is disabled —
			// `Some(...) = endpoint.accept()` is the only data branch and it
			// goes from "pending" to "disabled" the instant `accept()` yields
			// `None`. Catch that as a normal shutdown.
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
					let conn_cancel = self.cancel.child_token();
					let remote = incoming.remote_address();
					let span = tracing::info_span!("conn", peer = %remote);

					tokio::spawn(spawn_logged(
						"Connection handler",
						handle_connection(incoming, users, auth_timeout, zero_rtt, cb, conn_cancel),
					).instrument(span));
				}
				else => {
					info!("TUIC endpoint closed; shutting down listen loop");
					break;
				}
			}
		}

		Ok(())
	}
}

struct InboundCtx {
	conn: quinn::Connection,
	uuid: ArcSwapOption<Uuid>,
	auth_notify: Arc<Notify>,
	users: Arc<HashMap<Uuid, String>>,
	auth_timeout: Duration,
	udp_sessions: Cache<u16, UdpSession>,
	/// Parent of every per-UDP-session cancel token. Cancelling this tears
	/// down all live bridge tasks at once (used when the parent connection
	/// terminates).
	udp_root_cancel: CancellationToken,
}

/// Per-UDP-session state stored in the LRU cache.
///
/// `cancel` is a child of `InboundCtx::udp_root_cancel` and is wired into the
/// three bridge tasks via `tokio::select!`. When the session is evicted —
/// either by an explicit `Dissociate` command via `handle_dissociate` or by
/// LRU/capacity pressure — the moka `async_eviction_listener` calls
/// `cancel.cancel()`, causing all bridge tasks to exit promptly. Without this
/// the tasks captured strong `Arc<UdpStream>` clones AND owned the channel
/// halves they recv from, forming a self-sustaining cycle that survived the
/// cache eviction. The session "removed" from the cache but the tasks kept
/// running until the connection died, letting a peer that cycles assoc_ids
/// pile up unbounded background work.
#[derive(Clone)]
struct UdpSession {
	tuic_stream: Arc<crate::proto::UdpStream>,
	cancel: CancellationToken,
}

/// Per-connection ceiling on concurrent UDP associations. The previous
/// `u16::MAX` covered the entire association-id space — every assoc id had a
/// reserved cache slot and each session spawned three tasks plus four
/// channels, so a single authenticated peer could pin ~200k tasks at
/// O(few MB) state each. 1024 is plenty for legitimate clients (the spec's
/// own example uses single-digit assoc_ids) while keeping per-connection
/// memory bounded.
const MAX_UDP_SESSIONS_PER_CONN: u64 = 1024;

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

	let handshake_timeout = auth_timeout.saturating_mul(2);

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

	let udp_root_cancel = cancel.child_token();

	// Eviction listener fires for both explicit `remove()` (via
	// `handle_dissociate`) and capacity/LRU pressure. Cancel the session's
	// token so the bridge tasks unstick from their channel waits and shut
	// down promptly. Using the async listener so we can be cheap & infallible
	// — just toggle the token.
	let eviction_cancel = move |_k: Arc<u16>, v: UdpSession, _cause| -> moka::notification::ListenerFuture {
		Box::pin(async move {
			v.cancel.cancel();
		})
	};
	let udp_sessions = Cache::builder()
		.max_capacity(MAX_UDP_SESSIONS_PER_CONN)
		.async_eviction_listener(eviction_cancel)
		.build();

	let connection = Arc::new(InboundCtx {
		conn: conn.clone(),
		uuid: ArcSwapOption::empty(),
		auth_notify: Arc::new(Notify::new()),
		users,
		auth_timeout,
		udp_sessions,
		udp_root_cancel,
	});

	// Spawn authentication timeout task.
	let conn_auth = connection.clone();
	let auth_cancel = cancel.clone();
	tokio::spawn(
		async move {
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
		}
		.in_current_span(),
	);

	// One cancellation token shared by all acceptor tasks. Cancelling it
	// from the parent stops every acceptor at once; we also fire it after
	// the parent loop exits so InboundCtx (with its per-connection UDP
	// session cache) can be dropped instead of leaking until server
	// shutdown.
	let acceptor_cancel = cancel.child_token();

	// Datagram acceptor. Pre-auth datagrams are handled inline (serially)
	// so an unauthenticated peer can't spawn unbounded tasks parked on
	// `auth_notify`; once authed, each datagram is dispatched in parallel
	// so a slow outbound queue can't block the read loop.
	{
		let conn = connection.clone();
		let cb = callback.clone();
		let dg_cancel = acceptor_cancel.clone();
		tokio::spawn(
			async move {
				acceptor_loop(
					dg_cancel,
					"Read datagram",
					|| conn.conn.read_datagram(),
					|datagram| {
						let conn = conn.clone();
						let cb = cb.clone();
						async move {
							if conn.uuid.load().is_some() {
								tokio::spawn(
									spawn_logged("Datagram", handle_datagram(conn, datagram, cb))
										.instrument(tracing::debug_span!("datagram")),
								);
							} else if let Err(e) = handle_datagram(conn, datagram, cb).await {
								error!("Datagram error: {e:?}");
							}
						}
					},
				)
				.await;
			}
			.in_current_span(),
		);
	}

	// Uni stream acceptor.
	{
		let conn = connection.clone();
		let cb = callback.clone();
		let uni_cancel = acceptor_cancel.clone();
		tokio::spawn(
			async move {
				acceptor_loop(
					uni_cancel,
					"Accept uni",
					|| conn.conn.accept_uni(),
					|recv| {
						let conn = conn.clone();
						let cb = cb.clone();
						async move {
							tokio::spawn(
								spawn_logged("Uni stream", handle_uni_stream(conn, recv, cb))
									.instrument(tracing::debug_span!("uni_stream")),
							);
						}
					},
				)
				.await;
			}
			.in_current_span(),
		);
	}

	// Bi stream acceptor.
	{
		let conn = connection.clone();
		let cb = callback.clone();
		let bi_cancel = acceptor_cancel.clone();
		tokio::spawn(
			async move {
				acceptor_loop(
					bi_cancel,
					"Accept bi",
					|| conn.conn.accept_bi(),
					|(send, recv)| {
						let conn = conn.clone();
						let cb = cb.clone();
						async move {
							tokio::spawn(
								spawn_logged("Bi stream", handle_bi_stream(conn, send, recv, cb))
									.instrument(tracing::debug_span!("bi_stream")),
							);
						}
					},
				)
				.await;
			}
			.in_current_span(),
		);
	}

	// Exit on either server shutdown or peer disconnect. Without the
	// `conn.closed()` arm the handler would block on `cancel` until the
	// whole server stops, keeping InboundCtx and every UDP bridge task
	// alive long after the QUIC connection is gone.
	tokio::select! {
		_ = cancel.cancelled() => {
			connection.conn.close(VarInt::from_u32(0), b"server shutdown");
			info!("Connection from {} closed by server shutdown", remote_addr);
		}
		_ = connection.conn.closed() => {
			info!("Connection from {} closed", remote_addr);
		}
	}
	acceptor_cancel.cancel();

	Ok(())
}

async fn handle_uni_stream<C: InboundCallback>(
	ctx: Arc<InboundCtx>,
	mut recv: quinn::RecvStream,
	callback: C,
) -> eyre::Result<()> {
	let mut header_buf = [0u8; 2];
	recv.read_exact(&mut header_buf)
		.await
		.map_err(|e| eyre::eyre!("Failed to read uni stream header: {}", e))?;
	let header = crate::proto::decode_header(&mut &header_buf[..], "uni stream")?;

	match header.command {
		CmdType::Auth => {
			let mut body = [0u8; 16 + 32];
			recv.read_exact(&mut body)
				.await
				.map_err(|e| eyre::eyre!("Failed to read auth body: {}", e))?;
			let cmd = crate::proto::decode_command(CmdType::Auth, &mut &body[..], "uni stream")?;
			if let Command::Auth { uuid, token } = cmd {
				handle_auth(&ctx, uuid, token).await?;
			}
		}
		cmd_type => {
			if !ensure_authed(&ctx).await {
				warn!(
					command = ?cmd_type,
					"Uni stream rejected: not authenticated within {:?}",
					ctx.auth_timeout
				);
				return Ok(());
			}

			match cmd_type {
				CmdType::Packet => {
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

					// Read address (capped at ~258 bytes).
					let addr = read_address_exact(&mut recv)
						.await
						.wrap_err("Failed to read uni stream packet address")?;

					// Payload bounded by u16 size (≤ 65535).
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
					tracing::trace!("Received heartbeat from {:?}", ctx.uuid.load());
				}
				other => {
					warn!("Unexpected command on uni stream: {:?}", other);
				}
			}
		}
	}

	Ok(())
}

async fn handle_bi_stream<C: InboundCallback>(
	connection: Arc<InboundCtx>,
	send: quinn::SendStream,
	mut recv: quinn::RecvStream,
	callback: C,
) -> eyre::Result<()> {
	if !ensure_authed(&connection).await {
		warn!("Bi stream rejected: not authenticated within {:?}", connection.auth_timeout);
		return Ok(());
	}

	let mut header_buf = [0u8; 2];
	recv.read_exact(&mut header_buf)
		.await
		.map_err(|e| eyre::eyre!("Failed to read header: {}", e))?;
	let mut buf = &header_buf[..];

	let header = crate::proto::decode_header(&mut buf, "bi stream")?;

	match header.command {
		CmdType::Connect => {
			let _cmd = crate::proto::decode_command(CmdType::Connect, &mut [].as_ref(), "bi stream")?;

			let addr = read_address_exact(&mut recv)
				.await
				.wrap_err("Failed to read connect address")?;

			let target_addr = crate::proto::address_to_target(addr)?;

			info!(target = %target_addr, "TCP connect");

			let stream = QuicBidiStream { send, recv };

			callback.handle_tcpstream(target_addr, stream).await?;
		}
		_ => {
			warn!("Unexpected command on bi stream: {:?}", header.command);
		}
	}

	Ok(())
}

async fn handle_datagram<C: InboundCallback>(connection: Arc<InboundCtx>, data: bytes::Bytes, callback: C) -> eyre::Result<()> {
	if !ensure_authed(&connection).await {
		warn!("Datagram rejected: not authenticated within {:?}", connection.auth_timeout);
		return Ok(());
	}

	let mut buf = data;

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
				if buf.len() < size as usize {
					return Err(eyre::eyre!("datagram payload truncated: need {}, have {}", size, buf.len()));
				}
				let payload = buf.split_to(size as usize);

				let target_addr = match crate::proto::address_to_target(addr) {
					Ok(t) => t,
					Err(_) => wind_core::types::TargetAddr::IPv4(std::net::Ipv4Addr::UNSPECIFIED, 0),
				};

				tracing::debug!(
					assoc_id,
					pkt_id,
					frag = format_args!("{}/{}", frag_id, frag_total),
					target = %target_addr,
					payload_len = payload.len(),
					"UDP datagram received",
				);

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
			tracing::trace!("UDP heartbeat received");
		}
		other => {
			tracing::debug!(command = ?other, "unexpected datagram command");
		}
	}

	Ok(())
}

async fn handle_auth(connection: &InboundCtx, uuid: Uuid, token: [u8; 32]) -> eyre::Result<()> {
	// Look the user up, but never short-circuit on an unknown UUID — that would
	// give an attacker both a timing oracle (skipped keying-material export) and
	// an error-message oracle that reveals whether a UUID exists. Instead, always
	// run the export against either the real password or a fixed dummy, and
	// always run a constant-time comparison; both failure paths return the same
	// generic error.
	const DUMMY_PASSWORD: &[u8] = b"\x00\x00\x00\x00\x00\x00\x00\x00";
	let (password_bytes, user_known) = match connection.users.get(&uuid) {
		Some(pw) => (pw.as_bytes(), true),
		None => (DUMMY_PASSWORD, false),
	};

	let mut expected_token = [0u8; 32];
	let export_ok = connection
		.conn
		.export_keying_material(&mut expected_token, uuid.as_bytes(), password_bytes)
		.is_ok();

	// Constant-time comparison: never short-circuit on first differing byte.
	let mut diff: u8 = 0;
	for (a, b) in token.iter().zip(expected_token.iter()) {
		diff |= a ^ b;
	}
	let token_ok = diff == 0;

	if !(user_known && export_ok && token_ok) {
		// Single generic error for "unknown user", "bad token", and
		// "export failed" — do not leak which one triggered.
		return Err(eyre::eyre!("Invalid authentication"));
	}

	connection.uuid.store(Some(Arc::new(uuid)));
	connection.auth_notify.notify_waiters();
	info!(uuid = %uuid, "authenticated");

	Ok(())
}

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
	if frag_total == 0 {
		tracing::debug!(assoc_id, pkt_id, "dropping packet with frag_total=0");
		return Ok(());
	}

	let tuic_stream = get_or_create_session(ctx, assoc_id, callback).await?;

	if frag_total == 1 {
		tracing::trace!(assoc_id, pkt_id, target = %target_addr, len = payload.len(), "UDP packet → outbound");
		tuic_stream
			.receive_packet(UdpPacket {
				source: None,
				target: target_addr,
				payload,
			})
			.await?;
	} else {
		if let Some(complete) = tuic_stream
			.process_fragment(assoc_id, pkt_id, frag_total, frag_id, payload, None, target_addr)
			.await
		{
			tracing::debug!(assoc_id, pkt_id, frag_total, target = %complete.target, len = complete.payload.len(), "UDP packet reassembled → outbound");
			tuic_stream.receive_packet(complete).await?;
		}
	}

	Ok(())
}

/// Get an existing UDP session for `assoc_id` or create a new one.
async fn get_or_create_session<C: InboundCallback>(
	ctx: &Arc<InboundCtx>,
	assoc_id: u16,
	callback: &C,
) -> eyre::Result<Arc<crate::proto::UdpStream>> {
	if let Some(session) = ctx.udp_sessions.get(&assoc_id).await {
		return Ok(session.tuic_stream.clone());
	}

	let cb = callback.clone();
	let conn = ctx.conn.clone();
	let session_cancel = ctx.udp_root_cancel.child_token();
	let session = ctx
		.udp_sessions
		.entry(assoc_id)
		.or_insert_with(async {
			info!("Creating new UDP session for assoc_id {}", assoc_id);

			let (reassembled_tx, reassembled_rx) = crossfire::mpmc::bounded_async::<UdpPacket>(128);

			let (to_outbound_tx, to_outbound_rx) = mpsc::channel::<UdpPacket>(100);
			let (from_outbound_tx, mut from_outbound_rx) = mpsc::channel::<UdpPacket>(100);

			let tuic_stream = Arc::new(crate::proto::UdpStream::new(conn, assoc_id, reassembled_tx));

			let outbound_stream = CoreUdpStream {
				tx: from_outbound_tx,
				rx: to_outbound_rx,
			};

			// Bridge reassembled packets from quinn -> outbound with backpressure.
			let cancel_a = session_cancel.clone();
			tokio::spawn(
				async move {
					loop {
						tokio::select! {
							biased;
							_ = cancel_a.cancelled() => break,
							res = reassembled_rx.recv() => {
								let packet = match res {
									Ok(p) => p,
									Err(_) => break,
								};
								tokio::select! {
									_ = cancel_a.cancelled() => break,
									send_res = tokio::time::timeout(Duration::from_secs(5), to_outbound_tx.send(packet)) => {
										match send_res {
											Ok(Ok(())) => {}
											Ok(Err(mpsc::error::SendError(_))) => break,
											Err(_) => {
												warn!("UDP outbound queue full (assoc {}), dropping packet after 5s", assoc_id);
											}
										}
									}
								}
							}
						}
					}
				}
				.in_current_span(),
			);

			{
				let response_stream = tuic_stream.clone();
				let cancel_b = session_cancel.clone();
				tokio::spawn(
					async move {
						loop {
							tokio::select! {
								biased;
								_ = cancel_b.cancelled() => break,
								maybe_packet = from_outbound_rx.recv() => {
									let Some(packet) = maybe_packet else { break };
									if let Err(e) = response_stream.send_packet(packet).await {
										warn!("Failed to send UDP response (assoc {}): {}", assoc_id, e);
										break;
									}
								}
							}
						}
					}
					.in_current_span(),
				);
			}

			{
				let cancel_c = session_cancel.clone();
				tokio::spawn(
					async move {
						// `handle_udpstream` typically runs forever; race the
						// session-cancel token so it exits with the rest of
						// the session instead of holding the callback's
						// resources hostage after eviction/dissociate.
						tokio::select! {
							_ = cancel_c.cancelled() => {}
							res = cb.handle_udpstream(outbound_stream) => {
								if let Err(e) = res {
									error!("UDP stream handler error (assoc {}): {}", assoc_id, e);
								}
							}
						}
					}
					.in_current_span(),
				);
			}

			UdpSession {
				tuic_stream,
				cancel: session_cancel,
			}
		})
		.await;

	Ok(session.into_value().tuic_stream.clone())
}

async fn read_address_exact(recv: &mut quinn::RecvStream) -> eyre::Result<crate::proto::Address> {
	let mut type_byte = [0u8; 1];
	recv.read_exact(&mut type_byte)
		.await
		.map_err(|e| eyre::eyre!("Failed to read address type: {}", e))?;

	match type_byte[0] {
		0xFF => Ok(crate::proto::Address::None),
		0x01 => {
			let mut ip_bytes = [0u8; 4];
			recv.read_exact(&mut ip_bytes)
				.await
				.map_err(|e| eyre::eyre!("Failed to read IPv4 address: {}", e))?;
			let mut port_buf = [0u8; 2];
			recv.read_exact(&mut port_buf)
				.await
				.map_err(|e| eyre::eyre!("Failed to read IPv4 port: {}", e))?;
			Ok(crate::proto::Address::IPv4(
				std::net::Ipv4Addr::from(ip_bytes),
				u16::from_be_bytes(port_buf),
			))
		}
		0x02 => {
			let mut ip_bytes = [0u8; 16];
			recv.read_exact(&mut ip_bytes)
				.await
				.map_err(|e| eyre::eyre!("Failed to read IPv6 address: {}", e))?;
			let mut port_buf = [0u8; 2];
			recv.read_exact(&mut port_buf)
				.await
				.map_err(|e| eyre::eyre!("Failed to read IPv6 port: {}", e))?;
			Ok(crate::proto::Address::IPv6(
				std::net::Ipv6Addr::from(ip_bytes),
				u16::from_be_bytes(port_buf),
			))
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

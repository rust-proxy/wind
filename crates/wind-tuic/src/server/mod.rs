//! Backend-agnostic TUIC server core.
//!
//! This is the TUIC inbound protocol logic — auth handshake, the three parallel
//! accept loops (datagram / uni / bi), command dispatch, and per-association
//! UDP session management — written **once** generic over
//! [`wind_quic::QuicConnection`]. Both the quinn and quiche backends construct
//! their endpoint, accept an established connection, and hand it to
//! [`serve_connection`]; everything above the QUIC handle is shared.
//!
//! It is the generalization of the former quinn-only `quinn::inbound` server
//! (the reference behavior) and the replacement for the bespoke `wind-tuiche`
//! driver.

use std::{
	collections::HashMap,
	net::SocketAddr,
	sync::{
		Arc,
		atomic::{AtomicBool, Ordering},
	},
	time::Duration,
};

use arc_swap::ArcSwapOption;
use eyre::Context as _;
use moka::future::Cache;
use tokio::{
	io::{AsyncRead, AsyncReadExt as _},
	sync::{Notify, mpsc},
};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument as _, error, info, warn};
use uuid::Uuid;
use wind_core::{
	ConnInfo, ConnectDecision, InboundCallback, InboundHooks, Protocol, StatsCollector, UserId,
	udp::{UdpPacket, UdpStream as CoreUdpStream},
};
use wind_quic::{QuicConnection, QuicError};

use crate::proto::{CmdType, Command, UdpStream};

#[cfg(feature = "masquerade")]
mod masquerade;

/// Configuration for the HTTP/3 masquerade.
///
/// Kept dependency-free (just the upstream URL) so it threads through the
/// always-compiled [`serve_connection`] even when the `masquerade` feature is
/// off. The actual reverse-proxy engine lives in the feature-gated
/// [`masquerade`] module.
#[derive(Clone, Debug)]
pub struct MasqueradeConfig {
	/// Upstream site to reverse-proxy non-TUIC HTTP/3 requests to,
	/// e.g. `https://example.com`.
	pub upstream: String,
}

async fn spawn_logged(label: &str, fut: impl std::future::Future<Output = eyre::Result<()>>) {
	if let Err(err) = fut.await {
		error!("{label} error: {err:?}");
	}
}

/// Wait for the connection to be authenticated. Returns `true` once an
/// [`AuthState`] is set; returns `false` if the auth timeout elapses first.
/// Callers that get `false` must drop the request.
async fn ensure_authed<C: QuicConnection>(ctx: &InboundCtx<C>) -> bool {
	if ctx.auth.load().is_some() {
		return true;
	}
	if tokio::time::timeout(ctx.auth_timeout, ctx.auth_notify.notified())
		.await
		.is_err()
	{
		return false;
	}
	ctx.auth.load().is_some()
}

/// Drive an `accept`-style call in a loop until the connection errors or
/// `cancel` fires. Each accepted value is handed to `handle`; the loop exits on
/// connection error (benign closes logged at debug) or cancellation (silent).
async fn acceptor_loop<A, AccFut, HFut, AccFn, HFn>(
	cancel: CancellationToken,
	label: &'static str,
	mut accept: AccFn,
	mut handle: HFn,
) where
	AccFn: FnMut() -> AccFut,
	HFn: FnMut(A) -> HFut,
	AccFut: std::future::Future<Output = Result<A, QuicError>>,
	HFut: std::future::Future<Output = ()>,
{
	loop {
		let result = tokio::select! {
			_ = cancel.cancelled() => return,
			r = accept() => r,
		};
		match result {
			Err(e) => {
				// `ApplicationClosed`, `LocallyClosed`, and `TimedOut` are normal
				// lifecycle events; log at debug instead of error so legitimate
				// disconnects don't muddy operator logs.
				if matches!(
					&e,
					QuicError::ApplicationClosed { .. } | QuicError::LocallyClosed | QuicError::TimedOut
				) {
					tracing::debug!("{label} loop ending after benign connection close: {e:?}");
				} else {
					error!("{label} error: {e:?}");
				}
				return;
			}
			Ok(v) => handle(v).await,
		}
	}
}

/// Identity published atomically once a connection authenticates. Held behind a
/// single `ArcSwapOption` so a reader can never observe a half-populated state
/// (e.g. set but user unset).
struct AuthState {
	user: UserId,
}

struct InboundCtx<C: QuicConnection> {
	conn: C,
	auth: ArcSwapOption<AuthState>,
	auth_notify: Arc<Notify>,
	users: Arc<HashMap<Uuid, String>>,
	auth_timeout: Duration,
	udp_sessions: Cache<u16, UdpSession<C>>,
	/// Parent of every per-UDP-session cancel token. Cancelling this tears down
	/// all live bridge tasks at once (used when the parent connection
	/// terminates).
	udp_root_cancel: CancellationToken,
	/// Downstream extensibility hooks (auth / stats / connection management).
	hooks: InboundHooks,
	/// Per-connection context handed to connection-management hooks.
	conn_info: ConnInfo,
}

impl<C: QuicConnection> InboundCtx<C> {
	/// The authenticated user's identity, if the connection has authenticated.
	fn user(&self) -> Option<UserId> {
		self.auth.load().as_ref().map(|a| a.user.clone())
	}
}

/// Per-UDP-session state stored in the LRU cache.
///
/// `cancel` is a child of `InboundCtx::udp_root_cancel` and is wired into the
/// three bridge tasks via `tokio::select!`. When the session is evicted —
/// either by an explicit `Dissociate` or by LRU/capacity pressure — the moka
/// `async_eviction_listener` cancels it, so the bridge tasks exit promptly
/// instead of forming a self-sustaining cycle that outlives the cache entry.
struct UdpSession<C: QuicConnection> {
	tuic_stream: Arc<UdpStream<C>>,
	cancel: CancellationToken,
}

impl<C: QuicConnection> Clone for UdpSession<C> {
	fn clone(&self) -> Self {
		Self {
			tuic_stream: self.tuic_stream.clone(),
			cancel: self.cancel.clone(),
		}
	}
}

/// Per-connection ceiling on concurrent UDP associations. Bounds per-connection
/// memory: each session spawns three tasks plus channels, so an unbounded space
/// would let one authenticated peer pin a large amount of background work.
const MAX_UDP_SESSIONS_PER_CONN: u64 = 1024;

/// Per-connection senders for the lazily-started HTTP/3 masquerade. The
/// per-stream router pushes streams it classified as h3 here; `run_masquerade`
/// (spawned parked) pulls them after `go` fires on the first one. `None`
/// everywhere when the masquerade is disabled or not compiled in.
#[cfg_attr(not(feature = "masquerade"), allow(dead_code))]
struct H3Senders<C: QuicConnection> {
	uni_tx: mpsc::UnboundedSender<wind_quic::PrefixedRecv<C::RecvStream>>,
	bidi_tx: mpsc::UnboundedSender<(C::SendStream, wind_quic::PrefixedRecv<C::RecvStream>)>,
	go: Arc<Notify>,
}

/// A non-TUIC stream handed to the h3 masquerade by the per-stream router.
enum H3Stream<C: QuicConnection> {
	Uni(wind_quic::PrefixedRecv<C::RecvStream>),
	Bi(C::SendStream, wind_quic::PrefixedRecv<C::RecvStream>),
}

/// Whether a 2-byte prefix is TUIC framing: `[VER, CmdType]` with `CmdType` in
/// `Auth..=Heartbeat` (0..=4). An HTTP/3 stream-type / frame-type byte won't
/// satisfy both, so this distinguishes the two even when an h3 stream happens
/// to start with `VER`.
fn is_tuic_prefix(prefix: [u8; 2]) -> bool {
	prefix[0] == crate::proto::VER && prefix[1] <= u8::from(CmdType::Heartbeat)
}

/// Read the 2-byte classifier prefix from a stream (`None` if it closes first).
async fn read_prefix<R: AsyncRead + Unpin>(recv: &mut R) -> Option<[u8; 2]> {
	let mut prefix = [0u8; 2];
	recv.read_exact(&mut prefix).await.ok().map(|_| prefix)
}

/// Build this connection's HTTP/3 masquerade router: two channels feeding a
/// **parked** `run_masquerade` task (it only builds the h3 server once the
/// router wakes it on the first h3 stream). Returns `None` (and spawns nothing)
/// when the masquerade is disabled.
#[cfg(feature = "masquerade")]
fn spawn_h3_router<C: QuicConnection>(
	conn: C,
	masq: Option<MasqueradeConfig>,
	cancel: CancellationToken,
) -> Option<Arc<H3Senders<C>>> {
	let cfg = masq?;
	let (uni_tx, uni_rx) = mpsc::unbounded_channel();
	let (bidi_tx, bidi_rx) = mpsc::unbounded_channel();
	let go = Arc::new(Notify::new());
	// Run the masquerade parked. If it fails (invalid upstream URL, h3 setup
	// error) the connection would otherwise leak: a non-TUIC stream has already
	// flipped `h3_active`, so the auth-timeout guard won't reap it. Log the error
	// and close the connection ourselves, mirroring that guard's cleanup.
	let close_conn = conn.clone();
	let go_task = go.clone();
	tokio::spawn(async move {
		if let Err(e) = masquerade::run_masquerade(conn, uni_rx, bidi_rx, go_task, cfg, cancel).await {
			warn!("HTTP/3 masquerade task failed; closing connection: {e:?}");
			close_conn.close(0, b"");
		}
	});
	Some(Arc::new(H3Senders { uni_tx, bidi_tx, go }))
}

/// No router when the masquerade isn't compiled in.
#[cfg(not(feature = "masquerade"))]
fn spawn_h3_router<C: QuicConnection>(
	_conn: C,
	_masq: Option<MasqueradeConfig>,
	_cancel: CancellationToken,
) -> Option<Arc<H3Senders<C>>> {
	None
}

/// Route a stream the classifier decided is **not** TUIC: hand it to the h3
/// masquerade (waking the parked server), or close the connection if the
/// masquerade is off.
fn route_non_tuic<C: QuicConnection>(
	ctx: &InboundCtx<C>,
	h3: Option<&Arc<H3Senders<C>>>,
	active: &AtomicBool,
	stream: H3Stream<C>,
) {
	if let Some(s) = h3 {
		active.store(true, Ordering::Relaxed);
		match stream {
			H3Stream::Uni(recv) => {
				let _ = s.uni_tx.send(recv);
			}
			H3Stream::Bi(send, recv) => {
				let _ = s.bidi_tx.send((send, recv));
			}
		}
		s.go.notify_one();
	} else {
		drop(stream);
		ctx.conn.close(0, b"");
	}
}

/// Drive an established TUIC connection: spawn the auth-timeout guard and the
/// datagram/uni/bi accept loops, then run until the peer disconnects or
/// `cancel` fires. Backend-agnostic — both backends call this after their
/// handshake.
#[allow(clippy::too_many_arguments)]
pub async fn serve_connection<C, CB>(
	conn: C,
	remote_addr: SocketAddr,
	users: Arc<HashMap<Uuid, String>>,
	auth_timeout: Duration,
	callback: CB,
	cancel: CancellationToken,
	masq: Option<MasqueradeConfig>,
	hooks: InboundHooks,
) where
	C: QuicConnection,
	CB: InboundCallback,
{
	let conn_info = ConnInfo {
		remote_addr,
		protocol: Protocol::Tuic,
		conn_id: wind_core::hooks::next_conn_id(),
	};

	// Connection-level veto (pre-auth — no UserId yet).
	if let Some(ch) = &hooks.connection
		&& let ConnectDecision::Reject(reason) = ch.on_connect(&conn_info).await
	{
		info!("Connection from {} rejected by hook: {}", remote_addr, reason);
		conn.close(0, b"rejected");
		return;
	}

	let udp_root_cancel = cancel.child_token();

	// Eviction listener fires for both explicit `remove()` (via Dissociate) and
	// capacity/LRU pressure. Cancel the session's token so the bridge tasks
	// unstick from their channel waits and shut down promptly.
	let eviction_cancel = move |_k: Arc<u16>, v: UdpSession<C>, _cause| -> moka::notification::ListenerFuture {
		Box::pin(async move {
			v.cancel.cancel();
		})
	};
	let udp_sessions = Cache::builder()
		.max_capacity(MAX_UDP_SESSIONS_PER_CONN)
		.async_eviction_listener(eviction_cancel)
		.build();

	let connection = Arc::new(InboundCtx {
		conn,
		auth: ArcSwapOption::empty(),
		auth_notify: Arc::new(Notify::new()),
		users,
		auth_timeout,
		udp_sessions,
		udp_root_cancel,
		hooks,
		conn_info,
	});

	// Per-connection HTTP/3 masquerade router: a parked `run_masquerade` task plus
	// two channels the acceptor loops feed. `None` when masquerade is disabled.
	// `h3_active` flips true once any stream classifies as h3 so the auth-timeout
	// guard knows not to close what is actually an HTTP/3 connection.
	let h3 = spawn_h3_router(connection.conn.clone(), masq, cancel.clone());
	let h3_active = Arc::new(AtomicBool::new(false));

	// Authentication timeout: close the connection if it never authenticated AND
	// never turned out to be an HTTP/3 (masquerade) connection.
	{
		let conn_auth = connection.clone();
		let auth_cancel = cancel.clone();
		let active = h3_active.clone();
		tokio::spawn(
			async move {
				tokio::select! {
					_ = tokio::time::sleep(auth_timeout) => {
						if conn_auth.auth.load().is_none() && !active.load(Ordering::Relaxed) {
							warn!("Connection from {} authentication timeout", remote_addr);
							conn_auth.conn.close(0, b"auth timeout");
						}
					}
					_ = auth_cancel.cancelled() => {}
					_ = conn_auth.conn.closed() => {}
				}
			}
			.in_current_span(),
		);
	}

	// Per-user traffic sampler. A TUIC connection is exactly one authenticated
	// user, so the QUIC connection's own wire counters are that user's traffic.
	// Once authenticated, sample the byte counters periodically (and once more on
	// close), recording deltas against the user — no per-stream/per-packet
	// counting needed. Unauthenticated / h3-masquerade connections never bill.
	if connection.hooks.stats.is_some() {
		let ctx = connection.clone();
		let sampler_cancel = cancel.clone();
		tokio::spawn(run_traffic_sampler(ctx, sampler_cancel).in_current_span());
	}

	// One cancellation token shared by all acceptor tasks; fired after the
	// parent loop exits so `InboundCtx` (with its per-connection UDP session
	// cache) is dropped instead of leaking until server shutdown.
	let acceptor_cancel = cancel.child_token();

	// Datagram acceptor. Classify each datagram by its first two bytes: TUIC
	// datagrams (heartbeat / native-mode UDP) are handled inline pre-auth (so an
	// unauthenticated peer can't spawn unbounded tasks parked on `auth_notify`)
	// and spawned post-auth; non-TUIC datagrams are dropped — the masquerade
	// serves no QUIC datagrams.
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
							if datagram.len() < 2 || !is_tuic_prefix([datagram[0], datagram[1]]) {
								return;
							}
							if conn.auth.load().is_some() {
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

	// Uni stream acceptor. Every accepted stream reads its 2-byte prefix and
	// routes itself: TUIC (`is_tuic_prefix`) → `handle_uni_stream`, otherwise →
	// the h3 masquerade (or close). The peeked bytes are replayed via
	// `PrefixedRecv` so the chosen handler reads from byte 0.
	{
		let conn = connection.clone();
		let cb = callback.clone();
		let uni_cancel = acceptor_cancel.clone();
		let h3 = h3.clone();
		let active = h3_active.clone();
		tokio::spawn(
			async move {
				acceptor_loop(
					uni_cancel,
					"Accept uni",
					|| conn.conn.accept_uni(),
					|recv| {
						let conn = conn.clone();
						let cb = cb.clone();
						let h3 = h3.clone();
						let active = active.clone();
						async move {
							tokio::spawn(
								async move {
									let mut recv = recv;
									let Some(prefix) = read_prefix(&mut recv).await else { return };
									let recv = wind_quic::PrefixedRecv::new(bytes::Bytes::copy_from_slice(&prefix), recv);
									if is_tuic_prefix(prefix) {
										if let Err(e) = handle_uni_stream(conn, recv, cb).await {
											error!("Uni stream error: {e:?}");
										}
									} else {
										route_non_tuic(&conn, h3.as_ref(), &active, H3Stream::Uni(recv));
									}
								}
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

	// Bi stream acceptor — same per-stream classify + route.
	{
		let conn = connection.clone();
		let cb = callback.clone();
		let bi_cancel = acceptor_cancel.clone();
		let h3 = h3.clone();
		let active = h3_active.clone();
		tokio::spawn(
			async move {
				acceptor_loop(
					bi_cancel,
					"Accept bi",
					|| conn.conn.accept_bi(),
					|(send, recv)| {
						let conn = conn.clone();
						let cb = cb.clone();
						let h3 = h3.clone();
						let active = active.clone();
						async move {
							tokio::spawn(
								async move {
									let mut recv = recv;
									let Some(prefix) = read_prefix(&mut recv).await else { return };
									let recv = wind_quic::PrefixedRecv::new(bytes::Bytes::copy_from_slice(&prefix), recv);
									if is_tuic_prefix(prefix) {
										if let Err(e) = handle_bi_stream(conn, send, recv, cb).await {
											error!("Bi stream error: {e:?}");
										}
									} else {
										route_non_tuic(&conn, h3.as_ref(), &active, H3Stream::Bi(send, recv));
									}
								}
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

	// Exit on either server shutdown or peer disconnect.
	tokio::select! {
		_ = cancel.cancelled() => {
			connection.conn.close(0, b"server shutdown");
			info!("Connection from {} closed by server shutdown", remote_addr);
		}
		_ = connection.conn.closed() => {
			info!("Connection from {} closed", remote_addr);
		}
	}
	acceptor_cancel.cancel();

	// Connection lifecycle: notify the disconnect hook (user is `None` if the
	// connection never authenticated).
	if let Some(ch) = &connection.hooks.connection {
		ch.on_disconnect(&connection.conn_info, connection.user().as_ref()).await;
	}
}

/// Once authenticated, periodically sample the QUIC connection's wire byte
/// counters and record the deltas as this user's traffic. Runs until the
/// connection closes or `cancel` fires, doing a final sample on the way out.
async fn run_traffic_sampler<C: QuicConnection>(ctx: Arc<InboundCtx<C>>, cancel: CancellationToken) {
	if !ensure_authed(&ctx).await {
		return; // unauthenticated / h3 masquerade — not billed
	}
	let Some(stats) = ctx.hooks.stats.clone() else { return };
	let Some(user) = ctx.user() else { return };

	// Snap the cursor at auth time so pre-auth handshake bytes are not billed.
	let mut cursor = ctx.conn.byte_stats().await.unwrap_or((0, 0));

	let mut tick = tokio::time::interval(ctx.hooks.sample_interval);
	tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
	tick.tick().await; // consume the immediate first tick

	loop {
		tokio::select! {
			_ = tick.tick() => sample_once(&ctx, &stats, &user, &mut cursor).await,
			_ = ctx.conn.closed() => {
				sample_once(&ctx, &stats, &user, &mut cursor).await;
				break;
			}
			_ = cancel.cancelled() => {
				sample_once(&ctx, &stats, &user, &mut cursor).await;
				break;
			}
		}
	}
}

/// Read the connection's `(sent, recv)` wire counters and record the delta
/// since `cursor` as download/upload for `user`, then advance the cursor.
async fn sample_once<C: QuicConnection>(
	ctx: &Arc<InboundCtx<C>>,
	stats: &StatsCollector,
	user: &UserId,
	cursor: &mut (u64, u64),
) {
	if let Some((sent, recv)) = ctx.conn.byte_stats().await {
		let download = sent.saturating_sub(cursor.0);
		let upload = recv.saturating_sub(cursor.1);
		if upload > 0 {
			stats.record_upload(user, upload);
		}
		if download > 0 {
			stats.record_download(user, download);
		}
		*cursor = (sent, recv);
	}
}

async fn handle_uni_stream<C: QuicConnection, CB: InboundCallback>(
	ctx: Arc<InboundCtx<C>>,
	mut recv: impl AsyncRead + Unpin + Send + 'static,
	callback: CB,
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
					tracing::trace!("Received heartbeat from {:?}", ctx.user());
				}
				other => {
					warn!("Unexpected command on uni stream: {:?}", other);
				}
			}
		}
	}

	Ok(())
}

async fn handle_bi_stream<C: QuicConnection, CB: InboundCallback>(
	connection: Arc<InboundCtx<C>>,
	send: C::SendStream,
	mut recv: impl AsyncRead + Unpin + Send + 'static,
	callback: CB,
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

			if let Some(stats) = &connection.hooks.stats
				&& let Some(user) = connection.user()
			{
				stats.record_request(&user);
			}

			let stream = tokio::io::join(recv, send);

			callback.handle_tcpstream(target_addr, stream).await?;
		}
		_ => {
			warn!("Unexpected command on bi stream: {:?}", header.command);
		}
	}

	Ok(())
}

async fn handle_datagram<C: QuicConnection, CB: InboundCallback>(
	connection: Arc<InboundCtx<C>>,
	data: bytes::Bytes,
	callback: CB,
) -> eyre::Result<()> {
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

async fn handle_auth<C: QuicConnection>(connection: &InboundCtx<C>, uuid: Uuid, token: [u8; 32]) -> eyre::Result<()> {
	// Resolve the user's identity + password material via the auth hook, falling
	// back to the static user map when no hook is set. Never short-circuit on an
	// unknown UUID — that would give an attacker both a timing oracle (skipped
	// keying-material export) and an error-message oracle that reveals whether a
	// UUID exists. Always run the export against either the real password or a
	// fixed dummy and a constant-time comparison; both failure paths return the
	// same generic error.
	const DUMMY_PASSWORD: &[u8] = b"\x00\x00\x00\x00\x00\x00\x00\x00";
	let looked_up: Option<(UserId, Arc<[u8]>)> = match &connection.hooks.tuic_auth {
		Some(auth) => auth.lookup(&uuid).await,
		None => connection
			.users
			.get(&uuid)
			.map(|pw| (UserId::from(uuid), Arc::from(pw.as_bytes()))),
	};
	let (user, password_bytes, user_known): (Option<UserId>, Arc<[u8]>, bool) = match looked_up {
		Some((u, pw)) => (Some(u), pw, true),
		None => (None, Arc::from(DUMMY_PASSWORD), false),
	};

	let mut expected_token = [0u8; 32];
	let export_ok = connection
		.conn
		.export_keying_material(&mut expected_token, uuid.as_bytes(), password_bytes.as_ref())
		.await
		.is_ok();

	// Constant-time comparison: never short-circuit on first differing byte.
	let mut diff: u8 = 0;
	for (a, b) in token.iter().zip(expected_token.iter()) {
		diff |= a ^ b;
	}
	let token_ok = diff == 0;

	if !(user_known && export_ok && token_ok) {
		// Single generic error for "unknown user", "bad token", and "export
		// failed" — do not leak which one triggered.
		return Err(eyre::eyre!("Invalid authentication"));
	}
	let user = user.expect("user_known implies Some(user)");

	// Connection-management veto now that the identity is known (e.g. a per-user
	// concurrent-connection limit). A rejected connection is closed and never
	// publishes its auth state, so `ensure_authed` drops all subsequent streams.
	if let Some(ch) = &connection.hooks.connection
		&& let ConnectDecision::Reject(reason) = ch.on_authenticated(&connection.conn_info, &user).await
	{
		info!(uuid = %uuid, "authenticated user rejected by hook: {}", reason);
		connection.conn.close(0, b"rejected");
		return Ok(());
	}

	connection.auth.store(Some(Arc::new(AuthState { user: user.clone() })));
	connection.auth_notify.notify_waiters();
	info!(uuid = %uuid, user = %user, "authenticated");

	Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_udp_packet<C: QuicConnection, CB: InboundCallback>(
	ctx: &Arc<InboundCtx<C>>,
	assoc_id: u16,
	pkt_id: u16,
	frag_total: u8,
	frag_id: u8,
	target_addr: wind_core::types::TargetAddr,
	payload: bytes::Bytes,
	callback: &CB,
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
	} else if let Some(complete) = tuic_stream
		.process_fragment(assoc_id, pkt_id, frag_total, frag_id, payload, None, target_addr)
		.await
	{
		tracing::debug!(assoc_id, pkt_id, frag_total, target = %complete.target, len = complete.payload.len(), "UDP packet reassembled → outbound");
		tuic_stream.receive_packet(complete).await?;
	}

	Ok(())
}

/// Get an existing UDP session for `assoc_id` or create a new one.
async fn get_or_create_session<C: QuicConnection, CB: InboundCallback>(
	ctx: &Arc<InboundCtx<C>>,
	assoc_id: u16,
	callback: &CB,
) -> eyre::Result<Arc<UdpStream<C>>> {
	if let Some(session) = ctx.udp_sessions.get(&assoc_id).await {
		return Ok(session.tuic_stream.clone());
	}

	// New UDP association ≈ one request.
	if let Some(stats) = &ctx.hooks.stats
		&& let Some(user) = ctx.user()
	{
		stats.record_request(&user);
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

			let tuic_stream = Arc::new(UdpStream::new(conn, assoc_id, reassembled_tx));

			let outbound_stream = CoreUdpStream {
				tx: from_outbound_tx,
				rx: to_outbound_rx,
			};

			// Bridge reassembled packets -> outbound with backpressure.
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
						// session-cancel token so it exits with the rest of the
						// session instead of holding the callback's resources
						// hostage after eviction/dissociate.
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

async fn read_address_exact<R: AsyncRead + Unpin>(recv: &mut R) -> eyre::Result<crate::proto::Address> {
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

async fn handle_dissociate<C: QuicConnection>(connection: &InboundCtx<C>, assoc_id: u16) -> eyre::Result<()> {
	connection.udp_sessions.remove(&assoc_id).await;
	info!("Dissociated UDP session {}", assoc_id);
	Ok(())
}

#[cfg(test)]
mod tests {
	use std::sync::atomic::AtomicUsize;

	// Brings in Arc, Duration, Ordering, CancellationToken, QuicError, CmdType,
	// and the private helpers under test (`acceptor_loop`, `is_tuic_prefix`,
	// `read_prefix`).
	use super::*;

	/// Cancellation must interrupt an accept that is parked forever. This is
	/// the core of the graceful-shutdown chain: every per-connection acceptor
	/// loop is blocked in `accept()` when shutdown fires, and must unstick
	/// promptly without handling another item.
	#[tokio::test]
	async fn acceptor_loop_exits_when_cancelled_mid_accept() {
		let cancel = CancellationToken::new();
		let handled = Arc::new(AtomicUsize::new(0));
		let h = handled.clone();
		let loop_cancel = cancel.clone();

		let task = tokio::spawn(async move {
			acceptor_loop(
				loop_cancel,
				"test-mid-accept",
				// Never resolves: only the cancel branch can complete the loop.
				std::future::pending::<Result<(), QuicError>>,
				move |_item: ()| {
					let h = h.clone();
					async move {
						h.fetch_add(1, Ordering::SeqCst);
					}
				},
			)
			.await;
		});

		// Let the loop reach its `select!` and park on `accept()`.
		tokio::task::yield_now().await;
		cancel.cancel();

		tokio::time::timeout(Duration::from_secs(1), task)
			.await
			.expect("acceptor_loop did not exit within 1s of cancellation")
			.expect("acceptor_loop task panicked");

		assert_eq!(
			handled.load(Ordering::SeqCst),
			0,
			"no item should be handled when accept never resolves"
		);
	}

	/// A loop that is cancelled before it ever runs must exit without spinning.
	#[tokio::test]
	async fn acceptor_loop_exits_when_already_cancelled() {
		let cancel = CancellationToken::new();
		cancel.cancel();
		let handled = Arc::new(AtomicUsize::new(0));
		let h = handled.clone();

		tokio::time::timeout(
			Duration::from_secs(1),
			acceptor_loop(
				cancel,
				"test-pre-cancelled",
				std::future::pending::<Result<(), QuicError>>,
				move |_item: ()| {
					let h = h.clone();
					async move {
						h.fetch_add(1, Ordering::SeqCst);
					}
				},
			),
		)
		.await
		.expect("acceptor_loop did not exit promptly when pre-cancelled");

		assert_eq!(handled.load(Ordering::SeqCst), 0);
	}

	/// Items accepted before a benign connection close are handled, then the
	/// loop returns (it does not treat `LocallyClosed` as a fatal error nor
	/// spin).
	#[tokio::test]
	async fn acceptor_loop_handles_items_then_exits_on_benign_close() {
		let cancel = CancellationToken::new();
		let handled = Arc::new(AtomicUsize::new(0));
		let calls = Arc::new(AtomicUsize::new(0));
		let h = handled.clone();
		let c = calls.clone();

		tokio::time::timeout(
			Duration::from_secs(1),
			acceptor_loop(
				cancel,
				"test-benign-close",
				move || {
					let n = c.fetch_add(1, Ordering::SeqCst);
					async move { if n < 3 { Ok(()) } else { Err(QuicError::LocallyClosed) } }
				},
				move |_item: ()| {
					let h = h.clone();
					async move {
						h.fetch_add(1, Ordering::SeqCst);
					}
				},
			),
		)
		.await
		.expect("acceptor_loop did not terminate after a benign close");

		assert_eq!(
			handled.load(Ordering::SeqCst),
			3,
			"the three Ok items must be handled before the close ends the loop"
		);
	}

	/// `TimedOut` (idle timeout) is a benign lifecycle close: the loop returns.
	#[tokio::test]
	async fn acceptor_loop_exits_on_timed_out() {
		let cancel = CancellationToken::new();
		let handled = Arc::new(AtomicUsize::new(0));
		let h = handled.clone();

		tokio::time::timeout(
			Duration::from_secs(1),
			acceptor_loop(
				cancel,
				"test-timed-out",
				|| async { Err::<(), _>(QuicError::TimedOut) },
				move |_item: ()| {
					let h = h.clone();
					async move {
						h.fetch_add(1, Ordering::SeqCst);
					}
				},
			),
		)
		.await
		.expect("acceptor_loop did not terminate on TimedOut");

		assert_eq!(handled.load(Ordering::SeqCst), 0);
	}

	/// A non-benign error (e.g. connection lost) also ends the loop rather than
	/// retrying forever.
	#[tokio::test]
	async fn acceptor_loop_exits_on_fatal_error() {
		let cancel = CancellationToken::new();
		let handled = Arc::new(AtomicUsize::new(0));
		let h = handled.clone();

		tokio::time::timeout(
			Duration::from_secs(1),
			acceptor_loop(
				cancel,
				"test-fatal",
				|| async { Err::<(), _>(QuicError::ConnectionLost("boom".into())) },
				move |_item: ()| {
					let h = h.clone();
					async move {
						h.fetch_add(1, Ordering::SeqCst);
					}
				},
			),
		)
		.await
		.expect("acceptor_loop did not terminate on a fatal error");

		assert_eq!(handled.load(Ordering::SeqCst), 0);
	}

	/// The 2-byte classifier must accept only `[VER, CmdType]` framing and
	/// reject anything an HTTP/3 stream would start with.
	#[test]
	fn is_tuic_prefix_distinguishes_tuic_from_h3() {
		let auth = u8::from(CmdType::Auth);
		let heartbeat = u8::from(CmdType::Heartbeat);

		assert!(is_tuic_prefix([crate::proto::VER, auth]));
		assert!(is_tuic_prefix([crate::proto::VER, heartbeat]));
		// CmdType byte just past the valid range (Auth..=Heartbeat).
		assert!(!is_tuic_prefix([crate::proto::VER, heartbeat + 1]));
		// Correct command byte but wrong version byte.
		assert!(!is_tuic_prefix([crate::proto::VER.wrapping_add(1), auth]));
	}

	/// `read_prefix` yields the first two bytes, or `None` if the stream closes
	/// before two bytes arrive.
	#[tokio::test]
	async fn read_prefix_returns_two_bytes_or_none() {
		let mut full: &[u8] = &[0x05, 0x00, 0x42];
		assert_eq!(read_prefix(&mut full).await, Some([0x05, 0x00]));

		let mut short: &[u8] = &[0x05];
		assert_eq!(read_prefix(&mut short).await, None);

		let mut empty: &[u8] = &[];
		assert_eq!(read_prefix(&mut empty).await, None);
	}
}

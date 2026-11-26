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

use std::{collections::HashMap, future::Future, net::SocketAddr, sync::Arc, time::Duration};

use eyre::Context as _;
use moka::future::Cache;
use tokio::{
	io::{AsyncRead, AsyncReadExt as _},
	sync::{mpsc, watch},
};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument as _, error, info, warn};
use uuid::Uuid;
use wind_core::{
	ConnInfo, ConnectDecision, FlowContext, InboundCallback, InboundHooks, Protocol, StatsCollector, UserId,
	rule::NetworkType,
	udp::{UdpPacket, UdpStream as CoreUdpStream},
};
use wind_quic::{QuicConnection, QuicError};

use crate::{
	active::ActiveConnections,
	proto::{CmdType, Command, UdpStream},
};

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

/// Server fragment reassembly lifetime and collection interval.
#[derive(Clone, Copy, Debug)]
pub struct FragmentGc {
	pub interval: Duration,
	pub lifetime: Duration,
}
impl Default for FragmentGc {
	fn default() -> Self {
		Self {
			interval: UDP_FRAGMENT_GC_INTERVAL,
			lifetime: crate::udp::DEFAULT_FRAGMENT_TIMEOUT,
		}
	}
}
impl FragmentGc {
	pub fn validate(self) -> eyre::Result<()> {
		if self.interval.is_zero() || self.lifetime.is_zero() {
			return Err(eyre::eyre!("TUIC GC interval and lifetime must be positive"));
		}
		Ok(())
	}
}

async fn spawn_logged(label: &str, fut: impl std::future::Future<Output = eyre::Result<()>>) {
	if let Err(err) = fut.await {
		error!("{label} error: {err:?}");
	}
}

fn spawn_connection_child<F>(cancel: CancellationToken, fut: F) -> tokio::task::JoinHandle<()>
where
	F: Future<Output = ()> + Send + 'static,
{
	tokio::spawn(
		async move {
			tokio::select! {
				_ = cancel.cancelled() => {}
				_ = fut => {}
			}
		}
		.in_current_span(),
	)
}

/// Wait for the connection to be authenticated. Returns `true` once the
/// verified identity is published; returns `false` if the auth timeout elapses
/// first. Callers that get `false` must drop the request.
async fn ensure_authed<C: QuicConnection>(ctx: &InboundCtx<C>) -> bool {
	if ctx.is_authenticated() {
		return true;
	}
	let mut changes = ctx.auth.subscribe();
	let resolved = changes.wait_for(|state| matches!(state, AuthState::Authenticated(_) | AuthState::Closed(_)));
	matches!(tokio::time::timeout(ctx.auth_timeout, resolved).await, Ok(Ok(state)) if matches!(*state, AuthState::Authenticated(_)))
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
				// `ApplicationClosed`, `LocallyClosed`, and `TimedOut` are
				// normal lifecycle events; log at debug instead of error so
				// legitimate disconnects don't muddy operator logs.
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

const MAX_AUTH_ATTEMPTS: u8 = 3;

/// Complete Authenticate commands reserve a turn before any credential work.
/// Only the next turn may verify or publish an identity on this connection.
enum AuthState {
	Pending { admitted: u8, failed: u8 },
	Authenticated(UserId),
	Closed(Option<UserId>),
}

impl AuthState {
	const INITIAL: Self = Self::Pending { admitted: 0, failed: 0 };
}

struct InboundCtx<C: QuicConnection> {
	fragment_gc: FragmentGc,
	conn: C,
	/// The per-connection `conn` span (created by the backend, entered for the
	/// whole `serve_connection`). Held so `handle_auth` can record the
	/// authenticated `user` onto it, so every later per-connection log line —
	/// stream, datagram, relay — carries the user, not just the auth line.
	conn_span: tracing::Span,
	auth: watch::Sender<AuthState>,
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
	/// Stable per-inbound identifier used by `IN-NAME` routing rules.
	inbound_tag: Arc<str>,
	/// Live-connection registry for per-user limits + active kick. The
	/// connection registers itself here once authenticated and deregisters on
	/// close; `kick_user` cancels `conn_cancel` to drop it.
	active: Option<ActiveConnections>,
	/// This connection's cancel token (clone of the one driving
	/// `serve_connection`). Cancelling it closes the connection — used as the
	/// kick handle stored in `active`.
	conn_cancel: CancellationToken,
}

impl<C: QuicConnection> InboundCtx<C> {
	/// The authenticated user's identity, if the connection has authenticated.
	fn user(&self) -> Option<UserId> {
		match &*self.auth.borrow() {
			AuthState::Authenticated(user) | AuthState::Closed(Some(user)) => Some(user.clone()),
			_ => None,
		}
	}

	fn is_authenticated(&self) -> bool {
		matches!(*self.auth.borrow(), AuthState::Authenticated(_))
	}

	async fn claim_authentication(&self) -> eyre::Result<()> {
		enum Admission {
			Turn(u8),
			AlreadyAuthenticated,
			Refused,
		}
		let mut admission = Admission::Refused;
		self.auth.send_if_modified(|state| match state {
			AuthState::Pending { admitted, .. } if *admitted < MAX_AUTH_ATTEMPTS => {
				*admitted += 1;
				admission = Admission::Turn(*admitted);
				true
			}
			AuthState::Authenticated(_) => {
				admission = Admission::AlreadyAuthenticated;
				false
			}
			_ => false,
		});
		let turn = match admission {
			Admission::Turn(turn) => turn,
			Admission::AlreadyAuthenticated => {
				self.conn.close(0, b"already authenticated");
				eyre::bail!("already authenticated")
			}
			Admission::Refused => eyre::bail!("too many authentication attempts"),
		};
		let mut changes = self.auth.subscribe();
		let state = changes
			.wait_for(|state| match state {
				AuthState::Pending { failed, .. } => *failed + 1 == turn,
				_ => true,
			})
			.await?;
		match *state {
			AuthState::Pending { .. } => Ok(()),
			// An earlier turn succeeded while this command was queued.
			AuthState::Authenticated(_) => eyre::bail!("already authenticated"),
			AuthState::Closed(_) => eyre::bail!("connection closed"),
		}
	}

	fn reject_credentials(&self) {
		let mut exhausted = false;
		self.auth.send_if_modified(|state| {
			let AuthState::Pending { failed, .. } = state else {
				return false;
			};
			*failed += 1;
			exhausted = *failed == MAX_AUTH_ATTEMPTS;
			if exhausted {
				*state = AuthState::Closed(None);
			}
			true
		});
		if exhausted {
			self.conn.close(0, b"auth failed");
		}
	}

	fn publish_identity(&self, user: UserId) -> bool {
		self.auth.send_if_modified(|state| {
			if !matches!(state, AuthState::Pending { .. }) {
				return false;
			}
			// Serialize registration with teardown, including when a host auth
			// hook resumes concurrently with peer disconnect.
			if let Some(active) = &self.active {
				active.register(self.conn_info.conn_id, user.clone(), self.conn_cancel.clone());
			}
			*state = AuthState::Authenticated(user);
			true
		})
	}

	fn finish_authentication(&self) {
		let closed = self.auth.send_if_modified(|state| {
			let user = match state {
				AuthState::Closed(_) => return false,
				AuthState::Authenticated(user) => Some(user.clone()),
				AuthState::Pending { .. } => None,
			};
			*state = AuthState::Closed(user);
			true
		});
		if closed && let Some(active) = &self.active {
			active.deregister(self.conn_info.conn_id);
		}
	}

	fn close_pending_auth(&self, reason: &[u8]) -> bool {
		let closed = self.auth.send_if_modified(|state| {
			if matches!(state, AuthState::Pending { .. }) {
				*state = AuthState::Closed(None);
				return true;
			}
			false
		});
		if closed {
			self.conn.close(0, reason);
		}
		closed
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

/// How often a UDP session sweeps its fragment reassembly buffer.
///
/// The server has no GC configuration knob (unlike both client outbounds), so
/// this is a fixed period; the lifetime that actually decides eviction is
/// [`DEFAULT_FRAGMENT_TIMEOUT`](crate::udp::DEFAULT_FRAGMENT_TIMEOUT) (30 s),
/// measured per group from its last fragment. Without a tick the buffer would
/// only ever shrink under capacity pressure, so an incomplete group would stay
/// pinned for the association's lifetime.
const UDP_FRAGMENT_GC_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum H3Phase {
	#[cfg(feature = "masquerade")]
	Parked,
	Active,
}

/// Per-connection senders for the lazily-started HTTP/3 masquerade. The
/// per-stream router pushes streams it classified as h3 here; `run_masquerade`
/// (spawned parked) pulls them after the first activation. `None`
/// everywhere when the masquerade is disabled or not compiled in.
#[cfg_attr(not(feature = "masquerade"), allow(dead_code))]
struct H3Senders<C: QuicConnection> {
	uni_tx: mpsc::UnboundedSender<wind_quic::PrefixedRecv<C::RecvStream>>,
	bidi_tx: mpsc::UnboundedSender<(C::SendStream, wind_quic::PrefixedRecv<C::RecvStream>)>,
	phase: watch::Sender<H3Phase>,
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
	let (phase, activation) = watch::channel(H3Phase::Parked);
	// Run the masquerade parked. If it fails (invalid upstream URL, h3 setup
	// error) the connection would otherwise leak: a non-TUIC stream has already
	// activated the router, so the auth-timeout guard won't reap it. Log the
	// error and close the connection ourselves, mirroring that guard's
	// cleanup.
	let close_conn = conn.clone();
	tokio::spawn(async move {
		if let Err(e) = masquerade::run_masquerade(conn, uni_rx, bidi_rx, activation, cfg, cancel).await {
			warn!("HTTP/3 masquerade task failed; closing connection: {e:?}");
			close_conn.close(0, b"");
		}
	});
	Some(Arc::new(H3Senders { uni_tx, bidi_tx, phase }))
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
fn route_non_tuic<C: QuicConnection>(ctx: &InboundCtx<C>, h3: Option<&Arc<H3Senders<C>>>, stream: H3Stream<C>) {
	if let Some(s) = h3 {
		s.phase.send_if_modified(|phase| {
			let changed = *phase != H3Phase::Active;
			*phase = H3Phase::Active;
			changed
		});
		match stream {
			H3Stream::Uni(recv) => {
				let _ = s.uni_tx.send(recv);
			}
			H3Stream::Bi(send, recv) => {
				let _ = s.bidi_tx.send((send, recv));
			}
		}
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
	active: Option<ActiveConnections>,
	inbound_tag: Arc<str>,
) where
	C: QuicConnection,
	CB: InboundCallback + Clone,
{
	serve_connection_with_gc(
		conn,
		remote_addr,
		users,
		auth_timeout,
		callback,
		cancel,
		masq,
		hooks,
		active,
		inbound_tag,
		FragmentGc::default(),
	)
	.await;
}

/// Serve a TUIC connection with explicit fragment reassembly timing.
#[allow(clippy::too_many_arguments)]
pub async fn serve_connection_with_gc<C, CB>(
	conn: C,
	remote_addr: SocketAddr,
	users: Arc<HashMap<Uuid, String>>,
	auth_timeout: Duration,
	callback: CB,
	cancel: CancellationToken,
	masq: Option<MasqueradeConfig>,
	hooks: InboundHooks,
	active: Option<ActiveConnections>,
	inbound_tag: Arc<str>,
	fragment_gc: FragmentGc,
) where
	C: QuicConnection,
	CB: InboundCallback + Clone,
{
	if fragment_gc.validate().is_err() {
		conn.close(0, b"invalid GC configuration");
		return;
	}
	let conn_info = ConnInfo {
		remote_addr,
		protocol: Protocol::Tuic,
		conn_id: wind_core::hooks::next_conn_id(),
	};

	// The backend entered the per-connection `conn` span for the whole lifetime
	// of this future. Record the stable connection id onto it now (the user is
	// recorded later, on auth) so every line logged under this connection —
	// each stream, datagram, and relay — carries `id`/`user` without
	// re-stating them. Mirrors upstream tuic's `info_span!("conn", id, addr,
	// user = Empty)`.
	let conn_span = tracing::Span::current();
	conn_span.record("id", conn_info.conn_id);

	// Connection-level veto (pre-auth — no UserId yet).
	if let Some(ch) = &hooks.connection
		&& let ConnectDecision::Reject(reason) = ch.on_connect(&conn_info).await
	{
		info!("connection rejected by hook: {reason}");
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
		fragment_gc,
		conn,
		conn_span,
		auth: watch::Sender::new(AuthState::INITIAL),
		users,
		auth_timeout,
		udp_sessions,
		udp_root_cancel,
		hooks,
		conn_info,
		inbound_tag,
		active,
		conn_cancel: cancel.clone(),
	});

	// Per-connection HTTP/3 masquerade router: a parked `run_masquerade` task
	// plus two channels the acceptor loops feed. `None` when masquerade is
	// disabled. The router becomes active once any stream classifies as h3 so
	// the auth-timeout guard knows not to close what is actually an HTTP/3
	// connection.
	let h3 = spawn_h3_router(connection.conn.clone(), masq, cancel.clone());

	// Authentication timeout: close the connection if it never authenticated
	// AND never turned out to be an HTTP/3 (masquerade) connection.
	{
		let conn_auth = connection.clone();
		let auth_cancel = cancel.clone();
		let h3_phase = h3.as_ref().map(|router| router.phase.subscribe());
		tokio::spawn(
			async move {
				tokio::select! {
					_ = tokio::time::sleep(auth_timeout) => {
						if !h3_phase.as_ref().is_some_and(|phase| *phase.borrow() == H3Phase::Active)
							&& conn_auth.close_pending_auth(b"auth timeout")
						{
							warn!("authentication timeout");
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
	// Once authenticated, sample the byte counters periodically (and once more
	// on close), recording deltas against the user — no per-stream/per-packet
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
	// datagrams (heartbeat / native-mode UDP) are handled inline pre-auth (so
	// an unauthenticated peer can't spawn unbounded tasks waiting for
	// authentication) and spawned post-auth; non-TUIC datagrams are dropped —
	// the masquerade serves no QUIC datagrams.
	{
		let conn = connection.clone();
		let cb = callback.clone();
		let dg_cancel = acceptor_cancel.clone();
		let dg_task_cancel = dg_cancel.clone();
		tokio::spawn(
			async move {
				acceptor_loop(
					dg_cancel,
					"Read datagram",
					|| conn.conn.read_datagram(),
					|datagram| {
						let conn = conn.clone();
						let cb = cb.clone();
						let task_cancel = dg_task_cancel.clone();
						async move {
							if datagram.len() < 2 || !is_tuic_prefix([datagram[0], datagram[1]]) {
								return;
							}
							if conn.is_authenticated() {
								spawn_connection_child(
									task_cancel,
									spawn_logged("Datagram", handle_datagram(conn, datagram, cb)),
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
		let uni_task_cancel = uni_cancel.clone();
		let h3 = h3.clone();
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
						let task_cancel = uni_task_cancel.clone();
						async move {
							spawn_connection_child(task_cancel, async move {
								let mut recv = recv;
								let Some(prefix) = read_prefix(&mut recv).await else { return };
								let recv = wind_quic::PrefixedRecv::new(bytes::Bytes::copy_from_slice(&prefix), recv);
								if is_tuic_prefix(prefix) {
									if let Err(e) = handle_uni_stream(conn, recv, cb).await {
										error!("Uni stream error: {e:?}");
									}
								} else {
									route_non_tuic(&conn, h3.as_ref(), H3Stream::Uni(recv));
								}
							});
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
		let bi_task_cancel = bi_cancel.clone();
		let h3 = h3.clone();
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
						let task_cancel = bi_task_cancel.clone();
						async move {
							spawn_connection_child(task_cancel, async move {
								let mut recv = recv;
								let Some(prefix) = read_prefix(&mut recv).await else { return };
								let recv = wind_quic::PrefixedRecv::new(bytes::Bytes::copy_from_slice(&prefix), recv);
								if is_tuic_prefix(prefix) {
									if let Err(e) = handle_bi_stream(conn, send, recv, cb).await {
										error!("Bi stream error: {e:?}");
									}
								} else {
									route_non_tuic(&conn, h3.as_ref(), H3Stream::Bi(send, recv));
								}
							});
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
			info!("connection closed by server shutdown");
		}
		_ = connection.conn.closed() => {
			info!("connection closed");
		}
	}
	acceptor_cancel.cancel();
	connection.udp_root_cancel.cancel();
	connection.udp_sessions.invalidate_all();
	connection.udp_sessions.run_pending_tasks().await;

	connection.finish_authentication();

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

async fn handle_uni_stream<C: QuicConnection, CB: InboundCallback + Clone>(
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
			if let Command::Auth { uuid, token } = cmd
				&& let Err(e) = handle_auth(&ctx, uuid, token).await
			{
				warn!("Authentication failed: {e}");
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
					// `parse_command_body(Packet, ..)` yields only
					// `Command::Packet { .. }`, so this arm cannot be taken
					// today. It is an error return rather than a panic because
					// the bytes come from the peer: a decoder disagreement must
					// fail the media task, never abort it.
					let Command::Packet {
						assoc_id,
						pkt_id,
						frag_total,
						frag_id,
						size,
					} = cmd
					else {
						return Err(eyre::eyre!("Packet command body decoded into a different command variant"));
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
					tracing::trace!("heartbeat received");
				}
				other => {
					warn!("Unexpected command on uni stream: {:?}", other);
				}
			}
		}
	}

	Ok(())
}

async fn handle_bi_stream<C: QuicConnection, CB: InboundCallback + Clone>(
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

			let ctx = FlowContext {
				target: target_addr,
				network: NetworkType::Tcp,
				source: Some(connection.conn_info.remote_addr),
				inbound_tag: connection.inbound_tag.clone(),
				protocol: Protocol::Tuic,
				user: connection.user(),
				inbound_port: None,
				inbound_type: None,
			};

			let stream = tokio::io::join(recv, send);

			callback.handle_tcpstream(ctx, stream).await?;
		}
		_ => {
			warn!("Unexpected command on bi stream: {:?}", header.command);
		}
	}

	Ok(())
}

async fn handle_datagram<C: QuicConnection, CB: InboundCallback + Clone>(
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

/// Validate one `Authenticate` command.
///
/// A connection may retry invalid credentials within its original auth
/// deadline. TLS errors and admission vetoes are terminal. Credential failures
/// share a generic error for unknown users and incorrect tokens.
async fn handle_auth<C: QuicConnection>(connection: &InboundCtx<C>, uuid: Uuid, token: [u8; 32]) -> eyre::Result<()> {
	connection.claim_authentication().await?;

	// Resolve the user's identity + password material via the auth hook,
	// falling back to the static user map when no hook is set. Never
	// short-circuit on an unknown UUID — that would give an attacker both a
	// timing oracle (skipped keying-material export) and an error-message
	// oracle that reveals whether a UUID exists. Always run the export against
	// either the real password or a fixed dummy and a constant-time
	// comparison; both failure paths return the same generic error.
	const DUMMY_PASSWORD: &[u8] = b"\x00\x00\x00\x00\x00\x00\x00\x00";
	let looked_up: Option<(UserId, Arc<[u8]>)> = match &connection.hooks.tuic_auth {
		Some(auth) => auth.lookup(&uuid).await,
		None => connection
			.users
			.get(&uuid)
			.map(|pw| (UserId::from(uuid), Arc::from(pw.as_bytes()))),
	};
	let (user, password_bytes) = match looked_up {
		Some((user, password)) => (Some(user), password),
		None => (None, Arc::from(DUMMY_PASSWORD)),
	};

	// The exporter is bound to the completed TLS session. A connection the
	// server accepted at 0.5-RTT (`into_0rtt`) reaches this handler before the
	// handshake finishes, where backends such as rustls refuse to export. Wait
	// for the handshake first; for an already-established connection this
	// resolves immediately. A failed handshake is reported as a generic auth
	// failure so it does not leak whether the UUID exists.
	if connection.conn.authenticated().await.is_err() {
		connection.close_pending_auth(b"auth failed");
		return Err(eyre::eyre!("Invalid authentication"));
	}

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

	if !export_ok {
		connection.close_pending_auth(b"auth failed");
		return Err(eyre::eyre!("Invalid authentication"));
	}
	let Some(user) = user.filter(|_| token_ok) else {
		connection.reject_credentials();
		return Err(eyre::eyre!("Invalid authentication"));
	};

	// Connection-management veto now that the identity is known (e.g. a
	// per-user concurrent-connection limit). A rejected connection is closed
	// and never publishes its auth state, so `ensure_authed` drops all
	// subsequent streams.
	if let Some(ch) = &connection.hooks.connection
		&& let ConnectDecision::Reject(reason) = ch.on_authenticated(&connection.conn_info, &user).await
	{
		info!(uuid = %uuid, "authenticated user rejected by hook: {}", reason);
		connection.close_pending_auth(b"rejected");
		return Ok(());
	}

	if connection.publish_identity(user.clone()) {
		connection.conn_span.record("user", tracing::field::display(&user));
		info!(uuid = %uuid, "authenticated");
	}

	Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_udp_packet<C: QuicConnection, CB: InboundCallback + Clone>(
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

/// Drive one UDP session's fragment-reassembly GC.
///
/// Runs until `cancel` fires (the session's own token, so it always dies with
/// the session) or the session's `UdpStream` is gone. The weak handle matters:
/// if the session-creation future is cancelled before moka admits the entry,
/// nothing else holds the session's cancel token, and a strong handle would
/// keep both the stream and this task alive forever.
///
/// `interval` is a parameter rather than the constant directly so the
/// regression test can exercise eviction without a multi-second wait.
async fn run_udp_fragment_gc<C: QuicConnection>(
	stream: std::sync::Weak<UdpStream<C>>,
	cancel: CancellationToken,
	interval: Duration,
) {
	let mut gc_interval = tokio::time::interval(interval);
	gc_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
	gc_interval.tick().await; // The first tick resolves immediately.
	loop {
		tokio::select! {
			biased;
			_ = cancel.cancelled() => break,
			_ = gc_interval.tick() => {
				match stream.upgrade() {
					Some(stream) => stream.collect_garbage().await,
					None => break,
				}
			},
		}
	}
}

/// Get an existing UDP session for `assoc_id` or create a new one.
async fn get_or_create_session<C: QuicConnection, CB: InboundCallback + Clone>(
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

	// Session-level context: the destination is a placeholder — the dispatcher
	// stamps the first packet's real target onto it before routing (the
	// per-session routing decision is made on that packet, once).
	let udp_ctx = FlowContext {
		target: wind_core::types::TargetAddr::IPv4(std::net::Ipv4Addr::UNSPECIFIED, 0),
		network: NetworkType::Udp,
		source: Some(ctx.conn_info.remote_addr),
		inbound_tag: ctx.inbound_tag.clone(),
		protocol: Protocol::Tuic,
		user: ctx.user(),
		inbound_port: None,
		inbound_type: None,
	};

	let cb = callback.clone();
	let conn = ctx.conn.clone();
	let session_cancel = ctx.udp_root_cancel.child_token();
	let session = ctx
		.udp_sessions
		.entry(assoc_id)
		.or_insert_with(async {
			info!("Creating new UDP session for assoc_id {}", assoc_id);

			let (reassembled_tx, mut reassembled_rx) = mpsc::channel::<UdpPacket>(128);

			let (to_outbound_tx, to_outbound_rx) = mpsc::channel::<UdpPacket>(100);
			let (from_outbound_tx, mut from_outbound_rx) = mpsc::channel::<UdpPacket>(100);

			// The reply transport is not negotiated on the wire: `UdpStream`
			// keeps the datagram path only while the peer advertises DATAGRAM
			// support and otherwise falls back to one uni stream per packet, so
			// a client on stream relay (`udp_relay_mode = "quic"`) still
			// receives its replies.
			let tuic_stream =
				Arc::new(UdpStream::new(conn, assoc_id, reassembled_tx).with_gc_lifetime(ctx.fragment_gc.lifetime));

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
									Some(p) => p,
									None => break,
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

			// Fragment-reassembly GC for this session. Without it the buffer
			// only ever shrinks under capacity pressure, so an incomplete group
			// stays pinned for the association's lifetime. A weak handle keeps
			// the task from pinning the session if this insert is cancelled.
			tokio::spawn(
				run_udp_fragment_gc(Arc::downgrade(&tuic_stream), session_cancel.clone(), ctx.fragment_gc.interval)
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
							res = cb.handle_udpstream(udp_ctx, outbound_stream) => {
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
			// AddressType::Domain — 1-byte length + <length> bytes + 2-byte
			// port
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
pub(super) mod tests {
	use std::{
		future, io,
		net::Ipv4Addr,
		pin::Pin,
		sync::{
			Arc, Mutex,
			atomic::{AtomicBool, AtomicUsize, Ordering},
		},
		task::{Context, Poll},
	};

	use bytes::Bytes;
	use tokio::{
		io::{AsyncRead, AsyncWrite, ReadBuf},
		sync::Notify,
	};
	use uuid::Uuid;
	use wind_core::{ConnectionHooks, InboundCallback, TuicAuthenticator, UserId, udp::UdpStream as CoreUdpStream};
	use wind_quic::{QuicRecvStream, QuicSendStream};

	// Brings in Arc, Duration, Ordering, CancellationToken, QuicError, CmdType,
	// and the private helpers under test (`acceptor_loop`, `is_tuic_prefix`,
	// `read_prefix`).
	use super::*;

	/// Visible to the sibling `server::masquerade` test module as well.
	pub(crate) struct DummyQuicStream(tokio::io::DuplexStream);

	impl DummyQuicStream {
		fn pair() -> (Self, Self) {
			let (a, b) = tokio::io::duplex(64);
			(Self(a), Self(b))
		}
	}

	impl AsyncRead for DummyQuicStream {
		fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
			Pin::new(&mut self.0).poll_read(cx, buf)
		}
	}

	impl AsyncWrite for DummyQuicStream {
		fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
			Pin::new(&mut self.0).poll_write(cx, buf)
		}

		fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
			Pin::new(&mut self.0).poll_flush(cx)
		}

		fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
			Pin::new(&mut self.0).poll_shutdown(cx)
		}
	}

	impl QuicSendStream for DummyQuicStream {
		fn finish(&mut self) -> Result<(), QuicError> {
			Ok(())
		}

		fn reset(&mut self, _code: u64) {}

		fn id(&self) -> u64 {
			0
		}
	}

	impl QuicRecvStream for DummyQuicStream {
		fn stop(&mut self, _code: u64) {}

		fn id(&self) -> u64 {
			0
		}
	}

	/// What a [`DummyConn`] observed, for tests that need to assert on the
	/// connection-lifecycle calls the server makes.
	#[derive(Default)]
	struct ConnObservations {
		closes: Mutex<Vec<(u32, Vec<u8>)>>,
		exports: AtomicUsize,
		handshake_fails: AtomicBool,
	}

	/// Visible to the sibling `server::masquerade` test module, which drives
	/// `run_masquerade` with it.
	#[derive(Clone, Default)]
	pub(crate) struct DummyConn {
		blocked_uni: Option<CancellationToken>,
		obs: Option<Arc<ConnObservations>>,
	}

	impl DummyConn {
		#[cfg(all(feature = "client", any(feature = "quinn", feature = "quiche")))]
		pub(crate) fn with_blocked_uni(started: CancellationToken) -> Self {
			Self {
				blocked_uni: Some(started),
				..Self::default()
			}
		}

		/// A connection whose `close`/`export_keying_material` calls are
		/// recorded. The exporter yields a fixed `0xAB` token so a test can
		/// present the value the server expects.
		fn observed() -> (Self, Arc<ConnObservations>) {
			let obs = Arc::new(ConnObservations::default());
			(
				Self {
					obs: Some(obs.clone()),
					..Self::default()
				},
				obs,
			)
		}

		/// Like [`DummyConn::observed`], but the TLS handshake never completes
		/// (the 0.5-RTT case `handle_auth` waits for).
		fn observed_with_failed_handshake() -> (Self, Arc<ConnObservations>) {
			let (conn, obs) = Self::observed();
			obs.handshake_fails.store(true, Ordering::SeqCst);
			(conn, obs)
		}
	}

	impl QuicConnection for DummyConn {
		type RecvStream = DummyQuicStream;
		type SendStream = DummyQuicStream;

		async fn open_bi(&self) -> Result<(Self::SendStream, Self::RecvStream), QuicError> {
			Ok(DummyQuicStream::pair())
		}

		async fn accept_bi(&self) -> Result<(Self::SendStream, Self::RecvStream), QuicError> {
			future::pending().await
		}

		async fn open_uni(&self) -> Result<Self::SendStream, QuicError> {
			if let Some(started) = &self.blocked_uni {
				started.cancel();
				return future::pending().await;
			}
			Ok(DummyQuicStream::pair().0)
		}

		async fn accept_uni(&self) -> Result<Self::RecvStream, QuicError> {
			future::pending().await
		}

		fn send_datagram(&self, _data: bytes::Bytes) -> Result<(), QuicError> {
			Ok(())
		}

		async fn read_datagram(&self) -> Result<bytes::Bytes, QuicError> {
			future::pending().await
		}

		fn max_datagram_size(&self) -> Option<usize> {
			Some(1200)
		}

		async fn export_keying_material(&self, out: &mut [u8], _label: &[u8], _context: &[u8]) -> Result<(), QuicError> {
			if let Some(obs) = &self.obs {
				obs.exports.fetch_add(1, Ordering::SeqCst);
			}
			out.fill(0xAB);
			Ok(())
		}

		async fn authenticated(&self) -> Result<(), QuicError> {
			match &self.obs {
				Some(obs) if obs.handshake_fails.load(Ordering::SeqCst) => Err(QuicError::TimedOut),
				_ => Ok(()),
			}
		}

		fn close(&self, code: u32, reason: &[u8]) {
			if let Some(obs) = &self.obs {
				obs.closes
					.lock()
					.expect("close recorder poisoned")
					.push((code, reason.to_vec()));
			}
		}

		async fn closed(&self) {
			future::pending::<()>().await;
		}
	}

	#[derive(Clone)]
	struct HangingUdpCallback {
		started: Arc<Notify>,
		dropped: Arc<Notify>,
		was_dropped: Arc<AtomicBool>,
	}

	struct NotifyOnDrop {
		dropped: Arc<Notify>,
		was_dropped: Arc<AtomicBool>,
	}

	impl Drop for NotifyOnDrop {
		fn drop(&mut self) {
			self.was_dropped.store(true, Ordering::SeqCst);
			self.dropped.notify_waiters();
		}
	}

	#[tokio::test]
	async fn connection_child_task_is_dropped_on_cancel() {
		let cancel = CancellationToken::new();
		let dropped = Arc::new(Notify::new());
		let was_dropped = Arc::new(AtomicBool::new(false));
		let task = {
			let dropped = dropped.clone();
			let was_dropped = was_dropped.clone();
			spawn_connection_child(cancel.clone(), async move {
				let _guard = NotifyOnDrop { dropped, was_dropped };
				future::pending::<()>().await;
			})
		};

		tokio::task::yield_now().await;
		assert!(!was_dropped.load(Ordering::SeqCst));

		let dropped_notified = dropped.notified();
		cancel.cancel();
		tokio::time::timeout(Duration::from_secs(1), task)
			.await
			.expect("connection child task did not exit after cancellation")
			.expect("connection child task panicked");
		tokio::time::timeout(Duration::from_secs(1), dropped_notified)
			.await
			.expect("connection child future was not dropped");
		assert!(was_dropped.load(Ordering::SeqCst));
	}

	impl InboundCallback for HangingUdpCallback {
		#[allow(clippy::manual_async_fn)]
		fn handle_tcpstream(
			&self,
			_ctx: FlowContext,
			_stream: impl wind_core::tcp::AbstractTcpStream + 'static,
		) -> impl std::future::Future<Output = eyre::Result<()>> + Send {
			async { Ok(()) }
		}

		fn handle_udpstream(
			&self,
			_ctx: FlowContext,
			_udp_stream: CoreUdpStream,
		) -> impl std::future::Future<Output = eyre::Result<()>> + Send {
			let _guard = NotifyOnDrop {
				dropped: self.dropped.clone(),
				was_dropped: self.was_dropped.clone(),
			};
			self.started.notify_waiters();
			async move {
				let _g = _guard;
				future::pending().await
			}
		}
	}

	#[tokio::test]
	async fn udp_sessions_are_cancelled_when_connection_tears_down() {
		let udp_root_cancel = CancellationToken::new();
		let started = Arc::new(Notify::new());
		let dropped = Arc::new(Notify::new());
		let was_dropped = Arc::new(AtomicBool::new(false));
		let cb = HangingUdpCallback {
			started: started.clone(),
			dropped: dropped.clone(),
			was_dropped: was_dropped.clone(),
		};

		let eviction_cancel = move |_k: Arc<u16>, v: UdpSession<DummyConn>, _cause| -> moka::notification::ListenerFuture {
			Box::pin(async move {
				v.cancel.cancel();
			})
		};
		let ctx = Arc::new(InboundCtx {
			fragment_gc: FragmentGc {
				interval: Duration::from_millis(10),
				lifetime: Duration::from_millis(40),
			},
			conn: DummyConn::default(),
			conn_span: tracing::Span::none(),
			auth: watch::Sender::new(AuthState::Authenticated(UserId::from("test-user"))),
			users: Arc::new(HashMap::new()),
			auth_timeout: Duration::from_secs(1),
			udp_sessions: Cache::builder()
				.max_capacity(MAX_UDP_SESSIONS_PER_CONN)
				.async_eviction_listener(eviction_cancel)
				.build(),
			udp_root_cancel: udp_root_cancel.clone(),
			hooks: InboundHooks::default(),
			conn_info: ConnInfo {
				remote_addr: "127.0.0.1:12345".parse().unwrap(),
				protocol: Protocol::Tuic,
				conn_id: 1,
			},
			inbound_tag: Arc::from("test-tuic"),
			active: None,
			conn_cancel: CancellationToken::new(),
		});

		let stream = get_or_create_session(&ctx, 7, &cb).await.unwrap();
		tokio::time::timeout(Duration::from_secs(1), started.notified())
			.await
			.expect("UDP callback did not start");
		assert!(!was_dropped.load(Ordering::SeqCst));

		// Exercise the configured lifetime and interval through session
		// creation.
		let target = wind_core::types::TargetAddr::IPv4(Ipv4Addr::LOCALHOST, 9);
		assert!(
			stream
				.process_fragment(7, 1, 2, 0, Bytes::from_static(b"fragment"), None, target)
				.await
				.is_none()
		);
		assert_eq!(stream.incomplete_group_count_without_cleanup(), 1);
		tokio::time::timeout(Duration::from_secs(2), async {
			while stream.incomplete_group_count_without_cleanup() != 0 {
				tokio::time::sleep(Duration::from_millis(10)).await;
			}
		})
		.await
		.expect("configured server fragment GC must run");

		udp_root_cancel.cancel();
		ctx.udp_sessions.invalidate_all();
		ctx.udp_sessions.run_pending_tasks().await;

		tokio::time::timeout(Duration::from_secs(1), dropped.notified())
			.await
			.expect("UDP callback future was not dropped after teardown");
		assert!(was_dropped.load(Ordering::SeqCst));
	}

	/// F17/W10: the session GC task must actually evict a group that outlived
	/// the fragment lifetime. Before this, the server never ticked
	/// `collect_garbage` at all, so `DEFAULT_FRAGMENT_TIMEOUT` was dead on the
	/// server side and an incomplete group stayed pinned until the association
	/// was dissociated.
	#[tokio::test]
	async fn udp_fragment_gc_evicts_groups_past_the_fragment_lifetime() {
		let lifetime = Duration::from_millis(50);
		let (tx, _rx) = mpsc::channel::<UdpPacket>(8);
		let stream = Arc::new(UdpStream::new(DummyConn::default(), 7, tx).with_gc_lifetime(lifetime));
		let target = wind_core::types::TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

		// One fragment of two: tracked, but never completed.
		let incomplete = stream
			.process_fragment(7, 1, 2, 0, Bytes::from_static(b"AA"), None, target)
			.await;
		assert!(incomplete.is_none());
		assert_eq!(
			stream.incomplete_group_count_without_cleanup(),
			1,
			"the incomplete group must be tracked"
		);

		// Only the periodic task may evict it: the polling below never calls
		// cleanup itself, so an expired group can only disappear if the tick
		// fired.
		let cancel = CancellationToken::new();
		let gc = tokio::spawn(run_udp_fragment_gc(
			Arc::downgrade(&stream),
			cancel.clone(),
			Duration::from_millis(10),
		));

		let evicted = tokio::time::timeout(Duration::from_secs(5), async {
			while stream.incomplete_group_count_without_cleanup() != 0 {
				tokio::time::sleep(Duration::from_millis(10)).await;
			}
		})
		.await;
		cancel.cancel();
		gc.await.expect("GC task panicked");

		evicted.expect("the server-side GC never evicted a stale fragment group");
	}

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

	/// [`UdpPacket`] sink that records what the uni-stream packet path handed
	/// to the callback's outbound stream.
	#[derive(Clone)]
	struct RecordingUdpCallback {
		tx: tokio::sync::mpsc::UnboundedSender<UdpPacket>,
	}

	impl InboundCallback for RecordingUdpCallback {
		#[allow(clippy::manual_async_fn)]
		fn handle_tcpstream(
			&self,
			_ctx: FlowContext,
			_stream: impl wind_core::tcp::AbstractTcpStream + 'static,
		) -> impl std::future::Future<Output = eyre::Result<()>> + Send {
			async { Ok(()) }
		}

		fn handle_udpstream(
			&self,
			_ctx: FlowContext,
			mut udp_stream: CoreUdpStream,
		) -> impl std::future::Future<Output = eyre::Result<()>> + Send {
			let tx = self.tx.clone();
			async move {
				loop {
					let Some(packet) = udp_stream.rx.recv().await else {
						break;
					};
					if tx.send(packet).is_err() {
						break;
					}
				}
				Ok(())
			}
		}
	}

	/// W41: the uni-stream `Packet` path must forward the datagram it decoded
	/// instead of panicking. `decode_command(Packet, ..)` only ever yields
	/// `Command::Packet`, so the removed `unreachable!` was not reachable
	/// through this entry point and this test cannot distinguish the two: it
	/// drives the real `handle_uni_stream` with the exact wire bytes a client
	/// sends and pins the contract the guard now reports as an error — the
	/// command must still decode into a `Packet` and reach the callback.
	#[tokio::test]
	async fn uni_stream_packet_command_forwards_the_datagram_instead_of_panicking() {
		let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<UdpPacket>();
		let cb = RecordingUdpCallback { tx };

		// Pre-authenticated context: the packet path requires it, and the fix
		// must not disturb the forwarding itself.
		let ctx = unauthenticated_test_ctx(
			DummyConn::default(),
			Arc::new(CountingAuth {
				known: None,
				password: Arc::from(&b"pw"[..]),
				lookups: AtomicUsize::new(0),
			}),
		);
		ctx.auth.send_replace(AuthState::Authenticated(UserId::from("test-user")));
		let ctx = Arc::new(ctx);

		let payload = b"uni-stream-datagram";
		let mut bytes = vec![crate::proto::VER, u8::from(CmdType::Packet)];
		bytes.extend_from_slice(&7u16.to_be_bytes()); // assoc_id
		bytes.extend_from_slice(&1u16.to_be_bytes()); // pkt_id
		bytes.push(1); // frag_total == 1: a complete datagram
		bytes.push(0); // frag_id
		bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
		bytes.push(0x01); // AddressType::IPv4
		bytes.extend_from_slice(&[127, 0, 0, 1]);
		bytes.extend_from_slice(&8080u16.to_be_bytes());
		bytes.extend_from_slice(payload);

		let (mut writer, recv) = tokio::io::duplex(4096);
		tokio::io::AsyncWriteExt::write_all(&mut writer, &bytes)
			.await
			.expect("the duplex fixture must accept the frame");
		drop(writer);

		handle_uni_stream(ctx.clone(), recv, cb)
			.await
			.expect("a well-formed Packet command must be forwarded, not panic");

		let forwarded = tokio::time::timeout(Duration::from_secs(1), rx.recv())
			.await
			.expect("the datagram must reach the callback's outbound stream")
			.expect("the recording callback must stay alive");
		assert_eq!(forwarded.payload.as_ref(), payload.as_slice());
		assert_eq!(
			forwarded.target,
			wind_core::types::TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080)
		);

		ctx.udp_root_cancel.cancel();
		ctx.udp_sessions.invalidate_all();
		ctx.udp_sessions.run_pending_tasks().await;
	}

	/// Counting [`TuicAuthenticator`] that records the credential lookups the
	/// server performs and whether the UUID was known.
	struct CountingAuth {
		known: Option<Uuid>,
		password: Arc<[u8]>,
		lookups: AtomicUsize,
	}

	#[async_trait::async_trait]
	impl TuicAuthenticator for CountingAuth {
		async fn lookup(&self, uuid: &Uuid) -> Option<(UserId, Arc<[u8]>)> {
			self.lookups.fetch_add(1, Ordering::SeqCst);
			self.known
				.filter(|known| known == uuid)
				.map(|_| (UserId::from(*uuid), self.password.clone()))
		}
	}

	/// An unauthenticated connection context over `conn`, wired to `auth`, with
	/// a pristine auth state and attempt budget.
	fn auth_test_ctx(conn: DummyConn, auth: Arc<dyn TuicAuthenticator>) -> Arc<InboundCtx<DummyConn>> {
		Arc::new(unauthenticated_test_ctx(conn, auth))
	}

	/// The same context as [`auth_test_ctx`], additionally wired to the
	/// connection-management `connection` hooks.
	fn auth_test_ctx_with_hooks(
		conn: DummyConn,
		auth: Arc<dyn TuicAuthenticator>,
		connection: Arc<dyn ConnectionHooks>,
	) -> InboundCtx<DummyConn> {
		let mut ctx = unauthenticated_test_ctx(conn, auth);
		ctx.hooks.connection = Some(connection);
		ctx
	}

	/// The same context as [`auth_test_ctx`], but unwrapped so a test can seed
	/// the auth state before sharing it.
	fn unauthenticated_test_ctx(conn: DummyConn, auth: Arc<dyn TuicAuthenticator>) -> InboundCtx<DummyConn> {
		InboundCtx {
			fragment_gc: FragmentGc::default(),
			conn,
			conn_span: tracing::Span::none(),
			auth: watch::Sender::new(AuthState::INITIAL),
			users: Arc::new(HashMap::new()),
			auth_timeout: Duration::from_secs(1),
			udp_sessions: Cache::builder().max_capacity(MAX_UDP_SESSIONS_PER_CONN).build(),
			udp_root_cancel: CancellationToken::new(),
			hooks: InboundHooks {
				tuic_auth: Some(auth),
				..InboundHooks::default()
			},
			conn_info: ConnInfo {
				remote_addr: "127.0.0.1:12345".parse().unwrap(),
				protocol: Protocol::Tuic,
				conn_id: 1,
			},
			inbound_tag: Arc::from("test-tuic"),
			active: None,
			conn_cancel: CancellationToken::new(),
		}
	}

	#[tokio::test]
	async fn disconnect_serializes_with_identity_publication() {
		let auth = Arc::new(CountingAuth {
			known: None,
			password: Arc::from([]),
			lookups: AtomicUsize::new(0),
		});
		let user = UserId::from("test-user");
		for publish_first in [false, true] {
			let active = ActiveConnections::new();
			let mut ctx = unauthenticated_test_ctx(DummyConn::default(), auth.clone());
			ctx.active = Some(active.clone());
			ctx.claim_authentication().await.unwrap();
			if publish_first {
				assert!(ctx.publish_identity(user.clone()));
				assert_eq!(active.count_for(&user), 1);
			}
			ctx.finish_authentication();
			assert!(!ctx.publish_identity(user.clone()));
			assert_eq!(active.count_for(&user), 0);
			assert_eq!(ctx.user(), publish_first.then(|| user.clone()));
			assert!(!ensure_authed(&ctx).await);
		}
	}

	#[tokio::test]
	async fn auth_attempt_budget_bounds_lookups_per_connection() {
		let (conn, obs) = DummyConn::observed();
		let uuid = Uuid::new_v4();
		let auth = Arc::new(CountingAuth {
			known: Some(uuid),
			password: Arc::from(&b"pw"[..]),
			lookups: AtomicUsize::new(0),
		});
		let ctx = auth_test_ctx(conn, auth.clone());

		// Unknown users and bad tokens consume the same budget, even when
		// the unknown user happens to supply the dummy exporter's token.
		for (index, (id, token)) in [(Uuid::new_v4(), [0xAB; 32]), (uuid, [0xFF; 32]), (Uuid::new_v4(), [0xFF; 32])]
			.into_iter()
			.enumerate()
		{
			let err = handle_auth(&ctx, id, token).await.unwrap_err();
			assert_eq!(err.to_string(), "Invalid authentication");
			assert_eq!(auth.lookups.load(Ordering::SeqCst), index + 1);
			assert_eq!(obs.exports.load(Ordering::SeqCst), index + 1);
			assert!(ctx.user().is_none());
			assert_eq!(obs.closes.lock().unwrap().len(), usize::from(index == 2));
		}

		assert!(!ensure_authed(&ctx).await);
		assert!(handle_auth(&ctx, uuid, [0xAB; 32]).await.is_err());
		assert_eq!(auth.lookups.load(Ordering::SeqCst), 3);
		assert_eq!(obs.exports.load(Ordering::SeqCst), 3);
		assert_eq!(*obs.closes.lock().unwrap(), [(0, b"auth failed".to_vec())]);
	}

	#[tokio::test]
	async fn auth_retries_can_succeed_on_the_second_or_third_attempt() {
		let uuid = Uuid::new_v4();
		let auth = Arc::new(CountingAuth {
			known: Some(uuid),
			password: Arc::from(&b"pw"[..]),
			lookups: AtomicUsize::new(0),
		});
		for failures in [1, 2] {
			let (conn, obs) = DummyConn::observed();
			let ctx = auth_test_ctx(conn, auth.clone());
			let (released, result) = tokio::join!(
				biased;
				ensure_authed(&ctx),
				async {
					for _ in 0..failures {
						assert!(handle_auth(&ctx, uuid, [0xFF; 32]).await.is_err());
						assert!(!ctx.is_authenticated());
					}
					handle_auth(&ctx, uuid, [0xAB; 32]).await
				}
			);
			result.unwrap();
			assert!(released);
			assert_eq!(ctx.user(), Some(UserId::from(uuid)));
			assert!(obs.closes.lock().unwrap().is_empty());
			assert_eq!(obs.exports.load(Ordering::SeqCst), failures + 1);
		}
	}

	#[tokio::test]
	async fn pipelined_auth_commands_preserve_the_last_admitted_attempt() {
		let (conn, obs) = DummyConn::observed();
		let uuid = Uuid::new_v4();
		let auth = Arc::new(CountingAuth {
			known: Some(uuid),
			password: Arc::from(&b"pw"[..]),
			lookups: AtomicUsize::new(0),
		});
		let ctx = auth_test_ctx(conn, auth.clone());
		// Hold the first turn as if its lookup were still running.
		ctx.claim_authentication().await.unwrap();
		let mut second = std::pin::pin!(handle_auth(&ctx, uuid, [0xFF; 32]));
		let mut third = std::pin::pin!(handle_auth(&ctx, uuid, [0xAB; 32]));
		assert!(futures_util::poll!(&mut second).is_pending());
		assert!(futures_util::poll!(&mut third).is_pending());
		assert!(handle_auth(&ctx, uuid, [0xAB; 32]).await.is_err());
		assert_eq!(auth.lookups.load(Ordering::SeqCst), 0);
		assert!(obs.closes.lock().unwrap().is_empty());

		ctx.reject_credentials();
		assert!(second.await.is_err());
		third.await.unwrap();
		assert_eq!(ctx.user(), Some(UserId::from(uuid)));
		assert_eq!(auth.lookups.load(Ordering::SeqCst), 2);
		assert_eq!(obs.exports.load(Ordering::SeqCst), 2);
		assert!(obs.closes.lock().unwrap().is_empty());
	}

	/// A failed TLS handshake is terminal even on the first attempt.
	#[tokio::test]
	async fn auth_before_the_handshake_completes_closes_the_connection() {
		let (conn, obs) = DummyConn::observed_with_failed_handshake();
		let uuid = Uuid::new_v4();
		let auth = Arc::new(CountingAuth {
			known: Some(uuid),
			password: Arc::from(&b"pw"[..]),
			lookups: AtomicUsize::new(0),
		});
		let ctx = auth_test_ctx(conn, auth.clone());

		// The lookup still happens (it precedes the handshake wait), and the
		// error stays generic so it does not reveal whether the UUID exists.
		let err = handle_auth(&ctx, uuid, [0xAB; 32])
			.await
			.expect_err("an incomplete handshake must fail auth");
		assert_eq!(err.to_string(), "Invalid authentication");
		assert!(!ctx.is_authenticated(), "a failed handshake must not publish an identity");
		assert_eq!(auth.lookups.load(Ordering::SeqCst), 1);

		let closes = obs.closes.lock().expect("close recorder poisoned");
		assert_eq!(closes.len(), 1, "the connection must be closed exactly once");
		assert_eq!(closes[0], (0, b"auth failed".to_vec()));
	}

	#[tokio::test]
	async fn auth_hook_rejection_ends_retries_and_releases_waiters() {
		struct RejectUser;
		#[async_trait::async_trait]
		impl ConnectionHooks for RejectUser {
			async fn on_authenticated(&self, _info: &ConnInfo, _user: &UserId) -> ConnectDecision {
				ConnectDecision::Reject("connection limit".into())
			}
		}

		let (conn, obs) = DummyConn::observed();
		let uuid = Uuid::new_v4();
		let auth = Arc::new(CountingAuth {
			known: Some(uuid),
			password: Arc::from(&b"pw"[..]),
			lookups: AtomicUsize::new(0),
		});
		let ctx = auth_test_ctx_with_hooks(conn, auth.clone(), Arc::new(RejectUser));
		assert!(handle_auth(&ctx, uuid, [0xFF; 32]).await.is_err());
		let (allowed, _) = tokio::join!(biased; ensure_authed(&ctx), handle_auth(&ctx, uuid, [0xAB; 32]));
		assert!(!allowed);
		assert!(handle_auth(&ctx, uuid, [0xAB; 32]).await.is_err());
		assert!(ctx.user().is_none());
		assert_eq!(auth.lookups.load(Ordering::SeqCst), 2);
		assert_eq!(*obs.closes.lock().unwrap(), [(0, b"rejected".to_vec())]);
	}

	/// [`ConnectionHooks`] implementation that counts the lifecycle callbacks
	/// the server makes, so a test can pin how often the `on_authenticated`
	/// connection-management veto is asked.
	struct CountingConnectionHooks {
		authenticated: AtomicUsize,
	}

	#[async_trait::async_trait]
	impl ConnectionHooks for CountingConnectionHooks {
		async fn on_authenticated(&self, _info: &ConnInfo, _user: &UserId) -> ConnectDecision {
			self.authenticated.fetch_add(1, Ordering::SeqCst);
			tokio::task::yield_now().await;
			ConnectDecision::Accept
		}
	}

	/// W44: a repeated `Authenticate` on an already-authenticated connection
	/// must not re-enter the connection-management hook (`on_authenticated`),
	/// re-run the credential lookup, or republish the identity.
	#[tokio::test]
	async fn auth_on_an_already_authenticated_connection_is_refused() {
		let (conn, obs) = DummyConn::observed();
		let uuid = Uuid::new_v4();
		let auth = Arc::new(CountingAuth {
			known: Some(uuid),
			password: Arc::from(&b"pw"[..]),
			lookups: AtomicUsize::new(0),
		});
		let hooks = Arc::new(CountingConnectionHooks {
			authenticated: AtomicUsize::new(0),
		});
		let ctx = auth_test_ctx_with_hooks(conn, auth.clone(), hooks.clone());

		// First attempt: `DummyConn::observed` exports a fixed `0xAB` token.
		handle_auth(&ctx, uuid, [0xAB; 32])
			.await
			.expect("the token must match the mock exporter");
		assert_eq!(
			hooks.authenticated.load(Ordering::SeqCst),
			1,
			"auth publishes the identity once"
		);
		let published = ctx.user().expect("a successful auth publishes the identity");

		// Same credentials again on the same connection: the identity is
		// already published, so this must not authenticate a second
		// time.
		let err = handle_auth(&ctx, uuid, [0xAB; 32])
			.await
			.expect_err("a repeated Authenticate must be refused");
		assert_eq!(err.to_string(), "already authenticated");
		assert_eq!(
			auth.lookups.load(Ordering::SeqCst),
			1,
			"a repeated Authenticate must not reach the authenticator again"
		);
		assert_eq!(
			obs.exports.load(Ordering::SeqCst),
			1,
			"a repeated Authenticate must not run another keying-material export"
		);
		assert_eq!(
			hooks.authenticated.load(Ordering::SeqCst),
			1,
			"on_authenticated must not fire twice for one connection"
		);
		assert_eq!(ctx.user(), Some(published), "the published identity must not change");

		let closes = obs.closes.lock().expect("close recorder poisoned");
		assert_eq!(closes.len(), 1, "the repeated attempt terminates the connection");
		assert_eq!(closes[0], (0, b"already authenticated".to_vec()));
	}

	/// Concurrent valid commands may publish an identity and run the hook only
	/// once.
	#[tokio::test]
	async fn concurrent_duplicate_auth_commands_authenticate_exactly_once() {
		let (conn, obs) = DummyConn::observed();
		let uuid = Uuid::new_v4();
		let auth = Arc::new(CountingAuth {
			known: Some(uuid),
			password: Arc::from(&b"pw"[..]),
			lookups: AtomicUsize::new(0),
		});
		let hooks = Arc::new(CountingConnectionHooks {
			authenticated: AtomicUsize::new(0),
		});
		let ctx = auth_test_ctx_with_hooks(conn, auth.clone(), hooks.clone());
		let mut first = std::pin::pin!(handle_auth(&ctx, uuid, [0xAB; 32]));
		let mut second = std::pin::pin!(handle_auth(&ctx, uuid, [0xAB; 32]));
		assert!(futures_util::poll!(&mut first).is_pending());
		assert!(futures_util::poll!(&mut second).is_pending());
		first.await.unwrap();
		assert_eq!(second.await.unwrap_err().to_string(), "already authenticated");
		assert_eq!(
			auth.lookups.load(Ordering::SeqCst),
			1,
			"only one attempt may reach the authenticator"
		);
		assert_eq!(
			obs.exports.load(Ordering::SeqCst),
			1,
			"only one attempt may run the keying-material export"
		);
		assert_eq!(
			hooks.authenticated.load(Ordering::SeqCst),
			1,
			"on_authenticated must fire exactly once for one connection"
		);
		assert!(ctx.is_authenticated(), "the winning attempt publishes the identity");

		assert!(
			obs.closes.lock().unwrap().is_empty(),
			"a queued attempt preserves the winning connection"
		);
	}

	/// A correct token must still authenticate on its first attempt and must
	/// not trip the new terminal paths.
	#[tokio::test]
	async fn successful_auth_publishes_identity_and_does_not_close() {
		let (conn, obs) = DummyConn::observed();
		let uuid = Uuid::new_v4();
		let auth = Arc::new(CountingAuth {
			known: Some(uuid),
			password: Arc::from(&b"pw"[..]),
			lookups: AtomicUsize::new(0),
		});
		let ctx = auth_test_ctx(conn, auth.clone());

		// Start both waiters before publishing, then check a late arrival as
		// well.
		let (first, second, result) = tokio::join!(
			biased;
			ensure_authed(&ctx),
			ensure_authed(&ctx),
			handle_auth(&ctx, uuid, [0xAB; 32]),
		);
		result.expect("the token must match the mock exporter");
		assert!(first && second && ensure_authed(&ctx).await);

		assert!(ctx.is_authenticated(), "a successful auth publishes the identity");
		assert_eq!(auth.lookups.load(Ordering::SeqCst), 1);
		assert!(
			obs.closes.lock().expect("close recorder poisoned").is_empty(),
			"a successful auth must not close the connection"
		);
	}
}

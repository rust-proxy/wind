use std::{
	future::Future,
	net::{Ipv4Addr, Ipv6Addr, SocketAddr},
	pin::Pin,
	sync::{Arc, atomic::AtomicU16},
	time::Duration,
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use moka::future::Cache;
use quinn::TokioRuntime;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument as _, info, warn};
use uuid::Uuid;
use wind_core::{AppContext, FlowContext, Outbound, tcp::AbstractTcpStream, types::TargetAddr};
use wind_quic::quinn::{QuinnConnection, QuinnRecv, QuinnSend};

use crate::{
	Error,
	client::{
		association::{self, AssociationOptions},
		session::{SessionTransition, run_session},
	},
	proto::{ClientProtoExt, UdpRelayMode, UdpStream as TuicUdpStream, open_connect_stream},
	quinn::utils::{CongestionControl, congestion_controller_factory},
};

/// Creates the local UDP socket the QUIC endpoint binds to.
///
/// Wind calls the factory with the peer address the endpoint will dial, so
/// the caller can select the matching address family and skip interface
/// binding for loopback peers. This lets a consumer apply platform socket
/// options (for example Linux `SO_MARK` or bind-to-device) or bind a chosen
/// interface before quinn takes ownership of the socket.
pub type UdpSocketFactory = Arc<dyn Fn(SocketAddr) -> std::io::Result<std::net::UdpSocket> + Send + Sync + 'static>;

/// Resolves the server's current socket address before a reconnect attempt.
///
/// Supplied by a consumer that owns DNS resolution (e.g. clash-rs) so a
/// domain-configured peer follows DNS rotation, failover, or record changes
/// instead of pinning the address resolved when the outbound was built. It is
/// only consulted on reconnect; the initial connection uses `peer_addr`. The
/// error is only logged, so it is intentionally dependency-free.
pub type PeerResolver =
	Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<SocketAddr, String>> + Send>> + Send + Sync + 'static>;

#[derive(Clone)]
pub struct TuicOutboundOpts {
	pub peer_addr: SocketAddr,
	/// Optional resolver consulted before each reconnect attempt so a
	/// domain-configured peer can follow DNS changes / address rotation.
	///
	/// When `None` (or when it returns an error), the last known peer address
	/// is reused. The initial connection always uses `peer_addr`.
	pub peer_resolver: Option<PeerResolver>,
	pub sni: String,
	pub auth: (Uuid, Arc<[u8]>),
	pub zero_rtt_handshake: bool,
	pub heartbeat: Duration,
	pub gc_interval: Duration,
	pub gc_lifetime: Duration,
	pub skip_cert_verify: bool,
	pub alpn: Vec<String>,
	/// Automatic reconnect behaviour for the outbound connection.
	pub reconnect: ReconnectConfig,
	/// Prebuilt rustls client configuration. When `Some` it is used verbatim
	/// instead of the built-in [`super::tls::tls_config`], so a consumer can
	/// keep its own certificate verifier, mTLS client certificate, ALPN list,
	/// and SNI policy.
	pub client_config: Option<Arc<rustls::ClientConfig>>,
	/// QUIC congestion controller.
	pub congestion_control: CongestionControl,
	/// Maximum concurrent bidirectional streams; `None` keeps quinn's default.
	pub max_concurrent_bi_streams: Option<u32>,
	/// Maximum concurrent unidirectional streams; `None` keeps quinn's
	/// default.
	pub max_concurrent_uni_streams: Option<u32>,
	/// Transport send window (bytes); `None` keeps quinn's default.
	pub send_window: Option<u64>,
	/// Per-stream receive window (bytes); `None` keeps quinn's default.
	pub stream_receive_window: Option<u64>,
	/// Maximum idle time before the connection is closed; `None` keeps quinn's
	/// default.
	pub max_idle_time: Option<Duration>,
	/// How outgoing `Packet` commands are relayed (datagram vs uni stream).
	pub udp_relay_mode: UdpRelayMode,
	/// Optional factory for the local UDP socket used by the QUIC endpoint.
	///
	/// When `Some`, Wind hands the returned socket to quinn instead of binding
	/// its own, letting the caller pre-apply platform socket options or bind a
	/// specific interface. When `None`, Wind binds an ephemeral socket on the
	/// unspecified address matching the peer's address family.
	pub socket_factory: Option<UdpSocketFactory>,
}

/// Optional Quinn packetization tuning. None preserves backend defaults.
#[derive(Clone, Debug, Default)]
pub struct QuinnTransportOptions {
	pub initial_mtu: Option<u16>,
	pub min_mtu: Option<u16>,
	pub gso: Option<bool>,
	pub pmtu: Option<bool>,
}
impl QuinnTransportOptions {
	fn apply(&self, transport: &mut quinn::TransportConfig) -> eyre::Result<()> {
		if self.initial_mtu.is_some_and(|v| v < 1200) || self.min_mtu.is_some_and(|v| v < 1200) {
			return Err(eyre::eyre!("QUIC MTU must be at least 1200"));
		}
		if let Some(v) = self.initial_mtu {
			transport.initial_mtu(v);
		}
		if let Some(v) = self.min_mtu {
			transport.min_mtu(v);
		}
		if let Some(v) = self.gso {
			transport.enable_segmentation_offload(v);
		}
		if let Some(v) = self.pmtu {
			transport.mtu_discovery_config(v.then(Default::default));
		}
		Ok(())
	}
}

/// Controls how the outbound supervisor re-establishes the QUIC connection
/// after it drops.
#[derive(Clone, Debug)]
pub struct ReconnectConfig {
	/// When `false`, a dropped connection is not re-established — the
	/// supervisor closes it and exits (the pre-reconnect behaviour). When
	/// `true`, it retries with exponential backoff until it succeeds or the
	/// client shuts down.
	pub enabled: bool,
	/// Delay before the first reconnect attempt; doubled after each failure.
	/// Must be positive: a zero delay never grows and would turn the reconnect
	/// supervisor into a busy loop.
	pub initial_backoff: Duration,
	/// Upper bound on the backoff delay. Must be positive, otherwise every
	/// delay is clamped to zero.
	pub max_backoff: Duration,
}

impl Default for ReconnectConfig {
	fn default() -> Self {
		Self {
			enabled: true,
			initial_backoff: Duration::from_millis(500),
			max_backoff: Duration::from_secs(30),
		}
	}
}

pub struct TuicOutbound {
	pub ctx: Arc<AppContext>,
	pub endpoint: quinn::Endpoint,
	pub peer_addr: SocketAddr,
	pub sni: String,
	pub opts: TuicOutboundOpts,
	/// The live QUIC connection, swappable so the reconnect supervisor can
	/// replace it after a drop without callers holding a stale handle. Read
	/// sites `load_full()` the current connection per operation.
	pub connection: Arc<ArcSwap<QuinnConnection>>,
	pub udp_assoc_counter: AtomicU16,
	pub token: CancellationToken,
	pub udp_session: Cache<u16, Arc<TuicUdpStream<QuinnConnection>>>,
}

impl TuicOutbound {
	pub async fn new(ctx: Arc<AppContext>, opts: TuicOutboundOpts) -> Result<Self, Error> {
		Self::new_with_transport(ctx, opts, QuinnTransportOptions::default()).await
	}

	/// Create an outbound with explicit packetization settings, preserved
	/// across reconnects.
	pub async fn new_with_transport(
		ctx: Arc<AppContext>,
		opts: TuicOutboundOpts,
		transport: QuinnTransportOptions,
	) -> Result<Self, Error> {
		let peer_addr = opts.peer_addr;
		let server_name = opts.sni.clone();

		// Install the rustls default crypto provider EXACTLY ONCE per process.
		// `install_default` returns `Err` after the first call (the global is
		// already set), which we previously swallowed via `let _ = ...` on
		// every single `TuicOutbound::new`. `OnceLock::get_or_init` is the
		// canonical race-free single-init primitive.
		static PROVIDER_INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
		PROVIDER_INSTALLED.get_or_init(|| {
			#[cfg(feature = "aws-lc-rs")]
			let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
			#[cfg(feature = "ring")]
			let _ = rustls::crypto::ring::default_provider().install_default();
		});
		info!(target: "tuic_out", "Creating a new outbound");
		// `gc_interval`/`gc_lifetime` feed `tokio::time::interval` and the
		// fragment buffer's per-group lifetime. A zero interval would panic on
		// construction and a zero lifetime would expire every incomplete group
		// before it can be reassembled, so both are rejected up front.
		if opts.gc_interval.is_zero() {
			return Err(eyre::eyre!("TUIC GC interval must be positive"));
		}
		if opts.gc_lifetime.is_zero() {
			return Err(eyre::eyre!("TUIC GC lifetime must be positive"));
		}
		// Reject a zero backoff before binding a socket or dialing: the
		// supervisor would otherwise re-dial in a hot loop instead of waiting.
		validate_reconnect(&opts.reconnect)?;
		let client_config = {
			// A caller-supplied config wins: it may carry a custom verifier,
			// mTLS material, ALPN list, or SNI policy the built-in config
			// cannot express.
			let tls_config = match &opts.client_config {
				Some(cfg) => (**cfg).clone(),
				None => super::tls::tls_config(&server_name, &opts)?,
			};

			let mut client_config = quinn::ClientConfig::new(Arc::new(
				quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
					.map_err(|e| eyre::eyre!("Failed to build QUIC client config: {e}"))?,
			));
			let mut transport_config = quinn::TransportConfig::default();
			transport.apply(&mut transport_config)?;
			transport_config
				.congestion_controller_factory(congestion_controller_factory(opts.congestion_control))
				.keep_alive_interval(None);
			if let Some(v) = opts.max_concurrent_bi_streams {
				transport_config.max_concurrent_bidi_streams(v.into());
			}
			if let Some(v) = opts.max_concurrent_uni_streams {
				transport_config.max_concurrent_uni_streams(v.into());
			}
			if let Some(v) = opts.send_window {
				transport_config.send_window(v);
			}
			if let Some(v) = opts.stream_receive_window {
				transport_config.stream_receive_window(
					quinn::VarInt::from_u64(v)
						.map_err(|_| eyre::eyre!("stream_receive_window {v} exceeds the QUIC VarInt range"))?,
				);
			}
			if let Some(v) = opts.max_idle_time {
				transport_config.max_idle_timeout(Some(
					quinn::IdleTimeout::try_from(v).map_err(|_| eyre::eyre!("invalid max_idle_time {v:?}"))?,
				));
			}

			client_config.transport_config(Arc::new(transport_config));
			client_config
		};
		// The caller may supply the socket (e.g. to set Linux `SO_MARK` or bind
		// an interface) so policy routing and TUN setups keep working.
		// Otherwise bind the local socket in the same address family as the
		// peer: a quinn endpoint bound to 0.0.0.0 cannot dial an IPv6 peer --
		// `connect` returns `InvalidRemoteAddress` -- so an IPv6 server
		// (`[::1]:8444`) was unreachable when we always bound IPv4.
		let socket = bind_endpoint_socket(peer_addr, opts.socket_factory.as_ref())
			.await
			.map_err(|e| eyre::eyre!("Failed to create UDP socket for {}: {}", peer_addr, e))?;

		let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, Arc::new(TokioRuntime))?;
		endpoint.set_default_client_config(client_config);

		// Establish and authenticate the initial connection. The reconnect
		// supervisor reuses the same configured endpoint via
		// `connect_and_auth`.
		let connection = connect_and_auth(&endpoint, peer_addr, &server_name, &opts.auth, opts.zero_rtt_handshake).await?;

		Ok(Self {
			token: ctx.token.child_token(),
			ctx,
			endpoint,
			peer_addr,
			sni: server_name,
			opts,
			connection: Arc::new(ArcSwap::from_pointee(connection)),
			udp_assoc_counter: AtomicU16::new(0),
			udp_session: Cache::new(u64::from(u16::MAX) + 1),
		})
	}

	pub async fn start_poll(&self) -> eyre::Result<()> {
		let shutdown = self.ctx.token.child_token();
		let connection_cell = self.connection.clone();
		let endpoint = self.endpoint.clone();
		let peer_addr = self.peer_addr;
		let sni = self.sni.clone();
		let auth = self.opts.auth.clone();
		let heartbeat = self.opts.heartbeat;
		let zero_rtt = self.opts.zero_rtt_handshake;
		let reconnect = self.opts.reconnect.clone();
		let peer_resolver = self.opts.peer_resolver.clone();
		let socket_factory = self.opts.socket_factory.clone();
		let ctx = self.ctx.clone();
		let udp_session = self.udp_session.clone();

		// Connection supervisor: run one session (heartbeat + incoming
		// handling) over the live connection until it drops or we shut down.
		// On an unexpected drop, reconnect with backoff and swap the fresh
		// connection into `connection_cell` so `handle_tcp` / `handle_udp`
		// transparently use it. In-flight streams on the old connection are
		// NOT resurrected — callers see them close and retry, getting new
		// streams on the new connection.
		let supervisor = async move {
			loop {
				let conn = connection_cell.load_full().as_ref().clone();

				match run_session(&ctx, &conn, &udp_session, heartbeat, &shutdown, reconnect.enabled, peer_addr).await {
					SessionTransition::Shutdown | SessionTransition::StopAfterLoss => return eyre::Ok(()),
					SessionTransition::Reconnect => {}
				}

				match reconnect_loop(
					&endpoint,
					peer_addr,
					peer_resolver.as_ref(),
					&sni,
					&auth,
					zero_rtt,
					socket_factory.as_ref(),
					&reconnect,
					&shutdown,
				)
				.await
				{
					Some(new_conn) => {
						connection_cell.store(Arc::new(new_conn));
						info!(target: "tuic_out", "Reconnected to {}", peer_addr);
					}
					// Cancelled while backing off.
					None => return eyre::Ok(()),
				}
			}
		};
		self.ctx.tasks.spawn(supervisor.in_current_span());

		Ok(())
	}

	/// Open a TUIC TCP stream to `target`.
	///
	/// Opens a bidirectional QUIC stream, writes the `Connect` command header,
	/// and returns the joined stream for the caller to relay. This is the raw
	/// half of [`Outbound::handle_tcp`], exposed so a consumer that owns its
	/// own dispatcher (e.g. clash-rs) can reuse the connection supervisor
	/// without adopting wind's `Outbound` control flow.
	pub async fn connect_tcp(&self, target: &TargetAddr) -> Result<tokio::io::Join<QuinnRecv, QuinnSend>, Error> {
		let connection = self.connection.load_full();
		let (send, recv) = open_connect_stream(connection.as_ref(), target).await?;
		Ok(tokio::io::join(recv, send))
	}
}


/// Bind the local UDP socket the QUIC endpoint uses to reach `peer`.
///
/// Prefers the caller's [`UdpSocketFactory`] so platform socket options
/// (interface binding, Linux `SO_MARK`) are applied. Otherwise binds an
/// ephemeral socket on the unspecified address matching the peer's family:
/// a quinn endpoint bound to `0.0.0.0` cannot dial an IPv6 peer.
async fn bind_endpoint_socket(peer: SocketAddr, factory: Option<&UdpSocketFactory>) -> std::io::Result<std::net::UdpSocket> {
	match factory {
		Some(factory) => factory(peer),
		None => {
			let socket_addr = if peer.is_ipv6() {
				SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
			} else {
				SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
			};
			Ok(UdpSocket::bind(socket_addr).await?.into_std()?)
		}
	}
}

/// Whether `peer`'s address family differs from the endpoint's local socket,
/// meaning the endpoint must be rebound before dialing `peer` (quinn rejects
/// an IPv6 peer on an IPv4 socket).
fn peer_family_differs(local: SocketAddr, peer: SocketAddr) -> bool {
	local.is_ipv6() != peer.is_ipv6()
}

/// Open a fresh QUIC connection on `endpoint` and complete the TUIC auth
/// handshake. Shared by initial connect ([`TuicOutbound::new`]) and reconnect.
async fn connect_and_auth(
	endpoint: &quinn::Endpoint,
	peer_addr: SocketAddr,
	sni: &str,
	auth: &(Uuid, Arc<[u8]>),
	zero_rtt: bool,
) -> Result<QuinnConnection, Error> {
	let connecting = endpoint
		.connect(peer_addr, sni)
		.map_err(|e| eyre::eyre!("Failed to connect to {} ({}): {}", peer_addr, sni, e))?;

	// A resumed session lets quinn send 0-RTT early data. The TUIC auth token
	// is derived from the TLS keying-material exporter, which rustls only
	// exposes once the handshake completes, so the auth command itself cannot
	// be early data: take the 0-RTT connection handle, wait for the handshake,
	// then authenticate over 1-RTT. A server that rejects 0-RTT still completes
	// the handshake, so the fallback is transparent.
	let raw = if zero_rtt {
		match connecting.into_0rtt() {
			Ok(conn) => {
				conn.authenticated().await?;
				info!(target: "tuic_out", "0-RTT resumption accepted");
				conn
			}
			// No cached session ticket (e.g. the very first connection) — fall
			// back to a full 1-RTT handshake.
			Err(connecting) => connecting.await?,
		}
	} else {
		connecting.await?
	};

	// Wrap in the backend-agnostic handle so the shared client/proto code
	// (auth, heartbeat, TCP/UDP relay) drives it.
	let connection = QuinnConnection::new(raw);
	connection.send_auth(&auth.0, &auth.1).await?;
	Ok(connection)
}

/// Next exponential-backoff delay: doubling never grows a zero delay, so a
/// zero `current` is returned unchanged. [`validate_reconnect`] rejects a zero
/// `initial_backoff` up front, which is what keeps the loop from hot-spinning.
fn next_backoff(current: Duration, max: Duration) -> Duration {
	current.saturating_mul(2).min(max)
}

/// Reject a [`ReconnectConfig`] whose backoff could never grow.
///
/// [`next_backoff`] doubles the current delay, so `initial_backoff == 0`
/// stays `0` forever: `tokio::time::sleep(ZERO)` returns immediately and
/// [`reconnect_loop`] becomes a busy loop that re-dials as fast as the OS
/// allows until shutdown. `max_backoff == 0` is rejected for the same reason —
/// it would clamp every delay, including a non-zero `initial_backoff`, to
/// zero. The default config (500 ms → 30 s) is unaffected.
///
/// Checked regardless of `enabled`: a zero delay is invalid configuration
/// either way, and failing at construction is cheaper to diagnose than a busy
/// loop after the first drop.
fn validate_reconnect(reconnect: &ReconnectConfig) -> Result<(), Error> {
	if reconnect.initial_backoff.is_zero() {
		return Err(eyre::eyre!("TUIC reconnect initial backoff must be positive"));
	}
	if reconnect.max_backoff.is_zero() {
		return Err(eyre::eyre!("TUIC reconnect max backoff must be positive"));
	}
	Ok(())
}

/// Retry [`connect_and_auth`] with exponential backoff until it succeeds or
/// `shutdown` fires. Returns `None` if cancelled before a connection is made.
///
/// When a [`PeerResolver`] is supplied it is consulted before every attempt so
/// DNS rotation / failover is followed; a resolution error reuses the last
/// known address. If the peer's address family no longer matches the
/// endpoint's local socket, the endpoint is rebound (via the caller's socket
/// factory when present) so the new family is reachable.
#[allow(clippy::too_many_arguments)]
async fn reconnect_loop(
	endpoint: &quinn::Endpoint,
	peer_addr: SocketAddr,
	peer_resolver: Option<&PeerResolver>,
	sni: &str,
	auth: &(Uuid, Arc<[u8]>),
	zero_rtt: bool,
	socket_factory: Option<&UdpSocketFactory>,
	reconnect: &ReconnectConfig,
	shutdown: &CancellationToken,
) -> Option<QuinnConnection> {
	let mut backoff = reconnect.initial_backoff;
	let mut current_peer = peer_addr;

	loop {
		if let Some(resolver) = peer_resolver {
			match resolver().await {
				Ok(addr) => current_peer = addr,
				Err(e) => {
					warn!(target: "tuic_out", "Peer re-resolution for {sni} failed: {e}; reusing {current_peer}");
				}
			}
		}

		// A peer that changed address family cannot be reached from the
		// endpoint's current local socket (quinn rejects an IPv6 peer on an
		// IPv4 socket). Rebind before dialing so the new family is reachable.
		let family_changed = endpoint
			.local_addr()
			.map(|local| peer_family_differs(local, current_peer))
			.unwrap_or(false);
		if family_changed {
			match bind_endpoint_socket(current_peer, socket_factory).await {
				Ok(socket) => {
					if let Err(e) = endpoint.rebind(socket) {
						warn!(target: "tuic_out", "Failed to rebind endpoint socket for {current_peer}: {e}");
					}
				}
				Err(e) => {
					warn!(target: "tuic_out", "Failed to create endpoint socket for {current_peer}: {e}");
				}
			}
		}

		// Race the connect attempt against shutdown so a hung handshake (e.g.
		// the server is still down) doesn't delay a graceful exit.
		let attempt = tokio::select! {
			_ = shutdown.cancelled() => return None,
			r = connect_and_auth(endpoint, current_peer, sni, auth, zero_rtt) => r,
		};
		match attempt {
			Ok(conn) => return Some(conn),
			Err(e) => {
				warn!(target: "tuic_out", "Reconnect to {} failed: {e}; retrying in {:?}", current_peer, backoff);
				tokio::select! {
					_ = shutdown.cancelled() => return None,
					_ = tokio::time::sleep(backoff) => {}
				}
				backoff = next_backoff(backoff, reconnect.max_backoff);
			}
		}
	}
}


pub struct TuicTcpStream;

#[async_trait]
impl Outbound for TuicOutbound {
	async fn handle_tcp(&self, ctx: FlowContext, mut stream: Box<dyn AbstractTcpStream + 'static>) -> eyre::Result<()> {
		let mut tcp = self.connect_tcp(&ctx.target).await?;
		let (_, _, err) = wind_core::io::copy_io(&mut stream, &mut tcp).await;
		if let Some(e) = err {
			return Err(e.into());
		}
		Ok(())
	}

	async fn handle_udp(&self, _ctx: FlowContext, client_stream: wind_core::udp::UdpStream) -> eyre::Result<()> {
		association::run(
			&self.ctx,
			&self.token,
			&self.udp_session,
			&self.udp_assoc_counter,
			self.connection.load_full().as_ref().clone(),
			AssociationOptions {
				mode: self.opts.udp_relay_mode,
				gc_interval: self.opts.gc_interval,
				gc_lifetime: self.opts.gc_lifetime,
			},
			client_stream,
		)
		.await
	}
}

#[cfg(test)]
mod tests {
	use std::{
		net::{Ipv4Addr, SocketAddr},
		sync::Arc,
		time::Duration,
	};

	use bytes::BufMut as _;
	use moka::future::Cache;
	use wind_core::AppContext;

	use super::{
		QuinnConnection, ReconnectConfig, TuicOutbound, TuicOutboundOpts, next_backoff, peer_family_differs, validate_reconnect,
	};
	use crate::{
		client::session::dispatch_incoming_udp,
		proto::{AddressType, CmdType, UdpStream as TuicUdpStream, VER},
		quinn::{CongestionControl, UdpRelayMode},
	};

	#[test]
	fn next_backoff_doubles_until_capped() {
		let max = Duration::from_secs(30);
		assert_eq!(next_backoff(Duration::from_millis(500), max), Duration::from_secs(1));
		assert_eq!(next_backoff(Duration::from_secs(1), max), Duration::from_secs(2));
		assert_eq!(next_backoff(Duration::from_secs(16), max), max);
		// Already at/over the cap stays capped.
		assert_eq!(next_backoff(max, max), max);
		assert_eq!(next_backoff(Duration::from_secs(60), max), max);
	}

	#[test]
	fn next_backoff_does_not_overflow() {
		// Doubling near Duration::MAX must saturate, not panic.
		let huge = Duration::from_secs(u64::MAX / 2 + 1);
		let max = Duration::from_secs(u64::MAX);
		assert_eq!(next_backoff(huge, max), max);
	}

	/// A zero `initial_backoff` is the hot-spin input: `next_backoff` returns
	/// zero for every failure, so the supervisor re-dials without ever
	/// sleeping. It must be rejected instead of silently accepted.
	#[test]
	fn zero_initial_backoff_is_rejected() {
		let cfg = ReconnectConfig {
			initial_backoff: Duration::ZERO,
			..Default::default()
		};
		// Precondition of the bug this guards: doubling zero never grows it.
		assert_eq!(next_backoff(Duration::ZERO, cfg.max_backoff), Duration::ZERO);

		let err = validate_reconnect(&cfg).expect_err("a zero initial backoff must be rejected");
		assert!(
			format!("{err}").contains("reconnect initial backoff"),
			"unexpected error: {err}"
		);
	}

	/// A zero `max_backoff` clamps every delay — including a positive
	/// `initial_backoff` — to zero, so it is rejected too.
	#[test]
	fn zero_max_backoff_is_rejected() {
		let cfg = ReconnectConfig {
			max_backoff: Duration::ZERO,
			..Default::default()
		};
		assert_eq!(next_backoff(cfg.initial_backoff, Duration::ZERO), Duration::ZERO);

		let err = validate_reconnect(&cfg).expect_err("a zero max backoff must be rejected");
		assert!(format!("{err}").contains("reconnect max backoff"), "unexpected error: {err}");
	}

	#[test]
	fn default_reconnect_backoff_is_accepted() {
		let cfg = ReconnectConfig::default();
		assert!(validate_reconnect(&cfg).is_ok());
		// A disabled reconnect with sane delays stays acceptable.
		let disabled = ReconnectConfig { enabled: false, ..cfg };
		assert!(validate_reconnect(&disabled).is_ok());
	}

	#[test]
	fn peer_family_differs_only_across_families() {
		let v4: SocketAddr = "127.0.0.1:1".parse().unwrap();
		let v6: SocketAddr = "[::1]:1".parse().unwrap();
		assert!(!peer_family_differs(v4, v4));
		assert!(!peer_family_differs(v6, v6));
		assert!(peer_family_differs(v4, v6));
		assert!(peer_family_differs(v6, v4));
	}

	#[test]
	fn reconnect_config_default_is_enabled_with_sane_bounds() {
		let cfg = ReconnectConfig::default();
		assert!(cfg.enabled);
		assert_eq!(cfg.initial_backoff, Duration::from_millis(500));
		assert_eq!(cfg.max_backoff, Duration::from_secs(30));
		assert!(cfg.initial_backoff <= cfg.max_backoff);
	}

	/// The guard must run on the real construction path, before any socket is
	/// bound or connection attempted: a peer that nothing listens on would
	/// otherwise fail with a connect error instead of the config error (or, if
	/// it did connect, the supervisor would hot-spin on the zero delay).
	#[test_log::test(tokio::test)]
	async fn outbound_construction_rejects_a_zero_initial_backoff() {
		let opts = TuicOutboundOpts {
			peer_addr: "127.0.0.1:9443".parse().unwrap(),
			peer_resolver: None,
			sni: "localhost".into(),
			auth: (uuid::Uuid::nil(), Arc::<[u8]>::from(&[][..])),
			zero_rtt_handshake: false,
			heartbeat: Duration::from_secs(10),
			gc_interval: Duration::from_secs(10),
			gc_lifetime: Duration::from_secs(10),
			// The guard is a pure config check, so the TLS/verification choices
			// must not matter for reaching it.
			skip_cert_verify: true,
			alpn: vec!["h3".into()],
			reconnect: ReconnectConfig {
				initial_backoff: Duration::ZERO,
				..Default::default()
			},
			client_config: None,
			congestion_control: CongestionControl::Bbr,
			max_concurrent_bi_streams: None,
			max_concurrent_uni_streams: None,
			send_window: None,
			stream_receive_window: None,
			max_idle_time: None,
			udp_relay_mode: UdpRelayMode::Native,
			socket_factory: None,
		};

		let err = match tokio::time::timeout(
			Duration::from_secs(5),
			TuicOutbound::new(Arc::new(AppContext::default()), opts),
		)
		.await
		{
			Err(_) => panic!("the zero-backoff guard must reject before dialing, but construction hung"),
			Ok(Ok(_)) => panic!("a zero initial backoff must be rejected before dialing"),
			Ok(Err(err)) => err,
		};
		assert!(
			format!("{err}").contains("reconnect initial backoff"),
			"the zero-backoff guard must run before the connect attempt, got: {err}"
		);
	}

	/// One wire `Packet` frame exactly as [`dispatch_incoming_udp`] consumes
	/// it.
	///
	/// `address = None` selects the address-less (`AddressType::None`) form,
	/// which logs through the second, otherwise identical, `info!` call.
	fn packet_frame(frag_id: u8, frag_total: u8, address: Option<(Ipv4Addr, u16)>) -> bytes::Bytes {
		const PAYLOAD: &[u8] = b"pong";
		let mut frame = bytes::BytesMut::new();
		frame.put_u8(VER);
		frame.put_u8(CmdType::Packet.into());
		frame.put_u16(0x1234); // assoc_id
		frame.put_u16(7); // pkt_id
		frame.put_u8(frag_total);
		frame.put_u8(frag_id);
		frame.put_u16(PAYLOAD.len() as u16);
		match address {
			Some((ip, port)) => {
				frame.put_u8(AddressType::IPv4.into());
				frame.put_slice(&ip.octets());
				frame.put_u16(port);
			}
			None => frame.put_u8(AddressType::None.into()),
		}
		frame.put_slice(PAYLOAD);
		frame.freeze()
	}

	/// `frag_id` is a raw wire `u8`, so the 1-based fragment number in the log
	/// must be computed after widening: `frag_id + 1` overflows for `0xFF`
	/// (panic under `overflow-checks`, silent wrap to `0` in release).
	#[test_log::test(tokio::test)]
	async fn frag_id_255_does_not_overflow_the_log_path() {
		let sessions: Cache<u16, Arc<TuicUdpStream<QuinnConnection>>> = Cache::new(u64::from(u16::MAX));
		for address in [Some((Ipv4Addr::LOCALHOST, 8080)), None] {
			dispatch_incoming_udp(&sessions, packet_frame(0xFF, 2, address)).await;
		}
	}
}

#[cfg(test)]
mod transport_option_tests {
	use super::*;
	#[test]
	fn packetization_rejects_invalid_mtu_without_panicking() {
		for (initial, minimum) in [(1199, 1200), (1200, 1199)] {
			let opts = QuinnTransportOptions {
				initial_mtu: Some(initial),
				min_mtu: Some(minimum),
				..Default::default()
			};
			assert!(opts.apply(&mut quinn::TransportConfig::default()).is_err());
		}
	}
	#[test]
	fn packetization_applies_all_flags() {
		let opts = QuinnTransportOptions {
			initial_mtu: Some(1400),
			min_mtu: Some(1280),
			gso: Some(false),
			pmtu: Some(false),
		};
		let mut transport = quinn::TransportConfig::default();
		opts.apply(&mut transport).unwrap();
		let debug = format!("{transport:?}");
		assert!(debug.contains("initial_mtu: 1400"), "{debug}");
		assert!(debug.contains("min_mtu: 1280"), "{debug}");
		assert!(debug.contains("enable_segmentation_offload: false"), "{debug}");
		assert!(debug.contains("mtu_discovery_config: None"), "{debug}");
	}
}

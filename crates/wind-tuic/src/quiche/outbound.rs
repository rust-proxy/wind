//! TUIC outbound client — quiche (tokio-quiche) backend.
//!
//! Thin connection provider around [`wind_quic::quiche`], mirroring
//! [`TuicheInbound`](crate::quiche::TuicheInbound): it establishes the QUIC
//! connection (optionally resuming a cached TLS session for 0-RTT), sends the
//! shared [`ClientProtoExt::send_auth`] handshake, and drives the
//! backend-agnostic [`crate::client`] accept/heartbeat machinery. All TUIC
//! protocol logic (auth, heartbeat, TCP/UDP relay) is shared with the quinn
//! backend.
//!
//! A caller may supply a UDP socket factory for initial setup and reconnects.

use std::{
	net::SocketAddr,
	sync::{Arc, atomic::AtomicU16},
	time::Duration,
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use moka::future::Cache;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument as _, info, warn};
use uuid::Uuid;
use wind_core::{
	AppContext, FlowContext, Outbound, tcp::AbstractTcpStream, types::TargetAddr, udp::UdpStream as CoreUdpStream,
};
pub use wind_quic::quiche::UdpSocketFactory;
use wind_quic::{
	ClientTlsConfig, QuicConnection as _,
	quiche::{QuicheConnection, QuicheRecv, QuicheSend, connect_with_session_and_socket},
};

use crate::{
	Error,
	client::{
		association::{self, AssociationOptions},
		session::{SessionTransition, run_session},
	},
	proto::{ClientProtoExt, UdpRelayMode, UdpStream as TuicUdpStream, open_connect_stream},
	quiche::utils::{ConnectionOpts, UdpRelayMode as TransportUdpRelayMode},
};

/// How many 100 ms polls to wait for the server's `NewSessionTicket` before
/// giving up on caching a 0-RTT resumption ticket for this connection.
const SESSION_TICKET_POLLS: usize = 20;

/// Controls how the outbound supervisor re-establishes the QUIC connection
/// after it drops.
///
/// Backend-local mirror of the quinn outbound's config; the two are kept
/// separate so the quiche module does not depend on the quinn feature.
#[derive(Clone, Debug)]
pub struct ReconnectConfig {
	/// When `false`, a dropped connection is not re-established — the
	/// supervisor closes it and exits. When `true`, it retries with
	/// exponential backoff until it succeeds or the client shuts down.
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

/// Static configuration for a [`TuicheOutbound`].
#[derive(Clone)]
pub struct TuicheOutboundOpts {
	/// Binary ECHConfigList; require ECH acceptance when configured.
	pub ech_config_list: Option<Vec<u8>>,
	/// Server socket address to dial (already resolved).
	pub peer_addr: SocketAddr,
	/// Server name (SNI) sent and verified against.
	pub sni: String,
	/// TUIC credentials: `(uuid, password)`.
	pub auth: (Uuid, Arc<[u8]>),
	/// Verify the server certificate. Disabling it is insecure (MITM-able) and
	/// intended only for tests / explicitly-trusted setups.
	pub verify_certificate: bool,
	/// ALPN protocols to advertise, most-preferred first. Empty falls back to
	/// `h3` (the TUIC convention).
	pub alpn: Vec<Vec<u8>>,
	/// Interval between client heartbeats.
	pub heartbeat: Duration,
	/// Interval between runs of fragment-reassembly garbage collection.
	pub gc_interval: Duration,
	/// Lifetime after which incomplete fragment groups are evicted.
	pub gc_lifetime: Duration,
	/// Automatic reconnect behaviour after the connection drops.
	pub reconnect: ReconnectConfig,
	/// Transport-level tuning (idle timeout, windows, congestion control, ALPN,
	/// 0-RTT, and the UDP relay mode that also toggles QUIC DATAGRAM support).
	pub connection: ConnectionOpts,
}

/// Outbound manager for a single TUIC client connection.
pub struct TuicheOutbound {
	ctx: Arc<AppContext>,
	socket_factory: Option<UdpSocketFactory>,
	opts: TuicheOutboundOpts,
	/// Root token for this outbound. Cancelling it (e.g. on drop) stops the
	/// poll supervisor and every per-session accept loop.
	token: CancellationToken,
	/// The live QUIC connection, swappable so the reconnect supervisor can
	/// replace it after a drop without callers holding a stale handle.
	connection: Arc<ArcSwap<QuicheConnection>>,
	/// Cached TLS resumption ticket, captured after a successful handshake and
	/// replayed on reconnect to attempt 0-RTT early data.
	session: Arc<Mutex<Option<Vec<u8>>>>,
	udp_assoc_counter: AtomicU16,
	udp_session: Cache<u16, Arc<TuicUdpStream<QuicheConnection>>>,
}

impl TuicheOutbound {
	/// Create a new TUIC outbound builder.
	pub fn builder() -> TuicheOutboundBuilder {
		TuicheOutboundBuilder::new()
	}

	/// Dial the server, authenticate, and return a ready outbound.
	///
	/// This only establishes the connection; call
	/// [`start_poll`](Self::start_poll) to start the heartbeat and
	/// incoming-stream supervisor.
	pub async fn new(ctx: Arc<AppContext>, opts: TuicheOutboundOpts) -> Result<Self, Error> {
		Self::new_with_socket_factory(ctx, opts, None).await
	}

	pub async fn new_with_socket_factory(
		ctx: Arc<AppContext>,
		opts: TuicheOutboundOpts,
		socket_factory: Option<UdpSocketFactory>,
	) -> Result<Self, Error> {
		if opts.heartbeat.is_zero() {
			return Err(eyre::eyre!("TUIC heartbeat interval must be positive"));
		}
		if opts.gc_interval.is_zero() {
			return Err(eyre::eyre!("TUIC GC interval must be positive"));
		}
		if opts.gc_lifetime.is_zero() {
			return Err(eyre::eyre!("TUIC GC lifetime must be positive"));
		}
		// Reject a zero backoff before dialing: the supervisor would otherwise
		// re-dial in a hot loop instead of waiting between attempts.
		validate_reconnect(&opts.reconnect)?;

		let token = ctx.token.child_token();
		let session: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
		let connection = establish(&opts, None, socket_factory.as_ref()).await?;

		let outbound = Self {
			ctx,
			socket_factory,
			opts,
			token,
			connection: Arc::new(ArcSwap::from_pointee(connection)),
			session,
			udp_assoc_counter: AtomicU16::new(0),
			udp_session: Cache::new(u64::from(u16::MAX) + 1),
		};

		if outbound.opts.connection.enable_0rtt {
			spawn_ticket_capture(
				&outbound.ctx,
				outbound.connection.load_full().as_ref().clone(),
				outbound.session.clone(),
				outbound.token.child_token(),
			);
		}

		Ok(outbound)
	}

	/// The address the outbound dials.
	pub fn peer_addr(&self) -> SocketAddr {
		self.opts.peer_addr
	}

	/// The current live connection.
	pub fn connection(&self) -> Arc<QuicheConnection> {
		self.connection.load_full()
	}

	/// Start the connection supervisor: heartbeats, incoming-stream dispatch,
	/// and (when enabled) automatic reconnection with exponential backoff.
	pub async fn start_poll(&self) -> eyre::Result<()> {
		let shutdown = self.token.child_token();
		let connection = self.connection.clone();
		let session = self.session.clone();
		let ctx = self.ctx.clone();
		let opts = self.opts.clone();
		let socket_factory = self.socket_factory.clone();
		let udp_session = self.udp_session.clone();

		let supervisor = async move {
			loop {
				let conn = connection.load_full().as_ref().clone();

				match run_session(
					&ctx,
					&conn,
					&udp_session,
					opts.heartbeat,
					&shutdown,
					opts.reconnect.enabled,
					opts.peer_addr,
				)
				.await
				{
					SessionTransition::Shutdown | SessionTransition::StopAfterLoss => return eyre::Ok(()),
					SessionTransition::Reconnect => {}
				}

				match reconnect_loop(&opts, &session, &shutdown, socket_factory.as_ref()).await {
					Some(new_conn) => {
						if opts.connection.enable_0rtt {
							spawn_ticket_capture(&ctx, new_conn.clone(), session.clone(), shutdown.child_token());
						}
						connection.store(Arc::new(new_conn));
						info!(target: "tuic_out", peer = %opts.peer_addr, "Reconnected");
					}
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
	/// and returns the joined stream for the caller to relay.
	pub async fn connect_tcp(&self, target: &TargetAddr) -> Result<tokio::io::Join<QuicheRecv, QuicheSend>, Error> {
		let connection = self.connection.load_full();
		let (send, recv) = open_connect_stream(connection.as_ref(), target).await?;
		Ok(tokio::io::join(recv, send))
	}

	/// Close the live connection and stop the supervisor.
	pub fn close(&self) {
		self.token.cancel();
		self.connection.load_full().close(0, b"client closed");
	}

	/// How outgoing `Packet` commands are relayed on this connection.
	fn relay_mode(&self) -> UdpRelayMode {
		match self.opts.connection.udp_relay_mode {
			TransportUdpRelayMode::Datagram => UdpRelayMode::Native,
			TransportUdpRelayMode::Stream => UdpRelayMode::Quic,
		}
	}
}

impl Drop for TuicheOutbound {
	fn drop(&mut self) {
		self.token.cancel();
	}
}


/// Open a fresh QUIC connection and complete the TUIC auth handshake.
///
/// Shared by initial connect ([`TuicheOutbound::new`]) and reconnect. The
/// optional `session` ticket attempts TLS resumption (and 0-RTT when both
/// sides enable it); a rejected/absent ticket transparently falls back to a
/// full 1-RTT handshake.
async fn establish(
	opts: &TuicheOutboundOpts,
	session: Option<Vec<u8>>,
	factory: Option<&UdpSocketFactory>,
) -> Result<QuicheConnection, Error> {
	let tls = ClientTlsConfig {
		ech_config_list: opts.ech_config_list.clone(),
		server_name: opts.sni.clone(),
		verify_certificate: opts.verify_certificate,
		alpn: if opts.alpn.is_empty() {
			vec![b"h3".to_vec()]
		} else {
			opts.alpn.clone()
		},
		enable_early_data: opts.connection.enable_0rtt,
	};
	let transport = opts.connection.to_transport();

	let conn = connect_with_session_and_socket(opts.peer_addr, &tls, &transport, session, factory).await?;
	conn.send_auth(&opts.auth.0, &opts.auth.1).await?;
	Ok(conn)
}

/// Poll the connection for the server's `NewSessionTicket` and cache it for a
/// future reconnect. Best-effort: gives up after a bounded wait.
fn spawn_ticket_capture(
	ctx: &Arc<AppContext>,
	conn: QuicheConnection,
	session: Arc<Mutex<Option<Vec<u8>>>>,
	shutdown: CancellationToken,
) {
	ctx.tasks.spawn(
		async move {
			for _ in 0..SESSION_TICKET_POLLS {
				if let Some(ticket) = conn.session().await {
					*session.lock().await = Some(ticket);
					return;
				}
				tokio::select! {
					_ = shutdown.cancelled() => return,
					_ = tokio::time::sleep(Duration::from_millis(100)) => {}
				}
			}
		}
		.in_current_span(),
	);
}

/// Next exponential-backoff delay: doubling never grows a zero delay, so a
/// zero `current` is returned unchanged. [`validate_reconnect`] rejects a zero
/// `initial_backoff` up front, which is what keeps the loop from hot-spinning.
fn next_backoff(current: Duration, max: Duration) -> Duration {
	current.saturating_mul(2).min(max)
}

/// Reject a [`ReconnectConfig`] whose backoff could never grow.
///
/// Mirrors the quinn outbound's guard: [`next_backoff`] doubles the current
/// delay, so a zero `initial_backoff` (or a zero `max_backoff`, which clamps
/// every delay) makes [`reconnect_loop`] re-dial without waiting. The default
/// config (500 ms → 30 s) is unaffected.
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

/// Retry [`establish`] with exponential backoff until it succeeds or
/// `shutdown` fires. Returns `None` if cancelled before a connection is made.
async fn reconnect_loop(
	opts: &TuicheOutboundOpts,
	session: &Arc<Mutex<Option<Vec<u8>>>>,
	shutdown: &CancellationToken,
	factory: Option<&UdpSocketFactory>,
) -> Option<QuicheConnection> {
	let mut backoff = opts.reconnect.initial_backoff;

	loop {
		let cached = if opts.connection.enable_0rtt {
			session.lock().await.clone()
		} else {
			None
		};

		let attempt = tokio::select! {
			_ = shutdown.cancelled() => return None,
			r = establish(opts, cached, factory) => r,
		};

		match attempt {
			Ok(conn) => return Some(conn),
			Err(e) => {
				warn!(target: "tuic_out", peer = %opts.peer_addr, "Reconnect failed: {e}; retrying in {backoff:?}");
				tokio::select! {
					_ = shutdown.cancelled() => return None,
					_ = tokio::time::sleep(backoff) => {}
				}
				backoff = next_backoff(backoff, opts.reconnect.max_backoff);
			}
		}
	}
}


#[async_trait]
impl Outbound for TuicheOutbound {
	async fn handle_tcp(&self, ctx: FlowContext, mut stream: Box<dyn AbstractTcpStream + 'static>) -> eyre::Result<()> {
		let mut tcp = self.connect_tcp(&ctx.target).await?;
		let (_, _, err) = wind_core::io::copy_io(&mut stream, &mut tcp).await;
		if let Some(e) = err {
			return Err(e.into());
		}
		Ok(())
	}

	async fn handle_udp(&self, _ctx: FlowContext, client_stream: CoreUdpStream) -> eyre::Result<()> {
		association::run(
			&self.ctx,
			&self.token,
			&self.udp_session,
			&self.udp_assoc_counter,
			self.connection.load_full().as_ref().clone(),
			AssociationOptions {
				mode: self.relay_mode(),
				gc_interval: self.opts.gc_interval,
				gc_lifetime: self.opts.gc_lifetime,
			},
			client_stream,
		)
		.await
	}
}

/// Builder for [`TuicheOutbound`], mirroring
/// [`TuicheInboundBuilder`](crate::quiche::TuicheInboundBuilder).
pub struct TuicheOutboundBuilder {
	ech_config_list: Option<Vec<u8>>,
	server_addr: Option<SocketAddr>,
	server_name: Option<String>,
	uuid: Option<Uuid>,
	password: Option<Vec<u8>>,
	verify_certificate: bool,
	alpn: Vec<Vec<u8>>,
	heartbeat: Duration,
	gc_interval: Duration,
	gc_lifetime: Duration,
	reconnect: ReconnectConfig,
	connection: ConnectionOpts,
	context: Option<Arc<AppContext>>,
}

impl TuicheOutboundBuilder {
	/// Create a new builder.
	pub fn new() -> Self {
		Self {
			ech_config_list: None,
			server_addr: None,
			server_name: None,
			uuid: None,
			password: None,
			verify_certificate: true,
			alpn: Vec::new(),
			heartbeat: Duration::from_secs(3),
			gc_interval: Duration::from_secs(3),
			gc_lifetime: Duration::from_secs(15),
			reconnect: ReconnectConfig::default(),
			connection: ConnectionOpts::default(),
			context: None,
		}
	}

	/// Require ECH using the supplied binary ECHConfigList.
	pub fn ech_config_list(mut self, list: Vec<u8>) -> Self {
		self.ech_config_list = Some(list);
		self
	}

	/// Set the server socket address.
	pub fn server_addr(mut self, addr: SocketAddr) -> Self {
		self.server_addr = Some(addr);
		self
	}

	/// Set the server name (SNI).
	pub fn server_name(mut self, name: String) -> Self {
		self.server_name = Some(name);
		self
	}

	/// Set the user UUID.
	pub fn uuid(mut self, uuid: Uuid) -> Self {
		self.uuid = Some(uuid);
		self
	}

	/// Set the password.
	pub fn password(mut self, password: String) -> Self {
		self.password = Some(password.into_bytes());
		self
	}

	/// Enable or disable server certificate verification.
	pub fn verify_certificate(mut self, verify: bool) -> Self {
		self.verify_certificate = verify;
		self
	}

	/// Set the ALPN protocols to advertise, most-preferred first. Empty falls
	/// back to `h3`.
	pub fn alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {
		self.alpn = alpn;
		self
	}

	/// Set the heartbeat interval.
	pub fn heartbeat(mut self, interval: Duration) -> Self {
		self.heartbeat = interval;
		self
	}

	/// Set the fragment-reassembly GC interval.
	pub fn gc_interval(mut self, interval: Duration) -> Self {
		self.gc_interval = interval;
		self
	}

	/// Set the fragment-reassembly GC lifetime.
	pub fn gc_lifetime(mut self, lifetime: Duration) -> Self {
		self.gc_lifetime = lifetime;
		self
	}

	/// Set the reconnect behaviour.
	pub fn reconnect(mut self, reconnect: ReconnectConfig) -> Self {
		self.reconnect = reconnect;
		self
	}

	/// Set the transport-level connection options (including the UDP relay
	/// mode).
	pub fn connection_opts(mut self, opts: ConnectionOpts) -> Self {
		self.connection = opts;
		self
	}

	/// Set the application context that owns the outbound's tasks. Defaults to
	/// a fresh context.
	pub fn context(mut self, ctx: Arc<AppContext>) -> Self {
		self.context = Some(ctx);
		self
	}

	/// Dial the server and authenticate, returning a ready outbound.
	pub async fn build(self) -> Result<TuicheOutbound, Error> {
		let server_addr = self.server_addr.ok_or_else(|| eyre::eyre!("Server address not set"))?;
		let server_name = self.server_name.ok_or_else(|| eyre::eyre!("Server name not set"))?;
		let uuid = self.uuid.ok_or_else(|| eyre::eyre!("UUID not set"))?;
		let password = self.password.ok_or_else(|| eyre::eyre!("Password not set"))?;

		let opts = TuicheOutboundOpts {
			ech_config_list: self.ech_config_list,
			peer_addr: server_addr,
			sni: server_name,
			auth: (uuid, Arc::from(password.into_boxed_slice())),
			verify_certificate: self.verify_certificate,
			alpn: self.alpn,
			heartbeat: self.heartbeat,
			gc_interval: self.gc_interval,
			gc_lifetime: self.gc_lifetime,
			reconnect: self.reconnect,
			connection: self.connection,
		};

		TuicheOutbound::new(self.context.unwrap_or_default(), opts).await
	}
}

impl Default for TuicheOutboundBuilder {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::client::session::dispatch_incoming_udp;

	#[test]
	fn next_backoff_doubles_until_capped() {
		let max = Duration::from_secs(30);
		assert_eq!(next_backoff(Duration::from_millis(500), max), Duration::from_secs(1));
		assert_eq!(next_backoff(Duration::from_secs(16), max), max);
		assert_eq!(next_backoff(max, max), max);
	}

	#[test]
	fn reconnect_config_default_is_enabled_with_sane_bounds() {
		let cfg = ReconnectConfig::default();
		assert!(cfg.enabled);
		assert!(cfg.initial_backoff <= cfg.max_backoff);
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

	/// The guard must run on the real construction path, before the QUIC
	/// handshake is attempted: a peer that nothing listens on would otherwise
	/// fail with a dial error instead of the config error.
	#[test_log::test(tokio::test)]
	async fn outbound_construction_rejects_a_zero_initial_backoff() {
		let opts = TuicheOutboundOpts {
			ech_config_list: None,
			peer_addr: "127.0.0.1:9443".parse().unwrap(),
			sni: "localhost".into(),
			auth: (Uuid::nil(), Arc::<[u8]>::from(&[][..])),
			verify_certificate: false,
			alpn: Vec::new(),
			heartbeat: Duration::from_secs(10),
			gc_interval: Duration::from_secs(10),
			gc_lifetime: Duration::from_secs(10),
			reconnect: ReconnectConfig {
				initial_backoff: Duration::ZERO,
				..Default::default()
			},
			connection: ConnectionOpts::default(),
		};

		let err = match tokio::time::timeout(
			Duration::from_secs(5),
			TuicheOutbound::new(Arc::new(AppContext::default()), opts),
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
	fn packet_frame(frag_id: u8, frag_total: u8, address: Option<(std::net::Ipv4Addr, u16)>) -> bytes::Bytes {
		use bytes::BufMut as _;

		use crate::proto::{AddressType, CmdType, VER};

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
		let sessions: Cache<u16, Arc<TuicUdpStream<QuicheConnection>>> = Cache::new(u64::from(u16::MAX));
		for address in [Some((std::net::Ipv4Addr::LOCALHOST, 8080)), None] {
			dispatch_incoming_udp(&sessions, packet_frame(0xFF, 2, address)).await;
		}
	}

	#[tokio::test]
	async fn builder_requires_required_fields() {
		match TuicheOutboundBuilder::new().build().await {
			Ok(_) => panic!("missing server address must fail"),
			Err(err) => assert!(format!("{err}").contains("Server address"), "unexpected error: {err}"),
		}
	}

	/// End-to-end TCP round trip against a real quiche `TuicheInbound`.
	///
	/// Gated on the `server` feature because the echo inbound lives in the
	/// server module; the outbound itself only needs `client` + `quiche`.
	#[cfg(feature = "server")]
	mod loopback {
		use std::{net::Ipv4Addr, sync::Arc, time::Duration};

		use async_trait::async_trait;
		use bytes::Bytes;
		use tokio::{
			io::{AsyncReadExt as _, AsyncWriteExt as _},
			sync::mpsc,
		};
		use uuid::Uuid;
		use wind_core::{
			AbstractInbound, Dispatcher, FlowContext, Outbound, RouteAction, Router,
			hooks::Protocol,
			rule::NetworkType,
			tcp::AbstractTcpStream,
			types::TargetAddr,
			udp::{UdpPacket, UdpStream as CoreUdpStream},
		};
		use wind_quic::QuicConnection as _;

		use super::super::{ConnectionOpts, ReconnectConfig, TuicheOutbound, TuicheOutboundBuilder};
		use crate::quiche::{TuicheInboundBuilder, UdpRelayMode as TransportUdpRelayMode};

		/// Forwards every routed connection by echoing TCP payloads back, so
		/// the client can verify a full TUIC TCP round trip without a separate
		/// echo server or resolver. UDP datagrams are echoed in place.
		struct EchoOutbound;

		async fn echo_stream(mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send) -> eyre::Result<()> {
			let mut buf = vec![0u8; 16 * 1024];
			loop {
				let n = stream.read(&mut buf).await?;
				if n == 0 {
					return Ok(());
				}
				stream.write_all(&buf[..n]).await?;
			}
		}

		#[async_trait]
		impl Outbound for EchoOutbound {
			async fn handle_tcp(&self, _ctx: FlowContext, stream: Box<dyn AbstractTcpStream + 'static>) -> eyre::Result<()> {
				echo_stream(stream).await
			}

			async fn handle_udp(&self, _ctx: FlowContext, mut udp: CoreUdpStream) -> eyre::Result<()> {
				// Echo each datagram back to the client by re-sending it on the
				// association's outbound channel with the same attributed
				// target.
				while let Some(packet) = udp.rx.recv().await {
					let target = packet.target.clone();
					let reply = wind_core::udp::UdpPacket {
						source: Some(target.clone()),
						target,
						payload: packet.payload,
					};
					if udp.tx.send(reply).await.is_err() {
						break;
					}
				}
				Ok(())
			}
		}

		struct ForwardRouter;

		impl Router for ForwardRouter {
			#[allow(clippy::manual_async_fn)]
			fn route(&self, _ctx: &FlowContext) -> impl std::future::Future<Output = eyre::Result<RouteAction>> + Send {
				async { Ok(RouteAction::Forward("default".to_string())) }
			}
		}

		/// Start a quiche `TuicheInbound` that echoes, returning its bound
		/// address and the temp dir holding the certificate (kept alive by the
		/// caller). `server_opts` drives the server transport (notably the UDP
		/// relay mode / DATAGRAM support).
		async fn start_echo_server(
			uuid: Uuid,
			password: &str,
			server_opts: ConnectionOpts,
		) -> eyre::Result<(std::net::SocketAddr, tempfile::TempDir)> {
			start_echo_server_with(uuid, password, server_opts, |builder| builder).await
		}

		async fn start_echo_server_with(
			uuid: Uuid,
			password: &str,
			server_opts: ConnectionOpts,
			configure: impl FnOnce(TuicheInboundBuilder) -> TuicheInboundBuilder,
		) -> eyre::Result<(std::net::SocketAddr, tempfile::TempDir)> {
			let dir = tempfile::tempdir()?;
			let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
			let cert_path = dir.path().join("cert.pem");
			let key_path = dir.path().join("key.pem");
			std::fs::write(&cert_path, generated.cert.pem())?;
			std::fs::write(&key_path, generated.signing_key.serialize_pem())?;

			let (addr_tx, mut addr_rx) = tokio::sync::watch::channel(None::<std::net::SocketAddr>);
			let builder = TuicheInboundBuilder::new()
				.listen_addr("127.0.0.1:0".parse()?)
				.bound_addr(addr_tx)
				.certificate_path(cert_path.to_string_lossy().into_owned())
				.private_key_path(key_path.to_string_lossy().into_owned())
				.user(uuid, password.to_string())
				.connection_opts(server_opts);
			let inbound = configure(builder).build().await?;

			let mut dispatcher = Dispatcher::new(ForwardRouter);
			dispatcher.add_handler("default", Arc::new(EchoOutbound) as Arc<dyn Outbound>);
			tokio::spawn(async move {
				let _ = inbound.listen(&dispatcher).await;
			});

			let addr = addr_rx
				.wait_for(|a| a.is_some())
				.await?
				.ok_or_else(|| eyre::eyre!("listener exited before reporting its bound address"))?;
			Ok((addr, dir))
		}

		fn client_builder(
			addr: std::net::SocketAddr,
			uuid: Uuid,
			password: &str,
			relay_mode: TransportUdpRelayMode,
		) -> TuicheOutboundBuilder {
			let opts = ConnectionOpts {
				enable_0rtt: false,
				udp_relay_mode: relay_mode,
				..Default::default()
			};
			TuicheOutboundBuilder::new()
				.server_addr(addr)
				.server_name("localhost".to_string())
				.uuid(uuid)
				.password(password.to_string())
				.verify_certificate(false)
				.connection_opts(opts)
		}

		/// Deterministic failures for the UDP tests: a dropped connection must
		/// surface as a timeout in the test, not as a reconnect loop.
		fn no_reconnect() -> ReconnectConfig {
			ReconnectConfig {
				enabled: false,
				..Default::default()
			}
		}

		/// Send `payload` through `outbound`'s UDP association and return the
		/// echoed payload. The echo server mirrors the packet back on the same
		/// association, so this exercises the reply transport (datagram vs
		/// unidirectional stream) end to end.
		async fn udp_roundtrip(outbound: Arc<TuicheOutbound>, payload: &'static [u8]) -> eyre::Result<Bytes> {
			let target = TargetAddr::IPv4(Ipv4Addr::LOCALHOST, 9);
			let udp_ctx = FlowContext {
				target: target.clone(),
				network: NetworkType::Udp,
				source: None,
				inbound_tag: "quiche-loopback-test".into(),
				protocol: Protocol::Tunnel,
				user: None,
				inbound_port: None,
				inbound_type: None,
			};

			let (to_outbound_tx, to_outbound_rx) = mpsc::channel::<UdpPacket>(8);
			let (from_outbound_tx, mut from_outbound_rx) = mpsc::channel::<UdpPacket>(8);
			let client_stream = CoreUdpStream {
				tx: from_outbound_tx,
				rx: to_outbound_rx,
			};
			let client = outbound.clone();
			let owner = tokio::spawn(async move { client.handle_udp(udp_ctx, client_stream).await });

			to_outbound_tx
				.send(UdpPacket {
					source: None,
					target,
					payload: Bytes::from_static(payload),
				})
				.await?;

			let echoed = tokio::time::timeout(Duration::from_secs(10), from_outbound_rx.recv())
				.await
				.map_err(|_| eyre::eyre!("UDP echo timed out — the reply never reached the client"))?
				.ok_or_else(|| eyre::eyre!("reply channel closed before the echo arrived"))?;
			// Abort the caller while the input is still open. The tracked
			// association must stop forwarding and release its ID
			// independently.
			assert!(outbound.udp_session.contains_key(&0));
			owner.abort();
			assert!(owner.await.unwrap_err().is_cancelled());
			tokio::time::timeout(Duration::from_secs(3), async {
				to_outbound_tx.closed().await;
				while outbound.udp_session.contains_key(&0) {
					tokio::task::yield_now().await;
				}
			})
			.await?;
			Ok(echoed.payload)
		}

		#[tokio::test]
		async fn quiche_outbound_tcp_roundtrip() -> eyre::Result<()> {
			let uuid = Uuid::new_v4();
			let password = "test-password";
			let (addr, _dir) = start_echo_server(uuid, password, ConnectionOpts::default()).await?;

			let outbound = client_builder(addr, uuid, password, TransportUdpRelayMode::Datagram)
				.build()
				.await?;
			outbound.start_poll().await?;

			let target = TargetAddr::IPv4(Ipv4Addr::LOCALHOST, 80);
			let mut io = outbound.connect_tcp(&target).await?;

			for probe in [b"hello".as_slice(), b"tuic-over-quiche".as_slice()] {
				io.write_all(probe).await?;
				io.flush().await?;
				let mut buf = vec![0u8; probe.len()];
				io.read_exact(&mut buf).await?;
				assert_eq!(buf, probe);
			}

			outbound.close();
			Ok(())
		}

		/// W45: the quiche server offers `ConnectionOpts::alpn` during the TLS
		/// handshake; a client that provides the same list completes the
		/// handshake and authenticates.
		#[tokio::test]
		async fn quiche_server_offers_the_configured_alpn() -> eyre::Result<()> {
			let uuid = Uuid::new_v4();
			let password = "test-password";
			let server_opts = ConnectionOpts {
				alpn: vec![b"tuic-test".to_vec()],
				..Default::default()
			};
			let (addr, _dir) = start_echo_server(uuid, password, server_opts).await?;

			let outbound = client_builder(addr, uuid, password, TransportUdpRelayMode::Datagram)
				.alpn(vec![b"tuic-test".to_vec()])
				.build()
				.await?;
			outbound.close();
			Ok(())
		}

		/// The mirror image: the server offers only `tuic-test`, the client
		/// only `h3`. With no protocol in common the handshake can
		/// never complete, so dialing must fail. Before W45 the server
		/// discarded its own ALPN list and always offered `h3`, so this
		/// client authenticated successfully — proving the server-side
		/// ALPN was not actually enforced.
		#[tokio::test]
		async fn quiche_server_rejects_a_client_without_a_common_alpn() -> eyre::Result<()> {
			let uuid = Uuid::new_v4();
			let password = "test-password";
			let server_opts = ConnectionOpts {
				alpn: vec![b"tuic-test".to_vec()],
				..Default::default()
			};
			let (addr, _dir) = start_echo_server(uuid, password, server_opts).await?;

			// A mismatched ALPN surfaces as quiche giving up on the handshake
			// (quiche reports `timed out`), not as a distinct ALPN error, so
			// bound the dial and require a failure rather than a connection.
			let built = tokio::time::timeout(
				Duration::from_secs(20),
				client_builder(addr, uuid, password, TransportUdpRelayMode::Datagram).build(),
			)
			.await
			.expect("a server that enforces ALPN must never leave the dial hanging");

			// `TuicheOutbound` is deliberately not `Debug`, so match instead of
			// `expect_err`.
			match built {
				Ok(outbound) => {
					outbound.close();
					eyre::bail!("a client offering only `h3` authenticated to a server offering only `tuic-test`")
				}
				Err(err) => assert!(
					format!("{err}").contains("timed out"),
					"expected the handshake to time out with no common ALPN, got: {err}"
				),
			}
			Ok(())
		}

		/// W46: the inbound's authentication window is configurable and really
		/// applied. A raw QUIC client completes the handshake but never sends
		/// `Authenticate`, so the server's auth-timeout guard is the only thing
		/// that can close the connection. With the former private 3 s constant
		/// it survived the full 3 s; configured to 250 ms it must be gone well
		/// before that — the 2 s bound below sits under the old default on
		/// purpose, so this test fails if the window is ignored.
		#[tokio::test]
		async fn quiche_server_closes_an_unauthenticated_connection_at_the_configured_auth_timeout() -> eyre::Result<()> {
			let configured = Duration::from_millis(250);
			let (addr, _dir) = start_echo_server_with(Uuid::new_v4(), "test-password", ConnectionOpts::default(), |builder| {
				builder.auth_timeout(configured)
			})
			.await?;

			let tls = wind_quic::ClientTlsConfig {
				ech_config_list: None,
				server_name: "localhost".to_string(),
				verify_certificate: false,
				alpn: vec![b"h3".to_vec()],
				enable_early_data: false,
			};
			let started = std::time::Instant::now();
			let conn = wind_quic::quiche::connect(addr, &tls, &ConnectionOpts::default().to_transport()).await?;

			tokio::time::timeout(Duration::from_secs(2), conn.closed())
				.await
				.map_err(|_| eyre::eyre!("an unauthenticated connection outlived its configured {configured:?} auth window"))?;
			let elapsed = started.elapsed();
			assert!(
				elapsed < Duration::from_secs(2),
				"the server kept an unauthenticated connection for {elapsed:?}, past the configured {configured:?} window"
			);
			Ok(())
		}

		#[tokio::test]
		async fn quiche_auth_retries_on_the_same_connection() -> eyre::Result<()> {
			use tokio::sync::Notify;
			use wind_core::{InboundHooks, TuicAuthenticator, UserId};

			use crate::proto::{ClientProtoExt as _, open_connect_stream};

			struct ObservedUser {
				uuid: Uuid,
				lookup: Notify,
			}
			#[async_trait]
			impl TuicAuthenticator for ObservedUser {
				async fn lookup(&self, uuid: &Uuid) -> Option<(UserId, Arc<[u8]>)> {
					self.lookup.notify_one();
					(*uuid == self.uuid).then(|| (UserId::from(*uuid), Arc::from(b"test-password".as_slice())))
				}
			}

			let uuid = Uuid::new_v4();
			let user = Arc::new(ObservedUser {
				uuid,
				lookup: Notify::new(),
			});
			let (addr, _dir) = start_echo_server_with(uuid, "test-password", ConnectionOpts::default(), |builder| {
				builder.auth_timeout(Duration::from_secs(30)).hooks(InboundHooks {
					tuic_auth: Some(user.clone()),
					..Default::default()
				})
			})
			.await?;
			let tls = wind_quic::ClientTlsConfig {
				ech_config_list: None,
				server_name: "localhost".to_string(),
				verify_certificate: false,
				alpn: vec![b"h3".to_vec()],
				enable_early_data: false,
			};
			tokio::time::timeout(Duration::from_secs(10), async {
				for valid_third in [false, true] {
					let conn = wind_quic::quiche::connect(addr, &tls, &ConnectionOpts::default().to_transport()).await?;
					for _ in 0..2 {
						conn.send_auth(&uuid, b"wrong-password").await?;
						// A lookup confirms the server received this command
						// before we open the next stream.
						user.lookup.notified().await;
					}
					if valid_third {
						conn.send_auth(&uuid, b"test-password").await?;
						user.lookup.notified().await;
						let target = TargetAddr::IPv4(Ipv4Addr::LOCALHOST, 9);
						let (mut send, mut recv) = open_connect_stream(&conn, &target).await?;
						send.write_all(b"echo").await?;
						let mut reply = [0; 4];
						recv.read_exact(&mut reply).await?;
						assert_eq!(&reply, b"echo");
						conn.close(0, b"done");
					} else {
						conn.send_auth(&uuid, b"wrong-password").await?;
						user.lookup.notified().await;
						conn.closed().await;
					}
				}
				Ok(())
			})
			.await?
		}

		/// Control: the default (datagram) relay mode still round-trips when
		/// both transports advertise DATAGRAM support.
		#[tokio::test]
		async fn quiche_outbound_udp_datagram_roundtrip() -> eyre::Result<()> {
			let uuid = Uuid::new_v4();
			let password = "test-password";
			let (addr, _dir) = start_echo_server(uuid, password, ConnectionOpts::default()).await?;

			let outbound = Arc::new(
				client_builder(addr, uuid, password, TransportUdpRelayMode::Datagram)
					.reconnect(no_reconnect())
					.build()
					.await?,
			);
			outbound.start_poll().await?;

			let echoed = udp_roundtrip(outbound.clone(), b"udp-datagram-probe").await?;
			assert_eq!(echoed, &b"udp-datagram-probe"[..]);

			outbound.close();
			Ok(())
		}

		/// F18: a client on stream relay (`udp_relay_mode = "quic"`) never
		/// advertises DATAGRAM support, so the server must answer on
		/// unidirectional streams. Before the fix the reply took the datagram
		/// path, quiche rejected it (`InvalidState`) and the client saw no echo
		/// at all.
		#[tokio::test]
		async fn quiche_outbound_udp_stream_relay_roundtrip() -> eyre::Result<()> {
			let uuid = Uuid::new_v4();
			let password = "test-password";
			let (addr, _dir) = start_echo_server(uuid, password, ConnectionOpts::default()).await?;

			let outbound = Arc::new(
				client_builder(addr, uuid, password, TransportUdpRelayMode::Stream)
					.reconnect(no_reconnect())
					.build()
					.await?,
			);
			outbound.start_poll().await?;

			let echoed = udp_roundtrip(outbound.clone(), b"udp-stream-relay-probe").await?;
			assert_eq!(echoed, &b"udp-stream-relay-probe"[..]);

			outbound.close();
			Ok(())
		}

		/// The mirror image: the server transport has DATAGRAM disabled while
		/// the client is in datagram mode. The client must fall back to
		/// unidirectional streams for its uplink, otherwise quiche closes the
		/// connection on receipt of a DATAGRAM frame it did not enable. The
		/// server still answers with datagrams (the client can receive them).
		#[tokio::test]
		async fn quiche_outbound_udp_with_server_stream_transport_roundtrip() -> eyre::Result<()> {
			let uuid = Uuid::new_v4();
			let password = "test-password";
			let server_opts = ConnectionOpts {
				udp_relay_mode: TransportUdpRelayMode::Stream,
				..Default::default()
			};
			let (addr, _dir) = start_echo_server(uuid, password, server_opts).await?;

			let outbound = Arc::new(
				client_builder(addr, uuid, password, TransportUdpRelayMode::Datagram)
					.reconnect(no_reconnect())
					.build()
					.await?,
			);
			outbound.start_poll().await?;

			let echoed = udp_roundtrip(outbound.clone(), b"udp-server-stream-transport-probe").await?;
			assert_eq!(echoed, &b"udp-server-stream-transport-probe"[..]);

			outbound.close();
			Ok(())
		}
	}
}

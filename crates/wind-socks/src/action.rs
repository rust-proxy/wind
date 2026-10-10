use std::time::Duration;

use async_trait::async_trait;
use fast_socks5::client::{Config as Socks5Config, Socks5Stream};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tracing::Instrument;
use wind_core::{
	FlowContext, Outbound,
	tcp::{AbstractTcpStream, TcpKeepalive},
	types::TargetAddr,
	udp::UdpStream,
};

/// Options for a SOCKS5 outbound action handler.
#[derive(Clone, Debug)]
pub struct SocksOutboundOpts {
	/// SOCKS5 proxy address (e.g. "127.0.0.1:1080").
	pub addr: String,
	/// Optional authentication credentials.
	pub username: Option<String>,
	pub password: Option<String>,
	/// Whether UDP sessions may be handed to this outbound at all.
	///
	/// UDP ASSOCIATE is enabled only when explicitly set to true.
	pub allow_udp: Option<bool>,
	/// Half-close idle timeout for the TCP relay.  Once one side sends FIN,
	/// the relay is reaped after this much inactivity.  Set to
	/// `Duration::ZERO` to disable.
	pub stream_timeout: Duration,
	/// TCP keepalive configuration for the outbound socket.  When `None`,
	/// `SO_KEEPALIVE` is not set.
	pub tcp_keepalive: Option<TcpKeepalive>,
}

/// SOCKS5 outbound handler implementing the object-safe [`Outbound`] trait.
pub struct SocksOutbound {
	opts: SocksOutboundOpts,
	udp: crate::udp_outbound::SocksUdpOptions,
	cancel: tokio_util::sync::CancellationToken,
}

impl SocksOutbound {
	pub fn new(opts: SocksOutboundOpts) -> Self {
		Self {
			opts,
			udp: Default::default(),
			cancel: tokio_util::sync::CancellationToken::new(),
		}
	}

	pub fn with_udp_options(
		mut self,
		udp: crate::udp_outbound::SocksUdpOptions,
		cancel: tokio_util::sync::CancellationToken,
	) -> eyre::Result<Self> {
		udp.validate()?;
		crate::udp_outbound::authentication(&self.opts)?;
		self.udp = udp;
		self.cancel = cancel;
		Ok(self)
	}
}

#[async_trait]
impl Outbound for SocksOutbound {
	async fn handle_tcp(&self, ctx: FlowContext, mut stream: Box<dyn AbstractTcpStream>) -> eyre::Result<()> {
		let target = ctx.target;
		let span = tracing::debug_span!("socks5_tcp", target = %target, addr = %self.opts.addr);
		async move {
			let mut socks_stream = connect_socks5_tcp(&self.opts.addr, &target, &self.opts).await?;
			let (_, _, err) = wind_core::io::copy_bidirectional(&mut stream, &mut socks_stream, self.opts.stream_timeout).await;
			_ = socks_stream.shutdown().await;
			if let Some(e) = err {
				tracing::debug!(error = %e, "socks5 copy_bidirectional ended");
			}
			Ok(())
		}
		.instrument(span)
		.await
	}

	async fn handle_udp(&self, _ctx: FlowContext, stream: UdpStream) -> eyre::Result<()> {
		if !self.opts.allow_udp.unwrap_or(false) {
			return Err(eyre::eyre!("SOCKS5 UDP is disabled (allow_udp is false or unset)"));
		}
		crate::udp_outbound::run(&self.opts, &self.udp, &self.cancel, stream).await
	}
}

/// Connect to `target_addr` through the SOCKS5 proxy.
async fn connect_socks5_tcp(
	socks_addr: &str,
	target_addr: &TargetAddr,
	opts: &SocksOutboundOpts,
) -> eyre::Result<Socks5Stream<TcpStream>> {
	let config = Socks5Config::default();

	let (target_host, target_port) = match target_addr {
		TargetAddr::IPv4(ip, port) => (ip.to_string(), *port),
		TargetAddr::IPv6(ip, port) => (ip.to_string(), *port),
		TargetAddr::Domain(domain, port) => (domain.clone(), *port),
	};

	let stream = match (&opts.username, &opts.password) {
		(Some(user), Some(pass)) => {
			Socks5Stream::connect_with_password(socks_addr, target_host, target_port, user.clone(), pass.clone(), config)
				.await
				.map_err(|e| eyre::eyre!("SOCKS5 connect failed: {}", e))?
		}
		_ => Socks5Stream::connect(socks_addr, target_host, target_port, config)
			.await
			.map_err(|e| eyre::eyre!("SOCKS5 connect failed: {}", e))?,
	};

	// Disable Nagle on the hop to the SOCKS proxy — the same small-write
	// latency concern as the direct path (see
	// `wind_base::direct::connect_direct_tcp`).
	if let Err(e) = stream.get_socket_ref().set_nodelay(true) {
		tracing::debug!(error = %e, "failed to set TCP_NODELAY on socks5 outbound");
	}

	// Enable TCP keepalive with the same rationale as the direct path.
	if let Some(ref ka) = opts.tcp_keepalive
		&& let Err(e) = apply_socks_keepalive(stream.get_socket_ref(), ka)
	{
		tracing::debug!(error = %e, "failed to set TCP keepalive on socks5 outbound");
	}

	Ok(stream)
}

fn apply_socks_keepalive(s: &tokio::net::TcpStream, ka: &TcpKeepalive) -> std::io::Result<()> {
	#[cfg(unix)]
	{
		use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
		let sock = unsafe { socket2::Socket::from_raw_fd(s.as_raw_fd()) };
		if let Err(e) = sock.set_keepalive(true) {
			let _ = sock.into_raw_fd();
			return Err(e);
		}
		let _ = sock.into_raw_fd();
	}
	#[cfg(any(target_os = "linux", target_os = "android"))]
	{
		use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
		let sock = unsafe { socket2::Socket::from_raw_fd(s.as_raw_fd()) };
		let socket2_ka = socket2::TcpKeepalive::new()
			.with_time(ka.idle)
			.with_interval(ka.interval)
			.with_retries(ka.retries);
		let res = sock.set_tcp_keepalive(&socket2_ka);
		let _ = sock.into_raw_fd();
		res?
	}
	let _ = (s, ka);
	Ok(())
}

#[cfg(test)]
mod tests {
	use std::{future::Future, net::SocketAddr, sync::Arc};

	use bytes::Bytes;
	use tokio::sync::mpsc;
	use wind_core::{
		Dispatcher, FlowContext, InboundCallback, RouteAction, Router,
		hooks::Protocol,
		rule::{InboundType, NetworkType},
		types::TargetAddr,
		udp::{UdpPacket, UdpStream},
	};

	use super::*;

	/// Routes every flow to the `socks5` handler registered by the tests.
	struct ForwardSocks5;

	impl Router for ForwardSocks5 {
		#[allow(clippy::manual_async_fn)]
		fn route(&self, _ctx: &FlowContext) -> impl Future<Output = eyre::Result<RouteAction>> + Send {
			async { Ok(RouteAction::Forward("socks5".to_string())) }
		}
	}

	fn outbound(allow_udp: Option<bool>) -> SocksOutbound {
		SocksOutbound::new(SocksOutboundOpts {
			addr: "127.0.0.1:1080".to_string(),
			username: None,
			password: None,
			allow_udp,
			stream_timeout: Duration::ZERO,
			tcp_keepalive: None,
		})
	}

	/// A UDP session the handler is not expected to read from.
	fn udp_session_without_data() -> UdpStream {
		let (tx, _peer_receiver) = mpsc::channel::<UdpPacket>(1);
		let (_peer_sender, rx) = mpsc::channel::<UdpPacket>(1);
		UdpStream { tx, rx }
	}

	fn udp_ctx() -> FlowContext {
		FlowContext {
			target: TargetAddr::Domain("example.com".into(), 53),
			network: NetworkType::Udp,
			source: Some("192.0.2.10:40000".parse::<SocketAddr>().unwrap()),
			inbound_tag: Arc::from("socks-in"),
			protocol: Protocol::Socks5,
			user: None,
			inbound_port: Some(1080),
			inbound_type: Some(InboundType::Socks),
		}
	}

	/// An operator-disabled UDP path is intentional, but it must still be
	/// reported: `Ok(())` made the refusal indistinguishable from a delivered
	/// datagram.
	#[tokio::test]
	async fn udp_session_is_refused_with_an_explicit_error_when_udp_is_disabled() {
		for allow_udp in [Some(false), None] {
			let err = outbound(allow_udp)
				.handle_udp(udp_ctx(), udp_session_without_data())
				.await
				.expect_err("a disabled UDP path must fail loudly, not drop silently");
			let msg = err.to_string();
			assert!(
				msg.contains("allow_udp"),
				"unexpected error for allow_udp={allow_udp:?}: {msg}"
			);
		}
	}

	/// End-to-end at the dispatcher boundary: the error must reach the inbound
	/// callback (which logs it at `error`) rather than being converted into a
	/// successful session.
	#[tokio::test]
	async fn dispatcher_reports_the_refused_udp_session_instead_of_success() {
		let mut dispatcher = Dispatcher::new(ForwardSocks5);
		dispatcher.add_handler("socks5", Arc::new(outbound(Some(false))));

		let (tx, _peer_receiver) = mpsc::channel::<UdpPacket>(4);
		let (first_tx, rx) = mpsc::channel::<UdpPacket>(1);
		first_tx
			.try_send(UdpPacket {
				source: None,
				target: TargetAddr::Domain("example.com".into(), 53),
				payload: Bytes::from_static(b"query"),
			})
			.expect("pre-load the first datagram so the dispatcher can route");

		let err = dispatcher
			.handle_udpstream(udp_ctx(), UdpStream { tx, rx })
			.await
			.expect_err("the dispatcher must not turn a refused UDP session into success");
		assert!(err.to_string().contains("allow_udp"), "unexpected error: {err}");
	}
}

use async_trait::async_trait;
use fast_socks5::client::{Config as Socks5Config, Socks5Stream};
use tokio::net::TcpStream;
use tracing::Instrument;
use wind_core::{OutboundAction, tcp::AbstractTcpStream, types::TargetAddr, udp::UdpStream};

/// Options for a SOCKS5 outbound action handler.
#[derive(Clone, Debug)]
pub struct Socks5ActionOpts {
	/// SOCKS5 proxy address (e.g. "127.0.0.1:1080").
	pub addr: String,
	/// Optional authentication credentials.
	pub username: Option<String>,
	pub password: Option<String>,
	/// Whether to allow UDP traffic (sent directly, not over SOCKS5).
	pub allow_udp: Option<bool>,
}

/// SOCKS5 outbound handler implementing the object-safe `OutboundAction` trait.
pub struct Socks5Action {
	opts: Socks5ActionOpts,
}

impl Socks5Action {
	pub fn new(opts: Socks5ActionOpts) -> Self {
		Self { opts }
	}
}

#[async_trait]
impl OutboundAction for Socks5Action {
	async fn handle_tcp(&self, target: TargetAddr, mut stream: Box<dyn AbstractTcpStream>) -> eyre::Result<()> {
		let span = tracing::debug_span!("socks5_tcp", target = %target, addr = %self.opts.addr);
		async move {
			let mut socks_stream = connect_socks5_tcp(&self.opts.addr, &target, &self.opts).await?;
			if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut socks_stream).await {
				tracing::debug!(error = %e, "socks5 copy_bidirectional ended");
			}
			Ok(())
		}
		.instrument(span)
		.await
	}

	async fn handle_udp(&self, _udp_stream: UdpStream) -> eyre::Result<()> {
		if !self.opts.allow_udp.unwrap_or(false) {
			tracing::debug!("socks5 outbound disallows UDP, dropping");
			return Ok(());
		}
		tracing::warn!("UDP-over-SOCKS5 is not implemented");
		Ok(())
	}
}

/// Connect to `target_addr` through the SOCKS5 proxy.
async fn connect_socks5_tcp(
	socks_addr: &str,
	target_addr: &TargetAddr,
	opts: &Socks5ActionOpts,
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

	Ok(stream)
}

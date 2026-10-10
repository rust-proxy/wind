//! SOCKS5 UDP ASSOCIATE transport, independent of any QUIC implementation.

use std::{collections::HashSet, net::SocketAddr, time::Duration};

use bytes::Bytes;
use eyre::WrapErr;
use fast_socks5::{AuthenticationMethod, Socks5Command, client::Socks5Stream, util::target_addr::TargetAddr as SocksTarget};
use tokio::{
	io::AsyncReadExt,
	net::{TcpStream, UdpSocket},
};
use tokio_util::sync::CancellationToken;
use wind_core::{
	types::TargetAddr,
	udp::{UdpPacket, UdpStream},
};

use crate::{action::SocksOutboundOpts, convert_addr, convert_to_socks_addr};

const BUFFER_SIZE: usize = 65536;
const MAX_TARGETS: usize = 4096;

/// UDP-specific options. Existing TCP construction does not need these fields.
#[derive(Clone, Debug)]
pub struct SocksUdpOptions {
	pub timeout: Duration,
	pub buffer_size: usize,
	pub reconnect: bool,
	pub initial_backoff: Duration,
	pub max_backoff: Duration,
}

impl Default for SocksUdpOptions {
	fn default() -> Self {
		Self {
			timeout: Duration::from_secs(8),
			buffer_size: 2048,
			reconnect: false,
			initial_backoff: Duration::from_millis(500),
			max_backoff: Duration::from_secs(30),
		}
	}
}

impl SocksUdpOptions {
	pub fn validate(&self) -> eyre::Result<()> {
		if self.timeout.is_zero() {
			eyre::bail!("SOCKS5 UDP setup timeout must be positive");
		}
		if self.reconnect && (self.initial_backoff.is_zero() || self.max_backoff.is_zero()) {
			eyre::bail!("SOCKS5 UDP reconnect backoff must be positive");
		}
		Ok(())
	}
}

pub(crate) fn authentication(opts: &SocksOutboundOpts) -> eyre::Result<Option<AuthenticationMethod>> {
	match (&opts.username, &opts.password) {
		(Some(username), Some(password)) if (1..=255).contains(&username.len()) && (1..=255).contains(&password.len()) => {
			Ok(Some(AuthenticationMethod::Password {
				username: username.clone(),
				password: password.clone(),
			}))
		}
		(None, None) => Ok(None),
		_ => eyre::bail!("SOCKS5 username and password must be configured together and each contain 1 to 255 bytes"),
	}
}

struct Association {
	control: TcpStream,
	udp: UdpSocket,
}

impl Association {
	async fn connect(opts: &SocksOutboundOpts) -> eyre::Result<Self> {
		let auth = authentication(opts)?;
		let control = TcpStream::connect(&opts.addr)
			.await
			.wrap_err("SOCKS5 control connection failed")?;
		let peer = control.peer_addr()?;
		let mut socks = Socks5Stream::use_stream(control, auth, Default::default())
			.await
			.map_err(|_| eyre::eyre!("SOCKS5 authentication failed"))?;
		let unspecified: SocketAddr = if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse()?;
		let bound = socks
			.request(Socks5Command::UDPAssociate, SocksTarget::Ip(unspecified))
			.await
			.wrap_err("SOCKS5 UDP ASSOCIATE failed")?;
		let mut relay = match bound {
			SocksTarget::Ip(addr) => addr,
			SocksTarget::Domain(host, port) => tokio::net::lookup_host((host.as_str(), port))
				.await?
				.next()
				.ok_or_else(|| eyre::eyre!("SOCKS5 UDP relay has no address"))?,
		};
		if relay.port() == 0 {
			eyre::bail!("SOCKS5 UDP relay port must be nonzero");
		}
		if relay.ip().is_unspecified() {
			relay.set_ip(peer.ip());
		}
		let bind = if relay.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
		let udp = UdpSocket::bind(bind).await?;
		udp.connect(relay).await?;
		Ok(Self {
			control: socks.get_socket(),
			udp,
		})
	}
}

async fn associate(opts: &SocksOutboundOpts, udp: &SocksUdpOptions) -> eyre::Result<Association> {
	tokio::time::timeout(udp.timeout, Association::connect(opts))
		.await
		.wrap_err("SOCKS5 UDP setup timed out")?
}

pub(crate) async fn run(
	opts: &SocksOutboundOpts,
	udp: &SocksUdpOptions,
	token: &CancellationToken,
	mut stream: UdpStream,
) -> eyre::Result<()> {
	udp.validate()?;
	authentication(opts)?;
	// Dropping this future also drops the control connection, UDP socket and
	// all reconnect state. No association tasks outlive the owning stream.
	let replies = stream.tx.clone();
	let transfer = async {
		let mut association = associate(opts, udp).await?;
		loop {
			match relay(&mut association, &mut stream, udp.buffer_size).await {
				Ok(()) => return Ok(()),
				Err(error) if !udp.reconnect => return Err(error),
				Err(error) => tracing::warn!(%error, "SOCKS5 UDP association lost"),
			}
			drop(association);
			let mut backoff = udp.initial_backoff.min(udp.max_backoff);
			loop {
				let attempt = async move {
					tokio::time::sleep(backoff).await;
					associate(opts, udp).await
				};
				tokio::pin!(attempt);
				let result = loop {
					tokio::select! {
						result = &mut attempt => break result,
						packet = stream.rx.recv() => {
							// UDP packets during a broken association are discarded;
							// closing the input also ends an otherwise endless retry.
							if packet.is_none() { return Ok(()); }
						},
					}
				};
				match result {
					Ok(next) => {
						association = next;
						break;
					}
					Err(error) => tracing::warn!(%error, "SOCKS5 UDP reconnect failed"),
				}
				backoff = backoff.saturating_mul(2).min(udp.max_backoff);
			}
		}
	};
	tokio::select! {
		_ = token.cancelled() => Ok(()),
		_ = replies.closed() => Ok(()),
		result = transfer => result,
	}
}

// A remote resolver may return an IP even when the request used a domain.
// Trust only the negotiated relay; never resolve that domain locally to check
// it.
fn accepts_reply(targets: &HashSet<TargetAddr>, source: &TargetAddr) -> bool {
	targets.contains(source)
		|| targets.iter().any(|target| match (target, source) {
			(TargetAddr::Domain(_, expected), TargetAddr::IPv4(_, port) | TargetAddr::IPv6(_, port)) => expected == port,
			_ => false,
		})
}

async fn relay(association: &mut Association, stream: &mut UdpStream, buffer_hint: usize) -> eyre::Result<()> {
	let mut incoming = vec![0; BUFFER_SIZE];
	let mut packet = Vec::with_capacity(buffer_hint.clamp(2048, BUFFER_SIZE));
	let mut targets = HashSet::new();
	let mut control_byte = [0];
	loop {
		tokio::select! {
			result = association.control.read(&mut control_byte) => {
				result?;
				eyre::bail!("SOCKS5 control connection closed or sent unexpected data");
			},
			request = stream.rx.recv() => {
				let Some(request) = request else { return Ok(()); };
				if targets.len() >= MAX_TARGETS && !targets.contains(&request.target) { continue; }
				let header = fast_socks5::new_udp_header(convert_to_socks_addr(&request.target))?;
				if request.payload.len() + header.len() > 65507 { continue; }
				packet.clear();
				packet.extend_from_slice(&header);
				packet.extend_from_slice(&request.payload);
				association.udp.send(&packet).await?;
				targets.insert(request.target);
			},
			result = association.udp.recv(&mut incoming) => {
				let size = result?;
				let Ok((0, source, payload)) = fast_socks5::parse_udp_request(&incoming[..size]).await else { continue; };
				let source = convert_addr(&source);
				if !accepts_reply(&targets, &source) { continue; }
				let response = UdpPacket { source: Some(source.clone()), target: source, payload: Bytes::copy_from_slice(payload) };
				match stream.tx.try_send(response) {
					Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {},
					Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return Ok(()),
				}
			},
		}
	}
}

#[cfg(test)]
mod tests;

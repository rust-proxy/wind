use std::{
	net::{IpAddr, Ipv4Addr, SocketAddr},
	sync::Arc,
};

use fast_socks5::{ReplyError, Socks5Command, server::Socks5ServerProtocol, util::target_addr::TargetAddr as SocksTargetAddr};
use snafu::ResultExt;
use tokio::{
	net::{TcpListener, TcpStream},
	sync::mpsc,
};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument as _, error, info, warn};
use wind_core::{AbstractInbound, InboundCallback, types::TargetAddr, udp::UdpStream};

use crate::{CallbackSnafu, Error, IoSnafu, SocksSnafu};

pub struct SocksInboundOpt {
	/// Bind on address address. eg. `127.0.0.1:1080`
	pub listen_addr: SocketAddr,

	/// Our external IP address to be sent in reply packets (required for UDP)
	pub public_addr: Option<std::net::IpAddr>,

	/// Choose authentication type
	pub auth: AuthMode,

	/// Don't perform the auth handshake, send directly the command request
	pub skip_auth: bool,

	/// Allow UDP proxying, requires public-addr to be set
	pub allow_udp: bool,
}

pub enum AuthMode {
	NoAuth,
	Password { username: String, password: String },
}

pub struct SocksInbound {
	opts: Arc<SocksInboundOpt>,
	cancel: CancellationToken,
}

impl AbstractInbound for SocksInbound {
	async fn listen(&self, cb: &impl InboundCallback) -> eyre::Result<()> {
		let listener = TcpListener::bind(self.opts.listen_addr).await?;
		loop {
			tokio::select! {
				_ = self.cancel.cancelled() => {
					info!(target: "socks_in_reactor", "Cancellation received, shutting down");
					break;
				}
				res = listener.accept() => {
					let (stream, client_addr) = match res {
						Err(err) => {
							error!(target:"[IN] REACTOR", "{:}", err);
							continue;
						}
						Ok(conn) => conn,
					};

					let opts = self.opts.clone();
					let cb = cb.clone();
					tokio::spawn(
						async move {
							if let Err(err) = handle_income(opts, stream, client_addr, cb).await {
								error!(target: "socks_in_handler" , "{:}", err);
							}
						}
						.in_current_span(),
					);
				}
			};
		}
		Ok(())
	}
}

impl SocksInbound {
	pub async fn new(opts: SocksInboundOpt, cancel: CancellationToken) -> Self {
		Self {
			opts: Arc::new(opts),
			cancel,
		}
	}
}

async fn handle_income(
	opts: Arc<SocksInboundOpt>,
	stream: TcpStream,
	client_addr: SocketAddr,
	cb: impl InboundCallback,
) -> Result<(), Error> {
	let proto = match &opts.auth {
		AuthMode::NoAuth => Socks5ServerProtocol::accept_no_auth(stream).await.context(SocksSnafu)?,
		AuthMode::Password { username, password } => {
			Socks5ServerProtocol::accept_password_auth(stream, |user, pass| user == *username && pass == *password)
				.await
				.context(SocksSnafu)?
				.0
		}
	};
	let (proto, cmd, target_addr) = proto.read_command().await?;

	match cmd {
		Socks5Command::TCPConnect => {
			let inner = proto
				.reply_success(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
				.await?;
			let target_addr = match target_addr {
				SocksTargetAddr::Ip(socket_addr) => match socket_addr {
					SocketAddr::V4(socket_addr) => TargetAddr::IPv4(*socket_addr.ip(), socket_addr.port()),
					SocketAddr::V6(socket_addr) => TargetAddr::IPv6(*socket_addr.ip(), socket_addr.port()),
				},
				SocksTargetAddr::Domain(domain, port) => TargetAddr::Domain(domain, port),
			};
			cb.handle_tcpstream(target_addr, inner).await.context(CallbackSnafu)?;
		}
		Socks5Command::UDPAssociate if opts.allow_udp => {
			// RFC 1928 §6: the reply IP in BND.ADDR must be reachable by the
			// client. Previously hardcoded to 127.0.0.1, which broke any
			// non-loopback client. Prefer the operator-supplied `public_addr`;
			// otherwise fall back to the local TCP listen address (still
			// reachable for same-host clients) and log a warning.
			let reply_ip = match opts.public_addr {
				Some(ip) => ip,
				None => {
					warn!(
						target: "socks_in_handler",
						"SOCKS5 UDPAssociate from {} without `public_addr` configured; \
						 falling back to listen-IP {}. Remote clients will not be able \
						 to reach the UDP relay.",
						client_addr,
						opts.listen_addr.ip(),
					);
					opts.listen_addr.ip()
				}
			};
			let expected_client_ip = client_addr.ip();
			crate::ext::run_udp_proxy(proto, &target_addr, None, reply_ip, move |inbound| async move {
				let (tx_to_out, rx_from_in) = mpsc::channel(100);
				let (tx_to_in, rx_from_out) = mpsc::channel(100);

				let udp_stream = UdpStream {
					tx: tx_to_out,
					rx: rx_from_out,
				};

				let serve_stream = UdpStream {
					tx: tx_to_in,
					rx: rx_from_in,
				};

				let cb = cb.clone();
				tokio::spawn(
					async move {
						if let Err(e) = cb.handle_udpstream(udp_stream).await {
							error!(target: "socks_in_handler", "UDP association error: {}", e);
						}
					}
					.in_current_span(),
				);

				crate::udp::serve_udp_with_client(inbound.into(), serve_stream, Some(expected_client_ip))
					.await
					.context(IoSnafu)
			})
			.await?;
		}
		_ => {
			proto.reply_error(&ReplyError::CommandNotSupported).await?;
			return Err(ReplyError::CommandNotSupported.into());
		}
	};
	Ok(())
}

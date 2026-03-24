use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use fast_socks5::{ReplyError, Socks5Command, server::Socks5ServerProtocol, util::target_addr::TargetAddr as SocksTargetAddr};
use snafu::ResultExt;
use tokio::{
	net::{TcpListener, TcpStream},
	sync::mpsc,
};
use tokio_util::sync::CancellationToken;
use wind_core::{AbstractInbound, InboundCallback, error, info, types::TargetAddr, udp::UdpStream};

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
	opts: SocksInboundOpt,
	cancel: CancellationToken,
}

impl AbstractInbound for SocksInbound {
	async fn listen(&self, cb: &impl InboundCallback) -> eyre::Result<()> {
		let listener = TcpListener::bind(self.opts.listen_addr).await?;
		loop {
			tokio::select! {
				_ = self.cancel.cancelled() => {
					info!(target: "[IN] REACTOR", "Cancellation received, shutting down");
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

					if let Err(err) = self.handle_income(stream, client_addr, cb).await {
						error!(target: "[IN] HANDLER" , "{:}", err);
					}
				}
			};
		}
		Ok(())
	}
}

impl SocksInbound {
	pub async fn new(opts: SocksInboundOpt, cancel: CancellationToken) -> Self {
		Self { opts, cancel }
	}

	async fn handle_income(&self, stream: TcpStream, _client_addr: SocketAddr, cb: &impl InboundCallback) -> Result<(), Error> {
		let proto = match &self.opts.auth {
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
			Socks5Command::UDPAssociate if self.opts.allow_udp => {
				let reply_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
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
					tokio::spawn(async move {
						if let Err(e) = cb.handle_udpstream(udp_stream).await {
							error!(target: "[IN] HANDLER", "UDP association error: {}", e);
						}
					});

					crate::udp::serve_udp(inbound.into(), serve_stream).await.context(IoSnafu)
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
}

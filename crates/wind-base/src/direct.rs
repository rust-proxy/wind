use std::{
	net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
	sync::Arc,
};

use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tracing::Instrument;
use wind_core::{
	OutboundAction,
	dispatcher::BoxFuture,
	resolve::Resolver,
	tcp::AbstractTcpStream,
	types::TargetAddr,
	udp::{UdpPacket, UdpStream},
};

use crate::resolve::resolve_target;

/// Options for a direct outbound connection.
#[derive(Clone, Debug)]
pub struct DirectOutboundOpts {
	pub bind_ipv4: Option<Ipv4Addr>,
	pub bind_ipv6: Option<Ipv6Addr>,
	pub bind_device: Option<String>,
}

/// Direct outbound handler – connects to the target without any proxy.
pub struct DirectOutbound {
	opts: DirectOutboundOpts,
	resolver: Arc<dyn Resolver>,
}

impl DirectOutbound {
	pub fn new(opts: DirectOutboundOpts, resolver: Arc<dyn Resolver>) -> Self {
		Self { opts, resolver }
	}
}

impl OutboundAction for DirectOutbound {
	fn handle_tcp<'a>(&'a self, target: TargetAddr, mut stream: Box<dyn AbstractTcpStream>) -> BoxFuture<'a, eyre::Result<()>> {
		let span = tracing::debug_span!("direct_tcp", target = %target);
		Box::pin(
			async move {
				let target_sa = resolve_target(&target, self.resolver.as_ref()).await?;
				let mut target_stream = connect_direct_tcp(target_sa, &self.opts).await?;
				if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await {
					tracing::debug!(error = %e, "direct copy_bidirectional ended");
				}
				Ok(())
			}
			.instrument(span),
		)
	}

	fn handle_udp<'a>(&'a self, udp_stream: UdpStream) -> BoxFuture<'a, eyre::Result<()>> {
		let span = tracing::debug_span!("direct_udp");
		Box::pin(relay_udp_direct(self.opts.clone(), self.resolver.clone(), udp_stream).instrument(span))
	}
}

/// Open a direct TCP connection to `addr`, optionally binding a local
/// address/device as specified in `opts`.
pub async fn connect_direct_tcp(addr: SocketAddr, opts: &DirectOutboundOpts) -> eyre::Result<TcpStream> {
	let socket = match addr {
		SocketAddr::V4(_) => TcpSocket::new_v4()?,
		SocketAddr::V6(_) => TcpSocket::new_v6()?,
	};

	let bind_addr: Option<SocketAddr> = match addr {
		SocketAddr::V4(_) => opts.bind_ipv4.map(|ip| SocketAddr::V4(SocketAddrV4::new(ip, 0))),
		SocketAddr::V6(_) => opts.bind_ipv6.map(|ip| SocketAddr::V6(SocketAddrV6::new(ip, 0, 0, 0))),
	};

	if let Some(local) = bind_addr {
		socket.bind(local)?;
	}

	#[cfg(any(target_os = "linux", target_os = "android"))]
	if let Some(ref dev) = opts.bind_device {
		socket.bind_device(Some(dev.as_bytes()))?;
	}

	Ok(socket.connect(addr).await?)
}

async fn relay_udp_direct(_opts: DirectOutboundOpts, resolver: Arc<dyn Resolver>, udp_stream: UdpStream) -> eyre::Result<()> {
	let UdpStream { tx, mut rx } = udp_stream;

	let relay_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

	// Task: client → target
	let socket_send = relay_socket.clone();
	let send_task = tokio::spawn(async move {
		while let Some(pkt) = rx.recv().await {
			let target_sa = match resolve_target(&pkt.target, resolver.as_ref()).await {
				Ok(sa) => sa,
				Err(err) => {
					tracing::warn!(target = %pkt.target, error = %err, "UDP resolve failed");
					continue;
				}
			};
			if let Err(err) = socket_send.send_to(&pkt.payload, target_sa).await {
				tracing::warn!(target = %target_sa, error = %err, "UDP send failed");
			}
		}
	});

	// Task: target → client
	let socket_recv = relay_socket.clone();
	let recv_task = tokio::spawn(async move {
		let mut buf = vec![0u8; 65535];
		loop {
			match socket_recv.recv_from(&mut buf).await {
				Ok((len, src_addr)) => {
					use bytes::Bytes;
					let payload = Bytes::copy_from_slice(&buf[..len]);
					let pkt = UdpPacket {
						source: Some(TargetAddr::from(src_addr)),
						target: TargetAddr::from(src_addr),
						payload,
					};
					if tx.send(pkt).await.is_err() {
						break;
					}
				}
				Err(err) => {
					tracing::warn!(error = %err, "UDP recv error");
					break;
				}
			}
		}
	});

	tokio::select! {
		_ = send_task => {}
		_ = recv_task => {}
	}

	Ok(())
}

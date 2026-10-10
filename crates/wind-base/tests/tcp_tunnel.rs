//! Prebound TCP tunnel ownership, dispatch context, and shutdown regression.

use std::{
	net::SocketAddr,
	sync::{
		Arc,
		atomic::{AtomicUsize, Ordering},
	},
	time::Duration,
};

use async_trait::async_trait;
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::{TcpListener, TcpStream},
	sync::mpsc,
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use wind_base::tunnel::TunnelTcpInbound;
use wind_core::{
	AbstractInbound, Dispatcher, FlowContext, Outbound, Protocol as WindProtocol, RouteAction, Router, rule::NetworkType,
	tcp::AbstractTcpStream, types::TargetAddr, udp::UdpStream,
};

struct InspectRouter(mpsc::UnboundedSender<FlowContext>);

impl Router for InspectRouter {
	async fn route(&self, ctx: &FlowContext) -> eyre::Result<RouteAction> {
		self.0.send(ctx.clone())?;
		Ok(RouteAction::Forward("default".into()))
	}
}

struct ActiveRelay(Arc<AtomicUsize>);

impl Drop for ActiveRelay {
	fn drop(&mut self) {
		self.0.fetch_sub(1, Ordering::SeqCst);
	}
}

struct LoopbackOutbound(Arc<AtomicUsize>);

#[async_trait]
impl Outbound for LoopbackOutbound {
	async fn handle_tcp(&self, ctx: FlowContext, mut stream: Box<dyn AbstractTcpStream + 'static>) -> eyre::Result<()> {
		self.0.fetch_add(1, Ordering::SeqCst);
		let _active = ActiveRelay(self.0.clone());
		let mut remote = TcpStream::connect(ctx.target.to_string()).await?;
		tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
		Ok(())
	}

	async fn handle_udp(&self, _ctx: FlowContext, _stream: UdpStream) -> eyre::Result<()> {
		Err(eyre::eyre!("unexpected UDP dispatch"))
	}
}

#[tokio::test]
async fn prebound_forward_relays_bytes_preserves_context_and_drains_active_connections() -> eyre::Result<()> {
	tokio::time::timeout(Duration::from_secs(5), async {
		let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
		let remote = echo_listener.local_addr()?;
		let echo = AbortOnDropHandle::new(tokio::spawn(async move {
			let (mut stream, _) = echo_listener.accept().await?;
			let mut buffer = [0u8; 64];
			loop {
				let count = stream.read(&mut buffer).await?;
				if count == 0 {
					break;
				}
				stream.write_all(&buffer[..count]).await?;
			}
			Ok::<_, std::io::Error>(())
		}));
		let cancel = CancellationToken::new();
		let _cancel_on_drop = cancel.clone().drop_guard();
		let inbound = TunnelTcpInbound::bind(
			SocketAddr::from(([127, 0, 0, 1], 0)),
			(remote.ip().to_string(), remote.port()),
			cancel.clone(),
		)?;
		let listen = inbound.local_addr()?;
		assert!(std::net::TcpListener::bind(listen).is_err());
		let (context_tx, mut context_rx) = mpsc::unbounded_channel();
		let active = Arc::new(AtomicUsize::new(0));
		let mut dispatcher = Dispatcher::new(InspectRouter(context_tx));
		dispatcher.add_handler("default", Arc::new(LoopbackOutbound(active.clone())));
		let inbound_task = AbortOnDropHandle::new(tokio::spawn(async move { inbound.listen(&dispatcher).await }));
		let mut client = TcpStream::connect(listen).await?;
		let peer = client.local_addr()?;
		client.write_all(b"forwarded").await?;
		let mut response = [0u8; 9];
		client.read_exact(&mut response).await?;
		assert_eq!(&response, b"forwarded");
		let ctx = context_rx.recv().await.ok_or_else(|| eyre::eyre!("no routing context"))?;
		assert_eq!(ctx.target, TargetAddr::from(remote));
		assert_eq!(ctx.source, Some(peer));
		assert_eq!(ctx.network, NetworkType::Tcp);
		assert_eq!(ctx.protocol, WindProtocol::Tunnel);
		assert_eq!(&*ctx.inbound_tag, "tunnel");
		assert_eq!(ctx.inbound_port, Some(listen.port()));
		assert!(ctx.user.is_none());
		assert!(ctx.inbound_type.is_none());
		assert_eq!(active.load(Ordering::SeqCst), 1);
		cancel.cancel();
		inbound_task.await??;
		assert_eq!(active.load(Ordering::SeqCst), 0, "listen must drain active dispatch tasks");
		assert_eq!(client.read(&mut response).await?, 0);
		echo.await??;
		let _rebound = std::net::TcpListener::bind(listen)?;
		Ok::<_, eyre::Report>(())
	})
	.await?
}

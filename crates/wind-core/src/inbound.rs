use crate::{tcp::AbstractTcpStream, types::TargetAddr, udp::UdpStream};

pub trait FutResult<T> = Future<Output = eyre::Result<T>> + Send + Sync;

pub trait AbstractInbound {
	/// Should not return!
	fn listen(&self, cb: &impl InboundCallback) -> impl FutResult<()>;
}

pub trait InboundCallback: Send + Sync + Clone + 'static {
	fn handle_tcpstream(&self, target_addr: TargetAddr, stream: impl AbstractTcpStream + 'static) -> impl FutResult<()>;
	fn handle_udpstream(&self, udp_stream: UdpStream) -> impl FutResult<()>;
}

use std::future::Future;

use crate::{flow::FlowContext, tcp::AbstractTcpStream, udp::UdpStream};

pub trait AbstractInbound {
	/// Should not return!
	fn listen(&self, cb: &impl InboundCallback) -> impl Future<Output = eyre::Result<()>> + Send;
}

pub trait InboundCallback: Send + Sync + Clone + 'static {
	fn handle_tcpstream(
		&self,
		ctx: FlowContext,
		stream: impl AbstractTcpStream + 'static,
	) -> impl Future<Output = eyre::Result<()>> + Send;
	fn handle_udpstream(&self, ctx: FlowContext, udp_stream: UdpStream) -> impl Future<Output = eyre::Result<()>> + Send;
}

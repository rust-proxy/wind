use crate::{flow::FlowContext, tcp::AbstractTcpStream, udp::UdpStream};

pub trait AbstractOutbound {
	/// TCP traffic which needs handled by outbound
	fn handle_tcp(
		&self,
		ctx: FlowContext,
		stream: impl AbstractTcpStream,
		via: Option<impl AbstractOutbound + Sized + Send>,
	) -> impl Future<Output = eyre::Result<()>> + Send;
	/// UDP traffic which needs handled by outbound
	fn handle_udp(
		&self,
		ctx: FlowContext,
		udp_stream: UdpStream,
		via: Option<impl AbstractOutbound + Sized + Send>,
	) -> impl Future<Output = eyre::Result<()>> + Send;
}

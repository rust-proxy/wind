use crate::{tcp::AbstractTcpStream, types::TargetAddr, udp::UdpStream};

pub trait AbstractOutbound {
	/// TCP traffic which needs handled by outbound
	fn handle_tcp(
		&self,
		target_addr: TargetAddr,
		stream: impl AbstractTcpStream,
		via: Option<impl AbstractOutbound + Sized + Send>,
	) -> impl Future<Output = eyre::Result<()>> + Send;
	/// UDP traffic which needs handled by outbound
	fn handle_udp(
		&self,
		udp_stream: UdpStream,
		via: Option<impl AbstractOutbound + Sized + Send>,
	) -> impl Future<Output = eyre::Result<()>> + Send;
}

mod compat {
	use std::{
		pin::Pin,
		task::{Context, Poll},
	};

	use pin_project::pin_project;
	use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

	#[pin_project]
	struct TokioTcpCompat {
		#[pin]
		inner: tokio::net::TcpStream,
	}

	impl AsyncRead for TokioTcpCompat {
		fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
			let this = self.project();
			this.inner.poll_read(cx, buf)
		}
	}

	impl AsyncWrite for TokioTcpCompat {
		fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
			let this = self.project();
			this.inner.poll_write(cx, buf)
		}

		fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
			let this = self.project();
			this.inner.poll_flush(cx)
		}

		fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
			let this = self.project();
			this.inner.poll_shutdown(cx)
		}
	}
}

use tokio::io::{AsyncRead, AsyncWrite};

/// Bidirectionally relay bytes between two duplex streams until BOTH sides
/// have closed.
///
/// Delegates to [`tokio::io::copy_bidirectional`], which correctly handles
/// half-close: when one direction sees EOF, it calls `shutdown()` on the
/// opposite writer and continues pumping the remaining direction. The
/// previous hand-rolled implementation broke out of the outer loop on the
/// FIRST EOF, dropping any in-flight bytes flowing the other way — a common
/// problem for HTTP, where a client sends its request and FINs while the
/// server is still streaming the response.
pub async fn copy_io<A, B>(a: &mut A, b: &mut B) -> (usize, usize, Option<std::io::Error>)
where
	A: AsyncRead + AsyncWrite + Unpin + ?Sized,
	B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
	match tokio::io::copy_bidirectional(a, b).await {
		Ok((a2b, b2a)) => (a2b as usize, b2a as usize, None),
		Err(e) => (0, 0, Some(e)),
	}
}

#[cfg(feature = "quic")]
pub mod quinn {
	use std::{
		io,
		pin::Pin,
		task::{Context, Poll},
	};

	use quinn::{RecvStream, SendStream};
	use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

	pub struct QuinnCompat {
		send: SendStream,
		recv: RecvStream,
	}

	impl QuinnCompat {
		pub fn new(send_stream: SendStream, recv_stream: RecvStream) -> Self {
			QuinnCompat {
				send: send_stream,
				recv: recv_stream,
			}
		}

		pub fn send_stream(&self) -> &SendStream {
			&self.send
		}

		pub fn recv_stream(&self) -> &RecvStream {
			&self.recv
		}

		pub fn send_stream_mut(&mut self) -> &mut SendStream {
			&mut self.send
		}

		pub fn recv_stream_mut(&mut self) -> &mut RecvStream {
			&mut self.recv
		}

		pub fn into_inner(self) -> (SendStream, RecvStream) {
			(self.send, self.recv)
		}
	}

	impl AsyncWrite for QuinnCompat {
		fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
			Pin::new(&mut self.send).poll_write(cx, buf).map_err(io::Error::other)
		}

		fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
			Pin::new(&mut self.send).poll_flush(cx)
		}

		fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
			Pin::new(&mut self.send).poll_shutdown(cx)
		}
	}

	impl AsyncRead for QuinnCompat {
		fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
			Pin::new(&mut self.recv).poll_read(cx, buf)
		}
	}
}

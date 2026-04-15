use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const BUFFER_SIZE: usize = 16 * 1024;

pub async fn copy_io<A, B>(a: &mut A, b: &mut B) -> (usize, usize, Option<std::io::Error>)
where
	A: AsyncRead + AsyncWrite + Unpin + ?Sized,
	B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
	let mut a2b = [0u8; BUFFER_SIZE];
	let mut b2a = [0u8; BUFFER_SIZE];

	let mut a2b_num = 0;
	let mut b2a_num = 0;

	let mut last_err = None;

	loop {
		tokio::select! {
		   a2b_res = a.read(&mut a2b) => match a2b_res {
			  Ok(num) => {
				 // EOF
				 if num == 0 {
					break;
				 }
				 a2b_num += num;
				 if let Err(err) = b.write_all(&a2b[..num]).await {
					last_err = Some(err);
					break;
				 }
			  },
			  Err(err) => {
				 last_err = Some(err);
				 break;
			  }
		   },
		   b2a_res = b.read(&mut b2a) => match b2a_res {
			  Ok(num) => {
				 // EOF
				 if num == 0 {
					break;
				 }
				 b2a_num += num;
				 if let Err(err) = a.write_all(&b2a[..num]).await {
					last_err = Some(err);
					break;
				 }
			  },
			  Err(err) => {
				 last_err = Some(err);
				 break;
			  },
		   }
		}
	}

	(a2b_num, b2a_num, last_err)
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

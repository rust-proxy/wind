use std::{
	future::{Future, poll_fn},
	io,
	pin::Pin,
	task::{Context, Poll},
	time::Duration,
};

use tokio::{
	io::{AsyncRead, AsyncWrite, ReadBuf},
	time::{Instant, Sleep},
};

/// Per-direction copy buffer size. 64 KiB keeps enough bytes in flight over
/// high bandwidth-delay-product links (a QUIC tunnel to a distant peer).
const BUFFER_SIZE: usize = 64 * 1024;

struct CopyDirection {
	buffer: Box<[u8]>,
	position: usize,
	length: usize,
	transferred: usize,
	eof: bool,
	shutdown: bool,
}

impl CopyDirection {
	fn new() -> Self {
		Self {
			buffer: vec![0; BUFFER_SIZE].into_boxed_slice(),
			position: 0,
			length: 0,
			transferred: 0,
			eof: false,
			shutdown: false,
		}
	}

	// Each poll does at most one read and one write, keeping the other
	// direction and the idle timer responsive even for always-ready streams.
	fn poll_step<R, W>(
		&mut self,
		reader: &mut R,
		writer: &mut W,
		cx: &mut Context<'_>,
		last_error: &mut Option<io::Error>,
	) -> io::Result<bool>
	where
		R: AsyncRead + Unpin + ?Sized,
		W: AsyncWrite + Unpin + ?Sized,
	{
		if self.shutdown {
			return Ok(false);
		}

		let mut progress = false;
		if self.position == self.length && !self.eof {
			let mut buffer = ReadBuf::new(&mut self.buffer);
			if let Poll::Ready(result) = Pin::new(reader).poll_read(cx, &mut buffer) {
				result?;
				self.position = 0;
				self.length = buffer.filled().len();
				self.eof = self.length == 0;
				progress = true;
			}
		}

		if self.position < self.length {
			if let Poll::Ready(result) = Pin::new(writer).poll_write(cx, &self.buffer[self.position..self.length]) {
				let written = result?;
				if written == 0 {
					return Err(io::ErrorKind::WriteZero.into());
				}
				self.position += written;
				self.transferred += written;
				progress = true;
			}
		} else if self.eof
			&& let Poll::Ready(result) = Pin::new(writer).poll_shutdown(cx)
		{
			if let Err(error) = result {
				*last_error = Some(error);
			}
			self.shutdown = true;
			progress = true;
		}

		Ok(progress)
	}
}

/// Bidirectionally relay bytes between two duplex streams until BOTH sides
/// have closed. The counts include bytes successfully written in each
/// direction.
pub async fn copy_io<A, B>(a: &mut A, b: &mut B) -> (usize, usize, Option<std::io::Error>)
where
	A: AsyncRead + AsyncWrite + Unpin + ?Sized,
	B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
	copy_bidirectional(a, b, Duration::ZERO).await
}

/// Bidirectional relay with a half-close idle reaper. After either read half
/// reaches EOF, the timeout also covers pending writes and shutdowns. A zero
/// timeout disables the reaper. Counts include successfully written bytes.
pub async fn copy_bidirectional<A, B>(
	a: &mut A,
	b: &mut B,
	half_close_timeout: Duration,
) -> (usize, usize, Option<std::io::Error>)
where
	A: AsyncRead + AsyncWrite + Unpin + ?Sized,
	B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
	let mut a2b = CopyDirection::new();
	let mut b2a = CopyDirection::new();
	let mut last_err = None;
	let mut reaper: Option<Pin<Box<Sleep>>> = None;

	poll_fn(|cx| {
		let forward = a2b.poll_step(a, b, cx, &mut last_err);
		let progress =
			match forward.and_then(|forward| b2a.poll_step(b, a, cx, &mut last_err).map(|backward| forward || backward)) {
				Ok(progress) => progress,
				Err(error) => {
					last_err = Some(error);
					return Poll::Ready(());
				}
			};
		if a2b.shutdown && b2a.shutdown {
			return Poll::Ready(());
		}

		// Keep the reaper active while a FIN is pending too: shutdown can
		// encounter backpressure just like a write.
		if !half_close_timeout.is_zero() && (a2b.eof || b2a.eof) {
			let timer = reaper.get_or_insert_with(|| Box::pin(tokio::time::sleep(half_close_timeout)));
			if progress {
				timer.as_mut().reset(Instant::now() + half_close_timeout);
			}
			if timer.as_mut().poll(cx).is_ready() {
				return Poll::Ready(());
			}
		}
		if progress {
			cx.waker().wake_by_ref();
		}
		Poll::Pending
	})
	.await;

	(a2b.transferred, b2a.transferred, last_err)
}

#[cfg(test)]
mod tests {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	use super::*;

	async fn relay_with_early_reply(reverse: bool) {
		let (client, mut a) = tokio::io::duplex(64);
		let (mut b, mut target) = tokio::io::duplex(64);
		let (mut client_read, mut client_write) = tokio::io::split(client);
		let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
		let request = vec![1; BUFFER_SIZE * 2 + 17];
		let reply = [2; 128];

		let relay = async {
			if reverse {
				copy_io(&mut b, &mut a).await
			} else {
				copy_io(&mut a, &mut b).await
			}
		};
		let upload = async {
			client_write.write_all(&request).await.unwrap();
			client_write.shutdown().await.unwrap();
		};
		let download = async {
			let mut received = [0; 128];
			client_read.read_exact(&mut received).await.unwrap();
			assert_eq!(received, reply);
			reply_tx.send(()).unwrap();
			let mut rest = Vec::new();
			client_read.read_to_end(&mut rest).await.unwrap();
			assert!(rest.is_empty());
		};
		let server = async {
			// Let the upload fill the relay's buffer and block its writer.
			tokio::time::sleep(Duration::from_millis(30)).await;
			target.write_all(&reply).await.unwrap();
			// The target deliberately reads no upload until its reply arrives.
			reply_rx.await.unwrap();
			let mut received = Vec::new();
			target.read_to_end(&mut received).await.unwrap();
			assert_eq!(received, request);
			target.shutdown().await.unwrap();
		};
		let (result, (), (), ()) = tokio::time::timeout(Duration::from_secs(2), async {
			tokio::join!(relay, upload, download, server)
		})
		.await
		.expect("backpressure must not block the reply direction");
		assert!(result.2.is_none(), "{:?}", result.2);
		assert_eq!(
			(result.0, result.1),
			if reverse {
				(reply.len(), request.len())
			} else {
				(request.len(), reply.len())
			}
		);
	}

	#[tokio::test]
	async fn upload_backpressure_does_not_block_early_reply() {
		relay_with_early_reply(false).await;
	}

	#[tokio::test]
	async fn reverse_backpressure_does_not_block_early_reply() {
		relay_with_early_reply(true).await;
	}

	#[tokio::test]
	async fn half_close_delivers_fin_and_keeps_relaying_active_reply() {
		let (mut client, mut a) = tokio::io::duplex(64);
		let (mut b, mut target) = tokio::io::duplex(64);
		let idle = Duration::from_millis(120);
		let relay = copy_bidirectional(&mut a, &mut b, idle);
		let upload = async {
			client.write_all(b"request").await.unwrap();
			client.shutdown().await.unwrap();
			let mut received = Vec::new();
			client.read_to_end(&mut received).await.unwrap();
			assert_eq!(received, b"abcd");
		};
		let server = async {
			let mut request = Vec::new();
			target.read_to_end(&mut request).await.unwrap();
			assert_eq!(request, b"request");
			// Total reply time exceeds the idle timeout; each byte resets it.
			for byte in b"abcd" {
				tokio::time::sleep(idle / 2).await;
				target.write_all(&[*byte]).await.unwrap();
			}
			target.shutdown().await.unwrap();
		};
		let (result, (), ()) = tokio::time::timeout(Duration::from_secs(2), async { tokio::join!(relay, upload, server) })
			.await
			.expect("the reply must remain active after the upload FIN");
		assert_eq!((result.0, result.1), (7, 4));
		assert!(result.2.is_none());
	}

	#[derive(Default)]
	enum ReadEnd {
		#[default]
		Eof,
		Pending,
		Error,
	}

	#[derive(Default)]
	enum WriteBehavior {
		#[default]
		Ready,
		Partial,
		FailAfter(usize),
		Pending,
		Zero,
	}

	#[derive(Default)]
	enum ShutdownBehavior {
		#[default]
		Ready,
		Pending,
		Error,
	}

	#[derive(Default)]
	struct TestStream {
		input: &'static [u8],
		read_end: ReadEnd,
		writes: Vec<u8>,
		write_behavior: WriteBehavior,
		shutdown_behavior: ShutdownBehavior,
		shutdown_calls: usize,
		shutdown_bytes: Option<usize>,
	}

	impl AsyncRead for TestStream {
		fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
			if !self.input.is_empty() {
				let count = self.input.len().min(buf.remaining());
				buf.put_slice(&self.input[..count]);
				self.input = &self.input[count..];
				return Poll::Ready(Ok(()));
			}
			match self.read_end {
				ReadEnd::Eof => Poll::Ready(Ok(())),
				ReadEnd::Pending => Poll::Pending,
				ReadEnd::Error => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
			}
		}
	}

	impl AsyncWrite for TestStream {
		fn poll_write(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
			let count = match self.write_behavior {
				WriteBehavior::Ready => buf.len(),
				WriteBehavior::Partial => buf.len().min(2),
				WriteBehavior::FailAfter(limit) => {
					if self.writes.len() == limit {
						return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
					}
					buf.len().min(limit - self.writes.len())
				}
				WriteBehavior::Pending => return Poll::Pending,
				WriteBehavior::Zero => return Poll::Ready(Ok(0)),
			};
			self.writes.extend_from_slice(&buf[..count]);
			Poll::Ready(Ok(count))
		}

		fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
			Poll::Ready(Ok(()))
		}

		fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
			self.shutdown_calls += 1;
			let written = self.writes.len();
			self.shutdown_bytes.get_or_insert(written);
			match self.shutdown_behavior {
				ShutdownBehavior::Ready => Poll::Ready(Ok(())),
				ShutdownBehavior::Pending => Poll::Pending,
				ShutdownBehavior::Error => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
			}
		}
	}

	async fn reap(a: &mut TestStream, b: &mut TestStream) -> (usize, usize, Option<io::Error>) {
		tokio::time::timeout(Duration::from_secs(2), copy_bidirectional(a, b, Duration::from_millis(30)))
			.await
			.expect("the half-close idle reaper must remain responsive")
	}

	#[tokio::test]
	async fn half_close_reaps_pending_write_and_relays_other_direction() {
		let mut a = TestStream {
			input: b"upload",
			..Default::default()
		};
		let mut b = TestStream {
			input: b"reply",
			write_behavior: WriteBehavior::Pending,
			..Default::default()
		};
		let (forward, backward, error) = reap(&mut a, &mut b).await;
		assert_eq!((forward, backward), (0, 5));
		assert!(error.is_none());
		assert_eq!(a.writes, b"reply");
		assert!(b.writes.is_empty());
		assert_eq!(a.shutdown_calls, 1);
	}

	#[tokio::test]
	async fn half_close_reaps_pending_shutdown_and_relays_other_direction() {
		let mut a = TestStream::default();
		let mut b = TestStream {
			input: b"reply",
			read_end: ReadEnd::Pending,
			shutdown_behavior: ShutdownBehavior::Pending,
			..Default::default()
		};
		let (forward, backward, error) = reap(&mut a, &mut b).await;
		assert_eq!((forward, backward), (0, 5));
		assert!(error.is_none());
		assert_eq!(a.writes, b"reply");
		assert!(b.shutdown_calls > 0);
		assert_eq!(a.shutdown_calls, 0);
	}

	#[tokio::test]
	async fn both_eofs_do_not_disable_reaper_for_pending_shutdown() {
		let mut a = TestStream::default();
		let mut b = TestStream {
			shutdown_behavior: ShutdownBehavior::Pending,
			..Default::default()
		};
		let (forward, backward, error) = reap(&mut a, &mut b).await;
		assert_eq!((forward, backward), (0, 0));
		assert!(error.is_none());
		assert!(b.shutdown_calls > 0);
		assert_eq!(a.shutdown_calls, 1);
	}

	#[tokio::test]
	async fn zero_timeout_keeps_half_closed_stream_open() {
		let mut a = TestStream::default();
		let mut b = TestStream {
			input: b"reply",
			read_end: ReadEnd::Pending,
			..Default::default()
		};
		assert!(
			tokio::time::timeout(Duration::from_millis(60), copy_io(&mut a, &mut b))
				.await
				.is_err()
		);
		assert_eq!(a.writes, b"reply");
		assert_eq!(b.shutdown_calls, 1);
	}

	#[tokio::test]
	async fn idle_timeout_does_not_reap_streams_without_eof() {
		let mut a = TestStream {
			read_end: ReadEnd::Pending,
			..Default::default()
		};
		let mut b = TestStream {
			read_end: ReadEnd::Pending,
			..Default::default()
		};
		assert!(
			tokio::time::timeout(
				Duration::from_millis(60),
				copy_bidirectional(&mut a, &mut b, Duration::from_millis(10))
			)
			.await
			.is_err()
		);
		assert_eq!((a.shutdown_calls, b.shutdown_calls), (0, 0));
	}

	#[tokio::test]
	async fn partial_writes_drain_before_fin_and_count_in_both_directions() {
		let mut a = TestStream {
			input: b"upload",
			write_behavior: WriteBehavior::Partial,
			..Default::default()
		};
		let mut b = TestStream {
			input: b"reply",
			write_behavior: WriteBehavior::Partial,
			..Default::default()
		};
		let (forward, backward, error) = copy_io(&mut a, &mut b).await;
		assert_eq!((forward, backward), (6, 5));
		assert!(error.is_none());
		assert_eq!(a.writes, b"reply");
		assert_eq!(b.writes, b"upload");
		assert_eq!((a.shutdown_calls, b.shutdown_calls), (1, 1));
		assert_eq!((a.shutdown_bytes, b.shutdown_bytes), (Some(5), Some(6)));
	}

	#[tokio::test]
	async fn write_failure_preserves_successfully_written_counts() {
		let mut a = TestStream {
			input: b"upload",
			..Default::default()
		};
		let mut b = TestStream {
			input: b"reply",
			write_behavior: WriteBehavior::FailAfter(2),
			..Default::default()
		};
		let (forward, backward, error) = copy_io(&mut a, &mut b).await;
		assert_eq!((forward, backward), (2, 5));
		assert_eq!(error.unwrap().kind(), io::ErrorKind::BrokenPipe);
		assert_eq!(b.writes, b"up");
	}

	#[tokio::test]
	async fn read_failure_preserves_successfully_written_counts() {
		let mut a = TestStream {
			input: b"upload",
			read_end: ReadEnd::Error,
			..Default::default()
		};
		let mut b = TestStream::default();
		let (forward, backward, error) = copy_io(&mut a, &mut b).await;
		assert_eq!((forward, backward), (6, 0));
		assert_eq!(error.unwrap().kind(), io::ErrorKind::ConnectionReset);
		assert_eq!(b.writes, b"upload");
	}

	#[tokio::test]
	async fn zero_write_returns_write_zero() {
		let mut a = TestStream {
			input: b"upload",
			..Default::default()
		};
		let mut b = TestStream {
			write_behavior: WriteBehavior::Zero,
			..Default::default()
		};
		let (forward, backward, error) = copy_io(&mut a, &mut b).await;
		assert_eq!((forward, backward), (0, 0));
		assert_eq!(error.unwrap().kind(), io::ErrorKind::WriteZero);
	}

	#[tokio::test]
	async fn shutdown_failure_does_not_cancel_reply() {
		let mut a = TestStream::default();
		let mut b = TestStream {
			input: b"reply",
			shutdown_behavior: ShutdownBehavior::Error,
			..Default::default()
		};
		let (forward, backward, error) = copy_io(&mut a, &mut b).await;
		assert_eq!((forward, backward), (0, 5));
		assert_eq!(error.unwrap().kind(), io::ErrorKind::NotConnected);
		assert_eq!(a.writes, b"reply");
		assert_eq!((a.shutdown_calls, b.shutdown_calls), (1, 1));
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

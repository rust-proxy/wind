//! Channel-backed duplex stream bridging a quiche bidirectional stream (driven
//! by the [`crate::driver::TuicheDriver`] worker) to the `wind-core`
//! [`InboundCallback::handle_tcpstream`](wind_core::InboundCallback) relay.
//!
//! The `tokio-quiche` worker owns the `quiche::Connection` and can only touch
//! streams synchronously from inside the `ApplicationOverQuic` callbacks. The
//! TUIC TCP relay, however, wants an owned `AsyncRead + AsyncWrite` handle it
//! can hand to the outbound `copy_io`. [`QuicheStream`] is that handle: its
//! read half is fed by the worker (data the client sent on the QUIC stream) and
//! its write half drains to the worker (data to send back to the client).

use std::{
	future::Future,
	io,
	pin::Pin,
	task::{Context, Poll},
};

use bytes::Bytes;
use tokio::{
	io::{AsyncRead, AsyncWrite, ReadBuf},
	sync::mpsc,
};
use tokio_util::sync::PollSender;

/// Largest chunk copied per `poll_write`, bounding the size of a single `Bytes`
/// handed to the worker.
const WRITE_CHUNK: usize = 16 * 1024;

/// Duplex stream handed to `InboundCallback::handle_tcpstream`.
pub struct QuicheStream {
	/// Client → target payload, fed by the worker as it drains the QUIC stream.
	/// `None` from the channel (sender dropped) signals the client's FIN → EOF.
	read_rx: mpsc::Receiver<Bytes>,
	read_leftover: Bytes,
	/// Target → client payload, drained by the worker for `stream_send`.
	write_tx: PollSender<Bytes>,
}

impl QuicheStream {
	pub fn new(read_rx: mpsc::Receiver<Bytes>, write_tx: mpsc::Sender<Bytes>) -> Self {
		Self {
			read_rx,
			read_leftover: Bytes::new(),
			write_tx: PollSender::new(write_tx),
		}
	}
}

impl AsyncRead for QuicheStream {
	fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		if self.read_leftover.is_empty() {
			match self.read_rx.poll_recv(cx) {
				Poll::Ready(Some(b)) => self.read_leftover = b,
				// Sender dropped → client finished sending → clean EOF.
				Poll::Ready(None) => return Poll::Ready(Ok(())),
				Poll::Pending => return Poll::Pending,
			}
		}
		let n = self.read_leftover.len().min(buf.remaining());
		let chunk = self.read_leftover.split_to(n);
		buf.put_slice(&chunk);
		Poll::Ready(Ok(()))
	}
}

impl AsyncWrite for QuicheStream {
	fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
		match self.write_tx.poll_reserve(cx) {
			Poll::Ready(Ok(())) => {
				let n = data.len().min(WRITE_CHUNK);
				match self.write_tx.send_item(Bytes::copy_from_slice(&data[..n])) {
					Ok(()) => Poll::Ready(Ok(n)),
					Err(_) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "quic stream closed"))),
				}
			}
			Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "quic stream closed"))),
			Poll::Pending => Poll::Pending,
		}
	}

	fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Poll::Ready(Ok(()))
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		// Closing the sender makes the worker observe end-of-data on this
		// stream's back-channel and emit a FIN on the QUIC stream.
		self.write_tx.close();
		Poll::Ready(Ok(()))
	}
}

/// Result of polling a TCP back-channel: data to send to the client, or
/// end-of-stream when `data` is `None`.
pub struct TcpBack {
	pub stream_id: u64,
	pub data: Option<Bytes>,
	pub rx: mpsc::Receiver<Bytes>,
}

/// A self-contained future that resolves when a TCP stream's back-channel has a
/// new chunk (or closes). On resolution it returns the receiver so the worker
/// can re-arm it. Modelled on the rusteria/tokio-quiche stream-waiter pattern.
pub struct WaitTcpBack {
	stream_id: u64,
	rx: Option<mpsc::Receiver<Bytes>>,
}

impl WaitTcpBack {
	pub fn new(stream_id: u64, rx: mpsc::Receiver<Bytes>) -> Self {
		Self { stream_id, rx: Some(rx) }
	}
}

impl Future for WaitTcpBack {
	type Output = TcpBack;

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let stream_id = self.stream_id;
		let rx = self.rx.as_mut().expect("WaitTcpBack polled after completion");
		match rx.poll_recv(cx) {
			Poll::Ready(data) => {
				let rx = self.rx.take().unwrap();
				Poll::Ready(TcpBack { stream_id, data, rx })
			}
			Poll::Pending => Poll::Pending,
		}
	}
}

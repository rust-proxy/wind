//! An [`h3::quic`] server surface implemented over [`QuicConnection`].
//!
//! The TUIC server poses as a real HTTP/3 web server for clients that speak
//! actual HTTP/3 instead of TUIC (see the masquerade in `wind-tuic`). Rather
//! than bind to a specific QUIC engine, this adapter implements the hyperium
//! [`h3`] crate's transport traits over our backend-neutral
//! [`QuicConnection`], so the same HTTP/3 server runs over either the quinn or
//! quiche backend.
//!
//! Only the **server** surface is implemented: accepting peer-initiated uni
//! (control / QPACK) and bidi (request) streams, and opening our own uni
//! streams (control / QPACK). The classifier in `wind-tuic` races the peer's
//! first uni/bi stream and peeks a couple of bytes to decide TUIC vs HTTP/3;
//! whichever stream it consumed for an h3 connection is handed back (with the
//! peeked bytes replayed via [`PrefixedRecv`](crate::PrefixedRecv)) as
//! `first_uni` / `first_bidi`, so the adapter yields it before accepting
//! anything new. Every recv stream is a `PrefixedRecv` (with an empty prefix
//! when none was consumed), so the adapter is generic over the backend's
//! concrete stream types — no boxing or dynamic dispatch.
//!
//! The bridge is mechanical: our streams are `AsyncRead`/`AsyncWrite`, while
//! `h3::quic` is poll- and `Buf`-based. Recv streams read into a scratch buffer
//! and hand back `Bytes`; send streams buffer one `WriteBuf` and drain it
//! through `poll_write`. Our `QuicConnection` accept/open methods are `async
//! fn`, so each is driven as a boxed in-flight future stored on the
//! connection/opener.

use std::{
	future::Future,
	pin::Pin,
	task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use h3::quic::{
	BidiStream, Connection, ConnectionErrorIncoming, OpenStreams, RecvStream, SendStream, StreamErrorIncoming, StreamId,
	WriteBuf,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{PrefixedRecv, QuicConnection, QuicError, QuicRecvStream, QuicSendStream};

/// Scratch buffer size for a single `poll_data` read.
const RECV_CHUNK: usize = 16 * 1024;

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// A boxed in-flight `accept_bi` / `open_bi` future. Aliased because the bidi
/// case returns a `(SendStream, RecvStream)` tuple, which trips clippy's
/// `type_complexity` lint when written inline in every slot/signature.
type BoxBiFut<C> = BoxFut<Result<(<C as QuicConnection>::SendStream, <C as QuicConnection>::RecvStream), QuicError>>;

/// Build an HTTP/3 server connection over `conn`.
///
/// The classifier in `wind-tuic` races the connection's first uni/bi stream to
/// decide TUIC vs HTTP/3, consuming a couple of bytes to peek. Whichever stream
/// it consumed for an h3 connection is handed back here as `first_uni` and/or
/// `first_bidi` (with the peeked bytes replayed via [`PrefixedRecv`]), so the
/// h3 server yields it before accepting anything new — nothing is lost.
pub fn server_connection<C: QuicConnection>(
	conn: C,
	first_uni: Option<PrefixedRecv<C::RecvStream>>,
	first_bidi: Option<(C::SendStream, PrefixedRecv<C::RecvStream>)>,
) -> H3Conn<C> {
	H3Conn {
		conn,
		first_recv: first_uni.map(H3Recv::new),
		first_bidi: first_bidi.map(|(send, recv)| H3Bidi {
			send: H3Send::new(send),
			recv: H3Recv::new(recv),
		}),
		accept_recv_fut: None,
		accept_bi_fut: None,
		open_uni_fut: None,
		open_bi_fut: None,
	}
}

fn conn_err(e: QuicError) -> ConnectionErrorIncoming {
	match e {
		QuicError::TimedOut => ConnectionErrorIncoming::Timeout,
		QuicError::ApplicationClosed { .. } | QuicError::LocallyClosed => {
			ConnectionErrorIncoming::ApplicationClose { error_code: 0 }
		}
		other => ConnectionErrorIncoming::InternalError(other.to_string()),
	}
}

fn stream_err(e: QuicError) -> StreamErrorIncoming {
	StreamErrorIncoming::ConnectionErrorIncoming {
		connection_error: conn_err(e),
	}
}

// ---------------------------------------------------------------------------
// Recv stream
// ---------------------------------------------------------------------------

/// `h3::quic::RecvStream` over the backend's recv stream (wrapped in
/// [`PrefixedRecv`] so a peeked control-stream byte can be replayed).
pub struct H3Recv<C: QuicConnection> {
	inner: PrefixedRecv<C::RecvStream>,
	id: u64,
	scratch: Vec<u8>,
}

impl<C: QuicConnection> H3Recv<C> {
	fn new(inner: PrefixedRecv<C::RecvStream>) -> Self {
		let id = inner.id();
		Self {
			inner,
			id,
			scratch: vec![0u8; RECV_CHUNK],
		}
	}

	/// Wrap a freshly-accepted stream that needs no replayed prefix.
	fn passthrough(recv: C::RecvStream) -> Self {
		Self::new(PrefixedRecv::new(Bytes::new(), recv))
	}
}

impl<C: QuicConnection> RecvStream for H3Recv<C> {
	type Buf = Bytes;

	fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
		let mut rb = ReadBuf::new(&mut self.scratch);
		match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
			Poll::Ready(Ok(())) => {
				let filled = rb.filled();
				if filled.is_empty() {
					// Clean EOF (peer FIN).
					Poll::Ready(Ok(None))
				} else {
					Poll::Ready(Ok(Some(Bytes::copy_from_slice(filled))))
				}
			}
			Poll::Ready(Err(e)) => Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(e)))),
			Poll::Pending => Poll::Pending,
		}
	}

	fn stop_sending(&mut self, error_code: u64) {
		self.inner.stop(error_code);
	}

	fn recv_id(&self) -> StreamId {
		stream_id(self.id)
	}
}

// ---------------------------------------------------------------------------
// Send stream
// ---------------------------------------------------------------------------

/// `h3::quic::SendStream` over the backend's send stream.
pub struct H3Send<C: QuicConnection> {
	inner: C::SendStream,
	id: u64,
	/// At most one `WriteBuf` is buffered at a time; `poll_ready`/`poll_finish`
	/// drain it through the underlying `AsyncWrite`.
	pending: Option<WriteBuf<Bytes>>,
}

impl<C: QuicConnection> H3Send<C> {
	fn new(inner: C::SendStream) -> Self {
		let id = inner.id();
		Self {
			inner,
			id,
			pending: None,
		}
	}

	/// Flush the buffered `WriteBuf` (if any) to the underlying stream. Returns
	/// `Ready(Ok)` once nothing is buffered.
	fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
		if let Some(buf) = self.pending.as_mut() {
			while buf.has_remaining() {
				let chunk = buf.chunk();
				match Pin::new(&mut self.inner).poll_write(cx, chunk) {
					Poll::Ready(Ok(0)) => {
						return Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(std::io::Error::new(
							std::io::ErrorKind::WriteZero,
							"h3 send stream wrote zero bytes",
						)))));
					}
					Poll::Ready(Ok(n)) => buf.advance(n),
					Poll::Ready(Err(e)) => return Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(e)))),
					Poll::Pending => return Poll::Pending,
				}
			}
		}
		self.pending = None;
		Poll::Ready(Ok(()))
	}
}

impl<C: QuicConnection> SendStream<Bytes> for H3Send<C> {
	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
		self.poll_flush_pending(cx)
	}

	fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
		// h3 always polls `poll_ready` to readiness before `send_data`, so the
		// previous buffer has drained.
		self.pending = Some(data.into());
		Ok(())
	}

	fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
		match self.poll_flush_pending(cx) {
			Poll::Ready(Ok(())) => match Pin::new(&mut self.inner).poll_flush(cx) {
				Poll::Ready(Ok(())) => {
					let _ = self.inner.finish();
					Poll::Ready(Ok(()))
				}
				Poll::Ready(Err(e)) => Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(e)))),
				Poll::Pending => Poll::Pending,
			},
			other => other,
		}
	}

	fn reset(&mut self, reset_code: u64) {
		self.inner.reset(reset_code);
	}

	fn send_id(&self) -> StreamId {
		stream_id(self.id)
	}
}

// ---------------------------------------------------------------------------
// Bidi stream (request streams)
// ---------------------------------------------------------------------------

/// `h3::quic::BidiStream` joining an [`H3Send`] and an [`H3Recv`].
pub struct H3Bidi<C: QuicConnection> {
	send: H3Send<C>,
	recv: H3Recv<C>,
}

impl<C: QuicConnection> SendStream<Bytes> for H3Bidi<C> {
	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
		self.send.poll_ready(cx)
	}

	fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
		self.send.send_data(data)
	}

	fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
		self.send.poll_finish(cx)
	}

	fn reset(&mut self, reset_code: u64) {
		self.send.reset(reset_code);
	}

	fn send_id(&self) -> StreamId {
		self.send.send_id()
	}
}

impl<C: QuicConnection> RecvStream for H3Bidi<C> {
	type Buf = Bytes;

	fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
		self.recv.poll_data(cx)
	}

	fn stop_sending(&mut self, error_code: u64) {
		self.recv.stop_sending(error_code);
	}

	fn recv_id(&self) -> StreamId {
		self.recv.recv_id()
	}
}

impl<C: QuicConnection> BidiStream<Bytes> for H3Bidi<C> {
	type RecvStream = H3Recv<C>;
	type SendStream = H3Send<C>;

	fn split(self) -> (Self::SendStream, Self::RecvStream) {
		(self.send, self.recv)
	}
}

fn into_bidi<C: QuicConnection>((send, recv): (C::SendStream, C::RecvStream)) -> H3Bidi<C> {
	H3Bidi {
		send: H3Send::new(send),
		recv: H3Recv::passthrough(recv),
	}
}

// ---------------------------------------------------------------------------
// Opener
// ---------------------------------------------------------------------------

/// Opens local uni/bidi streams (HTTP/3 control + QPACK streams). Produced by
/// [`Connection::opener`].
pub struct H3Opener<C: QuicConnection> {
	conn: C,
	open_uni_fut: Option<BoxFut<Result<C::SendStream, QuicError>>>,
	open_bi_fut: Option<BoxBiFut<C>>,
}

impl<C: QuicConnection> OpenStreams<Bytes> for H3Opener<C> {
	type BidiStream = H3Bidi<C>;
	type SendStream = H3Send<C>;

	fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
		poll_open_bidi(&self.conn, &mut self.open_bi_fut, cx)
	}

	fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
		poll_open_send(&self.conn, &mut self.open_uni_fut, cx)
	}

	fn close(&mut self, _code: h3::error::Code, reason: &[u8]) {
		self.conn.close(0, reason);
	}
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// `h3::quic::Connection` over a [`QuicConnection`] handle.
pub struct H3Conn<C: QuicConnection> {
	conn: C,
	first_recv: Option<H3Recv<C>>,
	first_bidi: Option<H3Bidi<C>>,
	accept_recv_fut: Option<BoxFut<Result<C::RecvStream, QuicError>>>,
	accept_bi_fut: Option<BoxBiFut<C>>,
	open_uni_fut: Option<BoxFut<Result<C::SendStream, QuicError>>>,
	open_bi_fut: Option<BoxBiFut<C>>,
}

impl<C: QuicConnection> OpenStreams<Bytes> for H3Conn<C> {
	type BidiStream = H3Bidi<C>;
	type SendStream = H3Send<C>;

	fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
		poll_open_bidi(&self.conn, &mut self.open_bi_fut, cx)
	}

	fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
		poll_open_send(&self.conn, &mut self.open_uni_fut, cx)
	}

	fn close(&mut self, _code: h3::error::Code, reason: &[u8]) {
		self.conn.close(0, reason);
	}
}

impl<C: QuicConnection> Connection<Bytes> for H3Conn<C> {
	type OpenStreams = H3Opener<C>;
	type RecvStream = H3Recv<C>;

	fn poll_accept_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
		if let Some(recv) = self.first_recv.take() {
			return Poll::Ready(Ok(recv));
		}
		let poll = {
			let conn = &self.conn;
			let fut = self.accept_recv_fut.get_or_insert_with(|| boxed_accept_uni(conn.clone()));
			fut.as_mut().poll(cx)
		};
		match poll {
			Poll::Ready(res) => {
				self.accept_recv_fut = None;
				Poll::Ready(res.map(H3Recv::passthrough).map_err(conn_err))
			}
			Poll::Pending => Poll::Pending,
		}
	}

	fn poll_accept_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
		if let Some(bidi) = self.first_bidi.take() {
			return Poll::Ready(Ok(bidi));
		}
		let poll = {
			let conn = &self.conn;
			let fut = self.accept_bi_fut.get_or_insert_with(|| boxed_accept_bi(conn.clone()));
			fut.as_mut().poll(cx)
		};
		match poll {
			Poll::Ready(res) => {
				self.accept_bi_fut = None;
				Poll::Ready(res.map(into_bidi).map_err(conn_err))
			}
			Poll::Pending => Poll::Pending,
		}
	}

	fn opener(&self) -> Self::OpenStreams {
		H3Opener {
			conn: self.conn.clone(),
			open_uni_fut: None,
			open_bi_fut: None,
		}
	}
}

// ---------------------------------------------------------------------------
// Shared poll helpers
// ---------------------------------------------------------------------------

fn stream_id(id: u64) -> StreamId {
	// QUIC stream ids fit the h3 `StreamId` invariant (< 2^62); fall back to 0
	// only if a backend ever surfaces something out of range.
	StreamId::try_from(id).unwrap_or_else(|_| StreamId::try_from(0).expect("0 is a valid stream id"))
}

fn boxed_accept_uni<C: QuicConnection>(conn: C) -> BoxFut<Result<C::RecvStream, QuicError>> {
	Box::pin(async move { conn.accept_uni().await })
}

fn boxed_accept_bi<C: QuicConnection>(conn: C) -> BoxBiFut<C> {
	Box::pin(async move { conn.accept_bi().await })
}

fn poll_open_send<C: QuicConnection>(
	conn: &C,
	slot: &mut Option<BoxFut<Result<C::SendStream, QuicError>>>,
	cx: &mut Context<'_>,
) -> Poll<Result<H3Send<C>, StreamErrorIncoming>> {
	let poll = {
		let fut = slot.get_or_insert_with(|| {
			let conn = conn.clone();
			Box::pin(async move { conn.open_uni().await })
		});
		fut.as_mut().poll(cx)
	};
	match poll {
		Poll::Ready(res) => {
			*slot = None;
			Poll::Ready(res.map(H3Send::new).map_err(stream_err))
		}
		Poll::Pending => Poll::Pending,
	}
}

fn poll_open_bidi<C: QuicConnection>(
	conn: &C,
	slot: &mut Option<BoxBiFut<C>>,
	cx: &mut Context<'_>,
) -> Poll<Result<H3Bidi<C>, StreamErrorIncoming>> {
	let poll = {
		let fut = slot.get_or_insert_with(|| {
			let conn = conn.clone();
			Box::pin(async move { conn.open_bi().await })
		});
		fut.as_mut().poll(cx)
	};
	match poll {
		Poll::Ready(res) => {
			*slot = None;
			Poll::Ready(res.map(into_bidi).map_err(stream_err))
		}
		Poll::Pending => Poll::Pending,
	}
}

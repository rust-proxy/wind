use std::{
	pin::Pin,
	sync::{
		Arc,
		atomic::{AtomicBool, AtomicU64, Ordering},
	},
	task::{Context, Poll},
	time::Duration,
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Per-direction copy buffer size used by [`copy_io`].
///
/// `tokio::io::copy_bidirectional`'s default is only 8 KiB, which caps
/// single-stream throughput over high bandwidth-delay-product links (a QUIC
/// tunnel to a distant peer is exactly that): every 8 KiB requires a fresh
/// read/write/wakeup cycle, so the relay can't keep enough bytes in flight to
/// fill the congestion/flow-control window. 64 KiB lets each direction move an
/// order of magnitude more data per syscall while staying well within typical
/// stream receive windows.
pub const RELAY_BUF_SIZE: usize = 64 * 1024;

/// How long a *half-closed* relay may sit idle before it is torn down.
///
/// `copy_bidirectional` only returns once BOTH directions reach EOF. When the
/// outbound peer half-closes — e.g. the origin server sends its response and
/// FINs while the downstream TUIC client leaves its upload half of the QUIC
/// bi-stream open — the inbound→outbound direction never EOFs, so the outbound
/// TCP socket would sit in `CLOSE_WAIT` for the entire (long-lived) QUIC
/// connection. That is the "proxied TCP connections never terminate until the
/// server is killed" symptom.
///
/// Once the outbound side has closed, [`copy_io`] gives the surviving direction
/// this long to finish. Any byte moved resets the window, so a slow-but-live
/// transfer is never cut off; only a genuinely idle half-open relay is reaped.
pub const RELAY_HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Shared, per-relay progress state read by the half-close reaper.
#[derive(Default)]
struct RelayMeters {
	/// Bytes read from the inbound side `a` (inbound→outbound traffic).
	a2b: AtomicU64,
	/// Bytes read from the outbound side `b` (outbound→inbound traffic).
	b2a: AtomicU64,
	/// Set once the inbound writer is shut down — which `copy_bidirectional`
	/// only does after the *outbound* reader hit EOF, i.e. the outbound peer
	/// closed. Until this flips, the reaper stays disarmed (a fully-open but
	/// idle tunnel — keep-alive, long-poll — must never be reaped).
	half_closed: AtomicBool,
}

impl RelayMeters {
	/// Monotonic "bytes moved in either direction" counter; a stalled relay is
	/// one whose `activity()` does not change across a timeout window.
	fn activity(&self) -> u64 {
		self.a2b
			.load(Ordering::Relaxed)
			.wrapping_add(self.b2a.load(Ordering::Relaxed))
	}
}

/// One side of a relay, wrapping the real stream to (1) count throughput per
/// direction and (2) observe the half-close that arms the idle reaper.
struct Tracked<'s, S: ?Sized> {
	inner: &'s mut S,
	meters: Arc<RelayMeters>,
	/// `true` for the inbound stream `a`: its reads are inbound→outbound bytes,
	/// and a shutdown of its writer signals the outbound peer closed.
	is_inbound: bool,
}

impl<S: AsyncRead + Unpin + ?Sized> AsyncRead for Tracked<'_, S> {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
		let this = self.get_mut();
		let before = buf.filled().len();
		let res = Pin::new(&mut *this.inner).poll_read(cx, buf);
		if let Poll::Ready(Ok(())) = &res {
			let n = (buf.filled().len() - before) as u64;
			if n > 0 {
				let counter = if this.is_inbound { &this.meters.a2b } else { &this.meters.b2a };
				counter.fetch_add(n, Ordering::Relaxed);
			}
		}
		res
	}
}

impl<S: AsyncWrite + Unpin + ?Sized> AsyncWrite for Tracked<'_, S> {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
		let this = self.get_mut();
		Pin::new(&mut *this.inner).poll_write(cx, buf)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		let this = self.get_mut();
		Pin::new(&mut *this.inner).poll_flush(cx)
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		let this = self.get_mut();
		// `copy_bidirectional` shuts down a writer when the OPPOSITE reader hits
		// EOF. Shutting down the inbound writer therefore means the outbound peer
		// closed: arm the reaper so the still-open inbound→outbound direction can
		// no longer linger forever. The outbound writer's shutdown (the inbound
		// peer closed first) is the benign case `copy_bidirectional` already
		// handles — leave the reaper disarmed there so a slow outbound response is
		// not cut short.
		if this.is_inbound {
			this.meters.half_closed.store(true, Ordering::Release);
		}
		Pin::new(&mut *this.inner).poll_shutdown(cx)
	}

	fn poll_write_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &[std::io::IoSlice<'_>],
	) -> Poll<std::io::Result<usize>> {
		let this = self.get_mut();
		Pin::new(&mut *this.inner).poll_write_vectored(cx, bufs)
	}

	fn is_write_vectored(&self) -> bool {
		self.inner.is_write_vectored()
	}
}

/// Bidirectionally relay bytes between two duplex streams.
///
/// By convention `a` is the **inbound** stream (closer to the originating
/// client) and `b` the **outbound** stream (closer to the target).
///
/// The hot path delegates to [`tokio::io::copy_bidirectional_with_sizes`] (with
/// [`RELAY_BUF_SIZE`] per direction), which correctly handles half-close: when
/// one direction sees EOF, it calls `shutdown()` on the opposite writer and
/// continues pumping the remaining direction. (A previous hand-rolled
/// implementation broke out of the loop on the FIRST EOF, dropping in-flight
/// bytes flowing the other way — truncating responses for HTTP clients that FIN
/// after their request while the server is still streaming.)
///
/// On top of that, once the **outbound** peer closes, the surviving
/// inbound→outbound direction is bounded by [`RELAY_HALF_CLOSE_TIMEOUT`]: if it
/// moves no bytes for that long it is torn down, so a half-open connection the
/// downstream client never closes can no longer pin the outbound socket in
/// `CLOSE_WAIT` for the life of the QUIC connection.
pub async fn copy_io<A, B>(a: &mut A, b: &mut B) -> (usize, usize, Option<std::io::Error>)
where
	A: AsyncRead + AsyncWrite + Unpin + ?Sized,
	B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
	copy_io_with_timeout(a, b, RELAY_HALF_CLOSE_TIMEOUT).await
}

/// [`copy_io`] with an injectable half-close timeout (kept private so tests can
/// exercise the reaper without waiting the production grace period).
async fn copy_io_with_timeout<A, B>(
	a: &mut A,
	b: &mut B,
	half_close_timeout: Duration,
) -> (usize, usize, Option<std::io::Error>)
where
	A: AsyncRead + AsyncWrite + Unpin + ?Sized,
	B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
	let meters = Arc::new(RelayMeters::default());
	let mut ta = Tracked {
		inner: a,
		meters: meters.clone(),
		is_inbound: true,
	};
	let mut tb = Tracked {
		inner: b,
		meters: meters.clone(),
		is_inbound: false,
	};

	let relay = tokio::io::copy_bidirectional_with_sizes(&mut ta, &mut tb, RELAY_BUF_SIZE, RELAY_BUF_SIZE);
	tokio::pin!(relay);

	tokio::select! {
		res = &mut relay => match res {
			Ok((a2b, b2a)) => (a2b as usize, b2a as usize, None),
			Err(e) => (
				meters.a2b.load(Ordering::Relaxed) as usize,
				meters.b2a.load(Ordering::Relaxed) as usize,
				Some(e),
			),
		},
		// The relay went half-closed (outbound peer gone) and then idle past the
		// grace period: the surviving direction is a dead half-open connection.
		// Returning drops both `Tracked`s — and with them the inner streams —
		// closing the lingering sockets instead of leaking them.
		() = reap_when_half_open(&meters, half_close_timeout) => (
			meters.a2b.load(Ordering::Relaxed) as usize,
			meters.b2a.load(Ordering::Relaxed) as usize,
			None,
		),
	}
}

/// Resolve once the relay has been half-closed AND has then moved no bytes for
/// `idle_timeout`. Any activity, or a relay that has not (yet) half-closed,
/// resets the window — so an active transfer is never interrupted and a
/// fully-open idle tunnel is never reaped.
async fn reap_when_half_open(meters: &RelayMeters, idle_timeout: Duration) {
	// Sample several times per window so reaping lands within ~`idle_timeout` of
	// going quiet rather than up to 2× it, while staying cheap for the 30 s
	// production value (a 6 s tick).
	let poll = (idle_timeout / 5).clamp(Duration::from_millis(50), Duration::from_secs(5));
	let mut last_activity = meters.activity();
	let mut idle_for = Duration::ZERO;
	loop {
		tokio::time::sleep(poll).await;
		let activity = meters.activity();
		if activity != last_activity || !meters.half_closed.load(Ordering::Acquire) {
			last_activity = activity;
			idle_for = Duration::ZERO;
			continue;
		}
		idle_for += poll;
		if idle_for >= idle_timeout {
			return;
		}
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

#[cfg(test)]
mod tests {
	use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

	use super::*;

	/// A clean full-duplex exchange where both peers close completes promptly
	/// and reports the bytes relayed in each direction. The reaper must not
	/// fire on this path.
	#[tokio::test]
	async fn clean_full_close_completes() {
		let (mut a, mut a_peer) = tokio::io::duplex(1024);
		let (mut b, mut b_peer) = tokio::io::duplex(1024);

		let relay = tokio::spawn(async move { copy_io_with_timeout(&mut a, &mut b, Duration::from_secs(30)).await });

		// inbound → outbound: a's peer sends + closes, b's peer drains to EOF.
		a_peer.write_all(b"ping").await.unwrap();
		a_peer.shutdown().await.unwrap();
		let mut forward = Vec::new();
		b_peer.read_to_end(&mut forward).await.unwrap();
		assert_eq!(forward, b"ping");

		// outbound → inbound: b's peer replies + closes, a's peer drains to EOF.
		b_peer.write_all(b"pong!").await.unwrap();
		b_peer.shutdown().await.unwrap();
		let mut back = Vec::new();
		a_peer.read_to_end(&mut back).await.unwrap();
		assert_eq!(back, b"pong!");

		let (a2b, b2a, err) = relay.await.unwrap();
		assert!(err.is_none(), "clean close should not surface an error: {err:?}");
		assert_eq!(a2b, 4);
		assert_eq!(b2a, 5);
	}

	/// The regression: the outbound peer closes, the inbound peer leaves its
	/// upload half open and silent. `copy_bidirectional` alone would hang here
	/// forever (leaking the outbound socket); the reaper must tear it down once
	/// the half-open relay has been idle past the timeout.
	#[tokio::test]
	async fn half_open_idle_relay_is_reaped() {
		let (mut a, _a_peer) = tokio::io::duplex(1024);
		let (mut b, b_peer) = tokio::io::duplex(1024);

		// Outbound closes immediately: dropping b's peer makes b read EOF.
		drop(b_peer);

		// `_a_peer` stays alive and silent, so the inbound→outbound direction
		// never EOFs. Without the reaper copy_io would never return.
		let result = tokio::time::timeout(
			Duration::from_secs(5),
			copy_io_with_timeout(&mut a, &mut b, Duration::from_millis(150)),
		)
		.await;

		let (_a2b, _b2a, err) = result.expect("half-open relay was not reaped — copy_io hung");
		assert!(err.is_none(), "reaping a half-open relay is not an error: {err:?}");
	}

	/// A fully-open but idle tunnel (neither side has closed) must NOT be
	/// reaped: the half-close timer only arms once the outbound peer is gone.
	#[tokio::test]
	async fn fully_open_idle_relay_is_not_reaped() {
		let (mut a, _a_peer) = tokio::io::duplex(1024);
		let (mut b, _b_peer) = tokio::io::duplex(1024);

		// Both peers stay alive and silent — this models an idle keep-alive
		// connection. The relay must still be running after several timeouts.
		let result = tokio::time::timeout(
			Duration::from_millis(600),
			copy_io_with_timeout(&mut a, &mut b, Duration::from_millis(100)),
		)
		.await;

		assert!(result.is_err(), "an idle but fully-open relay must not be reaped");
	}
}

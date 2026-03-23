use std::{
	fmt::Debug,
	future::Future,
	io::{IoSliceMut, Result as IoResult},
	net::{IpAddr, Ipv6Addr, SocketAddr},
	pin::Pin,
	sync::Arc,
	task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::future::poll_fn;
pub use quinn_udp::{EcnCodepoint, RecvMeta as QuinnRecvMeta, Transmit, UdpSocketState};
// Re-export quinn-udp's RecvMeta directly
// pub use quinn_udp::RecvMeta;
use tokio::io::Interest;

use crate::types::TargetAddr;

pub trait UdpPoller: Send + Sync + Debug + 'static {
	fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>>;
}

/// Metadata for a single buffer filled with bytes received from the network
///
/// This is our custom version of RecvMeta that includes destination information
/// for better packet routing support.
#[derive(Debug, Clone)]
pub struct RecvMeta {
	/// The source address of the datagram(s) contained in the buffer
	pub addr: SocketAddr,
	/// The number of bytes the associated buffer has
	pub len: usize,
	/// The size of a single datagram in the associated buffer
	///
	/// When GRO (Generic Receive Offload) is used this indicates the size of a
	/// single datagram inside the buffer. If the buffer is larger, that is if
	/// [`len`] is greater then this value, then the individual datagrams
	/// contained have their boundaries at `stride` increments from the start.
	/// The last datagram could be smaller than `stride`.
	pub stride: usize,
	/// The Explicit Congestion Notification bits for the datagram(s) in the
	/// buffer
	pub ecn: Option<EcnCodepoint>,
	/// The destination IP address which was encoded in this datagram
	///
	/// Populated on platforms: Windows, Linux, Android (API level > 25),
	/// FreeBSD, OpenBSD, NetBSD, macOS, and iOS.
	pub dst_ip: Option<IpAddr>,
	/// The destination address that this packet is intended for
	/// This is our custom field for better packet routing
	pub destination: Option<TargetAddr>,
}

impl Default for RecvMeta {
	/// Constructs a value with arbitrary fields, intended to be overwritten
	fn default() -> Self {
		Self {
			addr: SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
			len: 0,
			stride: 0,
			ecn: None,
			dst_ip: None,
			destination: None,
		}
	}
}

impl From<QuinnRecvMeta> for RecvMeta {
	fn from(meta: QuinnRecvMeta) -> Self {
		Self {
			addr: meta.addr,
			len: meta.len,
			stride: meta.stride,
			ecn: meta.ecn,
			dst_ip: meta.dst_ip,
			destination: None,
		}
	}
}

#[derive(Debug, Clone)]
pub struct UdpPacket {
	pub source: Option<TargetAddr>,
	pub target: TargetAddr,
	pub payload: Bytes,
}

// TODO impl quinn::AsyncUdpSocket for AbstractUdpSocket

pub trait AbstractUdpSocket: Send + Sync {
	/// Required methods
	/// Creates a UDP socket I/O poller.
	fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>>;

	/// Tries to send a UDP datagram to the specified destination.
	fn try_send(&self, transmit: &Transmit) -> IoResult<()>;

	/// Poll to receive a UDP datagram.
	fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<IoResult<usize>>;

	/// Returns the local socket address.
	fn local_addr(&self) -> IoResult<SocketAddr>;

	/// Maximum number of segments that can be transmitted in one call.
	fn max_transmit_segments(&self) -> usize {
		1
	}

	/// Maximum number of segments that can be received in one call.
	fn max_receive_segments(&self) -> usize {
		1
	}

	/// Returns whether the socket may fragment packets.
	fn may_fragment(&self) -> bool {
		true
	}

	/// Supplied methods
	/// Receive a UDP datagram.
	/// `meta` is the returned metadata for each buffer in `bufs`.
	fn recv(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> impl Future<Output = IoResult<usize>> + Send {
		poll_fn(|cx| self.poll_recv(cx, bufs, meta))
	}

	/// Sends data on the socket to the given address.
	fn poll_send(&self, _cx: &mut Context<'_>, buf: &[u8], target: SocketAddr) -> Poll<IoResult<usize>> {
		let transmit = Transmit {
			destination: target,
			contents: buf,
			ecn: None,
			segment_size: None,
			src_ip: None,
		};
		match self.try_send(&transmit) {
			Ok(_) => Poll::Ready(Ok(buf.len())),
			Err(e) => Poll::Ready(Err(e)),
		}
	}

	/// Sends data on the socket to the given address.
	fn send<'a>(&'a self, buf: &'a [u8], target: SocketAddr) -> impl Future<Output = IoResult<usize>> + Send + 'a {
		poll_fn(move |cx| self.poll_send(cx, buf, target))
	}
}

#[derive(Debug)]
pub struct TokioUdpSocket {
	io: tokio::net::UdpSocket,
	inner: UdpSocketState,
}
impl TokioUdpSocket {
	pub fn new(sock: std::net::UdpSocket) -> std::io::Result<Self> {
		Ok(Self {
			inner: UdpSocketState::new((&sock).into())?,
			io: tokio::net::UdpSocket::from_std(sock)?,
		})
	}
}
impl AbstractUdpSocket for TokioUdpSocket {
	fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
		Box::pin(UdpPollHelper::new(move || {
			let socket = self.clone();
			async move { socket.io.writable().await }
		}))
	}

	fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
		self.io
			.try_io(Interest::WRITABLE, || self.inner.send((&self.io).into(), transmit))
	}

	fn poll_recv(
		&self,
		cx: &mut Context,
		bufs: &mut [std::io::IoSliceMut<'_>],
		meta: &mut [RecvMeta],
	) -> Poll<std::io::Result<usize>> {
		loop {
			ready!(self.io.poll_recv_ready(cx))?;
			// First, receive into quinn's RecvMeta
			let mut quinn_meta = vec![QuinnRecvMeta::default(); meta.len()];
			if let Ok(res) = self.io.try_io(Interest::READABLE, || {
				self.inner.recv((&self.io).into(), bufs, &mut quinn_meta)
			}) {
				// Convert quinn's RecvMeta to our RecvMeta
				for (i, qmeta) in quinn_meta.iter().enumerate().take(res) {
					if i < meta.len() {
						meta[i] = RecvMeta::from(*qmeta);
					}
				}
				return Poll::Ready(Ok(res));
			}
		}
	}

	fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
		self.io.local_addr()
	}

	fn may_fragment(&self) -> bool {
		self.inner.may_fragment()
	}

	fn max_transmit_segments(&self) -> usize {
		self.inner.max_gso_segments()
	}

	fn max_receive_segments(&self) -> usize {
		self.inner.gro_segments()
	}
}

pin_project_lite::pin_project! {
	pub struct UdpPollHelper<MakeFut, Fut> {
		make_fut: MakeFut,
		#[pin]
		fut: Option<Fut>,
	}
}

impl<MakeFut, Fut> UdpPollHelper<MakeFut, Fut> {
	pub fn new(make_fut: MakeFut) -> Self {
		Self { make_fut, fut: None }
	}
}

impl<MakeFut, Fut> UdpPoller for UdpPollHelper<MakeFut, Fut>
where
	MakeFut: Fn() -> Fut + Send + Sync + 'static,
	Fut: Future<Output = std::io::Result<()>> + Send + Sync + 'static,
{
	fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
		let mut this = self.project();
		if this.fut.is_none() {
			this.fut.set(Some((this.make_fut)()));
		}
		let result = this.fut.as_mut().as_pin_mut().unwrap().poll(cx);
		if result.is_ready() {
			this.fut.set(None);
		}
		result
	}
}

impl<MakeFut, Fut> Debug for UdpPollHelper<MakeFut, Fut> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("UdpPollHelper").finish_non_exhaustive()
	}
}

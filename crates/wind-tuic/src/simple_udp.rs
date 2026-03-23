//! Simplified UDP packet channel for wind-tuic
//!
//! This replaces the heavy AbstractUdpSocket trait with simple channels

use bytes::Bytes;
use crossfire::{MAsyncRx, MAsyncTx};
use std::net::SocketAddr;

/// Simple UDP packet structure
#[derive(Debug, Clone)]
pub struct SimpleUdpPacket {
	pub source: Option<SocketAddr>,
	pub target: SocketAddr,
	pub payload: Bytes,
}

impl SimpleUdpPacket {
	/// Create a new UDP packet
	pub fn new(source: Option<SocketAddr>, target: SocketAddr, payload: Bytes) -> Self {
		Self { source, target, payload }
	}
}

/// Simple bidirectional channel for UDP packets
pub struct SimpleUdpChannel {
	/// Sender for packets going to remote
	pub to_remote_tx: MAsyncTx<SimpleUdpPacket>,
	/// Receiver for packets coming from remote
	pub from_remote_rx: MAsyncRx<SimpleUdpPacket>,
}

impl SimpleUdpChannel {
	/// Create a new UDP channel with specified buffer size
	pub fn new(buffer_size: usize) -> (Self, SimpleUdpChannelTx) {
		let (to_remote_tx, to_remote_rx) = crossfire::mpmc::bounded_async::<SimpleUdpPacket>(buffer_size);
		let (from_remote_tx, from_remote_rx) = crossfire::mpmc::bounded_async::<SimpleUdpPacket>(buffer_size);

		let channel = Self {
			to_remote_tx,
			from_remote_rx,
		};

		let tx = SimpleUdpChannelTx {
			to_remote_rx,
			from_remote_tx,
		};

		(channel, tx)
	}
}

/// The "other side" of the UDP channel
#[derive(Clone)]
pub struct SimpleUdpChannelTx {
	/// Receiver for packets going to remote (read from here to send to TUIC)
	pub to_remote_rx: MAsyncRx<SimpleUdpPacket>,
	/// Sender for packets coming from remote (write here when received from TUIC)
	pub from_remote_tx: MAsyncTx<SimpleUdpPacket>,
}

impl SimpleUdpChannelTx {
	/// Send a packet from remote to local
	pub async fn send_from_remote(&self, packet: SimpleUdpPacket) -> Result<(), crossfire::SendError<SimpleUdpPacket>> {
		self.from_remote_tx.send(packet).await
	}

	/// Receive a packet from local to send to remote
	pub async fn recv_to_remote(&self) -> Result<SimpleUdpPacket, crossfire::RecvError> {
		self.to_remote_rx.recv().await
	}

	/// Try to receive a packet from local (non-blocking)
	pub fn try_recv_to_remote(&self) -> Result<SimpleUdpPacket, crossfire::TryRecvError> {
		self.to_remote_rx.try_recv()
	}
}

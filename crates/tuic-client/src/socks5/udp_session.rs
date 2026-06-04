use std::{
	collections::HashMap,
	io::Error as IoError,
	net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket},
	sync::Arc,
};

use bytes::Bytes;
use once_cell::sync::OnceCell;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use socks5_proto::Address;
use socks5_server::AssociatedUdpSocket;
use tokio::{net::UdpSocket, sync::RwLock as AsyncRwLock};
use tracing::{debug, warn};

use crate::error::Error;

pub static UDP_SESSIONS: OnceCell<AsyncRwLock<HashMap<u16, UdpSession>>> = OnceCell::new();

#[derive(Clone)]
pub struct UdpSession {
	socket: Arc<AssociatedUdpSocket>,
	assoc_id: u16,
	ctrl_addr: SocketAddr,
}

impl UdpSession {
	pub fn new(
		assoc_id: u16,
		ctrl_addr: SocketAddr,
		local_ip: IpAddr,
		dual_stack: Option<bool>,
		max_pkt_size: usize,
	) -> Result<Self, Error> {
		let domain = match local_ip {
			IpAddr::V4(_) => Domain::IPV4,
			IpAddr::V6(_) => Domain::IPV6,
		};

		let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
			.map_err(|err| Error::Socket("failed to create socks5 server UDP associate socket", err))?;

		if let Some(dual_stack) = dual_stack {
			socket
				.set_only_v6(!dual_stack)
				.map_err(|err| Error::Socket("socks5 server UDP associate dual-stack socket setting error", err))?;
		}

		socket
			.set_nonblocking(true)
			.map_err(|err| Error::Socket("failed setting socks5 server UDP associate socket as non-blocking", err))?;

		socket
			.bind(&SockAddr::from(SocketAddr::from((local_ip, 0))))
			.map_err(|err| Error::Socket("failed to bind socks5 server UDP associate socket", err))?;

		let socket = UdpSocket::from_std(StdUdpSocket::from(socket))
			.map_err(|err| Error::Socket("failed to create socks5 server UDP associate socket", err))?;

		Ok(Self {
			socket: Arc::new(AssociatedUdpSocket::from((socket, max_pkt_size))),
			assoc_id,
			ctrl_addr,
		})
	}

	pub async fn send(&self, pkt: Bytes, mut src_addr: Address) -> Result<(), Error> {
		if let Address::SocketAddress(SocketAddr::V6(v6)) = src_addr {
			if let Some(v4) = v6.ip().to_ipv4_mapped() {
				src_addr = Address::SocketAddress(SocketAddr::new(IpAddr::V4(v4), v6.port()));
			}
		}

		let src_addr_display = src_addr.to_string();
		// `peer_addr` fails if the socket has not yet been connected (no client
		// packet has arrived) or if the socket has been disconnected. Fall back
		// to a placeholder rather than panicking inside a log line.
		let dst_addr_display = self
			.socket
			.peer_addr()
			.map(|a| a.to_string())
			.unwrap_or_else(|_| "<unconnected>".to_string());

		debug!(
			"[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] send packet from {src_addr_display} to {dst_addr}",
			ctrl_addr = self.ctrl_addr,
			assoc_id = self.assoc_id,
			dst_addr = dst_addr_display,
		);

		if let Err(err) = self.socket.send(pkt, 0, src_addr).await {
			warn!(
				"[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] send packet from {src_addr_display} to {dst_addr} \
				 error: {err}",
				ctrl_addr = self.ctrl_addr,
				assoc_id = self.assoc_id,
				dst_addr = dst_addr_display,
			);

			return Err(Error::Io(err));
		}

		Ok(())
	}

	pub async fn recv(&self) -> Result<(Bytes, Address), Error> {
		let (pkt, frag, mut dst_addr, src_addr) = self.socket.recv_from().await?;

		if let Address::SocketAddress(SocketAddr::V6(v6)) = dst_addr {
			if let Some(v4) = v6.ip().to_ipv4_mapped() {
				dst_addr = Address::SocketAddress(SocketAddr::new(IpAddr::V4(v4), v6.port()));
			}
		}

		if let Ok(connected_addr) = self.socket.peer_addr() {
			let connected_addr = match connected_addr {
				SocketAddr::V4(addr) => {
					if let SocketAddr::V6(_) = src_addr {
						SocketAddr::new(addr.ip().to_ipv6_mapped().into(), addr.port())
					} else {
						connected_addr
					}
				}
				SocketAddr::V6(addr) => {
					if let SocketAddr::V4(_) = src_addr {
						if let Some(ip) = addr.ip().to_ipv4_mapped() {
							SocketAddr::new(IpAddr::V4(ip), addr.port())
						} else {
							connected_addr
						}
					} else {
						connected_addr
					}
				}
			};
			if src_addr != connected_addr {
				Err(IoError::other(format!("invalid source address: {src_addr}")))?;
			}
		} else {
			// First-packet race: previously the UDP associate socket was
			// `connect()`-bound to whoever sent the first datagram, with no
			// authentication. Any off-path attacker that could send a UDP
			// packet to the relay's bound port before the legitimate client
			// did would permanently own the association. We now require the
			// source IP to match the TCP control connection's peer IP before
			// latching it in.
			if src_addr.ip() != self.ctrl_addr.ip() {
				warn!(
					"[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] dropping initial UDP packet from unexpected source \
					 {src_addr} (expected client IP {ctrl_ip})",
					ctrl_addr = self.ctrl_addr,
					assoc_id = self.assoc_id,
					ctrl_ip = self.ctrl_addr.ip(),
				);
				return Err(Error::WrongPacketSource);
			}
			self.socket.connect(src_addr).await?;
		}

		if frag != 0 {
			Err(IoError::other("fragmented packet is not supported"))?;
		}

		debug!(
			"[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] receive packet from {src_addr} to {dst_addr}",
			ctrl_addr = self.ctrl_addr,
			assoc_id = self.assoc_id
		);

		Ok((pkt, dst_addr))
	}

	pub fn local_addr(&self) -> Result<SocketAddr, IoError> {
		self.socket.local_addr()
	}
}

// ---------------------------------------------------------------------------
// PR1 regression tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use std::net::{Ipv4Addr, SocketAddr};

	use tokio::{net::UdpSocket as TokioUdpSocket, time::Duration};

	use super::*;

	/// Build a minimal SOCKS5 UDP request frame:
	/// `RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT payload`.
	fn make_socks_udp_pkt(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
		let mut buf = vec![0x00, 0x00, 0x00, 0x01];
		match target {
			SocketAddr::V4(v4) => {
				buf.extend_from_slice(&v4.ip().octets());
				buf.extend_from_slice(&v4.port().to_be_bytes());
			}
			SocketAddr::V6(_) => unreachable!("v4 only in this helper"),
		}
		buf.extend_from_slice(payload);
		buf
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn first_packet_from_mismatched_ip_is_rejected() {
		// Control connection claims the legitimate client lives on TEST-NET-1.
		// The packet we will actually send comes from 127.0.0.1 — the IP check
		// MUST refuse to latch the association onto the wrong peer.
		let session = UdpSession::new(
			0,
			SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 9999)),
			IpAddr::V4(Ipv4Addr::LOCALHOST),
			None,
			65535,
		)
		.expect("create session");
		let relay_addr = session.local_addr().unwrap();

		// Off-path "attacker": binds to 127.0.0.1, races to send the first UDP
		// datagram before the legitimate (TEST-NET-1) client can.
		let attacker = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
		let frame = make_socks_udp_pkt(SocketAddr::from(([1, 1, 1, 1], 53)), b"hijack");
		attacker.send_to(&frame, relay_addr).await.unwrap();

		let res = tokio::time::timeout(Duration::from_millis(500), session.recv()).await;
		let err = res
			.expect("recv must return before timeout")
			.expect_err("first-packet hijack must be rejected");
		match err {
			Error::WrongPacketSource => {}
			other => panic!("expected WrongPacketSource, got {other:?}"),
		}
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn first_packet_from_matching_ip_latches_in() {
		// ctrl_addr.ip() == sender IP == 127.0.0.1 → must succeed and the
		// session socket becomes `connect()`-bound to the sender.
		let session = UdpSession::new(
			0,
			SocketAddr::from((Ipv4Addr::LOCALHOST, 9999)),
			IpAddr::V4(Ipv4Addr::LOCALHOST),
			None,
			65535,
		)
		.expect("create session");
		let relay_addr = session.local_addr().unwrap();

		let sender = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
		let frame = make_socks_udp_pkt(SocketAddr::from(([1, 1, 1, 1], 53)), b"ok");
		sender.send_to(&frame, relay_addr).await.unwrap();

		let (_pkt, addr) = tokio::time::timeout(Duration::from_millis(500), session.recv())
			.await
			.expect("recv must return before timeout")
			.expect("matching-IP packet must be accepted");

		match addr {
			Address::SocketAddress(SocketAddr::V4(v4)) => {
				assert_eq!(*v4.ip(), Ipv4Addr::new(1, 1, 1, 1));
				assert_eq!(v4.port(), 53);
			}
			other => panic!("unexpected dst addr {other:?}"),
		}
	}
}

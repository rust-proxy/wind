use std::{
	io,
	net::{SocketAddr, TcpStream, UdpSocket},
	time::Duration,
};

use cronet_rs::linux_dialer::SocketDialer;
use socket2::{Domain, Protocol, Socket, Type};

/// Kernel routing settings shared by all physical connections of one Naive
/// engine.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct LinuxSocketPolicy {
	pub interface: Option<String>,
	pub so_mark: Option<u32>,
}

#[derive(Debug)]
pub(super) struct LinuxDialer {
	policy: LinuxSocketPolicy,
	connect_timeout: Duration,
}

impl LinuxDialer {
	pub(super) fn new(policy: LinuxSocketPolicy, connect_timeout: Duration) -> io::Result<Self> {
		if connect_timeout.is_zero() {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"TCP connect timeout must be positive",
			));
		}
		// Linux IFNAMSIZ includes the terminating NUL. Reject truncation or an
		// accidental unbind.
		if let Some(name) = &policy.interface
			&& (name.is_empty() || name.as_bytes().contains(&0) || name.len() > 15)
		{
			return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid Linux interface name"));
		}
		Ok(Self { policy, connect_timeout })
	}

	fn socket(&self, peer: SocketAddr, kind: Type, protocol: Protocol) -> io::Result<Socket> {
		let socket = Socket::new(Domain::for_address(peer), kind, Some(protocol))?;
		if let Some(name) = &self.policy.interface {
			socket.bind_device(Some(name.as_bytes()))?;
		}
		if let Some(mark) = self.policy.so_mark {
			socket.set_mark(mark)?;
		}
		Ok(socket)
	}
}

impl SocketDialer for LinuxDialer {
	fn connect_tcp(&self, peer: SocketAddr) -> io::Result<TcpStream> {
		let socket = self.socket(peer, Type::STREAM, Protocol::TCP)?;
		socket.connect_timeout(&peer.into(), self.connect_timeout)?;
		Ok(socket.into())
	}

	fn connect_udp(&self, peer: SocketAddr) -> io::Result<UdpSocket> {
		let socket = self.socket(peer, Type::DGRAM, Protocol::UDP)?;
		socket.connect(&peer.into())?;
		Ok(socket.into())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn invalid_interface_never_becomes_an_unbound_dial() {
		for name in ["", "lo\0other", "1234567890123456"] {
			let policy = LinuxSocketPolicy {
				interface: Some(name.into()),
				so_mark: None,
			};
			assert_eq!(
				LinuxDialer::new(policy, Duration::from_secs(1)).unwrap_err().kind(),
				io::ErrorKind::InvalidInput
			);
		}
	}

	#[test]
	fn missing_device_fails_both_transports_before_connect() {
		let policy = LinuxSocketPolicy {
			interface: Some("no-such-if.test".into()),
			so_mark: None,
		};
		let dialer = LinuxDialer::new(policy, Duration::from_secs(1)).unwrap();
		let peer = SocketAddr::from(([127, 0, 0, 1], 443));
		assert!(dialer.connect_tcp(peer).is_err());
		assert!(dialer.connect_udp(peer).is_err());
	}
}

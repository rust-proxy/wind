use std::{
	io,
	net::{SocketAddr, TcpStream, UdpSocket},
	time::Duration,
};

use cronet_rs::socket_dialer::SocketDialer;
use socket2::{Domain, Protocol, Socket, Type};

/// One physical interface a Naive engine's sockets must use.
///
/// Linux binds by name; Apple and Windows bind by index. Both fields are kept
/// in the policy so it can be used as a cache key and named in diagnostics.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SocketInterface {
	pub name: String,
	pub index: u32,
}

/// Kernel routing settings shared by all physical connections of one Naive
/// engine.
///
/// `interface` is applied on Linux, macOS/iOS and Windows. `so_mark` is
/// Linux-only; other platforms reject a non-empty mark instead of silently
/// ignoring it.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct SocketPolicy {
	pub interface: Option<SocketInterface>,
	pub so_mark: Option<u32>,
}

#[derive(Debug)]
pub(super) struct PolicyDialer {
	policy: SocketPolicy,
	connect_timeout: Duration,
}

impl PolicyDialer {
	pub(super) fn new(policy: SocketPolicy, connect_timeout: Duration) -> io::Result<Self> {
		if connect_timeout.is_zero() {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"TCP connect timeout must be positive",
			));
		}
		validate_policy(&policy)?;
		Ok(Self { policy, connect_timeout })
	}

	fn socket(&self, peer: SocketAddr, kind: Type, protocol: Protocol) -> io::Result<Socket> {
		let socket = Socket::new(Domain::for_address(peer), kind, Some(protocol))?;
		apply_socket_policy(&socket, &self.policy, Domain::for_address(peer))?;
		Ok(socket)
	}
}

impl SocketDialer for PolicyDialer {
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

fn validate_policy(policy: &SocketPolicy) -> io::Result<()> {
	#[cfg(target_os = "linux")]
	{
		if let Some(interface) = &policy.interface
			&& (interface.name.is_empty() || interface.name.as_bytes().contains(&0) || interface.name.len() > 15)
		{
			return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid Linux interface name"));
		}
	}

	#[cfg(any(target_vendor = "apple", windows))]
	{
		if let Some(interface) = &policy.interface {
			if interface.name.is_empty() {
				return Err(io::Error::new(
					io::ErrorKind::InvalidInput,
					"interface name must not be empty",
				));
			}
			if interface.index == 0 {
				return Err(io::Error::new(io::ErrorKind::InvalidInput, "interface index must be nonzero"));
			}
		}
		if policy.so_mark.is_some() {
			return Err(io::Error::new(
				io::ErrorKind::Unsupported,
				"SO_MARK is only supported on Linux",
			));
		}
	}

	#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
	{
		if policy.interface.is_some() || policy.so_mark.is_some() {
			return Err(io::Error::new(
				io::ErrorKind::Unsupported,
				"socket policy is not supported on this platform",
			));
		}
	}

	Ok(())
}

fn apply_socket_policy(socket: &Socket, policy: &SocketPolicy, domain: Domain) -> io::Result<()> {
	#[cfg(target_os = "linux")]
	{
		let _ = domain;
		if let Some(interface) = &policy.interface {
			socket.bind_device(Some(interface.name.as_bytes()))?;
		}
		if let Some(mark) = policy.so_mark {
			socket.set_mark(mark)?;
		}
	}

	#[cfg(target_vendor = "apple")]
	{
		if let Some(interface) = &policy.interface {
			let index = std::num::NonZeroU32::new(interface.index)
				.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "interface index must be nonzero"))?;
			match domain {
				Domain::IPV4 => socket.bind_device_by_index_v4(Some(index))?,
				Domain::IPV6 => socket.bind_device_by_index_v6(Some(index))?,
				_ => {
					return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported socket family"));
				}
			}
		}
	}

	#[cfg(windows)]
	{
		if let Some(interface) = &policy.interface {
			windows_socket::bind_interface(socket, interface.index, domain)?;
		}
	}

	#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
	{
		let _ = (socket, policy, domain);
	}

	Ok(())
}

#[cfg(windows)]
mod windows_socket {
	use std::{io, os::windows::io::AsRawSocket};

	use socket2::{Domain, Socket};
	use windows_sys::Win32::Networking::WinSock::{
		IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, WSAGetLastError, setsockopt,
	};

	/// Windows expects the IPv4 interface index in network byte order, but the
	/// IPv6 index in host byte order. See the IP_UNICAST_IF and
	/// IPV6_UNICAST_IF documentation.
	fn unicast_if_value(index: u32, domain: Domain) -> io::Result<(i32, i32, [u8; 4])> {
		match domain {
			Domain::IPV4 => Ok((IPPROTO_IP, IP_UNICAST_IF, index.to_be_bytes())),
			Domain::IPV6 => Ok((IPPROTO_IPV6, IPV6_UNICAST_IF, index.to_ne_bytes())),
			_ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported socket family")),
		}
	}

	pub(super) fn bind_interface(socket: &Socket, index: u32, domain: Domain) -> io::Result<()> {
		let (level, option, value) = unicast_if_value(index, domain)?;
		let handle: SOCKET = socket.as_raw_socket() as usize;
		let rc = unsafe { setsockopt(handle, level, option, value.as_ptr(), value.len() as i32) };
		if rc != 0 {
			let code = unsafe { WSAGetLastError() };
			return Err(io::Error::from_raw_os_error(code));
		}
		Ok(())
	}

	#[cfg(test)]
	mod tests {
		use super::*;

		#[test]
		fn unicast_if_uses_the_documented_byte_order() {
			assert_eq!(
				unicast_if_value(7, Domain::IPV4).unwrap(),
				(IPPROTO_IP, IP_UNICAST_IF, 7u32.to_be_bytes())
			);
			assert_eq!(
				unicast_if_value(7, Domain::IPV6).unwrap(),
				(IPPROTO_IPV6, IPV6_UNICAST_IF, 7u32.to_ne_bytes())
			);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(target_os = "linux")]
	#[test]
	fn invalid_interface_never_becomes_an_unbound_dial() {
		for name in ["", "lo\0other", "1234567890123456"] {
			let policy = SocketPolicy {
				interface: Some(SocketInterface {
					name: name.into(),
					index: 1,
				}),
				so_mark: None,
			};
			assert_eq!(
				PolicyDialer::new(policy, Duration::from_secs(1)).unwrap_err().kind(),
				io::ErrorKind::InvalidInput
			);
		}
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn missing_device_fails_both_transports_before_connect() {
		let policy = SocketPolicy {
			interface: Some(SocketInterface {
				name: "no-such-if.test".into(),
				index: 1,
			}),
			so_mark: None,
		};
		let dialer = PolicyDialer::new(policy, Duration::from_secs(1)).unwrap();
		let peer = SocketAddr::from(([127, 0, 0, 1], 443));
		assert!(dialer.connect_tcp(peer).is_err());
		assert!(dialer.connect_udp(peer).is_err());
	}

	#[cfg(any(target_vendor = "apple", windows))]
	#[test]
	fn zero_interface_index_is_rejected() {
		let policy = SocketPolicy {
			interface: Some(SocketInterface {
				name: "test0".into(),
				index: 0,
			}),
			so_mark: None,
		};
		assert_eq!(
			PolicyDialer::new(policy, Duration::from_secs(1)).unwrap_err().kind(),
			io::ErrorKind::InvalidInput
		);
	}

	#[cfg(any(target_vendor = "apple", windows))]
	#[test]
	fn routing_mark_is_rejected_off_linux() {
		let policy = SocketPolicy {
			interface: None,
			so_mark: Some(1),
		};
		assert_eq!(
			PolicyDialer::new(policy, Duration::from_secs(1)).unwrap_err().kind(),
			io::ErrorKind::Unsupported
		);
	}

	#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
	#[test]
	fn unsupported_platform_rejects_a_interface_policy() {
		let policy = SocketPolicy {
			interface: Some(SocketInterface {
				name: "test0".into(),
				index: 1,
			}),
			so_mark: None,
		};
		assert_eq!(
			PolicyDialer::new(policy, Duration::from_secs(1)).unwrap_err().kind(),
			io::ErrorKind::Unsupported
		);
	}

	#[test]
	fn default_policy_can_dial_loopback() -> io::Result<()> {
		let dialer = PolicyDialer::new(SocketPolicy::default(), Duration::from_secs(1))?;
		let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
		let addr = listener.local_addr()?;
		let _tcp = dialer.connect_tcp(addr)?;
		let udp = std::net::UdpSocket::bind(("127.0.0.1", 0))?;
		let _udp = dialer.connect_udp(udp.local_addr()?)?;
		Ok(())
	}
}

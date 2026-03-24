use std::net::{SocketAddr, ToSocketAddrs};

use wind_core::types::TargetAddr;

/// Converts a `TargetAddr` to a `SocketAddr`.
///
/// This function handles IPv4, IPv6, and domain addresses:
/// - For IPv4 and IPv6 addresses, it directly converts to `SocketAddr`
/// - For domain names, it attempts to resolve to an IP address using DNS
///
/// # Panics
///
/// This function will panic if:
/// - The domain cannot be resolved to an IP address
/// - No addresses are found for the given domain
pub fn target_addr_to_socket_addr(addr: &TargetAddr) -> SocketAddr {
	match addr {
		TargetAddr::IPv4(ip, port) => SocketAddr::from((*ip, *port)),
		TargetAddr::IPv6(ip, port) => SocketAddr::from((*ip, *port)),
		TargetAddr::Domain(domain, port) => {
			// For domain, we need to resolve it to an IP address
			// Since this is a synchronous function, we'll use the first resolved
			// address or fallback to a default if resolution fails
			let addrs = (domain.as_str(), *port)
				.to_socket_addrs()
				.expect("Failed to resolve domain to socket address");
			addrs.into_iter().next().expect("No address found for the given domain")
		}
	}
}

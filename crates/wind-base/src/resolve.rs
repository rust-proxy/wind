use std::net::SocketAddr;

use wind_core::{types::TargetAddr, utils::StackPrefer};

/// Resolve a `TargetAddr` to a single `SocketAddr` respecting the given
/// IP-stack preference.
pub async fn resolve_target(target: &TargetAddr, prefer: StackPrefer) -> eyre::Result<SocketAddr> {
	match target {
		TargetAddr::IPv4(ip, port) => Ok(SocketAddr::from((*ip, *port))),
		TargetAddr::IPv6(ip, port) => Ok(SocketAddr::from((*ip, *port))),
		TargetAddr::Domain(domain, port) => {
			let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", domain, port)).await?.collect();

			if addrs.is_empty() {
				return Err(eyre::eyre!("DNS returned no addresses for {}", domain));
			}

			pick_addr_by_preference(addrs, prefer)
				.ok_or_else(|| eyre::eyre!("No address matching ip_mode {:?} for {}", prefer, domain))
		}
	}
}

/// Pick the best address from a resolved list according to `StackPrefer`.
pub fn pick_addr_by_preference(addrs: Vec<SocketAddr>, prefer: StackPrefer) -> Option<SocketAddr> {
	let v4: Vec<SocketAddr> = addrs.iter().copied().filter(|a| a.is_ipv4()).collect();
	let v6: Vec<SocketAddr> = addrs.iter().copied().filter(|a| a.is_ipv6()).collect();

	match prefer {
		StackPrefer::V4only => v4.into_iter().next(),
		StackPrefer::V6only => v6.into_iter().next(),
		StackPrefer::V4first => v4.into_iter().next().or_else(|| v6.into_iter().next()),
		StackPrefer::V6first => v6.into_iter().next().or_else(|| v4.into_iter().next()),
	}
}

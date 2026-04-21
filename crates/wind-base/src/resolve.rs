use std::net::SocketAddr;

use wind_core::{resolve::Resolver, types::TargetAddr};

/// Resolve a `TargetAddr` to a single `SocketAddr` using the given resolver.
pub async fn resolve_target(target: &TargetAddr, resolver: &dyn Resolver) -> eyre::Result<SocketAddr> {
	match target {
		TargetAddr::IPv4(ip, port) => Ok(SocketAddr::from((*ip, *port))),
		TargetAddr::IPv6(ip, port) => Ok(SocketAddr::from((*ip, *port))),
		TargetAddr::Domain(domain, port) => resolver.resolve(domain, *port).await,
	}
}

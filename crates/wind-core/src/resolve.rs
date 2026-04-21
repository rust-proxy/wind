use std::net::{IpAddr, SocketAddr};

use crate::utils::StackPrefer;

/// Trait for asynchronous DNS resolution.
///
/// Implementations can back this with system DNS, Hickory DNS, or any other
/// resolver. The trait is object-safe so it can be stored as
/// `Arc<dyn Resolver>`.
pub trait Resolver: Send + Sync + 'static {
	/// Resolve `host` to a single [`SocketAddr`].
	///
	/// Literal IP addresses bypass the resolver and are returned directly.
	fn resolve<'a>(
		&'a self,
		host: &'a str,
		port: u16,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = eyre::Result<SocketAddr>> + Send + 'a>>;

	/// Resolve `host` to every available [`SocketAddr`].
	///
	/// Literal IP addresses yield a single-entry vector.
	fn resolve_all<'a>(
		&'a self,
		host: &'a str,
		port: u16,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = eyre::Result<Vec<SocketAddr>>> + Send + 'a>>;
}

/// System DNS resolver backed by [`tokio::net::lookup_host`].
///
/// When the hostname is a literal IP address it is returned immediately
/// without hitting the network.
pub struct SystemResolver {
	pub prefer: StackPrefer,
}

impl SystemResolver {
	pub fn new(prefer: StackPrefer) -> Self {
		Self { prefer }
	}
}

impl Resolver for SystemResolver {
	fn resolve<'a>(
		&'a self,
		host: &'a str,
		port: u16,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = eyre::Result<SocketAddr>> + Send + 'a>> {
		Box::pin(async move {
			if let Ok(ip) = host.parse::<IpAddr>() {
				return Ok(SocketAddr::new(ip, port));
			}
			let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{host}:{port}")).await?.collect();
			if addrs.is_empty() {
				eyre::bail!("no DNS records for {host}");
			}
			pick_addr_by_preference(addrs, self.prefer)
				.ok_or_else(|| eyre::eyre!("no address matching {:?} for {host}", self.prefer))
		})
	}

	fn resolve_all<'a>(
		&'a self,
		host: &'a str,
		port: u16,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = eyre::Result<Vec<SocketAddr>>> + Send + 'a>> {
		Box::pin(async move {
			if let Ok(ip) = host.parse::<IpAddr>() {
				return Ok(vec![SocketAddr::new(ip, port)]);
			}
			let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{host}:{port}")).await?.collect();
			if addrs.is_empty() {
				eyre::bail!("no DNS records for {host}");
			}
			Ok(filter_addrs_by_preference(addrs, self.prefer))
		})
	}
}

/// Pick the best address from a resolved list according to [`StackPrefer`].
pub fn pick_addr_by_preference(addrs: Vec<SocketAddr>, prefer: StackPrefer) -> Option<SocketAddr> {
	let v4 = || addrs.iter().copied().filter(|a| a.is_ipv4());
	let v6 = || addrs.iter().copied().filter(|a| a.is_ipv6());

	match prefer {
		StackPrefer::V4only => v4().next(),
		StackPrefer::V6only => v6().next(),
		StackPrefer::V4first => v4().next().or_else(|| v6().next()),
		StackPrefer::V6first => v6().next().or_else(|| v4().next()),
	}
}

/// Filter addresses according to [`StackPrefer`], preserving order within the
/// preferred family.
pub fn filter_addrs_by_preference(addrs: Vec<SocketAddr>, prefer: StackPrefer) -> Vec<SocketAddr> {
	match prefer {
		StackPrefer::V4only => addrs.into_iter().filter(|a| a.is_ipv4()).collect(),
		StackPrefer::V6only => addrs.into_iter().filter(|a| a.is_ipv6()).collect(),
		StackPrefer::V4first => {
			let (mut v4, v6): (Vec<_>, Vec<_>) = addrs.into_iter().partition(|a| a.is_ipv4());
			v4.extend(v6);
			v4
		}
		StackPrefer::V6first => {
			let (v4, mut v6): (Vec<_>, Vec<_>) = addrs.into_iter().partition(|a| a.is_ipv4());
			v6.extend(v4);
			v6
		}
	}
}

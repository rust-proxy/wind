use std::{
	net::{IpAddr, SocketAddr},
	pin::Pin,
};

use eyre::{Context, Result};
use hickory_resolver::{
	TokioResolver,
	config::{LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts},
	name_server::TokioConnectionProvider,
	proto::xfer::Protocol,
};
use wind_core::{
	StackPrefer,
	resolve::{Resolver, filter_addrs_by_preference, pick_addr_by_preference},
};

use crate::config::{DnsConfig, DnsMode};

/// DNS resolver backed by [Hickory DNS](https://github.com/hickory-dns/hickory-dns).
pub struct HickoryResolver {
	inner: TokioResolver,
	prefer: StackPrefer,
}

impl HickoryResolver {
	pub fn new(inner: TokioResolver, prefer: StackPrefer) -> Self {
		Self { inner, prefer }
	}
}

impl Resolver for HickoryResolver {
	fn resolve<'a>(&'a self, host: &'a str) -> Pin<Box<dyn Future<Output = Result<IpAddr>> + Send + 'a>> {
		Box::pin(async move {
			if let Ok(ip) = host.parse::<IpAddr>() {
				return Ok(ip);
			}
			let lookup = self
				.inner
				.lookup_ip(host)
				.await
				.with_context(|| format!("hickory lookup_ip {host}"))?;
			let addrs: Vec<IpAddr> = lookup.iter().collect();
			if addrs.is_empty() {
				eyre::bail!("no DNS records for {host}");
			}
			pick_addr_by_preference(addrs, self.prefer)
				.ok_or_else(|| eyre::eyre!("no address matching {:?} for {host}", self.prefer))
		})
	}

	fn resolve_all<'a>(&'a self, host: &'a str) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>>> + Send + 'a>> {
		Box::pin(async move {
			if let Ok(ip) = host.parse::<IpAddr>() {
				return Ok(vec![ip]);
			}
			let lookup = self
				.inner
				.lookup_ip(host)
				.await
				.with_context(|| format!("hickory lookup_ip {host}"))?;
			let addrs: Vec<IpAddr> = lookup.iter().collect();
			if addrs.is_empty() {
				eyre::bail!("no DNS records for {host}");
			}
			Ok(filter_addrs_by_preference(addrs, self.prefer))
		})
	}
}

/// Build a [`HickoryResolver`] from the given configuration.
///
/// Returns `None` for `DnsMode::System`.
pub(crate) fn build(cfg: &DnsConfig) -> Result<Option<HickoryResolver>> {
	let rc: ResolverConfig = match cfg.mode {
		DnsMode::System => return Ok(None),
		DnsMode::Cloudflare => ResolverConfig::cloudflare(),
		DnsMode::CloudflareTls => ResolverConfig::cloudflare_tls(),
		DnsMode::CloudflareHttps => ResolverConfig::cloudflare_https(),
		DnsMode::Google => ResolverConfig::google(),
		DnsMode::GoogleTls => ResolverConfig::google_tls(),
		DnsMode::GoogleHttps => ResolverConfig::google_https(),
		DnsMode::Quad9 => ResolverConfig::quad9(),
		DnsMode::Quad9Tls => ResolverConfig::quad9_tls(),
		DnsMode::Quad9Https => ResolverConfig::quad9_https(),
		DnsMode::Custom => {
			if cfg.servers.is_empty() {
				eyre::bail!("[dns] mode = \"custom\" requires at least one entry in `servers`");
			}
			let mut rc = ResolverConfig::new();
			for s in &cfg.servers {
				let ns = parse_server(s).with_context(|| format!("parsing DNS server spec {s:?}"))?;
				rc.add_name_server(ns);
			}
			rc
		}
	};

	let mut opts = ResolverOpts::default();
	if let Some(t) = cfg.timeout {
		opts.timeout = t;
	}
	if let Some(a) = cfg.attempts {
		opts.attempts = a;
	}
	opts.ip_strategy = match cfg.stack_prefer {
		StackPrefer::V4only => LookupIpStrategy::Ipv4Only,
		StackPrefer::V6only => LookupIpStrategy::Ipv6Only,
		StackPrefer::V4first => LookupIpStrategy::Ipv4thenIpv6,
		StackPrefer::V6first => LookupIpStrategy::Ipv6thenIpv4,
	};

	let resolver = TokioResolver::builder_with_config(rc, TokioConnectionProvider::default())
		.with_options(opts)
		.build();
	Ok(Some(HickoryResolver::new(resolver, cfg.stack_prefer)))
}

/// Parse a DNS server URL or bare address into a [`NameServerConfig`].
fn parse_server(spec: &str) -> Result<NameServerConfig> {
	let (scheme, rest) = match spec.split_once("://") {
		Some((a, b)) => (a.to_ascii_lowercase(), b),
		None => (String::from("udp"), spec),
	};

	let (addr_part, sni) = match rest.rsplit_once('#') {
		Some((a, b)) => (a, Some(b.to_string())),
		None => (rest, None),
	};

	let (protocol, default_port) = match scheme.as_str() {
		"udp" => (Protocol::Udp, 53u16),
		"tcp" => (Protocol::Tcp, 53u16),
		"tls" => (Protocol::Tls, 853u16),
		"https" => (Protocol::Https, 443u16),
		other => eyre::bail!("unknown DNS scheme: {other}"),
	};

	let (ip_str, port) = split_host_port(addr_part, default_port)?;
	let ip: IpAddr = ip_str
		.parse()
		.with_context(|| format!("invalid IP literal in DNS server: {ip_str}"))?;
	let socket_addr = SocketAddr::new(ip, port);

	let mut ns = NameServerConfig::new(socket_addr, protocol);
	if matches!(protocol, Protocol::Tls | Protocol::Https) {
		ns.tls_dns_name = sni.or_else(|| Some(ip.to_string()));
	}
	Ok(ns)
}

fn split_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
	// Bracketed IPv6: [addr] or [addr]:port
	if let Some(rest) = s.strip_prefix('[') {
		let end = rest.find(']').ok_or_else(|| eyre::eyre!("unclosed IPv6 bracket in {s}"))?;
		let host = &rest[..end];
		let tail = &rest[end + 1..];
		let port = if let Some(p) = tail.strip_prefix(':') {
			p.parse::<u16>().with_context(|| format!("invalid port in {s}"))?
		} else if tail.is_empty() {
			default_port
		} else {
			eyre::bail!("trailing garbage after ']' in {s}");
		};
		return Ok((host.to_string(), port));
	}

	// Bare IPv6 (at least two colons) — cannot carry a port without brackets.
	if s.matches(':').count() >= 2 {
		return Ok((s.to_string(), default_port));
	}

	// "host:port" or "host"
	match s.rsplit_once(':') {
		Some((h, p)) => {
			let port = p.parse::<u16>().with_context(|| format!("invalid port in {s}"))?;
			Ok((h.to_string(), port))
		}
		None => Ok((s.to_string(), default_port)),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_bare_ipv4() {
		let ns = parse_server("1.1.1.1").unwrap();
		assert_eq!(ns.socket_addr, "1.1.1.1:53".parse().unwrap());
		assert!(matches!(ns.protocol, Protocol::Udp));
	}

	#[test]
	fn parse_ipv4_with_port() {
		let ns = parse_server("udp://1.1.1.1:5353").unwrap();
		assert_eq!(ns.socket_addr, "1.1.1.1:5353".parse().unwrap());
		assert!(matches!(ns.protocol, Protocol::Udp));
	}

	#[test]
	fn parse_dot_with_sni() {
		let ns = parse_server("tls://1.1.1.1#cloudflare-dns.com").unwrap();
		assert_eq!(ns.socket_addr, "1.1.1.1:853".parse().unwrap());
		assert!(matches!(ns.protocol, Protocol::Tls));
		assert_eq!(ns.tls_dns_name.as_deref(), Some("cloudflare-dns.com"));
	}

	#[test]
	fn parse_doh_bracketed_ipv6() {
		let ns = parse_server("https://[2606:4700:4700::1111]:443#cloudflare-dns.com").unwrap();
		assert_eq!(ns.socket_addr.port(), 443);
		assert!(matches!(ns.protocol, Protocol::Https));
		assert_eq!(ns.tls_dns_name.as_deref(), Some("cloudflare-dns.com"));
	}

	#[test]
	fn parse_bare_ipv6() {
		let ns = parse_server("2606:4700:4700::1111").unwrap();
		assert_eq!(ns.socket_addr.port(), 53);
	}

	#[test]
	fn parse_rejects_bad_scheme() {
		assert!(parse_server("ftp://1.1.1.1").is_err());
	}

	#[test]
	fn build_system_returns_none() {
		let mut cfg = DnsConfig::default();
		cfg.mode = DnsMode::System;
		assert!(matches!(cfg.mode, DnsMode::System));
		let result = build(&cfg).unwrap();
		assert!(result.is_none());
	}
}

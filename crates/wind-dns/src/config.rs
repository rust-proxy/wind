use std::time::Duration;

use educe::Educe;
use serde::{Deserialize, Serialize};
use wind_core::StackPrefer;

/// Preset or custom DNS resolver for outbound traffic.
///
/// * `System` preserves the legacy behaviour (`tokio::net::lookup_host`, which
///   in turn uses the OS `getaddrinfo`).
/// * The named presets use Hickory DNS with the published resolver IPs for each
///   provider. `*Tls` variants speak DoT, `*Https` variants speak DoH.
/// * `Custom` reads [`DnsConfig::servers`].
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Educe)]
#[serde(rename_all = "kebab-case")]
#[educe(Default)]
pub enum DnsMode {
	System,
	Cloudflare,
	#[educe(Default)]
	CloudflareTls,
	CloudflareHttps,
	Google,
	GoogleTls,
	GoogleHttps,
	Quad9,
	Quad9Tls,
	Quad9Https,
	Custom,
}

/// DNS resolver configuration.
///
/// Defaults to the OS resolver, matching the pre-existing behaviour. When a
/// non-`System` mode is selected, outbound FQDN lookups are routed through a
/// Hickory DNS resolver built from these settings.
#[derive(Debug, Clone, Deserialize, Serialize, Educe)]
#[serde(deny_unknown_fields)]
#[educe(Default)]
pub struct DnsConfig {
	/// Resolver mode. See [`DnsMode`].
	pub mode: DnsMode,

	/// Servers for `mode = "custom"`. Each entry is either a bare address or a
	/// URL-style specifier:
	///   * `1.1.1.1` or `1.1.1.1:53`        — UDP on port 53
	///   * `udp://1.1.1.1[:port]`
	///   * `tcp://1.1.1.1[:port]`
	///   * `tls://1.1.1.1[:port][#sni]`     — DoT (port defaults to 853)
	///   * `https://1.1.1.1[:port][#sni]`   — DoH (port defaults to 443)
	///
	/// IPv6 literals must be bracketed when a port is present, e.g.
	/// `tls://[2606:4700:4700::1111]:853#cloudflare-dns.com`.
	#[serde(default)]
	pub servers: Vec<String>,

	/// Per-query timeout. Defaults to the Hickory library default.
	#[serde(default, with = "humantime_serde::option")]
	pub timeout: Option<Duration>,

	/// Retry attempts per query. Defaults to the Hickory library default.
	pub attempts: Option<usize>,

	/// IP stack preference. Default: v4first (A first, then AAAA).
	#[educe(Default(expression = StackPrefer::V4first))]
	pub stack_prefer: StackPrefer,
}

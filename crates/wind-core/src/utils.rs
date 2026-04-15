use std::{net::IpAddr, str::FromStr};

use serde::{Deserialize, Serialize};

/// IP stack preference for address resolution.
///
/// Determines which IP version to prefer when resolving domain names.
///
/// # Variants
///
/// - `V4only`: Use only IPv4 addresses (alias: "v4", "only_v4")
/// - `V6only`: Use only IPv6 addresses (alias: "v6", "only_v6")
/// - `V4first`: Prefer IPv4, fallback to IPv6 (alias: "v4v6", "prefer_v4")
/// - `V6first`: Prefer IPv6, fallback to IPv4 (alias: "v6v4", "prefer_v6")
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StackPrefer {
	/// Use only IPv4 addresses
	#[serde(alias = "v4", alias = "only_v4")]
	#[default]
	V4only,
	/// Use only IPv6 addresses
	#[serde(alias = "v6", alias = "only_v6")]
	V6only,
	/// Prefer IPv4, fallback to IPv6
	#[serde(alias = "v4v6", alias = "prefer_v4", alias = "auto")]
	V4first,
	/// Prefer IPv6, fallback to IPv4
	#[serde(alias = "v6v4", alias = "prefer_v6")]
	V6first,
}

impl FromStr for StackPrefer {
	type Err = &'static str;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_ascii_lowercase().as_str() {
			"v4" | "v4only" | "only_v4" => Ok(StackPrefer::V4only),
			"v6" | "v6only" | "only_v6" => Ok(StackPrefer::V6only),
			"v4v6" | "v4first" | "prefer_v4" | "auto" => Ok(StackPrefer::V4first),
			"v6v4" | "v6first" | "prefer_v6" => Ok(StackPrefer::V6first),
			_ => Err("invalid stack preference"),
		}
	}
}

/// Check if an IP address is private (LAN address)
///
/// Returns `true` for:
/// - IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
///   (Link-local)
/// - IPv6: fc00::/7 (Unique Local Address), fe80::/10 (Link-local)
#[inline]
pub fn is_private_ip(ip: &IpAddr) -> bool {
	match ip {
		IpAddr::V4(ipv4) => {
			// 10.0.0.0/8
			ipv4.octets()[0] == 10
				// 172.16.0.0/12
				|| (ipv4.octets()[0] == 172 && (ipv4.octets()[1] >= 16 && ipv4.octets()[1] <= 31))
				// 192.168.0.0/16
				|| (ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168)
				// 169.254.0.0/16 (Link-local)
				|| (ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254)
		}
		IpAddr::V6(ipv6) => {
			// fc00::/7 (Unique Local Address)
			ipv6.octets()[0] & 0xfe == 0xfc
				// fe80::/10 (Link-local)
				|| (ipv6.octets()[0] == 0xfe && (ipv6.octets()[1] & 0xc0) == 0x80)
		}
	}
}

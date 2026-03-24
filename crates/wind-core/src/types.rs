use std::{
	fmt::Display,
	net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TargetAddr {
	Domain(String, u16),
	IPv4(Ipv4Addr, u16),
	IPv6(Ipv6Addr, u16),
}

impl From<SocketAddr> for TargetAddr {
	fn from(addr: SocketAddr) -> Self {
		match addr {
			SocketAddr::V4(addr) => TargetAddr::IPv4(*addr.ip(), addr.port()),
			SocketAddr::V6(addr) => TargetAddr::IPv6(*addr.ip(), addr.port()),
		}
	}
}

impl Display for TargetAddr {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			TargetAddr::Domain(domain, port) => write!(f, "{}:{}", domain, port),
			TargetAddr::IPv4(addr, port) => write!(f, "{}:{}", addr, port),
			TargetAddr::IPv6(addr, port) => write!(f, "[{}]:{}", addr, port),
		}
	}
}

impl Serialize for TargetAddr {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		self.to_string().serialize(serializer)
	}
}

impl<'de> Deserialize<'de> for TargetAddr {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		use serde::de::Error;

		let s = String::deserialize(deserializer)?;

		// Check if this is an IPv6 address with brackets [IPv6]:port
		if s.starts_with('[') {
			let end_bracket = match s.find(']') {
				Some(pos) => pos,
				None => {
					return Err(Error::custom("Invalid IPv6 address format, missing closing bracket"));
				}
			};

			// Ensure there's a colon after the closing bracket
			if end_bracket + 1 >= s.len() || !s[end_bracket + 1..].starts_with(':') {
				return Err(Error::custom("Invalid IPv6 address format, expected [IPv6]:port"));
			}

			let ipv6_str = &s[1..end_bracket];
			let port_str = &s[end_bracket + 2..];

			let ipv6_addr = match ipv6_str.parse::<Ipv6Addr>() {
				Ok(addr) => addr,
				Err(_) => return Err(Error::custom("Invalid IPv6 address")),
			};

			let port = match port_str.parse::<u16>() {
				Ok(p) => p,
				Err(_) => return Err(Error::custom("Invalid port number")),
			};

			return Ok(TargetAddr::IPv6(ipv6_addr, port));
		}

		// Split the string into host and port parts for IPv4 or domain
		let parts: Vec<&str> = s.split(':').collect();
		if parts.len() != 2 {
			return Err(Error::custom("Invalid address format, expected host:port"));
		}

		// Parse the port
		let port = match parts[1].parse::<u16>() {
			Ok(p) => p,
			Err(_) => return Err(Error::custom("Invalid port number")),
		};

		// Try to parse as IPv4 first
		if let Ok(ipv4) = parts[0].parse::<Ipv4Addr>() {
			Ok(TargetAddr::IPv4(ipv4, port))
		} else {
			// Otherwise treat as domain
			Ok(TargetAddr::Domain(parts[0].to_string(), port))
		}
	}
}


#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_display_ipv4() {
		let addr = TargetAddr::IPv4("127.0.0.1".parse().unwrap(), 8080);
		assert_eq!(addr.to_string(), "127.0.0.1:8080");
	}

	#[test]
	fn test_display_ipv6() {
		let addr = TargetAddr::IPv6("::1".parse().unwrap(), 8080);
		assert_eq!(addr.to_string(), "[::1]:8080");
	}

	#[test]
	fn test_display_domain() {
		let addr = TargetAddr::Domain("example.com".to_string(), 443);
		assert_eq!(addr.to_string(), "example.com:443");
	}

	#[test]
	fn test_serialize_deserialize_ipv4() {
		let addr = TargetAddr::IPv4("192.168.1.1".parse().unwrap(), 1234);
		let serialized = serde_json::to_string(&addr).unwrap();
		assert_eq!(serialized, "\"192.168.1.1:1234\"");
		let deserialized: TargetAddr = serde_json::from_str(&serialized).unwrap();
		assert_eq!(deserialized, addr);
	}

	#[test]
	fn test_serialize_deserialize_ipv6() {
		let addr = TargetAddr::IPv6("2001:db8::1".parse().unwrap(), 5678);
		let serialized = serde_json::to_string(&addr).unwrap();
		assert_eq!(serialized, "\"[2001:db8::1]:5678\"");
		let deserialized: TargetAddr = serde_json::from_str(&serialized).unwrap();
		assert_eq!(deserialized, addr);
	}

	#[test]
	fn test_serialize_deserialize_domain() {
		let addr = TargetAddr::Domain("test.org".to_string(), 80);
		let serialized = serde_json::to_string(&addr).unwrap();
		assert_eq!(serialized, "\"test.org:80\"");
		let deserialized: TargetAddr = serde_json::from_str(&serialized).unwrap();
		assert_eq!(deserialized, addr);
	}

	#[test]
	fn test_deserialize_invalid_ipv6() {
		let s = "[invalid]:1234";
		let result: Result<TargetAddr, _> = serde_json::from_str(&format!("\"{}\"", s));
		assert!(result.is_err());
	}

	#[test]
	fn test_deserialize_invalid_port() {
		let s = "127.0.0.1:notaport";
		let result: Result<TargetAddr, _> = serde_json::from_str(&format!("\"{}\"", s));
		assert!(result.is_err());
	}

	#[test]
	fn test_deserialize_missing_bracket() {
		let s = "[::1:8080";
		let result: Result<TargetAddr, _> = serde_json::from_str(&format!("\"{}\"", s));
		assert!(result.is_err());
	}

	#[test]
	fn test_deserialize_invalid_format() {
		let s = "justastring";
		let result: Result<TargetAddr, _> = serde_json::from_str(&format!("\"{}\"", s));
		assert!(result.is_err());
	}
}

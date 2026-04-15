use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Iface {
	pub name: String,
	pub ipv4: Option<Ipv4Addr>,
	pub ipv6: Option<Ipv6Addr>,
	pub index: u32,
}

#[derive(Debug, Clone, Default)]
pub enum Stack {
	#[default]
	V4,
	V6,
}
impl From<&SocketAddr> for Stack {
	fn from(value: &SocketAddr) -> Self {
		match value {
			SocketAddr::V4(..) => Self::V4,
			SocketAddr::V6(..) => Self::V6,
		}
	}
}
impl From<&IpAddr> for Stack {
	fn from(value: &IpAddr) -> Self {
		match value {
			IpAddr::V4(..) => Self::V4,
			IpAddr::V6(..) => Self::V6,
		}
	}
}

#[derive(Serialize, Debug, Clone, Copy)]
pub enum Network {
	TCP,
	UDP,
	ICMPv4,
	ICMPv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackPrefer {
	V4,
	V6,
	V4V6,
	V6V4,
}

impl StackPrefer {
	pub fn support_v6(&self) -> bool {
		!matches!(self, StackPrefer::V4)
	}
}

impl Serialize for StackPrefer {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		let s = match self {
			StackPrefer::V4 => "v4",
			StackPrefer::V6 => "v6",
			StackPrefer::V4V6 => "v4v6",
			StackPrefer::V6V4 => "v6v4",
		};
		serializer.serialize_str(s)
	}
}

impl<'de> Deserialize<'de> for StackPrefer {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		match s.to_ascii_lowercase().as_str() {
			"v4" | "v4only" | "only_v4" => Ok(StackPrefer::V4),
			"v6" | "v6only" | "only_v6" => Ok(StackPrefer::V6),
			"v4v6" | "v4_v6" | "v4first" | "prefer_v4" => Ok(StackPrefer::V4V6),
			"v6v4" | "v6_v4" | "v6first" | "prefer_v6" => Ok(StackPrefer::V6V4),
			_ => Err(serde::de::Error::custom(format!("invalid stack preference: '{s}'"))),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_stack_prefer_serialize() {
		assert_eq!(serde_json::to_string(&StackPrefer::V4).unwrap(), r#""v4""#);
		assert_eq!(serde_json::to_string(&StackPrefer::V6).unwrap(), r#""v6""#);
		assert_eq!(serde_json::to_string(&StackPrefer::V4V6).unwrap(), r#""v4v6""#);
		assert_eq!(serde_json::to_string(&StackPrefer::V6V4).unwrap(), r#""v6v4""#);
	}

	#[test]
	fn test_stack_prefer_deserialize_canonical() {
		assert_eq!(serde_json::from_str::<StackPrefer>(r#""v4""#).unwrap(), StackPrefer::V4);
		assert_eq!(serde_json::from_str::<StackPrefer>(r#""v6""#).unwrap(), StackPrefer::V6);
		assert_eq!(serde_json::from_str::<StackPrefer>(r#""v4v6""#).unwrap(), StackPrefer::V4V6);
		assert_eq!(serde_json::from_str::<StackPrefer>(r#""v6v4""#).unwrap(), StackPrefer::V6V4);
	}

	#[test]
	fn test_stack_prefer_deserialize_aliases() {
		// V4 aliases
		assert_eq!(serde_json::from_str::<StackPrefer>(r#""v4only""#).unwrap(), StackPrefer::V4);
		assert_eq!(serde_json::from_str::<StackPrefer>(r#""only_v4""#).unwrap(), StackPrefer::V4);

		// V6 aliases
		assert_eq!(serde_json::from_str::<StackPrefer>(r#""v6only""#).unwrap(), StackPrefer::V6);
		assert_eq!(serde_json::from_str::<StackPrefer>(r#""only_v6""#).unwrap(), StackPrefer::V6);

		// V4V6 aliases
		assert_eq!(serde_json::from_str::<StackPrefer>(r#""v4_v6""#).unwrap(), StackPrefer::V4V6);
		assert_eq!(
			serde_json::from_str::<StackPrefer>(r#""v4first""#).unwrap(),
			StackPrefer::V4V6
		);
		assert_eq!(
			serde_json::from_str::<StackPrefer>(r#""prefer_v4""#).unwrap(),
			StackPrefer::V4V6
		);

		// V6V4 aliases
		assert_eq!(serde_json::from_str::<StackPrefer>(r#""v6_v4""#).unwrap(), StackPrefer::V6V4);
		assert_eq!(
			serde_json::from_str::<StackPrefer>(r#""v6first""#).unwrap(),
			StackPrefer::V6V4
		);
		assert_eq!(
			serde_json::from_str::<StackPrefer>(r#""prefer_v6""#).unwrap(),
			StackPrefer::V6V4
		);
	}

	#[test]
	fn test_stack_prefer_deserialize_case_insensitive() {
		assert_eq!(serde_json::from_str::<StackPrefer>(r#""V4""#).unwrap(), StackPrefer::V4);
		assert_eq!(serde_json::from_str::<StackPrefer>(r#""V4V6""#).unwrap(), StackPrefer::V4V6);
		assert_eq!(
			serde_json::from_str::<StackPrefer>(r#""V6First""#).unwrap(),
			StackPrefer::V6V4
		);
	}

	#[test]
	fn test_stack_prefer_deserialize_invalid() {
		assert!(serde_json::from_str::<StackPrefer>(r#""invalid""#).is_err());
		assert!(serde_json::from_str::<StackPrefer>(r#""v5""#).is_err());
	}

	#[test]
	fn test_stack_prefer_roundtrip() {
		for variant in [StackPrefer::V4, StackPrefer::V6, StackPrefer::V4V6, StackPrefer::V6V4] {
			let serialized = serde_json::to_string(&variant).unwrap();
			let deserialized: StackPrefer = serde_json::from_str(&serialized).unwrap();
			assert_eq!(variant, deserialized);
		}
	}
}

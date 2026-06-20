//! Optional self-contained serde config for building an [`AclEngine`].
//!
//! Servers that already have their own outbound/routing config (e.g. wind's
//! `OutboundConfig`) can ignore this and drive [`AclEngine::builder`] directly.
//! This type exists for standalone consumers that want one struct to
//! deserialize.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use wind_core::resolve::Resolver;

use crate::{
	engine::{AclEngine, AclEngineBuilder, GuardConfig},
	syntax::apernet::{self as acl, AclRule},
};

fn default_outbound() -> String {
	"default".to_string()
}

/// Deserializable description of a routing policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct AclConfig {
	/// Outbound used when no rule matches.
	pub default: String,
	/// Clash / Mihomo rule lines.
	pub rules: Vec<String>,
	/// Hysteria-style ACL rules (array-of-tables or a multiline string).
	#[serde(deserialize_with = "acl::deserialize_acl")]
	pub acl: Vec<AclRule>,
	/// Loopback / private-range guards.
	pub guards: GuardConfig,
}

impl Default for AclConfig {
	fn default() -> Self {
		Self {
			default: default_outbound(),
			rules: Vec::new(),
			acl: Vec::new(),
			guards: GuardConfig::default(),
		}
	}
}

impl AclConfig {
	/// Turn this config into a partially-populated [`AclEngineBuilder`]. The
	/// caller still supplies the resolver (required when guards are on) and any
	/// inbound context before calling [`AclEngineBuilder::build`].
	pub fn builder(&self) -> eyre::Result<AclEngineBuilder> {
		Ok(AclEngine::builder(&self.default)
			.clash_rules(&self.rules)?
			.hysteria_acl(&self.acl)
			.guards(self.guards))
	}

	/// Convenience: build an engine directly, attaching `resolver` if provided.
	pub fn build(&self, resolver: Option<Arc<dyn Resolver>>) -> eyre::Result<AclEngine> {
		let mut builder = self.builder()?;
		if let Some(resolver) = resolver {
			builder = builder.resolver(resolver);
		}
		builder.build()
	}
}

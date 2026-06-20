//! The [`AclEngine`] router and its [`AclEngineBuilder`], backed by the
//! [`Ruleset`](crate::Ruleset) IR.
//!
//! The builder collects Clash/Mihomo rules and Hysteria-style ACL rules (the
//! latter converted via [`acl::acl_to_rules`]), lowers them through the
//! degenerate embedding ([`Ruleset::from_rules`]), and runs the
//! order-preserving optimizer ([`compile`]). The resulting engine implements
//! [`wind_core::Router`] and routes by building a `MatchContext` and calling
//! [`Ruleset::route`] — so its decisions are identical to evaluating the rules
//! first-match-wins, with the same Hysteria-precedes-Clash ordering as before.

use std::{net::IpAddr, sync::Arc};

use tracing::Instrument as _;
use wind_base::resolve::resolve_target;
use wind_core::{
	RouteAction, Router, is_private_ip,
	resolve::Resolver,
	rule::{InboundType, MatchContext, NetworkType, Rule},
	types::TargetAddr,
};

use crate::{
	Ruleset,
	acl::{self, AclRule},
	compile,
};

/// Loopback / private-range guards applied *before* rule evaluation.
///
/// When any guard is enabled the engine resolves the destination to an IP and
/// rejects connections to loopback / private space. Building an engine with a
/// guard enabled but no resolver is an error.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct GuardConfig {
	/// Reject destinations that resolve to a loopback address (`127.0.0.0/8`,
	/// `::1`).
	pub drop_loopback: bool,
	/// Reject destinations that resolve to RFC1918 / link-local / ULA space.
	pub drop_private: bool,
}

impl GuardConfig {
	#[inline]
	fn enabled(&self) -> bool {
		self.drop_loopback || self.drop_private
	}
}

/// A protocol-agnostic ACL / routing engine backed by the [`Ruleset`] IR.
///
/// Construct one via [`AclEngine::builder`]. It implements [`Router`], so it
/// can be handed directly to [`wind_core::Dispatcher::new`] or
/// [`wind_core::App::set_router`].
pub struct AclEngine {
	/// Compiled IR. Hysteria-converted rules precede Clash rules in the source
	/// order, so first-match-wins keeps the historical precedence.
	ruleset: Ruleset,
	guards: GuardConfig,
	/// Required whenever `guards.enabled()`. Validated at build time.
	resolver: Option<Arc<dyn Resolver>>,
	inbound_name: Option<String>,
	inbound_type: Option<InboundType>,
}

impl AclEngine {
	/// Start building an engine that falls back to `default_outbound` when no
	/// rule matches.
	pub fn builder(default_outbound: impl Into<String>) -> AclEngineBuilder {
		AclEngineBuilder {
			default_outbound: default_outbound.into(),
			hysteria: Vec::new(),
			clash: Vec::new(),
			guards: GuardConfig::default(),
			resolver: None,
			inbound_name: None,
			inbound_type: None,
			hijack_seen: false,
		}
	}

	async fn do_route(&self, target: &TargetAddr, is_tcp: bool) -> eyre::Result<RouteAction> {
		// 1. Guards — resolve the destination and drop loopback / private space.
		if self.guards.enabled() {
			let resolver = self
				.resolver
				.as_ref()
				.expect("guards enabled without a resolver (should be rejected at build time)");
			let resolved = resolve_target(target, resolver.as_ref()).await?;
			if self.guards.drop_loopback && resolved.ip().is_loopback() {
				tracing::debug!(resolved = %resolved, "dropping loopback connection");
				return Ok(RouteAction::Reject(format!("loopback address rejected: {resolved}")));
			}
			if self.guards.drop_private && is_private_ip(&resolved.ip()) {
				tracing::debug!(resolved = %resolved, "dropping private-range connection");
				return Ok(RouteAction::Reject(format!("private address rejected: {resolved}")));
			}
		}

		// 2. Build the match context from what `route` can see. `src_ip` and
		// `inbound_user` are intentionally left `None` — the route signature
		// carries neither.
		let (domain, dst_ip, port) = match target {
			TargetAddr::Domain(d, p) => (Some(d.as_str()), None, *p),
			TargetAddr::IPv4(ip, p) => (None, Some(IpAddr::V4(*ip)), *p),
			TargetAddr::IPv6(ip, p) => (None, Some(IpAddr::V6(*ip)), *p),
		};
		let ctx = MatchContext {
			domain,
			dst_ip,
			dst_port: Some(port),
			network: Some(if is_tcp { NetworkType::Tcp } else { NetworkType::Udp }),
			inbound_name: self.inbound_name.as_deref(),
			inbound_type: self.inbound_type,
			..Default::default()
		};

		// 3. The IR evaluates first-match-wins and falls back to the default
		// outbound policy. It is infallible.
		Ok(self.ruleset.route(&ctx))
	}
}

impl Router for AclEngine {
	async fn route(&self, target: &TargetAddr, is_tcp: bool) -> eyre::Result<RouteAction> {
		let span = tracing::debug_span!("acl_route", target = %target, proto = if is_tcp { "tcp" } else { "udp" });
		self.do_route(target, is_tcp).instrument(span).await
	}
}

/// Builder for [`AclEngine`]. See [`AclEngine::builder`].
pub struct AclEngineBuilder {
	default_outbound: String,
	hysteria: Vec<Rule>,
	clash: Vec<Rule>,
	guards: GuardConfig,
	resolver: Option<Arc<dyn Resolver>>,
	inbound_name: Option<String>,
	inbound_type: Option<InboundType>,
	hijack_seen: bool,
}

impl AclEngineBuilder {
	/// Add Clash / Mihomo rule lines (e.g. `DOMAIN-SUFFIX,google.com,proxy`).
	///
	/// Returns an error identifying the first invalid line.
	pub fn clash_rules<I, S>(mut self, rules: I) -> eyre::Result<Self>
	where
		I: IntoIterator<Item = S>,
		S: AsRef<str>,
	{
		let lines: Vec<String> = rules.into_iter().map(|s| s.as_ref().to_string()).collect();
		for (idx, parsed) in Rule::parse_rules(&lines.join("\n")).into_iter().enumerate() {
			match parsed {
				Ok(rule) => self.clash.push(rule),
				Err(e) => {
					let rule = lines.get(idx).map(String::as_str).unwrap_or("<unknown>");
					eyre::bail!("invalid clash rule #{} ({rule:?}): {e}", idx + 1);
				}
			}
		}
		Ok(self)
	}

	/// Add already-parsed Hysteria-style ACL rules, compiled to Clash rules via
	/// [`acl::acl_to_rules`].
	pub fn hysteria_acl(mut self, acl: &[AclRule]) -> Self {
		if acl.iter().any(|r| r.hijack.is_some()) {
			self.hijack_seen = true;
		}
		self.hysteria.extend(acl::acl_to_rules(acl));
		self
	}

	/// Parse and add Hysteria-style ACL rules from a multiline string
	/// (`proxy 10.6.0.0/16 tcp/443` per line; `#` comments and blanks skipped).
	pub fn hysteria_acl_str(self, input: &str) -> eyre::Result<Self> {
		let rules = acl::parse_multiline_acl_string(input)?;
		Ok(self.hysteria_acl(&rules))
	}

	/// Enable loopback / private-range guards. Requires [`Self::resolver`].
	pub fn guards(mut self, guards: GuardConfig) -> Self {
		self.guards = guards;
		self
	}

	/// Set the resolver used by guards (and, in future, by IP-based rules on
	/// domain targets).
	pub fn resolver(mut self, resolver: Arc<dyn Resolver>) -> Self {
		self.resolver = Some(resolver);
		self
	}

	/// Provide a static inbound name so `IN-NAME` rules can match.
	pub fn inbound_name(mut self, name: impl Into<String>) -> Self {
		self.inbound_name = Some(name.into());
		self
	}

	/// Provide the static inbound type so `IN-TYPE` rules can match. Only set
	/// this for inbounds that are genuinely SOCKS or HTTP.
	pub fn inbound_type(mut self, ty: InboundType) -> Self {
		self.inbound_type = Some(ty);
		self
	}

	/// Finalize the engine. Errors if a guard is enabled without a resolver.
	pub fn build(self) -> eyre::Result<AclEngine> {
		if self.guards.enabled() && self.resolver.is_none() {
			eyre::bail!("loopback/private guards are enabled but no resolver was provided");
		}
		if self.hijack_seen {
			tracing::warn!("ACL hijack/redirect targets are parsed but not yet honored; they will be ignored");
		}
		let hysteria_count = self.hysteria.len();
		if hysteria_count > 0 {
			tracing::info!("[acl] compiled {hysteria_count} Hysteria-style ACL rule(s) to Metacubex format");
		}

		// Hysteria-converted rules take precedence over explicit Clash rules,
		// matching the historical ordering. The IR embedding preserves source
		// order, and the optimizer preserves first-match-wins semantics.
		let all: Vec<Rule> = self.hysteria.into_iter().chain(self.clash).collect();
		let ruleset = compile(Ruleset::from_rules(all, self.default_outbound));

		Ok(AclEngine {
			ruleset,
			guards: self.guards,
			resolver: self.resolver,
			inbound_name: self.inbound_name,
			inbound_type: self.inbound_type,
		})
	}
}

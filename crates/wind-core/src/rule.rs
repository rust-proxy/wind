//! Metacubex-style routing rule engine.
//!
//! Provides rule-based routing decisions compatible with Clash/Mihomo rule
//! syntax.  Rules are evaluated in order; the first matching rule wins.
//!
//! # Supported Rule Types
//!
//! ## Domain Rules
//! - `DOMAIN` — exact domain match
//! - `DOMAIN-SUFFIX` — domain suffix match (includes subdomains)
//! - `DOMAIN-KEYWORD` — domain contains keyword
//! - `DOMAIN-WILDCARD` — wildcard pattern matching
//! - `DOMAIN-REGEX` — regular expression matching
//! - `GEOSITE` — GeoSite database matching
//!
//! ## IP Rules
//! - `IP-CIDR` — IPv4/IPv6 CIDR matching
//! - `IP-CIDR6` — IPv6 CIDR matching
//! - `IP-SUFFIX` — IP network suffix matching
//! - `IP-ASN` — Autonomous System Number matching
//! - `GEOIP` — GeoIP country code matching
//!
//! ## Source IP Rules
//! - `SRC-GEOIP` — source IP GeoIP matching
//! - `SRC-IP-ASN` — source IP ASN matching
//! - `SRC-IP-CIDR` — source IP CIDR matching
//! - `SRC-IP-SUFFIX` — source IP suffix matching
//!
//! ## Port Rules
//! - `DST-PORT` — destination port matching
//! - `SRC-PORT` — source port matching
//!
//! ## Inbound Rules
//! - `IN-PORT` — inbound port matching
//! - `IN-TYPE` — inbound type (SOCKS/HTTP)
//! - `IN-USER` — inbound user matching
//! - `IN-NAME` — inbound name matching
//!
//! ## Process Rules
//! - `PROCESS-PATH` — process path matching
//! - `PROCESS-PATH-REGEX` — process path regex matching
//! - `PROCESS-NAME` — process name matching
//! - `PROCESS-NAME-REGEX` — process name regex matching
//! - `UID` — user ID matching
//!
//! ## Network Rules
//! - `NETWORK` — network type (tcp/udp)
//! - `DSCP` — DSCP value matching
//!
//! ## Advanced Rules
//! - `RULE-SET` — external rule set reference (placeholder)
//! - `AND` — logical AND of multiple rules
//! - `OR` — logical OR of multiple rules
//! - `NOT` — logical NOT of a rule
//! - `SUB-RULE` — sub-rule reference (placeholder)
//! - `MATCH` — match all (default rule)
//!
//! # Usage
//!
//! ```ignore
//! use wind_core::rule::{Rule, MatchContext, NetworkType};
//!
//! let rules: Vec<Rule> = Rule::parse_rules(r#"
//!     DOMAIN-SUFFIX,google.com,proxy
//!     IP-CIDR,127.0.0.0/8,direct,no-resolve
//!     MATCH,proxy
//! "#).into_iter().filter_map(Result::ok).collect();
//!
//! let ctx = MatchContext {
//!     domain: Some("www.google.com"),
//!     dst_port: Some(443),
//!     network: Some(NetworkType::Tcp),
//!     ..Default::default()
//! };
//!
//! for rule in &rules {
//!     if rule.matches(&ctx) {
//!         println!("target: {}", rule.target);
//!         break;
//!     }
//! }
//! ```

use std::{fmt, net::IpAddr};

use ipnet::{IpNet, Ipv6Net};
use regex::Regex;

// ============================================================================
// Core types
// ============================================================================

/// Network protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
	Tcp,
	Udp,
}

/// Inbound connection type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundType {
	Socks,
	Http,
	/// Matches both SOCKS and HTTP.
	SocksOrHttp,
}

/// A single routing rule: type + target + options.
///
/// Rules follow the format `RULE_TYPE,VALUE,TARGET[,OPTIONS...]`.
/// The special type `MATCH` uses `MATCH,TARGET`.
pub struct Rule {
	/// The rule type and its match parameters.
	pub rule_type: RuleType,
	/// The outbound target (e.g. `"DIRECT"`, `"PROXY"`, `"REJECT"`, or a
	/// named outbound).
	pub target: String,
	/// Extra options such as `"no-resolve"`.
	pub options: Vec<String>,
}

/// All supported rule types.
pub enum RuleType {
	// -- Domain rules --
	/// Exact domain match (case-insensitive).
	Domain(String),
	/// Domain suffix match — also matches subdomains.
	DomainSuffix(String),
	/// Domain contains keyword (case-insensitive).
	DomainKeyword(String),
	/// Wildcard domain (`*` and `?`).
	DomainWildcard(String),
	/// Domain matched by regex.
	DomainRegex(Regex),
	/// GeoSite database match — requires external lookup.
	GeoSite(String),

	// -- IP rules (destination) --
	/// IPv4/IPv6 CIDR match on destination IP.
	IpCidr(IpNet),
	/// IPv6-only CIDR match on destination IP.
	IpCidr6(Ipv6Net),
	/// IP network suffix match on destination IP.
	IpSuffix(IpNet),
	/// Autonomous System Number match on destination IP.
	IpAsn(u32),
	/// GeoIP country code match on destination IP.
	GeoIp(String),

	// -- IP rules (source) --
	/// GeoIP match on source IP.
	SrcGeoIp(String),
	/// ASN match on source IP.
	SrcIpAsn(u32),
	/// CIDR match on source IP.
	SrcIpCidr(IpNet),
	/// IP network suffix match on source IP.
	SrcIpSuffix(IpNet),

	// -- Port rules --
	/// Destination port match.
	DstPort(u16),
	/// Destination port range match (inclusive).
	DstPortRange(u16, u16),
	/// Source port match.
	SrcPort(u16),
	/// Source port range match (inclusive).
	SrcPortRange(u16, u16),

	// -- Inbound rules --
	/// Inbound listening port.
	InPort(u16),
	/// Inbound type (SOCKS / HTTP).
	InType(InboundType),
	/// Inbound authenticated user name.
	InUser(String),
	/// Inbound name identifier.
	InName(String),

	// -- Process rules --
	/// Exact process executable path.
	ProcessPath(String),
	/// Process path matched by regex.
	ProcessPathRegex(Regex),
	/// Exact process name.
	ProcessName(String),
	/// Process name matched by regex.
	ProcessNameRegex(Regex),
	/// Unix UID.
	Uid(u32),

	// -- Network rules --
	/// Network protocol match (TCP / UDP).
	Network(NetworkType),
	/// DSCP value match.
	Dscp(u8),

	// -- Advanced rules --
	/// External rule set reference (placeholder — always `false`).
	RuleSet(String),
	/// Logical AND of sub-rules.
	And(Vec<Rule>),
	/// Logical OR of sub-rules.
	Or(Vec<Rule>),
	/// Logical NOT of a sub-rule.
	Not(Box<Rule>),
	/// Sub-rule reference (placeholder — delegates to contained rule).
	SubRule(Box<Rule>, String),

	// -- Catch-all --
	/// Matches every connection.
	Match,
}

// ============================================================================
// MatchContext
// ============================================================================

/// Context supplied to [`Rule::matches`].
///
/// Fill in the fields that are known; unknown fields should be `None` (the
/// default).
pub struct MatchContext<'a> {
	// -- Connection info --
	pub src_ip: Option<IpAddr>,
	pub dst_ip: Option<IpAddr>,
	pub src_port: Option<u16>,
	pub dst_port: Option<u16>,
	pub domain: Option<&'a str>,

	// -- Network info --
	pub network: Option<NetworkType>,
	pub dscp: Option<u8>,

	// -- Inbound info --
	pub inbound_port: Option<u16>,
	pub inbound_type: Option<InboundType>,
	pub inbound_user: Option<&'a str>,
	pub inbound_name: Option<&'a str>,

	// -- Process info --
	pub process_path: Option<&'a str>,
	pub process_name: Option<&'a str>,
	pub uid: Option<u32>,

	// -- External lookup functions (provided by caller) --
	pub geoip_lookup: Option<&'a dyn Fn(&str, IpAddr) -> bool>,
	pub asn_lookup: Option<&'a dyn Fn(u32, IpAddr) -> bool>,
	pub geosite_lookup: Option<&'a dyn Fn(&str, &str) -> bool>,
}

// Manual impls because the function-pointer fields prevent derive.

impl<'a> Default for MatchContext<'a> {
	fn default() -> Self {
		Self {
			src_ip: None,
			dst_ip: None,
			src_port: None,
			dst_port: None,
			domain: None,
			network: None,
			dscp: None,
			inbound_port: None,
			inbound_type: None,
			inbound_user: None,
			inbound_name: None,
			process_path: None,
			process_name: None,
			uid: None,
			geoip_lookup: None,
			asn_lookup: None,
			geosite_lookup: None,
		}
	}
}

impl<'a> Clone for MatchContext<'a> {
	fn clone(&self) -> Self {
		Self {
			src_ip: self.src_ip,
			dst_ip: self.dst_ip,
			src_port: self.src_port,
			dst_port: self.dst_port,
			domain: self.domain,
			network: self.network,
			dscp: self.dscp,
			inbound_port: self.inbound_port,
			inbound_type: self.inbound_type,
			inbound_user: self.inbound_user,
			inbound_name: self.inbound_name,
			process_path: self.process_path,
			process_name: self.process_name,
			uid: self.uid,
			geoip_lookup: self.geoip_lookup,
			asn_lookup: self.asn_lookup,
			geosite_lookup: self.geosite_lookup,
		}
	}
}

impl fmt::Debug for MatchContext<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("MatchContext")
			.field("src_ip", &self.src_ip)
			.field("dst_ip", &self.dst_ip)
			.field("src_port", &self.src_port)
			.field("dst_port", &self.dst_port)
			.field("domain", &self.domain)
			.field("network", &self.network)
			.field("dscp", &self.dscp)
			.field("inbound_port", &self.inbound_port)
			.field("inbound_type", &self.inbound_type)
			.field("inbound_user", &self.inbound_user)
			.field("inbound_name", &self.inbound_name)
			.field("process_path", &self.process_path)
			.field("process_name", &self.process_name)
			.field("uid", &self.uid)
			.field("geoip_lookup", &self.geoip_lookup.is_some())
			.field("asn_lookup", &self.asn_lookup.is_some())
			.field("geosite_lookup", &self.geosite_lookup.is_some())
			.finish()
	}
}

// ============================================================================
// Matching
// ============================================================================

impl Rule {
	/// Returns `true` if this rule matches the given context.
	pub fn matches(&self, ctx: &MatchContext) -> bool {
		match &self.rule_type {
			// -- Domain --
			RuleType::Domain(d) => ctx.domain.is_some_and(|h| h.eq_ignore_ascii_case(d)),

			RuleType::DomainSuffix(suffix) => ctx.domain.is_some_and(|h| {
				h.eq_ignore_ascii_case(suffix) || h.to_ascii_lowercase().ends_with(&format!(".{}", suffix.to_ascii_lowercase()))
			}),

			RuleType::DomainKeyword(kw) => ctx
				.domain
				.is_some_and(|h| h.to_ascii_lowercase().contains(&kw.to_ascii_lowercase())),

			RuleType::DomainWildcard(pattern) => ctx.domain.is_some_and(|h| wildcard_match(pattern, h)),

			RuleType::DomainRegex(re) => ctx.domain.is_some_and(|h| re.is_match(h)),

			RuleType::GeoSite(site) => ctx
				.domain
				.and_then(|d| ctx.geosite_lookup.map(|f| f(site, d)))
				.unwrap_or(false),

			// -- IP (destination) --
			RuleType::IpCidr(net) => ctx.dst_ip.is_some_and(|ip| net.contains(&ip)),

			RuleType::IpCidr6(net) => ctx.dst_ip.is_some_and(|ip| match ip {
				IpAddr::V6(v6) => net.contains(&v6),
				_ => false,
			}),

			RuleType::IpSuffix(net) => ctx.dst_ip.is_some_and(|ip| net.contains(&ip)),

			RuleType::IpAsn(asn) => ctx.dst_ip.and_then(|ip| ctx.asn_lookup.map(|f| f(*asn, ip))).unwrap_or(false),

			RuleType::GeoIp(country) => ctx
				.dst_ip
				.and_then(|ip| ctx.geoip_lookup.map(|f| f(country, ip)))
				.unwrap_or(false),

			// -- IP (source) --
			RuleType::SrcGeoIp(country) => ctx
				.src_ip
				.and_then(|ip| ctx.geoip_lookup.map(|f| f(country, ip)))
				.unwrap_or(false),

			RuleType::SrcIpAsn(asn) => ctx.src_ip.and_then(|ip| ctx.asn_lookup.map(|f| f(*asn, ip))).unwrap_or(false),

			RuleType::SrcIpCidr(net) => ctx.src_ip.is_some_and(|ip| net.contains(&ip)),

			RuleType::SrcIpSuffix(net) => ctx.src_ip.is_some_and(|ip| net.contains(&ip)),

			// -- Port --
			RuleType::DstPort(p) => ctx.dst_port.is_some_and(|dp| dp == *p),
			RuleType::DstPortRange(lo, hi) => ctx.dst_port.is_some_and(|dp| dp >= *lo && dp <= *hi),
			RuleType::SrcPort(p) => ctx.src_port.is_some_and(|sp| sp == *p),
			RuleType::SrcPortRange(lo, hi) => ctx.src_port.is_some_and(|sp| sp >= *lo && sp <= *hi),

			// -- Inbound --
			RuleType::InPort(p) => ctx.inbound_port.is_some_and(|ip| ip == *p),

			RuleType::InType(in_type) => ctx.inbound_type.is_some_and(|t| match in_type {
				InboundType::SocksOrHttp => t == InboundType::Socks || t == InboundType::Http,
				_ => t == *in_type,
			}),

			RuleType::InUser(user) => ctx.inbound_user.is_some_and(|u| u == user),
			RuleType::InName(name) => ctx.inbound_name.is_some_and(|n| n == name),

			// -- Process --
			RuleType::ProcessPath(path) => ctx.process_path.is_some_and(|p| p == path),
			RuleType::ProcessPathRegex(re) => ctx.process_path.is_some_and(|p| re.is_match(p)),
			RuleType::ProcessName(name) => ctx.process_name.is_some_and(|n| n == name),
			RuleType::ProcessNameRegex(re) => ctx.process_name.is_some_and(|n| re.is_match(n)),
			RuleType::Uid(uid) => ctx.uid.is_some_and(|u| u == *uid),

			// -- Network --
			RuleType::Network(n) => ctx.network.is_some_and(|nn| nn == *n),
			RuleType::Dscp(d) => ctx.dscp.is_some_and(|dd| dd == *d),

			// -- Advanced --
			RuleType::RuleSet(_) => false, // placeholder
			RuleType::And(rules) => rules.iter().all(|r| r.matches(ctx)),
			RuleType::Or(rules) => rules.iter().any(|r| r.matches(ctx)),
			RuleType::Not(rule) => !rule.matches(ctx),
			RuleType::SubRule(rule, _) => rule.matches(ctx), // placeholder

			// -- Catch-all --
			RuleType::Match => true,
		}
	}

	/// Returns `true` if the rule carries the `no-resolve` option.
	pub fn no_resolve(&self) -> bool {
		self.options.iter().any(|o| o.eq_ignore_ascii_case("no-resolve"))
	}
}

// ============================================================================
// Parsing
// ============================================================================

/// Errors that can occur while parsing a rule string.
#[derive(Debug, Clone, PartialEq)]
pub enum RuleParseError {
	EmptyOrComment,
	InvalidFormat(String),
	UnknownRuleType(String),
	InvalidRegex(String),
	InvalidIpCidr(String),
	InvalidNumber(String),
	InvalidInboundType(String),
	InvalidNetworkType(String),
}

impl fmt::Display for RuleParseError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::EmptyOrComment => write!(f, "empty line or comment"),
			Self::InvalidFormat(s) => write!(f, "invalid format: {s}"),
			Self::UnknownRuleType(s) => write!(f, "unknown rule type: {s}"),
			Self::InvalidRegex(s) => write!(f, "invalid regex: {s}"),
			Self::InvalidIpCidr(s) => write!(f, "invalid IP/CIDR: {s}"),
			Self::InvalidNumber(s) => write!(f, "invalid number: {s}"),
			Self::InvalidInboundType(s) => write!(f, "invalid inbound type: {s}"),
			Self::InvalidNetworkType(s) => write!(f, "invalid network type: {s}"),
		}
	}
}

impl std::error::Error for RuleParseError {}

impl Rule {
	/// Parse one rule from a line such as `DOMAIN-SUFFIX,google.com,PROXY`.
	pub fn parse(line: &str) -> Result<Self, RuleParseError> {
		let line = line.trim();
		if line.is_empty() || line.starts_with('#') {
			return Err(RuleParseError::EmptyOrComment);
		}

		// Split respecting parenthesised groups (for AND/OR/NOT compound rules).
		let parts = split_top_level(line);
		if parts.len() < 2 {
			return Err(RuleParseError::InvalidFormat(
				"rule must have at least type and target".into(),
			));
		}

		let type_str = parts[0].trim();

		// MATCH has no value field: MATCH,TARGET
		if type_str.eq_ignore_ascii_case("MATCH") {
			return Ok(Self {
				rule_type: RuleType::Match,
				target: parts[1].trim().to_string(),
				options: parts[2..].iter().map(|s| s.trim().to_string()).collect(),
			});
		}

		// All other rules: TYPE,VALUE,TARGET[,OPTIONS...]
		if parts.len() < 3 {
			return Err(RuleParseError::InvalidFormat(format!(
				"rule type '{type_str}' requires value and target"
			)));
		}

		let value = parts[1].trim();
		let target = parts[2].trim().to_string();
		let options: Vec<String> = parts[3..].iter().map(|s| s.trim().to_string()).collect();
		let rule_type = Self::parse_type(type_str, value)?;

		Ok(Self {
			rule_type,
			target,
			options,
		})
	}

	fn parse_type(type_str: &str, value: &str) -> Result<RuleType, RuleParseError> {
		match type_str.to_ascii_uppercase().as_str() {
			// Domain rules
			"DOMAIN" => Ok(RuleType::Domain(value.to_string())),
			"DOMAIN-SUFFIX" => Ok(RuleType::DomainSuffix(value.to_string())),
			"DOMAIN-KEYWORD" => Ok(RuleType::DomainKeyword(value.to_string())),
			"DOMAIN-WILDCARD" => Ok(RuleType::DomainWildcard(value.to_string())),
			"DOMAIN-REGEX" => {
				let re = Regex::new(value).map_err(|e| RuleParseError::InvalidRegex(e.to_string()))?;
				Ok(RuleType::DomainRegex(re))
			}
			"GEOSITE" => Ok(RuleType::GeoSite(value.to_string())),

			// IP rules (destination)
			"IP-CIDR" => {
				let net = value
					.parse::<IpNet>()
					.map_err(|e| RuleParseError::InvalidIpCidr(e.to_string()))?;
				Ok(RuleType::IpCidr(net))
			}
			"IP-CIDR6" => {
				let net = value
					.parse::<Ipv6Net>()
					.map_err(|e| RuleParseError::InvalidIpCidr(e.to_string()))?;
				Ok(RuleType::IpCidr6(net))
			}
			"IP-SUFFIX" => {
				let net = value
					.parse::<IpNet>()
					.map_err(|e| RuleParseError::InvalidIpCidr(e.to_string()))?;
				Ok(RuleType::IpSuffix(net))
			}
			"IP-ASN" => {
				let asn = value
					.parse::<u32>()
					.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
				Ok(RuleType::IpAsn(asn))
			}
			"GEOIP" => Ok(RuleType::GeoIp(value.to_string())),

			// Source IP rules
			"SRC-GEOIP" => Ok(RuleType::SrcGeoIp(value.to_string())),
			"SRC-IP-ASN" => {
				let asn = value
					.parse::<u32>()
					.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
				Ok(RuleType::SrcIpAsn(asn))
			}
			"SRC-IP-CIDR" => {
				let net = value
					.parse::<IpNet>()
					.map_err(|e| RuleParseError::InvalidIpCidr(e.to_string()))?;
				Ok(RuleType::SrcIpCidr(net))
			}
			"SRC-IP-SUFFIX" => {
				let net = value
					.parse::<IpNet>()
					.map_err(|e| RuleParseError::InvalidIpCidr(e.to_string()))?;
				Ok(RuleType::SrcIpSuffix(net))
			}

			// Port rules
			"DST-PORT" => Self::parse_port_or_range(value, false),
			"SRC-PORT" => Self::parse_port_or_range(value, true),

			// Inbound rules
			"IN-PORT" => {
				let port = value
					.parse::<u16>()
					.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
				Ok(RuleType::InPort(port))
			}
			"IN-TYPE" => {
				let in_type = match value.to_ascii_uppercase().as_str() {
					"SOCKS" => InboundType::Socks,
					"HTTP" => InboundType::Http,
					"SOCKS/HTTP" => InboundType::SocksOrHttp,
					_ => return Err(RuleParseError::InvalidInboundType(value.to_string())),
				};
				Ok(RuleType::InType(in_type))
			}
			"IN-USER" => Ok(RuleType::InUser(value.to_string())),
			"IN-NAME" => Ok(RuleType::InName(value.to_string())),

			// Process rules
			"PROCESS-PATH" => Ok(RuleType::ProcessPath(value.to_string())),
			"PROCESS-PATH-REGEX" => {
				let re = Regex::new(value).map_err(|e| RuleParseError::InvalidRegex(e.to_string()))?;
				Ok(RuleType::ProcessPathRegex(re))
			}
			"PROCESS-NAME" => Ok(RuleType::ProcessName(value.to_string())),
			"PROCESS-NAME-REGEX" => {
				let re = Regex::new(value).map_err(|e| RuleParseError::InvalidRegex(e.to_string()))?;
				Ok(RuleType::ProcessNameRegex(re))
			}
			"UID" => {
				let uid = value
					.parse::<u32>()
					.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
				Ok(RuleType::Uid(uid))
			}

			// Network rules
			"NETWORK" => match value.to_ascii_lowercase().as_str() {
				"tcp" => Ok(RuleType::Network(NetworkType::Tcp)),
				"udp" => Ok(RuleType::Network(NetworkType::Udp)),
				_ => Err(RuleParseError::InvalidNetworkType(value.to_string())),
			},
			"DSCP" => {
				let dscp = value
					.parse::<u8>()
					.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
				Ok(RuleType::Dscp(dscp))
			}

			// Advanced rules
			"RULE-SET" => Ok(RuleType::RuleSet(value.to_string())),
			"AND" => {
				let sub = Self::parse_compound(value)?;
				Ok(RuleType::And(sub))
			}
			"OR" => {
				let sub = Self::parse_compound(value)?;
				Ok(RuleType::Or(sub))
			}
			"NOT" => {
				let sub = Self::parse_compound(value)?;
				if sub.len() != 1 {
					return Err(RuleParseError::InvalidFormat(
						"NOT rule must contain exactly one sub-rule".into(),
					));
				}
				Ok(RuleType::Not(Box::new(sub.into_iter().next().unwrap())))
			}
			"SUB-RULE" => {
				let sub = Self::parse_compound(value)?;
				if sub.is_empty() {
					return Err(RuleParseError::InvalidFormat("SUB-RULE must contain a condition".into()));
				}
				Ok(RuleType::SubRule(Box::new(sub.into_iter().next().unwrap()), String::new()))
			}

			other => Err(RuleParseError::UnknownRuleType(other.to_string())),
		}
	}

	/// Parse a port value that may be a single port or a range (`start-end`).
	fn parse_port_or_range(value: &str, is_src: bool) -> Result<RuleType, RuleParseError> {
		if let Some((lo_s, hi_s)) = value.split_once('-') {
			let lo = lo_s
				.trim()
				.parse::<u16>()
				.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
			let hi = hi_s
				.trim()
				.parse::<u16>()
				.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
			if is_src {
				Ok(RuleType::SrcPortRange(lo, hi))
			} else {
				Ok(RuleType::DstPortRange(lo, hi))
			}
		} else {
			let port = value
				.parse::<u16>()
				.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
			if is_src {
				Ok(RuleType::SrcPort(port))
			} else {
				Ok(RuleType::DstPort(port))
			}
		}
	}

	/// Parse compound (nested) rules like `((DOMAIN,baidu.com),(NETWORK,UDP))`.
	fn parse_compound(value: &str) -> Result<Vec<Rule>, RuleParseError> {
		let value = value.trim();
		let content = value
			.strip_prefix('(')
			.and_then(|s| s.strip_suffix(')'))
			.ok_or_else(|| RuleParseError::InvalidFormat("compound rule must be wrapped in parentheses".into()))?;

		let mut rules = Vec::new();
		let mut depth = 0i32;
		let mut start = 0;

		for (i, ch) in content.char_indices() {
			match ch {
				'(' => depth += 1,
				')' => depth -= 1,
				',' if depth == 0 => {
					Self::push_compound_part(content, start, i, &mut rules)?;
					start = i + 1;
				}
				_ => {}
			}
		}
		Self::push_compound_part(content, start, content.len(), &mut rules)?;

		Ok(rules)
	}

	fn push_compound_part(content: &str, start: usize, end: usize, out: &mut Vec<Rule>) -> Result<(), RuleParseError> {
		let part = content[start..end].trim();
		if part.is_empty() {
			return Ok(());
		}
		let inner = part.strip_prefix('(').and_then(|s| s.strip_suffix(')')).unwrap_or(part);
		let rule_with_target = format!("{inner},TEMP");
		let mut rule = Rule::parse(&rule_with_target)?;
		rule.target = String::new();
		out.push(rule);
		Ok(())
	}

	/// Parse multiple rules from a multi-line string.  Comments (`#`) and
	/// blank lines are silently skipped.
	pub fn parse_rules(content: &str) -> Vec<Result<Self, RuleParseError>> {
		content
			.lines()
			.map(str::trim)
			.filter(|l| !l.is_empty() && !l.starts_with('#'))
			.map(Self::parse)
			.collect()
	}
}

// ============================================================================
// Display
// ============================================================================

impl fmt::Display for NetworkType {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Tcp => write!(f, "tcp"),
			Self::Udp => write!(f, "udp"),
		}
	}
}

impl fmt::Display for InboundType {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Socks => write!(f, "SOCKS"),
			Self::Http => write!(f, "HTTP"),
			Self::SocksOrHttp => write!(f, "SOCKS/HTTP"),
		}
	}
}

impl fmt::Display for RuleType {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Domain(v) => write!(f, "DOMAIN,{v}"),
			Self::DomainSuffix(v) => write!(f, "DOMAIN-SUFFIX,{v}"),
			Self::DomainKeyword(v) => write!(f, "DOMAIN-KEYWORD,{v}"),
			Self::DomainWildcard(v) => write!(f, "DOMAIN-WILDCARD,{v}"),
			Self::DomainRegex(v) => write!(f, "DOMAIN-REGEX,{v}"),
			Self::GeoSite(v) => write!(f, "GEOSITE,{v}"),
			Self::IpCidr(v) => write!(f, "IP-CIDR,{v}"),
			Self::IpCidr6(v) => write!(f, "IP-CIDR6,{v}"),
			Self::IpSuffix(v) => write!(f, "IP-SUFFIX,{v}"),
			Self::IpAsn(v) => write!(f, "IP-ASN,{v}"),
			Self::GeoIp(v) => write!(f, "GEOIP,{v}"),
			Self::SrcGeoIp(v) => write!(f, "SRC-GEOIP,{v}"),
			Self::SrcIpAsn(v) => write!(f, "SRC-IP-ASN,{v}"),
			Self::SrcIpCidr(v) => write!(f, "SRC-IP-CIDR,{v}"),
			Self::SrcIpSuffix(v) => write!(f, "SRC-IP-SUFFIX,{v}"),
			Self::DstPort(v) => write!(f, "DST-PORT,{v}"),
			Self::DstPortRange(lo, hi) => write!(f, "DST-PORT,{lo}-{hi}"),
			Self::SrcPort(v) => write!(f, "SRC-PORT,{v}"),
			Self::SrcPortRange(lo, hi) => write!(f, "SRC-PORT,{lo}-{hi}"),
			Self::InPort(v) => write!(f, "IN-PORT,{v}"),
			Self::InType(v) => write!(f, "IN-TYPE,{v}"),
			Self::InUser(v) => write!(f, "IN-USER,{v}"),
			Self::InName(v) => write!(f, "IN-NAME,{v}"),
			Self::ProcessPath(v) => write!(f, "PROCESS-PATH,{v}"),
			Self::ProcessPathRegex(v) => write!(f, "PROCESS-PATH-REGEX,{v}"),
			Self::ProcessName(v) => write!(f, "PROCESS-NAME,{v}"),
			Self::ProcessNameRegex(v) => write!(f, "PROCESS-NAME-REGEX,{v}"),
			Self::Uid(v) => write!(f, "UID,{v}"),
			Self::Network(v) => write!(f, "NETWORK,{v}"),
			Self::Dscp(v) => write!(f, "DSCP,{v}"),
			Self::RuleSet(v) => write!(f, "RULE-SET,{v}"),
			Self::And(rules) => {
				write!(f, "AND,(")?;
				for (i, r) in rules.iter().enumerate() {
					if i > 0 {
						write!(f, ",")?;
					}
					write!(f, "({})", r.rule_type)?;
				}
				write!(f, ")")
			}
			Self::Or(rules) => {
				write!(f, "OR,(")?;
				for (i, r) in rules.iter().enumerate() {
					if i > 0 {
						write!(f, ",")?;
					}
					write!(f, "({})", r.rule_type)?;
				}
				write!(f, ")")
			}
			Self::Not(rule) => write!(f, "NOT,(({}))", rule.rule_type),
			Self::SubRule(rule, name) => write!(f, "SUB-RULE,(({}))),{name}", rule.rule_type),
			Self::Match => write!(f, "MATCH"),
		}
	}
}

impl fmt::Display for Rule {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.rule_type)?;
		if !self.target.is_empty() {
			write!(f, ",{}", self.target)?;
		}
		for opt in &self.options {
			write!(f, ",{opt}")?;
		}
		Ok(())
	}
}

impl fmt::Debug for Rule {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Rule({})", self)
	}
}

impl fmt::Debug for RuleType {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self)
	}
}

// ============================================================================
// Helpers
// ============================================================================

/// Simple wildcard matching (`*` = any chars, `?` = one char).
/// Case-insensitive.
fn wildcard_match(pattern: &str, text: &str) -> bool {
	let pattern = pattern.to_ascii_lowercase();
	let text = text.to_ascii_lowercase();

	let mut re = String::from("^");
	for ch in pattern.chars() {
		match ch {
			'*' => re.push_str(".*"),
			'?' => re.push('.'),
			c if c.is_ascii_punctuation() => {
				re.push('\\');
				re.push(c);
			}
			c => re.push(c),
		}
	}
	re.push('$');

	Regex::new(&re).is_ok_and(|r| r.is_match(&text))
}

/// Split a rule line on commas, but treat parenthesised groups as a single
/// token.
///
/// e.g. `AND,((NETWORK,tcp),(DST-PORT,443)),PROXY` → `["AND",
/// "((NETWORK,tcp),(DST-PORT,443))", "PROXY"]`
fn split_top_level(s: &str) -> Vec<String> {
	let mut parts = Vec::new();
	let mut depth = 0i32;
	let mut start = 0;

	for (i, ch) in s.char_indices() {
		match ch {
			'(' => depth += 1,
			')' => depth -= 1,
			',' if depth == 0 => {
				parts.push(s[start..i].to_string());
				start = i + 1;
			}
			_ => {}
		}
	}
	parts.push(s[start..].to_string());
	parts
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	// -- Domain rules --

	#[test]
	fn parse_domain_exact() {
		let rule = Rule::parse("DOMAIN,example.com,REJECT").unwrap();
		assert_eq!(rule.target, "REJECT");

		let yes = MatchContext {
			domain: Some("example.com"),
			..Default::default()
		};
		let no = MatchContext {
			domain: Some("sub.example.com"),
			..Default::default()
		};
		assert!(rule.matches(&yes));
		assert!(!rule.matches(&no));
	}

	#[test]
	fn parse_domain_suffix() {
		let rule = Rule::parse("DOMAIN-SUFFIX,google.com,PROXY").unwrap();
		assert_eq!(rule.target, "PROXY");

		assert!(rule.matches(&MatchContext {
			domain: Some("www.google.com"),
			..Default::default()
		}));
		assert!(rule.matches(&MatchContext {
			domain: Some("google.com"),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			domain: Some("notgoogle.com"),
			..Default::default()
		}));
	}

	#[test]
	fn parse_domain_keyword() {
		let rule = Rule::parse("DOMAIN-KEYWORD,ads,REJECT").unwrap();
		assert!(rule.matches(&MatchContext {
			domain: Some("ads.example.com"),
			..Default::default()
		}));
		assert!(rule.matches(&MatchContext {
			domain: Some("example-ads.net"),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			domain: Some("example.com"),
			..Default::default()
		}));
	}

	#[test]
	fn parse_domain_wildcard() {
		let rule = Rule::parse("DOMAIN-WILDCARD,*.ad.com,REJECT").unwrap();
		assert!(rule.matches(&MatchContext {
			domain: Some("foo.ad.com"),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			domain: Some("ad.com"),
			..Default::default()
		}));
	}

	#[test]
	fn parse_domain_regex() {
		let rule = Rule::parse("DOMAIN-REGEX,^ad\\.,REJECT").unwrap();
		assert!(rule.matches(&MatchContext {
			domain: Some("ad.example.com"),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			domain: Some("example.ad.com"),
			..Default::default()
		}));
	}

	#[test]
	fn parse_geosite() {
		let rule = Rule::parse("GEOSITE,cn,DIRECT").unwrap();
		assert_eq!(rule.target, "DIRECT");
		assert!(matches!(rule.rule_type, RuleType::GeoSite(ref s) if s == "cn"));

		// Without a lookup function — should not match.
		assert!(!rule.matches(&MatchContext {
			domain: Some("baidu.com"),
			..Default::default()
		}));

		// With a lookup function.
		let lookup = |_code: &str, _domain: &str| true;
		let ctx = MatchContext {
			domain: Some("baidu.com"),
			geosite_lookup: Some(&lookup),
			..Default::default()
		};
		assert!(rule.matches(&ctx));
	}

	// -- IP rules --

	#[test]
	fn parse_ip_cidr() {
		let rule = Rule::parse("IP-CIDR,192.168.0.0/16,DIRECT").unwrap();
		assert!(rule.matches(&MatchContext {
			dst_ip: Some("192.168.1.1".parse().unwrap()),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			dst_ip: Some("10.0.0.1".parse().unwrap()),
			..Default::default()
		}));
	}

	#[test]
	fn parse_ip_cidr6() {
		let rule = Rule::parse("IP-CIDR6,fc00::/7,DIRECT").unwrap();
		assert!(rule.matches(&MatchContext {
			dst_ip: Some("fd12::1".parse().unwrap()),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			dst_ip: Some("2001:db8::1".parse().unwrap()),
			..Default::default()
		}));
	}

	#[test]
	fn parse_ip_suffix() {
		let rule = Rule::parse("IP-SUFFIX,10.0.0.0/8,DIRECT").unwrap();
		assert!(rule.matches(&MatchContext {
			dst_ip: Some("10.1.2.3".parse().unwrap()),
			..Default::default()
		}));
	}

	#[test]
	fn parse_ip_asn() {
		let rule = Rule::parse("IP-ASN,13335,PROXY").unwrap();
		assert!(matches!(rule.rule_type, RuleType::IpAsn(13335)));

		// Without lookup — false.
		assert!(!rule.matches(&MatchContext {
			dst_ip: Some("1.1.1.1".parse().unwrap()),
			..Default::default()
		}));
	}

	#[test]
	fn parse_geoip() {
		let rule = Rule::parse("GEOIP,CN,DIRECT").unwrap();
		assert!(matches!(rule.rule_type, RuleType::GeoIp(ref s) if s == "CN"));
	}

	#[test]
	fn parse_src_ip_cidr() {
		let rule = Rule::parse("SRC-IP-CIDR,192.168.1.0/24,DIRECT").unwrap();
		assert!(rule.matches(&MatchContext {
			src_ip: Some("192.168.1.50".parse().unwrap()),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			src_ip: Some("10.0.0.1".parse().unwrap()),
			..Default::default()
		}));
	}

	// -- Port rules --

	#[test]
	fn parse_dst_port() {
		let rule = Rule::parse("DST-PORT,443,PROXY").unwrap();
		assert!(rule.matches(&MatchContext {
			dst_port: Some(443),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			dst_port: Some(80),
			..Default::default()
		}));
	}

	#[test]
	fn parse_src_port() {
		let rule = Rule::parse("SRC-PORT,12345,DIRECT").unwrap();
		assert!(rule.matches(&MatchContext {
			src_port: Some(12345),
			..Default::default()
		}));
	}

	// -- Inbound rules --

	#[test]
	fn parse_in_port() {
		let rule = Rule::parse("IN-PORT,1080,DIRECT").unwrap();
		assert!(rule.matches(&MatchContext {
			inbound_port: Some(1080),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			inbound_port: Some(8080),
			..Default::default()
		}));
	}

	#[test]
	fn parse_in_type() {
		let rule = Rule::parse("IN-TYPE,SOCKS,PROXY").unwrap();
		assert!(rule.matches(&MatchContext {
			inbound_type: Some(InboundType::Socks),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			inbound_type: Some(InboundType::Http),
			..Default::default()
		}));
	}

	#[test]
	fn parse_in_type_combined() {
		let rule = Rule::parse("IN-TYPE,SOCKS/HTTP,PROXY").unwrap();
		assert!(rule.matches(&MatchContext {
			inbound_type: Some(InboundType::Socks),
			..Default::default()
		}));
		assert!(rule.matches(&MatchContext {
			inbound_type: Some(InboundType::Http),
			..Default::default()
		}));
	}

	#[test]
	fn parse_in_user() {
		let rule = Rule::parse("IN-USER,admin,PROXY").unwrap();
		assert!(rule.matches(&MatchContext {
			inbound_user: Some("admin"),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			inbound_user: Some("guest"),
			..Default::default()
		}));
	}

	#[test]
	fn parse_in_name() {
		let rule = Rule::parse("IN-NAME,socks-in,PROXY").unwrap();
		assert!(rule.matches(&MatchContext {
			inbound_name: Some("socks-in"),
			..Default::default()
		}));
	}

	// -- Process rules --

	#[test]
	fn parse_process_name() {
		let rule = Rule::parse("PROCESS-NAME,chrome,PROXY").unwrap();
		assert!(rule.matches(&MatchContext {
			process_name: Some("chrome"),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			process_name: Some("firefox"),
			..Default::default()
		}));
	}

	#[test]
	fn parse_process_name_regex() {
		let rule = Rule::parse("PROCESS-NAME-REGEX,^chrom,PROXY").unwrap();
		assert!(rule.matches(&MatchContext {
			process_name: Some("chrome"),
			..Default::default()
		}));
		assert!(rule.matches(&MatchContext {
			process_name: Some("chromium"),
			..Default::default()
		}));
	}

	#[test]
	fn parse_process_path() {
		let rule = Rule::parse("PROCESS-PATH,/usr/bin/curl,DIRECT").unwrap();
		assert!(rule.matches(&MatchContext {
			process_path: Some("/usr/bin/curl"),
			..Default::default()
		}));
	}

	#[test]
	fn parse_uid() {
		let rule = Rule::parse("UID,1000,DIRECT").unwrap();
		assert!(rule.matches(&MatchContext {
			uid: Some(1000),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			uid: Some(0),
			..Default::default()
		}));
	}

	// -- Network rules --

	#[test]
	fn parse_network() {
		let rule = Rule::parse("NETWORK,tcp,PROXY").unwrap();
		assert!(rule.matches(&MatchContext {
			network: Some(NetworkType::Tcp),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			network: Some(NetworkType::Udp),
			..Default::default()
		}));
	}

	#[test]
	fn parse_dscp() {
		let rule = Rule::parse("DSCP,46,PROXY").unwrap();
		assert!(rule.matches(&MatchContext {
			dscp: Some(46),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			dscp: Some(0),
			..Default::default()
		}));
	}

	// -- Match --

	#[test]
	fn parse_match_all() {
		let rule = Rule::parse("MATCH,FALLBACK").unwrap();
		assert!(rule.matches(&MatchContext::default()));
	}

	// -- Options --

	#[test]
	fn parse_with_options() {
		let rule = Rule::parse("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve").unwrap();
		assert!(rule.no_resolve());
		assert_eq!(rule.options, vec!["no-resolve"]);
	}

	// -- Advanced: AND / OR / NOT --

	#[test]
	fn parse_and_rule() {
		let rule = Rule::parse("AND,((NETWORK,tcp),(DST-PORT,443)),PROXY").unwrap();
		assert_eq!(rule.target, "PROXY");

		let yes = MatchContext {
			network: Some(NetworkType::Tcp),
			dst_port: Some(443),
			..Default::default()
		};
		assert!(rule.matches(&yes));

		let no = MatchContext {
			network: Some(NetworkType::Udp),
			dst_port: Some(443),
			..Default::default()
		};
		assert!(!rule.matches(&no));
	}

	#[test]
	fn parse_or_rule() {
		let rule = Rule::parse("OR,((DST-PORT,80),(DST-PORT,443)),PROXY").unwrap();

		assert!(rule.matches(&MatchContext {
			dst_port: Some(80),
			..Default::default()
		}));
		assert!(rule.matches(&MatchContext {
			dst_port: Some(443),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			dst_port: Some(22),
			..Default::default()
		}));
	}

	#[test]
	fn parse_not_rule() {
		let rule = Rule::parse("NOT,((NETWORK,udp)),PROXY").unwrap();

		assert!(rule.matches(&MatchContext {
			network: Some(NetworkType::Tcp),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			network: Some(NetworkType::Udp),
			..Default::default()
		}));
	}

	// -- Multi-line parsing --

	#[test]
	fn parse_rules_multiline() {
		let rules = Rule::parse_rules(
			r#"
			# comment
			DOMAIN,ad.example.com,REJECT
			DOMAIN-SUFFIX,google.com,PROXY
			IP-CIDR,127.0.0.0/8,DIRECT
			MATCH,PROXY
			"#,
		);
		assert_eq!(rules.len(), 4);
		assert!(rules.iter().all(Result::is_ok));
	}

	// -- Display round-trip --

	#[test]
	fn display_round_trip() {
		let input = "DOMAIN-SUFFIX,google.com,PROXY";
		let rule = Rule::parse(input).unwrap();
		assert_eq!(rule.to_string(), input);
	}

	// -- Error cases --

	#[test]
	fn unknown_rule_type() {
		let err = Rule::parse("UNKNOWN,value,TARGET").unwrap_err();
		assert!(matches!(err, RuleParseError::UnknownRuleType(_)));
	}

	#[test]
	fn invalid_cidr() {
		let err = Rule::parse("IP-CIDR,not_a_cidr,DIRECT").unwrap_err();
		assert!(matches!(err, RuleParseError::InvalidIpCidr(_)));
	}

	#[test]
	fn invalid_inbound_type() {
		let err = Rule::parse("IN-TYPE,QUIC,TARGET").unwrap_err();
		assert!(matches!(err, RuleParseError::InvalidInboundType(_)));
	}

	#[test]
	fn empty_line_is_error() {
		assert!(matches!(Rule::parse("").unwrap_err(), RuleParseError::EmptyOrComment));
		assert!(matches!(
			Rule::parse("# comment").unwrap_err(),
			RuleParseError::EmptyOrComment
		));
	}

	// -- Port range rules --

	#[test]
	fn parse_dst_port_range() {
		let rule = Rule::parse("DST-PORT,1000-2000,PROXY").unwrap();
		assert!(rule.matches(&MatchContext {
			dst_port: Some(1000),
			..Default::default()
		}));
		assert!(rule.matches(&MatchContext {
			dst_port: Some(1500),
			..Default::default()
		}));
		assert!(rule.matches(&MatchContext {
			dst_port: Some(2000),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			dst_port: Some(999),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			dst_port: Some(2001),
			..Default::default()
		}));
	}

	#[test]
	fn parse_src_port_range() {
		let rule = Rule::parse("SRC-PORT,50000-60000,DIRECT").unwrap();
		assert!(rule.matches(&MatchContext {
			src_port: Some(55000),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			src_port: Some(49999),
			..Default::default()
		}));
	}

	#[test]
	fn display_port_range_round_trip() {
		let rule = Rule::parse("DST-PORT,8000-9000,PROXY").unwrap();
		assert_eq!(rule.to_string(), "DST-PORT,8000-9000,PROXY");

		let rule2 = Rule::parse("SRC-PORT,100-200,DIRECT").unwrap();
		assert_eq!(rule2.to_string(), "SRC-PORT,100-200,DIRECT");
	}

	// -- Source IP rules --

	#[test]
	fn parse_src_ip_suffix() {
		let rule = Rule::parse("SRC-IP-SUFFIX,192.168.0.0/16,DIRECT").unwrap();
		assert!(rule.matches(&MatchContext {
			src_ip: Some("192.168.10.1".parse().unwrap()),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			src_ip: Some("10.0.0.1".parse().unwrap()),
			..Default::default()
		}));
	}

	#[test]
	fn parse_src_geoip_with_lookup() {
		let rule = Rule::parse("SRC-GEOIP,CN,DIRECT").unwrap();
		// Without lookup → false
		assert!(!rule.matches(&MatchContext {
			src_ip: Some("1.2.3.4".parse().unwrap()),
			..Default::default()
		}));
		// With lookup
		let lookup = |code: &str, _ip: std::net::IpAddr| code == "CN";
		let ctx = MatchContext {
			src_ip: Some("1.2.3.4".parse().unwrap()),
			geoip_lookup: Some(&lookup),
			..Default::default()
		};
		assert!(rule.matches(&ctx));
	}

	#[test]
	fn parse_src_ip_asn_with_lookup() {
		let rule = Rule::parse("SRC-IP-ASN,4808,DIRECT").unwrap();
		// Without lookup → false
		assert!(!rule.matches(&MatchContext {
			src_ip: Some("1.2.3.4".parse().unwrap()),
			..Default::default()
		}));
		// With lookup
		let lookup = |asn: u32, _ip: std::net::IpAddr| asn == 4808;
		let ctx = MatchContext {
			src_ip: Some("1.2.3.4".parse().unwrap()),
			asn_lookup: Some(&lookup),
			..Default::default()
		};
		assert!(rule.matches(&ctx));
	}

	// -- Process rules (regex) --

	#[test]
	fn parse_process_path_regex() {
		let rule = Rule::parse("PROCESS-PATH-REGEX,/usr/.*/curl,DIRECT").unwrap();
		assert!(rule.matches(&MatchContext {
			process_path: Some("/usr/local/bin/curl"),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			process_path: Some("/opt/bin/wget"),
			..Default::default()
		}));
	}

	// -- GeoIp with lookup --

	#[test]
	fn parse_geoip_with_lookup() {
		let rule = Rule::parse("GEOIP,US,PROXY").unwrap();
		let lookup = |code: &str, _ip: std::net::IpAddr| code == "US";
		let ctx = MatchContext {
			dst_ip: Some("8.8.8.8".parse().unwrap()),
			geoip_lookup: Some(&lookup),
			..Default::default()
		};
		assert!(rule.matches(&ctx));
	}

	#[test]
	fn parse_ip_asn_with_lookup() {
		let rule = Rule::parse("IP-ASN,13335,PROXY").unwrap();
		let lookup = |asn: u32, _ip: std::net::IpAddr| asn == 13335;
		let ctx = MatchContext {
			dst_ip: Some("1.1.1.1".parse().unwrap()),
			asn_lookup: Some(&lookup),
			..Default::default()
		};
		assert!(rule.matches(&ctx));
	}

	// -- Compound rules edge cases --

	#[test]
	fn nested_and_or_compound() {
		// OR((NETWORK,tcp),(DST-PORT,53))
		let rule = Rule::parse("OR,((NETWORK,tcp),(DST-PORT,53)),PROXY").unwrap();
		assert!(rule.matches(&MatchContext {
			network: Some(NetworkType::Tcp),
			..Default::default()
		}));
		assert!(rule.matches(&MatchContext {
			dst_port: Some(53),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			network: Some(NetworkType::Udp),
			dst_port: Some(80),
			..Default::default()
		}));
	}

	#[test]
	fn not_compound_negates() {
		// NOT DOMAIN-SUFFIX google.com → matches everything except google.com
		let rule = Rule::parse("NOT,((DOMAIN-SUFFIX,google.com)),PROXY").unwrap();
		assert!(rule.matches(&MatchContext {
			domain: Some("example.com"),
			..Default::default()
		}));
		assert!(!rule.matches(&MatchContext {
			domain: Some("www.google.com"),
			..Default::default()
		}));
	}

	// -- RuleSet and SubRule (placeholders) --

	#[test]
	fn rule_set_always_false() {
		let rule = Rule::parse("RULE-SET,my-set,PROXY").unwrap();
		assert!(!rule.matches(&MatchContext::default()));
	}

	// -- Case sensitivity --

	#[test]
	fn domain_case_insensitive() {
		let rule = Rule::parse("DOMAIN,Example.COM,REJECT").unwrap();
		assert!(rule.matches(&MatchContext {
			domain: Some("example.com"),
			..Default::default()
		}));
		assert!(rule.matches(&MatchContext {
			domain: Some("EXAMPLE.COM"),
			..Default::default()
		}));
	}

	#[test]
	fn domain_suffix_case_insensitive() {
		let rule = Rule::parse("DOMAIN-SUFFIX,Google.Com,PROXY").unwrap();
		assert!(rule.matches(&MatchContext {
			domain: Some("WWW.GOOGLE.COM"),
			..Default::default()
		}));
	}

	// -- None field behavior --

	#[test]
	fn none_fields_never_match_specific_rules() {
		let rule = Rule::parse("DOMAIN,example.com,REJECT").unwrap();
		assert!(!rule.matches(&MatchContext::default())); // domain is None

		let rule = Rule::parse("IP-CIDR,10.0.0.0/8,DIRECT").unwrap();
		assert!(!rule.matches(&MatchContext::default())); // dst_ip is None

		let rule = Rule::parse("DST-PORT,443,PROXY").unwrap();
		assert!(!rule.matches(&MatchContext::default())); // dst_port is None

		let rule = Rule::parse("NETWORK,tcp,PROXY").unwrap();
		assert!(!rule.matches(&MatchContext::default())); // network is None
	}

	// -- Display for compound rules --

	#[test]
	fn display_and_rule() {
		let rule = Rule::parse("AND,((NETWORK,tcp),(DST-PORT,443)),PROXY").unwrap();
		let s = rule.to_string();
		assert!(s.starts_with("AND,"));
		assert!(s.contains("NETWORK,tcp"));
		assert!(s.contains("DST-PORT,443"));
		assert!(s.ends_with(",PROXY"));
	}

	// -- Error cases --

	#[test]
	fn invalid_regex() {
		let err = Rule::parse("DOMAIN-REGEX,[invalid,TARGET").unwrap_err();
		assert!(matches!(err, RuleParseError::InvalidRegex(_)));
	}

	#[test]
	fn invalid_port_number() {
		let err = Rule::parse("DST-PORT,99999,TARGET").unwrap_err();
		assert!(matches!(err, RuleParseError::InvalidNumber(_)));
	}

	#[test]
	fn invalid_network_type() {
		let err = Rule::parse("NETWORK,sctp,TARGET").unwrap_err();
		assert!(matches!(err, RuleParseError::InvalidNetworkType(_)));
	}

	#[test]
	fn not_requires_single_subrule() {
		let err = Rule::parse("NOT,((NETWORK,tcp),(DST-PORT,443)),TARGET").unwrap_err();
		assert!(matches!(err, RuleParseError::InvalidFormat(_)));
	}
}

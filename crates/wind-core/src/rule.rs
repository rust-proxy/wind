//! Metacubex-style routing rule engine.
//!
//! Provides rule-based routing decisions compatible with Clash/Mihomo rule
//! syntax.  Rules are evaluated in order; the first matching rule wins.
//!
//! # Supported Rule Types
//!
//! | Type              | Example                                    |
//! |-------------------|--------------------------------------------|
//! | `DOMAIN`          | `DOMAIN,example.com,REJECT`                |
//! | `DOMAIN-SUFFIX`   | `DOMAIN-SUFFIX,google.com,PROXY`           |
//! | `DOMAIN-KEYWORD`  | `DOMAIN-KEYWORD,ads,REJECT`                |
//! | `DOMAIN-WILDCARD` | `DOMAIN-WILDCARD,*.ad.com,REJECT`          |
//! | `DOMAIN-REGEX`    | `DOMAIN-REGEX,^ad\..*,REJECT`              |
//! | `IP-CIDR`         | `IP-CIDR,192.168.0.0/16,DIRECT`           |
//! | `IP-CIDR6`        | `IP-CIDR6,fc00::/7,DIRECT`                |
//! | `DST-PORT`        | `DST-PORT,443,PROXY`                       |
//! | `SRC-PORT`        | `SRC-PORT,12345,DIRECT`                    |
//! | `NETWORK`         | `NETWORK,udp,DIRECT`                       |
//! | `MATCH`           | `MATCH,PROXY`                              |
//!
//! # Usage
//!
//! ```ignore
//! use wind_core::rule::{Rule, MatchContext, NetworkType};
//!
//! let rules: Vec<Rule> = Rule::parse_rules(r#"
//!     DOMAIN-SUFFIX,google.com,proxy
//!     IP-CIDR,127.0.0.0/8,direct
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
	/// Domain suffix match – also matches subdomains.
	DomainSuffix(String),
	/// Domain contains keyword (case-insensitive).
	DomainKeyword(String),
	/// Wildcard domain (`*` and `?`).
	DomainWildcard(String),
	/// Domain matched by regex.
	DomainRegex(Regex),

	// -- IP rules --
	/// IPv4/IPv6 CIDR match on the destination IP.
	IpCidr(IpNet),
	/// IPv6-only CIDR match on the destination IP.
	IpCidr6(Ipv6Net),

	// -- Port rules --
	/// Destination port match.
	DstPort(u16),
	/// Source port match.
	SrcPort(u16),

	// -- Network rules --
	/// Network protocol match (TCP / UDP).
	Network(NetworkType),

	// -- Catch-all --
	/// Matches every connection.
	Match,
}

/// Context supplied to [`Rule::matches`].
///
/// Fill in the fields that are known; unknown fields should be `None` (the
/// default).
#[derive(Debug, Clone, Default)]
pub struct MatchContext<'a> {
	pub src_ip: Option<IpAddr>,
	pub dst_ip: Option<IpAddr>,
	pub src_port: Option<u16>,
	pub dst_port: Option<u16>,
	pub domain: Option<&'a str>,
	pub network: Option<NetworkType>,
}

// ============================================================================
// Matching
// ============================================================================

impl Rule {
	/// Returns `true` if this rule matches the given context.
	pub fn matches(&self, ctx: &MatchContext) -> bool {
		match &self.rule_type {
			RuleType::Domain(d) => ctx.domain.is_some_and(|h| h.eq_ignore_ascii_case(d)),

			RuleType::DomainSuffix(suffix) => ctx.domain.is_some_and(|h| {
				h.eq_ignore_ascii_case(suffix)
					|| h.to_ascii_lowercase()
						.ends_with(&format!(".{}", suffix.to_ascii_lowercase()))
			}),

			RuleType::DomainKeyword(kw) => {
				ctx.domain
					.is_some_and(|h| h.to_ascii_lowercase().contains(&kw.to_ascii_lowercase()))
			}

			RuleType::DomainWildcard(pattern) => ctx.domain.is_some_and(|h| wildcard_match(pattern, h)),

			RuleType::DomainRegex(re) => ctx.domain.is_some_and(|h| re.is_match(h)),

			RuleType::IpCidr(net) => ctx.dst_ip.is_some_and(|ip| net.contains(&ip)),

			RuleType::IpCidr6(net) => ctx.dst_ip.is_some_and(|ip| match ip {
				IpAddr::V6(v6) => net.contains(&v6),
				_ => false,
			}),

			RuleType::DstPort(p) => ctx.dst_port.is_some_and(|dp| dp == *p),

			RuleType::SrcPort(p) => ctx.src_port.is_some_and(|sp| sp == *p),

			RuleType::Network(n) => ctx.network.is_some_and(|nn| nn == *n),

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

		let parts: Vec<&str> = line.split(',').collect();
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
			"DOMAIN" => Ok(RuleType::Domain(value.to_string())),
			"DOMAIN-SUFFIX" => Ok(RuleType::DomainSuffix(value.to_string())),
			"DOMAIN-KEYWORD" => Ok(RuleType::DomainKeyword(value.to_string())),
			"DOMAIN-WILDCARD" => Ok(RuleType::DomainWildcard(value.to_string())),
			"DOMAIN-REGEX" => {
				let re = Regex::new(value).map_err(|e| RuleParseError::InvalidRegex(e.to_string()))?;
				Ok(RuleType::DomainRegex(re))
			}
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
			"DST-PORT" => {
				let port = value
					.parse::<u16>()
					.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
				Ok(RuleType::DstPort(port))
			}
			"SRC-PORT" => {
				let port = value
					.parse::<u16>()
					.map_err(|e| RuleParseError::InvalidNumber(e.to_string()))?;
				Ok(RuleType::SrcPort(port))
			}
			"NETWORK" => match value.to_ascii_lowercase().as_str() {
				"tcp" => Ok(RuleType::Network(NetworkType::Tcp)),
				"udp" => Ok(RuleType::Network(NetworkType::Udp)),
				_ => Err(RuleParseError::InvalidNetworkType(value.to_string())),
			},
			other => Err(RuleParseError::UnknownRuleType(other.to_string())),
		}
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

impl fmt::Display for RuleType {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Domain(v) => write!(f, "DOMAIN,{v}"),
			Self::DomainSuffix(v) => write!(f, "DOMAIN-SUFFIX,{v}"),
			Self::DomainKeyword(v) => write!(f, "DOMAIN-KEYWORD,{v}"),
			Self::DomainWildcard(v) => write!(f, "DOMAIN-WILDCARD,{v}"),
			Self::DomainRegex(v) => write!(f, "DOMAIN-REGEX,{v}"),
			Self::IpCidr(v) => write!(f, "IP-CIDR,{v}"),
			Self::IpCidr6(v) => write!(f, "IP-CIDR6,{v}"),
			Self::DstPort(v) => write!(f, "DST-PORT,{v}"),
			Self::SrcPort(v) => write!(f, "SRC-PORT,{v}"),
			Self::Network(v) => write!(f, "NETWORK,{v}"),
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_domain_exact() {
		let rule = Rule::parse("DOMAIN,example.com,REJECT").unwrap();
		assert_eq!(rule.target, "REJECT");

		let yes = MatchContext { domain: Some("example.com"), ..Default::default() };
		let no = MatchContext { domain: Some("sub.example.com"), ..Default::default() };
		assert!(rule.matches(&yes));
		assert!(!rule.matches(&no));
	}

	#[test]
	fn parse_domain_suffix() {
		let rule = Rule::parse("DOMAIN-SUFFIX,google.com,PROXY").unwrap();
		assert_eq!(rule.target, "PROXY");

		assert!(rule.matches(&MatchContext { domain: Some("www.google.com"), ..Default::default() }));
		assert!(rule.matches(&MatchContext { domain: Some("google.com"), ..Default::default() }));
		assert!(!rule.matches(&MatchContext { domain: Some("notgoogle.com"), ..Default::default() }));
	}

	#[test]
	fn parse_domain_keyword() {
		let rule = Rule::parse("DOMAIN-KEYWORD,ads,REJECT").unwrap();
		assert!(rule.matches(&MatchContext { domain: Some("ads.example.com"), ..Default::default() }));
		assert!(rule.matches(&MatchContext { domain: Some("example-ads.net"), ..Default::default() }));
		assert!(!rule.matches(&MatchContext { domain: Some("example.com"), ..Default::default() }));
	}

	#[test]
	fn parse_domain_wildcard() {
		let rule = Rule::parse("DOMAIN-WILDCARD,*.ad.com,REJECT").unwrap();
		assert!(rule.matches(&MatchContext { domain: Some("foo.ad.com"), ..Default::default() }));
		assert!(!rule.matches(&MatchContext { domain: Some("ad.com"), ..Default::default() }));
	}

	#[test]
	fn parse_domain_regex() {
		let rule = Rule::parse("DOMAIN-REGEX,^ad\\.,REJECT").unwrap();
		assert!(rule.matches(&MatchContext { domain: Some("ad.example.com"), ..Default::default() }));
		assert!(!rule.matches(&MatchContext { domain: Some("example.ad.com"), ..Default::default() }));
	}

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
	fn parse_dst_port() {
		let rule = Rule::parse("DST-PORT,443,PROXY").unwrap();
		assert!(rule.matches(&MatchContext { dst_port: Some(443), ..Default::default() }));
		assert!(!rule.matches(&MatchContext { dst_port: Some(80), ..Default::default() }));
	}

	#[test]
	fn parse_src_port() {
		let rule = Rule::parse("SRC-PORT,12345,DIRECT").unwrap();
		assert!(rule.matches(&MatchContext { src_port: Some(12345), ..Default::default() }));
	}

	#[test]
	fn parse_network() {
		let rule = Rule::parse("NETWORK,tcp,PROXY").unwrap();
		assert!(rule.matches(&MatchContext { network: Some(NetworkType::Tcp), ..Default::default() }));
		assert!(!rule.matches(&MatchContext { network: Some(NetworkType::Udp), ..Default::default() }));
	}

	#[test]
	fn parse_match_all() {
		let rule = Rule::parse("MATCH,FALLBACK").unwrap();
		assert!(rule.matches(&MatchContext::default()));
	}

	#[test]
	fn parse_with_options() {
		let rule = Rule::parse("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve").unwrap();
		assert!(rule.no_resolve());
		assert_eq!(rule.options, vec!["no-resolve"]);
	}

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

	#[test]
	fn display_round_trip() {
		let input = "DOMAIN-SUFFIX,google.com,PROXY";
		let rule = Rule::parse(input).unwrap();
		assert_eq!(rule.to_string(), input);
	}

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
	fn empty_line_is_error() {
		assert!(matches!(Rule::parse("").unwrap_err(), RuleParseError::EmptyOrComment));
		assert!(matches!(Rule::parse("# comment").unwrap_err(), RuleParseError::EmptyOrComment));
	}
}

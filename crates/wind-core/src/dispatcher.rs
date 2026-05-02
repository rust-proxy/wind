//! Generic dispatcher: sits between inbound and outbound.
//!
//! The dispatcher receives every inbound connection from an [`InboundCallback`]
//! implementation, evaluates routing rules via a user-supplied [`Router`], and
//! hands the connection off to the matching [`OutboundAction`] handler.
//!
//! # Design
//!
//! * [`Router`] – an **async** trait that inspects the destination and returns
//!   a [`RouteAction`].  Implementations live in the application crate (e.g.
//!   `tuic-server`) where ACL rules and outbound configs are known.
//! * [`OutboundAction`] – an **object-safe** trait representing a concrete
//!   outbound handler (direct, socks5, …).  Handlers are keyed by name string.
//! * [`Dispatcher`] – wraps a router and a map of named handlers, and
//!   implements [`InboundCallback`] so it can be passed directly to
//!   `inbound.listen()`.

use std::{collections::HashMap, future::Future, net::IpAddr, pin::Pin, sync::Arc};

use tracing::Instrument;

use crate::{
	InboundCallback,
	rule::{MatchContext, NetworkType, Rule},
	tcp::AbstractTcpStream,
	types::TargetAddr,
	udp::UdpStream,
};

// ============================================================================
// Public types
// ============================================================================

/// Boxed future alias used throughout this module.
///
/// Both `Send` and `Sync` are required so the future satisfies the
/// `FutResult` alias used by `InboundCallback`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Decision returned by a [`Router`].
#[derive(Debug, Clone)]
pub enum RouteAction {
	/// Reject the connection (drop it with an optional reason).
	Reject(String),
	/// Forward to the named outbound handler.
	///
	/// The name must match a key previously registered via
	/// [`Dispatcher::add_handler`] (or `"default"` which is always tried as a
	/// fallback).
	Forward(String),
}

// ============================================================================
// Router trait
// ============================================================================

/// Determines which outbound handler should serve a connection.
///
/// Implementations are free to perform DNS resolution, consult ACL tables, or
/// apply any other policy.  The trait is object-safe; all methods take
/// `&self` and return a pinned boxed future.
pub trait Router: Send + Sync + 'static {
	/// Classify a TCP or UDP connection.
	///
	/// * `target` – the destination address as reported by the inbound.
	/// * `is_tcp`  – `true` for TCP streams, `false` for UDP streams.
	fn route<'a>(&'a self, target: &'a TargetAddr, is_tcp: bool) -> BoxFuture<'a, eyre::Result<RouteAction>>;
}

// ============================================================================
// OutboundAction trait
// ============================================================================

/// Object-safe outbound handler.
///
/// Each concrete outbound strategy (direct connect, SOCKS5 proxy, …)
/// implements this trait.  The stream types are erased via trait objects so
/// handlers can be stored in a `HashMap`.
pub trait OutboundAction: Send + Sync + 'static {
	/// Handle an inbound TCP stream.
	///
	/// The stream is boxed and `'static` so it can be stored or sent across
	/// tasks.  All concrete `AbstractTcpStream` implementations (owned
	/// `TcpStream`, `Socks5Stream<TcpStream>`, …) satisfy this bound.
	fn handle_tcp<'a>(
		&'a self,
		target: TargetAddr,
		stream: Box<dyn AbstractTcpStream + 'static>,
	) -> BoxFuture<'a, eyre::Result<()>>;

	/// Handle an inbound UDP session.
	fn handle_udp<'a>(&'a self, stream: UdpStream) -> BoxFuture<'a, eyre::Result<()>>;
}

// ============================================================================
// Dispatcher
// ============================================================================

/// Routes inbound connections to named outbound handlers.
///
/// # Construction
///
/// ```ignore
/// let mut dispatcher = Dispatcher::new(my_router);
/// dispatcher.add_handler("default", Arc::new(DirectOutbound::new()));
/// dispatcher.add_handler("via_socks5", Arc::new(Socks5Outbound::new("127.0.0.1:1080")));
/// ```
///
/// Then pass `dispatcher` (or `dispatcher.clone()`) to `inbound.listen()`.
pub struct Dispatcher<R: Router> {
	router: Arc<R>,
	handlers: Arc<HashMap<String, Arc<dyn OutboundAction>>>,
}

impl<R: Router> Dispatcher<R> {
	/// Create a new dispatcher with the given router and no handlers yet.
	pub fn new(router: R) -> Self {
		Self {
			router: Arc::new(router),
			handlers: Arc::new(HashMap::new()),
		}
	}

	/// Register a named outbound handler.
	///
	/// Call this before passing the dispatcher to an inbound.  The name
	/// `"default"` is used as the fallback when the router returns a name that
	/// is not otherwise registered.
	pub fn add_handler(&mut self, name: impl Into<String>, handler: Arc<dyn OutboundAction>) {
		Arc::make_mut(&mut self.handlers).insert(name.into(), handler);
	}

	/// Look up a handler by name, falling back to `"default"` if the exact
	/// name is not registered.
	fn resolve_handler(&self, name: &str) -> Option<Arc<dyn OutboundAction>> {
		self.handlers.get(name).or_else(|| self.handlers.get("default")).cloned()
	}
}

impl<R: Router> Clone for Dispatcher<R> {
	fn clone(&self) -> Self {
		Self {
			router: self.router.clone(),
			handlers: self.handlers.clone(),
		}
	}
}

// ============================================================================
// InboundCallback implementation
// ============================================================================

impl<R: Router> InboundCallback for Dispatcher<R> {
	async fn handle_tcpstream(&self, target_addr: TargetAddr, stream: impl AbstractTcpStream + 'static) -> eyre::Result<()> {
		let span = tracing::debug_span!("dispatch_tcp", target = %target_addr);
		self.dispatch_tcp(target_addr, stream).instrument(span).await
	}

	async fn handle_udpstream(&self, udp_stream: UdpStream) -> eyre::Result<()> {
		self.dispatch_udp(udp_stream)
			.instrument(tracing::debug_span!("dispatch_udp"))
			.await
	}
}

impl<R: Router> Dispatcher<R> {
	async fn dispatch_tcp(&self, target_addr: TargetAddr, stream: impl AbstractTcpStream + 'static) -> eyre::Result<()> {
		let action = self.router.route(&target_addr, true).await?;

		match action {
			RouteAction::Reject(reason) => {
				tracing::debug!(reason = %reason, "rejected");
				Err(eyre::eyre!("connection rejected: {}", reason))
			}
			RouteAction::Forward(name) => {
				tracing::debug!(outbound = %name, "forwarding");

				let handler = self
					.resolve_handler(&name)
					.ok_or_else(|| eyre::eyre!("no outbound handler registered for '{}' (and no 'default')", name))?;

				handler.handle_tcp(target_addr, Box::new(stream)).await
			}
		}
	}

	async fn dispatch_udp(&self, udp_stream: UdpStream) -> eyre::Result<()> {
		let sentinel = TargetAddr::IPv4(std::net::Ipv4Addr::UNSPECIFIED, 0);
		let action = self.router.route(&sentinel, false).await?;

		match action {
			RouteAction::Reject(reason) => {
				tracing::debug!(reason = %reason, "rejected");
				Err(eyre::eyre!("UDP session rejected: {}", reason))
			}
			RouteAction::Forward(name) => {
				tracing::debug!(outbound = %name, "forwarding");

				let handler = self
					.resolve_handler(&name)
					.ok_or_else(|| eyre::eyre!("no outbound handler registered for '{}' (and no 'default')", name))?;

				handler.handle_udp(udp_stream).await
			}
		}
	}
}

// ============================================================================
// AclRouter – built-in Router backed by Rule list
// ============================================================================

/// A built-in [`Router`] that evaluates a list of [`Rule`]s in order.
///
/// The first matching rule determines the outbound.  If no rule matches, the
/// configured default outbound is used.
///
/// Rule targets are mapped to [`RouteAction`] as follows:
///
/// * `"reject"` / `"block"` / `"deny"` (case-insensitive) →
///   [`RouteAction::Reject`]
/// * anything else → [`RouteAction::Forward`] with the target name
///
/// # Example
///
/// ```ignore
/// use wind_core::{Dispatcher, dispatcher::AclRouter};
/// use wind_core::rule::Rule;
///
/// let rules: Vec<Rule> = Rule::parse_rules(r#"
///     DOMAIN-SUFFIX,ads.example.com,reject
///     DOMAIN-SUFFIX,google.com,proxy
///     IP-CIDR,10.0.0.0/8,direct
///     MATCH,proxy
/// "#).into_iter().filter_map(Result::ok).collect();
///
/// let router = AclRouter::new(rules, "direct");
/// let mut dispatcher = Dispatcher::new(router);
/// // dispatcher.add_handler("direct", ...);
/// // dispatcher.add_handler("proxy", ...);
/// ```
pub struct AclRouter {
	rules: Vec<Rule>,
	default_outbound: String,
}

impl AclRouter {
	/// Create a router with the given ordered rules and a fallback outbound
	/// name used when no rule matches.
	pub fn new(rules: Vec<Rule>, default_outbound: impl Into<String>) -> Self {
		Self {
			rules,
			default_outbound: default_outbound.into(),
		}
	}
}

impl Router for AclRouter {
	fn route<'a>(&'a self, target: &'a TargetAddr, is_tcp: bool) -> BoxFuture<'a, eyre::Result<RouteAction>> {
		let span = tracing::trace_span!("acl_route", target = %target, proto = if is_tcp { "tcp" } else { "udp" });
		Box::pin(self.eval_rules(target, is_tcp).instrument(span))
	}
}

impl AclRouter {
	async fn eval_rules(&self, target: &TargetAddr, is_tcp: bool) -> eyre::Result<RouteAction> {
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
			..Default::default()
		};

		for rule in &self.rules {
			if rule.matches(&ctx) {
				tracing::debug!(rule = %rule, "matched");
				return Ok(rule_target_to_action(&rule.target, rule));
			}
		}

		tracing::debug!(outbound = %self.default_outbound, "no rule matched, using default");
		Ok(RouteAction::Forward(self.default_outbound.clone()))
	}
}

/// Map a rule target string to a [`RouteAction`].
fn rule_target_to_action(target: &str, rule: &Rule) -> RouteAction {
	match target.to_ascii_lowercase().as_str() {
		"reject" | "block" | "deny" => RouteAction::Reject(format!("rejected by rule: {}", rule)),
		name => RouteAction::Forward(name.to_string()),
	}
}

// ============================================================================
// Adapter: AbstractOutbound → OutboundAction
// ============================================================================

use crate::AbstractOutbound;

/// Placeholder type used for the `via` parameter when no outbound chaining
/// is desired.
///
/// Calling `handle_tcp` / `handle_udp` on this type will **panic**.
/// It must never be used — it only exists to fill the generic `via`
/// parameter of [`AbstractOutbound`].
pub struct NoChain;

impl AbstractOutbound for NoChain {
	async fn handle_tcp(
		&self,
		_target_addr: TargetAddr,
		_stream: impl crate::tcp::AbstractTcpStream,
		_via: Option<impl AbstractOutbound + Sized + Send>,
	) -> eyre::Result<()> {
		unreachable!("NoChain::handle_tcp should never be called")
	}

	async fn handle_udp(
		&self,
		_stream: crate::udp::UdpStream,
		_via: Option<impl AbstractOutbound + Sized + Send>,
	) -> eyre::Result<()> {
		unreachable!("NoChain::handle_udp should never be called")
	}
}

/// Adapter that wraps any [`AbstractOutbound`] implementation as an
/// [`OutboundAction`] (object-safe, store-able in the dispatcher).
///
/// The `via` chain parameter is filled with [`NoChain`] (panics if called).
pub struct OutboundAsAction<O> {
	pub inner: O,
}

impl<O: AbstractOutbound + Send + Sync + 'static> OutboundAction for OutboundAsAction<O> {
	fn handle_tcp<'a>(
		&'a self,
		target: TargetAddr,
		stream: Box<dyn crate::tcp::AbstractTcpStream + 'static>,
	) -> BoxFuture<'a, eyre::Result<()>> {
		Box::pin(async move {
			self.inner
				.handle_tcp(target, stream, Option::<NoChain>::None)
				.await
		})
	}

	fn handle_udp<'a>(&'a self, stream: crate::udp::UdpStream) -> BoxFuture<'a, eyre::Result<()>> {
		Box::pin(async move {
			self.inner
				.handle_udp(stream, Option::<NoChain>::None)
				.await
		})
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use std::sync::{
		Arc,
		atomic::{AtomicBool, Ordering},
	};

	use super::*;

	// -- Helpers --

	fn parse_rules(text: &str) -> Vec<Rule> {
		Rule::parse_rules(text).into_iter().filter_map(Result::ok).collect()
	}

	/// A trivial `OutboundAction` that just records whether it was called.
	struct MockHandler {
		tcp_called: AtomicBool,
		udp_called: AtomicBool,
	}

	impl MockHandler {
		fn new() -> Self {
			Self {
				tcp_called: AtomicBool::new(false),
				udp_called: AtomicBool::new(false),
			}
		}
	}

	impl OutboundAction for MockHandler {
		fn handle_tcp<'a>(
			&'a self,
			_target: TargetAddr,
			_stream: Box<dyn AbstractTcpStream + 'static>,
		) -> BoxFuture<'a, eyre::Result<()>> {
			self.tcp_called.store(true, Ordering::Relaxed);
			Box::pin(async { Ok(()) })
		}

		fn handle_udp<'a>(&'a self, _stream: UdpStream) -> BoxFuture<'a, eyre::Result<()>> {
			self.udp_called.store(true, Ordering::Relaxed);
			Box::pin(async { Ok(()) })
		}
	}

	// -- AclRouter unit tests --

	#[tokio::test]
	async fn acl_router_domain_suffix_match() {
		let router = AclRouter::new(parse_rules("DOMAIN-SUFFIX,google.com,proxy"), "direct");

		let target = TargetAddr::Domain("www.google.com".into(), 443);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "proxy"));
	}

	#[tokio::test]
	async fn acl_router_domain_exact_no_match() {
		let router = AclRouter::new(parse_rules("DOMAIN,example.com,proxy"), "direct");

		let target = TargetAddr::Domain("other.com".into(), 80);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "direct"));
	}

	#[tokio::test]
	async fn acl_router_ip_cidr_match() {
		let router = AclRouter::new(parse_rules("IP-CIDR,192.168.0.0/16,lan"), "default");

		let target = TargetAddr::IPv4("192.168.1.100".parse().unwrap(), 8080);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "lan"));

		let target = TargetAddr::IPv4("10.0.0.1".parse().unwrap(), 8080);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "default"));
	}

	#[tokio::test]
	async fn acl_router_reject_action() {
		let router = AclRouter::new(parse_rules("DOMAIN-KEYWORD,ads,reject"), "direct");

		let target = TargetAddr::Domain("ads.example.com".into(), 443);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Reject(_)));
	}

	#[tokio::test]
	async fn acl_router_block_and_deny_also_reject() {
		let rules = parse_rules(
			r#"
			DOMAIN,block.com,block
			DOMAIN,deny.com,deny
			"#,
		);
		let router = AclRouter::new(rules, "direct");

		let action = router.route(&TargetAddr::Domain("block.com".into(), 80), true).await.unwrap();
		assert!(matches!(action, RouteAction::Reject(_)));

		let action = router.route(&TargetAddr::Domain("deny.com".into(), 80), true).await.unwrap();
		assert!(matches!(action, RouteAction::Reject(_)));
	}

	#[tokio::test]
	async fn acl_router_network_type_filter() {
		let rules = parse_rules(
			r#"
			NETWORK,tcp,proxy
			NETWORK,udp,direct
			"#,
		);
		let router = AclRouter::new(rules, "fallback");

		let target = TargetAddr::Domain("any.com".into(), 443);

		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "proxy"));

		let action = router.route(&target, false).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "direct"));
	}

	#[tokio::test]
	async fn acl_router_dst_port_match() {
		let router = AclRouter::new(parse_rules("DST-PORT,443,proxy"), "direct");

		let target = TargetAddr::Domain("example.com".into(), 443);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "proxy"));

		let target = TargetAddr::Domain("example.com".into(), 80);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "direct"));
	}

	#[tokio::test]
	async fn acl_router_first_match_wins() {
		let rules = parse_rules(
			r#"
			DOMAIN-SUFFIX,google.com,first
			DOMAIN-SUFFIX,google.com,second
			MATCH,last
			"#,
		);
		let router = AclRouter::new(rules, "default");

		let target = TargetAddr::Domain("www.google.com".into(), 443);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "first"));
	}

	#[tokio::test]
	async fn acl_router_match_all_catchall() {
		let rules = parse_rules(
			r#"
			DOMAIN,specific.com,specific
			MATCH,catchall
			"#,
		);
		let router = AclRouter::new(rules, "default");

		let target = TargetAddr::Domain("random.org".into(), 80);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "catchall"));
	}

	#[tokio::test]
	async fn acl_router_ipv6_target() {
		let router = AclRouter::new(parse_rules("IP-CIDR6,fc00::/7,local"), "default");

		let target = TargetAddr::IPv6("fd12::1".parse().unwrap(), 443);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "local"));

		let target = TargetAddr::IPv6("2001:db8::1".parse().unwrap(), 443);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "default"));
	}

	// -- Dispatcher + AclRouter integration tests --

	#[tokio::test]
	async fn dispatcher_routes_tcp_to_correct_handler() {
		let rules = parse_rules(
			r#"
			DOMAIN-SUFFIX,proxy.me,proxy_out
			MATCH,default
			"#,
		);

		let proxy_handler = Arc::new(MockHandler::new());
		let default_handler = Arc::new(MockHandler::new());

		let mut dispatcher = Dispatcher::new(AclRouter::new(rules, "default"));
		dispatcher.add_handler("proxy_out", proxy_handler.clone());
		dispatcher.add_handler("default", default_handler.clone());

		// Create a duplex stream
		let (client, _server) = tokio::io::duplex(1024);

		let target = TargetAddr::Domain("app.proxy.me".into(), 443);
		dispatcher.handle_tcpstream(target, client).await.unwrap();

		assert!(proxy_handler.tcp_called.load(Ordering::Relaxed));
		assert!(!default_handler.tcp_called.load(Ordering::Relaxed));
	}

	#[tokio::test]
	async fn dispatcher_routes_udp_to_correct_handler() {
		let rules = parse_rules("MATCH,relay");

		let handler = Arc::new(MockHandler::new());

		let mut dispatcher = Dispatcher::new(AclRouter::new(rules, "default"));
		dispatcher.add_handler("relay", handler.clone());

		let (tx, _rx) = tokio::sync::mpsc::channel(1);
		let (_tx2, rx2) = tokio::sync::mpsc::channel(1);
		let stream = UdpStream { tx, rx: rx2 };

		dispatcher.handle_udpstream(stream).await.unwrap();
		assert!(handler.udp_called.load(Ordering::Relaxed));
	}

	#[tokio::test]
	async fn dispatcher_rejects_connection() {
		let rules = parse_rules("DOMAIN,blocked.com,reject");

		let mut dispatcher = Dispatcher::new(AclRouter::new(rules, "default"));
		dispatcher.add_handler("default", Arc::new(MockHandler::new()));

		let (client, _server) = tokio::io::duplex(1024);
		let target = TargetAddr::Domain("blocked.com".into(), 80);

		let result = dispatcher.handle_tcpstream(target, client).await;
		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("rejected"));
	}

	#[tokio::test]
	async fn dispatcher_fallback_to_default_handler() {
		let rules = parse_rules("DOMAIN,special.com,special_out");

		let default_handler = Arc::new(MockHandler::new());
		let mut dispatcher = Dispatcher::new(AclRouter::new(rules, "default"));
		dispatcher.add_handler("default", default_handler.clone());

		let (client, _server) = tokio::io::duplex(1024);
		let target = TargetAddr::Domain("other.com".into(), 80);
		dispatcher.handle_tcpstream(target, client).await.unwrap();

		assert!(default_handler.tcp_called.load(Ordering::Relaxed));
	}

	#[tokio::test]
	async fn dispatcher_unknown_handler_falls_back_to_default() {
		// Router returns a name that isn't registered — should fall back to "default"
		let rules = parse_rules("MATCH,nonexistent_handler");

		let default_handler = Arc::new(MockHandler::new());
		let mut dispatcher = Dispatcher::new(AclRouter::new(rules, "default"));
		dispatcher.add_handler("default", default_handler.clone());

		let (client, _server) = tokio::io::duplex(1024);
		let target = TargetAddr::Domain("any.com".into(), 80);
		dispatcher.handle_tcpstream(target, client).await.unwrap();

		assert!(default_handler.tcp_called.load(Ordering::Relaxed));
	}

	#[tokio::test]
	async fn dispatcher_no_handler_returns_error() {
		// No handlers registered at all — should error
		let rules = parse_rules("MATCH,missing");
		let dispatcher = Dispatcher::new(AclRouter::new(rules, "default"));

		let (client, _server) = tokio::io::duplex(1024);
		let result = dispatcher
			.handle_tcpstream(TargetAddr::Domain("a.com".into(), 80), client)
			.await;
		assert!(result.is_err());
	}

	// -- Port range routing --

	#[tokio::test]
	async fn acl_router_dst_port_range() {
		let router = AclRouter::new(parse_rules("DST-PORT,8000-9000,proxy"), "direct");

		let target = TargetAddr::Domain("example.com".into(), 8080);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "proxy"));

		let target = TargetAddr::Domain("example.com".into(), 80);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "direct"));
	}

	// -- Compound rules in routing --

	#[tokio::test]
	async fn acl_router_and_compound() {
		let rules = parse_rules("AND,((DOMAIN-SUFFIX,example.com),(DST-PORT,443)),secure_proxy");
		let router = AclRouter::new(rules, "direct");

		// Both match → secure_proxy
		let target = TargetAddr::Domain("www.example.com".into(), 443);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "secure_proxy"));

		// Domain matches but port doesn't → direct
		let target = TargetAddr::Domain("www.example.com".into(), 80);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "direct"));

		// Port matches but domain doesn't → direct
		let target = TargetAddr::Domain("other.org".into(), 443);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "direct"));
	}

	#[tokio::test]
	async fn acl_router_or_compound() {
		let rules = parse_rules("OR,((DOMAIN,a.com),(DOMAIN,b.com)),proxy");
		let router = AclRouter::new(rules, "direct");

		let target = TargetAddr::Domain("a.com".into(), 80);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "proxy"));

		let target = TargetAddr::Domain("b.com".into(), 80);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "proxy"));

		let target = TargetAddr::Domain("c.com".into(), 80);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "direct"));
	}

	#[tokio::test]
	async fn acl_router_not_compound() {
		let rules = parse_rules("NOT,((DOMAIN-SUFFIX,internal.corp)),proxy");
		let router = AclRouter::new(rules, "direct");

		// Doesn't match suffix → NOT succeeds → proxy
		let target = TargetAddr::Domain("external.com".into(), 80);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "proxy"));

		// Matches suffix → NOT fails → direct
		let target = TargetAddr::Domain("app.internal.corp".into(), 80);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "direct"));
	}

	// -- SrcIpCidr in routing (no src_ip in TargetAddr context → never matches) --

	#[tokio::test]
	async fn acl_router_src_ip_cidr_no_match_without_context() {
		let router = AclRouter::new(parse_rules("SRC-IP-CIDR,192.168.0.0/16,local"), "default");

		let target = TargetAddr::Domain("example.com".into(), 80);
		let action = router.route(&target, true).await.unwrap();
		// SRC-IP-CIDR can't match because AclRouter doesn't have src_ip context
		assert!(matches!(action, RouteAction::Forward(name) if name == "default"));
	}

	// -- Domain + port combination --

	#[tokio::test]
	async fn acl_router_domain_and_port_combination() {
		let rules = parse_rules(
			r#"
			AND,((DOMAIN-SUFFIX,api.example.com),(DST-PORT,8443)),api_proxy
			DOMAIN-SUFFIX,example.com,web_proxy
			MATCH,direct
			"#,
		);
		let router = AclRouter::new(rules, "direct");

		// api.example.com:8443 → api_proxy (first rule)
		let target = TargetAddr::Domain("api.example.com".into(), 8443);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "api_proxy"));

		// api.example.com:443 → web_proxy (second rule)
		let target = TargetAddr::Domain("api.example.com".into(), 443);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "web_proxy"));

		// other.org:80 → direct (MATCH)
		let target = TargetAddr::Domain("other.org".into(), 80);
		let action = router.route(&target, true).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "direct"));
	}
}

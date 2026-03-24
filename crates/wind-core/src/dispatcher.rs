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

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use crate::{InboundCallback, tcp::AbstractTcpStream, types::TargetAddr, udp::UdpStream};

// ============================================================================
// Public types
// ============================================================================

/// Boxed future alias used throughout this module.
///
/// Both `Send` and `Sync` are required so the future satisfies the
/// `FutResult` alias used by `InboundCallback`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + Sync + 'a>>;

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
		let action = self.router.route(&target_addr, true).await?;

		match action {
			RouteAction::Reject(reason) => {
				tracing::debug!("[dispatcher] TCP {} → reject: {}", target_addr, reason);
				return Err(eyre::eyre!("connection rejected: {}", reason));
			}
			RouteAction::Forward(name) => {
				tracing::debug!("[dispatcher] TCP {} → outbound '{}'", target_addr, name);

				let handler = self
					.resolve_handler(&name)
					.ok_or_else(|| eyre::eyre!("no outbound handler registered for '{}' (and no 'default')", name))?;

				// Erase the concrete stream type into a Box<dyn AbstractTcpStream>.
				handler.handle_tcp(target_addr, Box::new(stream)).await
			}
		}
	}

	async fn handle_udpstream(&self, udp_stream: UdpStream) -> eyre::Result<()> {
		// For UDP we peek at the target from the stream's perspective.
		// Because UdpStream is a channel pair, we cannot peek without consuming
		// a packet.  Instead we wrap the stream in a small shim that intercepts
		// the first packet, classifies it, then replays it into the handler.
		//
		// For simplicity we classify using a sentinel "unknown" address when
		// no target is readily available from the stream struct itself.  Real
		// per-packet routing happens inside the OutboundAction handler.
		//
		// If your Router needs per-packet classification, implement it inside
		// your OutboundAction::handle_udp instead.
		//
		// Here we use a dummy TargetAddr for initial routing (e.g. the handler
		// selection stage). This works well for most use cases where all UDP is
		// routed to the same outbound, or the OutboundAction handles per-packet
		// routing internally.
		//
		// For finer-grained control, use a custom Router that inspects a known
		// session target recorded elsewhere (e.g. from the TUIC header).
		let sentinel = TargetAddr::IPv4(std::net::Ipv4Addr::UNSPECIFIED, 0);
		let action = self.router.route(&sentinel, false).await?;

		match action {
			RouteAction::Reject(reason) => {
				tracing::debug!("[dispatcher] UDP session → reject: {}", reason);
				Err(eyre::eyre!("UDP session rejected: {}", reason))
			}
			RouteAction::Forward(name) => {
				tracing::debug!("[dispatcher] UDP session → outbound '{}'", name);

				let handler = self
					.resolve_handler(&name)
					.ok_or_else(|| eyre::eyre!("no outbound handler registered for '{}' (and no 'default')", name))?;

				handler.handle_udp(udp_stream).await
			}
		}
	}
}

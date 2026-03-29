//! Wind framework adapter for tuic-server
//!
//! This module wires together:
//!
//! * [`TuicRouter`] – implements `wind_core::Router`.  For every incoming
//!   connection it resolves the destination, applies experimental guards, and
//!   evaluates the ACL table to pick the right named outbound.
//! * [`TuicOutboundHandler`] – implements `wind_core::OutboundAction`.  Each
//!   instance wraps a single [`OutboundRule`] (direct or socks5) and performs
//!   the actual TCP/UDP relay.
//! * [`create_inbound`] – factory that builds a `wind_core::Dispatcher` wired
//!   to a `wind_tuic::TuicInbound` and returns the pair.
//!
//! # Dispatch flow
//!
//! For every incoming TCP stream or UDP session:
//!
//! 1. **Resolve** the `TargetAddr` to a `SocketAddr` using the default
//!    outbound's ip_mode (needed for ACL matching).
//! 2. **Experimental guards** – drop loopback / private addresses if
//!    configured.
//! 3. **ACL evaluation** – first-match wins.  The rule names `"reject"`,
//!    `"block"`, `"deny"` cause rejection; `"allow"` / `"default"` map to the
//!    `"default"` handler; any other name looks up a named outbound.
//! 4. **Outbound dispatch** via the `Dispatcher` / `OutboundAction` trait.

use std::{
	net::{SocketAddr, SocketAddrV4, SocketAddrV6},
	sync::Arc,
};

use fast_socks5::client::{Config as Socks5Config, Socks5Stream};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use wind_core::{
	AclRouter, AppContext, Dispatcher, OutboundAction, RouteAction, Router,
	dispatcher::BoxFuture,
	rule::Rule,
	tcp::AbstractTcpStream,
	types::TargetAddr,
	udp::{UdpPacket, UdpStream},
	utils::{StackPrefer, is_private_ip},
};
use wind_tuic::inbound::{TuicInbound, TuicInboundOpts};

use crate::{AppContext as TuicAppContext, config::OutboundRule};

// ============================================================================
// TuicRouter – implements wind_core::Router
// ============================================================================

/// Combined router for tuic-server.
///
/// Evaluation order:
/// 1. **Experimental guards** – reject loopback / private addresses.
/// 2. **Legacy ACL rules** (`[[acl]]`) – first-match wins.
/// 3. **Metacubex-style rules** (`rules = [...]`) – delegated to
///    [`AclRouter`] from wind-core.
/// 4. If nothing matched, forward to `"default"` outbound.
pub struct TuicRouter {
	ctx: Arc<TuicAppContext>,
	/// Handles the new `rules` field; `None` when no rules are configured.
	acl_router: Option<AclRouter>,
}

impl TuicRouter {
	pub fn new(ctx: Arc<TuicAppContext>) -> Self {
		let acl_router = if ctx.cfg.rules.is_empty() {
			None
		} else {
			// Move the parsed rules into an AclRouter.
			// We cannot move out of Arc, so we need to rebuild the Vec.
			let rules: Vec<Rule> = ctx
				.cfg
				.rules
				.iter()
				.map(|r| Rule::parse(&r.to_string()).expect("round-trip rule parse"))
				.collect();
			Some(AclRouter::new(rules, "default"))
		};
		Self { ctx, acl_router }
	}
}

impl Router for TuicRouter {
	fn route<'a>(&'a self, target: &'a TargetAddr, is_tcp: bool) -> BoxFuture<'a, eyre::Result<RouteAction>> {
		Box::pin(async move {
			let port = target.port();
			let default_ip_mode = self.ctx.cfg.outbound.default.ip_mode.unwrap_or(StackPrefer::V4first);

			// Resolve to SocketAddr for legacy ACL matching.
			let resolved = resolve_target(target, default_ip_mode).await?;

			// --- Experimental guards ---
			let exp = &self.ctx.cfg.experimental;
			if exp.drop_loopback && resolved.ip().is_loopback() {
				tracing::debug!("[router] dropping loopback connection to {}", resolved);
				return Ok(RouteAction::Reject(format!("loopback address rejected: {}", resolved)));
			}
			if exp.drop_private && is_private_ip(&resolved.ip()) {
				tracing::debug!("[router] dropping private-range connection to {}", resolved);
				return Ok(RouteAction::Reject(format!("private address rejected: {}", resolved)));
			}

			// --- Legacy ACL evaluation ---
			for rule in &self.ctx.cfg.acl {
				if rule.matching(resolved, port, is_tcp).await {
					let outbound_name = rule.outbound.as_str();
					let action = match outbound_name {
						"reject" | "block" | "deny" => RouteAction::Reject(format!("rejected by ACL rule: {}", rule)),
						"allow" | "default" => RouteAction::Forward("default".to_string()),
						name => RouteAction::Forward(name.to_string()),
					};
					return Ok(action);
				}
			}

			// --- Metacubex-style rules (via AclRouter) ---
			if let Some(acl_router) = &self.acl_router {
				return acl_router.route(target, is_tcp).await;
			}

			// No rule matched – use the default outbound.
			Ok(RouteAction::Forward("default".to_string()))
		})
	}
}

// ============================================================================
// TuicOutboundHandler – implements wind_core::OutboundAction
// ============================================================================

/// Executes a single outbound rule (direct or socks5).
pub struct TuicOutboundHandler {
	rule: OutboundRule,
}

impl TuicOutboundHandler {
	pub fn new(rule: OutboundRule) -> Self {
		Self { rule }
	}
}

impl OutboundAction for TuicOutboundHandler {
	fn handle_tcp<'a>(&'a self, target: TargetAddr, mut stream: Box<dyn AbstractTcpStream>) -> BoxFuture<'a, eyre::Result<()>> {
		Box::pin(async move {
			match self.rule.kind.as_str() {
				"socks5" => {
					let socks_addr = self
						.rule
						.addr
						.as_deref()
						.ok_or_else(|| eyre::eyre!("socks5 outbound missing 'addr'"))?;

					let socks_stream = connect_socks5_tcp(socks_addr, &target, &self.rule).await?;
					tokio::io::copy_bidirectional(&mut stream, &mut { socks_stream }).await?;
				}
				_ => {
					// "direct" and anything else treated as direct
					let ip_mode = self.rule.ip_mode.unwrap_or(StackPrefer::V4first);
					let target_sa = resolve_target(&target, ip_mode).await?;
					let mut target_stream = connect_direct_tcp(target_sa, &self.rule).await?;
					tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await?;
				}
			}

			Ok(())
		})
	}

	fn handle_udp<'a>(&'a self, udp_stream: UdpStream) -> BoxFuture<'a, eyre::Result<()>> {
		// Clone the rule fields we need into the async block.
		let rule = self.rule.clone();

		Box::pin(async move {
			let UdpStream { tx, mut rx } = udp_stream;
			let default_ip_mode = rule.ip_mode.unwrap_or(StackPrefer::V4first);

			// Bind a local UDP socket for direct relaying (reused across packets).
			let relay_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

			// Task: client → target
			let socket_send = relay_socket.clone();
			let rule_send = rule.clone();
			let send_task = tokio::spawn(async move {
				while let Some(pkt) = rx.recv().await {
					let resolved = match resolve_target(&pkt.target, default_ip_mode).await {
						Ok(sa) => sa,
						Err(err) => {
							tracing::warn!("[udp relay] resolve failed for {}: {}", pkt.target, err);
							continue;
						}
					};

					match rule_send.kind.as_str() {
						"socks5" => {
							if !rule_send.allow_udp.unwrap_or(false) {
								tracing::debug!("[udp relay] socks5 outbound disallows UDP, dropping packet to {}", resolved);
								continue;
							}
							tracing::warn!(
								"[udp relay] UDP-over-SOCKS5 is not implemented; sending directly to {}",
								resolved
							);
							if let Err(err) = socket_send.send_to(&pkt.payload, resolved).await {
								tracing::warn!("[udp relay] send failed to {}: {}", resolved, err);
							}
						}
						_ => {
							let ip_mode = rule_send.ip_mode.unwrap_or(StackPrefer::V4first);
							let target_sa = match resolve_target(&pkt.target, ip_mode).await {
								Ok(sa) => sa,
								Err(err) => {
									tracing::warn!(
										"[udp relay] resolve failed for {} with ip_mode {:?}: {}",
										pkt.target,
										ip_mode,
										err
									);
									continue;
								}
							};
							if let Err(err) = socket_send.send_to(&pkt.payload, target_sa).await {
								tracing::warn!("[udp relay] send failed to {}: {}", target_sa, err);
							}
						}
					}
				}
			});

			// Task: target → client (responses on relay socket)
			let socket_recv = relay_socket.clone();
			let recv_task = tokio::spawn(async move {
				let mut buf = vec![0u8; 65535];
				loop {
					match socket_recv.recv_from(&mut buf).await {
						Ok((len, src_addr)) => {
							use bytes::Bytes;
							let payload = Bytes::copy_from_slice(&buf[..len]);
							let pkt = UdpPacket {
								source: Some(TargetAddr::from(src_addr)),
								target: TargetAddr::from(src_addr),
								payload,
							};
							if tx.send(pkt).await.is_err() {
								break;
							}
						}
						Err(err) => {
							tracing::warn!("[udp relay] recv error: {}", err);
							break;
						}
					}
				}
			});

			tokio::select! {
				_ = send_task => {}
				_ = recv_task => {}
			}

			Ok(())
		})
	}
}

// ============================================================================
// Helpers: resolution
// ============================================================================

/// Resolve a `TargetAddr` to a single `SocketAddr` respecting the given
/// IP-stack preference.
async fn resolve_target(target: &TargetAddr, prefer: StackPrefer) -> eyre::Result<SocketAddr> {
	match target {
		TargetAddr::IPv4(ip, port) => Ok(SocketAddr::from((*ip, *port))),
		TargetAddr::IPv6(ip, port) => Ok(SocketAddr::from((*ip, *port))),
		TargetAddr::Domain(domain, port) => {
			let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", domain, port)).await?.collect();

			if addrs.is_empty() {
				return Err(eyre::eyre!("DNS returned no addresses for {}", domain));
			}

			pick_addr_by_preference(addrs, prefer)
				.ok_or_else(|| eyre::eyre!("No address matching ip_mode {:?} for {}", prefer, domain))
		}
	}
}

/// Pick the best address from a resolved list according to `StackPrefer`.
fn pick_addr_by_preference(addrs: Vec<SocketAddr>, prefer: StackPrefer) -> Option<SocketAddr> {
	let v4: Vec<SocketAddr> = addrs.iter().copied().filter(|a| a.is_ipv4()).collect();
	let v6: Vec<SocketAddr> = addrs.iter().copied().filter(|a| a.is_ipv6()).collect();

	match prefer {
		StackPrefer::V4only => v4.into_iter().next(),
		StackPrefer::V6only => v6.into_iter().next(),
		StackPrefer::V4first => v4.into_iter().next().or_else(|| v6.into_iter().next()),
		StackPrefer::V6first => v6.into_iter().next().or_else(|| v4.into_iter().next()),
	}
}

// ============================================================================
// Helpers: direct TCP connect
// ============================================================================

/// Open a direct TCP connection to `addr`, optionally binding a local
/// address/device as specified in `rule`.
async fn connect_direct_tcp(addr: SocketAddr, rule: &OutboundRule) -> eyre::Result<TcpStream> {
	let socket = match addr {
		SocketAddr::V4(_) => TcpSocket::new_v4()?,
		SocketAddr::V6(_) => TcpSocket::new_v6()?,
	};

	let bind_addr: Option<SocketAddr> = match addr {
		SocketAddr::V4(_) => rule.bind_ipv4.map(|ip| SocketAddr::V4(SocketAddrV4::new(ip, 0))),
		SocketAddr::V6(_) => rule.bind_ipv6.map(|ip| SocketAddr::V6(SocketAddrV6::new(ip, 0, 0, 0))),
	};

	if let Some(local) = bind_addr {
		socket.bind(local)?;
	}

	#[cfg(any(target_os = "linux", target_os = "android"))]
	if let Some(ref dev) = rule.bind_device {
		socket.bind_device(Some(dev.as_bytes()))?;
	}

	Ok(socket.connect(addr).await?)
}

// ============================================================================
// Helpers: SOCKS5 TCP connect
// ============================================================================

/// Connect to `target_addr` through the SOCKS5 proxy described in `rule`.
async fn connect_socks5_tcp(
	socks_addr: &str,
	target_addr: &TargetAddr,
	rule: &OutboundRule,
) -> eyre::Result<Socks5Stream<TcpStream>> {
	let config = Socks5Config::default();

	let (target_host, target_port) = match target_addr {
		TargetAddr::IPv4(ip, port) => (ip.to_string(), *port),
		TargetAddr::IPv6(ip, port) => (ip.to_string(), *port),
		TargetAddr::Domain(domain, port) => (domain.clone(), *port),
	};

	let stream = match (&rule.username, &rule.password) {
		(Some(user), Some(pass)) => {
			Socks5Stream::connect_with_password(socks_addr, target_host, target_port, user.clone(), pass.clone(), config)
				.await
				.map_err(|e| eyre::eyre!("SOCKS5 connect failed: {}", e))?
		}
		_ => Socks5Stream::connect(socks_addr, target_host, target_port, config)
			.await
			.map_err(|e| eyre::eyre!("SOCKS5 connect failed: {}", e))?,
	};

	Ok(stream)
}

// ============================================================================
// TargetAddr helper – port extraction
// ============================================================================

trait TargetAddrExt {
	fn port(&self) -> u16;
}

impl TargetAddrExt for TargetAddr {
	fn port(&self) -> u16 {
		match self {
			TargetAddr::IPv4(_, p) | TargetAddr::IPv6(_, p) | TargetAddr::Domain(_, p) => *p,
		}
	}
}

// ============================================================================
// Inbound factory
// ============================================================================

/// Creates a wind-tuic inbound and a fully-wired `Dispatcher` from
/// tuic-server configuration.
pub async fn create_inbound(ctx: Arc<TuicAppContext>) -> eyre::Result<(TuicInbound, Dispatcher<TuicRouter>)> {
	let cfg = &ctx.cfg;

	// Load or generate TLS certificate and key
	let (certs, key) = if cfg.tls.auto_ssl && crate::tls::is_valid_domain(&cfg.tls.hostname) {
		// wind-tuic takes raw cert/key; ACME via wind-acme is only supported
		// through the standalone Server path which uses a resolver.
		// Here we attempt to load existing cert files, or fall back to self-signed.
		tracing::warn!(
			"auto_ssl with wind-tuic adapter is not fully supported; \
			 attempting to load existing certs or falling back to self-signed for: {}",
			cfg.tls.hostname
		);
		let cert_path = &cfg.tls.certificate;
		let key_path = &cfg.tls.private_key;

		match load_cert_from_files(cert_path, key_path) {
			Ok(pair) => {
				tracing::info!("Loaded existing certificate from disk");
				pair
			}
			Err(_) => {
				tracing::warn!("No valid certificate found, using self-signed");
				generate_self_signed(&cfg.tls.hostname)?
			}
		}
	} else if cfg.tls.self_sign {
		generate_self_signed(&cfg.tls.hostname)?
	} else {
		load_cert_from_files(&cfg.tls.certificate, &cfg.tls.private_key)?
	};

	let opts = TuicInboundOpts {
		listen_addr: cfg.server,
		certificate: certs,
		private_key: key,
		alpn: cfg.tls.alpn.clone(),
		users: cfg.users.clone(),
		auth_timeout: cfg.auth_timeout,
		max_idle_time: cfg.quic.max_idle_time,
		max_concurrent_bi_streams: 512,
		max_concurrent_uni_streams: 512,
		send_window: cfg.quic.send_window,
		receive_window: cfg.quic.receive_window,
		zero_rtt: cfg.zero_rtt_handshake,
		initial_mtu: cfg.quic.initial_mtu,
		min_mtu: cfg.quic.min_mtu,
		gso: cfg.quic.gso,
	};

	let wind_ctx = Arc::new(AppContext::default());
	let inbound = TuicInbound::new(wind_ctx, opts);

	// Build the Dispatcher
	let router = TuicRouter::new(ctx.clone());
	let mut dispatcher = Dispatcher::new(router);

	// Register the default outbound handler
	dispatcher.add_handler("default", Arc::new(TuicOutboundHandler::new(cfg.outbound.default.clone())));

	// Register all named outbound handlers
	for (name, rule) in &cfg.outbound.named {
		dispatcher.add_handler(name.clone(), Arc::new(TuicOutboundHandler::new(rule.clone())));
	}

	Ok((inbound, dispatcher))
}

fn generate_self_signed(
	hostname: &str,
) -> eyre::Result<(
	Vec<rustls::pki_types::CertificateDer<'static>>,
	rustls::pki_types::PrivateKeyDer<'static>,
)> {
	let generated = rcgen::generate_simple_self_signed(vec![hostname.to_string()])?;
	let cert_der = rustls::pki_types::CertificateDer::from(generated.cert);
	let priv_key = rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
	Ok((vec![cert_der], rustls::pki_types::PrivateKeyDer::Pkcs8(priv_key)))
}

fn load_cert_from_files(
	cert_path: &std::path::Path,
	key_path: &std::path::Path,
) -> eyre::Result<(
	Vec<rustls::pki_types::CertificateDer<'static>>,
	rustls::pki_types::PrivateKeyDer<'static>,
)> {
	let cert_data = std::fs::read(cert_path)?;
	let key_data = std::fs::read(key_path)?;
	let certs = rustls_pemfile::certs(&mut cert_data.as_slice()).collect::<Result<Vec<_>, _>>()?;
	let key = rustls_pemfile::private_key(&mut key_data.as_slice())?
		.ok_or_else(|| eyre::eyre!("No private key found"))?;
	Ok((certs, key))
}

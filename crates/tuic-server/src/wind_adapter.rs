//! Wind framework adapter for tuic-server
//!
//! This module wires together:
//!
//! * [`TuicRouter`] – implements `wind_core::Router`.  For every incoming
//!   connection it resolves the destination, applies experimental guards, and
//!   evaluates the ACL table to pick the right named outbound.
//! * Outbound handlers from `wind-base` ([`DirectOutbound`]) and `wind-socks`
//!   ([`Socks5Action`]) perform the actual TCP/UDP relay.
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

use std::sync::Arc;

use tracing::Instrument;
use wind_base::{
	direct::{DirectOutbound, DirectOutboundOpts},
	resolve::resolve_target,
};
use wind_core::{
	AclRouter, AppContext, Dispatcher, OutboundAction, RouteAction, Router, SystemResolver,
	resolve::Resolver,
	rule::Rule,
	types::TargetAddr,
	utils::{StackPrefer, is_private_ip},
};
use wind_socks::action::{Socks5Action, Socks5ActionOpts};
use wind_tuic::{
	quiche::inbound::{TuicheInbound, TuicheInboundBuilder},
	quinn::inbound::{TuicInbound, TuicInboundOpts},
};

pub enum ServerInbound {
	Tuic(TuicInbound),
	Tuiche(TuicheInbound),
}

impl wind_core::AbstractInbound for ServerInbound {
	async fn listen(&self, cb: &impl wind_core::InboundCallback) -> eyre::Result<()> {
		match self {
			ServerInbound::Tuic(inbound) => inbound.listen(cb).await,
			ServerInbound::Tuiche(inbound) => inbound.listen(cb).await,
		}
	}
}

use crate::{AppContext as TuicAppContext, acl::acl_to_rules, config::OutboundRule};

fn make_outbound_action(rule: &OutboundRule, resolver: Arc<dyn Resolver>) -> Arc<dyn OutboundAction> {
	match rule.kind.as_str() {
		"socks5" => Arc::new(Socks5Action::new(Socks5ActionOpts {
			addr: rule.addr.clone().unwrap_or_default(),
			username: rule.username.clone(),
			password: rule.password.clone(),
			allow_udp: rule.allow_udp,
		})),
		_ => Arc::new(DirectOutbound::new(
			DirectOutboundOpts {
				bind_ipv4: rule.bind_ipv4,
				bind_ipv6: rule.bind_ipv6,
				bind_device: rule.bind_device.clone(),
			},
			resolver,
		)),
	}
}

pub struct TuicRouter {
	ctx: Arc<TuicAppContext>,
	resolver: Arc<dyn Resolver>,
	acl_router: Option<AclRouter>,
}

impl TuicRouter {
	pub fn new(ctx: Arc<TuicAppContext>, resolver: Arc<dyn Resolver>) -> Self {
		let converted = acl_to_rules(&ctx.cfg.acl);

		let explicit: Vec<Rule> = ctx
			.cfg
			.rules
			.iter()
			.map(|r| Rule::parse(&r.to_string()).expect("round-trip rule parse"))
			.collect();

		let all_rules: Vec<Rule> = converted.into_iter().chain(explicit).collect();

		let acl_router = if all_rules.is_empty() {
			None
		} else {
			if !ctx.cfg.acl.is_empty() {
				tracing::info!(
					"[router] converted {} legacy ACL rule(s) to Metacubex format",
					ctx.cfg.acl.len()
				);
			}
			Some(AclRouter::new(all_rules, "default"))
		};

		Self {
			ctx,
			resolver,
			acl_router,
		}
	}
}

impl Router for TuicRouter {
	async fn route(&self, target: &TargetAddr, is_tcp: bool) -> eyre::Result<RouteAction> {
		let span = tracing::debug_span!("route", target = %target, proto = if is_tcp { "tcp" } else { "udp" });
		self.do_route(target, is_tcp).instrument(span).await
	}
}

impl TuicRouter {
	async fn do_route(&self, target: &TargetAddr, is_tcp: bool) -> eyre::Result<RouteAction> {
		let exp = &self.ctx.cfg.experimental;
		let need_resolve = exp.drop_loopback || exp.drop_private;

		if need_resolve {
			let resolved = resolve_target(target, self.resolver.as_ref()).await?;
			if exp.drop_loopback && resolved.ip().is_loopback() {
				tracing::debug!(resolved = %resolved, "dropping loopback connection");
				return Ok(RouteAction::Reject(format!("loopback address rejected: {}", resolved)));
			}
			if exp.drop_private && is_private_ip(&resolved.ip()) {
				tracing::debug!(resolved = %resolved, "dropping private-range connection");
				return Ok(RouteAction::Reject(format!("private address rejected: {}", resolved)));
			}
		}

		if let Some(acl_router) = &self.acl_router {
			return acl_router.route(target, is_tcp).await;
		}

		Ok(RouteAction::Forward("default".to_string()))
	}
}


pub async fn create_inbound(ctx: Arc<TuicAppContext>) -> eyre::Result<(ServerInbound, Dispatcher<TuicRouter>)> {
	let cfg = &ctx.cfg;

	let mut cert_resolver = None;
	let (certs, key) = if cfg.tls.auto_ssl && crate::tls::is_valid_domain(&cfg.tls.hostname) {
		tracing::info!(
			"auto_ssl enabled, starting ACME management for: {} (staging: {})",
			cfg.tls.hostname,
			cfg.tls.acme_staging
		);
		let cache_dir = std::path::Path::new("acme-cache");
		let resolver = wind_acme::start_acme(
			ctx.cancel.child_token(),
			&cfg.tls.hostname,
			&cfg.tls.acme_email,
			cache_dir,
			!cfg.tls.acme_staging,
		)
		.await?;
		cert_resolver = Some(resolver);
		(vec![], rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into()))
	} else if cfg.tls.self_sign {
		generate_self_signed(&cfg.tls.hostname)?
	} else {
		load_cert_from_files(&cfg.tls.certificate, &cfg.tls.private_key)?
	};

	// Derive the wind-core token from the tuic-server cancel token so a single
	// `cancel()` from the binary's signal handler tears down the listen loop
	// AND every spawned inbound task (each wind_ctx.tasks-tracked task uses a
	// child of `wind_ctx.token`). Previously `wind_ctx` was an independent
	// `AppContext::default()`, so ctrl-c would return from `main` while the
	// listen loop was still alive in the background — quinn's connections
	// stayed up and log guards never flushed.
	let wind_ctx = Arc::new(AppContext {
		tasks: tokio_util::task::TaskTracker::new(),
		token: ctx.cancel.child_token(),
	});

	let default_ip_mode = cfg.outbound.default.ip_mode.unwrap_or(StackPrefer::V4first);
	let resolver: Arc<dyn Resolver> = match wind_dns::build(&cfg.dns)? {
		Some(hickory) => {
			tracing::info!("[dns] using {:?} resolver", cfg.dns.mode);
			Arc::new(hickory)
		}
		None => {
			tracing::info!("[dns] using system resolver");
			Arc::new(SystemResolver::new(default_ip_mode))
		}
	};

	let inbound = if cfg.backend == "tuiche" {
		tracing::info!("Initializing wind-tuiche backend (experimental)");
		let mut builder = TuicheInboundBuilder::new()
			.listen_addr(cfg.server)
			.max_idle_time(cfg.quic.max_idle_time);
		for (uuid, pwd) in &cfg.users {
			builder = builder.user(*uuid, pwd.clone());
		}
		ServerInbound::Tuiche(builder.build().await?)
	} else {
		let opts = TuicInboundOpts {
			listen_addr: cfg.server,
			certificate: certs,
			private_key: key,
			cert_resolver,
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
		ServerInbound::Tuic(TuicInbound::new(wind_ctx, opts))
	};

	let router = TuicRouter::new(ctx.clone(), resolver.clone());
	let mut dispatcher = Dispatcher::new(router);

	dispatcher.add_handler("default", make_outbound_action(&cfg.outbound.default, resolver.clone()));

	for (name, rule) in &cfg.outbound.named {
		dispatcher.add_handler(name.clone(), make_outbound_action(rule, resolver.clone()));
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
	let key = rustls_pemfile::private_key(&mut key_data.as_slice())?.ok_or_else(|| eyre::eyre!("No private key found"))?;
	Ok((certs, key))
}

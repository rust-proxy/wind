//! Wind framework [`Plugin`] for the wind binary.
//!
//! Assembles the configured outbounds (tuic / naive / load-balance), the
//! default router, and the SOCKS5 inbound into a single composable [`App`]
//! via [`wind_core::App`], matching how tuic-server / tuic-client wire their
//! runtimes.

use std::{collections::HashMap, sync::Arc, time::Duration};

use tracing::info;
use wind_base::load_balance::{LoadBalanceOpts, LoadBalanceOutbound, LoadBalanceStrategy};
use wind_core::{App, AppContext, InboundHooks, Outbound, Plugin, Router};
use wind_naive::NaiveOutbound;
use wind_socks::inbound::SocksInbound;
use wind_tuic::quinn::outbound::TuicOutbound;

use crate::conf::runtime::{Config, InboundOpts, OutboundOpts};

/// Router — always forwards to the first outbound (TODO: ACL rules).
#[derive(Clone)]
pub struct DefaultRouter {
	pub default: String,
}

impl Router for DefaultRouter {
	#[allow(clippy::manual_async_fn)]
	fn route(
		&self,
		_ctx: &wind_core::FlowContext,
	) -> impl std::future::Future<Output = eyre::Result<wind_core::RouteAction>> + Send {
		async move { Ok(wind_core::RouteAction::Forward(self.default.clone())) }
	}
}

/// The application-level router: a closed set of routing policies for the wind
/// binary. Dispatched statically (hand-written `match`, no vtable).
#[derive(Clone)]
pub enum WindRouter {
	Default(DefaultRouter),
}

#[allow(clippy::manual_async_fn)]
impl Router for WindRouter {
	fn route(
		&self,
		ctx: &wind_core::FlowContext,
	) -> impl std::future::Future<Output = eyre::Result<wind_core::RouteAction>> + Send {
		async move {
			match self {
				WindRouter::Default(r) => r.route(ctx).await,
			}
		}
	}
}

/// Wind framework plugin that wires the configured runtime.
pub struct WindPlugin {
	cfg: Config,
}

impl WindPlugin {
	pub fn new(cfg: Config) -> Self {
		Self { cfg }
	}
}

impl Plugin<WindRouter> for WindPlugin {
	async fn build(self, app: App<WindRouter>) -> eyre::Result<App<WindRouter>> {
		let ctx = app.context().clone();

		// Two-phase construction:
		//  1. Build regular outbounds (tuic, naive) and stash them by tag.
		//  2. Build load-balance outbounds, resolving child proxy tags from the map
		//     built in phase 1.
		let mut handlers: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
		let mut lb_configs: Vec<(String, crate::conf::runtime::LoadBalanceRuntimeOpts)> = Vec::new();
		if self.cfg.outbounds.is_empty() {
			return Err(eyre::eyre!(
				"WindPlugin: no outbounds configured; add at least one outbound so the router has a target"
			));
		}
		let default_tag = self
			.cfg
			.outbounds
			.first()
			.map(|o| o.tag.clone())
			.unwrap_or_else(|| "default".into());

		for ob in self.cfg.outbounds {
			let tag = ob.tag;
			match ob.opts {
				OutboundOpts::Tuic(opts) => {
					let out = TuicOutbound::new(ctx.clone(), opts).await?;
					handlers.insert(tag.clone(), Arc::new(out));
					info!(target: "wind_boot", "outbound '{tag}' [tuic]");
				}
				OutboundOpts::Naive(opts) => {
					let out = NaiveOutbound::new(opts).await?;
					handlers.insert(tag.clone(), Arc::new(out));
					info!(target: "wind_boot", "outbound '{tag}' [naive]");
				}
				OutboundOpts::LoadBalance(lb) => {
					lb_configs.push((tag, lb));
				}
			}
		}

		for (tag, lb) in lb_configs {
			let children: Vec<Arc<dyn Outbound>> = {
				lb.proxy_tags
					.iter()
					.map(|t| {
						handlers.get(t).cloned().ok_or_else(|| {
							eyre::eyre!(
								"load-balance '{tag}' references unknown proxy '{t}'; proxies must be declared before the \
								 load-balance group"
							)
						})
					})
					.collect::<eyre::Result<Vec<_>>>()?
			};

			let strategy = parse_strategy(&lb.strategy_str)?;
			let opts = LoadBalanceOpts {
				strategy,
				url: lb.url,
				interval: Duration::from_secs(lb.interval_secs),
				lazy: lb.lazy,
			};

			let lb_out = LoadBalanceOutbound::new(opts, children);
			let lb_arc = Arc::new(lb_out);
			if !lb.lazy {
				lb_arc.start_health_check(Duration::from_secs(lb.interval_secs));
			}
			handlers.insert(tag.clone(), lb_arc);
			info!(target: "wind_boot", "outbound '{tag}' [load-balance]");
		}

		let mut app = app.set_router(WindRouter::Default(DefaultRouter { default: default_tag }));
		for (name, handler) in handlers {
			app = app.add_outbound(name, handler);
		}

		// Inbounds: materialized with the finalized hooks bundle + shared ctx.
		for ib in self.cfg.inbounds {
			let tag = ib.tag;
			match ib.opts {
				InboundOpts::Socks(opts) => {
					let listen_addr = opts.listen_addr;
					app = app.add_inbound_with(move |hooks: InboundHooks, ctx: Arc<AppContext>| {
						let mut opts = opts;
						opts.hooks = hooks;
						SocksInbound::new(opts, ctx.token.child_token())
					});
					info!(target: "wind_boot", "inbound '{tag}' [socks] ({listen_addr})");
				}
			}
		}

		Ok(app)
	}
}

fn parse_strategy(s: &str) -> eyre::Result<LoadBalanceStrategy> {
	match s.to_ascii_lowercase().as_str() {
		"round-robin" | "round_robin" | "rr" => Ok(LoadBalanceStrategy::RoundRobin),
		"consistent-hashing" | "consistent_hashing" | "ch" => Ok(LoadBalanceStrategy::ConsistentHashing),
		"sticky-sessions" | "sticky_sessions" | "ss" => Ok(LoadBalanceStrategy::StickySessions),
		other => Err(eyre::eyre!(
			"unknown load-balance strategy '{other}'; expected one of: round-robin, consistent-hashing, sticky-sessions"
		)),
	}
}

#[cfg(test)]
mod tests {
	use wind_core::{FlowContext, RouteAction, rule::NetworkType, types::TargetAddr};

	use super::*;

	#[tokio::test]
	async fn wind_router_forwards_to_configured_default() {
		let router = WindRouter::Default(DefaultRouter {
			default: "main".to_string(),
		});
		let ctx = FlowContext {
			target: TargetAddr::Domain("example.com".into(), 443),
			network: NetworkType::Tcp,
			source: None,
			inbound_tag: "socks".into(),
			protocol: wind_core::Protocol::Socks5,
			user: None,
			inbound_port: None,
			inbound_type: None,
		};
		let action = router.route(&ctx).await.unwrap();
		assert!(matches!(action, RouteAction::Forward(name) if name == "main"));
	}

	#[test]
	fn parse_strategy_covers_known_aliases() {
		assert!(parse_strategy("round-robin").is_ok());
		assert!(parse_strategy("consistent_hashing").is_ok());
		assert!(parse_strategy("ss").is_ok());
		assert!(parse_strategy("bogus").is_err());
	}
}

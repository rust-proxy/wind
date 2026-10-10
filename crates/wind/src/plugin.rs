//! Wind framework [`Plugin`] for the wind binary.
//!
//! Assembles the configured outbounds (socks / tuic / naive / load-balance),
//! the default router, and SOCKS5 / tunnel inbounds into a single composable
//! [`App`] via [`wind_core::App`], matching how tuic-server / tuic-client wire
//! their runtimes.

use std::{collections::HashMap, sync::Arc};

use tracing::info;
use wind_base::{
	load_balance::{LoadBalanceOpts, LoadBalanceOutbound},
	tunnel::{TunnelTcpInbound, TunnelUdpInbound},
};
use wind_core::{AbstractInbound, App, AppContext, Dispatcher, InboundHooks, Outbound, Plugin, Router, RunningInbound};
use wind_naive::NaiveOutbound;
use wind_socks::{action::SocksOutbound, inbound::SocksInbound};
use wind_tuic::quinn::outbound::TuicOutbound;

use crate::conf::{
	persistent::{TunnelInboundConfig, TunnelNetwork},
	resolved::{ResolvedConfig, ResolvedInboundOpts, ResolvedOutbound},
};

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
///
/// SOCKS outbounds and their fixed tunnels are started before eager transport
/// setup. Remaining outbounds follow [`ResolvedConfig`] dependency order, so
/// a load-balance group always finds its child proxies already registered.
pub struct WindPlugin {
	cfg: ResolvedConfig,
}

impl WindPlugin {
	pub fn new(cfg: ResolvedConfig) -> Self {
		Self { cfg }
	}
}

impl Plugin<WindRouter> for WindPlugin {
	async fn build(self, mut app: App<WindRouter>) -> eyre::Result<App<WindRouter>> {
		let ctx = app.context().clone();

		let mut handlers: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
		let (socks, other): (Vec<_>, Vec<_>) = self
			.cfg
			.outbounds
			.into_iter()
			.partition(|ob| matches!(ob, ResolvedOutbound::Socks { .. }));
		for ob in socks {
			if let ResolvedOutbound::Socks { tag, opts, udp } = ob {
				let out = SocksOutbound::new(opts).with_udp_options(udp, ctx.token.clone())?;
				handlers.insert(tag, Arc::new(out));
			}
		}
		let mut inbounds = Vec::new();
		for ib in self.cfg.inbounds {
			if let ResolvedInboundOpts::Tunnel(ref tunnel) = ib.opts
				&& let Some(name) = &ib.outbound
				&& let Some(outbound) = handlers.get(name)
			{
				let scope = Arc::new(AppContext {
					tasks: ctx.tasks.clone(),
					token: ctx.token.child_token(),
				});
				let inbound = bind_tunnel(tunnel, scope.token.clone())?;
				let mut dispatcher =
					Dispatcher::new(WindRouter::Default(DefaultRouter { default: name.clone() })).context(scope.clone());
				dispatcher.add_handler(name.clone(), outbound.clone());
				app = app.own_running_inbound(RunningInbound::start(scope, inbound, dispatcher.with_outbound(name.clone())?));
				continue;
			}
			inbounds.push(ib);
		}
		for ob in other {
			match ob {
				ResolvedOutbound::Socks { .. } => {
					return Err(eyre::eyre!("SOCKS outbound was not built in the transport phase"));
				}
				ResolvedOutbound::Tuic { tag, opts } => {
					let out = TuicOutbound::new(ctx.clone(), opts).await?;
					out.start_poll().await?;
					handlers.insert(tag.clone(), Arc::new(out));
					info!(target: "wind_boot", "outbound '{tag}' [tuic]");
				}
				ResolvedOutbound::Naive { tag, opts } => {
					let out = NaiveOutbound::new(opts).await?;
					handlers.insert(tag.clone(), Arc::new(out));
					info!(target: "wind_boot", "outbound '{tag}' [naive]");
				}
				ResolvedOutbound::LoadBalance { tag, opts } => {
					// Reference existence and ordering are guaranteed by
					// `ResolvedConfig`; the defensive error below is a
					// fail-safe, not a user-facing path.
					let children: Vec<Arc<dyn Outbound>> = opts
						.proxies
						.iter()
						.map(|t| {
							handlers.get(t).cloned().ok_or_else(|| {
								eyre::eyre!(
									"load-balance '{tag}' references proxy '{t}' that is not yet built (internal ordering \
									 error)"
								)
							})
						})
						.collect::<eyre::Result<Vec<_>>>()?;

					let lb_out = LoadBalanceOutbound::new(
						LoadBalanceOpts {
							strategy: opts.strategy,
							url: opts.url,
							interval: opts.interval,
							lazy: opts.lazy,
						},
						children,
					);
					let lb_arc = Arc::new(lb_out);
					// The outbound itself decides whether to probe: it is a
					// no-op for `lazy` groups.
					lb_arc.start_health_check();
					handlers.insert(tag.clone(), lb_arc);
					info!(target: "wind_boot", "outbound '{tag}' [load-balance]");
				}
			}
		}

		let mut app = app.set_router(WindRouter::Default(DefaultRouter {
			default: self.cfg.default_tag,
		}));
		for (name, handler) in handlers {
			app = app.add_outbound(name, handler);
		}

		// Inbounds: materialized with the finalized hooks bundle + shared ctx.
		for ib in inbounds {
			let tag = ib.tag;
			match ib.opts {
				ResolvedInboundOpts::Tunnel(tunnel) => {
					let inbound = bind_tunnel(&tunnel, ctx.token.child_token())?;
					let factory = move |_: InboundHooks, _: Arc<AppContext>| inbound;
					app = match ib.outbound {
						Some(name) => app.add_inbound_with_outbound(name, factory),
						None => app.add_inbound_with(factory),
					};
				}
				ResolvedInboundOpts::Socks(opts) => {
					let listen_addr = opts.listen_addr;
					let factory = move |hooks: InboundHooks, ctx: Arc<AppContext>| {
						let mut opts = opts;
						opts.hooks = hooks;
						SocksInbound::new(opts, ctx.token.child_token())
					};
					app = match ib.outbound {
						Some(name) => app.add_inbound_with_outbound(name, factory),
						None => app.add_inbound_with(factory),
					};
					info!(target: "wind_boot", "inbound '{tag}' [socks] ({listen_addr})");
				}
			}
		}

		Ok(app)
	}
}

// Materialize before network setup so listener ports stay reserved on success
// and are released automatically when a later construction step fails.
enum BoundTunnel {
	Tcp(TunnelTcpInbound),
	Udp(TunnelUdpInbound),
}

fn bind_tunnel(config: &TunnelInboundConfig, cancel: tokio_util::sync::CancellationToken) -> eyre::Result<BoundTunnel> {
	Ok(match config.network {
		TunnelNetwork::Tcp => BoundTunnel::Tcp(
			TunnelTcpInbound::from_socket(
				std::net::TcpListener::bind(config.listen_addr)?,
				config.remote_addr.clone(),
				cancel,
			)?
			.with_tag(config.tag.clone()),
		),
		TunnelNetwork::Udp => BoundTunnel::Udp(
			TunnelUdpInbound::from_socket(
				std::net::UdpSocket::bind(config.listen_addr)?,
				config.remote_addr.clone(),
				config.timeout,
				cancel,
			)?
			.with_tag(config.tag.clone()),
		),
	})
}

#[async_trait::async_trait]
impl<R: Router> AbstractInbound<R> for BoundTunnel {
	async fn listen(&self, cb: &Dispatcher<R>) -> eyre::Result<()> {
		match self {
			Self::Tcp(inbound) => inbound.listen(cb).await,
			Self::Udp(inbound) => inbound.listen(cb).await,
		}
	}
}

#[cfg(test)]
mod tests {
	use wind_core::{FlowContext, RouteAction, rule::NetworkType, types::TargetAddr};

	use super::*;

	#[tokio::test]
	async fn fixed_socks_tunnel_runs_during_eager_setup_and_releases_on_cancel() -> eyre::Result<()> {
		use std::time::Duration;

		use tokio::{
			io::{AsyncReadExt, AsyncWriteExt},
			net::{TcpListener, UdpSocket},
		};

		let socks = TcpListener::bind("127.0.0.1:0").await?;
		let relay = UdpSocket::bind("127.0.0.1:0").await?;
		let reservation = std::net::UdpSocket::bind("127.0.0.1:0")?;
		let tunnel_addr = reservation.local_addr()?;
		let config = format!(
			r#"
inbounds:
  - type: tunnel
    tag: transport
    listen_addr: {tunnel_addr}
    remote_addr: proxy-only.invalid:443
    network: udp
    outbound: upstream
outbounds:
  - type: tuic
    tag: default
    server_addr: {tunnel_addr}
    sni: proxy-only.invalid
    uuid: 00000000-0000-0000-0000-000000000000
    password: test-only
    skip_cert_verify: true
  - type: socks
    tag: upstream
    server_addr: {}
    allow_udp: true
"#,
			socks.local_addr()?
		);
		let config = ResolvedConfig::try_from(serde_yaml::from_str::<crate::conf::persistent::PersistentConfig>(&config)?)?;
		let app = App::<WindRouter>::new();
		let ctx = app.context().clone();
		drop(reservation);
		{
			let build = app.add_plugin(WindPlugin::new(config));
			tokio::pin!(build);
			let observe = async {
				let (mut control, _) = socks.accept().await?;
				let mut greeting = [0; 2];
				control.read_exact(&mut greeting).await?;
				assert_eq!(greeting[0], 5);
				let mut methods = vec![0; usize::from(greeting[1])];
				control.read_exact(&mut methods).await?;
				assert!(methods.contains(&0));
				control.write_all(&[5, 0]).await?;
				let mut request = [0; 10];
				control.read_exact(&mut request).await?;
				assert_eq!(&request[..4], &[5, 3, 0, 1]);
				let mut response = vec![5, 0, 0, 1, 127, 0, 0, 1];
				response.extend_from_slice(&relay.local_addr()?.port().to_be_bytes());
				control.write_all(&response).await?;
				let mut packet = [0; 65536];
				let (size, _) = relay.recv_from(&mut packet).await?;
				assert_eq!(&packet[..4], &[0, 0, 0, 3]);
				let name_len = usize::from(packet[4]);
				assert_eq!(&packet[5..5 + name_len], b"proxy-only.invalid");
				assert!(size > 7 + name_len, "expected QUIC handshake payload");
				eyre::Ok(())
			};
			tokio::select! {
				result = &mut build => eyre::bail!("eager construction ended before proxy received QUIC: {:?}", result.err()),
				result = tokio::time::timeout(Duration::from_secs(5), observe) => result??,
			}
			// Cancelling an in-progress build drops its early listener guard.
		}
		tokio::time::timeout(Duration::from_secs(3), async {
			while !ctx.tasks.is_empty() {
				tokio::task::yield_now().await;
			}
		})
		.await?;
		assert!(!ctx.token.is_cancelled());
		let _released = std::net::UdpSocket::bind(tunnel_addr)?;
		Ok(())
	}

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
}

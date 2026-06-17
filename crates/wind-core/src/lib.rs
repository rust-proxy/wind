pub mod app;
pub mod dispatcher;
pub mod hooks;
pub mod inbound;
mod interface;
pub mod io;
mod outbound;
pub mod resolve;
pub mod rule;
pub mod types;

pub use app::{App, Plugin};
pub use dispatcher::{AclRouter, Dispatcher, OutboundAction, RouteAction, Router};
pub use hooks::{
	ConnInfo, ConnectDecision, ConnectionHooks, InboundHooks, Protocol, StatsCollector, StaticTuicAuth, StaticUserPass,
	TrafficSink, TuicAuthenticator, UserId, UserPassAuthenticator, UserTraffic,
};
pub use inbound::*;
pub use interface::*;
pub use outbound::*;
pub use resolve::{Resolver, SystemResolver};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub mod quic;
pub mod tcp;
pub mod udp;
pub mod utils;

pub use quic::{QuicCongestionControl, parse_congestion_control};
pub use utils::{StackPrefer, is_private_ip};

#[cfg(test)]
mod udp_tests;

pub struct AppContext {
	pub tasks: TaskTracker,
	pub token: CancellationToken,
}

impl Default for AppContext {
	fn default() -> Self {
		Self {
			tasks: TaskTracker::new(),
			token: CancellationToken::new(),
		}
	}
}

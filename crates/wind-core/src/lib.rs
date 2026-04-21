pub mod dispatcher;
pub mod inbound;
mod interface;
pub mod io;
mod outbound;
pub mod resolve;
pub mod rule;
pub mod types;

pub use dispatcher::{AclRouter, Dispatcher, OutboundAction, RouteAction, Router};
pub use inbound::*;
pub use interface::*;
pub use outbound::*;
pub use resolve::{Resolver, SystemResolver};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub mod log;

pub mod tcp;
pub mod udp;
pub mod utils;

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

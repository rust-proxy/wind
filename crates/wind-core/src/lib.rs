#![feature(impl_trait_in_fn_trait_return)]
#![feature(type_alias_impl_trait)]
#![feature(trait_alias)]

pub mod dispatcher;
pub mod inbound;
mod interface;
pub mod io;
mod outbound;
pub mod types;

pub use dispatcher::{Dispatcher, OutboundAction, RouteAction, Router};
pub use inbound::*;
pub use interface::*;
pub use outbound::*;
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

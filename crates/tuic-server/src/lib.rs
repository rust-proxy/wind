use std::sync::Arc;

use tokio_util::sync::CancellationToken;
// The Hysteria ACL types/parsers live in `wind-acl`'s apernet syntax
// module; re-export it as `acl` so existing `crate::acl::*` paths keep
// resolving.
pub use wind_acl::syntax::apernet as acl;
use wind_core::AbstractInbound;
pub mod compat;
pub mod config;
pub mod error;
pub mod log;
pub mod tls;
pub mod utils;
pub mod wind_adapter;

pub use config::{Cli, Config, Control};

pub struct AppContext {
	pub cfg: Config,
	pub cancel: CancellationToken,
}

/// Run the TUIC server with the given configuration (using wind-tuic).
///
/// Constructs its own [`CancellationToken`] internally; callers that want to
/// drive a graceful shutdown from outside should use [`run_with_cancel`].
pub async fn run(cfg: Config) -> eyre::Result<()> {
	run_with_cancel(cfg, CancellationToken::new()).await
}

/// Run the TUIC server with a caller-owned cancel token.
///
/// Cancelling `cancel` causes the listen loop to exit and every spawned
/// connection/UDP-session handler to wind down via its child token. Pair with
/// `tokio::select!` on `ctrl_c()` so signal-triggered shutdown is graceful
/// instead of relying on runtime drop.
pub async fn run_with_cancel(cfg: Config, cancel: CancellationToken) -> eyre::Result<()> {
	let ctx = Arc::new(AppContext { cancel, cfg });

	let (inbound, adapter) = wind_adapter::create_inbound(ctx).await?;

	tracing::info!("Starting TUIC server");

	inbound.listen(&adapter).await
}

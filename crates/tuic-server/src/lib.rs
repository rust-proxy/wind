// Library interface for tuic-server
// This allows the server to be used as a library in integration tests

use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use wind_core::AbstractInbound;

pub mod acl;
pub mod compat;
pub mod config;
pub mod error;
pub mod io;
pub mod server;
pub mod tls;
pub mod utils;
pub mod wind_adapter;

pub use config::{Cli, Config, Control};

pub struct AppContext {
	pub cfg: Config,
	pub cancel: CancellationToken,
}

/// Run the TUIC server with the given configuration (using wind-tuic)
pub async fn run(cfg: Config) -> eyre::Result<()> {
	let ctx = Arc::new(AppContext {
		cancel: CancellationToken::new(),
		cfg,
	});

	// Create wind-tuic inbound and adapter
	let (inbound, adapter) = wind_adapter::create_inbound(ctx).await?;

	tracing::info!("Starting TUIC server with wind-tuic backend");

	// Start the server
	inbound.listen(&adapter).await
}

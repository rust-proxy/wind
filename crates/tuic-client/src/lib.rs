// Library interface for tuic-client
// This allows the client to be used as a library in integration tests

use std::sync::Arc;

use wind_core::AppContext;

pub mod config;
pub mod error;
pub mod forward;
pub mod socks5;
pub mod utils;
pub mod wind_adapter;

pub use config::Config;

/// Run the TUIC client with the given configuration (using wind-tuic)
pub async fn run(cfg: Config) -> eyre::Result<()> {
	// Initialize wind-tuic connection
	let ctx = Arc::new(AppContext::default());
	let _adapter = wind_adapter::create_connection(ctx, cfg.relay).await?;

	tracing::info!("TUIC client initialized with wind-tuic backend");

	// Start forwarders
	forward::start(cfg.local.tcp_forward.clone(), cfg.local.udp_forward.clone()).await;

	// Start SOCKS5 server
	match socks5::Server::set_config(cfg.local) {
		Ok(()) => {}
		Err(err) => {
			return Err(err.into());
		}
	}

	socks5::Server::start().await;
	Ok(())
}

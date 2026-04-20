use std::process;

use clap::Parser;
#[cfg(feature = "jemallocator")]
use tikv_jemallocator::Jemalloc;
use tuic_server::config::{Cli, Control, EnvState, parse_config};

#[cfg(feature = "jemallocator")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> eyre::Result<()> {
	#[cfg(feature = "aws-lc-rs")]
	{
		_ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	}

	#[cfg(feature = "ring")]
	{
		_ = rustls::crypto::ring::default_provider().install_default();
	}
	let cli = Cli::parse();
	let env_state = EnvState::from_system();
	let cfg = match parse_config(cli, env_state).await {
		Ok(cfg) => cfg,
		Err(err) => {
			// Check if it's a Control error (Help or Version)
			if let Some(control) = err.downcast_ref::<Control>() {
				println!("{}", control);
				process::exit(0);
			}
			return Err(err);
		}
	};
	let _guards = tuic_server::log::init(&cfg)?;
	tokio::select! {
		res = tuic_server::run(cfg) => {
			if let Err(err) = res {
				tracing::error!("Server exited with error: {err}");
				return Err(err);
			}
		}
		res = tokio::signal::ctrl_c() => {
			if let Err(err) = res {
				tracing::error!("Failed to listen for Ctrl-C: {err}");
				return Err(eyre::eyre!("Failed to listen for Ctrl-C: {err}"));
			} else {
				tracing::info!("Received Ctrl-C, shutting down.");
			}
		}
	}
	Ok(())
}

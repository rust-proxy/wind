//! Wind framework adapter for tuic-client
//!
//! This module provides integration between the original tuic-client logic
//! and the wind-tuic implementation.

use std::{net::SocketAddr, sync::Arc};

use once_cell::sync::OnceCell;
use wind_core::{AbstractOutbound, AppContext, tcp::AbstractTcpStream, types::TargetAddr, udp::UdpStream};
use wind_tuic::outbound::{TuicOutbound, TuicOutboundOpts};

use crate::config::Relay;

// Global wind-tuic connection
static WIND_CONNECTION: OnceCell<TuicOutboundAdapter> = OnceCell::new();

/// Wind-tuic outbound wrapper for tuic-client
pub struct TuicOutboundAdapter {
	pub outbound: TuicOutbound,
}

impl TuicOutboundAdapter {
	pub async fn new(ctx: Arc<AppContext>, relay: Relay) -> eyre::Result<Self> {
		// Parse server address
		let server_addr = if let Some(ip) = relay.ip {
			SocketAddr::new(ip, relay.server.1)
		} else {
			// Resolve domain
			let addrs = tokio::net::lookup_host(format!("{}:{}", relay.server.0, relay.server.1)).await?;
			addrs
				.into_iter()
				.next()
				.ok_or_else(|| eyre::eyre!("Failed to resolve server address"))?
		};

		// Convert password to Arc<[u8]>
		let password: Arc<[u8]> = relay.password.clone();

		// Create wind-tuic outbound options
		let opts = TuicOutboundOpts {
			peer_addr: server_addr,
			sni: relay.sni.unwrap_or_else(|| relay.server.0.clone()),
			auth: (relay.uuid, password),
			zero_rtt_handshake: relay.zero_rtt_handshake,
			heartbeat: relay.heartbeat,
			gc_interval: relay.gc_interval,
			gc_lifetime: relay.gc_lifetime,
			skip_cert_verify: relay.skip_cert_verify,
			alpn: relay
				.alpn
				.into_iter()
				.map(|v| String::from_utf8_lossy(&v).to_string())
				.collect(),
		};

		// Create outbound
		let outbound = TuicOutbound::new(ctx, opts).await?;

		// Start polling
		outbound.start_poll().await?;

		Ok(Self { outbound })
	}
}

impl AbstractOutbound for TuicOutboundAdapter {
	async fn handle_tcp(
		&self,
		target_addr: TargetAddr,
		stream: impl AbstractTcpStream,
		_dialer: Option<impl AbstractOutbound>,
	) -> eyre::Result<()> {
		self.outbound
			.handle_tcp(target_addr, stream, None::<TuicOutboundAdapter>)
			.await
	}

	async fn handle_udp(&self, udp_stream: UdpStream, _dialer: Option<impl AbstractOutbound>) -> eyre::Result<()> {
		self.outbound.handle_udp(udp_stream, None::<TuicOutboundAdapter>).await
	}
}

impl TuicOutboundAdapter {
	/// Get the global wind-tuic connection
	pub fn get() -> Option<&'static Self> {
		WIND_CONNECTION.get()
	}

	/// Initialize the global wind-tuic connection
	pub fn set_global(adapter: Self) -> Result<(), Self> {
		WIND_CONNECTION.set(adapter)
	}
}

/// Create a new TUIC connection using wind-tuic and set it as global
pub async fn create_connection(ctx: Arc<AppContext>, relay: Relay) -> eyre::Result<()> {
	let adapter = TuicOutboundAdapter::new(ctx, relay).await?;
	TuicOutboundAdapter::set_global(adapter).map_err(|_| eyre::eyre!("Failed to set global wind-tuic connection"))?;
	Ok(())
}

/// Get the global wind-tuic connection
pub fn get_connection() -> Option<&'static TuicOutboundAdapter> {
	TuicOutboundAdapter::get()
}

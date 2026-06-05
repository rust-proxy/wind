//! Utility functions and types for wind-tuiche

use std::time::Duration;

/// Congestion control algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionControl {
	#[default]
	Cubic,
	Bbr,
	Reno,
}

impl From<CongestionControl> for &str {
	fn from(cc: CongestionControl) -> Self {
		match cc {
			CongestionControl::Cubic => "cubic",
			CongestionControl::Bbr => "bbr",
			CongestionControl::Reno => "reno",
		}
	}
}

/// UDP relay mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UdpRelayMode {
	#[default]
	Datagram,
	Stream,
}

/// Connection options
#[derive(Debug, Clone)]
pub struct ConnectionOpts {
	/// Maximum idle timeout
	pub max_idle_timeout: Duration,
	/// Maximum concurrent bidirectional streams
	pub max_concurrent_bi_streams: u64,
	/// Maximum concurrent unidirectional streams
	pub max_concurrent_uni_streams: u64,
	/// Send window size
	pub send_window: u64,
	/// Receive window size
	pub receive_window: u64,
	/// Congestion control algorithm
	pub congestion_control: CongestionControl,
	/// UDP relay mode
	pub udp_relay_mode: UdpRelayMode,
	/// Enable 0-RTT
	pub enable_0rtt: bool,
}

impl Default for ConnectionOpts {
	fn default() -> Self {
		Self {
			max_idle_timeout: Duration::from_secs(30),
			max_concurrent_bi_streams: 100,
			max_concurrent_uni_streams: 100,
			send_window: 8 * 1024 * 1024,    // 8 MB
			receive_window: 8 * 1024 * 1024, // 8 MB
			congestion_control: CongestionControl::default(),
			udp_relay_mode: UdpRelayMode::default(),
			enable_0rtt: true,
		}
	}
}

/// Connection statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
	/// Total bytes sent
	pub bytes_sent: u64,
	/// Total bytes received
	pub bytes_received: u64,
	/// Packets sent
	pub packets_sent: u64,
	/// Packets received
	pub packets_received: u64,
	/// Lost packets
	pub packets_lost: u64,
	/// Retransmitted packets
	pub packets_retransmitted: u64,
}

// NOTE: `QuicheError` and `QuicheResult` used to live here. Every variant
// of `QuicheError` was unconstructed and the type was unused anywhere in
// the workspace — the whole quiche subsystem is currently a placeholder
// (see review findings on `TuicheInbound::listen` / `TuicheOutbound`).
// Re-add either type when the implementation actually surfaces structured
// errors.

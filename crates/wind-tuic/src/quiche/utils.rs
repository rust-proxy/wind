//! Configuration types for the quiche backend (mirrors the former
//! `wind-tuiche` surface).

use std::time::Duration;

use wind_quic::QuicCongestionControl;

/// Congestion control algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionControl {
	#[default]
	Cubic,
	Bbr,
	Reno,
}

impl From<CongestionControl> for QuicCongestionControl {
	fn from(cc: CongestionControl) -> Self {
		match cc {
			CongestionControl::Cubic => QuicCongestionControl::Cubic,
			CongestionControl::Bbr => QuicCongestionControl::Bbr,
			CongestionControl::Reno => QuicCongestionControl::Reno,
		}
	}
}

/// UDP relay mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UdpRelayMode {
	#[default]
	Datagram,
	Stream,
}

/// Connection options.
#[derive(Debug, Clone)]
pub struct ConnectionOpts {
	/// Maximum idle timeout.
	pub max_idle_timeout: Duration,
	/// Maximum concurrent bidirectional streams.
	pub max_concurrent_bi_streams: u64,
	/// Maximum concurrent unidirectional streams.
	pub max_concurrent_uni_streams: u64,
	/// Send window size.
	pub send_window: u64,
	/// Receive window size.
	pub receive_window: u64,
	/// Congestion control algorithm.
	pub congestion_control: CongestionControl,
	/// UDP relay mode.
	pub udp_relay_mode: UdpRelayMode,
	/// Enable 0-RTT.
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

impl ConnectionOpts {
	/// Translate into a backend-neutral [`wind_quic::TransportConfig`].
	pub(crate) fn to_transport(&self) -> wind_quic::TransportConfig {
		wind_quic::TransportConfig {
			max_concurrent_bidi_streams: self.max_concurrent_bi_streams,
			max_concurrent_uni_streams: self.max_concurrent_uni_streams,
			send_window: self.send_window,
			receive_window: self.receive_window,
			max_idle_timeout: Some(self.max_idle_timeout),
			congestion: self.congestion_control.into(),
			// TUIC's native UDP relay uses QUIC DATAGRAM frames (RFC 9221).
			enable_datagram: matches!(self.udp_relay_mode, UdpRelayMode::Datagram),
			enable_0rtt: self.enable_0rtt,
			alpn: vec![b"h3".to_vec()],
			..Default::default()
		}
	}
}

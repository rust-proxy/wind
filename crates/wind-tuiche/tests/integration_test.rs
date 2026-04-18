//! Integration tests for wind-tuiche

use std::time::Duration;

use wind_tuiche::utils::{CongestionControl, ConnectionOpts, UdpRelayMode};

#[test]
fn test_congestion_control() {
	let cc = CongestionControl::default();
	assert_eq!(cc, CongestionControl::Cubic);

	let cc = CongestionControl::Bbr;
	let s: &str = cc.into();
	assert_eq!(s, "bbr");

	let cc = CongestionControl::Reno;
	let s: &str = cc.into();
	assert_eq!(s, "reno");
}

#[test]
fn test_udp_relay_mode() {
	let mode = UdpRelayMode::default();
	assert_eq!(mode, UdpRelayMode::Datagram);

	let mode = UdpRelayMode::Stream;
	assert_ne!(mode, UdpRelayMode::default());
}

#[test]
fn test_connection_opts_default() {
	let opts = ConnectionOpts::default();

	assert_eq!(opts.max_idle_timeout, Duration::from_secs(30));
	assert_eq!(opts.max_concurrent_bi_streams, 100);
	assert_eq!(opts.max_concurrent_uni_streams, 100);
	assert_eq!(opts.send_window, 8 * 1024 * 1024);
	assert_eq!(opts.receive_window, 8 * 1024 * 1024);
	assert_eq!(opts.congestion_control, CongestionControl::Cubic);
	assert_eq!(opts.udp_relay_mode, UdpRelayMode::Datagram);
	assert!(opts.enable_0rtt);
}

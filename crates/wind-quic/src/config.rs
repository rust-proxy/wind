//! Backend-neutral configuration inputs.
//!
//! These types carry the operator's intent without leaking any backend's native
//! configuration (rustls / boring / `quinn::TransportConfig` / `QuicSettings`).
//! Each backend maps them onto its own representation at endpoint-construction
//! time.

use std::time::Duration;

pub use wind_core::quic::QuicCongestionControl;

/// QUIC transport tuning, shared by both backends.
#[derive(Clone, Debug)]
pub struct TransportConfig {
	/// Maximum number of concurrent peer-initiated bidirectional streams.
	pub max_concurrent_bidi_streams: u64,
	/// Maximum number of concurrent peer-initiated unidirectional streams.
	pub max_concurrent_uni_streams: u64,
	/// Connection-level send window, in bytes.
	pub send_window: u64,
	/// Connection / per-stream receive window, in bytes.
	pub receive_window: u64,
	/// Idle timeout. `None` disables it.
	pub max_idle_timeout: Option<Duration>,
	/// Initial MTU guess.
	pub initial_mtu: u16,
	/// Lower bound on the MTU.
	pub min_mtu: u16,
	/// Enable generic segmentation offload (quinn only; ignored by quiche).
	pub gso: bool,
	/// Congestion-control algorithm.
	pub congestion: QuicCongestionControl,
	/// Initial congestion window in bytes. `None` uses the backend default.
	pub initial_window: Option<u64>,
	/// Advertise QUIC DATAGRAM (RFC 9221) support.
	pub enable_datagram: bool,
	/// Allow 0-RTT early data (resumption).
	pub enable_0rtt: bool,
	/// ALPN protocols to advertise, most-preferred first.
	pub alpn: Vec<Vec<u8>>,
}

impl Default for TransportConfig {
	fn default() -> Self {
		Self {
			max_concurrent_bidi_streams: 100,
			max_concurrent_uni_streams: 100,
			send_window: 8 * 1024 * 1024,
			receive_window: 8 * 1024 * 1024,
			max_idle_timeout: Some(Duration::from_secs(30)),
			initial_mtu: 1200,
			min_mtu: 1200,
			gso: false,
			congestion: QuicCongestionControl::default(),
			initial_window: None,
			enable_datagram: true,
			enable_0rtt: false,
			alpn: vec![b"h3".to_vec()],
		}
	}
}

/// Where a server's certificate + private key come from.
#[derive(Clone, Debug)]
pub enum CertSource {
	/// Paths to PEM files on disk. The only form the quiche backend accepts
	/// (tokio-quiche loads credentials from file paths).
	PemPaths { cert: String, key: String },
	/// In-memory PEM bytes. Supported by the quinn backend only.
	PemBytes { cert: Vec<u8>, key: Vec<u8> },
}

/// Server-side TLS configuration.
#[derive(Clone, Debug)]
pub struct ServerTlsConfig {
	/// The certificate chain + key to present.
	pub cert: CertSource,
}

impl ServerTlsConfig {
	/// Convenience constructor for PEM file paths.
	pub fn from_pem_paths(cert: impl Into<String>, key: impl Into<String>) -> Self {
		Self {
			cert: CertSource::PemPaths {
				cert: cert.into(),
				key: key.into(),
			},
		}
	}
}

/// Client-side TLS configuration.
#[derive(Clone, Debug)]
pub struct ClientTlsConfig {
	/// Server name (SNI) to send and verify against.
	pub server_name: String,
	/// Verify the server certificate. Disabling it is insecure (MITM-able) and
	/// intended only for tests / explicitly-trusted setups.
	pub verify_certificate: bool,
	/// ALPN protocols to advertise, most-preferred first.
	pub alpn: Vec<Vec<u8>>,
}

impl ClientTlsConfig {
	/// A verifying client config for `server_name` advertising the `h3` ALPN.
	pub fn new(server_name: impl Into<String>) -> Self {
		Self {
			server_name: server_name.into(),
			verify_certificate: true,
			alpn: vec![b"h3".to_vec()],
		}
	}
}

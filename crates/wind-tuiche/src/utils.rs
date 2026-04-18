//! Utility functions and types for wind-tuiche

use std::{io, time::Duration};

/// Congestion control algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionControl {
    Cubic,
    Bbr,
    Reno,
}

impl Default for CongestionControl {
    fn default() -> Self {
        Self::Cubic
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpRelayMode {
    Datagram,
    Stream,
}

impl Default for UdpRelayMode {
    fn default() -> Self {
        Self::Datagram
    }
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
            send_window: 8 * 1024 * 1024, // 8 MB
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

/// Error types for wind-tuiche
#[derive(Debug, thiserror::Error)]
pub enum QuicheError {
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("TLS error: {0}")]
    Tls(String),
    
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Connection error: {0}")]
    Connection(String),
    
    #[error("Timeout: {0}")]
    Timeout(String),
    
    #[error("Authentication error: {0}")]
    Auth(String),
}

/// Result type for quiche operations
pub type QuicheResult<T> = Result<T, QuicheError>;
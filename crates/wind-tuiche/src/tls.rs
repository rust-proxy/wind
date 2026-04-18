//! TLS configuration for quiche (BoringSSL)

use std::time::Duration;

/// TLS configuration for quiche
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Verify server certificate
    pub verify_certificate: bool,
    /// ALPN protocols to negotiate
    pub alpn: Vec<String>,
    /// Maximum idle timeout
    pub max_idle_timeout: Duration,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            verify_certificate: true,
            alpn: vec!["tuic".to_string()],
            max_idle_timeout: Duration::from_secs(30),
        }
    }
}
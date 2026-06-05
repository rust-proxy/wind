//! TUIC inbound server implementation backed by `tokio-quiche`.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use futures_util::StreamExt;
use tokio::net::UdpSocket;
use tokio_quiche::{
	ConnectionParams,
	metrics::DefaultMetrics,
	settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths},
};
use tracing::{info, warn};
use uuid::Uuid;
use wind_core::inbound::{AbstractInbound, InboundCallback};

use crate::{
	Result,
	driver::TuicheDriver,
	utils::{ConnectionOpts, UdpRelayMode},
};

/// TUIC server implementation using the `tokio-quiche` backend.
#[allow(dead_code)]
pub struct TuicheInbound {
	listen_addr: SocketAddr,
	users: HashMap<Uuid, Vec<u8>>,
	opts: ConnectionOpts,
	/// Path to the PEM-encoded TLS certificate chain.
	cert_path: Option<String>,
	/// Path to the PEM-encoded private key.
	private_key_path: Option<String>,
}

impl TuicheInbound {
	/// Create a new TUIC server builder
	pub fn builder() -> TuicheInboundBuilder {
		TuicheInboundBuilder::new()
	}

	/// Translate [`ConnectionOpts`] into a [`tokio_quiche`] [`QuicSettings`].
	fn quic_settings(&self) -> QuicSettings {
		let mut settings = QuicSettings::default();
		settings.max_idle_timeout = Some(self.opts.max_idle_timeout);
		settings.initial_max_streams_bidi = self.opts.max_concurrent_bi_streams;
		settings.initial_max_streams_uni = self.opts.max_concurrent_uni_streams;
		settings.cc_algorithm = <&str>::from(self.opts.congestion_control).to_string();
		// TUIC relies on QUIC DATAGRAM frames (RFC 9221) for its native UDP relay
		// mode, so the backend must advertise datagram support.
		settings.enable_dgram = matches!(self.opts.udp_relay_mode, UdpRelayMode::Datagram);
		settings.alpn = vec![b"h3".to_vec()];
		settings
	}
}

impl AbstractInbound for TuicheInbound {
	async fn listen(&self, cb: &impl InboundCallback) -> eyre::Result<()> {
		info!("Starting wind-tuiche (tokio-quiche) inbound on {}", self.listen_addr);

		// `tokio-quiche` servers must always present TLS credentials.
		let (cert_path, private_key_path) = match (&self.cert_path, &self.private_key_path) {
			(Some(cert), Some(key)) => (cert, key),
			_ => {
				return Err(eyre::eyre!(
					"wind-tuiche inbound requires a certificate and private key (set certificate_path / private_key_path)"
				));
			}
		};

		let socket = UdpSocket::bind(self.listen_addr).await?;

		let params = ConnectionParams::new_server(
			self.quic_settings(),
			TlsCertificatePaths {
				cert: cert_path,
				private_key: private_key_path,
				kind: CertificateKind::X509,
			},
			Hooks::default(),
		);

		let mut listeners = tokio_quiche::listen([socket], params, DefaultMetrics)
			.map_err(|e| eyre::eyre!("failed to start tokio-quiche listener: {e}"))?;
		let mut stream = listeners.remove(0);

		// Shared registered-user table handed to every connection's driver.
		let users = Arc::new(self.users.clone());

		info!("wind-tuiche listening loop started");

		while let Some(conn) = stream.next().await {
			match conn {
				Ok(conn) => {
					// Each connection gets its own TUIC protocol driver running on
					// the tokio-quiche worker. `start` spawns the worker and
					// returns a handle we don't need to retain.
					let driver = TuicheDriver::new(cb.clone(), users.clone());
					conn.start(driver);
				}
				Err(e) => {
					warn!("wind-tuiche listener error: {e}");
				}
			}
		}

		Ok(())
	}
}

/// Builder for [`TuicheInbound`].
pub struct TuicheInboundBuilder {
	listen_addr: Option<SocketAddr>,
	users: HashMap<Uuid, Vec<u8>>,
	cert_path: Option<String>,
	private_key_path: Option<String>,
	opts: ConnectionOpts,
}

impl TuicheInboundBuilder {
	/// Create a new builder
	pub fn new() -> Self {
		Self {
			listen_addr: None,
			users: HashMap::new(),
			cert_path: None,
			private_key_path: None,
			opts: ConnectionOpts::default(),
		}
	}

	/// Set the listen address
	pub fn listen_addr(mut self, addr: SocketAddr) -> Self {
		self.listen_addr = Some(addr);
		self
	}

	/// Add a user
	pub fn user(mut self, uuid: Uuid, password: String) -> Self {
		self.users.insert(uuid, password.into_bytes());
		self
	}

	/// Set the path to the PEM-encoded TLS certificate chain.
	pub fn certificate_path(mut self, path: impl Into<String>) -> Self {
		self.cert_path = Some(path.into());
		self
	}

	/// Set the path to the PEM-encoded private key.
	pub fn private_key_path(mut self, path: impl Into<String>) -> Self {
		self.private_key_path = Some(path.into());
		self
	}

	/// Set maximum idle time
	pub fn max_idle_time(mut self, time: Duration) -> Self {
		self.opts.max_idle_timeout = time;
		self
	}

	/// Set connection options
	pub fn connection_opts(mut self, opts: ConnectionOpts) -> Self {
		self.opts = opts;
		self
	}

	/// Build the server
	pub async fn build(self) -> Result<TuicheInbound> {
		let listen_addr = self.listen_addr.ok_or_else(|| eyre::eyre!("Listen address not set"))?;

		Ok(TuicheInbound {
			listen_addr,
			users: self.users,
			opts: self.opts,
			cert_path: self.cert_path,
			private_key_path: self.private_key_path,
		})
	}
}

impl Default for TuicheInboundBuilder {
	fn default() -> Self {
		Self::new()
	}
}

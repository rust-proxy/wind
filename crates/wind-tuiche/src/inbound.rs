//! TUIC inbound server implementation with quiche

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use tokio::net::UdpSocket;
use uuid::Uuid;
use wind_core::{
	inbound::{AbstractInbound, InboundCallback},
	info, warn,
};

use crate::{Result, utils::ConnectionOpts};

const MAX_DATAGRAM_SIZE: usize = 1350;

#[allow(dead_code)]
/// TUIC server implementation using quiche
pub struct TuicheInbound {
	listen_addr: SocketAddr,
	users: HashMap<Uuid, Vec<u8>>,
	opts: ConnectionOpts,
}

impl TuicheInbound {
	/// Create a new TUIC server builder
	pub fn builder() -> TuicheInboundBuilder {
		TuicheInboundBuilder::new()
	}

	fn create_quiche_config(&self) -> eyre::Result<quiche::Config> {
		let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

		// This is a minimal configuration. In a real setup, we should load
		// TLS certificates, keys, and setup proper ALPN.
		config.verify_peer(false);
		config.set_application_protos(&[b"h3"])?; // Placeholder ALPN

		config.set_max_idle_timeout(self.opts.max_idle_timeout.as_millis() as u64);
		config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
		config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
		config.set_initial_max_data(10_000_000);
		config.set_initial_max_stream_data_bidi_local(1_000_000);
		config.set_initial_max_stream_data_bidi_remote(1_000_000);
		config.set_initial_max_stream_data_uni(1_000_000);
		config.set_initial_max_streams_bidi(self.opts.max_concurrent_bi_streams);
		config.set_initial_max_streams_uni(self.opts.max_concurrent_uni_streams);
		config.set_disable_active_migration(true);

		// A real implementation would setup certificates here:
		// config.load_cert_chain_from_pem_file("cert.pem")?;
		// config.load_priv_key_from_pem_file("key.pem")?;

		Ok(config)
	}
}

impl AbstractInbound for TuicheInbound {
	async fn listen(&self, _cb: &impl InboundCallback) -> eyre::Result<()> {
		info!("Starting wind-tuiche quiche inbound on {}", self.listen_addr);

		let _config = self.create_quiche_config()?;
		let socket = Arc::new(UdpSocket::bind(self.listen_addr).await?);

		// Use a simple task with a select loop to handle incoming UDP datagrams
		// and connection timeouts.
		let mut buf = [0; 65535];
		let _out = [0; MAX_DATAGRAM_SIZE];

		// In a real implementation we'd manage a map of quiche::Connection objects
		// and handle their timers, streams, and route traffic to `cb`.
		// Here we provide the basic event loop structure.

		info!("Quiche inbound listening loop started");

		loop {
			tokio::select! {
				result = socket.recv_from(&mut buf) => {
					let (len, src) = match result {
						Ok(r) => r,
						Err(_e) => {
							// error!("UDP recv error: {}", _e);
							continue;
						}
					};

					// Parse the QUIC header
					let hdr = match quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN) {
						Ok(v) => v,
						Err(_e) => {
							// warn!("Failed to parse QUIC header: {}", _e);
							continue;
						}
					};

					// Example logic to handle connections:
					// 1. Lookup `hdr.dcid` in a HashMap<Vec<u8>, quiche::Connection>.
					// 2. If missing and `hdr.ty == quiche::Type::Initial`, create via `quiche::accept`.
					// 3. Feed packet `conn.recv()`.
					// 4. Handle readable streams and call `cb.handle_tcpstream` or UDP handlers.
					// 5. Drain `conn.send()` and forward via `socket.send_to()`.

					// Note: This is a placeholder for the actual complex state machine.
					// As requested, the loop is implemented but the deep TUIC protocol parsing
					// inside QUIC streams requires more extensive logic similar to `wind-tuic`.
					warn!("Received QUIC packet from {}, DCID len: {}", src, hdr.dcid.len());
				}
			}
		}
	}
}

/// Builder for TuicheInbound
pub struct TuicheInboundBuilder {
	listen_addr: Option<SocketAddr>,
	users: HashMap<Uuid, Vec<u8>>,
	max_idle_time: Duration,
	opts: ConnectionOpts,
}

impl TuicheInboundBuilder {
	/// Create a new builder
	pub fn new() -> Self {
		Self {
			listen_addr: None,
			users: HashMap::new(),
			max_idle_time: Duration::from_secs(30),
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

	/// Set maximum idle time
	pub fn max_idle_time(mut self, time: Duration) -> Self {
		self.max_idle_time = time;
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
		})
	}
}

impl Default for TuicheInboundBuilder {
	fn default() -> Self {
		Self::new()
	}
}

//! TUIC inbound server — quiche (tokio-quiche) backend.
//!
//! A thin wrapper mirroring the former `wind-tuiche` public surface: it builds
//! a [`wind_quic::quiche`] listener (with live certificate rotation via
//! [`CertStore`]), accepts established connections, and drives each through the
//! backend-agnostic [`crate::server::serve_connection`]. All TUIC protocol
//! logic is shared with the quinn backend.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use tokio_util::sync::CancellationToken;
use tracing::{Instrument as _, info};
use uuid::Uuid;
use wind_core::inbound::{AbstractInbound, InboundCallback};
use wind_quic::{
	QuicConnection as _, ServerTlsConfig,
	quiche::{CertStore, bind_server},
};

use crate::{Result, quiche::utils::ConnectionOpts};

/// Authentication timeout for quiche connections. The peer must send its `Auth`
/// command within this window or the connection is closed (matches the quinn
/// backend's default).
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

/// TUIC server using the quiche / tokio-quiche backend.
#[allow(dead_code)]
pub struct TuicheInbound {
	listen_addr: SocketAddr,
	users: HashMap<Uuid, String>,
	opts: ConnectionOpts,
	/// Path to the PEM-encoded TLS certificate chain.
	cert_path: String,
	/// Path to the PEM-encoded private key.
	private_key_path: String,
	/// Hot-swappable certificate served to every handshake; update via
	/// [`TuicheInbound::cert_store`] for live rotation (e.g. ACME renewal).
	cert_store: CertStore,
	/// Root cancellation token: cancelling it stops the accept loop and tears
	/// down every live connection (each gets a child token).
	cancel: CancellationToken,
}

impl TuicheInbound {
	/// Create a new TUIC server builder.
	pub fn builder() -> TuicheInboundBuilder {
		TuicheInboundBuilder::new()
	}

	/// Handle to the hot-swappable certificate store. Call
	/// [`CertStore::update`] to rotate the served certificate live.
	pub fn cert_store(&self) -> CertStore {
		self.cert_store.clone()
	}
}

impl AbstractInbound for TuicheInbound {
	async fn listen(&self, cb: &impl InboundCallback) -> eyre::Result<()> {
		info!("Starting wind-tuic (quiche) inbound on {}", self.listen_addr);

		let tls = ServerTlsConfig::from_pem_paths(self.cert_path.clone(), self.private_key_path.clone());
		let transport = self.opts.to_transport();

		let mut acceptor = bind_server(self.listen_addr, &tls, &transport, Some(&self.cert_store)).await?;

		let users = Arc::new(self.users.clone());
		// Root of every per-connection token: cancelling `self.cancel` (e.g. from
		// a ctrl-c handler via `TuicheInboundBuilder::cancel_token`) stops the
		// accept loop *and* winds down every spawned connection handler, whose
		// `serve_connection` closes its QUIC connection on cancellation.
		let root_cancel = self.cancel.clone();

		info!("wind-tuic (quiche) listening loop started");

		loop {
			let conn = tokio::select! {
				_ = root_cancel.cancelled() => {
					info!("wind-tuic (quiche) inbound shutting down");
					break;
				}
				maybe_conn = acceptor.accept() => {
					let Some(conn) = maybe_conn else {
						info!("wind-tuic (quiche) acceptor closed; shutting down listen loop");
						break;
					};
					conn
				}
			};
			let remote = conn.peer_addr().unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
			let span = tracing::info_span!("conn", peer = %remote);
			let users = users.clone();
			let cb = cb.clone();
			let cancel = root_cancel.child_token();
			tokio::spawn(crate::server::serve_connection(conn, remote, users, AUTH_TIMEOUT, cb, cancel).instrument(span));
		}

		Ok(())
	}
}

/// Builder for [`TuicheInbound`].
pub struct TuicheInboundBuilder {
	listen_addr: Option<SocketAddr>,
	users: HashMap<Uuid, String>,
	cert_path: Option<String>,
	private_key_path: Option<String>,
	opts: ConnectionOpts,
	cancel: Option<CancellationToken>,
}

impl TuicheInboundBuilder {
	/// Create a new builder.
	pub fn new() -> Self {
		Self {
			listen_addr: None,
			users: HashMap::new(),
			cert_path: None,
			private_key_path: None,
			opts: ConnectionOpts::default(),
			cancel: None,
		}
	}

	/// Set the cancellation token driving graceful shutdown. Cancelling it
	/// stops the accept loop and closes every live connection. Defaults to a
	/// fresh token (i.e. the server only stops when the acceptor closes).
	pub fn cancel_token(mut self, cancel: CancellationToken) -> Self {
		self.cancel = Some(cancel);
		self
	}

	/// Set the listen address.
	pub fn listen_addr(mut self, addr: SocketAddr) -> Self {
		self.listen_addr = Some(addr);
		self
	}

	/// Add a user.
	pub fn user(mut self, uuid: Uuid, password: String) -> Self {
		self.users.insert(uuid, password);
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

	/// Set maximum idle time.
	pub fn max_idle_time(mut self, time: Duration) -> Self {
		self.opts.max_idle_timeout = time;
		self
	}

	/// Set connection options.
	pub fn connection_opts(mut self, opts: ConnectionOpts) -> Self {
		self.opts = opts;
		self
	}

	/// Build the server. Reads the certificate and key files to seed the
	/// hot-swappable [`CertStore`]; both paths are required.
	pub async fn build(self) -> Result<TuicheInbound> {
		let listen_addr = self.listen_addr.ok_or_else(|| eyre::eyre!("Listen address not set"))?;
		let cert_path = self
			.cert_path
			.ok_or_else(|| eyre::eyre!("wind-tuic quiche inbound requires a certificate (set certificate_path)"))?;
		let private_key_path = self
			.private_key_path
			.ok_or_else(|| eyre::eyre!("wind-tuic quiche inbound requires a private key (set private_key_path)"))?;

		let cert_pem = std::fs::read(&cert_path).map_err(|e| eyre::eyre!("reading certificate {}: {e}", cert_path))?;
		let key_pem =
			std::fs::read(&private_key_path).map_err(|e| eyre::eyre!("reading private key {}: {e}", private_key_path))?;
		let cert_store = CertStore::from_pem(&cert_pem, &key_pem)?;

		Ok(TuicheInbound {
			listen_addr,
			users: self.users,
			opts: self.opts,
			cert_path,
			private_key_path,
			cert_store,
			cancel: self.cancel.unwrap_or_default(),
		})
	}
}

impl Default for TuicheInboundBuilder {
	fn default() -> Self {
		Self::new()
	}
}

//! Naive outbound using `cronet-rs` (Cronet-based CONNECT proxy).
//!
//! This crate provides [`NaiveOutbound`], an implementation of
//! [`wind_core::AbstractOutbound`] that tunnels TCP (and UDP-over-TCP) through
//! a NaiveProxy server via the Cronet HTTP/2 or QUIC CONNECT protocol with
//! padding.

use std::{
	io::{Read, Write},
	sync::Arc,
};

use cronet_rs::naive_client::{NaiveClient, NaiveClientConfig, QuicCongestionControl};
use eyre::Context as _;
use tokio::{
	io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
	sync::mpsc,
};
use tracing::{Instrument, info};
use wind_core::{
	AbstractOutbound,
	tcp::AbstractTcpStream,
	types::TargetAddr,
	udp::{UdpPacket, UdpStream},
};

// ============================================================================
// Options
// ============================================================================

/// Configuration for the Naive outbound.
#[derive(Clone, Debug)]
pub struct NaiveOutboundOpts {
	/// NaiveProxy server address (host:port).
	pub server_address: String,

	/// Server name (SNI), defaults to server_address's host.
	pub server_name: Option<String>,

	/// Username for proxy authentication.
	pub username: Option<String>,

	/// Password for proxy authentication.
	pub password: Option<String>,

	/// Number of concurrent connections to the Cronet engine.
	/// 1 = single connection (default).
	pub concurrency: u32,

	/// Enable QUIC.
	pub quic_enabled: bool,

	/// QUIC congestion control algorithm.
	pub quic_congestion_control: QuicCongestionControl,

	/// PEM-encoded trusted root certificates.
	/// If `None`, the platform trust store is used.
	pub trusted_root_certificates: Option<String>,

	/// Enable ECH (Encrypted Client Hello).
	pub ech_enabled: bool,

	/// Extra headers to include in every CONNECT request.
	pub extra_headers: std::collections::HashMap<String, String>,

	/// Path to `libcronet.so` (or `.dylib`) shared library.
	///
	/// If `None`, the loader tries these locations in order:
	///   1. `LD_LIBRARY_PATH` / system default (`libcronet.so`)
	///   2. `./libcronet.so`
	///   3. `/usr/local/lib/libcronet.so`
	///   4. `/opt/cronet/libcronet.so`
	pub cronet_lib_path: Option<String>,
}

impl Default for NaiveOutboundOpts {
	fn default() -> Self {
		Self {
			server_address: String::new(),
			server_name: None,
			username: None,
			password: None,
			concurrency: 1,
			quic_enabled: false,
			quic_congestion_control: QuicCongestionControl::Default,
			trusted_root_certificates: None,
			ech_enabled: false,
			extra_headers: std::collections::HashMap::new(),
			cronet_lib_path: None,
		}
	}
}

// ============================================================================
// NaiveOutbound
// ============================================================================

/// An outbound that tunnels traffic through a NaiveProxy server via Cronet.
///
/// Uses `cronet-rs` (Chromium Cronet C API bindings) to establish HTTP/2
/// or QUIC CONNECT tunnels with NaiveProxy padding protocol.
///
/// The Cronet engine is shared across all connections (`RwLock` read-locked
/// only during dial), so concurrent tunnels are not serialized.
pub struct NaiveOutbound {
	/// Shared Cronet engine behind a read-write lock.
	///
	/// `dial()` takes `&self`, so concurrent dials acquire a **read** lock and
	/// run in parallel.  The write lock is only held during `start()`.
	client: Arc<tokio::sync::RwLock<NaiveClient>>,
}

impl NaiveOutbound {
	/// Create and start a new `NaiveOutbound`.
	///
	/// This spawns the Cronet engine (a blocking FFI operation) in a
	/// background blocking thread so the async caller is not stalled.
	///
	/// `cronet_lib_path` controls how `libcronet` is loaded — see
	/// [`NaiveOutboundOpts::cronet_lib_path`].
	pub async fn new(opts: NaiveOutboundOpts) -> eyre::Result<Self> {
		// Load libcronet before touching any FFI.
		load_cronet(opts.cronet_lib_path.clone())?;

		let server_name = opts
			.server_name
			.clone()
			.unwrap_or_else(|| opts.server_address.split(':').next().unwrap_or("").to_string());

		let config = NaiveClientConfig {
			server_address: opts.server_address.clone(),
			server_name: Some(server_name),
			username: opts.username.clone(),
			password: opts.password.clone(),
			concurrency: opts.concurrency,
			extra_headers: opts.extra_headers.clone(),
			trusted_root_certificates: opts.trusted_root_certificates.clone(),
			quic_enabled: opts.quic_enabled,
			quic_congestion_control: opts.quic_congestion_control,
			ech_enabled: opts.ech_enabled,
			..Default::default()
		};

		let client = NaiveClient::new(config).map_err(|e| eyre::eyre!("Failed to create NaiveClient: {e}"))?;

		let client = Arc::new(tokio::sync::RwLock::new(client));

		// Start the Cronet engine (requires &mut → write lock).
		let client_for_start = client.clone();
		tokio::task::spawn_blocking(move || -> eyre::Result<()> {
			let mut guard = client_for_start.blocking_write();
			guard.start().map_err(|e| eyre::eyre!("Failed to start Cronet engine: {e}"))
		})
		.await
		.context("Spawn blocking for engine start failed")??;

		info!(target: "naive", "NaiveOutbound started, server={}", opts.server_address);

		Ok(Self { client })
	}
}

// ============================================================================
// AbstractOutbound implementation
// ============================================================================

impl AbstractOutbound for NaiveOutbound {
	async fn handle_tcp(
		&self,
		target_addr: TargetAddr,
		stream: impl AbstractTcpStream,
		_via: Option<impl AbstractOutbound + Sized + Send>,
	) -> eyre::Result<()> {
		let target_str = target_addr.to_string();
		let client = self.client.clone();

		info!(target: "naive_tcp", "connecting to {target_str}");

		// Dial a CONNECT tunnel via the Cronet engine.
		//
		// `dial_and_handshake` takes `&self` so we only need a **read** lock;
		// concurrent calls are NOT serialized.
		let target_for_dial = target_str.clone();
		let naive_conn = tokio::task::spawn_blocking(move || -> eyre::Result<_> {
			let guard = client.blocking_read();
			guard
				.dial_and_handshake(&target_for_dial)
				.map_err(|e| eyre::eyre!("CONNECT to {target_for_dial} failed: {e}"))
		})
		.await
		.context("Spawn blocking for dial failed")??;

		info!(target: "naive_tcp", "CONNECT tunnel established to {target_str}");

		// Bridge the blocking NaiveConn to the async stream.
		naive_async_bridge(naive_conn, stream).await
	}

	async fn handle_udp(&self, udp_stream: UdpStream, _via: Option<impl AbstractOutbound + Sized + Send>) -> eyre::Result<()> {
		let UdpStream { tx: _tx, mut rx } = udp_stream;
		let client = self.client.clone();

		while let Some(packet) = rx.recv().await {
			let UdpPacket {
				source: _,
				target,
				payload,
			} = packet;
			let target_str = target.to_string();
			let client = client.clone();
			let payload_len = payload.len();

			tokio::spawn(
				async move {
					if let Err(e) = udp_tunnel_tx(client, &target_str, &payload).await {
						tracing::warn!(target = %target_str, error = %e, "[NAIVE:UDP] tunnel failed");
					} else {
						info!(target = %target_str, bytes = payload_len, "[NAIVE:UDP] sent {payload_len} bytes via tunnel");
					}
				}
				.in_current_span(),
			);
		}

		Ok(())
	}
}

// ============================================================================
// UDP-over-TCP
// ============================================================================

/// Send a single UDP payload through a short-lived CONNECT tunnel.
async fn udp_tunnel_tx(client: Arc<tokio::sync::RwLock<NaiveClient>>, target: &str, payload: &[u8]) -> eyre::Result<()> {
	let target = target.to_string();
	let data = payload.to_vec();

	// Read-lock (parallel dials are fine).
	let client_dial = client.clone();
	let mut naive_conn = tokio::task::spawn_blocking(move || -> eyre::Result<_> {
		let guard = client_dial.blocking_read();
		guard
			.dial_and_handshake(&target)
			.map_err(|e| eyre::eyre!("UDP CONNECT tunnel to {target} failed: {e}"))
	})
	.await
	.context("Spawn blocking for UDP dial failed")??;

	tokio::task::spawn_blocking(move || -> eyre::Result<()> {
		naive_conn
			.write_all(&data)
			.map_err(|e| eyre::eyre!("UDP tunnel write failed: {e}"))?;
		naive_conn.flush().map_err(|e| eyre::eyre!("UDP tunnel flush failed: {e}"))?;
		// Drop closes the tunnel.
		Ok(())
	})
	.await
	.context("Spawn blocking for UDP write failed")?
}

// ============================================================================
// Async bridge — blocking NaiveConn → async I/O
// ============================================================================

/// Bridge data between a blocking [`cronet_rs::naive_conn::NaiveConn`] and a
/// tokio [`AsyncRead`] + [`AsyncWrite`] stream.
///
/// Spawns a dedicated **std::thread** that owns the `NaiveConn` and relays
/// data through `mpsc` channels.  The Cronet C API expects all stream
/// operations from the same thread.
async fn naive_async_bridge(
	mut naive: cronet_rs::naive_conn::NaiveConn,
	mut stream: impl AsyncRead + AsyncWrite + Unpin,
) -> eyre::Result<()> {
	let span = tracing::debug_span!("naive_bridge");

	async move {
		let (naive_write_tx, mut naive_write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
		let (naive_read_tx, mut naive_read_rx) = mpsc::unbounded_channel::<Vec<u8>>();

		// ── I/O thread (owns NaiveConn) ──────────────────────────────
		let io_handle = std::thread::Builder::new()
			.name("wind-naive-io".into())
			.spawn(move || {
				let mut read_buf = [0u8; 65535];

				loop {
					// Drain pending writes.
					while let Ok(data) = naive_write_rx.try_recv() {
						if naive.write_all(&data).is_err() {
							return;
						}
						let _ = naive.flush();
					}

					// Re-check after flush.
					if let Ok(data) = naive_write_rx.try_recv() {
						if naive.write_all(&data).is_err() {
							return;
						}
						let _ = naive.flush();
					}

					// Block on a read.
					match naive.read(&mut read_buf) {
						Ok(0) => {
							tracing::debug!("naive conn EOF");
							return;
						}
						Ok(n) => {
							if naive_read_tx.send(read_buf[..n].to_vec()).is_err() {
								return;
							}
						}
						Err(e) => {
							tracing::debug!(error = %e, "naive conn read error");
							return;
						}
					}
				}
			})
			.expect("spawn wind-naive-io thread");

		// ── Local I/O (async, select! across both directions) ────────
		let mut local_buf = vec![0u8; 65535];

		loop {
			tokio::select! {
				result = stream.read(&mut local_buf) => {
					match result {
						Ok(0) => break,
						Ok(n) => {
							if naive_write_tx.send(local_buf[..n].to_vec()).is_err() {
								break;
							}
							local_buf = vec![0u8; 65535];
						}
						Err(e) => {
							tracing::debug!(error = %e, "local stream read error");
							break;
						}
					}
				}
				Some(data) = naive_read_rx.recv() => {
					if let Err(e) = stream.write_all(&data).await {
						tracing::debug!(error = %e, "local stream write error");
						break;
					}
					let _ = stream.flush().await;
				}
				else => break,
			}
		}

		let _ = io_handle.join();
		Ok(())
	}
	.instrument(span)
	.await
}

// ============================================================================
// libcronet loader
// ============================================================================

/// Default search paths for `libcronet`.
const CRONET_SEARCH_PATHS: &[&str] = &[
	"libcronet.so",   // system LD_LIBRARY_PATH
	"./libcronet.so", // CWD
	"/usr/local/lib/libcronet.so",
	"/opt/cronet/libcronet.so",
];

/// Load the `libcronet` shared library.
///
/// If `path` is `Some(...)`, that exact path is tried first.  On failure, or
/// when `path` is `None`, the default search paths are tried.
fn load_cronet(path: Option<String>) -> eyre::Result<()> {
	use cronet_rs::sys::load_library;

	let paths: Vec<&str> = if let Some(ref p) = path {
		let mut v = vec![p.as_str()];
		v.extend(CRONET_SEARCH_PATHS);
		v
	} else {
		CRONET_SEARCH_PATHS.to_vec()
	};


	for lib_path in &paths {
		match unsafe { load_library(lib_path) } {
			Ok(()) => {
				info!(target: "naive", "Loaded libcronet from {lib_path}");
				return Ok(());
			}
			Err(e) => {
				let msg = format!("{e}");
				// "already loaded" means success.
				if msg.contains("already loaded") {
					return Ok(());
				}
				tracing::debug!(target: "naive", "libcronet not found at {lib_path}: {msg}");
			}
		}
	}

	Err(eyre::eyre!(
		"Cannot load libcronet. Tried: {}. Please install libcronet and set `cronet_lib_path` in config, or place \
		 libcronet.so in LD_LIBRARY_PATH.",
		paths.join(", "),
	))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_opts_default() {
		let opts = NaiveOutboundOpts::default();
		assert!(opts.server_address.is_empty());
		assert!(opts.server_name.is_none());
		assert!(opts.username.is_none());
		assert!(opts.password.is_none());
		assert_eq!(opts.concurrency, 1);
		assert!(!opts.quic_enabled);
		assert!(opts.trusted_root_certificates.is_none());
		assert!(!opts.ech_enabled);
		assert!(opts.extra_headers.is_empty());
		assert!(opts.cronet_lib_path.is_none());
	}

	#[test]
	fn test_opts_custom() {
		let opts = NaiveOutboundOpts {
			server_address: "proxy.example.com:443".into(),
			server_name: Some("proxy.example.com".into()),
			username: Some("user".into()),
			password: Some("pass".into()),
			concurrency: 2,
			quic_enabled: true,
			quic_congestion_control: QuicCongestionControl::Bbr,
			cronet_lib_path: Some("/opt/cronet/libcronet.so.119".into()),
			..Default::default()
		};
		assert_eq!(opts.server_address, "proxy.example.com:443");
		assert_eq!(opts.server_name.unwrap(), "proxy.example.com");
		assert_eq!(opts.username.unwrap(), "user");
		assert_eq!(opts.password.unwrap(), "pass");
		assert_eq!(opts.concurrency, 2);
		assert!(opts.quic_enabled);
		assert_eq!(opts.cronet_lib_path.unwrap(), "/opt/cronet/libcronet.so.119");
	}

	#[test]
	fn test_opts_with_auth() {
		let opts = NaiveOutboundOpts {
			server_address: "server.com:443".into(),
			username: Some("naive".into()),
			password: Some("+naive_password".into()),
			..Default::default()
		};
		assert_eq!(opts.server_address, "server.com:443");
		assert!(opts.username.is_some());
		assert!(opts.password.is_some());
	}

	#[test]
	fn test_opts_extra_headers() {
		let mut headers = std::collections::HashMap::new();
		headers.insert("X-Custom".into(), "value".into());

		let opts = NaiveOutboundOpts {
			server_address: "s.example.com:443".into(),
			extra_headers: headers,
			..Default::default()
		};
		assert_eq!(opts.extra_headers.get("X-Custom").unwrap(), "value");
	}
}

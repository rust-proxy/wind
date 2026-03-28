//! Integration tests for the wind-tuic QUIC proxy.
//!
//! Provides public test helpers and verifies TUIC connection, authentication,
//! and TCP proxy behaviour.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use wind_core::{AppContext, InboundCallback, tcp::AbstractTcpStream, types::TargetAddr};

// =============================================================================
// Public Test Helpers
// =============================================================================

/// A simple [`InboundCallback`] that relays TCP connections directly to their
/// targets and silently drops incoming UDP streams.
///
/// Suitable for use in integration tests that exercise TUIC server behaviour.
#[derive(Clone)]
pub struct DirectCallback;

impl InboundCallback for DirectCallback {
	async fn handle_tcpstream(
		&self,
		target_addr: TargetAddr,
		mut stream: impl AbstractTcpStream + 'static,
	) -> eyre::Result<()> {
		let addr = target_addr.to_string();
		let mut target = tokio::net::TcpStream::connect(&addr).await?;
		tokio::io::copy_bidirectional(&mut stream, &mut target).await?;
		Ok(())
	}

	async fn handle_udpstream(&self, _stream: wind_core::udp::UdpStream) -> eyre::Result<()> {
		Ok(())
	}
}

/// Generate a self-signed TLS certificate suitable for TUIC testing.
pub fn generate_tuic_test_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
	let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
	let cert_der = CertificateDer::from(cert.cert);
	let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
	(vec![cert_der], PrivateKeyDer::Pkcs8(key_der))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use uuid::Uuid;
	use wind_core::{AbstractInbound, AbstractOutbound};
	use wind_tuic::{
		inbound::{TuicInbound, TuicInboundOpts},
		outbound::{TuicOutbound, TuicOutboundOpts},
	};

	const TEST_PASSWORD: &[u8] = b"wind_tuic_test_secret";

	// -------------------------------------------------------------------------
	// Test setup helpers
	// -------------------------------------------------------------------------

	struct TuicTestSetup {
		server_addr: SocketAddr,
		uuid: Uuid,
		ctx: Arc<AppContext>,
	}

	impl Drop for TuicTestSetup {
		fn drop(&mut self) {
			self.ctx.token.cancel();
		}
	}

	async fn setup_tuic_server() -> eyre::Result<TuicTestSetup> {
		let (cert, key) = generate_tuic_test_cert();
		let uuid = Uuid::new_v4();
		let mut users = HashMap::new();
		users.insert(uuid, String::from_utf8_lossy(TEST_PASSWORD).to_string());

		// Obtain a free UDP port without holding the socket
		let temp = std::net::UdpSocket::bind("127.0.0.1:0")?;
		let server_addr = temp.local_addr()?;
		drop(temp);

		let ctx = Arc::new(AppContext::default());
		let opts = TuicInboundOpts {
			listen_addr: server_addr,
			certificate: cert,
			private_key: key,
			alpn: vec!["h3".to_string()],
			users,
			auth_timeout: Duration::from_secs(5),
			max_idle_time: Duration::from_secs(30),
			zero_rtt: false,
			..Default::default()
		};

		let server = TuicInbound::new(ctx.clone(), opts);
		let callback = Arc::new(DirectCallback);
		tokio::spawn(async move {
			let _ = server.listen(callback.as_ref()).await;
		});

		// Allow the server time to bind and begin accepting
		tokio::time::sleep(Duration::from_millis(300)).await;

		Ok(TuicTestSetup { server_addr, uuid, ctx })
	}

	async fn connect_tuic_client(setup: &TuicTestSetup) -> eyre::Result<Arc<TuicOutbound>> {
		let ctx = Arc::new(AppContext::default());
		let opts = TuicOutboundOpts {
			peer_addr: setup.server_addr,
			sni: "localhost".to_string(),
			auth: (setup.uuid, Arc::from(TEST_PASSWORD)),
			zero_rtt_handshake: false,
			heartbeat: Duration::from_secs(5),
			gc_interval: Duration::from_secs(5),
			gc_lifetime: Duration::from_secs(30),
			skip_cert_verify: true,
			alpn: vec!["h3".to_string()],
		};
		let client = Arc::new(TuicOutbound::new(ctx.clone(), opts).await?);
		let poll_client = client.clone();
		tokio::spawn(async move {
			let _ = poll_client.start_poll().await;
		});
		tokio::time::sleep(Duration::from_millis(100)).await;
		Ok(client)
	}

	// =========================================================================
	// Connection & Authentication Tests
	// =========================================================================

	/// A TUIC client must be able to establish a QUIC connection to the server.
	#[tokio::test]
	async fn test_tuic_connection() {
		let setup = setup_tuic_server().await.expect("Failed to start TUIC server");
		let result = connect_tuic_client(&setup).await;
		assert!(result.is_ok(), "Client should connect successfully: {:?}", result.err());
	}

	/// Connecting with a valid UUID and correct password must succeed.
	#[tokio::test]
	async fn test_tuic_auth_valid_credentials() {
		let setup = setup_tuic_server().await.expect("Failed to start TUIC server");
		let result = connect_tuic_client(&setup).await;
		assert!(result.is_ok(), "Valid credentials must be accepted: {:?}", result.err());
	}

	/// The QUIC transport layer must accept a connection even when the
	/// application-level password is wrong.  The server validates the Auth
	/// unidirectional stream asynchronously and will close the connection after
	/// the auth timeout.
	#[tokio::test]
	async fn test_tuic_auth_wrong_password() {
		let setup = setup_tuic_server().await.expect("Failed to start TUIC server");
		let ctx = Arc::new(AppContext::default());
		let opts = TuicOutboundOpts {
			peer_addr: setup.server_addr,
			sni: "localhost".to_string(),
			auth: (setup.uuid, Arc::from(b"wrong_password_123".as_slice())),
			zero_rtt_handshake: false,
			heartbeat: Duration::from_secs(5),
			gc_interval: Duration::from_secs(5),
			gc_lifetime: Duration::from_secs(30),
			skip_cert_verify: true,
			alpn: vec!["h3".to_string()],
		};
		let result = TuicOutbound::new(ctx, opts).await;
		assert!(
			result.is_ok(),
			"QUIC transport connection should succeed regardless of password (auth is async): {:?}",
			result.err()
		);
	}

	/// Connecting with an unknown UUID should still establish the QUIC
	/// connection; the server will reject the Auth stream and close the
	/// connection after the auth timeout.
	#[tokio::test]
	async fn test_tuic_auth_unknown_user() {
		let setup = setup_tuic_server().await.expect("Failed to start TUIC server");
		let ctx = Arc::new(AppContext::default());
		let opts = TuicOutboundOpts {
			peer_addr: setup.server_addr,
			sni: "localhost".to_string(),
			auth: (Uuid::new_v4(), Arc::from(TEST_PASSWORD)),
			zero_rtt_handshake: false,
			heartbeat: Duration::from_secs(5),
			gc_interval: Duration::from_secs(5),
			gc_lifetime: Duration::from_secs(30),
			skip_cert_verify: true,
			alpn: vec!["h3".to_string()],
		};
		let result = TuicOutbound::new(ctx, opts).await;
		assert!(
			result.is_ok(),
			"QUIC transport should succeed with unknown UUID; auth failure is handled async: {:?}",
			result.err()
		);
	}

	// =========================================================================
	// TCP Proxy Tests
	// =========================================================================

	/// End-to-end TCP relay through TUIC: a message written on the local stream
	/// must reach the echo target and the echo must arrive back at the caller.
	#[tokio::test]
	async fn test_tuic_tcp_proxy() {
		use tokio::net::TcpListener;

		// Start a simple TCP echo server
		let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let echo_addr = echo.local_addr().unwrap();
		tokio::spawn(async move {
			while let Ok((mut stream, _)) = echo.accept().await {
				tokio::spawn(async move {
					let mut buf = vec![0u8; 4096];
					loop {
						match stream.read(&mut buf).await {
							Ok(0) | Err(_) => break,
							Ok(n) => {
								if stream.write_all(&buf[..n]).await.is_err() {
									break;
								}
							}
						}
					}
				});
			}
		});

		let setup = setup_tuic_server().await.expect("Failed to start TUIC server");
		let client = connect_tuic_client(&setup).await.expect("Failed to connect TUIC client");

		// `local` is the test end; `remote` is passed to handle_tcp as the local stream.
		let (mut local, remote) = tokio::io::duplex(4096);
		let target = TargetAddr::IPv4(std::net::Ipv4Addr::LOCALHOST, echo_addr.port());

		// Drive the TCP relay in a background task
		tokio::spawn(async move {
			let _ = client.handle_tcp(target, remote, None::<TuicOutbound>).await;
		});

		let msg = b"hello wind-tuic";
		local.write_all(msg).await.expect("Write to relay stream failed");

		let mut buf = vec![0u8; msg.len()];
		let read_result = tokio::time::timeout(Duration::from_secs(5), local.read_exact(&mut buf)).await;

		assert!(read_result.is_ok(), "Read timed out waiting for echo");
		assert!(read_result.unwrap().is_ok(), "read_exact failed");
		assert_eq!(&buf, msg, "Echoed payload must match sent data");
	}

	/// A large message (causing multiple QUIC sends) must be relayed correctly.
	#[tokio::test]
	async fn test_tuic_tcp_proxy_large_payload() {
		use tokio::net::TcpListener;

		let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let echo_addr = echo.local_addr().unwrap();
		tokio::spawn(async move {
			while let Ok((stream, _)) = echo.accept().await {
				tokio::spawn(async move {
					let (mut r, mut w) = stream.into_split();
					tokio::io::copy(&mut r, &mut w).await.ok();
				});
			}
		});

		let setup = setup_tuic_server().await.expect("Failed to start TUIC server");
		let client = connect_tuic_client(&setup).await.expect("Failed to connect TUIC client");

		let (mut local, remote) = tokio::io::duplex(65536);
		let target = TargetAddr::IPv4(std::net::Ipv4Addr::LOCALHOST, echo_addr.port());
		tokio::spawn(async move {
			let _ = client.handle_tcp(target, remote, None::<TuicOutbound>).await;
		});

		// 32 KiB payload
		let payload: Vec<u8> = (0u8..=255).cycle().take(32 * 1024).collect();
		local.write_all(&payload).await.expect("Write failed");

		let mut received = vec![0u8; payload.len()];
		let read_result = tokio::time::timeout(Duration::from_secs(10), local.read_exact(&mut received)).await;

		assert!(read_result.is_ok(), "Large payload read timed out");
		assert!(read_result.unwrap().is_ok(), "read_exact failed for large payload");
		assert_eq!(received, payload, "Large payload echo must match");
	}
}

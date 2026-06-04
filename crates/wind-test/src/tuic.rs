//! Integration tests for the wind-tuic QUIC proxy.
//!
//! Provides public test helpers and verifies TUIC connection, authentication,
//! and TCP proxy behaviour.

#[cfg(test)]
use std::{collections::HashMap, time::Duration};
use std::{net::SocketAddr, sync::Arc};

use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::UdpSocket;
use tracing::Instrument as _;
#[cfg(test)]
use wind_core::AppContext;
use wind_core::{
	InboundCallback,
	tcp::AbstractTcpStream,
	types::TargetAddr,
	udp::{UdpPacket, UdpStream},
};

// =============================================================================
// Public Test Helpers
// =============================================================================

/// A simple [`InboundCallback`] that relays TCP connections directly to their
/// targets and relays UDP packets to real targets via a bound UDP socket.
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

	async fn handle_udpstream(&self, stream: UdpStream) -> eyre::Result<()> {
		let UdpStream { tx, mut rx } = stream;
		let relay_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

		let send_socket = relay_socket.clone();
		let recv_handle = tokio::spawn(
			async move {
				while let Some(packet) = rx.recv().await {
					let target_addr = match packet.target {
						TargetAddr::IPv4(ip, port) => SocketAddr::new(std::net::IpAddr::V4(ip), port),
						TargetAddr::IPv6(ip, port) => SocketAddr::new(std::net::IpAddr::V6(ip), port),
						TargetAddr::Domain(..) => continue,
					};
					let _ = send_socket.send_to(&packet.payload, target_addr).await;
				}
			}
			.in_current_span(),
		);

		tokio::spawn(
			async move {
				let mut buf = vec![0u8; 65536];
				#[allow(clippy::while_let_loop)]
				loop {
					match relay_socket.recv_from(&mut buf).await {
						Ok((n, peer)) => {
							let source = match peer {
								SocketAddr::V4(a) => TargetAddr::IPv4(*a.ip(), a.port()),
								SocketAddr::V6(a) => TargetAddr::IPv6(*a.ip(), a.port()),
							};
							let packet = UdpPacket {
								source: Some(source.clone()),
								target: source,
								payload: Bytes::copy_from_slice(&buf[..n]),
							};
							if tx.send(packet).await.is_err() {
								break;
							}
						}
						Err(_) => break,
					}
				}
			}
			.in_current_span(),
		);

		recv_handle.await?;
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
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use uuid::Uuid;
	use wind_core::{AbstractInbound, AbstractOutbound};
	use wind_tuic::quinn::{
		inbound::{TuicInbound, TuicInboundOpts},
		outbound::{TuicOutbound, TuicOutboundOpts},
	};

	use super::*;

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
		tokio::spawn(
			async move {
				let _ = server.listen(callback.as_ref()).await;
			}
			.in_current_span(),
		);

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
		let client: std::sync::Arc<TuicOutbound> = std::sync::Arc::new(TuicOutbound::new(ctx.clone(), opts).await?);
		let poll_client = client.clone();
		tokio::spawn(
			async move {
				let _ = poll_client.start_poll().await;
			}
			.in_current_span(),
		);
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
		let result: eyre::Result<std::sync::Arc<TuicOutbound>> = connect_tuic_client(&setup).await;
		assert!(result.is_ok(), "Client should connect successfully: {:?}", result.err());
	}

	/// Connecting with a valid UUID and correct password must succeed.
	#[tokio::test]
	async fn test_tuic_auth_valid_credentials() {
		let setup = setup_tuic_server().await.expect("Failed to start TUIC server");
		let result: eyre::Result<std::sync::Arc<TuicOutbound>> = connect_tuic_client(&setup).await;
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
		let result: eyre::Result<TuicOutbound> = TuicOutbound::new(ctx, opts).await;
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
		let result: eyre::Result<TuicOutbound> = TuicOutbound::new(ctx, opts).await;
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
		let client: std::sync::Arc<TuicOutbound> = connect_tuic_client(&setup).await.expect("Failed to connect TUIC client");

		// `local` is the test end; `remote` is passed to handle_tcp as the local
		// stream.
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
		let client: std::sync::Arc<TuicOutbound> = connect_tuic_client(&setup).await.expect("Failed to connect TUIC client");

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

	// =========================================================================
	// PR2 verification: per-fragment INFO-level logs must stay demoted
	// =========================================================================

	/// PR2 regression test for log-level noise on the UDP fragmentation path.
	///
	/// Before PR2 `crates/wind-tuic/src/proto/udp_stream.rs` emitted
	/// `"Fragmentation params: ..."` once per fragmented send and
	/// `"Sending fragment N/M: K bytes"` once per fragment, both at
	/// `tracing::Level::INFO`. On a busy UDP path this was extremely noisy
	/// (allocation + formatting + I/O per packet) and obscured the genuine
	/// state-change events operators care about.
	///
	/// PR2 demoted both call sites to `tracing::Level::DEBUG`. The test uses
	/// `#[tracing_test::traced_test]` to install a global subscriber that
	/// captures every event into a process-wide buffer, scoped per-test via
	/// the test's own span (the macro enters a span named after the function;
	/// `logs_assert` filters captured lines by ` {span_name}:`). Spawned
	/// tasks across `wind-tuic`, `wind-socks`, `wind-naive`, and this file's
	/// own helpers are wrapped with `Instrument::in_current_span` so the
	/// captured buffer sees events from deeply-nested `tokio::spawn` chains.
	/// A 32 KiB UDP payload forces ~28 fragments at the 1200-byte default
	/// datagram size; the assertion then confirms no `INFO` line contains
	/// either forbidden format string and that at least one `DEBUG` line
	/// does (proving fragmentation ran and the capture pipeline is alive).
	///
	/// Note on the `no-env-filter` feature: the `#[traced_test]` macro
	/// silently ignores its attribute arguments and hardcodes the EnvFilter
	/// directive to `<test_crate>=trace` (here `wind_test=trace`), which
	/// would reject every event whose target is an identifier-style string
	/// like `"udp"` or `"tuic_out"`. Enabling `tracing-test/no-env-filter`
	/// in `Cargo.toml` switches the directive to plain `trace`, matching
	/// every event regardless of target.
	#[tracing_test::traced_test]
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn test_pr2_fragmented_udp_emits_no_info_log_noise() {
		// (1) Spin up a UDP echo server on loopback.
		let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let echo_addr = echo.local_addr().unwrap();
		tokio::spawn(
			async move {
				let mut buf = vec![0u8; 65536];
				loop {
					match echo.recv_from(&mut buf).await {
						Ok((n, from)) => {
							let _ = echo.send_to(&buf[..n], from).await;
						}
						Err(_) => break,
					}
				}
			}
			.in_current_span(),
		);

		// (2) Bring up the TUIC server + client.
		let setup = setup_tuic_server().await.expect("setup tuic server");
		let client = connect_tuic_client(&setup).await.expect("connect tuic client");

		// (3) Build a wind-core UdpStream pair: the test owns one side, the
		// TUIC outbound owns the other.
		let (tx_to_client, rx_at_client) = tokio::sync::mpsc::channel::<UdpPacket>(32);
		let (tx_to_test, mut rx_at_test) = tokio::sync::mpsc::channel::<UdpPacket>(32);

		let stream_for_client = UdpStream {
			tx: tx_to_test,
			rx: rx_at_client,
		};
		let client_for_udp = client.clone();
		tokio::spawn(
			async move {
				let _ = client_for_udp.handle_udp(stream_for_client, None::<TuicOutbound>).await;
			}
			.in_current_span(),
		);

		// (4) Push a UDP packet that MUST fragment.
		//
		// macOS's default `net.inet.udp.maxdgram = 9216` limits one UDP
		// `send_to` to 9 KiB. The DirectCallback's UDP relay socket forwards
		// the reassembled payload as a single datagram to the echo server,
		// so a 32 KiB payload silently fails with EMSGSIZE on darwin and the
		// echo never roundtrips back — observed in CI. Cap at 9 KiB on
		// macOS; on every other platform keep the 32 KiB stress size so the
		// test still exercises a deep fragmentation count (~24 frags vs ~7).
		// At 9 KiB with the default 1414-byte QUIC datagram size we still
		// produce ~7 fragments, which is enough to verify the demoted-log
		// invariant.
		let payload_size = if cfg!(target_os = "macos") { 9 * 1024 } else { 32 * 1024 };
		let payload: Bytes = (0u8..=255).cycle().take(payload_size).collect::<Vec<u8>>().into();
		let target = TargetAddr::IPv4(std::net::Ipv4Addr::LOCALHOST, echo_addr.port());
		tx_to_client
			.send(UdpPacket {
				source: None,
				target: target.clone(),
				payload: payload.clone(),
			})
			.await
			.expect("send UDP packet into TUIC outbound");

		// (5) Drain the reassembled echo so we know fragmentation actually ran
		// on both sides before we examine logs.
		let echoed = tokio::time::timeout(Duration::from_secs(15), rx_at_test.recv())
			.await
			.expect("echo timed out — fragmentation roundtrip did not complete in time")
			.expect("upstream channel closed before echo arrived");
		assert_eq!(echoed.payload.len(), payload.len(), "echoed payload length mismatch");
		assert_eq!(echoed.payload, payload, "echoed payload bytes mismatch");

		// (6) Give spawned sender tasks a moment to flush any pending logs.
		tokio::time::sleep(Duration::from_millis(50)).await;

		// (7) Inspect the captured log lines. `tracing-test`'s `logs_assert`
		// filters captured lines by ` {span_name}:` (the test function name);
		// spawned tasks instrumented with `.in_current_span()` keep the
		// test's span as the current span, so their pre-formatted lines DO
		// include `test_pr2_..._noise:` and pass the filter.
		logs_assert(|lines: &[&str]| {
			for forbidden in ["Fragmentation params", "Sending fragment "] {
				if let Some(bad) = lines.iter().find(|l| l.contains(" INFO ") && l.contains(forbidden)) {
					return Err(format!(
						"PR2 demoted log '{forbidden}' is back at INFO level — found: {bad:?}"
					));
				}
			}
			if !lines.iter().any(|l| l.contains(" INFO ")) {
				return Err("sanity: no INFO events captured during the roundtrip".into());
			}
			let debug_hits = lines
				.iter()
				.filter(|l| l.contains(" DEBUG "))
				.filter(|l| l.contains("Sending fragment ") || l.contains("Fragmentation params"))
				.count();
			if debug_hits == 0 {
				return Err(
					"sanity: no DEBUG fragment events captured — fragmentation didn't run or the capture is broken".into(),
				);
			}
			Ok(())
		});
	}
}

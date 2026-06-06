//! 0-RTT integration test for the tokio-quiche (`wind-tuiche`) backend.
//!
//! Runs in its own test binary (separate process) because `tuic_client::run`
//! installs a process-global connection. 0-RTT early data is enabled on both
//! the server (`enable_early_data`) and the client (`zero_rtt_handshake`); the
//! test verifies the 0-RTT-enabled config path handshakes and relays correctly.
//!
//! It does not assert that early data was actually replayed on a resumed
//! handshake — that would require a custom resumption client; the first
//! connection is always 1-RTT.

use std::time::Duration;

use serial_test::serial;
use tokio::time::timeout;
use tuic_tests::{run_tcp_echo_server, start_quiche_pair, test_tcp_through_socks5};

#[tokio::test]
#[serial]
#[tracing_test::traced_test]
async fn quiche_zero_rtt_tcp_relay() -> eyre::Result<()> {
	let socks = start_quiche_pair(8464, 1094, true).await;

	let (tcp_echo, tcp_addr) = run_tcp_echo_server("127.0.0.1:0", "Quiche 0-RTT").await;
	tokio::time::sleep(Duration::from_millis(200)).await;

	let ok = timeout(
		Duration::from_secs(10),
		test_tcp_through_socks5(&socks, tcp_addr, b"hello 0-rtt over quiche", "Quiche 0-RTT"),
	)
	.await
	.expect("0-RTT TCP relay timed out");
	tcp_echo.abort();

	assert!(ok, "TCP echo through the 0-RTT quiche backend did not round-trip");
	Ok(())
}

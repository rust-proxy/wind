//! Backend-generic loopback smoke test.
//!
//! The same `run_case` exercise runs against both backends: open a bidi stream
//! and echo, send a uni stream, round-trip a datagram, confirm the keying
//! material matches on both ends, and close.

#![cfg(any(feature = "quinn", feature = "quiche"))]

use std::{net::SocketAddr, time::Duration};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wind_quic::{ClientTlsConfig, QuicConnection, QuicSendStream, ServerTlsConfig, TransportConfig};

/// Generate a self-signed cert for `localhost` and write it to a temp dir,
/// returning `(dir, cert_path, key_path)`. The dir is returned so it outlives
/// the test (dropping it deletes the files).
fn write_self_signed() -> (tempfile::TempDir, String, String) {
	let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
	let cert_pem = generated.cert.pem();
	let key_pem = generated.signing_key.serialize_pem();

	let dir = tempfile::tempdir().unwrap();
	let cert_path = dir.path().join("cert.pem");
	let key_path = dir.path().join("key.pem");
	std::fs::write(&cert_path, cert_pem).unwrap();
	std::fs::write(&key_path, key_pem).unwrap();
	(
		dir,
		cert_path.to_string_lossy().into_owned(),
		key_path.to_string_lossy().into_owned(),
	)
}

fn configs(cert: &str, key: &str) -> (ServerTlsConfig, ClientTlsConfig, TransportConfig) {
	let server_tls = ServerTlsConfig::from_pem_paths(cert, key);
	let mut client_tls = ClientTlsConfig::new("localhost");
	client_tls.verify_certificate = false;
	let transport = TransportConfig::default();
	(server_tls, client_tls, transport)
}

/// The shared exercise. `server` is a freshly-accepted server connection;
/// `client` is the matching client connection.
async fn run_case<C: QuicConnection>(server: C, client: C) {
	const LABEL: &[u8] = b"wind-quic-test-label";
	const CONTEXT: &[u8] = b"wind-quic-test-context";

	let server_task = tokio::spawn(async move {
		// 1. bidi echo.
		let (mut s_send, mut s_recv) = server.accept_bi().await.expect("accept_bi");
		let mut buf = [0u8; 4];
		s_recv.read_exact(&mut buf).await.expect("server read ping");
		assert_eq!(&buf, b"ping");
		s_send.write_all(b"pong").await.expect("server write pong");
		s_send.finish().expect("server finish");

		// 2. uni receive.
		let mut u_recv = server.accept_uni().await.expect("accept_uni");
		let mut ubuf = Vec::new();
		u_recv.read_to_end(&mut ubuf).await.expect("server read uni");
		assert_eq!(ubuf.as_slice(), b"hello-uni");

		// 3. datagram echo (if supported).
		if server.max_datagram_size().is_some() {
			let dg = server.read_datagram().await.expect("server read datagram");
			server.send_datagram(dg).expect("server echo datagram");
		}

		// 4. keying material.
		let mut km = [0u8; 32];
		server
			.export_keying_material(&mut km, LABEL, CONTEXT)
			.await
			.expect("server export keying material");

		// Give the datagram echo time to flush before the worker can be torn
		// down by the client closing.
		tokio::time::sleep(Duration::from_millis(50)).await;
		km
	});

	let client_km = {
		// 1. bidi echo.
		let (mut c_send, mut c_recv) = client.open_bi().await.expect("open_bi");
		c_send.write_all(b"ping").await.expect("client write ping");
		c_send.finish().expect("client finish");
		let mut buf = [0u8; 4];
		c_recv.read_exact(&mut buf).await.expect("client read pong");
		assert_eq!(&buf, b"pong");

		// 2. uni send.
		let mut u_send = client.open_uni().await.expect("open_uni");
		u_send.write_all(b"hello-uni").await.expect("client write uni");
		u_send.finish().expect("client finish uni");

		// 3. datagram round-trip.
		if client.max_datagram_size().is_some() {
			client
				.send_datagram(Bytes::from_static(b"datagram-payload"))
				.expect("client send datagram");
			let echoed = client.read_datagram().await.expect("client read datagram");
			assert_eq!(&echoed[..], b"datagram-payload");
		}

		// 4. keying material.
		let mut km = [0u8; 32];
		client
			.export_keying_material(&mut km, LABEL, CONTEXT)
			.await
			.expect("client export keying material");
		km
	};

	let server_km = server_task.await.expect("server task");
	assert_eq!(server_km, client_km, "RFC 5705 keying material must match on both ends");

	// 5. close completes.
	client.close(0, b"done");
	tokio::time::timeout(Duration::from_secs(2), client.closed())
		.await
		.expect("client.closed() should resolve after close");
}

#[cfg(feature = "quinn")]
#[test_log::test(tokio::test(flavor = "multi_thread", worker_threads = 2))]
async fn quinn_loopback() {
	use wind_quic::quinn;

	let (_dir, cert, key) = write_self_signed();
	let (server_tls, client_tls, transport) = configs(&cert, &key);

	let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
	let acceptor = quinn::bind_server(addr, &server_tls, &transport).expect("bind_server");
	let local = acceptor.local_addr().expect("local_addr");

	let server_fut = async move { acceptor.accept().await.expect("incoming").expect("server conn") };
	let client_fut = quinn::connect(local, &client_tls, &transport);
	let (server_conn, client_conn) = tokio::join!(server_fut, client_fut);
	let client_conn = client_conn.expect("client connect");

	run_case(server_conn, client_conn).await;
}

#[cfg(feature = "quiche")]
#[test_log::test(tokio::test(flavor = "multi_thread", worker_threads = 2))]
async fn quiche_loopback() {
	use wind_quic::quiche;

	let (_dir, cert, key) = write_self_signed();
	let (server_tls, client_tls, transport) = configs(&cert, &key);

	let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
	let mut acceptor = quiche::bind_server(addr, &server_tls, &transport, None)
		.await
		.expect("bind_server");
	let local = acceptor.local_addr();

	let server_fut = async move { acceptor.accept().await.expect("server conn") };
	let client_fut = quiche::connect(local, &client_tls, &transport);
	let (server_conn, client_conn) = tokio::join!(server_fut, client_fut);
	let client_conn = client_conn.expect("client connect");

	run_case(server_conn, client_conn).await;
}

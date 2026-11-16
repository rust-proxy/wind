//! Real Wind -> Cronet -> sing-box -> loopback TCP half-close regressions.
//! Set WIND_NAIVE_SING_BOX and WIND_NAIVE_CRONET_LIB, then run with --ignored.

use std::{
	fs::File,
	net::{Ipv4Addr, SocketAddr},
	path::PathBuf,
	process::{Child, Command, Stdio},
	sync::Arc,
	time::Duration,
};

use eyre::{Context, Result, bail};
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::TcpListener,
};
use tokio_util::task::AbortOnDropHandle;
use wind_core::{FlowContext, Outbound, hooks::Protocol, rule::NetworkType, types::TargetAddr};
use wind_naive::{NaiveOutbound, NaiveOutboundOpts};

struct Server {
	child: Child,
	_dir: tempfile::TempDir,
	port: u16,
	ca: String,
}

impl Drop for Server {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

impl Server {
	async fn start(quic: bool) -> Result<Self> {
		let binary =
			PathBuf::from(std::env::var_os("WIND_NAIVE_SING_BOX").ok_or_else(|| eyre::eyre!("set WIND_NAIVE_SING_BOX"))?);
		let dir = tempfile::tempdir()?;
		let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])?;
		params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
		params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(7);
		let key = rcgen::KeyPair::generate()?;
		let ca = params.self_signed(&key)?.pem();
		std::fs::write(dir.path().join("cert.pem"), &ca)?;
		std::fs::write(dir.path().join("key.pem"), key.serialize_pem())?;
		// sing-box binds after configuration is written; reserve an unused port
		// for the selected transport, and report startup failures explicitly.
		let port = if quic {
			std::net::UdpSocket::bind("127.0.0.1:0")?.local_addr()?.port()
		} else {
			std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port()
		};
		let config = serde_json::json!({
			"log": {"level": "info", "timestamp": false},
			"inbounds": [{
				"type": "naive", "listen": "127.0.0.1", "listen_port": port,
				// UDP-only proves the QUIC test cannot fall back to HTTP/2.
				"network": if quic { "udp" } else { "tcp" },
				"users": [{"username": "half-close-test", "password": "synthetic-password"}],
				"tls": {"enabled": true, "certificate_path": "cert.pem", "key_path": "key.pem"}
			}],
			"outbounds": [{"type": "direct"}]
		});
		std::fs::write(dir.path().join("server.json"), serde_json::to_vec(&config)?)?;
		let log_path = dir.path().join("server.log");
		let log = File::create(&log_path)?;
		let mut command = Command::new(binary.canonicalize()?);
		command.args(["run", "-c", "server.json"]).current_dir(dir.path());
		command.stdin(Stdio::null()).stdout(log.try_clone()?).stderr(log);
		#[cfg(windows)]
		{
			use std::os::windows::process::CommandExt;
			command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
		}
		let mut server = Self {
			child: command.spawn()?,
			_dir: dir,
			port,
			ca,
		};
		tokio::time::timeout(Duration::from_secs(10), async {
			loop {
				if let Some(status) = server.child.try_wait()? {
					bail!("sing-box exited with {status}: {}", std::fs::read_to_string(&log_path)?);
				}
				if std::fs::read_to_string(&log_path)?.contains("sing-box started") {
					return Ok::<_, eyre::Report>(());
				}
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		})
		.await
		.context("sing-box startup timed out")??;
		Ok(server)
	}
}

fn flow(target: SocketAddr) -> FlowContext {
	FlowContext {
		target: TargetAddr::IPv4(Ipv4Addr::LOCALHOST, target.port()),
		network: NetworkType::Tcp,
		source: None,
		inbound_tag: "half-close-e2e".into(),
		protocol: Protocol::Naive,
		user: None,
		inbound_port: None,
		inbound_type: None,
	}
}

async fn request_half_close(outbound: Arc<NaiveOutbound>, size: usize) -> Result<()> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let destination = listener.local_addr()?;
	let request: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
	let expected_request = request.clone();
	let response = vec![0xa5; 256 * 1024];
	let expected_response = response.clone();
	let target = AbortOnDropHandle::new(tokio::spawn(async move {
		let (mut socket, _) = listener.accept().await?;
		let mut received = Vec::new();
		socket.read_to_end(&mut received).await?;
		assert_eq!(received.len(), expected_request.len());
		assert!(received == expected_request, "request contents differ");
		// Only the real destination's TCP EOF can release this response.
		socket.write_all(&response).await?;
		socket.shutdown().await?;
		Ok::<_, eyre::Report>(())
	}));
	let (local, mut client) = tokio::io::duplex(1024);
	let relay = AbortOnDropHandle::new(tokio::spawn(async move {
		outbound.handle_tcp(flow(destination), Box::new(local)).await
	}));
	client.write_all(&request).await?;
	client.shutdown().await?;
	client.shutdown().await?;
	let mut received = Vec::new();
	client.read_to_end(&mut received).await?;
	assert_eq!(received.len(), expected_response.len());
	assert!(received == expected_response, "response contents differ");
	relay.await??;
	target.await??;
	Ok(())
}

async fn half_close_suite(quic: bool) -> Result<()> {
	let server = Server::start(quic).await?;
	let address = format!("127.0.0.1:{}", server.port);
	let outbound = Arc::new(
		NaiveOutbound::new(NaiveOutboundOpts {
			server_address: address.clone(),
			// The native client currently builds its URL from this full authority.
			server_name: Some(address),
			username: Some("half-close-test".into()),
			password: Some("synthetic-password".into()),
			trusted_root_certificates: Some(server.ca.clone()),
			cronet_lib_path: Some(std::env::var("WIND_NAIVE_CRONET_LIB").context("set WIND_NAIVE_CRONET_LIB")?),
			quic_enabled: quic,
			..Default::default()
		})
		.await?,
	);
	for size in [0, 7, 256 * 1024] {
		tokio::time::timeout(Duration::from_secs(15), request_half_close(outbound.clone(), size))
			.await
			.context(format!("request half-close timed out (size={size}, quic={quic})"))??;
	}
	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires sing-box and native Cronet"]
async fn h2_half_close_e2e() -> Result<()> {
	half_close_suite(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires sing-box and native Cronet"]
async fn h3_half_close_e2e() -> Result<()> {
	half_close_suite(true).await
}

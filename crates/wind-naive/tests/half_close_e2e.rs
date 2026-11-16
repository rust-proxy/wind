//! Real Wind -> Cronet -> Docker sing-box -> host TCP half-close regressions.
//! Set CLIENT_IP and WIND_NAIVE_CRONET_LIB, then run with --ignored.

use std::{
	collections::HashMap,
	net::{Ipv4Addr, SocketAddrV4},
	panic::AssertUnwindSafe,
	sync::Arc,
	time::Duration,
};

use bollard::{
	API_DEFAULT_VERSION, Docker, body_full,
	models::{ContainerCreateBody, HostConfig, PortBinding},
	query_parameters::{
		CreateContainerOptions, CreateImageOptions, LogsOptions, RemoveContainerOptions, StartContainerOptions,
		UploadToContainerOptions,
	},
};
use eyre::{Context, ContextCompat, Result, bail};
use futures_util::{FutureExt, TryStreamExt};
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::TcpListener,
};
use tokio_util::task::AbortOnDropHandle;
use wind_core::{FlowContext, Outbound, hooks::Protocol, rule::NetworkType, types::TargetAddr};
use wind_naive::{NaiveOutbound, NaiveOutboundOpts};

const IMAGE: &str = "ghcr.io/sagernet/sing-box:v1.14.4";

struct Server {
	docker: Docker,
	id: String,
	host: String,
	port: u16,
	ca: String,
	target_ip: Ipv4Addr,
}

impl Server {
	async fn start(quic: bool) -> Result<Self> {
		// Explicit callback address also supports remote Docker daemons.
		let target_ip = std::env::var("CLIENT_IP")
			.context("set CLIENT_IP to the test host IPv4 address reachable from Docker")?
			.parse()?;
		let (docker, host) = match std::env::var("DOCKER_HOST") {
			Ok(endpoint) if endpoint.starts_with("tcp://") || endpoint.starts_with("http://") => {
				let url = url::Url::parse(&endpoint)?;
				let host = url.host_str().context("DOCKER_HOST has no host")?.to_owned();
				(
					Docker::connect_with_http(&endpoint.replacen("tcp://", "http://", 1), 60, API_DEFAULT_VERSION)?,
					host,
				)
			}
			Ok(endpoint) => (
				Docker::connect_with_socket(&endpoint, 60, API_DEFAULT_VERSION)?,
				"127.0.0.1".into(),
			),
			Err(_) => (Docker::connect_with_socket_defaults()?, "127.0.0.1".into()),
		};
		let mut pull = docker.create_image(
			Some(CreateImageOptions {
				from_image: Some(IMAGE.into()),
				..Default::default()
			}),
			None,
			None,
		);
		while pull.try_next().await?.is_some() {}
		let mut params = rcgen::CertificateParams::new(vec![host.clone()])?;
		params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
		params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(7);
		let key = rcgen::KeyPair::generate()?;
		let ca = params.self_signed(&key)?.pem();
		let config = serde_json::json!({
			"log": {"level": "info", "timestamp": false},
			"inbounds": [{
				"type": "naive", "listen": "0.0.0.0", "listen_port": 10002,
				// UDP-only proves the QUIC test cannot fall back to HTTP/2.
				"network": if quic { "udp" } else { "tcp" },
				"users": [{"username": "half-close-test", "password": "synthetic-password"}],
				"tls": {"enabled": true, "certificate_path": "/cert.pem", "key_path": "/key.pem"}
			}],
			"outbounds": [{"type": "direct"}]
		});
		let mut archive = tar::Builder::new(Vec::new());
		for (name, content) in [
			("cert.pem", ca.as_bytes().to_vec()),
			("key.pem", key.serialize_pem().into_bytes()),
			("server.json", serde_json::to_vec(&config)?),
		] {
			let mut header = tar::Header::new_gnu();
			header.set_size(content.len() as u64);
			header.set_mode(0o600);
			header.set_cksum();
			archive.append_data(&mut header, name, content.as_slice())?;
		}
		let archive = archive.into_inner()?;
		let port_key = format!("10002/{}", if quic { "udp" } else { "tcp" });
		let created = docker
			.create_container(
				Some(CreateContainerOptions::default()),
				ContainerCreateBody {
					image: Some(IMAGE.into()),
					cmd: Some(vec!["run".into(), "-c".into(), "/server.json".into()]),
					exposed_ports: Some(vec![port_key.clone()]),
					host_config: Some(HostConfig {
						port_bindings: Some(HashMap::from([(
							port_key.clone(),
							Some(vec![PortBinding {
								host_ip: Some("0.0.0.0".into()),
								host_port: Some("0".into()),
							}]),
						)])),
						..Default::default()
					}),
					..Default::default()
				},
			)
			.await?;
		let mut server = Self {
			docker,
			id: created.id,
			host,
			port: 0,
			ca,
			target_ip,
		};
		let ready = async {
			server
				.docker
				.upload_to_container(
					&server.id,
					Some(UploadToContainerOptions {
						path: "/".into(),
						..Default::default()
					}),
					body_full(archive.into()),
				)
				.await?;
			server
				.docker
				.start_container(&server.id, Some(StartContainerOptions::default()))
				.await?;
			let inspect = server.docker.inspect_container(&server.id, None).await?;
			server.port = inspect
				.network_settings
				.and_then(|n| n.ports)
				.and_then(|mut ports| ports.remove(&port_key))
				.flatten()
				.and_then(|ports| ports.into_iter().find_map(|p| p.host_port))
				.context("Docker did not publish a port")?
				.parse()?;
			tokio::time::timeout(Duration::from_secs(15), async {
				loop {
					let logs = server
						.docker
						.logs(
							&server.id,
							Some(LogsOptions {
								stdout: true,
								stderr: true,
								..Default::default()
							}),
						)
						.try_collect::<Vec<_>>()
						.await?;
					let output = logs.iter().map(ToString::to_string).collect::<String>();
					let inspect = server.docker.inspect_container(&server.id, None).await?;
					if !inspect.state.and_then(|s| s.running).unwrap_or(false) {
						bail!("sing-box exited: {output}");
					}
					if output.contains("sing-box started") {
						return Ok::<_, eyre::Report>(());
					}
					tokio::time::sleep(Duration::from_millis(50)).await;
				}
			})
			.await
			.context("Docker sing-box startup timed out")??;
			Ok::<_, eyre::Report>(())
		}
		.await;
		if let Err(error) = ready {
			server.cleanup().await?;
			return Err(error);
		}
		Ok(server)
	}

	async fn cleanup(&self) -> Result<()> {
		let logs = self
			.docker
			.logs(
				&self.id,
				Some(LogsOptions {
					stdout: true,
					stderr: true,
					..Default::default()
				}),
			)
			.try_collect::<Vec<_>>()
			.await;
		if let Ok(logs) = logs {
			for line in logs {
				eprint!("{line}");
			}
		}
		self.docker
			.remove_container(
				&self.id,
				Some(RemoveContainerOptions {
					force: true,
					..Default::default()
				}),
			)
			.await?;
		Ok(())
	}
}

fn flow(target: SocketAddrV4) -> FlowContext {
	FlowContext {
		target: TargetAddr::IPv4(*target.ip(), target.port()),
		network: NetworkType::Tcp,
		source: None,
		inbound_tag: "half-close-e2e".into(),
		protocol: Protocol::Naive,
		user: None,
		inbound_port: None,
		inbound_type: None,
	}
}

async fn request_half_close(outbound: Arc<NaiveOutbound>, target_ip: Ipv4Addr, size: usize) -> Result<()> {
	let listener = TcpListener::bind("0.0.0.0:0").await?;
	let destination = SocketAddrV4::new(target_ip, listener.local_addr()?.port());
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
	let result = AssertUnwindSafe(async {
		let address = format!("{}:{}", server.host, server.port);
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
			tokio::time::timeout(
				Duration::from_secs(15),
				request_half_close(outbound.clone(), server.target_ip, size),
			)
			.await
			.context(format!("request half-close timed out (size={size}, quic={quic})"))??;
		}
		Ok::<_, eyre::Report>(())
	})
	.catch_unwind()
	.await;
	let cleanup = server.cleanup().await;
	match result {
		Ok(result) => {
			result?;
			cleanup
		}
		Err(panic) => {
			cleanup?;
			std::panic::resume_unwind(panic)
		}
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker, CLIENT_IP and native Cronet"]
async fn h2_half_close_e2e() -> Result<()> {
	half_close_suite(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker, CLIENT_IP and native Cronet"]
async fn h3_half_close_e2e() -> Result<()> {
	half_close_suite(true).await
}

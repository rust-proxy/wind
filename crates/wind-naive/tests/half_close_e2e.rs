//! Real Wind -> Cronet -> Docker sing-box -> container TCP half-close
//! regressions. In dynamic mode set WIND_NAIVE_CRONET_LIB, then run with
//! --ignored.

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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::task::AbortOnDropHandle;
use wind_core::{FlowContext, Outbound, hooks::Protocol, rule::NetworkType, types::TargetAddr};
use wind_naive::{NaiveOutbound, NaiveOutboundOpts};

const IMAGE: &str = "ghcr.io/sagernet/sing-box:v1.14.4";
const TARGET_IMAGE: &str = "python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e";

struct Server {
	docker: Docker,
	id: String,
	host: String,
	port: u16,
	ca: String,
	target_id: Option<String>,
}

impl Server {
	async fn start(quic: bool) -> Result<Self> {
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
		for image in [IMAGE, TARGET_IMAGE] {
			// Digest-pinned fixtures can be reused without contacting the
			// registry.
			if image.contains("@sha256:") && docker.inspect_image(image).await.is_ok() {
				continue;
			}
			let mut pull = docker.create_image(
				Some(CreateImageOptions {
					from_image: Some(image.into()),
					..Default::default()
				}),
				None,
				None,
			);
			while pull.try_next().await?.is_some() {}
		}
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
			target_id: None,
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
			let target = server
				.docker
				.create_container(
					Some(CreateContainerOptions::default()),
					ContainerCreateBody {
						image: Some(TARGET_IMAGE.into()),
						cmd: Some(vec!["python".into(), "-u".into(), "/targets.py".into()]),
						host_config: Some(HostConfig {
							network_mode: Some(format!("container:{}", server.id)),
							..Default::default()
						}),
						..Default::default()
					},
				)
				.await?;
			server.target_id = Some(target.id.clone());
			let mut archive = tar::Builder::new(Vec::new());
			let content = include_bytes!("targets.py");
			let mut header = tar::Header::new_gnu();
			header.set_size(content.len() as u64);
			header.set_mode(0o600);
			header.set_cksum();
			archive.append_data(&mut header, "targets.py", content.as_slice())?;
			server
				.docker
				.upload_to_container(
					&target.id,
					Some(UploadToContainerOptions {
						path: "/".into(),
						..Default::default()
					}),
					body_full(archive.into_inner()?.into()),
				)
				.await?;
			server
				.docker
				.start_container(&target.id, Some(StartContainerOptions::default()))
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
					let target_output = server
						.docker
						.logs(
							&target.id,
							Some(LogsOptions {
								stdout: true,
								stderr: true,
								..Default::default()
							}),
						)
						.try_collect::<Vec<_>>()
						.await?
						.iter()
						.map(ToString::to_string)
						.collect::<String>();
					if !server
						.docker
						.inspect_container(&target.id, None)
						.await?
						.state
						.and_then(|s| s.running)
						.unwrap_or(false)
					{
						bail!("targets exited: {target_output}");
					}
					if output.contains("sing-box started") && target_output.contains("half-close targets ready") {
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
		let target_cleanup = if let Some(id) = &self.target_id {
			self.docker
				.remove_container(
					id,
					Some(RemoveContainerOptions {
						force: true,
						..Default::default()
					}),
				)
				.await
		} else {
			Ok(())
		};
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
		target_cleanup?;
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

async fn request_half_close(outbound: Arc<NaiveOutbound>, index: usize, size: usize) -> Result<()> {
	let destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10003 + index as u16);
	let request: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
	let expected_response = vec![0xa5; 256 * 1024];
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
	Ok(())
}

async fn half_close_suite(quic: bool) -> Result<()> {
	let server = Server::start(quic).await?;
	let result = AssertUnwindSafe(async {
		let address = format!("{}:{}", server.host, server.port);
		for round in 0..3 {
			let outbound = Arc::new(
				NaiveOutbound::new(NaiveOutboundOpts {
					server_address: address.clone(),
					// Cronet builds the URL from this host and port.
					server_name: Some(address.clone()),
					username: Some("half-close-test".into()),
					password: Some("synthetic-password".into()),
					trusted_root_certificates: Some(server.ca.clone()),
					cronet_lib_path: std::env::var("WIND_NAIVE_CRONET_LIB").ok(),
					quic_enabled: quic,
					..Default::default()
				})
				.await?,
			);
			for (index, size) in [0, 7, 256 * 1024].into_iter().enumerate() {
				tokio::time::timeout(Duration::from_secs(15), request_half_close(outbound.clone(), index, size))
					.await
					.context(format!(
						"request half-close timed out (round={round}, size={size}, quic={quic})"
					))??;
			}
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
#[ignore = "requires Docker and native Cronet"]
async fn h2_half_close_e2e() -> Result<()> {
	half_close_suite(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker and native Cronet"]
async fn h3_half_close_e2e() -> Result<()> {
	half_close_suite(true).await
}

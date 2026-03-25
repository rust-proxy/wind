use std::{
	net::{IpAddr, Ipv4Addr, SocketAddr},
	sync::{Arc, atomic::AtomicU16},
	time::Duration,
};
use quinn_congestions::bbr::BbrConfig;
use eyre::ensure;
use moka::future::Cache;
use quinn::TokioRuntime;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use wind_core::{
	AbstractOutbound, AppContext, info,
	tcp::AbstractTcpStream,
	types::TargetAddr,
	udp::{UdpPacket, UdpStream},
	warn,
};

use crate::{
	Error,
	proto::{ClientProtoExt, UdpStream as TuicUdpStream},
	task::ClientTaskExt,
};

pub struct TuicOutboundOpts {
	pub peer_addr: SocketAddr,
	pub sni: String,
	pub auth: (Uuid, Arc<[u8]>),
	pub zero_rtt_handshake: bool,
	pub heartbeat: Duration,
	pub gc_interval: Duration,
	pub gc_lifetime: Duration,
	pub skip_cert_verify: bool,
	pub alpn: Vec<String>,
}

pub struct TuicOutbound {
	pub ctx: Arc<AppContext>,
	pub endpoint: quinn::Endpoint,
	pub peer_addr: SocketAddr,
	pub sni: String,
	pub opts: TuicOutboundOpts,
	pub connection: quinn::Connection,
	pub udp_assoc_counter: AtomicU16,
	pub token: CancellationToken,
	pub udp_session: Cache<u16, Arc<TuicUdpStream>>,
}

impl TuicOutbound {
	pub async fn new(ctx: Arc<AppContext>, opts: TuicOutboundOpts) -> Result<Self, Error> {
		let peer_addr = opts.peer_addr;
		let server_name = opts.sni.clone();

		// TODO move to top-level initialization
		{
			#[cfg(feature = "aws-lc-rs")]
			let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
			#[cfg(feature = "ring")]
			let _ = rustls::crypto::ring::default_provider().install_default();
		}
		info!(target: "[OUT]", "Creating a new outboud");
		let client_config = {
			let tls_config = super::tls::tls_config(&server_name, &opts)?;

			let mut client_config = quinn::ClientConfig::new(Arc::new(
				quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).unwrap(),
			));
			let mut transport_config = quinn::TransportConfig::default();
			transport_config
				.congestion_controller_factory(Arc::new(BbrConfig::default()))
				.keep_alive_interval(None);

			client_config.transport_config(Arc::new(transport_config));
			client_config
		};
		let socket_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
		let socket = UdpSocket::bind(&socket_addr)
			.await
			.map_err(|e| eyre::eyre!("Failed to bind socket to {}: {}", socket_addr, e))?
			.into_std()?;

		let mut endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, Arc::new(TokioRuntime))?;
		endpoint.set_default_client_config(client_config);
		let connection = endpoint
			.connect(peer_addr, &server_name)
			.map_err(|e| eyre::eyre!("Failed to connect to {} ({}): {}", peer_addr, server_name, e))?
			.await?;

		connection.send_auth(&opts.auth.0, &opts.auth.1).await?;

		Ok(Self {
			token: ctx.token.child_token(),
			ctx,
			endpoint,
			peer_addr,
			sni: server_name,
			opts,
			connection,
			udp_assoc_counter: AtomicU16::new(0),
			udp_session: Cache::new(u16::MAX.into()),
		})
	}

	pub async fn start_poll(&self) -> eyre::Result<()> {
		// Monitor cancellation token for shutdown
		let cancel_token = self.ctx.token.child_token();
		let connection = self.connection.clone();
		let udp_session = self.udp_session.clone();

		let mut hb_interval = tokio::time::interval(self.opts.heartbeat);
		const HEARTBEAT_MAX_FAILURES: usize = 3;

		let (datagram_rx, bi_rx, uni_rx) = self
			.connection
			.handle_incoming(self.ctx.clone(), cancel_token.clone())
			.await?;

		self.ctx.tasks.spawn(async move {
			let mut hb_failures = 0;
			hb_interval.tick().await;

			loop {
				tokio::select! {
					_ = cancel_token.cancelled() => {
						info!(target: "[OUT]", "Heartbeat poll cancelled");
						return Ok(());
					}
					_ = hb_interval.tick() => {
						if let Err(e) = connection.send_heartbeat().await {
							hb_failures += 1;
							info!(target: "[OUT]", "Heartbeat failed ({}/{}): {}", hb_failures, HEARTBEAT_MAX_FAILURES, e);

							if hb_failures >= HEARTBEAT_MAX_FAILURES {
								return Err(eyre::eyre!("Too many heartbeat failures ({}/{})", hb_failures, HEARTBEAT_MAX_FAILURES));
							}
						} else if hb_failures > 0 {
							info!(target: "[OUT]", "Heartbeat succeeded after {} failures", hb_failures);
							hb_failures = 0;
						}
					}
					Ok(_) = bi_rx.recv() => {
						warn!(target: "[OUT]", "Received bi-directional stream on Outbound");
					}
					Ok(bytes) = datagram_rx.recv() => {
						info!(target: "[OUT]", "Received datagram: {} bytes", bytes.len());
						// Process the received datagram
						use bytes::Buf;

						let mut buf = bytes::BytesMut::from(bytes.as_ref());

						// Parse header, command, and address using helper functions
						let header = match crate::proto::decode_header(&mut buf, "datagram") {
							Ok(h) => h,
							Err(e) => {
								warn!(target: "[OUT]", "Failed to decode header: {}", e);
								continue;
							}
						};

						let cmd = match crate::proto::decode_command(header.command, &mut buf, "datagram") {
							Ok(c) => c,
							Err(e) => {
								warn!(target: "[OUT]", "Failed to decode command: {}", e);
								continue;
							}
						};

						// Process UDP packet
						if let crate::proto::Command::Packet {
							assoc_id,
							pkt_id,
							frag_total,
							frag_id,
							size,
						} = cmd {
							// Parse address
							let addr = match crate::proto::decode_address(&mut buf, "UDP packet") {
								Ok(a) => a,
								Err(e) => {
									warn!(target: "[OUT]", "Failed to decode address: {}", e);
									continue;
								}
							};

							// Extract payload
							let payload = buf.copy_to_bytes(size as usize);

							// Convert address to TargetAddr and handle logging
							let (target, has_address) = match crate::proto::address_to_target(addr) {
								Ok(t) => (t, true),
								Err(_) => {
									(TargetAddr::IPv4(std::net::Ipv4Addr::UNSPECIFIED, 0), false)
								}
							};

							if has_address {
								info!(target: "[OUT]", "Received UDP packet: assoc={:#06x}, pkt={}, frag={}/{}, size={}, target={}",
									assoc_id, pkt_id, frag_id + 1, frag_total, size, target);
							} else {
								info!(target: "[OUT]", "Received UDP fragment: assoc={:#06x}, pkt={}, frag={}/{}, size={} (no address - non-first fragment)",
									assoc_id, pkt_id, frag_id + 1, frag_total, size);
							}

							// Find the corresponding UDP session
							if let Some(tuic_udp_stream) = udp_session.get(&assoc_id).await {
								let complete_packet = if frag_total > 1 {
									tuic_udp_stream.process_fragment(assoc_id, pkt_id, frag_total, frag_id, payload, None, target).await
								} else {
									Some(wind_core::udp::UdpPacket {
										source: None,
										target,
										payload,
									})
								};

							if let Some(packet) = complete_packet {
                                if let Err(e) = tuic_udp_stream.receive_packet(packet).await {
									warn!(target: "[OUT]", "Failed to send packet to UDP session {:#06x}: {}", assoc_id, e);
								}
                            }
						} else {
								warn!(target: "[OUT]", "Received UDP packet for unknown association {:#06x}", assoc_id);
							}
						} else {
							warn!(target: "[OUT]", "Received non-Packet command in datagram: {:?}", cmd);
						}
					}

					Ok(_recv) = uni_rx.recv() => {
						info!(target: "[OUT]", "Received uni-directional stream");
					}
				}
			}
		});

		Ok(())
	}
}

pub struct TuicTcpStream;

impl AbstractOutbound for TuicOutbound {
	async fn handle_tcp(
		&self,
		target_addr: TargetAddr,
		stream: impl AbstractTcpStream,
		_dialer: Option<impl AbstractOutbound>,
	) -> eyre::Result<()> {
		self.connection.open_tcp(&target_addr, stream).await?;
		Ok(())
	}

	async fn handle_udp(
		&self,
		client_stream: wind_core::udp::UdpStream,
		_dialer: Option<impl AbstractOutbound>,
	) -> eyre::Result<()> {
		use std::sync::atomic::Ordering;
		// Create a cancel token for single udp session
		let cancel = self.token.child_token();
		// Generate a new UDP association ID
		let assoc_id = self.udp_assoc_counter.fetch_add(1, Ordering::SeqCst);
		info!(target: "[OUT]", "Creating new UDP association: {:#06x}", assoc_id);

		let connection = self.connection.clone();
		let (receive_tx, receive_rx) = crossfire::mpmc::bounded_async(128);
		let tuic_stream = Arc::new(crate::proto::UdpStream::new(connection.clone(), assoc_id, receive_tx));
		self.udp_session.insert(assoc_id, tuic_stream.clone()).await;
		let cancel_stream = cancel.clone();

		let mut gc_interval = tokio::time::interval(self.opts.gc_interval);
		gc_interval.tick().await;

		let mut client_rx = client_stream.rx;
		let client_tx = client_stream.tx;

		self.ctx.tasks.spawn(async move {
			loop {
				tokio::select! {
					_ = cancel_stream.cancelled() => {
						info!(target: "[OUT]", "UDP stream sender for association {:#06x} cancelled", assoc_id);
						break;
					}

					result = receive_rx.recv() => {
						let packet = match result {
							Err(e) => {
								warn!(target: "[OUT]", "Error receiving packet from channel for association {:#06x}: {}", assoc_id, e);
								break;
							}
							Ok(packet) => packet,
						};

						if let Err(e) = client_tx.send(packet).await {
							warn!(target: "[OUT]", "Failed to send UDP packet to local socket (assoc {:#06x}): {:?}", assoc_id, e);
							break;
						} else {
							info!(target: "[OUT]", "Received UDP packet forward to local (assoc {:#06x})", assoc_id);
						}
					}
					// send queue
					packet = client_rx.recv() => {
						let packet = match packet {
							None => {
								warn!(target: "[OUT]", "Error receiving packet from channel for association {:#06x}: channel closed", assoc_id);
								break;
							}
							Some(packet) => packet,
						};

						// Send packet to remote via UDP stream
						let payload_len = packet.payload.len();
						if let Err(e) = tuic_stream.send_packet(packet).await {
							warn!(target: "[OUT]", "Failed to send UDP packet to remote (assoc {:#06x}): {}", assoc_id, e);
						} else {
							info!(target: "[OUT]", "Sent UDP packet to remote ({} bytes, assoc {:#06x})", payload_len, assoc_id);
						}
					}
					_ = gc_interval.tick() => {
						// Perform garbage collection of expired fragments
						tuic_stream.collect_garbage().await;
					}
				}
			}
			eyre::Ok(())
		});

		let cancel_healthy = self.ctx.token.clone();
		loop {
			tokio::select! {
				_ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
					info!(target: "[OUT]", "UDP handler for association {:#06x} active", assoc_id);
				}

				_ = cancel_healthy.cancelled() => break,
			}
		}

		// Clean up the UDP association before exiting
		if let Err(err) = self.connection.drop_udp(assoc_id).await {
			info!(target: "[OUT]", "Error dropping UDP association {:#06x}: {}", assoc_id, err);
		}

		Ok(())
	}
}

use socks5_proto::{Address, Reply};
use socks5_server::{
	Associate, Bind, Connect,
	connection::{associate, bind, connect},
};
use tracing::{debug, warn};
use wind_core::{
	AbstractOutbound,
	types::TargetAddr,
	udp::{UdpPacket, UdpStream},
};

use super::{Server, UDP_SESSIONS, udp_session::UdpSession};
use crate::wind_adapter::get_connection;

impl Server {
	pub async fn handle_associate(
		assoc: Associate<associate::NeedReply>,
		assoc_id: u16,
		dual_stack: Option<bool>,
		max_pkt_size: usize,
	) {
		let peer_addr = assoc.peer_addr().unwrap();
		let local_ip = assoc.local_addr().unwrap().ip();

		match UdpSession::new(assoc_id, peer_addr, local_ip, dual_stack, max_pkt_size) {
			Ok(session) => {
				let local_addr = session.local_addr().unwrap();
				debug!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] bound to {local_addr}");

				let mut assoc = match assoc.reply(Reply::Succeeded, Address::SocketAddress(local_addr)).await {
					Ok(assoc) => assoc,
					Err(err) => {
						warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] command reply error: {err}");
						return;
					}
				};

				UDP_SESSIONS.get().unwrap().write().await.insert(assoc_id, session.clone());

				// Create wind UdpStream channels
				// wind_tx: packets from local SOCKS5 client → send to remote (outbound reads
				// rx) wind_rx: packets from remote → send back to local SOCKS5 client
				// (outbound writes tx)
				let (local_to_remote_tx, local_to_remote_rx) = tokio::sync::mpsc::channel::<UdpPacket>(128);
				let (remote_to_local_tx, mut remote_to_local_rx) = tokio::sync::mpsc::channel::<UdpPacket>(128);

				let wind_udp_stream = UdpStream {
					tx: remote_to_local_tx,
					rx: local_to_remote_rx,
				};

				// Task: receive from local SOCKS5 UDP socket → forward to wind outbound
				let session_recv = session.clone();
				let local_to_remote_tx_clone = local_to_remote_tx.clone();
				let handle_local_incoming_pkt = async move {
					loop {
						let (pkt, target_addr) = match session_recv.recv().await {
							Ok(res) => res,
							Err(err) => {
								warn!(
									"[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed to receive UDP packet: {err}"
								);
								continue;
							}
						};

						let target = match target_addr {
							Address::DomainAddress(domain, port) => TargetAddr::Domain(domain, port),
							Address::SocketAddress(addr) => TargetAddr::from(addr),
						};

						let udp_pkt = UdpPacket {
							source: None,
							target,
							payload: pkt,
						};

						if let Err(err) = local_to_remote_tx_clone.send(udp_pkt).await {
							warn!(
								"[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed forwarding UDP packet to wind: \
								 {err}"
							);
						}
					}
				};

				// Task: receive from wind outbound → forward back to local SOCKS5 UDP client
				let session_send = session.clone();
				let handle_remote_incoming_pkt = async move {
					while let Some(pkt) = remote_to_local_rx.recv().await {
						let src_addr = match pkt.source.or(Some(pkt.target.clone())) {
							Some(TargetAddr::Domain(domain, port)) => Address::DomainAddress(domain, port),
							Some(TargetAddr::IPv4(ip, port)) => {
								Address::SocketAddress(std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port))
							}
							Some(TargetAddr::IPv6(ip, port)) => {
								Address::SocketAddress(std::net::SocketAddr::new(std::net::IpAddr::V6(ip), port))
							}
							None => Address::unspecified(),
						};

						if let Err(err) = session_send.send(pkt.payload, src_addr).await {
							warn!(
								"[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed sending UDP packet to local: \
								 {err}"
							);
						}
					}
				};

				// Spawn wind outbound UDP handler
				let outbound_handle = tokio::spawn(async move {
					match get_connection() {
						Some(adapter) => {
							if let Err(err) = adapter
								.handle_udp(wind_udp_stream, None::<crate::wind_adapter::TuicOutboundAdapter>)
								.await
							{
								warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] wind UDP handler error: {err}");
							}
						}
						None => {
							warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] no wind connection available");
						}
					}
				});

				tokio::spawn(handle_remote_incoming_pkt);

				match tokio::select! {
					res = assoc.wait_until_closed() => res,
					_ = handle_local_incoming_pkt => unreachable!(),
				} {
					Ok(()) => {}
					Err(err) => {
						warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] associate connection error: {err}")
					}
				}

				debug!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] stopped associating");

				UDP_SESSIONS.get().unwrap().write().await.remove(&assoc_id).unwrap();

				// Cancel the outbound UDP handler
				outbound_handle.abort();
			}
			Err(err) => {
				warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed setting up UDP associate session: {err}");

				match assoc.reply(Reply::GeneralFailure, Address::unspecified()).await {
					Ok(mut assoc) => {
						let _ = assoc.shutdown().await;
					}
					Err(err) => {
						warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] command reply error: {err}")
					}
				}
			}
		}
	}

	pub async fn handle_bind(bind: Bind<bind::NeedFirstReply>) {
		let peer_addr = bind.peer_addr().unwrap();
		warn!("[socks5] [{peer_addr}] [bind] command not supported");

		match bind.reply(Reply::CommandNotSupported, Address::unspecified()).await {
			Ok(mut bind) => {
				let _ = bind.shutdown().await;
			}
			Err(err) => warn!("[socks5] [{peer_addr}] [bind] command reply error: {err}"),
		}
	}

	pub async fn handle_connect(conn: Connect<connect::NeedReply>, addr: Address) {
		let peer_addr = conn.peer_addr().unwrap();
		let target_addr = match addr {
			Address::DomainAddress(domain, port) => TargetAddr::Domain(domain, port),
			Address::SocketAddress(addr) => TargetAddr::from(addr),
		};

		match conn.reply(Reply::Succeeded, Address::unspecified()).await {
			Ok(conn) => match get_connection() {
				Some(adapter) => {
					if let Err(err) = adapter
						.handle_tcp(target_addr.clone(), conn, None::<crate::wind_adapter::TuicOutboundAdapter>)
						.await
					{
						warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] TCP stream relay error: {err}");
					}
				}
				None => {
					warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] no wind connection available");
				}
			},
			Err(err) => {
				warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] command reply error: {err}");
			}
		}
	}
}

use std::{
	net::{Ipv4Addr, SocketAddr},
	sync::Arc,
};

use arc_swap::ArcSwap;
use fast_socks5::{new_udp_header, util::target_addr::TargetAddr as SocksTargetAddr};
use tokio::net::UdpSocket;
use tokio_util::bytes::Bytes;
use tracing::warn;
use wind_core::{
	types::TargetAddr,
	udp::{UdpPacket, UdpStream},
};

/// Convert SOCKS target address to our TargetAddr
fn convert_target_addr(socks_addr: &SocksTargetAddr) -> TargetAddr {
	match socks_addr {
		SocksTargetAddr::Ip(socket_addr) => match socket_addr {
			SocketAddr::V4(addr) => TargetAddr::IPv4(*addr.ip(), addr.port()),
			SocketAddr::V6(addr) => TargetAddr::IPv6(*addr.ip(), addr.port()),
		},
		SocksTargetAddr::Domain(domain, port) => TargetAddr::Domain(domain.clone(), *port),
	}
}

/// Synchronously parse SOCKS5 UDP request header
fn parse_udp_request_sync(data: &[u8]) -> Result<(u8, SocksTargetAddr, &[u8]), String> {
	if data.len() < 4 {
		return Err("Packet too short for SOCKS5 UDP header".into());
	}

	// Check reserved bytes (should be 0x00 0x00)
	if data[0] != 0x00 || data[1] != 0x00 {
		return Err("Invalid reserved bytes in SOCKS5 UDP header".into());
	}

	let frag = data[2];
	let atyp = data[3];

	let mut offset = 4;

	let target_addr = match atyp {
		0x01 => {
			if data.len() < offset + 6 {
				return Err("Incomplete IPv4 address in SOCKS5 UDP header".into());
			}
			let ip = std::net::Ipv4Addr::new(data[offset], data[offset + 1], data[offset + 2], data[offset + 3]);
			let port = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
			offset += 6;
			SocksTargetAddr::Ip(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
		}
		0x03 => {
			if data.len() < offset + 1 {
				return Err("Incomplete domain length in SOCKS5 UDP header".into());
			}
			let domain_len = data[offset] as usize;
			offset += 1;

			if data.len() < offset + domain_len + 2 {
				return Err("Incomplete domain name in SOCKS5 UDP header".into());
			}

			let domain = String::from_utf8_lossy(&data[offset..offset + domain_len]).to_string();
			offset += domain_len;
			let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
			offset += 2;
			SocksTargetAddr::Domain(domain, port)
		}
		0x04 => {
			if data.len() < offset + 18 {
				return Err("Incomplete IPv6 address in SOCKS5 UDP header".into());
			}
			let mut ip_bytes = [0u8; 16];
			ip_bytes.copy_from_slice(&data[offset..offset + 16]);
			let ip = std::net::Ipv6Addr::from(ip_bytes);
			let port = u16::from_be_bytes([data[offset + 16], data[offset + 17]]);
			offset += 18;
			SocksTargetAddr::Ip(SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0)))
		}
		_ => {
			return Err(format!("Unsupported address type: {}", atyp));
		}
	};

	let payload = &data[offset..];
	Ok((frag, target_addr, payload))
}

pub async fn serve_udp(socket: std::net::UdpSocket, stream: UdpStream) -> std::io::Result<()> {
	serve_udp_with_client(socket, stream, None).await
}

/// Serve the SOCKS5 UDP relay socket.
///
/// `expected_client_ip`, when supplied, is the client IP learned from the
/// associated TCP control connection (per RFC 1928 §6 the server SHOULD only
/// accept UDP from this address). When `None`, the first packet's source IP
/// is latched in instead; either way, subsequent packets from a different IP
/// are dropped and logged.
pub async fn serve_udp_with_client(
	socket: std::net::UdpSocket,
	stream: UdpStream,
	expected_client_ip: Option<std::net::IpAddr>,
) -> std::io::Result<()> {
	let socket = Arc::new(UdpSocket::from_std(socket)?);
	let UdpStream { tx, mut rx } = stream;

	// Expected client (IP+port). Sentinel port==0 means "not yet observed".
	let source_addr = Arc::new(ArcSwap::new(Arc::new(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))));
	let expected_ip = Arc::new(ArcSwap::new(Arc::new(expected_client_ip)));

	let socket_rx = socket.clone();
	let source_addr_rx = source_addr.clone();
	let expected_ip_rx = expected_ip.clone();

	let mut rx_buf = vec![0u8; 65536];

	let rx_task = async move {
		loop {
			match socket_rx.recv_from(&mut rx_buf).await {
				Ok((len, addr)) => {
					// Enforce RFC 1928 §6: drop datagrams whose source does not
					// match the expected client. The expected client is either
					// supplied by the caller (from the TCP control connection) or
					// latched in on the first observed packet.
					//
					// The relay socket may be bound as IPv6 dual-stack (the
					// default in `ext::udp_bind_random_port`), in which case an
					// IPv4 client's source IP arrives as `::ffff:V4`. Normalise
					// both sides to IPv4 before comparing so the check does not
					// fail spuriously on V4-mapped V6 addresses.
					let current = **source_addr_rx.load();
					let observed_ip = unmap_v4_mapped(addr.ip());
					match **expected_ip_rx.load() {
						Some(ip) => {
							let expected = unmap_v4_mapped(ip);
							if observed_ip != expected {
								warn!(
									target: "udp",
									"Dropping UDP datagram from unexpected source {} (expected client IP {})",
									addr, ip
								);
								continue;
							}
						}
						None => {
							if current.port() == 0 {
								// First packet — latch in this client.
								expected_ip_rx.store(Arc::new(Some(observed_ip)));
							} else if observed_ip != unmap_v4_mapped(current.ip()) {
								warn!(
									target: "udp",
									"Dropping UDP datagram from unexpected source {} (latched client IP {})",
									addr, current.ip()
								);
								continue;
							}
						}
					}
					let packet_data = &rx_buf[..len];

					// Only commit the observed peer to `source_addr` AFTER the
					// frame parses cleanly. Storing first meant a malformed
					// datagram from an authorized client (or an attacker that
					// somehow got past the IP check) could displace the
					// previously-latched address, leaving the reply path
					// pointing at a stale or hostile peer.
					//
					// TODO RFC 1928 §7: honour the FRAG byte. The current
					// implementation drops fragmentation entirely.
					match parse_udp_request_sync(packet_data) {
						Ok((_frag, target_addr, payload)) => {
							source_addr_rx.store(Arc::new(addr));
							let packet = UdpPacket {
								source: None,
								target: convert_target_addr(&target_addr),
								payload: Bytes::copy_from_slice(payload),
							};
							if tx.send(packet).await.is_err() {
								break;
							}
						}
						Err(e) => {
							warn!(target: "udp", "Failed to parse SOCKS5 UDP header from {addr}: {e}");
						}
					}
				}
				Err(e) => {
					warn!(target: "udp", "Error receiving from socket: {}", e);
					break;
				}
			}
		}
	};

	let tx_task = async move {
		while let Some(packet) = rx.recv().await {
			let current_client = **source_addr.load();
			if current_client.port() == 0 {
				continue; // No client yet
			}

			// RFC 1928 §7: the reply's ATYP/DST.ADDR/DST.PORT MUST identify the
			// REMOTE host that sent the data, not the client. Prefer the packet's
			// recorded source; fall back to its target if the source is unknown.
			let reply_origin = match &packet.source {
				Some(src) => target_addr_to_socket(src),
				None => target_addr_to_socket(&packet.target),
			};

			if let Ok(mut packet_with_header) = new_udp_header(reply_origin) {
				packet_with_header.extend_from_slice(&packet.payload);
				if let Err(e) = socket.send_to(&packet_with_header, current_client).await {
					warn!(target: "udp", "Error sending to client: {}", e);
				}
			}
		}
	};

	tokio::select! {
		_ = rx_task => {}
		_ = tx_task => {}
	}

	Ok(())
}

/// Best-effort conversion from `TargetAddr` to `SocketAddr` for use as the
/// reply origin in the SOCKS5 UDP response header. Domain targets are reported
/// as `0.0.0.0:port` because RFC 1928 has no codepoint for "host", but most
/// clients ignore the origin host field anyway.
fn target_addr_to_socket(t: &TargetAddr) -> SocketAddr {
	match t {
		TargetAddr::IPv4(ip, port) => SocketAddr::new((*ip).into(), *port),
		TargetAddr::IPv6(ip, port) => SocketAddr::new((*ip).into(), *port),
		TargetAddr::Domain(_, port) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), *port),
	}
}

/// Unwrap an IPv4-mapped IPv6 address (`::ffff:V4`) back to IPv4 so that
/// dual-stack relay sockets compare addresses on equal footing with caller-
/// supplied IPv4 expectations.
fn unmap_v4_mapped(ip: std::net::IpAddr) -> std::net::IpAddr {
	match ip {
		std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
			Some(v4) => std::net::IpAddr::V4(v4),
			None => std::net::IpAddr::V6(v6),
		},
		v4 => v4,
	}
}

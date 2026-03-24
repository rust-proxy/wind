use std::{
	net::{Ipv4Addr, SocketAddr},
	sync::Arc,
};

use arc_swap::ArcSwap;
use fast_socks5::{new_udp_header, util::target_addr::TargetAddr as SocksTargetAddr};
use tokio::net::UdpSocket;
use tokio_util::bytes::Bytes;
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

	// Parse target address based on address type
	let target_addr = match atyp {
		0x01 => {
			// IPv4
			if data.len() < offset + 6 {
				return Err("Incomplete IPv4 address in SOCKS5 UDP header".into());
			}
			let ip = std::net::Ipv4Addr::new(data[offset], data[offset + 1], data[offset + 2], data[offset + 3]);
			let port = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
			offset += 6;
			SocksTargetAddr::Ip(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
		}
		0x03 => {
			// Domain name
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
			// IPv6
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
			return Err(format!("Unsupported address type: {}", atyp).into());
		}
	};

	let payload = &data[offset..];
	Ok((frag, target_addr, payload))
}

pub async fn serve_udp(socket: std::net::UdpSocket, stream: UdpStream) -> std::io::Result<()> {
	let socket = Arc::new(UdpSocket::from_std(socket)?);
	let UdpStream { tx, mut rx } = stream;

	let source_addr = Arc::new(ArcSwap::new(Arc::new(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))));

	let socket_rx = socket.clone();
	let source_addr_rx = source_addr.clone();

	let mut rx_buf = vec![0u8; 65536];

	let rx_task = async move {
		loop {
			match socket_rx.recv_from(&mut rx_buf).await {
				Ok((len, addr)) => {
					source_addr_rx.store(Arc::new(addr));
					let packet_data = &rx_buf[..len];

					match parse_udp_request_sync(packet_data) {
						Ok((_frag, target_addr, payload)) => {
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
							wind_core::warn!(target: "[UDP]", "Failed to parse SOCKS5 UDP header: {}", e);
						}
					}
				}
				Err(e) => {
					wind_core::warn!(target: "[UDP]", "Error receiving from socket: {}", e);
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

			if let Ok(mut packet_with_header) = new_udp_header(current_client) {
				packet_with_header.extend_from_slice(&packet.payload);
				if let Err(e) = socket.send_to(&packet_with_header, current_client).await {
					wind_core::warn!(target: "[UDP]", "Error sending to client: {}", e);
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

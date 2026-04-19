mod error;
pub use error::*;

mod header;
pub use header::*;

mod cmd;
pub use cmd::*;

mod addr;
pub use addr::*;

mod udp_stream;
use std::future::Future;

use bytes::{Buf, BytesMut};
use eyre::eyre;
use tokio_util::codec::Encoder;
pub use udp_stream::*;
use wind_core::{io::quinn::QuinnCompat, tcp::AbstractTcpStream, types::TargetAddr};

// Replace Error from crate::Error with our own local eyre::Error wrapper or
// alias
pub type Error = eyre::Report;

pub const VER: u8 = 5;

/// Helper function to decode header with better error reporting
pub fn decode_header(buf: &mut impl Buf, context: &str) -> Result<Header, Error> {
	if buf.remaining() < 2 {
		return Err(eyre!("Incomplete header in {}", context));
	}
	let ver = buf.get_u8();
	if ver != VER {
		return Err(eyre!("Version mismatch: expected {}, got {}", VER, ver));
	}
	let cmd = CmdType::from(buf.get_u8());
	if matches!(cmd, CmdType::Other(_)) {
		return Err(eyre!("Unknown command type: {}", u8::from(cmd)));
	}
	Ok(Header::new(cmd))
}

/// Helper function to decode command with better error reporting
pub fn decode_command(cmd_type: CmdType, buf: &mut impl Buf, context: &str) -> Result<Command, Error> {
	match cmd_type {
		CmdType::Auth => {
			if buf.remaining() < 16 + 32 {
				return Err(eyre!("Incomplete auth command in {}", context));
			}
			let mut uuid = [0; 16];
			buf.copy_to_slice(&mut uuid);
			let mut token = [0; 32];
			buf.copy_to_slice(&mut token);
			Ok(Command::Auth {
				uuid: uuid::Uuid::from_bytes(uuid),
				token,
			})
		}
		CmdType::Connect => Ok(Command::Connect),
		CmdType::Packet => {
			if buf.remaining() < 8 {
				return Err(eyre!("Incomplete packet command in {}", context));
			}
			Ok(Command::Packet {
				assoc_id: buf.get_u16(),
				pkt_id: buf.get_u16(),
				frag_total: buf.get_u8(),
				frag_id: buf.get_u8(),
				size: buf.get_u16(),
			})
		}
		CmdType::Dissociate => {
			if buf.remaining() < 2 {
				return Err(eyre!("Incomplete dissociate command in {}", context));
			}
			Ok(Command::Dissociate { assoc_id: buf.get_u16() })
		}
		CmdType::Heartbeat => Ok(Command::Heartbeat),
		CmdType::Other(v) => Err(eyre!("Unknown command type: {}", v)),
	}
}

/// Helper function to decode address with better error reporting
pub fn decode_address(buf: &mut impl Buf, context: &str) -> Result<Address, Error> {
	if !buf.has_remaining() {
		return Err(eyre!("Incomplete address in {}", context));
	}
	let addr_type = AddressType::from(buf.chunk()[0]);

	match addr_type {
		AddressType::None => {
			buf.advance(1);
			Ok(Address::None)
		}
		AddressType::IPv4 => {
			if buf.remaining() < 1 + 4 + 2 {
				return Err(eyre!("Incomplete IPv4 address in {}", context));
			}
			buf.advance(1);
			let mut octets = [0; 4];
			buf.copy_to_slice(&mut octets);
			let ip = std::net::Ipv4Addr::from(octets);
			let port = buf.get_u16();
			Ok(Address::IPv4(ip, port))
		}
		AddressType::IPv6 => {
			if buf.remaining() < 1 + 16 + 2 {
				return Err(eyre!("Incomplete IPv6 address in {}", context));
			}
			buf.advance(1);
			let mut octets = [0; 16];
			buf.copy_to_slice(&mut octets);
			let ip = std::net::Ipv6Addr::from(octets);
			let port = buf.get_u16();
			Ok(Address::IPv6(ip, port))
		}
		AddressType::Domain => {
			if buf.remaining() < 2 {
				return Err(eyre!("Incomplete Domain address in {}", context));
			}
			let len = buf.chunk()[1] as usize;
			if buf.remaining() < 1 + 1 + len + 2 {
				return Err(eyre!("Incomplete Domain address in {}", context));
			}
			buf.advance(2);
			let mut domain = vec![0; len];
			buf.copy_to_slice(&mut domain);
			let s = String::from_utf8(domain).map_err(|_| eyre!("Invalid UTF-8 domain in {}", context))?;
			let port = buf.get_u16();
			Ok(Address::Domain(s, port))
		}
		AddressType::Other(v) => Err(eyre!("Unknown address type: {}", v)),
	}
}

/// Helper function to convert Address to TargetAddr
pub fn address_to_target(addr: Address) -> Result<TargetAddr, Error> {
	match addr {
		Address::Domain(domain, port) => Ok(TargetAddr::Domain(domain, port)),
		Address::IPv4(ip, port) => Ok(TargetAddr::IPv4(ip, port)),
		Address::IPv6(ip, port) => Ok(TargetAddr::IPv6(ip, port)),
		Address::None => Err(eyre!("Address::None cannot be converted to TargetAddr")),
	}
}

#[cfg(feature = "quinn")]
/// Helper function to encode and send data via unidirectional stream
pub async fn encode_and_send_uni(
	conn: &quinn::Connection,
	cmd_type: CmdType,
	command: Command,
	address: Option<Address>,
) -> Result<(), Error> {
	let mut buf = BytesMut::with_capacity(64);
	HeaderCodec.encode(Header::new(cmd_type), &mut buf)?;
	CmdCodec(cmd_type).encode(command, &mut buf)?;
	if let Some(addr) = address {
		AddressCodec.encode(addr, &mut buf)?;
	}
	let mut send = conn.open_uni().await?;
	send.write_chunk(buf.into()).await?;
	Ok(())
}

#[cfg(feature = "quinn")]
pub trait ClientProtoExt {
	fn send_auth(&self, uuid: &uuid::Uuid, secret: &[u8]) -> impl Future<Output = Result<(), Error>> + Send;
	fn send_heartbeat(&self) -> impl Future<Output = Result<(), Error>> + Send;
	fn open_tcp(
		&self,
		addr: &TargetAddr,
		stream: impl AbstractTcpStream,
	) -> impl Future<Output = Result<(usize, usize), Error>> + Send;
	fn send_udp(
		&self,
		assoc_id: u16,
		pkt_id: u16,
		addr: &TargetAddr,
		packet: bytes::Bytes,
		datagram: bool,
	) -> impl Future<Output = Result<(), Error>> + Send;
	fn drop_udp(&self, assoc_id: u16) -> impl Future<Output = Result<(), Error>> + Send;
}

#[cfg(feature = "quinn")]
impl ClientProtoExt for quinn::Connection {
	async fn send_auth(&self, uuid: &uuid::Uuid, secret: &[u8]) -> Result<(), Error> {
		// Generate the authentication token
		let mut token = [0u8; 32];
		self.export_keying_material(&mut token, uuid.as_bytes(), secret)
			.map_err(|_| eyre!("export_keying_material requested output length is too large."))?;

		// Create and encode the auth command
		let auth_cmd = Command::Auth { uuid: *uuid, token };

		// Pre-calculate the exact buffer capacity needed: 2 bytes for header + 16 bytes
		// for UUID + 32 bytes for token
		let mut buf = BytesMut::with_capacity(2 + 16 + 32);

		// Encode the header and command
		HeaderCodec.encode(Header::new(CmdType::Auth), &mut buf)?;
		CmdCodec(CmdType::Auth).encode(auth_cmd, &mut buf)?;

		// Open a unidirectional stream and send the data
		let mut send = self.open_uni().await?;
		send.write_chunk(buf.into()).await?;

		Ok(())
	}

	async fn open_tcp(&self, addr: &TargetAddr, mut stream: impl AbstractTcpStream) -> Result<(usize, usize), Error> {
		let (mut send, recv) = self.open_bi().await?;
		let mut buf = BytesMut::with_capacity(9);
		HeaderCodec.encode(Header::new(CmdType::Connect), &mut buf)?;
		CmdCodec(CmdType::Connect).encode(Command::Connect, &mut buf)?;
		AddressCodec.encode(addr.to_owned().into(), &mut buf)?;
		send.write_chunk(buf.into()).await?;
		let (a, b, err) = wind_core::io::copy_io(&mut stream, &mut QuinnCompat::new(send, recv)).await;
		// Guard clause: return early if there's an error
		if let Some(e) = err {
			return Err(e.into());
		}
		Ok((a, b))
	}

	async fn send_udp(
		&self,
		assoc_id: u16,
		pkt_id: u16,
		addr: &TargetAddr,
		payload: bytes::Bytes,
		datagram: bool,
	) -> Result<(), Error> {
		let mut buf = BytesMut::with_capacity(12);
		HeaderCodec.encode(Header::new(CmdType::Packet), &mut buf)?;
		CmdCodec(CmdType::Packet).encode(
			Command::Packet {
				assoc_id,
				pkt_id,
				frag_total: 1,
				frag_id: 0,
				size: payload.len() as u16,
			},
			&mut buf,
		)?;
		AddressCodec.encode(addr.to_owned().into(), &mut buf)?;
		if datagram {
			let mut combined = buf.freeze().chain(payload);
			self.send_datagram(combined.copy_to_bytes(combined.remaining()))?;
		} else {
			let mut send = self.open_uni().await?;
			send.write_all_chunks(&mut [buf.into(), payload]).await?;
		}
		Ok(())
	}

	async fn drop_udp(&self, assoc_id: u16) -> Result<(), Error> {
		let mut send = self.open_uni().await?;
		let mut buf = BytesMut::with_capacity(4);
		HeaderCodec.encode(Header::new(CmdType::Dissociate), &mut buf)?;
		CmdCodec(CmdType::Dissociate).encode(Command::Dissociate { assoc_id }, &mut buf)?;
		send.write_chunk(buf.into()).await?;
		Ok(())
	}

	async fn send_heartbeat(&self) -> Result<(), Error> {
		// Pre-allocate the exact size needed for the heartbeat: 2 bytes (version +
		// command)
		let mut buf = BytesMut::with_capacity(2);

		// Encode the heartbeat command header (no additional payload needed)
		HeaderCodec.encode(Header::new(CmdType::Heartbeat), &mut buf)?;

		// Send it as a datagram for lowest latency
		self.send_datagram(buf.freeze())?;

		Ok(())
	}
}

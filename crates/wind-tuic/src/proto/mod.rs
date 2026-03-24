mod error;
pub use error::*;

mod header;

use bytes::{Buf, BytesMut};
use eyre::eyre;
pub use header::*;

mod cmd;
pub use cmd::*;

mod tests;

mod addr;
pub use addr::*;

mod udp_stream;
use tokio_util::codec::{Decoder, Encoder};
pub use udp_stream::*;
use wind_core::{io::quinn::QuinnCompat, tcp::AbstractTcpStream, types::TargetAddr};

use crate::Error;

pub const VER: u8 = 5;

/// Helper function to decode header with better error reporting
pub fn decode_header(buf: &mut BytesMut, context: &str) -> Result<Header, Error> {
	HeaderCodec.decode(buf)?
		.ok_or_else(|| eyre!("Incomplete header in {}", context).into())
}

/// Helper function to decode command with better error reporting
pub fn decode_command(cmd_type: CmdType, buf: &mut BytesMut, context: &str) -> Result<Command, Error> {
	CmdCodec(cmd_type).decode(buf)?
		.ok_or_else(|| eyre!("Incomplete command in {}", context).into())
}

/// Helper function to decode address with better error reporting
pub fn decode_address(buf: &mut BytesMut, context: &str) -> Result<Address, Error> {
	AddressCodec.decode(buf)?
		.ok_or_else(|| eyre!("Incomplete address in {}", context).into())
}

/// Helper function to convert Address to TargetAddr
pub fn address_to_target(addr: Address) -> Result<TargetAddr, Error> {
	match addr {
		Address::Domain(domain, port) => Ok(TargetAddr::Domain(domain, port)),
		Address::IPv4(ip, port) => Ok(TargetAddr::IPv4(ip, port)),
		Address::IPv6(ip, port) => Ok(TargetAddr::IPv6(ip, port)),
		Address::None => Err(eyre!("Address::None cannot be converted to TargetAddr").into()),
	}
}

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

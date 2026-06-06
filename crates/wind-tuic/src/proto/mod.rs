//! TUIC protocol surface for the quinn backend.
//!
//! The backend-agnostic wire codecs, [`ProtoError`], and the pure decode
//! helpers now live in the [`tuic_core::proto`] crate and are re-exported here
//! so existing `wind_tuic::proto::…` paths keep working. This module adds the
//! quinn-specific glue: [`ClientProtoExt`] and [`encode_and_send_uni`], plus
//! the quinn-coupled [`UdpStream`] (see [`udp_stream`]).

pub use tuic_core::proto::*;

mod udp_stream;
#[cfg(feature = "quinn")]
use std::future::Future;

#[cfg(feature = "quinn")]
use bytes::BytesMut;
#[cfg(feature = "quinn")]
use eyre::eyre;
#[cfg(feature = "quinn")]
use tokio_util::codec::Encoder;
pub use udp_stream::*;
#[cfg(feature = "quinn")]
use wind_core::{io::quinn::QuinnCompat, tcp::AbstractTcpStream, types::TargetAddr};

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
	// Finish the stream so the peer's `read_to_end` (or equivalent EOF detector)
	// observes a clean end-of-stream marker. Without this, dropping `send`
	// resets the stream and the receiver sees a RESET_STREAM frame racing the
	// payload, which intermittently breaks auth/dissociate/uni-UDP paths.
	send.finish()?;
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
		// Mark end-of-stream so the server's authenticator sees a clean EOF
		// rather than a reset on drop. See note on `encode_and_send_uni`.
		send.finish()?;

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
		// Pre-size for header (2) + Packet command (8) + address + payload so
		// the datagram branch can ship a single `Bytes` without a second
		// allocation + memcpy. The old code built a `Chain<Bytes, Bytes>` and
		// then `copy_to_bytes`'d it, which exactly negated the point of using
		// Chain (Chain cannot return a zero-copy slice when its two halves
		// live in distinct `Bytes`).
		let addr_size = match addr {
			TargetAddr::IPv4(..) => 1 + 4 + 2,
			TargetAddr::IPv6(..) => 1 + 16 + 2,
			TargetAddr::Domain(d, _) => 1 + 1 + d.len() + 2,
		};
		let header_overhead = 2 + 8 + addr_size;
		let mut buf = BytesMut::with_capacity(header_overhead + if datagram { payload.len() } else { 0 });
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
			buf.extend_from_slice(&payload);
			self.send_datagram(buf.freeze())?;
		} else {
			let mut send = self.open_uni().await?;
			send.write_all_chunks(&mut [buf.into(), payload]).await?;
			// Clean EOF — see note on `encode_and_send_uni`.
			send.finish()?;
		}
		Ok(())
	}

	async fn drop_udp(&self, assoc_id: u16) -> Result<(), Error> {
		let mut send = self.open_uni().await?;
		let mut buf = BytesMut::with_capacity(4);
		HeaderCodec.encode(Header::new(CmdType::Dissociate), &mut buf)?;
		CmdCodec(CmdType::Dissociate).encode(Command::Dissociate { assoc_id }, &mut buf)?;
		send.write_chunk(buf.into()).await?;
		// Clean EOF — see note on `encode_and_send_uni`.
		send.finish()?;
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

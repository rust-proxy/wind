use bytes::{Buf, BufMut as _};
use tokio_util::codec::{Decoder, Encoder};
use uuid::Uuid;

use super::CmdType;
use crate::proto::{BytesRemainingSnafu, UnknownCommandTypeSnafu};

#[derive(Debug, Clone, Copy)]
pub struct CmdCodec(pub CmdType);

#[derive(Debug, Clone, PartialEq)]
pub enum Command {
	Auth {
		uuid:  uuid::Uuid,
		token: [u8; 32],
	},
	Connect,
	Packet {
		assoc_id:   u16,
		pkt_id:     u16,
		frag_total: u8,
		frag_id:    u8,
		size:       u16,
	},
	Dissociate {
		assoc_id: u16,
	},
	Heartbeat,
}

// https://github.com/proxy-rs/wind/blob/main/crates/wind-tuic/SPEC.md#5-command-definitions
#[cfg(feature = "decode")]
impl Decoder for CmdCodec {
	type Error = crate::proto::ProtoError;
	type Item = Command;

	fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
		match self.0 {
			CmdType::Auth => {
				if src.len() < 16 + 32 {
					return Ok(None);
				}
				let mut uuid = [0; 16];
				src.copy_to_slice(&mut uuid);
				let uuid = Uuid::from_bytes(uuid);
				let mut token = [0; 32];
				src.copy_to_slice(&mut token);
				Ok(Some(Command::Auth { uuid, token }))
			}
			CmdType::Connect => Ok(Some(Command::Connect)),
			CmdType::Packet => {
				if src.len() < 8 {
					return Ok(None);
				}

				Ok(Some(Command::Packet {
					assoc_id:   src.get_u16(),
					pkt_id:     src.get_u16(),
					frag_total: src.get_u8(),
					frag_id:    src.get_u8(),
					size:       src.get_u16(),
				}))
			}
			CmdType::Dissociate => {
				if src.len() < 2 {
					return Ok(None);
				}

				Ok(Some(Command::Dissociate { assoc_id: src.get_u16() }))
			}
			CmdType::Heartbeat => Ok(Some(Command::Heartbeat)),
			CmdType::Other(value) => UnknownCommandTypeSnafu { value }.fail(),
		}
	}

	fn decode_eof(&mut self, buf: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
		match self.decode(buf) {
			Ok(None) => BytesRemainingSnafu.fail(),
			v => v,
		}
	}
}

#[cfg(feature = "encode")]
impl Encoder<Command> for CmdCodec {
	type Error = crate::proto::ProtoError;

	fn encode(&mut self, item: Command, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
		match item {
			Command::Auth { uuid, token } => {
				dst.reserve(16 + 32);
				dst.put_slice(uuid.as_bytes());
				dst.put_slice(&token);
			}
			Command::Connect => {}
			Command::Packet {
				assoc_id: assos_id,
				pkt_id,
				frag_total,
				frag_id,
				size,
			} => {
				dst.reserve(8);
				dst.put_u16(assos_id);
				dst.put_u16(pkt_id);
				dst.put_u8(frag_total);
				dst.put_u8(frag_id);
				dst.put_u16(size);
			}
			Command::Dissociate { assoc_id: assos_id } => {
				dst.reserve(2);
				dst.put_u16(assos_id);
			}
			Command::Heartbeat => {}
		}
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use futures_util::SinkExt as _;
	use tokio_stream::StreamExt as _;
	use tokio_util::codec::{FramedRead, FramedWrite};
	use uuid::Uuid;

	use super::Command;
	use crate::proto::{CmdCodec, ProtoError};

	/// Usual test
	#[test_log::test(tokio::test)]
	async fn test_cmd_1() -> eyre::Result<()> {
		let vars = vec![
			Command::Auth {
				uuid:  Uuid::parse_str("02f09a3f-1624-3b1d-8409-44eff7708208")?,
				token: [1; 32],
			},
			Command::Connect,
			Command::Packet {
				assoc_id:   123,
				pkt_id:     123,
				frag_total: 5,
				frag_id:    1,
				size:       8,
			},
			Command::Dissociate { assoc_id: 23 },
			Command::Heartbeat,
		];
		for cmd in vars {
			let buffer = Vec::with_capacity(128);
			let mut writer = FramedWrite::new(buffer, CmdCodec((&cmd).into()));
			let mut expect_len = 0;
			match cmd {
				Command::Auth { .. } => expect_len = expect_len + 16 + 32,
				Command::Connect => expect_len = expect_len + 0,
				Command::Packet { .. } => expect_len = expect_len + 8,
				Command::Dissociate { .. } => expect_len = expect_len + 2,
				Command::Heartbeat => expect_len = expect_len + 0,
			}
			writer.send(cmd.clone()).await?;
			assert_eq!(writer.get_ref().len(), expect_len);
			let buffer = writer.get_ref();
			let mut reader = FramedRead::new(buffer.as_slice(), CmdCodec((&cmd).into()));

			let frame = reader.next().await.unwrap()?;
			assert_eq!(cmd, frame);
		}

		Ok(())
	}
	/// Data not fully arrive
	#[test_log::test(tokio::test)]
	async fn test_cmd_2() -> eyre::Result<()> {
		let vars = vec![
			Command::Auth {
				uuid:  Uuid::parse_str("02f09a3f-1624-3b1d-8409-44eff7708208")?,
				token: [1; 32],
			},
			Command::Packet {
				assoc_id:   123,
				pkt_id:     123,
				frag_total: 5,
				frag_id:    1,
				size:       8,
			},
			Command::Dissociate { assoc_id: 23 },
		];
		for cmd in vars {
			let buffer = Vec::with_capacity(128);
			let mut writer = FramedWrite::new(buffer, CmdCodec((&cmd).into()));
			writer.send(cmd.clone()).await?;
			let mut buffer = writer.into_inner();
			let full_len = buffer.len();
			let mut half_b = buffer.split_off(full_len / 2 as usize);
			let mut half_a = buffer;
			{
				let mut reader = FramedRead::new(half_a.as_slice(), CmdCodec((&cmd).into()));
				assert!(matches!(
					reader.next().await.unwrap().unwrap_err(),
					ProtoError::BytesRemaining
				));
			}
			half_a.append(&mut half_b);
			let mut reader = FramedRead::new(half_a.as_slice(), CmdCodec((&cmd).into()));
			assert_eq!(reader.next().await.unwrap()?, cmd);
		}

		Ok(())
	}
}

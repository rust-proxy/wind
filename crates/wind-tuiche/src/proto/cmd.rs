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
        uuid: uuid::Uuid,
        token: [u8; 32],
    },
    Connect,
    Packet {
        assoc_id: u16,
        pkt_id: u16,
        frag_total: u8,
        frag_id: u8,
        size: u16,
    },
    Dissociate {
        assoc_id: u16,
    },
    Heartbeat,
}

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
                    assoc_id: src.get_u16(),
                    pkt_id: src.get_u16(),
                    frag_total: src.get_u8(),
                    frag_id: src.get_u8(),
                    size: src.get_u16(),
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
    type Error = std::io::Error;

    fn encode(&mut self, item: Command, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        match item {
            Command::Auth { uuid, token } => {
                dst.reserve(16 + 32);
                dst.put_slice(uuid.as_bytes());
                dst.put_slice(&token);
            }
            Command::Connect => {}
            Command::Packet {
                assoc_id,
                pkt_id,
                frag_total,
                frag_id,
                size,
            } => {
                dst.reserve(8);
                dst.put_u16(assoc_id);
                dst.put_u16(pkt_id);
                dst.put_u8(frag_total);
                dst.put_u8(frag_id);
                dst.put_u16(size);
            }
            Command::Dissociate { assoc_id } => {
                dst.reserve(2);
                dst.put_u16(assoc_id);
            }
            Command::Heartbeat => {}
        }
        Ok(())
    }
}
use bytes::{Buf, BufMut};
use num_enum::{FromPrimitive, IntoPrimitive};
use snafu::ensure;
use tokio_util::codec::{Decoder, Encoder};

use super::{Command, VER};
use crate::proto::{BytesRemainingSnafu, UnknownCommandTypeSnafu, VersionDismatchSnafu};

#[derive(Debug, Clone, Copy)]
pub struct HeaderCodec;

#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    pub version: u8,
    pub command: CmdType,
}

#[derive(IntoPrimitive, FromPrimitive, Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum CmdType {
    Auth = 0,
    Connect = 1,
    Packet = 2,
    Dissociate = 3,
    Heartbeat = 4,
    #[num_enum(catch_all)]
    Other(u8),
}

impl Header {
    pub fn new(command: CmdType) -> Self {
        Self { version: VER, command }
    }
}

#[cfg(feature = "decode")]
impl Decoder for HeaderCodec {
    type Error = crate::proto::ProtoError;
    type Item = Header;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 2 {
            return Ok(None);
        }
        let ver = src.get_u8();
        ensure!(
            ver == VER,
            VersionDismatchSnafu {
                expect: VER,
                current: ver
            }
        );

        let cmd = CmdType::from(src.get_u8());

        ensure!(
            !matches!(cmd, CmdType::Other(..)),
            UnknownCommandTypeSnafu { value: u8::from(cmd) }
        );

        Ok(Some(Header::new(cmd)))
    }

    fn decode_eof(&mut self, buf: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decode(buf) {
            Ok(None) => BytesRemainingSnafu.fail(),
            v => v,
        }
    }
}

#[cfg(feature = "encode")]
impl Encoder<Header> for HeaderCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Header, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        dst.reserve(2);
        dst.put_u8(item.version);
        dst.put_u8(item.command.into());
        Ok(())
    }
}

impl From<&Command> for CmdType {
    fn from(value: &Command) -> Self {
        match value {
            Command::Auth { .. } => CmdType::Auth,
            Command::Connect => CmdType::Connect,
            Command::Packet { .. } => CmdType::Packet,
            Command::Dissociate { .. } => CmdType::Dissociate,
            Command::Heartbeat => CmdType::Heartbeat,
        }
    }
}
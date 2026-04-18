use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str,
};

use bytes::{Buf, BufMut};
use num_enum::{FromPrimitive, IntoPrimitive};
use snafu::{ResultExt, ensure};
use tokio_util::codec::{Decoder, Encoder};
use wind_core::types::TargetAddr;

#[cfg(feature = "decode")]
use crate::proto::ProtoError;
use crate::proto::{BytesRemainingSnafu, DomainTooLongSnafu, FailParseDomainSnafu, UnknownAddressTypeSnafu};

/// Codec for TUIC address encoding and decoding
#[derive(Debug, Clone, Copy)]
pub struct AddressCodec;

/// TUIC Address representation
#[derive(Debug, Clone, PartialEq)]
pub enum Address {
    /// No address
    None,
    /// Domain name and port
    Domain(String, u16),
    /// IPv4 address and port
    IPv4(Ipv4Addr, u16),
    /// IPv6 address and port
    IPv6(Ipv6Addr, u16),
}

/// Address type indicators as defined in TUIC protocol
#[derive(IntoPrimitive, FromPrimitive, Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum AddressType {
    None = u8::MAX,
    Domain = 0,
    IPv4 = 1,
    IPv6 = 2,
    #[num_enum(catch_all)]
    Other(u8),
}

impl From<TargetAddr> for Address {
    fn from(value: TargetAddr) -> Self {
        match value {
            TargetAddr::Domain(s, port) => Self::Domain(s, port),
            TargetAddr::IPv4(addr, port) => Self::IPv4(addr, port),
            TargetAddr::IPv6(addr, port) => Self::IPv6(addr, port),
        }
    }
}

#[cfg(feature = "decode")]
impl Decoder for AddressCodec {
    type Error = ProtoError;
    type Item = Address;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        let addr_type = AddressType::from(src[0]);

        ensure!(
            !matches!(addr_type, AddressType::Other(_)),
            UnknownAddressTypeSnafu {
                value: u8::from(addr_type)
            }
        );

        match addr_type {
            AddressType::None => {
                src.advance(1);
                Ok(Some(Address::None))
            }
            AddressType::IPv4 => {
                if src.len() < 1 + 4 + 2 {
                    return Ok(None);
                }
                src.advance(1);

                let addr = Ipv4Addr::new(src.get_u8(), src.get_u8(), src.get_u8(), src.get_u8());
                let port = src.get_u16();
                Ok(Some(Address::IPv4(addr, port)))
            }
            AddressType::IPv6 => {
                if src.len() < 1 + 16 + 2 {
                    return Ok(None);
                }
                src.advance(1);

                let mut octets = [0u8; 16];
                src.copy_to_slice(&mut octets);
                let addr = Ipv6Addr::from(octets);
                let port = src.get_u16();
                Ok(Some(Address::IPv6(addr, port)))
            }
            AddressType::Domain => {
                if src.len() < 1 + 1 + 2 {
                    return Ok(None);
                }
                src.advance(1);

                let domain_len = src.get_u8() as usize;
                ensure!(domain_len <= 255, DomainTooLongSnafu { length: domain_len });

                if src.len() < domain_len + 2 {
                    return Ok(None);
                }

                let domain = str::from_utf8(&src[..domain_len])
                    .map_err(|e| ProtoError::FailParseDomain { source: e })?
                    .to_string();
                src.advance(domain_len);

                let port = src.get_u16();
                Ok(Some(Address::Domain(domain, port)))
            }
            _ => UnknownAddressTypeSnafu { value: 0 }.fail(),
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
impl Encoder<Address> for AddressCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Address, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        match item {
            Address::None => {
                dst.reserve(1);
                dst.put_u8(AddressType::None.into());
            }
            Address::IPv4(addr, port) => {
                dst.reserve(1 + 4 + 2);
                dst.put_u8(AddressType::IPv4.into());
                dst.put_slice(&addr.octets());
                dst.put_u16(port);
            }
            Address::IPv6(addr, port) => {
                dst.reserve(1 + 16 + 2);
                dst.put_u8(AddressType::IPv6.into());
                dst.put_slice(&addr.octets());
                dst.put_u16(port);
            }
            Address::Domain(domain, port) => {
                if domain.len() > 255 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Domain too long",
                    ));
                }
                dst.reserve(1 + 1 + domain.len() + 2);
                dst.put_u8(AddressType::Domain.into());
                dst.put_u8(domain.len() as u8);
                dst.put_slice(domain.as_bytes());
                dst.put_u16(port);
            }
        }
        Ok(())
    }
}
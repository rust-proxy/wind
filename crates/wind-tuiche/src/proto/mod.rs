mod error;
pub use error::*;

mod header;

use bytes::{Buf, BytesMut};
use eyre::eyre;
pub use header::*;

mod cmd;
pub use cmd::*;

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
    HeaderCodec
        .decode(buf)?
        .ok_or_else(|| eyre!("Incomplete header in {}", context))
}

/// Helper function to decode command with better error reporting
pub fn decode_command(cmd_type: CmdType, buf: &mut BytesMut, context: &str) -> Result<Command, Error> {
    CmdCodec(cmd_type)
        .decode(buf)?
        .ok_or_else(|| eyre!("Incomplete command in {}", context))
}

/// Helper function to decode address with better error reporting
pub fn decode_address(buf: &mut BytesMut, context: &str) -> Result<Address, Error> {
    AddressCodec
        .decode(buf)?
        .ok_or_else(|| eyre!("Incomplete address in {}", context))
}

/// Convert Address to TargetAddr
pub fn address_to_target(addr: Address) -> Result<TargetAddr, Error> {
    match addr {
        Address::None => Err(eyre!("Address is None")),
        Address::Domain(domain, port) => Ok(TargetAddr::Domain(domain, port)),
        Address::IPv4(ip, port) => Ok(TargetAddr::IPv4(ip, port)),
        Address::IPv6(ip, port) => Ok(TargetAddr::IPv6(ip, port)),
    }
}
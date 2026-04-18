use std::{io, str::Utf8Error};

use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ProtoError {
    #[snafu(display("Version dismatch, expect {expect}, got {current}"))]
    VersionDismatch {
        expect: u8,
        current: u8,
    },
    #[snafu(display("Unknown command type {value}"))]
    UnknownCommandType {
        value: u8,
    },
    #[snafu(display("Unable to decode address due to type {value}"))]
    UnknownAddressType {
        value: u8,
    },
    #[snafu(display("Unable to decode domain name"))]
    FailParseDomain {
        source: Utf8Error,
    },
    #[snafu(display("Domain too long: {length}"))]
    DomainTooLong {
        length: usize,
    },
    #[snafu(display("Insufficient bytes to decode"))]
    BytesRemaining,
    #[snafu(display("Invalid packet size"))]
    InvalidPacketSize,
    #[snafu(display("Invalid fragment configuration"))]
    InvalidFragment,
    #[snafu(display("IO error: {source}"))]
    Io {
        source: io::Error,
    },
}

impl From<io::Error> for ProtoError {
    fn from(source: io::Error) -> Self {
        ProtoError::Io { source }
    }
}
use std::{backtrace::Backtrace, str::Utf8Error};

use quinn::ReadToEndError;
use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ProtoError {
	VersionDismatch {
		expect:    u8,
		current:   u8,
		backtrace: Backtrace,
	},
	#[snafu(display("Unknown command type {value}"))]
	UnknownCommandType {
		value:     u8,
		backtrace: Backtrace,
	},
	#[snafu(display("Unable to decode address due to type {value}"))]
	UnknownAddressType {
		value:     u8,
		backtrace: Backtrace,
	},
	FailParseDomain {
		// HEX
		raw:       String,
		source:    Utf8Error,
		backtrace: Backtrace,
	},
	DomainTooLong {
		domain:    String,
		backtrace: Backtrace,
	},
	// Caller should yield
	BytesRemaining,
	Io {
		// #[snafu(backtrace)]
		source:    std::io::Error,
		backtrace: Backtrace,
	},
	NumericOverflow {
		field:     String,
		num:       String,
		backtrace: Backtrace,
	},
	ReadToEnd {
		source:    ReadToEndError,
		backtrace: Backtrace,
	},
}

impl From<std::io::Error> for ProtoError {
	#[inline(always)]
	fn from(_source: std::io::Error) -> Self {
		#[cfg(debug_assertions)]
		panic!("IO error should not be created by From<io::Error>");
		#[cfg(not(debug_assertions))]
		{
			use snafu::IntoError as _;
			IoSnafu.into_error(_source)
		}
	}
}

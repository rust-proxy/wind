#![feature(error_generic_member_access)]

use std::{backtrace::Backtrace, net::SocketAddr};

use fast_socks5::{ReplyError, server::SocksServerError, util::target_addr::TargetAddr as SocksTargetAddr};
use snafu::{IntoError, Snafu};
use wind_core::types::TargetAddr;

pub mod ext;
pub mod inbound;
pub mod udp;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum Error {
	BindSocket {
		socket_addr: SocketAddr,
		source:      std::io::Error,
		backtrace:   Backtrace,
	},
	Io {
		// action: String
		source:    std::io::Error,
		backtrace: Backtrace,
	},
	Socks {
		#[snafu(provide)]
		source:    SocksServerError,
		backtrace: Backtrace,
	},
	SocksReply {
		#[snafu(provide)]
		source:    ReplyError,
		backtrace: Backtrace,
	},
	Callback {
		#[snafu(provide)]
		source:    eyre::Report,
		backtrace: Backtrace,
	},
}

impl From<SocksServerError> for Error {
	#[inline(always)]
	fn from(value: SocksServerError) -> Self {
		SocksSnafu.into_error(value)
	}
}

impl From<ReplyError> for Error {
	#[inline(always)]
	fn from(value: ReplyError) -> Self {
		SocksReplySnafu.into_error(value)
	}
}

pub fn convert_addr(addr: &SocksTargetAddr) -> TargetAddr {
	match addr {
		SocksTargetAddr::Domain(domain, port) => TargetAddr::Domain(domain.clone(), *port),
		SocksTargetAddr::Ip(socket_addr) => match socket_addr.ip() {
			std::net::IpAddr::V4(ipv4) => TargetAddr::IPv4(ipv4, socket_addr.port()),
			std::net::IpAddr::V6(ipv6) => TargetAddr::IPv6(ipv6, socket_addr.port()),
		},
	}
}

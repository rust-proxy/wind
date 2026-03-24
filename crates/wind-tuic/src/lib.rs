#![feature(error_generic_member_access)]

pub mod proto;
mod task;
pub mod tls;

#[cfg(feature = "server")]
pub mod inbound;

#[cfg(feature = "client")]
pub mod outbound;

pub type Error = eyre::Report;
pub type Result<T> = eyre::Result<T>;

//! TUIC (TCP/UDP over QUIC) implementation built on the [`tokio-quiche`]
//! backend.
//!
//! This crate mirrors the public surface of the quinn-backed `wind-tuic`
//! crate, but drives the underlying QUIC stack with Cloudflare's
//! [`tokio-quiche`] library instead of quinn.
//!
//! [`tokio-quiche`]: https://docs.rs/tokio-quiche

pub mod task;
pub mod utils;

#[cfg(feature = "server")]
mod driver;
#[cfg(feature = "server")]
mod stream;

/// Backend-agnostic TUIC wire codecs and decode helpers, shared with
/// `wind-tuic` via the [`tuic_core`] crate.
pub use tuic_core::proto;
/// Backend-agnostic UDP fragment reassembly state machine.
pub use tuic_core::udp;
pub use utils::{CongestionControl, ConnectionOpts, ConnectionStats, UdpRelayMode};

#[cfg(feature = "server")]
pub mod inbound;

#[cfg(feature = "client")]
pub mod outbound;

#[cfg(feature = "server")]
pub use inbound::{TuicheInbound, TuicheInboundBuilder};
#[cfg(feature = "client")]
pub use outbound::{TuicheOutbound, TuicheOutboundBuilder};

pub type Error = eyre::Report;
pub type Result<T> = eyre::Result<T>;

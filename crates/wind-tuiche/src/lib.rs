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

// The tokio-quiche-backed parts are **64-bit only** (see Cargo.toml:
// tokio-quiche doesn't compile on 32-bit). On 32-bit targets this crate is just
// the backend-agnostic re-exports below, so the workspace still builds
// everywhere.
#[cfg(all(feature = "server", target_pointer_width = "64"))]
mod driver;
#[cfg(all(feature = "server", target_pointer_width = "64"))]
mod stream;
#[cfg(all(feature = "server", target_pointer_width = "64"))]
pub mod tls;

/// Backend-agnostic TUIC wire codecs and decode helpers, shared with
/// `wind-tuic` via the [`tuic_core`] crate.
pub use tuic_core::proto;
/// Backend-agnostic UDP fragment reassembly state machine.
pub use tuic_core::udp;
pub use utils::{CongestionControl, ConnectionOpts, ConnectionStats, UdpRelayMode};

#[cfg(all(feature = "server", target_pointer_width = "64"))]
pub mod inbound;

#[cfg(all(feature = "client", target_pointer_width = "64"))]
pub mod outbound;

#[cfg(all(feature = "server", target_pointer_width = "64"))]
pub use inbound::{TuicheInbound, TuicheInboundBuilder};
#[cfg(all(feature = "client", target_pointer_width = "64"))]
pub use outbound::{TuicheOutbound, TuicheOutboundBuilder};
#[cfg(all(feature = "server", target_pointer_width = "64"))]
pub use tls::CertStore;

pub type Error = eyre::Report;
pub type Result<T> = eyre::Result<T>;

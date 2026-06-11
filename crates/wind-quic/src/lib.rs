//! Backend-agnostic QUIC abstraction unifying [quinn] and [quiche] (via
//! [tokio-quiche]) behind a single handle-based async trait family.
//!
//! `wind-tuic` (quinn) and `wind-tuiche` (tokio-quiche) each carry their own
//! copy of the QUIC plumbing because the two engines have fundamentally
//! different I/O models:
//!
//! * **quinn** is *handle-based / async*: a [`quinn::Connection`] is `Clone +
//!   Send` with async `open_bi`/`accept_bi`/… and streams that implement
//!   [`AsyncRead`](tokio::io::AsyncRead) /
//!   [`AsyncWrite`](tokio::io::AsyncWrite).
//! * **tokio-quiche** is *callback-driven sans-IO*: you implement
//!   `ApplicationOverQuic` over `&mut quiche::Connection`, using synchronous
//!   `stream_recv`/`stream_send`/`dgram_*`. There is no owned connection
//!   handle.
//!
//! This crate resolves the gap the same way [`tonic-h3`](https://github.com/youyuanwu/tonic-h3)
//! unifies quinn / s2n-quic / msquic behind the `h3::quic` trait family:
//! it defines a **handle-based async** trait surface ([`QuicConnection`],
//! [`QuicSendStream`], [`QuicRecvStream`]). The handle-based engine (quinn)
//! implements it with thin newtype wrappers; the sans-IO engine (quiche)
//! implements it by running its event loop in an internal driver task and
//! bridging through channels.
//!
//! Backends are feature-gated:
//!
//! * `quinn`  — enables the [`quinn`](crate::quinn) module.
//! * `quiche` — enables the [`quiche`](crate::quiche) module.
//!
//! [quinn]: https://docs.rs/quinn
//! [quiche]: https://docs.rs/quiche
//! [tokio-quiche]: https://docs.rs/tokio-quiche

pub mod config;
pub mod error;
pub mod traits;

pub use config::{CertSource, ClientTlsConfig, ServerTlsConfig, TransportConfig};
pub use error::{QuicError, Result};
pub use traits::{QuicConnection, QuicRecvStream, QuicSendStream};
// Re-export the shared congestion-control selector so consumers configure the
// transport without depending on `wind-core` directly.
pub use wind_core::quic::QuicCongestionControl;

#[cfg(feature = "quinn")]
pub mod quinn;

#[cfg(feature = "quiche")]
pub mod quiche;

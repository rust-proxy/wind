//! Backend-agnostic TUIC protocol primitives shared by the quinn-based
//! [`wind-tuic`] crate and the tokio-quiche-based [`wind-tuiche`] crate.
//!
//! This crate deliberately has **no QUIC backend dependency**. It contains:
//!
//! * [`proto`] — the on-wire codecs (header / command / address), the
//!   [`ProtoError`](proto::ProtoError) type, and the pure decode helpers used
//!   on the production hot path.
//! * [`udp`] — the UDP fragment reassembly state machine
//!   ([`FragmentReassemblyBuffer`](udp::FragmentReassemblyBuffer)).
//!
//! The backend-specific glue (opening QUIC streams, sending datagrams, the
//! connection lifecycle) lives in the `wind-tuic` / `wind-tuiche` crates.

pub mod proto;
pub mod udp;

pub type Error = eyre::Report;
pub type Result<T> = eyre::Result<T>;

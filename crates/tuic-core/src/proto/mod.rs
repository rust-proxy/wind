mod error;
pub use error::*;

mod header;
pub use header::*;

mod cmd;
pub use cmd::*;

mod addr;
pub use addr::*;
use bytes::Buf;
use eyre::eyre;
use wind_core::types::TargetAddr;

/// Local error alias for the free wire-helper decoders below.
///
/// The codecs return `Result<Option<Item>, ProtoError>` (the
/// `tokio_util::codec::Decoder` contract — `Ok(None)` means "need more bytes").
/// The free helpers return `Result<Item, eyre::Report>` instead: incomplete
/// input is an error rather than a request for more bytes.
pub type Error = eyre::Report;

pub const VER: u8 = 5;

// ---------------------------------------------------------------------------
// Wire decoders used by the production hot path.
//
// NOTE: these helpers intentionally duplicate the parsing logic of the
// `HeaderCodec` / `CmdCodec` / `AddressCodec` impls in `header.rs` / `cmd.rs` /
// `addr.rs`. The codecs return `Result<Option<Item>>` (the
// `tokio_util::codec::Decoder` contract — `Ok(None)` means "need more bytes")
// and are used by `FramedRead`/`FramedWrite` for tests and the encoder side of
// the wire. The free helpers below return `Result<Item, eyre::Report>` —
// incomplete input is an error rather than a request for more bytes — which
// fits the way the inbound/outbound paths consume single datagrams or stream
// prefixes that are already known to be complete.
//
// Any change to the on-wire format MUST be mirrored across both
// implementations. There is no shared core because their error contracts are
// fundamentally different. A future refactor could introduce a small
// `WireRead` trait shared by both, but that is intentionally out of scope.
// ---------------------------------------------------------------------------

/// Helper function to decode header with better error reporting
pub fn decode_header(buf: &mut impl Buf, context: &str) -> Result<Header, Error> {
	if buf.remaining() < 2 {
		return Err(eyre!("Incomplete header in {}", context));
	}
	let ver = buf.get_u8();
	if ver != VER {
		return Err(eyre!("Version mismatch: expected {}, got {}", VER, ver));
	}
	let cmd = CmdType::from(buf.get_u8());
	if matches!(cmd, CmdType::Other(_)) {
		return Err(eyre!("Unknown command type: {}", u8::from(cmd)));
	}
	Ok(Header::new(cmd))
}

/// Helper function to decode command with better error reporting
pub fn decode_command(cmd_type: CmdType, buf: &mut impl Buf, context: &str) -> Result<Command, Error> {
	match cmd_type {
		CmdType::Auth => {
			if buf.remaining() < 16 + 32 {
				return Err(eyre!("Incomplete auth command in {}", context));
			}
			let mut uuid = [0; 16];
			buf.copy_to_slice(&mut uuid);
			let mut token = [0; 32];
			buf.copy_to_slice(&mut token);
			Ok(Command::Auth {
				uuid: uuid::Uuid::from_bytes(uuid),
				token,
			})
		}
		CmdType::Connect => Ok(Command::Connect),
		CmdType::Packet => {
			if buf.remaining() < 8 {
				return Err(eyre!("Incomplete packet command in {}", context));
			}
			Ok(Command::Packet {
				assoc_id: buf.get_u16(),
				pkt_id: buf.get_u16(),
				frag_total: buf.get_u8(),
				frag_id: buf.get_u8(),
				size: buf.get_u16(),
			})
		}
		CmdType::Dissociate => {
			if buf.remaining() < 2 {
				return Err(eyre!("Incomplete dissociate command in {}", context));
			}
			Ok(Command::Dissociate { assoc_id: buf.get_u16() })
		}
		CmdType::Heartbeat => Ok(Command::Heartbeat),
		CmdType::Other(v) => Err(eyre!("Unknown command type: {}", v)),
	}
}

/// Helper function to decode address with better error reporting.
///
/// Operates on any `Buf`. The previous implementation peeked into `buf.chunk()`
/// for the type tag and the domain length, which is only correct for
/// contiguous `Buf`s — a chained/multi-chunk buffer can return as little as one
/// byte from `chunk()` even when `remaining()` is much larger, so the
/// `buf.chunk()[1]` access could panic. The version below reads with `get_u8`
/// after explicit `remaining()` checks, which is contract-correct for every
/// `Buf` impl. Callers in this crate always pass contiguous `Bytes`, so this
/// is hardening rather than a live fix; still, it keeps the API honest.
pub fn decode_address(buf: &mut impl Buf, context: &str) -> Result<Address, Error> {
	if !buf.has_remaining() {
		return Err(eyre!("Incomplete address in {}", context));
	}
	let addr_type = AddressType::from(buf.get_u8());

	match addr_type {
		AddressType::None => Ok(Address::None),
		AddressType::IPv4 => {
			// Already consumed the type byte; need IPv4 (4) + Port (2) = 6 more.
			if buf.remaining() < 4 + 2 {
				return Err(eyre!("Incomplete IPv4 address in {}", context));
			}
			let mut octets = [0; 4];
			buf.copy_to_slice(&mut octets);
			let ip = std::net::Ipv4Addr::from(octets);
			let port = buf.get_u16();
			Ok(Address::IPv4(ip, port))
		}
		AddressType::IPv6 => {
			if buf.remaining() < 16 + 2 {
				return Err(eyre!("Incomplete IPv6 address in {}", context));
			}
			let mut octets = [0; 16];
			buf.copy_to_slice(&mut octets);
			let ip = std::net::Ipv6Addr::from(octets);
			let port = buf.get_u16();
			Ok(Address::IPv6(ip, port))
		}
		AddressType::Domain => {
			if !buf.has_remaining() {
				return Err(eyre!("Incomplete Domain address in {}", context));
			}
			let len = buf.get_u8() as usize;
			if buf.remaining() < len + 2 {
				return Err(eyre!("Incomplete Domain address in {}", context));
			}
			let mut domain = vec![0; len];
			buf.copy_to_slice(&mut domain);
			let s = String::from_utf8(domain).map_err(|_| eyre!("Invalid UTF-8 domain in {}", context))?;
			let port = buf.get_u16();
			Ok(Address::Domain(s, port))
		}
		AddressType::Other(v) => Err(eyre!("Unknown address type: {}", v)),
	}
}

/// Helper function to convert Address to TargetAddr
pub fn address_to_target(addr: Address) -> Result<TargetAddr, Error> {
	match addr {
		Address::Domain(domain, port) => Ok(TargetAddr::Domain(domain, port)),
		Address::IPv4(ip, port) => Ok(TargetAddr::IPv4(ip, port)),
		Address::IPv6(ip, port) => Ok(TargetAddr::IPv6(ip, port)),
		Address::None => Err(eyre!("Address::None cannot be converted to TargetAddr")),
	}
}

// ---------------------------------------------------------------------------
// Regression tests for the wire-helper decoders.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use bytes::{Buf, Bytes};

	use super::*;

	/// Build a SOCKS-style IPv4 address frame: ATYP(1) + IPv4(4) + Port(2).
	fn ipv4_addr_frame() -> Vec<u8> {
		let mut v = Vec::new();
		v.push(u8::from(AddressType::IPv4));
		v.extend_from_slice(&[127, 0, 0, 1]);
		v.extend_from_slice(&80u16.to_be_bytes());
		v
	}

	fn domain_addr_frame(name: &[u8]) -> Vec<u8> {
		assert!(name.len() <= u8::MAX as usize);
		let mut v = Vec::new();
		v.push(u8::from(AddressType::Domain));
		v.push(name.len() as u8);
		v.extend_from_slice(name);
		v.extend_from_slice(&443u16.to_be_bytes());
		v
	}

	/// `decode_address` is declared over `impl Buf`. A `Chain` of two `Bytes`
	/// is the canonical multi-chunk buffer — its `chunk()` returns only the
	/// first half. The pre-PR2 implementation indexed `buf.chunk()[1]` for the
	/// domain length, which would panic when the split happened between the
	/// type byte and the length byte. The new implementation uses `get_u8`
	/// after explicit `remaining()` checks and must handle the split cleanly.
	#[test]
	fn decode_address_is_buf_safe_when_split_between_chunks() {
		let frame = domain_addr_frame(b"example.com");

		// Walk every possible split point; the decoder must succeed at all of
		// them and produce the same result as the contiguous parse.
		let contiguous = {
			let mut b: &[u8] = &frame;
			decode_address(&mut b, "contiguous").expect("contiguous parse must succeed")
		};

		for split in 1..frame.len() {
			let (a, b) = frame.split_at(split);
			let mut chained = Bytes::copy_from_slice(a).chain(Bytes::copy_from_slice(b));
			let parsed = decode_address(&mut chained, "chained").unwrap_or_else(|e| panic!("split {split} failed: {e:?}"));
			assert_eq!(parsed, contiguous, "split {split} produced a different address");
			assert_eq!(chained.remaining(), 0, "split {split} left {} bytes", chained.remaining());
		}
	}

	/// `decode_address` must also handle the IPv4 case across a split. (The
	/// IPv4 path previously called `buf.chunk()[0]` for the type byte — that's
	/// fine for the first byte under the `Buf` contract — but the underlying
	/// pattern is fragile, so we lock in correct behaviour for all splits.)
	#[test]
	fn decode_address_ipv4_across_split() {
		let frame = ipv4_addr_frame();
		for split in 1..frame.len() {
			let (a, b) = frame.split_at(split);
			let mut chained = Bytes::copy_from_slice(a).chain(Bytes::copy_from_slice(b));
			let parsed = decode_address(&mut chained, "chained").unwrap_or_else(|e| panic!("split {split} failed: {e:?}"));
			match parsed {
				Address::IPv4(ip, port) => {
					assert_eq!(ip, std::net::Ipv4Addr::LOCALHOST);
					assert_eq!(port, 80);
				}
				other => panic!("expected IPv4 at split {split}, got {other:?}"),
			}
		}
	}

	/// Truncated input must NOT panic — it must return an `Err` with the
	/// "Incomplete ..." context string from the caller.
	#[test]
	fn decode_address_truncated_returns_err() {
		// Just the ATYP byte for a domain — length byte and body are missing.
		let mut buf: &[u8] = &[u8::from(AddressType::Domain)];
		let err = decode_address(&mut buf, "ctx").expect_err("must error on truncated input");
		assert!(format!("{err}").contains("Incomplete"));

		// ATYP + length but no payload.
		let mut buf: &[u8] = &[u8::from(AddressType::Domain), 0x05];
		let err = decode_address(&mut buf, "ctx").expect_err("must error on truncated payload");
		assert!(format!("{err}").contains("Incomplete"));

		// IPv4 missing the last port byte.
		let mut v = ipv4_addr_frame();
		v.pop();
		let mut buf: &[u8] = &v;
		let err = decode_address(&mut buf, "ctx").expect_err("must error on truncated v4");
		assert!(format!("{err}").contains("Incomplete"));
	}
}

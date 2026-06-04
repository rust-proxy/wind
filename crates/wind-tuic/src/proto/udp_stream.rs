use std::{
	sync::{
		Arc, OnceLock,
		atomic::{AtomicU16, AtomicU64, Ordering},
	},
	time::{Duration, Instant},
};

use arc_swap::{ArcSwap, ArcSwapOption};
use bytes::{BufMut, Bytes, BytesMut};
use crossfire::{MAsyncTx, mpmc};
use moka::future::Cache;
use tokio_util::codec::Encoder;
use wind_core::{types::TargetAddr, udp::UdpPacket};

type UdpPacketTx = MAsyncTx<mpmc::Array<UdpPacket>>;

use crate::proto::{Address, AddressCodec, ClientProtoExt as _, CmdCodec, CmdType, Command, Header, HeaderCodec};

// Define MTU sizes for UDP segmentation
const MAX_FRAGMENTS: u8 = 255; // Maximum number of fragments allowed
const FRAGMENT_TIMEOUT_MS: u64 = 30000; // 30 seconds timeout for fragment reassembly

static INIT_TIME: OnceLock<Instant> = OnceLock::new();

fn init_time() -> &'static Instant {
	INIT_TIME.get_or_init(Instant::now)
}

/// Fragment information for reassembly
struct FragmentInfo {
	assoc_id: u16,
	pkt_id: u16,
	frag_total: u8,
	frag_id: u8,
	source: Option<TargetAddr>,
	target: TargetAddr,
}

pub struct UdpStream {
	connection: quinn::Connection,
	assoc_id: u16,
	receive_tx: UdpPacketTx,
	next_pkt_id: AtomicU16, // Track packet IDs for fragmentation
	// Fragment reassembly state (wrapped in Mutex for interior mutability)
	fragment_buffer: FragmentReassemblyBuffer,
}

/// Structure to track fragments of a packet for reassembly
struct FragmentMetadata {
	frag_total: u8,
	fragments: Cache<u8, Bytes>,
	last_updated: AtomicU64,
	source: ArcSwapOption<TargetAddr>,
	target: ArcSwap<TargetAddr>,
}

/// Buffer for reassembling fragmented packets
struct FragmentReassemblyBuffer {
	fragments: Cache<(u16, u16), Arc<FragmentMetadata>>, // (assoc_id, pkt_id) -> fragment metadata
}

impl FragmentReassemblyBuffer {
	/// Create a new fragment reassembly buffer
	fn new() -> Self {
		Self {
			fragments: Cache::new(1000),
		}
	}

	/// Add a fragment to the buffer.
	///
	/// `frag_total` and `frag_id` arrive straight from the wire and are
	/// fully attacker-controlled. We validate them up front:
	///
	/// * `frag_total == 0` — meaningless ("packet split into zero pieces"). The
	///   old code would insert a zero-capacity sub-cache and trip the
	///   "entry_count == frag_total" check immediately with an empty payload
	///   set, which `reassemble_packet` then turned into a zero-byte packet.
	///   Reject up front.
	/// * `frag_id >= frag_total` — out of range; would poison the
	///   per-(assoc_id, pkt_id) sub-cache by storing under a key the reassembly
	///   walk never reads, permanently blocking the genuine packet from
	///   completing. Reject.
	/// * `frag_total` disagreement with the first fragment we've seen for this
	///   (assoc_id, pkt_id) — also rejected, otherwise an attacker could
	///   over-declare `frag_total = 255` on a forged packet and pin a 255-entry
	///   sub-cache against a victim's stream.
	async fn add_fragment(&self, info: FragmentInfo, payload: Bytes) -> Option<UdpPacket> {
		let FragmentInfo {
			assoc_id,
			pkt_id,
			frag_total,
			frag_id,
			source,
			target,
		} = info;

		if frag_total == 0 || frag_id >= frag_total {
			tracing::warn!(
				target: "[UDP]",
				assoc_id,
				pkt_id,
				frag_total,
				frag_id,
				"Dropping fragment with invalid frag fields (frag_total == 0 or frag_id >= frag_total)",
			);
			return None;
		}

		let key = (assoc_id, pkt_id);

		// Check if this is a placeholder address (used for non-first fragments)
		let is_placeholder_addr = matches!(target, TargetAddr::IPv4(ip, 0) if ip.is_unspecified());
		// Wrap in Arc once so both the `or_insert_with` future and the
		// post-lookup `store` path can share a reference without cloning the
		// underlying `TargetAddr` (which for `Domain` includes a `String`).
		let target_arc = Arc::new(target);
		let source_arc = source.map(Arc::new);

		// Get or create the fragment metadata
		let is_complete = {
			let meta = self
				.fragments
				.entry(key)
				.or_insert_with({
					let target_arc = target_arc.clone();
					let source_arc = source_arc.clone();
					async move {
						Arc::new(FragmentMetadata {
							frag_total,
							fragments: Cache::new(frag_total.into()),
							last_updated: AtomicU64::new(init_time().elapsed().as_secs()),
							source: ArcSwapOption::new(source_arc),
							target: ArcSwap::new(target_arc),
						})
					}
				})
				.await;

			// Reject fragments whose `frag_total` disagrees with the packet
			// that's already being assembled. Without this check, a forged
			// packet with a different frag_total wedges (or grows) the
			// per-(assoc_id, pkt_id) sub-cache.
			if meta.value().frag_total != frag_total {
				tracing::warn!(
					target: "[UDP]",
					assoc_id,
					pkt_id,
					expected_frag_total = meta.value().frag_total,
					got_frag_total = frag_total,
					frag_id,
					"Dropping fragment with mismatched frag_total for an existing reassembly",
				);
				return None;
			}

			// If this is the first fragment (frag_id == 0) and it has a real address,
			// update the target address in case we received other fragments first with
			// placeholder addresses
			if frag_id == 0 && !is_placeholder_addr {
				meta.value().target.store(target_arc);
			}

			// Update timestamp
			meta.value()
				.last_updated
				.store(init_time().elapsed().as_secs(), Ordering::Relaxed);

			// Store this fragment
			meta.value().fragments.insert(frag_id, payload).await;

			// Ensure all pending cache operations are completed
			meta.value().fragments.run_pending_tasks().await;

			// Check if all fragments have been received
			meta.value().fragments.entry_count() == meta.value().frag_total as u64
		};

		if is_complete {
			// All fragments received, reassemble the packet
			return self.reassemble_packet(key).await;
		}

		None // Not all fragments received yet
	}

	/// Clean up expired fragments.
	///
	/// `invalidate_entries_if` only registers a predicate; the actual eviction
	/// happens during housekeeping. We drive it via `run_pending_tasks` so the
	/// cleanup is observable before this call returns.
	async fn cleanup_expired(&self) {
		if let Err(e) = self.fragments.invalidate_entries_if(move |_, meta| {
			init_time().elapsed() - Duration::from_secs(meta.last_updated.load(Ordering::Relaxed))
				>= Duration::from_millis(FRAGMENT_TIMEOUT_MS)
		}) {
			wind_core::warn!(target: "[UDP]", "Failed to register fragment cleanup predicate: {:?}", e);
			return;
		}
		self.fragments.run_pending_tasks().await;
	}

	/// Reassemble a complete packet from fragments
	async fn reassemble_packet(&self, key: (u16, u16)) -> Option<UdpPacket> {
		if let Some(meta) = self.fragments.remove(&key).await {
			// Create a buffer to hold the reassembled packet
			let mut total_size = 0;
			for i in 0..meta.frag_total {
				let fragment = meta.fragments.get(&i).await?;
				total_size += fragment.len();
			}
			let mut buffer = BytesMut::with_capacity(total_size);

			// Combine fragments in order
			for i in 0..meta.frag_total {
				let fragment = meta.fragments.get(&i).await?;
				buffer.put_slice(&fragment);
			}

			// Return the reassembled packet
			let payload = buffer.freeze();
			match Arc::try_unwrap(meta) {
				Ok(m) => {
					let source = m
						.source
						.into_inner()
						.map(|arc| Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone()));
					let target = Arc::try_unwrap(m.target.into_inner()).unwrap_or_else(|a| (*a).clone());

					Some(UdpPacket { source, target, payload })
				}
				Err(arc) => {
					let source = arc.source.load().as_ref().map(|a| (**a).clone());
					let target = (**arc.target.load()).clone();

					Some(UdpPacket { source, target, payload })
				}
			}
		} else {
			None
		}
	}
}

impl UdpStream {
	pub fn new(connection: quinn::Connection, assoc_id: u16, receive_tx: UdpPacketTx) -> Self {
		Self {
			connection,
			assoc_id,
			receive_tx,
			next_pkt_id: AtomicU16::new(0),
			fragment_buffer: FragmentReassemblyBuffer::new(),
		}
	}

	pub async fn send_packet(&self, packet: UdpPacket) -> eyre::Result<()> {
		let payload_len = packet.payload.len();

		let addr_size = match packet.target {
			TargetAddr::IPv4(..) => 1 + 4 + 2,  // Type (1) + IPv4 (4) + Port (2)
			TargetAddr::IPv6(..) => 1 + 16 + 2, // Type (1) + IPv6 (16) + Port (2)
			TargetAddr::Domain(ref domain, _) => {
				let domain_len = domain.len();
				if domain_len > 255 {
					return Err(eyre::eyre!("Domain name too long"));
				}
				1 + 1 + domain_len + 2 // Type (1) + Length (1) + Domain + Port (2)
			}
		};

		// Calculate header overhead for single packet sending
		// Header (2 bytes) + Command (8 bytes) + Address
		let header_overhead = 10 + addr_size;
		// `saturating_sub` so that a transiently tiny `max_datagram_size`
		// (well below the 10+addr_size header overhead) cannot underflow into
		// `usize::MAX` and let an arbitrarily large payload sneak through the
		// single-datagram branch (where it would then exceed
		// `send_datagram`'s size limit).
		let max_datagram_size = self.connection.max_datagram_size().unwrap_or(1200);
		let single_dg_payload_max = max_datagram_size.saturating_sub(header_overhead);
		if payload_len <= single_dg_payload_max {
			// Allocate the packet id atomically — `load` then `fetch_add` is
			// racy: two concurrent send_packet calls could read the same id
			// and emit two datagrams with identical (assoc_id, pkt_id), which
			// collides with the receiver's fragment-reassembly state.
			let pkt_id = self.next_pkt_id.fetch_add(1, Ordering::Relaxed);
			self.connection
				.send_udp(self.assoc_id, pkt_id, &packet.target, packet.payload, true)
				.await?;
			return Ok(());
		}

		self.send_fragmented_packet(packet).await
	}

	async fn send_fragmented_packet(&self, packet: UdpPacket) -> eyre::Result<()> {
		let payload_len = packet.payload.len();

		// Calculate address size for proper fragment size calculation
		let first_frag_addr_size = match packet.target {
			TargetAddr::IPv4(..) => 1 + 4 + 2,
			TargetAddr::IPv6(..) => 1 + 16 + 2,
			TargetAddr::Domain(ref domain, _) => 1 + 1 + domain.len() + 2,
		};
		// Subsequent fragments use Address::None which is only 1 byte
		let subsequent_frag_addr_size = 1;

		// Calculate max fragment payload size for first and subsequent fragments
		// Header (2 bytes) + Command (8 bytes) + Address
		let max_datagram_size = self.connection.max_datagram_size().unwrap_or(1200);
		let first_frag_header_overhead = 10 + first_frag_addr_size;
		let subsequent_frag_header_overhead = 10 + subsequent_frag_addr_size;
		let first_frag_max_payload = max_datagram_size.saturating_sub(first_frag_header_overhead);
		let subsequent_frag_max_payload = max_datagram_size.saturating_sub(subsequent_frag_header_overhead);

		// Guard against pathological `max_datagram_size` values where the
		// header overhead consumes the entire datagram. In that case both
		// `saturating_sub`s yield 0 and `div_ceil(0)` would panic; refuse the
		// send instead. This was previously reachable both by an adversarial
		// peer advertising a tiny max_datagram_size and by an unusually long
		// domain target that inflated the first-fragment overhead past the
		// datagram size.
		if first_frag_max_payload == 0 || subsequent_frag_max_payload == 0 {
			return Err(eyre::eyre!(
				"max_datagram_size ({}) is too small for header overhead ({} first / {} subsequent) — cannot fragment",
				max_datagram_size,
				first_frag_header_overhead,
				subsequent_frag_header_overhead,
			));
		}

		tracing::debug!(
			target: "[UDP]",
			"Fragmentation params: payload={}, first_frag_overhead={}, subsequent_frag_overhead={}, max_datagram={}, first_frag_max={}, subsequent_frag_max={}",
			payload_len,
			first_frag_header_overhead,
			subsequent_frag_header_overhead,
			max_datagram_size,
			first_frag_max_payload,
			subsequent_frag_max_payload,
		);

		// Calculate number of fragments needed
		// First fragment can hold first_frag_max_payload bytes
		// Each subsequent fragment can hold subsequent_frag_max_payload bytes
		let mut remaining_payload = payload_len;
		let fragment_count = if remaining_payload <= first_frag_max_payload {
			1
		} else {
			remaining_payload -= first_frag_max_payload;
			1 + remaining_payload.div_ceil(subsequent_frag_max_payload)
		};
		if fragment_count > MAX_FRAGMENTS as usize {
			return Err(eyre::eyre!(
				"Packet too large for fragmentation, exceeds maximum fragment count"
			));
		}

		// Assign a packet ID for all fragments in this packet.
		// `try_from` guards against future changes that might weaken the
		// bounds check above from silently truncating the fragment count.
		let pkt_id = self.next_pkt_id.fetch_add(1, Ordering::Relaxed);
		let frag_total =
			u8::try_from(fragment_count).map_err(|_| eyre::eyre!("Fragment count {} exceeds u8 range", fragment_count))?;

		// Fragment and send each piece
		let mut offset = 0;
		for frag_id in 0..fragment_count {
			// Calculate fragment size based on whether it's the first fragment or not
			let max_frag_payload = if frag_id == 0 {
				first_frag_max_payload
			} else {
				subsequent_frag_max_payload
			};

			let remaining = payload_len - offset;
			let fragment_size = remaining.min(max_frag_payload);
			let end = offset + fragment_size;

			// Extract this fragment's payload
			let fragment_payload = packet.payload.slice(offset..end);

			// Allocate one buffer sized for header + payload so we can append
			// without reallocation or an intermediate concat.
			let header_overhead = if frag_id == 0 {
				first_frag_header_overhead
			} else {
				subsequent_frag_header_overhead
			};
			let mut buf = BytesMut::with_capacity(header_overhead + fragment_payload.len());

			// Create packet command with fragmentation info
			HeaderCodec.encode(Header::new(CmdType::Packet), &mut buf)?;
			CmdCodec(CmdType::Packet).encode(
				Command::Packet {
					assoc_id: self.assoc_id,
					pkt_id,
					frag_total,
					frag_id: frag_id as u8,
					size: fragment_payload.len() as u16,
				},
				&mut buf,
			)?;

			// Add target address (only in first fragment)
			if frag_id == 0 {
				AddressCodec.encode(packet.target.to_owned().into(), &mut buf)?;
			} else {
				AddressCodec.encode(Address::None, &mut buf)?;
			}

			buf.put_slice(&fragment_payload);
			let combined_payload = buf.freeze();

			// Per-packet diagnostics are kept at `trace`/`debug` — emitting at
			// `info` for every fragment on a busy UDP path was expensive
			// (string formatting + I/O cost per packet), and the size is
			// recoverable from the warn-level error if it ever overflows.
			let datagram_size = combined_payload.len();
			let max_allowed = self.connection.max_datagram_size().unwrap_or(1200);
			if datagram_size > max_allowed {
				wind_core::warn!(
					target: "[UDP]",
					"Fragment too large: {} bytes > {} bytes max (frag {}/{})",
					datagram_size, max_allowed, frag_id + 1, frag_total,
				);
			} else {
				tracing::debug!(
					target: "[UDP]",
					"Sending fragment {}/{}: {} bytes",
					frag_id + 1, frag_total, datagram_size,
				);
			}

			// Send using datagram
			self.connection
				.send_datagram(combined_payload)
				.map_err(|e| eyre::eyre!("Failed to send fragment: {}", e))?;

			// Update offset for next fragment
			offset = end;
		}

		Ok(())
	}

	/// Process an incoming packet fragment
	/// This would be called by the packet handler in the TUIC protocol
	#[allow(clippy::too_many_arguments)]
	pub async fn process_fragment(
		&self,
		assoc_id: u16,
		pkt_id: u16,
		frag_total: u8,
		frag_id: u8,
		payload: Bytes,
		source: Option<TargetAddr>,
		target: TargetAddr,
	) -> Option<UdpPacket> {
		// Add fragment to reassembly buffer and check if packet is complete
		self.fragment_buffer
			.add_fragment(
				FragmentInfo {
					assoc_id,
					pkt_id,
					frag_total,
					frag_id,
					source,
					target,
				},
				payload,
			)
			.await
	}

	/// Receive a complete packet from remote server
	/// This will forward the packet to the local receive channel
	pub async fn receive_packet(&self, packet: UdpPacket) -> eyre::Result<()> {
		self.receive_tx
			.send(packet)
			.await
			.map_err(|e| eyre::eyre!("Failed to send packet to receive channel: {:?}", e))
	}

	pub async fn collect_garbage(&self) {
		self.fragment_buffer.cleanup_expired().await;
	}

	pub async fn close(&mut self) -> Result<(), crate::Error> {
		// Close the UDP association
		self.connection.drop_udp(self.assoc_id).await
	}
}

#[cfg(test)]
mod tests {
	use std::net::Ipv4Addr;

	use super::*;

	/// Test helper to calculate address size according to SPEC.md Section 6.2
	/// (Address Type Registry) and Section 6.3 (Address Type Specifications)
	fn calculate_addr_size(target: &TargetAddr) -> usize {
		match target {
			TargetAddr::IPv4(..) => 1 + 4 + 2,  // Type (1) + IPv4 (4) + Port (2) = 7 bytes
			TargetAddr::IPv6(..) => 1 + 16 + 2, // Type (1) + IPv6 (16) + Port (2) = 19 bytes
			TargetAddr::Domain(domain, _) => 1 + 1 + domain.len() + 2, /* Type (1) + Len (1) +
			                                      * Domain + Port (2) */
		}
	}

	/// SPEC.md Section 8.6: Fragmentation Size Calculations
	#[test]
	fn test_fragment_count_calculation() {
		const MAX_DATAGRAM_SIZE: usize = 1200;
		let addr = TargetAddr::IPv4(Ipv4Addr::new(192, 168, 1, 1), 8080);

		// First fragment has full address
		let first_frag_overhead = 2 + 8 + calculate_addr_size(&addr);
		// Subsequent fragments use Address::None (1 byte)
		let subsequent_frag_overhead = 2 + 8 + 1;

		let first_frag_max = MAX_DATAGRAM_SIZE - first_frag_overhead;
		let subsequent_frag_max = MAX_DATAGRAM_SIZE - subsequent_frag_overhead;

		// Helper function to calculate fragment count
		let calc_frags = |payload_size: usize| -> usize {
			if payload_size <= first_frag_max {
				1
			} else {
				let remaining = payload_size - first_frag_max;
				1 + remaining.div_ceil(subsequent_frag_max)
			}
		};

		// Test various payload sizes
		let test_cases = vec![
			(1000, 1),                                     // Small payload, 1 fragment
			(first_frag_max, 1),                           // Exactly max size for first fragment, 1 fragment
			(first_frag_max + 1, 2),                       // Just over, 2 fragments
			(first_frag_max + subsequent_frag_max, 2),     // Exactly 2 fragments
			(first_frag_max + subsequent_frag_max + 1, 3), // Just over 2x, 3 fragments
			(10000, calc_frags(10000)),                    // Large payload
		];

		for (payload_size, expected_fragments) in test_cases {
			let fragment_count = calc_frags(payload_size);
			assert_eq!(
				fragment_count, expected_fragments,
				"Payload {} bytes should require {} fragments",
				payload_size, expected_fragments
			);
		}
	}

	/// SPEC.md Section 8.7: Implementation Constraints - Fragment count must
	/// not exceed 255
	#[test]
	fn test_max_fragment_limit() {
		const MAX_FRAGMENTS: u8 = 255;
		const MAX_DATAGRAM_SIZE: usize = 1200;

		let addr = TargetAddr::IPv4(Ipv4Addr::new(192, 168, 1, 1), 8080);

		// First fragment has full address
		let first_frag_overhead = 2 + 8 + calculate_addr_size(&addr);
		// Subsequent fragments use Address::None (1 byte)
		let subsequent_frag_overhead = 2 + 8 + 1;

		let first_frag_max = MAX_DATAGRAM_SIZE - first_frag_overhead;
		let subsequent_frag_max = MAX_DATAGRAM_SIZE - subsequent_frag_overhead;

		// Maximum allowable payload with 255 fragments
		// First fragment + 254 subsequent fragments
		let max_payload = first_frag_max + (subsequent_frag_max * (MAX_FRAGMENTS as usize - 1));

		// Calculate fragment count
		let remaining = max_payload - first_frag_max;
		let fragment_count = 1 + remaining.div_ceil(subsequent_frag_max);

		assert_eq!(fragment_count, 255, "Should be able to send 255 fragments");
		assert!(fragment_count <= MAX_FRAGMENTS as usize, "Fragment count must not exceed 255");

		// One byte over should exceed limit
		let oversized_payload = max_payload + 1;
		let oversized_remaining = oversized_payload - first_frag_max;
		let oversized_count = 1 + oversized_remaining.div_ceil(subsequent_frag_max);
		assert!(
			oversized_count > MAX_FRAGMENTS as usize,
			"Oversized payload should exceed fragment limit"
		);
	}

	/// Test fragment reassembly buffer
	#[test_log::test(tokio::test)]
	async fn test_fragment_reassembly_single_fragment() {
		let buffer = FragmentReassemblyBuffer::new();
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);
		let payload = Bytes::from("test payload");

		// Single fragment packet
		let result = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 100,
					frag_total: 1,
					frag_id: 0,
					source: None,
					target: target.clone(),
				},
				payload.clone(),
			)
			.await;

		assert!(result.is_some(), "Single fragment should complete immediately");
		let packet = result.unwrap();
		assert_eq!(packet.payload, payload);
	}

	/// Test fragment reassembly with multiple fragments
	#[test_log::test(tokio::test)]
	async fn test_fragment_reassembly_multiple_fragments() {
		let buffer = FragmentReassemblyBuffer::new();
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

		let frag1 = Bytes::from("Hello ");
		let frag2 = Bytes::from("World");

		// Add first fragment
		let result1 = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 200,
					frag_total: 2,
					frag_id: 0,
					source: None,
					target: target.clone(),
				},
				frag1.clone(),
			)
			.await;
		assert!(result1.is_none(), "First fragment should not complete packet");

		// Add second fragment - should complete
		let result2 = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 200,
					frag_total: 2,
					frag_id: 1,
					source: None,
					target: target.clone(),
				},
				frag2.clone(),
			)
			.await;
		assert!(result2.is_some(), "Second fragment should complete packet");

		let packet = result2.unwrap();
		assert_eq!(packet.payload, Bytes::from("Hello World"));
	}

	/// Test fragment reassembly with out-of-order fragments
	#[test_log::test(tokio::test)]
	async fn test_fragment_reassembly_out_of_order() {
		let buffer = FragmentReassemblyBuffer::new();
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

		let frag0 = Bytes::from("A");
		let frag1 = Bytes::from("B");
		let frag2 = Bytes::from("C");

		// Add fragments out of order: 2, 0, 1
		assert!(
			buffer
				.add_fragment(
					FragmentInfo {
						assoc_id: 1,
						pkt_id: 300,
						frag_total: 3,
						frag_id: 2,
						source: None,
						target: target.clone(),
					},
					frag2.clone(),
				)
				.await
				.is_none()
		);
		assert!(
			buffer
				.add_fragment(
					FragmentInfo {
						assoc_id: 1,
						pkt_id: 300,
						frag_total: 3,
						frag_id: 0,
						source: None,
						target: target.clone(),
					},
					frag0.clone(),
				)
				.await
				.is_none()
		);

		let result = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 300,
					frag_total: 3,
					frag_id: 1,
					source: None,
					target: target.clone(),
				},
				frag1.clone(),
			)
			.await;
		assert!(result.is_some(), "All fragments received, should complete");

		let packet = result.unwrap();
		assert_eq!(packet.payload, Bytes::from("ABC"));
	}

	/// Test multiple simultaneous fragmentations
	#[test_log::test(tokio::test)]
	async fn test_multiple_simultaneous_fragmentations() {
		let buffer = FragmentReassemblyBuffer::new();
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

		// Start two different packets
		buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 100,
					frag_total: 2,
					frag_id: 0,
					source: None,
					target: target.clone(),
				},
				Bytes::from("A1"),
			)
			.await;
		buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 101,
					frag_total: 2,
					frag_id: 0,
					source: None,
					target: target.clone(),
				},
				Bytes::from("B1"),
			)
			.await;

		// Complete first packet
		let result1 = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 100,
					frag_total: 2,
					frag_id: 1,
					source: None,
					target: target.clone(),
				},
				Bytes::from("A2"),
			)
			.await;
		assert!(result1.is_some());
		assert_eq!(result1.unwrap().payload, Bytes::from("A1A2"));

		// Complete second packet
		let result2 = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 101,
					frag_total: 2,
					frag_id: 1,
					source: None,
					target: target.clone(),
				},
				Bytes::from("B2"),
			)
			.await;
		assert!(result2.is_some());
		assert_eq!(result2.unwrap().payload, Bytes::from("B1B2"));
	}

	/// Test fragment cleanup (expired fragments)
	#[test_log::test(tokio::test)]
	async fn test_fragment_cleanup() {
		let buffer = FragmentReassemblyBuffer::new();
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

		// Add incomplete fragment
		buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 400,
					frag_total: 2,
					frag_id: 0,
					source: None,
					target: target.clone(),
				},
				Bytes::from("test"),
			)
			.await;

		// Wait for pending tasks to ensure the fragment is properly stored
		buffer.fragments.run_pending_tasks().await;
		assert_eq!(buffer.fragments.entry_count(), 1, "Should have one incomplete packet");

		// Manually remove the entry to simulate cleanup
		buffer.fragments.remove(&(1, 400)).await;
		buffer.fragments.run_pending_tasks().await;

		assert_eq!(buffer.fragments.entry_count(), 0, "Fragments should be cleaned up");
	}

	/// Verify saturating_sub prevents underflow as mentioned in SPEC.md Section
	/// 8.7
	#[test]
	fn test_saturating_sub_prevents_underflow() {
		let small_mtu: usize = 10;
		let large_overhead: usize = 100;

		// Using saturating_sub should give 0 instead of underflowing
		let result = small_mtu.saturating_sub(large_overhead);
		assert_eq!(result, 0, "saturating_sub should prevent underflow");

		// Normal subtraction would panic in debug mode or wrap in release
		// This test verifies the implementation advice from SPEC.md Section 8.7
	}

	// ----------------------------------------------------------------------
	// PR2 regression tests
	// ----------------------------------------------------------------------

	/// `frag_total == 0` and `frag_id >= frag_total` are both forbidden by
	/// the spec, but are attacker-controlled on the wire. The buffer must
	/// drop such fragments instead of producing a zero-byte "reassembled"
	/// packet or poisoning the per-pkt sub-cache.
	#[test_log::test(tokio::test)]
	async fn test_add_fragment_rejects_zero_total() {
		let buffer = FragmentReassemblyBuffer::new();
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

		let res = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 1,
					frag_total: 0,
					frag_id: 0,
					source: None,
					target,
				},
				Bytes::from_static(b"x"),
			)
			.await;
		assert!(res.is_none(), "frag_total=0 must be dropped");
		buffer.fragments.run_pending_tasks().await;
		assert_eq!(buffer.fragments.entry_count(), 0, "frag_total=0 must not insert an entry");
	}

	#[test_log::test(tokio::test)]
	async fn test_add_fragment_rejects_out_of_range_frag_id() {
		let buffer = FragmentReassemblyBuffer::new();
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

		let res = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 1,
					frag_total: 3,
					frag_id: 7, // > frag_total
					source: None,
					target,
				},
				Bytes::from_static(b"x"),
			)
			.await;
		assert!(res.is_none(), "frag_id >= frag_total must be dropped");
		buffer.fragments.run_pending_tasks().await;
		assert_eq!(
			buffer.fragments.entry_count(),
			0,
			"out-of-range frag_id must not insert an entry"
		);
	}

	/// Once a reassembly slot is open with `frag_total = N`, fragments
	/// claiming a different `frag_total` for the same (assoc_id, pkt_id)
	/// must be rejected, otherwise an attacker can over-declare to grow
	/// the per-packet sub-cache or block completion entirely.
	#[test_log::test(tokio::test)]
	async fn test_add_fragment_rejects_mismatched_frag_total() {
		let buffer = FragmentReassemblyBuffer::new();
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

		// First legitimate fragment opens the slot at frag_total=2.
		let _ = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 1,
					frag_total: 2,
					frag_id: 0,
					source: None,
					target: target.clone(),
				},
				Bytes::from_static(b"AA"),
			)
			.await;

		// Forged fragment claiming frag_total=255 — must be dropped.
		let res = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 1,
					frag_total: 255,
					frag_id: 200,
					source: None,
					target: target.clone(),
				},
				Bytes::from_static(b"X"),
			)
			.await;
		assert!(res.is_none(), "mismatched frag_total must be dropped");

		// The legitimate completion path still works after the forged drop.
		let completed = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 1,
					frag_total: 2,
					frag_id: 1,
					source: None,
					target,
				},
				Bytes::from_static(b"BB"),
			)
			.await;
		let packet = completed.expect("legitimate completion must still succeed");
		assert_eq!(&packet.payload[..], b"AABB");
	}
}

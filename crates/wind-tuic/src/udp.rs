//! UDP fragment reassembly state machine for the TUIC native (datagram) UDP
//! relay mode.
//!
//! This is the receive-side counterpart to the per-backend send path. It is
//! fully backend-agnostic: it consumes already-decoded fragment metadata plus a
//! payload [`Bytes`] and yields a reassembled [`UdpPacket`] once every fragment
//! of a `(assoc_id, pkt_id)` group has arrived. The buffer is hardened against
//! attacker-controlled fragment fields (see
//! [`FragmentReassemblyBuffer::add_fragment`]).

use std::{
	collections::{HashMap, hash_map::Entry},
	sync::Mutex,
	time::{Duration, Instant},
};

use bytes::{BufMut, Bytes, BytesMut};
use wind_core::{types::TargetAddr, udp::UdpPacket};

/// Maximum number of fragments allowed for a single packet.
pub const MAX_FRAGMENTS: u8 = 255;
/// Maximum number of concurrently tracked incomplete fragment groups per
/// [`FragmentReassemblyBuffer`]. Exceeding it evicts the oldest groups, so a
/// peer that opens many never-completing groups cannot grow the buffer without
/// bound.
const MAX_INCOMPLETE_GROUPS: usize = 1000;
/// Timeout (ms) after which incomplete fragment groups are evicted.
const FRAGMENT_TIMEOUT_MS: u64 = 30000;
/// Default lifetime for incomplete fragment groups, exposed so callers can
/// reuse it when constructing a [`UdpStream`](crate::proto::UdpStream).
pub const DEFAULT_FRAGMENT_TIMEOUT: Duration = Duration::from_millis(FRAGMENT_TIMEOUT_MS);

/// Fragment information for reassembly.
pub struct FragmentInfo {
	pub assoc_id: u16,
	pub pkt_id: u16,
	pub frag_total: u8,
	pub frag_id: u8,
	pub source: Option<TargetAddr>,
	pub target: TargetAddr,
}

/// A map entry owns one incomplete packet until completion or eviction.
struct FragmentGroup {
	fragments: Vec<Option<Bytes>>,
	missing: usize,
	last_updated: Instant,
	source: Option<TargetAddr>,
	target: TargetAddr,
}

impl FragmentGroup {
	fn into_packet(self) -> UdpPacket {
		let size = self.fragments.iter().flatten().map(Bytes::len).sum();
		let mut buffer = BytesMut::with_capacity(size);
		for part in self.fragments.into_iter().flatten() {
			buffer.put_slice(&part);
		}
		UdpPacket {
			source: self.source,
			target: self.target,
			payload: buffer.freeze(),
		}
	}
}

/// Buffer for reassembling fragmented packets.
///
/// The tracked groups live in an explicit map instead of a cache with an
/// expiration policy: eviction here has to be *observable*, because the
/// lifetime is a resource-exhaustion bound rather than a hint (see
/// [`FragmentReassemblyBuffer::cleanup_expired`]). moka's
/// `invalidate_entries_if` cannot provide that without
/// `support_invalidation_closures`, and its per-entry `Expiry` alone does not
/// evict from `run_pending_tasks` at all; both were verified against
/// `moka-0.12.16` before choosing this representation.
pub struct FragmentReassemblyBuffer {
	inner: Mutex<FragmentState>,
}

/// State behind [`FragmentReassemblyBuffer::inner`].
struct FragmentState {
	groups: HashMap<(u16, u16), FragmentGroup>,
	/// Lifetime after the last fragment of a group; set at construction (see
	/// [`FragmentReassemblyBuffer::new`]).
	lifetime: Duration,
}

impl Default for FragmentReassemblyBuffer {
	fn default() -> Self {
		Self::new(DEFAULT_FRAGMENT_TIMEOUT)
	}
}

impl FragmentReassemblyBuffer {
	/// Create a new fragment reassembly buffer whose incomplete groups are
	/// evicted `lifetime` after the last fragment they received.
	///
	/// The lifetime is a constructor argument rather than a per-cleanup
	/// argument on purpose: a lifetime that only reaches cleanup could be
	/// silently unreachable, which is exactly the no-op this type used to have.
	pub fn new(lifetime: Duration) -> Self {
		Self {
			inner: Mutex::new(FragmentState {
				groups: HashMap::new(),
				lifetime,
			}),
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
	///   set, which then yielded a zero-byte packet. Reject up front.
	/// * `frag_id >= frag_total` — out of range; would poison the
	///   per-(assoc_id, pkt_id) group by storing under a slot the reassembly
	///   walk never reads, permanently blocking the genuine packet from
	///   completing. Reject.
	/// * `frag_total` disagreement with the first fragment we've seen for this
	///   (assoc_id, pkt_id) — also rejected, otherwise an attacker could
	///   over-declare `frag_total = 255` on a forged packet and pin a 255-entry
	///   group against a victim's stream.
	pub async fn add_fragment(&self, info: FragmentInfo, payload: Bytes) -> Option<UdpPacket> {
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
				target: "udp",
				assoc_id,
				pkt_id,
				frag_total,
				frag_id,
				"Dropping fragment with invalid frag fields (frag_total == 0 or frag_id >= frag_total)",
			);
			return None;
		}

		let key = (assoc_id, pkt_id);

		// Take the completed group out of the map in the same critical section
		// that observes completion, so no other fragment can race the
		// reassembly. The lock is never held across an await point.
		let completed = {
			let mut state = self.inner.lock().expect("fragment buffer mutex poisoned");

			if !state.groups.contains_key(&key) {
				// Capacity pressure: drop the oldest groups first so a peer
				// cannot pin unbounded memory with never-completing groups.
				while state.groups.len() >= MAX_INCOMPLETE_GROUPS {
					Self::evict_oldest(&mut state.groups);
				}
			}

			let mut entry = match state.groups.entry(key) {
				Entry::Vacant(slot) => slot.insert_entry(FragmentGroup {
					fragments: vec![None; usize::from(frag_total)],
					missing: usize::from(frag_total),
					last_updated: Instant::now(),
					source,
					target,
				}),
				Entry::Occupied(mut slot) => {
					let group = slot.get_mut();
					if group.fragments.len() != usize::from(frag_total) {
						tracing::warn!(
							target: "udp", assoc_id, pkt_id, frag_id,
							expected_frag_total = group.fragments.len(), got_frag_total = frag_total,
							"Dropping fragment with mismatched frag_total for an existing reassembly",
						);
						return None;
					}
					// A real address on fragment zero supersedes the address of
					// the first arrival.
					if frag_id == 0 && !matches!(target, TargetAddr::IPv4(ip, 0) if ip.is_unspecified()) {
						group.target = target;
					}
					slot
				}
			};
			let group = entry.get_mut();
			if group.fragments[usize::from(frag_id)].replace(payload).is_none() {
				group.missing -= 1;
			}
			group.last_updated = Instant::now();
			if group.missing != 0 {
				return None;
			}
			entry.remove()
		};
		Some(completed.into_packet())
	}

	/// Evict fragment groups that outlived their lifetime.
	///
	/// A group is retained for the configured lifetime after its **last**
	/// fragment arrived, and eviction is unconditional here (not merely
	/// "scheduled"): callers drive this on a timer and depend on stale groups
	/// being gone by the time it returns.
	pub async fn cleanup_expired(&self) {
		let mut state = self.inner.lock().expect("fragment buffer mutex poisoned");
		let lifetime = state.lifetime;
		state.groups.retain(|_, meta| meta.last_updated.elapsed() < lifetime);
	}

	/// Drop the group whose last fragment is the oldest.
	fn evict_oldest(groups: &mut HashMap<(u16, u16), FragmentGroup>) {
		let Some(oldest) = groups.iter().min_by_key(|(_, meta)| meta.last_updated).map(|(key, _)| *key) else {
			return;
		};
		groups.remove(&oldest);
	}

	/// Number of incomplete fragment groups currently retained, after evicting
	/// those past their lifetime. Test-only: the buffer is not a metrics
	/// surface.
	#[cfg(test)]
	pub(crate) async fn incomplete_group_count(&self) -> usize {
		self.cleanup_expired().await;
		self.incomplete_group_count_without_cleanup()
	}

	/// Number of incomplete fragment groups currently retained, **without**
	/// evicting anything first. Test-only: lets a test observe the state the
	/// periodic GC left behind instead of running cleanup itself.
	#[cfg(test)]
	pub(crate) fn incomplete_group_count_without_cleanup(&self) -> usize {
		self.inner.lock().expect("fragment buffer mutex poisoned").groups.len()
	}
}

#[cfg(test)]
mod tests {
	use std::{net::Ipv4Addr, time::Duration};

	use super::*;

	#[tokio::test]
	async fn fragment_zero_updates_the_target_but_keeps_the_first_arrivals_source() {
		let buffer = FragmentReassemblyBuffer::default();
		let placeholder = TargetAddr::IPv4(Ipv4Addr::UNSPECIFIED, 0);
		let target = TargetAddr::Domain("example.test".into(), 53);
		let source = TargetAddr::IPv4(Ipv4Addr::LOCALHOST, 1111);
		let fragment = |frag_id, source, target| FragmentInfo {
			assoc_id: 1,
			pkt_id: 2,
			frag_total: 2,
			frag_id,
			source,
			target,
		};
		assert!(
			buffer
				.add_fragment(fragment(1, Some(source.clone()), placeholder), Bytes::from_static(b"b"))
				.await
				.is_none()
		);
		let packet = buffer
			.add_fragment(fragment(0, None, target.clone()), Bytes::from_static(b"a"))
			.await
			.unwrap();
		assert_eq!(packet.source, Some(source));
		assert_eq!(packet.target, target);
		assert_eq!(packet.payload.as_ref(), b"ab");
		assert_eq!(buffer.incomplete_group_count_without_cleanup(), 0);
	}

	#[test_log::test(tokio::test)]
	async fn test_fragment_reassembly_single_fragment() {
		let buffer = FragmentReassemblyBuffer::new(DEFAULT_FRAGMENT_TIMEOUT);
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);
		let payload = Bytes::from("test payload");

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

	#[test_log::test(tokio::test)]
	async fn test_fragment_reassembly_multiple_fragments() {
		let buffer = FragmentReassemblyBuffer::new(DEFAULT_FRAGMENT_TIMEOUT);
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

		let frag1 = Bytes::from("Hello ");
		let frag2 = Bytes::from("World");

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

	#[test_log::test(tokio::test)]
	async fn test_fragment_reassembly_out_of_order() {
		let buffer = FragmentReassemblyBuffer::new(DEFAULT_FRAGMENT_TIMEOUT);
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

		let frag0 = Bytes::from("A");
		let frag1 = Bytes::from("B");
		let frag2 = Bytes::from("C");

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

	#[test_log::test(tokio::test)]
	async fn test_multiple_simultaneous_fragmentations() {
		let buffer = FragmentReassemblyBuffer::new(DEFAULT_FRAGMENT_TIMEOUT);
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

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

	/// An incomplete group is tracked, and cleanup within its lifetime leaves
	/// it alone.
	#[test_log::test(tokio::test)]
	async fn test_incomplete_group_is_tracked_until_its_lifetime() {
		let buffer = FragmentReassemblyBuffer::new(DEFAULT_FRAGMENT_TIMEOUT);
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

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

		assert_eq!(buffer.incomplete_group_count().await, 1, "Should have one incomplete packet");

		assert_eq!(
			buffer.incomplete_group_count().await,
			1,
			"cleanup must not drop a group that is still within its lifetime"
		);
	}

	/// `frag_total == 0` and `frag_id >= frag_total` are both forbidden by
	/// the spec, but are attacker-controlled on the wire. The buffer must
	/// drop such fragments instead of producing a zero-byte "reassembled"
	/// packet or poisoning the per-pkt sub-cache.
	#[test_log::test(tokio::test)]
	async fn test_add_fragment_rejects_zero_total() {
		let buffer = FragmentReassemblyBuffer::new(DEFAULT_FRAGMENT_TIMEOUT);
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
		assert_eq!(
			buffer.incomplete_group_count().await,
			0,
			"frag_total=0 must not insert an entry"
		);
	}

	#[test_log::test(tokio::test)]
	async fn test_add_fragment_rejects_out_of_range_frag_id() {
		let buffer = FragmentReassemblyBuffer::new(DEFAULT_FRAGMENT_TIMEOUT);
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
		assert_eq!(
			buffer.incomplete_group_count().await,
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
		let buffer = FragmentReassemblyBuffer::new(DEFAULT_FRAGMENT_TIMEOUT);
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

	// -----------------------------------------------------------------------
	// F17: incomplete fragment groups must actually be evicted. The previous
	// construction (`Cache::new(1000)` plus `invalidate_entries_if`) could
	// never evict anything — moka answers
	// `PredicateError::InvalidationClosuresDisabled` unless the cache was
	// built with `support_invalidation_closures`, so the documented 30 s
	// fragment timeout was a guaranteed no-op and stale groups stayed pinned
	// for the association's lifetime.
	// -----------------------------------------------------------------------

	/// A zero lifetime must evict an incomplete group as soon as cleanup runs:
	/// the group's deadline is its last fragment, so it is already expired.
	#[test_log::test(tokio::test)]
	async fn f17_zero_lifetime_evicts_incomplete_group() {
		let buffer = FragmentReassemblyBuffer::new(Duration::ZERO);
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

		let res = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 1,
					frag_total: 2,
					frag_id: 0,
					source: None,
					target,
				},
				Bytes::from_static(b"AA"),
			)
			.await;
		assert!(res.is_none(), "an incomplete group must not complete");

		buffer.cleanup_expired().await;
		assert_eq!(
			buffer.incomplete_group_count().await,
			0,
			"an incomplete group past its lifetime must be evicted"
		);
	}

	/// A group that stops receiving fragments is evicted once its lifetime
	/// elapses; a group created afterwards is retained by the same cleanup,
	/// which is the control for a cleanup that would evict unconditionally.
	#[test_log::test(tokio::test)]
	async fn f17_stale_group_is_evicted_but_live_group_is_retained() {
		let lifetime = Duration::from_millis(150);
		let buffer = FragmentReassemblyBuffer::new(lifetime);
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

		let stale = buffer
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
		assert!(stale.is_none());
		assert_eq!(buffer.incomplete_group_count().await, 1, "the incomplete group is tracked");

		// Outlive the lifetime, then create a fresh group.
		tokio::time::sleep(lifetime * 2).await;
		let fresh = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 2,
					frag_total: 2,
					frag_id: 0,
					source: None,
					target,
				},
				Bytes::from_static(b"CC"),
			)
			.await;
		assert!(fresh.is_none());

		// Cleanup within the fresh group's lifetime evicts the stale group and
		// leaves the fresh one: the lifetime is measured per group from its own
		// last fragment, not from "the most recent cleanup".
		assert_eq!(
			buffer.incomplete_group_count().await,
			1,
			"the stale group is evicted while the fresh one survives"
		);
	}

	/// Regression guard for the completion path: reassembly still works when
	/// the group is assembled within its lifetime, and arriving fragments
	/// refresh the deadline rather than letting the group expire mid-assembly.
	#[test_log::test(tokio::test)]
	async fn f17_reassembly_still_completes_within_lifetime() {
		let buffer = FragmentReassemblyBuffer::new(Duration::from_millis(150));
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

		let first = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 9,
					frag_total: 3,
					frag_id: 0,
					source: None,
					target: target.clone(),
				},
				Bytes::from_static(b"AA"),
			)
			.await;
		assert!(first.is_none());

		// Outlive the lifetime between fragments: the group must survive
		// because the deadline restarts on each arriving fragment.
		tokio::time::sleep(Duration::from_millis(100)).await;
		let second = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 9,
					frag_total: 3,
					frag_id: 1,
					source: None,
					target: target.clone(),
				},
				Bytes::from_static(b"BB"),
			)
			.await;
		assert!(second.is_none());

		tokio::time::sleep(Duration::from_millis(100)).await;
		let third = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 9,
					frag_total: 3,
					frag_id: 2,
					source: None,
					target,
				},
				Bytes::from_static(b"CC"),
			)
			.await;

		let packet = third.expect("a group receiving fragments must not expire mid-assembly");
		assert_eq!(&packet.payload[..], b"AABBCC");
	}

	/// A repeated `frag_id` overwrites its slot instead of counting twice, so a
	/// peer cannot complete a group by resending one fragment.
	#[test_log::test(tokio::test)]
	async fn f17_duplicate_fragment_id_does_not_complete_a_group() {
		let buffer = FragmentReassemblyBuffer::new(DEFAULT_FRAGMENT_TIMEOUT);
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

		for _ in 0..4 {
			let res = buffer
				.add_fragment(
					FragmentInfo {
						assoc_id: 1,
						pkt_id: 3,
						frag_total: 2,
						frag_id: 0,
						source: None,
						target: target.clone(),
					},
					Bytes::from_static(b"AA"),
				)
				.await;
			assert!(res.is_none(), "resending frag_id 0 must not complete a 2-fragment group");
		}

		let completed = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: 3,
					frag_total: 2,
					frag_id: 1,
					source: None,
					target,
				},
				Bytes::from_static(b"BB"),
			)
			.await;
		let packet = completed.expect("the genuine second fragment must still complete the group");
		assert_eq!(&packet.payload[..], b"AABB");
	}

	/// Never-completing groups are bounded by capacity: once
	/// [`MAX_INCOMPLETE_GROUPS`] groups are tracked, admitting another one
	/// evicts the oldest instead of growing the buffer.
	#[test_log::test(tokio::test)]
	async fn f17_capacity_evicts_oldest_incomplete_groups() {
		let buffer = FragmentReassemblyBuffer::new(DEFAULT_FRAGMENT_TIMEOUT);
		let target = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);

		for pkt_id in 0..MAX_INCOMPLETE_GROUPS as u16 {
			let res = buffer
				.add_fragment(
					FragmentInfo {
						assoc_id: 1,
						pkt_id,
						frag_total: 2,
						frag_id: 0,
						source: None,
						target: target.clone(),
					},
					Bytes::from_static(b"AA"),
				)
				.await;
			assert!(res.is_none());
		}
		assert_eq!(
			buffer.incomplete_group_count().await,
			MAX_INCOMPLETE_GROUPS,
			"the buffer is at its capacity bound"
		);

		// One more group evicts the oldest (pkt_id 0) rather than growing.
		let res = buffer
			.add_fragment(
				FragmentInfo {
					assoc_id: 1,
					pkt_id: u16::MAX,
					frag_total: 2,
					frag_id: 0,
					source: None,
					target,
				},
				Bytes::from_static(b"AA"),
			)
			.await;
		assert!(res.is_none());
		assert_eq!(
			buffer.incomplete_group_count().await,
			MAX_INCOMPLETE_GROUPS,
			"the buffer stays bounded by evicting its oldest group"
		);
	}
}

use rkyv::{Archived, vec::ArchivedVec};

use crate::snapshot::*;

impl ArchivedGeoSiteIndex {
	pub fn contains(&self, category: &str, domain: &str) -> bool {
		let idx = binary_search_cat(&self.categories, category);
		let Some(idx) = idx else {
			return false;
		};
		let cat = &self.categories[idx];

		let exact_start = cat.exact_start.to_native() as usize;
		let exact_len = cat.exact_len.to_native() as usize;
		if binary_search_str(&self.exact_domains, exact_start, exact_len, domain).is_some() {
			return true;
		}

		let suffix_start = cat.suffix_start.to_native() as usize;
		let suffix_len = cat.suffix_len.to_native() as usize;
		if suffix_match(&self.suffix_domains, suffix_start, suffix_len, domain) {
			return true;
		}

		let keyword_start = cat.keyword_start.to_native() as usize;
		let keyword_len = cat.keyword_len.to_native() as usize;
		if keyword_match(&self.keyword_domains, keyword_start, keyword_len, domain) {
			return true;
		}

		false
	}
}

fn binary_search_cat(cats: &ArchivedVec<ArchivedCategoryInfo>, name: &str) -> Option<usize> {
	let len = cats.len();
	if len == 0 {
		return None;
	}
	let mut lo = 0usize;
	let mut hi = len;
	while lo < hi {
		let mid = lo + (hi - lo) / 2;
		match cats[mid].name.as_str().cmp(name) {
			std::cmp::Ordering::Less => lo = mid + 1,
			std::cmp::Ordering::Greater => hi = mid,
			std::cmp::Ordering::Equal => return Some(mid),
		}
	}
	None
}

fn binary_search_str(v: &ArchivedVec<Archived<String>>, start: usize, len: usize, needle: &str) -> Option<usize> {
	if len == 0 {
		return None;
	}
	let mut lo = start;
	let mut hi = start + len;
	while lo < hi {
		let mid = lo + (hi - lo) / 2;
		match v[mid].as_str().cmp(needle) {
			std::cmp::Ordering::Less => lo = mid + 1,
			std::cmp::Ordering::Greater => hi = mid,
			std::cmp::Ordering::Equal => return Some(mid),
		}
	}
	None
}

fn suffix_match(v: &ArchivedVec<Archived<String>>, start: usize, len: usize, domain: &str) -> bool {
	if len == 0 {
		return false;
	}
	let lower = domain.to_ascii_lowercase();
	let bytes = lower.as_bytes();
	let mut pos = 0usize;
	loop {
		let candidate = if pos == 0 {
			&bytes[pos..]
		} else if bytes[pos] == b'.' {
			&bytes[pos + 1..]
		} else {
			pos += 1;
			continue;
		};

		let cand_str = match std::str::from_utf8(candidate) {
			Ok(s) => s,
			Err(_) => break,
		};

		if binary_search_str_suffix(v, start, len, cand_str) {
			return true;
		}

		if pos + 1 >= bytes.len() {
			break;
		}
		pos += 1;
	}
	false
}

fn binary_search_str_suffix(v: &ArchivedVec<Archived<String>>, start: usize, len: usize, needle: &str) -> bool {
	if len == 0 {
		return false;
	}
	let mut lo = start;
	let mut hi = start + len;
	while lo < hi {
		let mid = lo + (hi - lo) / 2;
		match v[mid].as_str().cmp(needle) {
			std::cmp::Ordering::Less => lo = mid + 1,
			std::cmp::Ordering::Greater => hi = mid,
			std::cmp::Ordering::Equal => return true,
		}
	}
	false
}

fn keyword_match(v: &ArchivedVec<Archived<String>>, start: usize, len: usize, domain: &str) -> bool {
	if len == 0 {
		return false;
	}
	let lower = domain.to_ascii_lowercase();
	let end = start + len;
	(start..end).any(|i| lower.contains(v[i].as_str()))
}

impl ArchivedGeoIpIndex {
	pub fn contains(&self, country: &str, ip: std::net::IpAddr) -> bool {
		match ip {
			std::net::IpAddr::V4(v4) => {
				let addr = u32::from(v4);
				let pos = partition_point_v4(&self.v4_entries, addr);
				scan_backward_v4(&self.v4_entries, pos, addr, country)
			}
			std::net::IpAddr::V6(v6) => {
				let addr = u128::from(v6);
				let pos = partition_point_v6(&self.v6_entries, addr);
				scan_backward_v6(&self.v6_entries, pos, addr, country)
			}
		}
	}
}

fn partition_point_v4(entries: &ArchivedVec<ArchivedCidrV4>, target: u32) -> usize {
	let len = entries.len();
	let mut lo: usize = 0;
	let mut hi: usize = len;
	while lo < hi {
		let mid = lo + (hi - lo) / 2;
		if entries[mid].addr.to_native() <= target {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	lo
}

fn partition_point_v6(entries: &ArchivedVec<ArchivedCidrV6>, target: u128) -> usize {
	let len = entries.len();
	let mut lo: usize = 0;
	let mut hi: usize = len;
	while lo < hi {
		let mid = lo + (hi - lo) / 2;
		if entries[mid].addr.to_native() <= target {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	lo
}

fn scan_backward_v4(entries: &ArchivedVec<ArchivedCidrV4>, pos: usize, addr: u32, country: &str) -> bool {
	let mut i = pos;
	let mut checked = 0u32;
	while i > 0 && checked < 5 {
		i -= 1;
		let entry = &entries[i];
		if cidr_contains_v4(addr, entry.addr.to_native(), entry.prefix) {
			return entry.country.as_str().eq_ignore_ascii_case(country);
		}
		checked += 1;
	}
	false
}

fn scan_backward_v6(entries: &ArchivedVec<ArchivedCidrV6>, pos: usize, addr: u128, country: &str) -> bool {
	let mut i = pos;
	let mut checked = 0u32;
	while i > 0 && checked < 5 {
		i -= 1;
		let entry = &entries[i];
		if cidr_contains_v6(addr, entry.addr.to_native(), entry.prefix) {
			return entry.country.as_str().eq_ignore_ascii_case(country);
		}
		checked += 1;
	}
	false
}

fn cidr_contains_v4(addr: u32, cidr_addr: u32, prefix: u8) -> bool {
	if prefix == 0 {
		return true;
	}
	let shift = 32u32.saturating_sub(prefix as u32);
	(addr ^ cidr_addr).wrapping_shr(shift) == 0
}

fn cidr_contains_v6(addr: u128, cidr_addr: u128, prefix: u8) -> bool {
	if prefix == 0 {
		return true;
	}
	let shift = 128u32.saturating_sub(prefix as u32);
	(addr ^ cidr_addr).wrapping_shr(shift) == 0
}

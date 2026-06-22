use geosite_rs::{GeoIpList, GeoSiteList, decode_geoip, decode_geosite};

use crate::snapshot::*;

pub fn build_snapshot(geosite_bytes: &[u8], geoip_bytes: &[u8]) -> Result<GeoDataSnapshot, crate::error::GeoDataError> {
	let geosite_list = decode_geosite(geosite_bytes).map_err(|e| crate::error::GeoDataError::Decode(e.to_string()))?;
	let geoip_list = decode_geoip(geoip_bytes).map_err(|e| crate::error::GeoDataError::Decode(e.to_string()))?;

	let geosite = build_geosite(&geosite_list);
	let geoip = build_geoip(&geoip_list);

	Ok(GeoDataSnapshot { geosite, geoip })
}

fn build_geosite(list: &GeoSiteList) -> GeoSiteIndex {
	let mut categories: Vec<CategoryInfo> = Vec::new();
	let mut exact_domains: Vec<String> = Vec::new();
	let mut suffix_domains: Vec<String> = Vec::new();
	let mut keyword_domains: Vec<String> = Vec::new();

	for site in &list.entry {
		let mut exact: Vec<String> = Vec::new();
		let mut suffix: Vec<String> = Vec::new();
		let mut keyword: Vec<String> = Vec::new();

		for domain in &site.domain {
			let value = domain.value.to_ascii_lowercase();
			match domain.r#type {
				0 => keyword.push(value), // Plain → keyword match
				1 => {}                   // Regex → skip (not in flat arrays)
				2 => suffix.push(value),  // Domain → suffix match
				3 => exact.push(value),   // Full → exact match
				_ => {}
			}
		}

		exact.sort();
		exact.dedup();
		suffix.sort();
		suffix.dedup();
		keyword.sort();
		keyword.dedup();

		let exact_start = exact_domains.len() as u32;
		let exact_len = exact.len() as u32;
		let suffix_start = suffix_domains.len() as u32;
		let suffix_len = suffix.len() as u32;
		let keyword_start = keyword_domains.len() as u32;
		let keyword_len = keyword.len() as u32;

		exact_domains.extend(exact);
		suffix_domains.extend(suffix);
		keyword_domains.extend(keyword);

		categories.push(CategoryInfo {
			name: site.country_code.clone(),
			exact_start,
			exact_len,
			suffix_start,
			suffix_len,
			keyword_start,
			keyword_len,
		});
	}

	// Sort categories by name for binary search.
	categories.sort_by(|a, b| a.name.cmp(&b.name));

	GeoSiteIndex {
		categories,
		exact_domains,
		suffix_domains,
		keyword_domains,
	}
}

fn build_geoip(list: &GeoIpList) -> GeoIpIndex {
	let mut v4_entries: Vec<CidrV4> = Vec::new();
	let mut v6_entries: Vec<CidrV6> = Vec::new();

	for geoip in &list.entry {
		for cidr in &geoip.cidr {
			match cidr.ip.len() {
				4 => {
					let addr = u32::from_be_bytes([cidr.ip[0], cidr.ip[1], cidr.ip[2], cidr.ip[3]]);
					v4_entries.push(CidrV4 {
						addr,
						prefix: cidr.prefix as u8,
						country: geoip.country_code.clone(),
					});
				}
				16 => {
					let addr = u128::from_be_bytes([
						cidr.ip[0],
						cidr.ip[1],
						cidr.ip[2],
						cidr.ip[3],
						cidr.ip[4],
						cidr.ip[5],
						cidr.ip[6],
						cidr.ip[7],
						cidr.ip[8],
						cidr.ip[9],
						cidr.ip[10],
						cidr.ip[11],
						cidr.ip[12],
						cidr.ip[13],
						cidr.ip[14],
						cidr.ip[15],
					]);
					v6_entries.push(CidrV6 {
						addr,
						prefix: cidr.prefix as u8,
						country: geoip.country_code.clone(),
					});
				}
				_ => {}
			}
		}
	}

	v4_entries.sort_by(|a, b| a.addr.cmp(&b.addr).then_with(|| b.prefix.cmp(&a.prefix)));
	v4_entries.dedup_by(|a, b| a.addr == b.addr && a.prefix == b.prefix);

	v6_entries.sort_by(|a, b| a.addr.cmp(&b.addr).then_with(|| b.prefix.cmp(&a.prefix)));
	v6_entries.dedup_by(|a, b| a.addr == b.addr && a.prefix == b.prefix);

	GeoIpIndex { v4_entries, v6_entries }
}

use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Serialize, Deserialize)]
pub struct GeoDataSnapshot {
	pub geosite: GeoSiteIndex,
	pub geoip: GeoIpIndex,
}

#[derive(Archive, Serialize, Deserialize)]
pub struct GeoSiteIndex {
	pub categories: Vec<CategoryInfo>,
	pub exact_domains: Vec<String>,
	pub suffix_domains: Vec<String>,
	pub keyword_domains: Vec<String>,
}

#[derive(Archive, Serialize, Deserialize)]
pub struct CategoryInfo {
	pub name: String,
	pub exact_start: u32,
	pub exact_len: u32,
	pub suffix_start: u32,
	pub suffix_len: u32,
	pub keyword_start: u32,
	pub keyword_len: u32,
}

#[derive(Archive, Serialize, Deserialize)]
pub struct GeoIpIndex {
	pub v4_entries: Vec<CidrV4>,
	pub v6_entries: Vec<CidrV6>,
}

#[derive(Archive, Serialize, Deserialize)]
pub struct CidrV4 {
	pub addr: u32,
	pub prefix: u8,
	pub country: String,
}

#[derive(Archive, Serialize, Deserialize)]
pub struct CidrV6 {
	pub addr: u128,
	pub prefix: u8,
	pub country: String,
}

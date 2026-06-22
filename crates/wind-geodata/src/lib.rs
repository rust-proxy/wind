use std::{fs::File, net::IpAddr, path::Path};

use memmap2::Mmap;

use crate::{builder::build_snapshot, snapshot::ArchivedGeoDataSnapshot};

pub mod builder;
mod error;
mod query;
pub mod snapshot;

pub use error::GeoDataError;

pub struct GeoData {
	#[allow(dead_code)]
	mmap: Mmap,
}

impl GeoData {
	pub fn open(cache_path: &Path) -> Result<Self, GeoDataError> {
		let file = File::open(cache_path)?;
		let mmap = unsafe { Mmap::map(&file)? };
		Ok(Self { mmap })
	}

	pub fn build_and_open(geosite_bytes: &[u8], geoip_bytes: &[u8], cache_path: &Path) -> Result<Self, GeoDataError> {
		let snapshot = build_snapshot(geosite_bytes, geoip_bytes)?;
		let buf = rkyv::api::high::to_bytes::<rkyv::rancor::Error>(&snapshot).map_err(|_| GeoDataError::Serialize)?;
		std::fs::write(cache_path, &buf)?;
		let file = File::open(cache_path)?;
		let mmap = unsafe { Mmap::map(&file)? };
		Ok(Self { mmap })
	}

	fn snapshot(&self) -> &ArchivedGeoDataSnapshot {
		unsafe { rkyv::access_unchecked(&self.mmap) }
	}

	pub fn geoip_lookup(&self) -> impl Fn(&str, IpAddr) -> bool + '_ {
		|country, ip| self.snapshot().geoip.contains(country, ip)
	}

	pub fn geosite_lookup(&self) -> impl Fn(&str, &str) -> bool + '_ {
		|category, domain| self.snapshot().geosite.contains(category, domain)
	}
}

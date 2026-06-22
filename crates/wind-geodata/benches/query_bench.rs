use std::{
	io::Read,
	net::IpAddr,
	path::{Path, PathBuf},
};

use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn testdata_dir() -> PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata")
}

fn ensure_testdata() {
	let dir = testdata_dir();
	let geoip = dir.join("geoip.dat");
	let geosite = dir.join("geosite.dat");

	if !geoip.exists() {
		eprintln!("downloading geoip.dat …");
		download(
			"https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202406202209/geoip.dat",
			&geoip,
		);
	}
	if !geosite.exists() {
		eprintln!("downloading geosite.dat …");
		download(
			"https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202406202209/geosite.dat",
			&geosite,
		);
	}
}

fn download(url: &str, dest: &Path) {
	let resp = ureq::get(url).call().expect("download failed");
	let mut body = Vec::new();
	resp.into_body().as_reader().read_to_end(&mut body).expect("read failed");
	std::fs::write(dest, &body).expect("write failed");
}

fn load_geo() -> wind_geodata::GeoData {
	let dir = testdata_dir();
	let cache = dir.join("geodata.rkyv");
	if cache.exists() {
		eprintln!("loading rkyv cache …");
		wind_geodata::GeoData::open(&cache).expect("open cache")
	} else {
		eprintln!("building from .dat …");
		let geosite = std::fs::read(dir.join("geosite.dat")).expect("read geosite.dat");
		let geoip = std::fs::read(dir.join("geoip.dat")).expect("read geoip.dat");
		wind_geodata::GeoData::build_and_open(&geosite, &geoip, &cache).expect("build")
	}
}

fn bench_build_from_dat(c: &mut Criterion) {
	ensure_testdata();
	let dir = testdata_dir();
	let geosite = std::fs::read(dir.join("geosite.dat")).unwrap();
	let geoip = std::fs::read(dir.join("geoip.dat")).unwrap();

	c.bench_function("build/from_dat", |b| {
		b.iter(|| wind_geodata::builder::build_snapshot(black_box(&geosite), black_box(&geoip)).unwrap())
	});
}

fn bench_mmap_open(c: &mut Criterion) {
	ensure_testdata();
	let dir = testdata_dir();
	let cache = dir.join("geodata.rkyv");
	if !cache.exists() {
		let geosite = std::fs::read(dir.join("geosite.dat")).unwrap();
		let geoip = std::fs::read(dir.join("geoip.dat")).unwrap();
		wind_geodata::GeoData::build_and_open(&geosite, &geoip, &cache).unwrap();
	}

	c.bench_function("mmap/open", |b| {
		b.iter(|| wind_geodata::GeoData::open(black_box(&cache)).unwrap())
	});
}

fn bench_geosite_exact(c: &mut Criterion) {
	ensure_testdata();
	let geo = load_geo();
	let lookup = geo.geosite_lookup();

	c.bench_function("geosite/exact/hit", |b| {
		b.iter(|| lookup(black_box("cn"), black_box("www.baidu.com")))
	});
	c.bench_function("geosite/exact/miss", |b| {
		b.iter(|| lookup(black_box("cn"), black_box("this-domain-does-not-exist.xyz")))
	});
}

fn bench_geosite_suffix(c: &mut Criterion) {
	ensure_testdata();
	let geo = load_geo();
	let lookup = geo.geosite_lookup();

	c.bench_function("geosite/suffix/hit", |b| {
		b.iter(|| lookup(black_box("google"), black_box("mail.google.com")))
	});
}

fn bench_geosite_keyword(c: &mut Criterion) {
	ensure_testdata();
	let geo = load_geo();
	let lookup = geo.geosite_lookup();

	c.bench_function("geosite/keyword/hit", |b| {
		b.iter(|| lookup(black_box("category-ads-all"), black_box("ads.example.com")))
	});
}

fn bench_geoip_v4(c: &mut Criterion) {
	ensure_testdata();
	let geo = load_geo();
	let lookup = geo.geoip_lookup();
	let _ip_cn: IpAddr = "223.5.5.5".parse().unwrap();
	let ip_us: IpAddr = "8.8.8.8".parse().unwrap();

	c.bench_function("geoip/v4/hit", |b| b.iter(|| lookup(black_box("US"), black_box(ip_us))));
	c.bench_function("geoip/v4/miss", |b| b.iter(|| lookup(black_box("XX"), black_box(ip_us))));
}

fn bench_geoip_v6(c: &mut Criterion) {
	ensure_testdata();
	let geo = load_geo();
	let lookup = geo.geoip_lookup();
	let ip: IpAddr = "2001:4860:4860::8888".parse().unwrap();

	c.bench_function("geoip/v6/hit", |b| b.iter(|| lookup(black_box("US"), black_box(ip))));
}

criterion_group!(
	benches,
	bench_build_from_dat,
	bench_mmap_open,
	bench_geosite_exact,
	bench_geosite_suffix,
	bench_geosite_keyword,
	bench_geoip_v4,
	bench_geoip_v6,
);
criterion_main!(benches);

//! Config parsing tests for the new multi-inbound/outbound config format.

use figment::{
	Figment,
	providers::{Format, Toml as TomlProvider},
};

#[test]
fn default_config_has_socks_inbound() {
	let cfg: wind::conf::persistent::PersistentConfig = wind::conf::persistent::PersistentConfig::default();

	assert_eq!(cfg.inbounds.len(), 1);
	assert_eq!(cfg.outbounds.len(), 1);

	let first = &cfg.inbounds[0];
	match first {
		wind::conf::persistent::InboundConfig::Socks(s) => {
			assert_eq!(s.tag, "socks-in");
			assert_eq!(s.listen_addr.to_string(), "127.0.0.1:6666");
		}
	}

	let out = &cfg.outbounds[0];
	match out {
		wind::conf::persistent::OutboundConfig::Tuic(t) => {
			assert_eq!(t.tag, "tuic-out");
		}
	}
}

#[test]
fn socks_inbound_parses() {
	let toml = r#"
[inbounds]
type = "socks"
tag = "my-socks"
listen_addr = "0.0.0.0:1080"
"#;

	// TOML inline table syntax for single-element array
	let full = format!(
		r#"
inbounds = [{{ type = "socks", tag = "my-socks", listen_addr = "0.0.0.0:1080" }}]

outbounds = [{{ type = "tuic", tag = "out", server_addr = "127.0.0.1:9443", uuid = "c1e6dbe2-f417-4890-994c-9ee15b926597", password = "pass" }}]
"#
	);

	let cfg: wind::conf::persistent::PersistentConfig = Figment::new().merge(TomlProvider::string(&full)).extract().unwrap();

	assert_eq!(cfg.inbounds.len(), 1);
	assert_eq!(cfg.outbounds.len(), 1);

	match &cfg.inbounds[0] {
		wind::conf::persistent::InboundConfig::Socks(s) => {
			assert_eq!(s.tag, "my-socks");
			assert_eq!(s.listen_addr.to_string(), "0.0.0.0:1080");
		}
	}
}

#[test]
fn yaml_format_parses() {
	let yaml = r#"
inbounds:
  - type: socks
    tag: socks-in
    listen_addr: "127.0.0.1:6666"
outbounds:
  - type: tuic
    tag: tuic-out
    server_addr: "127.0.0.1:9443"
    uuid: "c1e6dbe2-f417-4890-994c-9ee15b926597"
    password: "test_passwd"
"#;

	let cfg: wind::conf::persistent::PersistentConfig = Figment::new()
		.merge(figment::providers::Yaml::string(yaml))
		.extract()
		.unwrap();

	assert_eq!(cfg.inbounds.len(), 1);
	assert_eq!(cfg.outbounds.len(), 1);

	match &cfg.inbounds[0] {
		wind::conf::persistent::InboundConfig::Socks(s) => {
			assert_eq!(s.listen_addr.to_string(), "127.0.0.1:6666");
		}
	}
}

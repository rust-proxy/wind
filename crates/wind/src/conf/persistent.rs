use std::{
	net::{Ipv4Addr, SocketAddr},
	path::PathBuf,
	time::Duration,
};

use educe::Educe;
use figment::{
	Figment,
	providers::{Env, Format, Toml, Yaml},
};
use serde::{Deserialize, Serialize};
use wind_core::types::TargetAddr;
use wind_socks::inbound::AuthMode;

#[derive(Debug, Deserialize, Serialize, Educe)]
#[educe(Default)]
pub struct PersistentConfig {
	pub socks_opt: SocksOpt,
	pub tuic_opt: TuicOpt,
}

#[derive(Debug, Deserialize, Serialize, Educe)]
#[educe(Default)]
pub struct SocksOpt {
	#[educe(Default(expression = "127.0.0.1:6666".parse().unwrap()))]
	pub listen_addr: SocketAddr,

	#[educe(Default = None)]
	pub public_addr: Option<std::net::IpAddr>,

	#[educe(Default = AuthModeConfig::NoAuth)]
	pub auth: AuthModeConfig,

	#[educe(Default = false)]
	pub skip_auth: bool,

	#[educe(Default = true)]
	pub allow_udp: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Educe)]
#[educe(Default)]
pub enum AuthModeConfig {
	#[educe(Default)]
	NoAuth,
	Password {
		username: String,
		password: String,
	},
}

impl From<AuthModeConfig> for AuthMode {
	fn from(config: AuthModeConfig) -> Self {
		match config {
			AuthModeConfig::NoAuth => AuthMode::NoAuth,
			AuthModeConfig::Password { username, password } => AuthMode::Password { username, password },
		}
	}
}

#[derive(Debug, Deserialize, Serialize, Educe)]
#[educe(Default)]
pub struct TuicOpt {
	#[educe(Default = TargetAddr::IPv4(Ipv4Addr::new(127, 0, 0, 1), 9443))]
	pub server_addr: TargetAddr,

	#[educe(Default = "localhost")]
	pub sni: String,

	#[educe(Default = "c1e6dbe2-f417-4890-994c-9ee15b926597".parse().unwrap())]
	pub uuid: uuid::Uuid,

	#[educe(Default = "test_passwd")]
	pub password: String,

	#[educe(Default = false)]
	pub zero_rtt_handshake: bool,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(10)))]
	pub heartbeat: Duration,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(20)))]
	pub gc_interval: Duration,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(20)))]
	pub gc_lifetime: Duration,

	#[educe(Default = true)]
	pub skip_cert_verify: bool,

	#[educe(Default(expression = vec![String::from("h3")]))]
	pub alpn: Vec<String>,
}

impl PersistentConfig {
	pub fn export_to_file(&self, file_path: &PathBuf, format: &str) -> eyre::Result<()> {
		use std::{fs, io::Write};

		match format.to_lowercase().as_str() {
			"yaml" => {
				let yaml_content = serde_yaml::to_string(&self)?;
				let mut file = fs::File::create(file_path)?;
				file.write_all(yaml_content.as_bytes())?;
			}
			"toml" => {
				let toml_content = toml::to_string_pretty(&self)?;
				let mut file = fs::File::create(file_path)?;
				file.write_all(toml_content.as_bytes())?;
			}
			_ => return Err(eyre::eyre!("Unsupported file format: {}", format)),
		}

		Ok(())
	}

	pub fn load(config_path: Option<String>, config_dir: Option<PathBuf>) -> eyre::Result<Self> {
		// Start with empty figment (will use default values via serde)
		let mut figment = Figment::new();

		// Load from default configuration location
		if let Some(config_dir) = config_dir {
			let config_file = config_dir.join("config.toml");
			if config_file.exists() {
				figment = figment.merge(Toml::file(config_file));
			}

			let config_file = config_dir.join("config.yaml");
			if config_file.exists() {
				figment = figment.merge(Yaml::file(config_file));
			}
		} else {
			// Try to load from default locations in current directory
			let config_toml = std::path::Path::new("config.toml");
			if config_toml.exists() {
				figment = figment.merge(Toml::file(config_toml));
			}

			let config_yaml = std::path::Path::new("config.yaml");
			if config_yaml.exists() {
				figment = figment.merge(Yaml::file(config_yaml));
			}
		}

		// If specific config path is provided, use that
		if let Some(config_path) = config_path {
			if config_path.ends_with(".toml") {
				figment = figment.merge(Toml::file(config_path));
			} else if config_path.ends_with(".yaml") || config_path.ends_with(".yml") {
				figment = figment.merge(Yaml::file(config_path));
			} else {
				// Assume it's TOML format
				figment = figment.merge(Toml::file(config_path));
			}
		}

		// Environment variables can override config files
		figment = figment.merge(Env::prefixed("WIND_"));

		// Extract the configuration
		let config: PersistentConfig = figment.extract()?;

		Ok(config)
	}
}

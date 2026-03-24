use wind_socks::inbound::SocksInboundOpt;
use wind_tuic::outbound::TuicOutboundOpts;

use crate::{conf::persistent::PersistentConfig, util::target_addr_to_socket_addr};

pub struct Config {
	pub socks_opt: SocksInboundOpt,
	pub tuic_opt: TuicOutboundOpts,
}
impl Config {
	pub fn from_persist(config: PersistentConfig) -> Self {
		Self {
			socks_opt: SocksInboundOpt {
				listen_addr: config.socks_opt.listen_addr,
				public_addr: config.socks_opt.public_addr,
				auth: config.socks_opt.auth.into(),
				skip_auth: config.socks_opt.skip_auth,
				allow_udp: config.socks_opt.allow_udp,
			},
			tuic_opt: TuicOutboundOpts {
				peer_addr: target_addr_to_socket_addr(&config.tuic_opt.server_addr),
				sni: config.tuic_opt.sni.clone(),
				auth: (config.tuic_opt.uuid, config.tuic_opt.password.as_bytes().to_vec().into()),
				zero_rtt_handshake: config.tuic_opt.zero_rtt_handshake,
				heartbeat: config.tuic_opt.heartbeat,
				gc_interval: config.tuic_opt.gc_interval,
				gc_lifetime: config.tuic_opt.gc_lifetime,
				skip_cert_verify: config.tuic_opt.skip_cert_verify,
				alpn: config.tuic_opt.alpn.clone(),
			},
		}
	}
}

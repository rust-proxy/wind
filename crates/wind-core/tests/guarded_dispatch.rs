use std::{
	future::Future,
	net::{IpAddr, SocketAddr},
	pin::Pin,
	sync::{
		Arc, Mutex,
		atomic::{AtomicUsize, Ordering},
	},
	time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::{Notify, mpsc};
use wind_acl::{AclEngine, GuardConfig};
use wind_core::{
	AppContext, Dispatcher, FlowContext, InboundCallback, Outbound, RouteAction, Router,
	hooks::{Protocol, UserId},
	resolve::{Resolver, resolve_target_with_preference},
	rule::{InboundType, NetworkType},
	tcp::AbstractTcpStream,
	types::TargetAddr,
	udp::{UdpPacket, UdpStream},
	utils::StackPrefer,
};

fn flow(target: TargetAddr, network: NetworkType) -> FlowContext {
	FlowContext {
		target,
		network,
		source: Some("198.51.100.2:12345".parse().unwrap()),
		inbound_tag: Arc::from("guard-test"),
		protocol: Protocol::Socks5,
		user: Some(UserId::from("guard-user")),
		inbound_port: Some(1080),
		inbound_type: Some(InboundType::Socks),
	}
}

fn target(addr: &str, port: u16) -> TargetAddr {
	SocketAddr::new(addr.parse().unwrap(), port).into()
}

/// A second lookup or an outbound IP-family override selects a local address.
struct ChangingResolver {
	first: IpAddr,
	rebind_calls: AtomicUsize,
	all_calls: AtomicUsize,
}

impl ChangingResolver {
	fn new(first: &str) -> Self {
		Self {
			first: first.parse().unwrap(),
			rebind_calls: AtomicUsize::new(0),
			all_calls: AtomicUsize::new(0),
		}
	}
}

impl Resolver for ChangingResolver {
	fn resolve<'a>(&'a self, host: &'a str) -> Pin<Box<dyn Future<Output = eyre::Result<IpAddr>> + Send + 'a>> {
		Box::pin(async move {
			match host {
				"rebind.example" => Ok(if self.rebind_calls.fetch_add(1, Ordering::SeqCst) == 0 {
					self.first
				} else {
					"127.0.0.1".parse().unwrap()
				}),
				"other.example" => Ok("2001:db8::1".parse().unwrap()),
				"private.example" => Ok("::ffff:10.0.0.1".parse().unwrap()),
				_ => eyre::bail!("synthetic DNS failure"),
			}
		})
	}

	fn resolve_all<'a>(&'a self, _host: &'a str) -> Pin<Box<dyn Future<Output = eyre::Result<Vec<IpAddr>>> + Send + 'a>> {
		Box::pin(async move {
			self.all_calls.fetch_add(1, Ordering::SeqCst);
			Ok(vec!["::1".parse().unwrap(), "10.0.0.1".parse().unwrap()])
		})
	}
}

fn engine(resolver: Arc<ChangingResolver>, enabled: bool) -> AclEngine {
	AclEngine::builder("default")
		.clash_rules(["DOMAIN,rebind.example,guarded", "DOMAIN,other.example,other"])
		.unwrap()
		.guards(GuardConfig {
			drop_loopback: enabled,
			drop_private: enabled,
		})
		.resolver(resolver)
		.build()
		.unwrap()
}

#[derive(Default)]
struct Observations {
	context: Option<TargetAddr>,
	packets: Vec<(TargetAddr, SocketAddr, Bytes)>,
}

/// Exercise the same resolver entry point as DirectOutbound, including its
/// per-outbound IP-family override, without contacting public destinations.
struct ResolvingOutbound {
	resolver: Arc<ChangingResolver>,
	seen: Mutex<Observations>,
}

impl ResolvingOutbound {
	fn new(resolver: Arc<ChangingResolver>) -> Self {
		Self {
			resolver,
			seen: Mutex::new(Observations::default()),
		}
	}

	fn check_metadata(ctx: &FlowContext, network: NetworkType) {
		assert_eq!(ctx.network, network);
		assert_eq!(ctx.source, Some("198.51.100.2:12345".parse().unwrap()));
		assert_eq!(ctx.inbound_tag.as_ref(), "guard-test");
		assert_eq!(ctx.protocol, Protocol::Socks5);
		assert_eq!(ctx.user, Some(UserId::from("guard-user")));
		assert_eq!(ctx.inbound_port, Some(1080));
		assert_eq!(ctx.inbound_type, Some(InboundType::Socks));
	}
}

#[async_trait]
impl Outbound for ResolvingOutbound {
	async fn handle_tcp(&self, ctx: FlowContext, _stream: Box<dyn AbstractTcpStream + 'static>) -> eyre::Result<()> {
		Self::check_metadata(&ctx, NetworkType::Tcp);
		let addr = resolve_target_with_preference(&ctx.target, self.resolver.as_ref(), Some(StackPrefer::V6first)).await?;
		let mut seen = self.seen.lock().unwrap();
		seen.context = Some(ctx.target.clone());
		seen.packets.push((ctx.target, addr, Bytes::new()));
		Ok(())
	}

	async fn handle_udp(&self, ctx: FlowContext, mut stream: UdpStream) -> eyre::Result<()> {
		Self::check_metadata(&ctx, NetworkType::Udp);
		self.seen.lock().unwrap().context = Some(ctx.target);
		while let Some(packet) = stream.rx.recv().await {
			let addr =
				resolve_target_with_preference(&packet.target, self.resolver.as_ref(), Some(StackPrefer::V6first)).await?;
			self.seen.lock().unwrap().packets.push((packet.target, addr, packet.payload));
		}
		Ok(())
	}
}

#[tokio::test]
async fn guarded_tcp_pins_checked_ip_and_matches_original_domain() {
	for public in ["203.0.113.1", "2001:db8::1"] {
		let resolver = Arc::new(ChangingResolver::new(public));
		let handler = Arc::new(ResolvingOutbound::new(resolver.clone()));
		let mut dispatcher = Dispatcher::new(engine(resolver.clone(), true));
		dispatcher.add_handler("guarded", handler.clone());
		let (stream, _peer) = tokio::io::duplex(64);
		dispatcher
			.handle_tcpstream(
				flow(TargetAddr::Domain("rebind.example".into(), 443), NetworkType::Tcp),
				stream,
			)
			.await
			.unwrap();

		let seen = handler.seen.lock().unwrap();
		assert_eq!(seen.context, Some(target(public, 443)));
		assert_eq!(seen.packets[0].1, SocketAddr::new(public.parse().unwrap(), 443));
		assert_eq!(
			resolver.rebind_calls.load(Ordering::SeqCst),
			1,
			"the checked target must never be resolved again"
		);
		assert_eq!(
			resolver.all_calls.load(Ordering::SeqCst),
			0,
			"outbound preference must not change the checked address"
		);
	}
}

#[tokio::test]
async fn disabled_guards_preserve_domain_and_outbound_resolution() {
	let resolver = Arc::new(ChangingResolver::new("203.0.113.1"));
	let handler = Arc::new(ResolvingOutbound::new(resolver.clone()));
	let mut dispatcher = Dispatcher::new(engine(resolver.clone(), false));
	dispatcher.add_handler("guarded", handler.clone());
	let domain = TargetAddr::Domain("rebind.example".into(), 443);
	let (stream, _peer) = tokio::io::duplex(64);
	dispatcher
		.handle_tcpstream(flow(domain.clone(), NetworkType::Tcp), stream)
		.await
		.unwrap();
	assert_eq!(handler.seen.lock().unwrap().context, Some(domain));
	assert_eq!(
		resolver.rebind_calls.load(Ordering::SeqCst),
		0,
		"disabled guards must not look up the domain"
	);
	assert_eq!(resolver.all_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn disabled_guards_preserve_udp_domains_for_every_packet() {
	let resolver = Arc::new(ChangingResolver::new("203.0.113.1"));
	let handler = Arc::new(ResolvingOutbound::new(resolver.clone()));
	let mut dispatcher = Dispatcher::new(engine(resolver.clone(), false));
	dispatcher.add_handler("guarded", handler.clone());
	let first = TargetAddr::Domain("rebind.example".into(), 53);
	let later = TargetAddr::Domain("other.example".into(), 5353);
	let (tx, _rx) = mpsc::channel(1);
	let (input, rx) = mpsc::channel(2);
	for target in [first.clone(), later.clone()] {
		input
			.send(UdpPacket {
				source: None,
				target,
				payload: Bytes::new(),
			})
			.await
			.unwrap();
	}
	drop(input);
	dispatcher
		.handle_udpstream(flow(first.clone(), NetworkType::Udp), UdpStream { tx, rx })
		.await
		.unwrap();
	let seen = handler.seen.lock().unwrap();
	assert_eq!(seen.context, Some(first.clone()));
	assert_eq!(
		seen.packets.iter().map(|packet| packet.0.clone()).collect::<Vec<_>>(),
		vec![first, later]
	);
	assert_eq!(resolver.rebind_calls.load(Ordering::SeqCst), 0);
	assert_eq!(resolver.all_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn guarded_dispatch_rejects_resolved_local_and_private_targets_before_outbound() {
	for ip in [
		"127.0.0.1",
		"::1",
		"::ffff:127.0.0.1",
		"0.0.0.0",
		"10.0.0.1",
		"::ffff:10.0.0.1",
		"fe80::1",
	] {
		let resolver = Arc::new(ChangingResolver::new(ip));
		let handler = Arc::new(ResolvingOutbound::new(resolver.clone()));
		let mut dispatcher = Dispatcher::new(engine(resolver, true));
		dispatcher.add_handler("guarded", handler.clone());
		let domain = TargetAddr::Domain("rebind.example".into(), 53);
		let (stream, _peer) = tokio::io::duplex(64);
		assert!(
			dispatcher
				.handle_tcpstream(flow(domain.clone(), NetworkType::Tcp), stream)
				.await
				.is_err()
		);

		let (tx, _rx) = mpsc::channel(1);
		let (input, rx) = mpsc::channel(1);
		input
			.send(UdpPacket {
				source: None,
				target: domain.clone(),
				payload: Bytes::new(),
			})
			.await
			.unwrap();
		drop(input);
		assert!(
			dispatcher
				.handle_udpstream(flow(domain, NetworkType::Udp), UdpStream { tx, rx })
				.await
				.is_err()
		);
		assert!(
			handler.seen.lock().unwrap().context.is_none(),
			"{ip} must never reach an outbound"
		);
	}
}

#[tokio::test]
async fn guarded_udp_checks_every_target_and_keeps_first_outbound() {
	let resolver = Arc::new(ChangingResolver::new("203.0.113.1"));
	let handler = Arc::new(ResolvingOutbound::new(resolver.clone()));
	let other = Arc::new(ResolvingOutbound::new(resolver.clone()));
	let mut dispatcher = Dispatcher::new(engine(resolver.clone(), true));
	dispatcher.add_handler("guarded", handler.clone());
	dispatcher.add_handler("other", other.clone());
	let domain = TargetAddr::Domain("rebind.example".into(), 53);
	let (tx, _rx) = mpsc::channel(1);
	let (input, rx) = mpsc::channel(16);
	let targets = [
		domain.clone(),
		domain.clone(), // DNS has rebound to loopback.
		target("127.0.0.1", 53),
		target("10.0.0.1", 53),
		TargetAddr::Domain("private.example".into(), 53),
		TargetAddr::Domain("fail.example".into(), 53),
		TargetAddr::Domain("other.example".into(), 5353),
	];
	for (index, target) in targets.into_iter().enumerate() {
		input
			.send(UdpPacket {
				source: None,
				target,
				payload: Bytes::from(vec![index as u8]),
			})
			.await
			.unwrap();
	}
	drop(input);
	tokio::time::timeout(
		Duration::from_secs(5),
		dispatcher.handle_udpstream(flow(domain, NetworkType::Udp), UdpStream { tx, rx }),
	)
	.await
	.unwrap()
	.unwrap();
	let seen = handler.seen.lock().unwrap();
	assert_eq!(seen.context, Some(target("203.0.113.1", 53)));
	assert_eq!(
		seen.packets.len(),
		2,
		"rejected or unresolved subsequent destinations must be dropped"
	);
	assert_eq!(seen.packets[0].0, target("203.0.113.1", 53));
	assert_eq!(seen.packets[0].2.as_ref(), &[0]);
	assert_eq!(seen.packets[1].0, target("2001:db8::1", 5353));
	assert_eq!(seen.packets[1].2.as_ref(), &[6]);
	assert!(
		other.seen.lock().unwrap().context.is_none(),
		"later packets must keep the first outbound"
	);
	assert_eq!(resolver.rebind_calls.load(Ordering::SeqCst), 2);
	assert_eq!(resolver.all_calls.load(Ordering::SeqCst), 0);
}

struct PendingTargetRouter {
	started: Arc<Notify>,
}

impl Router for PendingTargetRouter {
	async fn route(&self, _ctx: &FlowContext) -> eyre::Result<RouteAction> {
		Ok(RouteAction::Forward("default".into()))
	}

	async fn prepare_udp_target(&self, _ctx: &FlowContext) -> eyre::Result<TargetAddr> {
		self.started.notify_one();
		std::future::pending().await
	}
}

struct CloseAfterLookupStarted {
	started: Arc<Notify>,
}

#[async_trait]
impl Outbound for CloseAfterLookupStarted {
	async fn handle_tcp(&self, _ctx: FlowContext, _stream: Box<dyn AbstractTcpStream + 'static>) -> eyre::Result<()> {
		Ok(())
	}

	async fn handle_udp(&self, _ctx: FlowContext, mut stream: UdpStream) -> eyre::Result<()> {
		assert!(stream.rx.recv().await.is_some());
		self.started.notified().await;
		Ok(())
	}
}

#[tokio::test]
async fn udp_target_lookup_is_cancelled_when_outbound_closes() {
	let context = Arc::new(AppContext::default());
	let started = Arc::new(Notify::new());
	let mut dispatcher = Dispatcher::new(PendingTargetRouter {
		started: started.clone(),
	})
	.context(context.clone());
	dispatcher.add_handler("default", Arc::new(CloseAfterLookupStarted { started }));
	let (tx, _rx) = mpsc::channel(1);
	let (input, rx) = mpsc::channel(2);
	for _ in 0..2 {
		input
			.send(UdpPacket {
				source: None,
				target: target("203.0.113.1", 53),
				payload: Bytes::new(),
			})
			.await
			.unwrap();
	}
	tokio::time::timeout(
		Duration::from_secs(5),
		dispatcher.handle_udpstream(flow(target("0.0.0.0", 0), NetworkType::Udp), UdpStream { tx, rx }),
	)
	.await
	.unwrap()
	.unwrap();
	context.tasks.close();
	tokio::time::timeout(Duration::from_secs(5), context.tasks.wait())
		.await
		.unwrap();
	assert!(
		context.tasks.is_empty(),
		"a pending target lookup must not hold up task drain after outbound exit"
	);
	drop(input);
}

#[tokio::test]
async fn udp_target_lookup_is_cancelled_on_application_shutdown() {
	let context = Arc::new(AppContext::default());
	let started = Arc::new(Notify::new());
	let mut dispatcher = Dispatcher::new(PendingTargetRouter {
		started: started.clone(),
	})
	.context(context.clone());
	let handler = Arc::new(ResolvingOutbound::new(Arc::new(ChangingResolver::new("203.0.113.1"))));
	dispatcher.add_handler("default", handler);
	let (tx, _rx) = mpsc::channel(1);
	let (input, rx) = mpsc::channel(2);
	for _ in 0..2 {
		input
			.send(UdpPacket {
				source: None,
				target: target("203.0.113.1", 53),
				payload: Bytes::new(),
			})
			.await
			.unwrap();
	}
	let dispatch = tokio::spawn(async move {
		dispatcher
			.handle_udpstream(flow(target("0.0.0.0", 0), NetworkType::Udp), UdpStream { tx, rx })
			.await
	});
	tokio::time::timeout(Duration::from_secs(5), started.notified())
		.await
		.unwrap();
	context.token.cancel();
	context.tasks.close();
	tokio::time::timeout(Duration::from_secs(5), context.tasks.wait())
		.await
		.unwrap();
	tokio::time::timeout(Duration::from_secs(5), dispatch)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
	drop(input);
}

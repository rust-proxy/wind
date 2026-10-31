use fast_socks5::server::Socks5ServerProtocol;
use tokio::{net::TcpListener, sync::mpsc, task::JoinHandle};

use super::*;

const LIMIT: Duration = Duration::from_secs(3);

fn opts(addr: SocketAddr) -> SocksOutboundOpts {
	SocksOutboundOpts {
		addr: addr.to_string(),
		username: None,
		password: None,
		allow_udp: Some(true),
		stream_timeout: Duration::ZERO,
		tcp_keepalive: None,
	}
}

struct Case {
	send: mpsc::Sender<UdpPacket>,
	replies: mpsc::Receiver<UdpPacket>,
	proxy: UdpSocket,
	peer: SocketAddr,
	_control: TcpStream,
	task: JoinHandle<eyre::Result<()>>,
}

impl Drop for Case {
	fn drop(&mut self) {
		self.task.abort();
	}
}

async fn case(hint: usize) -> eyre::Result<Case> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let control = TcpStream::connect(listener.local_addr()?).await?;
	let (peer_control, _) = listener.accept().await?;
	let proxy = UdpSocket::bind("127.0.0.1:0").await?;
	let udp = UdpSocket::bind("127.0.0.1:0").await?;
	// Darwin's default UDP send buffer is smaller than the 65 KB fixture.
	// Reserve room on both sockets without reducing the whole-datagram check.
	for socket in [&proxy, &udp] {
		let socket = socket2::SockRef::from(socket);
		socket.set_send_buffer_size(BUFFER_SIZE * 2)?;
		socket.set_recv_buffer_size(BUFFER_SIZE * 2)?;
	}
	udp.connect(proxy.local_addr()?).await?;
	let peer = udp.local_addr()?;
	let (send, rx) = mpsc::channel(8);
	let (tx, replies) = mpsc::channel(8);
	let task = tokio::spawn(async move { relay(&mut Association { control, udp }, &mut UdpStream { tx, rx }, hint).await });
	Ok(Case {
		send,
		replies,
		proxy,
		peer,
		_control: peer_control,
		task,
	})
}

async fn request(case: &Case, target: TargetAddr, payload: &[u8]) -> eyre::Result<()> {
	case.send
		.send(UdpPacket {
			source: None,
			target: target.clone(),
			payload: Bytes::copy_from_slice(payload),
		})
		.await?;
	let mut buffer = vec![0; BUFFER_SIZE];
	let (size, _) = tokio::time::timeout(LIMIT, case.proxy.recv_from(&mut buffer)).await??;
	let (frag, received, data) = fast_socks5::parse_udp_request(&buffer[..size]).await?;
	assert_eq!(frag, 0);
	assert_eq!(convert_addr(&received), target);
	assert_eq!(data, payload);
	Ok(())
}

#[tokio::test]
async fn malformed_fragmented_wrong_target_and_wrong_source_replies_are_dropped() -> eyre::Result<()> {
	let mut case = case(0).await?;
	let target: SocketAddr = "127.0.0.1:443".parse()?;
	request(&case, target.into(), b"request").await?;
	let mut valid = fast_socks5::new_udp_header(target)?;
	valid.extend_from_slice(b"valid");
	let mut reserved = valid.clone();
	reserved[0] = 1;
	let mut fragmented = valid.clone();
	fragmented[2] = 1;
	let wrong = fast_socks5::new_udp_header(("127.0.0.1", 444))?;
	let domain = fast_socks5::new_udp_header(("localhost", 443))?;
	for packet in [vec![], vec![0], vec![0, 0, 0, 1], reserved, fragmented, wrong, domain] {
		case.proxy.send_to(&packet, case.peer).await?;
	}
	let attacker = UdpSocket::bind("127.0.0.1:0").await?;
	attacker.send_to(&valid, case.peer).await?;
	assert!(
		tokio::time::timeout(Duration::from_millis(50), case.replies.recv())
			.await
			.is_err()
	);
	case.proxy.send_to(&valid, case.peer).await?;
	let reply = tokio::time::timeout(LIMIT, case.replies.recv())
		.await?
		.ok_or_else(|| eyre::eyre!("missing reply"))?;
	assert_eq!(reply.payload.as_ref(), b"valid");
	assert_eq!(reply.source, Some(target.into()));
	Ok(())
}

#[tokio::test]
async fn domains_ipv6_and_extreme_buffer_hints_preserve_whole_datagrams() -> eyre::Result<()> {
	for hint in [0, 1, usize::MAX] {
		let mut case = case(hint).await?;
		for target in [
			TargetAddr::Domain("only-proxy-knows.invalid".into(), 443),
			"[::1]:443".parse::<SocketAddr>()?.into(),
		] {
			let payload = vec![0xa5; 65000];
			request(&case, target, &payload).await?;
			// Domain requests legitimately receive an IP-literal response.
			let mut packet = fast_socks5::new_udp_header("[::1]:443".parse::<SocketAddr>()?)?;
			packet.extend_from_slice(&payload);
			case.proxy.send_to(&packet, case.peer).await?;
			let reply = tokio::time::timeout(LIMIT, case.replies.recv())
				.await?
				.ok_or_else(|| eyre::eyre!("missing reply"))?;
			assert_eq!(reply.payload.as_ref(), payload);
		}
	}
	Ok(())
}

async fn proxy_session(port_zero: bool) -> eyre::Result<(SocksOutboundOpts, JoinHandle<eyre::Result<(TcpStream, UdpSocket)>>)> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let addr = listener.local_addr()?;
	let task = tokio::spawn(async move {
		let (stream, _) = listener.accept().await?;
		let proto = Socks5ServerProtocol::accept_no_auth(stream).await?;
		let (proto, command, _) = proto.read_command().await?;
		assert_eq!(command, Socks5Command::UDPAssociate);
		let udp = UdpSocket::bind("127.0.0.1:0").await?;
		let reply = SocketAddr::from(([0, 0, 0, 0], if port_zero { 0 } else { udp.local_addr()?.port() }));
		let stream = proto.reply_success(reply).await?;
		Ok((stream, udp))
	});
	Ok((opts(addr), task))
}

#[tokio::test]
async fn unspecified_relay_uses_control_peer_and_zero_port_is_rejected() -> eyre::Result<()> {
	let (opts, task) = proxy_session(false).await?;
	let association = associate(&opts, &SocksUdpOptions::default()).await?;
	let (_control, udp) = tokio::time::timeout(LIMIT, task).await???;
	assert_eq!(association.udp.peer_addr()?, udp.local_addr()?);
	let (opts, task) = proxy_session(true).await?;
	assert!(associate(&opts, &SocksUdpOptions::default()).await.is_err());
	let _ = tokio::time::timeout(LIMIT, task).await???;
	Ok(())
}

#[tokio::test]
async fn setup_is_bounded_and_cancellable() -> eyre::Result<()> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let options = opts(listener.local_addr()?);
	let udp = SocksUdpOptions {
		timeout: Duration::from_millis(50),
		..Default::default()
	};
	assert!(
		associate(&options, &udp)
			.await
			.err()
			.is_some_and(|e| e.to_string().contains("timed out"))
	);
	let token = CancellationToken::new();
	let (tx, _replies) = mpsc::channel(1);
	let (_requests, rx) = mpsc::channel(1);
	let cancellation = async {
		tokio::task::yield_now().await;
		token.cancel();
	};
	let udp = SocksUdpOptions::default();
	let (result, ()) = tokio::join!(run(&options, &udp, &token, UdpStream { tx, rx }), cancellation);
	result?;
	Ok(())
}

#[tokio::test]
async fn invalid_credentials_fail_before_connecting() -> eyre::Result<()> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	for (username, password) in [
		(Some("u".into()), None),
		(None, Some("p".into())),
		(Some("".into()), Some("p".into())),
		(Some("u".repeat(256)), Some("p".into())),
	] {
		let mut options = opts(listener.local_addr()?);
		options.username = username;
		options.password = password;
		assert!(Association::connect(&options).await.is_err());
	}
	assert!(
		tokio::time::timeout(Duration::from_millis(50), listener.accept())
			.await
			.is_err()
	);
	Ok(())
}

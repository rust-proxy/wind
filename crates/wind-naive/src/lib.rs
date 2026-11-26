//! Naive outbound using `cronet-rs` (Cronet-based CONNECT proxy).
//!
//! This crate provides [`NaiveOutbound`], an implementation of
//! [`wind_core::Outbound`] that tunnels TCP (and UDP-over-TCP) through
//! a NaiveProxy server via the Cronet HTTP/2 or QUIC CONNECT protocol with
//! padding.

use std::{
	io::{Read, Write},
	sync::{
		Arc,
		atomic::{AtomicUsize, Ordering},
	},
	thread::JoinHandle,
};

use async_trait::async_trait;
use cronet_rs::{
	naive_client::{NaiveClient, NaiveClientConfig, QuicCongestionControl as CronetCongestionControl},
	naive_conn::NaiveConn,
};
use eyre::Context as _;
use tokio::{
	io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
	sync::{mpsc, oneshot},
};
use tokio_util::task::AbortOnDropHandle;
use tracing::info;
use wind_core::{
	FlowContext, Outbound, QuicCongestionControl,
	tcp::AbstractTcpStream,
	udp::{UdpPacket, UdpStream},
};

mod socket_policy;
mod uot;
pub use socket_policy::{SocketInterface, SocketPolicy};

/// Map the transport-agnostic [`QuicCongestionControl`] onto the `cronet-rs`
/// representation expected by the underlying engine.
fn to_cronet(cc: QuicCongestionControl) -> CronetCongestionControl {
	match cc {
		QuicCongestionControl::Default => CronetCongestionControl::Default,
		QuicCongestionControl::Bbr => CronetCongestionControl::Bbr,
		QuicCongestionControl::BbrV2 => CronetCongestionControl::BbrV2,
		QuicCongestionControl::Cubic => CronetCongestionControl::Cubic,
		QuicCongestionControl::Reno => CronetCongestionControl::Reno,
	}
}

/// Configuration for the Naive outbound.
#[derive(Clone, Debug)]
pub struct NaiveOutboundOpts {
	/// NaiveProxy server address (host:port).
	pub server_address: String,

	/// Server name (SNI), defaults to server_address's host.
	pub server_name: Option<String>,

	/// Username for proxy authentication.
	pub username: Option<String>,

	/// Password for proxy authentication.
	pub password: Option<String>,

	/// Number of concurrent connections to the Cronet engine.
	/// 1 = single connection (default).
	pub concurrency: u32,

	/// Enable QUIC.
	pub quic_enabled: bool,

	/// QUIC congestion control algorithm.
	pub quic_congestion_control: QuicCongestionControl,

	/// PEM-encoded trusted root certificates.
	/// If `None`, the platform trust store is used.
	pub trusted_root_certificates: Option<String>,

	/// Enable ECH (Encrypted Client Hello).
	pub ech_enabled: bool,

	/// Extra headers to include in every CONNECT request.
	pub extra_headers: std::collections::HashMap<String, String>,

	/// Path to a `libcronet` shared library (`libcronet.so`, `cronet.dll`, or
	/// `libcronet.dylib`).
	///
	/// If `None`, the loader tries:
	///   - Unix: `libcronet.{so,dylib}` from `LD_LIBRARY_PATH` /
	///     `DYLD_LIBRARY_PATH` or the system default, `./libcronet.{so,dylib}`,
	///     then `/usr/local/lib` and `/opt/cronet`;
	///   - Windows: `libcronet.dll` and `cronet.dll` in the directory
	///     containing the running executable. The current directory and `PATH`
	///     are not searched implicitly.
	pub cronet_lib_path: Option<String>,

	/// `HostResolverRules` override for the proxy server, e.g.
	/// `MAP proxy.example.com 203.0.113.7`. Pins the dial address while
	/// `server_name` keeps driving SNI and certificate verification.
	pub host_resolver_rules: Option<String>,
}

impl Default for NaiveOutboundOpts {
	fn default() -> Self {
		Self {
			server_address: String::new(),
			server_name: None,
			username: None,
			password: None,
			concurrency: 1,
			quic_enabled: false,
			quic_congestion_control: QuicCongestionControl::Default,
			trusted_root_certificates: None,
			ech_enabled: false,
			extra_headers: std::collections::HashMap::new(),
			cronet_lib_path: None,
			host_resolver_rules: None,
		}
	}
}

/// An outbound that tunnels traffic through a NaiveProxy server via Cronet.
///
/// Uses `cronet-rs` (Chromium Cronet C API bindings) to establish HTTP/2
/// or QUIC CONNECT tunnels with NaiveProxy padding protocol.
///
/// The Cronet engine is shared across all connections (`RwLock` read-locked
/// only during dial), so concurrent tunnels are not serialized.
pub struct NaiveOutbound {
	/// Shared Cronet engine behind a read-write lock.
	///
	/// `dial()` takes `&self`, so concurrent dials acquire a **read** lock and
	/// run in parallel.  The write lock is only held during `start()`.
	client: Arc<tokio::sync::RwLock<NaiveClient>>,
}

/// Extract the host from a `host:port` authority, handling bracketed IPv6.
///
/// `[2001:db8::1]:443` -> `2001:db8::1`, `example.com:443` -> `example.com`,
/// `1.2.3.4:443` -> `1.2.3.4`, `example.com` -> `example.com`. A naive
/// `split(':').next()` would return `[2001` for the IPv6 case, producing a
/// bogus SNI.
fn host_from_authority(authority: &str) -> &str {
	if let Some(rest) = authority.strip_prefix('[') {
		// Bracketed IPv6: the host is everything up to the closing bracket.
		if let Some(end) = rest.find(']') {
			return &rest[..end];
		}
	}
	// Otherwise strip a trailing `:port` (the last colon); no colon means the
	// whole string is the host.
	authority.rsplit_once(':').map_or(authority, |(host, _)| host)
}

impl NaiveOutbound {
	/// Create and start a new `NaiveOutbound`.
	///
	/// This spawns the Cronet engine (a blocking FFI operation) in a
	/// background blocking thread so the async caller is not stalled.
	///
	/// `cronet_lib_path` controls how `libcronet` is loaded — see
	/// [`NaiveOutboundOpts::cronet_lib_path`].
	pub async fn new(opts: NaiveOutboundOpts) -> eyre::Result<Self> {
		Self::new_inner(opts, NaiveClient::start).await
	}

	/// Create an engine whose physical TCP and QUIC sockets use this routing
	/// policy.
	///
	/// Linux applies the interface name with `SO_BINDTODEVICE` and the mark
	/// with `SO_MARK`. macOS/iOS bind by interface index with `IP_BOUND_IF` /
	/// `IPV6_BOUND_IF`; Windows uses `IP_UNICAST_IF` / `IPV6_UNICAST_IF`.
	/// Other platforms reject a policy instead of silently dialing unbound.
	pub async fn new_with_socket_policy(
		opts: NaiveOutboundOpts,
		policy: SocketPolicy,
		connect_timeout: std::time::Duration,
	) -> eyre::Result<Self> {
		if policy == SocketPolicy::default() {
			return Self::new(opts).await;
		}
		let dialer = Arc::new(socket_policy::PolicyDialer::new(policy, connect_timeout)?);
		Self::new_inner(opts, move |client| client.start_with_dialer(dialer)).await
	}

	async fn new_inner(
		opts: NaiveOutboundOpts,
		start: impl FnOnce(&mut NaiveClient) -> Result<(), cronet_rs::error::CronetError> + Send + 'static,
	) -> eyre::Result<Self> {
		// Load libcronet before touching any FFI.
		load_cronet(opts.cronet_lib_path.clone())?;

		let server_name = opts
			.server_name
			.clone()
			.unwrap_or_else(|| host_from_authority(&opts.server_address).to_string());

		let config = NaiveClientConfig {
			server_address: opts.server_address.clone(),
			server_name: Some(server_name),
			username: opts.username.clone(),
			password: opts.password.clone(),
			concurrency: opts.concurrency,
			extra_headers: opts.extra_headers.clone(),
			trusted_root_certificates: opts.trusted_root_certificates.clone(),
			quic_enabled: opts.quic_enabled,
			quic_congestion_control: to_cronet(opts.quic_congestion_control),
			ech_enabled: opts.ech_enabled,
			host_resolver_rules: opts.host_resolver_rules.clone(),
			..Default::default()
		};

		let client = NaiveClient::new(config).map_err(|e| eyre::eyre!("Failed to create NaiveClient: {e}"))?;

		let client = Arc::new(tokio::sync::RwLock::new(client));

		// Start the Cronet engine (requires &mut → write lock).
		let client_for_start = client.clone();
		tokio::task::spawn_blocking(move || -> eyre::Result<()> {
			let mut guard = client_for_start.blocking_write();
			start(&mut guard).map_err(|e| eyre::eyre!("Failed to start Cronet engine: {e}"))
		})
		.await
		.context("Spawn blocking for engine start failed")??;

		info!(target: "naive", "NaiveOutbound started, server={}", opts.server_address);

		Ok(Self { client })
	}

	async fn dial(&self, target: String) -> eyre::Result<(NaiveConn, CancelOnDrop)> {
		let client = self.client.clone();
		let (cancel_tx, cancel_rx) = oneshot::channel();
		let worker = AbortOnDropHandle::new(tokio::task::spawn_blocking(move || -> eyre::Result<_> {
			let mut conn = client
				.blocking_read()
				.dial(&target)
				.map_err(|e| eyre::eyre!("CONNECT to {target} failed: {e}"))?;
			// Hand cancellation to the async caller before blocking for
			// headers. Dropping either an undelivered guard or its
			// receiver cancels this stream.
			if cancel_tx.send(CancelOnDrop(conn.cancel_handle())).is_err() {
				eyre::bail!("CONNECT canceled");
			}
			conn.handshake().map_err(|e| eyre::eyre!("CONNECT to {target} failed: {e}"))?;
			// A detached worker must drop its native stream before the engine.
			Ok((conn, client))
		}));
		let cancel = cancel_rx.await;
		let (conn, _client) = worker.await.context("join CONNECT worker")??;
		Ok((conn, cancel?))
	}
}

#[async_trait]
impl Outbound for NaiveOutbound {
	async fn handle_tcp(&self, ctx: FlowContext, stream: Box<dyn AbstractTcpStream + 'static>) -> eyre::Result<()> {
		let target_str = ctx.target.to_string();

		info!(target: "naive_tcp", "connecting to {target_str}");

		let (naive_conn, _cancel) = self.dial(target_str.clone()).await?;

		info!(target: "naive_tcp", "CONNECT tunnel established to {target_str}");

		// Bridge the blocking NaiveConn to the async stream.
		let (reader, writer, _) = naive_conn.into_split()?;
		naive_async_bridge(
			reader,
			writer,
			stream,
			Some(self.client.clone()),
			cronet_rs::naive_conn::NaiveWriteHalf::shutdown,
		)
		.await
	}

	async fn handle_udp(&self, _ctx: FlowContext, udp_stream: UdpStream) -> eyre::Result<()> {
		self.handle_udp_with_deadline(udp_stream, None).await
	}
}

impl NaiveOutbound {
	/// Relay UDP through a **single** Naive CONNECT tunnel using UoT v2
	/// framing.
	///
	/// NaiveProxy's classic protocol only tunnels TCP, so all datagrams for
	/// this [`UdpStream`] are multiplexed over one CONNECT tunnel opened to
	/// the UoT magic authority ([`uot::MAGIC_ADDRESS`]); each packet carries
	/// its own destination/source address. This requires a UoT-v2-aware server
	/// (e.g. sing-box's naive inbound) on the other end.
	///
	/// This replaces the previous per-datagram fire-and-forget design, which
	/// paid a full TLS+CONNECT handshake per packet, could fan out unbounded
	/// tasks, and silently black-holed every reply.
	///
	/// The optional deadline applies only to establishing CONNECT.
	pub async fn handle_udp_with_deadline(
		&self,
		udp_stream: UdpStream,
		deadline: Option<tokio::time::Instant>,
	) -> eyre::Result<()> {
		let UdpStream { tx, mut rx } = udp_stream;

		// Defer opening the tunnel until the first datagram so idle UDP
		// associations cost nothing, and so the UoT request header can name a
		// concrete destination.
		let Some(first) = rx.recv().await else {
			return Ok(());
		};

		// UoT signals via the CONNECT authority; the port is informational
		// (the server matches on the magic host), so any value works.
		let magic = format!("{}:443", uot::MAGIC_ADDRESS);
		let dial = self.dial(magic);
		let (naive_conn, _cancel) = match deadline {
			Some(deadline) => tokio::time::timeout_at(deadline, dial)
				.await
				.context("Naive UDP CONNECT timed out")??,
			None => dial.await?,
		};

		info!(target: "naive_udp", "UoT v{} tunnel established", uot::VERSION);

		naive_uot_bridge(naive_conn, first, rx, tx, self.client.clone()).await
	}
}

/// Number of bridge I/O threads that have been fully joined.
///
/// A parked reader exits after Cronet delivers the cancellation callback,
/// so this can grow after [`reap_blocking_thread`] was queued. It lets a
/// regression test can prove the thread handle is joined rather than detached:
/// with a detached handle the count can never move.
static REAPED_IO_THREADS: AtomicUsize = AtomicUsize::new(0);

/// How many bridge I/O threads have finished and been joined.
#[cfg(test)]
fn reaped_io_threads() -> usize {
	REAPED_IO_THREADS.load(Ordering::Acquire)
}

/// Name of the bridge I/O thread, as reported by `std::thread::Builder`.
const BRIDGE_IO_THREAD_NAME: &str = "wind-naive-io";

struct CancelOnDrop(cronet_rs::bidirectional::StreamCancel);
impl Drop for CancelOnDrop {
	fn drop(&mut self) {
		self.0.cancel();
	}
}

/// Name of the UoT bridge I/O thread.
const UOT_IO_THREAD_NAME: &str = "wind-naive-uot-io";

/// Name of the plain thread that joins an I/O thread outside a tokio runtime.
const REAPER_THREAD_NAME: &str = "wind-naive-reaper";

/// Largest chunk a naive bridge relays in one read.
///
/// It is also the size of the **single** read buffer each relay owns (see
/// [`relay_local_and_naive`] and the TCP bridge's I/O thread) — never one
/// buffer per chunk.
const NAIVE_BRIDGE_CHUNK: usize = 65535;

/// Spawn a bridge I/O thread with an injectable strategy.
///
/// The bridges run in `Result`-returning functions, so a refused thread —
/// `EAGAIN` when the OS thread limit, the process limit, or the address space
/// for the stack is exhausted — must surface as an error instead of unwinding
/// the task. [`spawn_io_thread`] passes `std::thread::Builder::spawn`; the
/// strategy is a parameter only so a test can drive the refused-thread path
/// deterministically, which the OS cannot be asked to do.
fn spawn_io_thread_with<'a>(
	name: &str,
	spawn: impl FnOnce(&str, Box<dyn FnOnce() + Send + 'a>) -> std::io::Result<JoinHandle<()>> + 'a,
	body: impl FnOnce() + Send + 'a,
) -> std::io::Result<JoinHandle<()>> {
	spawn(name, Box::new(body))
}

/// Spawn one of the bridge I/O threads, reporting a refused thread as an error.
fn spawn_io_thread(name: &str, body: impl FnOnce() + Send + 'static) -> std::io::Result<JoinHandle<()>> {
	spawn_io_thread_with(
		name,
		|name, body| std::thread::Builder::new().name(name.to_string()).spawn(body),
		body,
	)
}

/// Join `handle` on a thread that is allowed to block, absorbing a refused
/// reaper thread instead of propagating it.
fn reap_blocking_thread_with(
	handle: JoinHandle<()>,
	spawn: impl FnOnce(&str, Box<dyn FnOnce() + Send + 'static>) -> std::io::Result<JoinHandle<()>>,
) {
	if let Ok(runtime) = tokio::runtime::Handle::try_current() {
		// Detached on purpose: this task only *waits* for `handle`, and it is
		// the runtime's blocking pool — not a `join()` on an async worker —
		// that pays for that wait.
		#[expect(
			clippy::let_underscore_future,
			reason = "the reaping task is intentionally detached; its only job is to join `handle`"
		)]
		let _ = runtime.spawn_blocking(move || {
			let _ = handle.join();
			REAPED_IO_THREADS.fetch_add(1, Ordering::AcqRel);
		});
	} else {
		// No reactor to hand the wait to; a plain thread keeps the reaping
		// behaviour identical for callers outside a tokio runtime.
		if let Err(e) = spawn(
			REAPER_THREAD_NAME,
			Box::new(move || {
				let _ = handle.join();
				REAPED_IO_THREADS.fetch_add(1, Ordering::AcqRel);
			}),
		) {
			// Reaping is best-effort: the relay it belongs to is already over,
			// and panicking here (from `Drop`, possibly during an unwind) would
			// abort the process instead of merely detaching the thread.
			tracing::warn!(error = %e, "could not spawn a thread to reap a wind-naive io thread");
		}
	}
}

/// Join a detached-able blocking thread from a thread that is allowed to block.
///
/// `Drop` runs on an async worker, so it cannot `join` inline: the Cronet
/// reader must wait for its cancellation callback before releasing its buffer.
/// The reaper lives on a blocking thread (or a plain one outside a runtime),
/// so the standard thread and the `NaiveConn` it owns — including its socket —
/// are reclaimed instead of being abandoned by a dropped [`JoinHandle`].
fn reap_blocking_thread(handle: JoinHandle<()>) {
	reap_blocking_thread_with(handle, |name, body| {
		std::thread::Builder::new().name(name.to_string()).spawn(body)
	});
}

/// Owns a bridge's blocking I/O thread for as long as the relay is running.
///
/// Together with `CancelOnDrop`, this joins the worker after native I/O has
/// stopped, including when the relay future is dropped before completion.
struct JoinSession {
	handle: Option<JoinHandle<()>>,
}

impl JoinSession {
	fn new(handle: JoinHandle<()>) -> Self {
		Self { handle: Some(handle) }
	}
}

impl Drop for JoinSession {
	fn drop(&mut self) {
		if let Some(handle) = self.handle.take() {
			reap_blocking_thread(handle);
		}
	}
}

/// Relay UoT with independent blocking readers and writers. A parked read
/// must never prevent the next client datagram from reaching the server.
async fn naive_uot_bridge(
	naive: cronet_rs::naive_conn::NaiveConn,
	first: UdpPacket,
	mut rx: mpsc::Receiver<UdpPacket>,
	tx: mpsc::Sender<UdpPacket>,
	client: Arc<tokio::sync::RwLock<NaiveClient>>,
) -> eyre::Result<()> {
	const QUEUE: usize = 64;
	let (uplink_tx, mut uplink_rx) = mpsc::channel::<Vec<u8>>(QUEUE);
	let (downlink_tx, mut downlink_rx) = mpsc::channel::<UdpPacket>(QUEUE);
	let mut initial = uot::encode_request(&first.target)?;
	uot::encode_packet_into(&mut initial, &first.target, &first.payload)?;
	let (reader, writer, _) = naive.into_split()?;
	let writer_client = client.clone();
	let _writer = JoinSession::new(
		spawn_io_thread("wind-naive-uot-write", move || {
			let _client = writer_client;
			let mut writer = writer;
			if writer.write_all(&initial).and_then(|_| writer.flush()).is_err() {
				return;
			}
			while let Some(frame) = uplink_rx.blocking_recv() {
				if writer.write_all(&frame).and_then(|_| writer.flush()).is_err() {
					break;
				}
			}
		})
		.context("spawn wind-naive-uot-write thread")?,
	);
	let _reader = JoinSession::new(
		spawn_io_thread(UOT_IO_THREAD_NAME, move || {
			let _client = client;
			let mut reader = reader;
			while let Ok((source, payload)) = uot::read_packet(&mut reader) {
				let packet = UdpPacket {
					source: Some(source.clone()),
					target: source,
					payload: payload.into(),
				};
				if downlink_tx.blocking_send(packet).is_err() {
					break;
				}
			}
		})
		.context("spawn wind-naive-uot-io thread")?,
	);
	let uplink = async move {
		while let Some(packet) = rx.recv().await {
			if let Ok(frame) = uot::encode_packet(&packet.target, &packet.payload)
				&& uplink_tx.send(frame).await.is_err()
			{
				break;
			}
		}
	};
	let downlink = async move {
		while let Some(packet) = downlink_rx.recv().await {
			if tx.send(packet).await.is_err() {
				break;
			}
		}
	};
	tokio::select! { _ = uplink => {}, _ = downlink => {} }
	Ok(())
}

/// Relay both directions independently until both reach EOF, or either fails.
///
/// Owns the relay's **single** read buffer: `read` fills it from the start and
/// reports the filled prefix, so the next read reuses it as is — no fresh
/// allocation and no re-zeroing. The previous code assigned
/// `local_buf = vec![0u8; NAIVE_BRIDGE_CHUNK]` after every successful read,
/// which allocated *and* zeroed 64 KiB per chunk (the old buffer is still alive
/// while the new one is allocated, so the allocator cannot hand back the same
/// block).
///
/// Split out of [`naive_async_bridge`] so the buffer's lifetime — one per
/// relay, not one per chunk — can be asserted without a Cronet engine.
async fn relay_local_and_naive(
	stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
	naive_write_tx: mpsc::Sender<Vec<u8>>,
	naive_read_rx: &mut mpsc::Receiver<std::io::Result<Vec<u8>>>,
	writer_done: oneshot::Receiver<std::io::Result<()>>,
) -> std::io::Result<()> {
	let (mut local_read, mut local_write) = tokio::io::split(stream);
	let uplink = async move {
		let mut local_buf = vec![0u8; NAIVE_BRIDGE_CHUNK];
		loop {
			let n = local_read.read(&mut local_buf).await?;
			if n == 0 {
				break;
			}
			naive_write_tx
				.send(local_buf[..n].to_vec())
				.await
				.map_err(std::io::Error::other)?;
		}
		// Closing this queue lets the worker drain every queued byte before
		// sending END_STREAM. It does not cancel the independent reader.
		drop(naive_write_tx);
		Ok::<_, std::io::Error>(())
	};
	let downlink = async {
		while let Some(data) = naive_read_rx.recv().await {
			local_write.write_all(&data?).await?;
			local_write.flush().await?;
		}
		local_write.shutdown().await
	};
	let writer = async { writer_done.await.map_err(std::io::Error::other)? };
	// Observe worker errors even while the local reader is idle. A successful
	// half-close only completes its own future; errors cancel the whole relay.
	tokio::try_join!(uplink, downlink, writer)?;
	Ok(())
}

/// Bridge data between a blocking Cronet connection
/// ([`cronet_rs::naive_conn::NaiveConn`]) and a tokio [`AsyncRead`] +
/// [`AsyncWrite`] stream.
///
/// Uses independent read/write workers and bounded queues. Both workers
/// retain the engine and are reaped even when the async relay is cancelled.
///
/// The thread is reaped through a [`JoinSession`] when the bridge returns, so
/// the thread and the connection's socket do not leak past the relay.
///
/// Generic over the connection so the relay's shutdown contract — including
/// that the I/O thread is handed to a [`JoinSession`] instead of being
/// detached — can be driven by a test double without a Cronet engine.
async fn naive_async_bridge<R, W, S>(
	reader: R,
	writer: W,
	mut stream: impl AsyncRead + AsyncWrite + Unpin,
	client: Option<Arc<tokio::sync::RwLock<NaiveClient>>>,
	shutdown_write: S,
) -> eyre::Result<()>
where
	R: Read + Send + 'static,
	W: Write + Send + 'static,
	S: FnOnce(&mut W) -> std::io::Result<()> + Send + 'static,
{
	const QUEUE: usize = 64;
	let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(QUEUE);
	let (read_tx, mut read_rx) = mpsc::channel::<std::io::Result<Vec<u8>>>(QUEUE);
	let (writer_done_tx, writer_done_rx) = oneshot::channel();
	let writer_client = client.clone();
	// Install each guard immediately, including on partial startup and task
	// cancellation. Keep the engine alive until native I/O has finished.
	let _writer = JoinSession::new(
		spawn_io_thread("wind-naive-write", move || {
			let _client = writer_client;
			let mut writer = writer;
			let result = (|| {
				while let Some(data) = write_rx.blocking_recv() {
					writer.write_all(&data)?;
					writer.flush()?;
				}
				shutdown_write(&mut writer)
			})();
			let _ = writer_done_tx.send(result);
		})
		.context("spawn wind-naive-write thread")?,
	);
	let _reader = JoinSession::new(
		spawn_io_thread(BRIDGE_IO_THREAD_NAME, move || {
			let _client = client;
			let mut reader = reader;
			let mut buf = [0u8; NAIVE_BRIDGE_CHUNK];
			loop {
				match reader.read(&mut buf) {
					Ok(0) => break,
					Err(error) => {
						let _ = read_tx.blocking_send(Err(error));
						break;
					}
					Ok(n) => {
						if read_tx.blocking_send(Ok(buf[..n].to_vec())).is_err() {
							break;
						}
					}
				}
			}
		})
		.context("spawn wind-naive-io thread")?,
	);
	relay_local_and_naive(&mut stream, write_tx, &mut read_rx, writer_done_rx).await?;
	Ok(())
}

/// Default search paths for `libcronet` (dynamic loading only).
#[cfg(target_vendor = "apple")]
const CRONET_SEARCH_PATHS: &[&str] = &[
	"libcronet.dylib",
	"./libcronet.dylib",
	"/usr/local/lib/libcronet.dylib",
	"/opt/cronet/libcronet.dylib",
];

/// Default search paths for `libcronet` (dynamic loading only).
#[cfg(all(not(target_vendor = "apple"), not(windows)))]
const CRONET_SEARCH_PATHS: &[&str] = &[
	"libcronet.so",
	"./libcronet.so",
	"/usr/local/lib/libcronet.so",
	"/opt/cronet/libcronet.so",
];

/// Default DLL names for `libcronet` on Windows (dynamic loading only).
///
/// [`default_cronet_paths`] resolves these against the directory containing
/// the running executable, so they do not depend on the process working
/// directory or `PATH`.
#[cfg(windows)]
const CRONET_SEARCH_PATHS: &[&str] = &["libcronet.dll", "cronet.dll"];

/// Expand the platform default library candidates.
fn default_cronet_paths() -> Vec<String> {
	#[cfg(windows)]
	{
		let exe_dir = std::env::current_exe()
			.ok()
			.and_then(|exe| exe.parent().map(std::path::Path::to_path_buf));
		windows_cronet_paths(exe_dir.as_deref())
	}
	#[cfg(not(windows))]
	{
		CRONET_SEARCH_PATHS.iter().map(|name| (*name).to_string()).collect()
	}
}

/// Windows candidates resolved against the executable's directory when it is
/// known, falling back to bare names otherwise.
#[cfg(windows)]
fn windows_cronet_paths(exe_dir: Option<&std::path::Path>) -> Vec<String> {
	match exe_dir {
		Some(dir) => CRONET_SEARCH_PATHS
			.iter()
			.map(|name| dir.join(name).to_string_lossy().into_owned())
			.collect(),
		None => CRONET_SEARCH_PATHS.iter().map(|name| (*name).to_string()).collect(),
	}
}

/// Load the `libcronet` shared library.
///
/// If `path` is `Some(...)`, that exact path is tried first.  On failure, or
/// when `path` is `None`, the default search paths are tried.
fn load_cronet(path: Option<String>) -> eyre::Result<()> {
	if cronet_rs::sys::STATIC_LINKED {
		return Ok(());
	}
	use cronet_rs::sys::load_library;

	// Candidate order: an explicit `cronet_lib_path` wins, then the prebuilt
	// fetched by `cronet-sys`'s build script under `--features download`, then
	// the implicit system search paths.
	let mut paths: Vec<String> = Vec::new();
	if let Some(p) = path {
		paths.push(p);
	}
	#[cfg(feature = "download")]
	if let Some(p) = cronet_rs::sys::downloaded_library_path() {
		paths.push(p.to_string());
	}
	paths.extend(default_cronet_paths());

	for lib_path in &paths {
		match unsafe { load_library(lib_path) } {
			Ok(()) => {
				info!(target: "naive", "Loaded libcronet from {lib_path}");
				return Ok(());
			}
			Err(e) => {
				let msg = format!("{e}");
				// "already loaded" means success.
				if msg.contains("already loaded") {
					return Ok(());
				}
				tracing::debug!(target: "naive", "libcronet not found at {lib_path}: {msg}");
			}
		}
	}

	let mut msg = format!(
		"Cannot load libcronet. Tried: {}. Please install libcronet and set `cronet_lib_path` in config, or place the shared \
		 library on the loader search path.",
		paths.join(", "),
	);
	#[cfg(feature = "download")]
	msg.push_str(
		" The `download` feature was enabled but no verified prebuilt was available; check the build output for the \
		 download/checksum error.",
	);
	#[cfg(not(feature = "download"))]
	msg.push_str(" Rebuild with `--features download` to fetch and SHA-256-verify a prebuilt libcronet.");
	Err(eyre::eyre!("{msg}"))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn host_from_authority_handles_ipv6_and_domains() {
		assert_eq!(host_from_authority("[2001:db8::1]:443"), "2001:db8::1");
		assert_eq!(host_from_authority("[::1]:8443"), "::1");
		assert_eq!(host_from_authority("example.com:443"), "example.com");
		assert_eq!(host_from_authority("1.2.3.4:443"), "1.2.3.4");
		assert_eq!(host_from_authority("example.com"), "example.com");
	}

	#[test]
	fn test_opts_default() {
		let opts = NaiveOutboundOpts::default();
		assert!(opts.server_address.is_empty());
		assert!(opts.server_name.is_none());
		assert!(opts.username.is_none());
		assert!(opts.password.is_none());
		assert_eq!(opts.concurrency, 1);
		assert!(!opts.quic_enabled);
		assert!(opts.trusted_root_certificates.is_none());
		assert!(!opts.ech_enabled);
		assert!(opts.extra_headers.is_empty());
		assert!(opts.cronet_lib_path.is_none());
		assert!(opts.host_resolver_rules.is_none());
	}

	#[test]
	fn test_opts_custom() {
		let opts = NaiveOutboundOpts {
			server_address: "proxy.example.com:443".into(),
			server_name: Some("proxy.example.com".into()),
			username: Some("user".into()),
			password: Some("pass".into()),
			concurrency: 2,
			quic_enabled: true,
			quic_congestion_control: QuicCongestionControl::Bbr,
			cronet_lib_path: Some("/opt/cronet/libcronet.so.119".into()),
			host_resolver_rules: Some("MAP proxy.example.com 203.0.113.7".into()),
			..Default::default()
		};
		assert_eq!(opts.server_address, "proxy.example.com:443");
		assert_eq!(opts.server_name.unwrap(), "proxy.example.com");
		assert_eq!(opts.username.unwrap(), "user");
		assert_eq!(opts.password.unwrap(), "pass");
		assert_eq!(opts.concurrency, 2);
		assert!(opts.quic_enabled);
		assert_eq!(opts.cronet_lib_path.unwrap(), "/opt/cronet/libcronet.so.119");
		assert_eq!(opts.host_resolver_rules.unwrap(), "MAP proxy.example.com 203.0.113.7");
	}

	#[test]
	fn test_opts_with_auth() {
		let opts = NaiveOutboundOpts {
			server_address: "server.com:443".into(),
			username: Some("naive".into()),
			password: Some("+naive_password".into()),
			..Default::default()
		};
		assert_eq!(opts.server_address, "server.com:443");
		assert!(opts.username.is_some());
		assert!(opts.password.is_some());
	}

	#[test]
	fn test_opts_extra_headers() {
		let mut headers = std::collections::HashMap::new();
		headers.insert("X-Custom".into(), "value".into());

		let opts = NaiveOutboundOpts {
			server_address: "s.example.com:443".into(),
			extra_headers: headers,
			..Default::default()
		};
		assert_eq!(opts.extra_headers.get("X-Custom").unwrap(), "value");
	}

	/// With `download` enabled, `cronet-sys`'s build script must have fetched a
	/// prebuilt and exposed a real, existing path that the loader will try.
	#[cfg(feature = "download")]
	#[test]
	fn download_feature_exposes_a_prebuilt_library() {
		let path = cronet_rs::sys::downloaded_library_path().expect("`download` feature should expose a prebuilt library path");
		assert!(
			std::path::Path::new(path).exists(),
			"downloaded libcronet should exist on disk: {path}"
		);
	}

	static BRIDGE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

	async fn wait_for_workers(before: usize) {
		tokio::time::timeout(std::time::Duration::from_secs(2), async {
			while reaped_io_threads() < before + 2 {
				tokio::time::sleep(std::time::Duration::from_millis(5)).await;
			}
		})
		.await
		.unwrap();
	}

	fn tcp_pair() -> (std::net::TcpStream, std::net::TcpStream) {
		let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
		let (server, _) = listener.accept().unwrap();
		for stream in [&client, &server] {
			stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
			stream.set_write_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
		}
		(client, server)
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn local_half_close_preserves_eof_delimited_response() {
		let _guard = BRIDGE_TEST_LOCK.lock().await;
		let before = reaped_io_threads();
		let (native, mut server) = tcp_pair();
		let payload = vec![0x5a; 256 * 1024];
		let expected = payload.clone();
		let server = std::thread::spawn(move || {
			let mut request = Vec::new();
			server.read_to_end(&mut request).unwrap();
			assert_eq!(request, expected);
			// No response is possible before the bridge forwards the write EOF.
			server.write_all(&request).unwrap();
			server.shutdown(std::net::Shutdown::Write).unwrap();
		});
		let (local, mut peer) = tokio::io::duplex(1024);
		let bridge = naive_async_bridge(native.try_clone().unwrap(), native, local, None, |writer| {
			writer.shutdown(std::net::Shutdown::Write)
		});
		let client = async {
			peer.write_all(&payload).await.unwrap();
			peer.shutdown().await.unwrap();
			peer.shutdown().await.unwrap();
			let mut response = Vec::new();
			peer.read_to_end(&mut response).await.unwrap();
			assert_eq!(response, payload);
		};
		tokio::time::timeout(std::time::Duration::from_secs(10), async {
			let (result, ()) = tokio::join!(bridge, client);
			result.unwrap();
		})
		.await
		.unwrap();
		server.join().unwrap();
		wait_for_workers(before).await;
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn remote_half_close_preserves_request_direction() {
		let _guard = BRIDGE_TEST_LOCK.lock().await;
		let before = reaped_io_threads();
		let (native, mut server) = tcp_pair();
		let server = std::thread::spawn(move || {
			server.write_all(b"response").unwrap();
			server.shutdown(std::net::Shutdown::Write).unwrap();
			let mut request = Vec::new();
			server.read_to_end(&mut request).unwrap();
			assert_eq!(request, b"request after remote EOF");
		});
		let (local, mut peer) = tokio::io::duplex(8);
		let bridge = naive_async_bridge(native.try_clone().unwrap(), native, local, None, |writer| {
			writer.shutdown(std::net::Shutdown::Write)
		});
		let client = async {
			let mut response = Vec::new();
			peer.read_to_end(&mut response).await.unwrap();
			assert_eq!(response, b"response");
			peer.write_all(b"request after remote EOF").await.unwrap();
			peer.shutdown().await.unwrap();
		};
		tokio::time::timeout(std::time::Duration::from_secs(10), async {
			let (result, ()) = tokio::join!(bridge, client);
			result.unwrap();
		})
		.await
		.unwrap();
		server.join().unwrap();
		wait_for_workers(before).await;
	}

	#[tokio::test]
	async fn bridge_reports_native_shutdown_failure() {
		let _guard = BRIDGE_TEST_LOCK.lock().await;
		let before = reaped_io_threads();
		let (local, mut peer) = tokio::io::duplex(8);
		peer.shutdown().await.unwrap();
		let result = tokio::time::timeout(
			std::time::Duration::from_secs(2),
			naive_async_bridge(std::io::empty(), std::io::sink(), local, None, |_| {
				Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "shutdown failed"))
			}),
		)
		.await
		.unwrap();
		assert!(result.unwrap_err().to_string().contains("shutdown failed"));
		wait_for_workers(before).await;
	}

	#[tokio::test]
	async fn bridge_reports_native_write_failure_while_local_reader_is_idle() {
		let _guard = BRIDGE_TEST_LOCK.lock().await;
		let before = reaped_io_threads();
		struct FailedWriter;
		impl Write for FailedWriter {
			fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
				Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "write failed"))
			}

			fn flush(&mut self) -> std::io::Result<()> {
				Ok(())
			}
		}
		let (local, mut peer) = tokio::io::duplex(8);
		peer.write_all(b"request").await.unwrap();
		// Keep the local write half open: the error must wake an idle relay.
		let result = tokio::time::timeout(
			std::time::Duration::from_secs(2),
			naive_async_bridge(std::io::empty(), FailedWriter, local, None, |_| Ok(())),
		)
		.await
		.unwrap();
		assert!(result.unwrap_err().to_string().contains("write failed"));
		wait_for_workers(before).await;
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn parked_read_does_not_block_uplink() {
		let _guard = BRIDGE_TEST_LOCK.lock().await;
		let before = reaped_io_threads();
		struct Reader(std::sync::mpsc::Receiver<Vec<u8>>);
		impl Read for Reader {
			fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
				match self.0.recv() {
					Ok(data) => {
						buf[..data.len()].copy_from_slice(&data);
						Ok(data.len())
					}
					Err(_) => Ok(0),
				}
			}
		}
		struct Writer(std::sync::mpsc::Sender<Vec<u8>>);
		impl Write for Writer {
			fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
				self.0.send(data.to_vec()).map_err(std::io::Error::other)?;
				Ok(data.len())
			}

			fn flush(&mut self) -> std::io::Result<()> {
				Ok(())
			}
		}
		let (tx, rx) = std::sync::mpsc::channel();
		let (local, mut peer) = tokio::io::duplex(64);
		let bridge = tokio::spawn(naive_async_bridge(Reader(rx), Writer(tx), local, None, |_| Ok(())));
		peer.write_all(b"ping").await.unwrap();
		let mut reply = [0; 4];
		tokio::time::timeout(std::time::Duration::from_secs(2), peer.read_exact(&mut reply))
			.await
			.unwrap()
			.unwrap();
		assert_eq!(&reply, b"ping");
		drop(peer);
		bridge.await.unwrap().unwrap();
		tokio::time::timeout(std::time::Duration::from_secs(2), async {
			while reaped_io_threads() < before + 2 {
				tokio::time::sleep(std::time::Duration::from_millis(5)).await;
			}
		})
		.await
		.unwrap();
	}

	/// A stand-in for the blocking Cronet connection: its first `read` parks
	/// until the test releases it (then reports EOF), and writes are discarded.
	struct BlockingIo {
		connected: std::sync::mpsc::Sender<()>,
		release: std::sync::mpsc::Receiver<()>,
	}

	impl std::io::Read for BlockingIo {
		fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
			let _ = self.connected.send(());
			// A closed sender (test finished) or the timeout both mean "go on".
			let _ = self.release.recv_timeout(std::time::Duration::from_secs(5));
			Ok(0)
		}
	}

	impl std::io::Write for BlockingIo {
		fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
			Ok(buf.len())
		}

		fn flush(&mut self) -> std::io::Result<()> {
			Ok(())
		}
	}

	/// The TCP bridge must hand its blocking I/O thread to a [`JoinSession`]
	/// when the relay ends, instead of detaching the handle.
	///
	/// The connection double parks in its first `read` until the test releases
	/// it, so the thread provably cannot finish on its own while the relay
	/// runs. A detached handle leaves `reaped_io_threads` frozen and this test
	/// fails; the session's reaper moves it.
	///
	/// A multi-thread runtime is required: the test blocks its own thread while
	/// waiting for the I/O thread to park, so the bridge task and that thread
	/// must be able to make progress in parallel.
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn bridge_hands_its_io_thread_to_the_session() {
		let _guard = BRIDGE_TEST_LOCK.lock().await;
		let (connected_tx, connected_rx) = std::sync::mpsc::channel::<()>();
		let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

		// A live local stream keeps the relay's `select!` pending until the
		// test drops the peer, so the bridge future does not return before the
		// I/O thread has been created and parked.
		let (local, peer) = tokio::io::duplex(64);

		let before = reaped_io_threads();
		let bridge = tokio::spawn(naive_async_bridge(
			BlockingIo {
				connected: connected_tx,
				release: release_rx,
			},
			std::io::sink(),
			local,
			None,
			|_| Ok(()),
		));

		connected_rx
			.recv_timeout(std::time::Duration::from_secs(10))
			.expect("the bridge must have spawned its I/O thread and parked it in read");

		// The thread is parked in its first `read`, so neither the relay nor a
		// detached handle can have reaped anything yet.
		assert_eq!(
			reaped_io_threads(),
			before,
			"a parked io thread must not be reported as reaped"
		);

		// Cancellation must reap workers even while a native read is parked.
		drop(peer);
		bridge.abort();
		assert!(bridge.await.unwrap_err().is_cancelled());
		let _ = release_tx.send(());

		let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
		while reaped_io_threads() < before + 2 && std::time::Instant::now() < deadline {
			// A plain sleep: reaping happens on the blocking pool, so nothing
			// has to be driven on this runtime for it to progress.
			std::thread::sleep(std::time::Duration::from_millis(10));
		}
		assert_eq!(
			reaped_io_threads(),
			before + 2,
			"the bridge must join its io thread instead of detaching the handle"
		);
	}

	/// A local-stream double that records the **address** of the buffer every
	/// read is handed, then replays `chunks` and reports EOF.
	///
	/// An entry in a `ReadBuf` is the slice the caller passed to `read`, so
	/// with nothing filled yet `filled().as_ptr()` is the address of that
	/// buffer: two reads that observe the same address were handed the same
	/// buffer.
	struct ReadBufAddressProbe {
		chunks: std::collections::VecDeque<Vec<u8>>,
		bases: Arc<std::sync::Mutex<Vec<usize>>>,
	}

	impl tokio::io::AsyncRead for ReadBufAddressProbe {
		fn poll_read(
			self: std::pin::Pin<&mut Self>,
			_cx: &mut std::task::Context<'_>,
			buf: &mut tokio::io::ReadBuf<'_>,
		) -> std::task::Poll<std::io::Result<()>> {
			let this = self.get_mut();
			this.bases.lock().unwrap().push(buf.filled().as_ptr() as usize);
			if let Some(chunk) = this.chunks.pop_front() {
				buf.put_slice(&chunk);
			}
			// An unfilled `ReadBuf` is how a reader reports EOF.
			std::task::Poll::Ready(Ok(()))
		}
	}

	impl tokio::io::AsyncWrite for ReadBufAddressProbe {
		fn poll_write(
			self: std::pin::Pin<&mut Self>,
			_cx: &mut std::task::Context<'_>,
			buf: &[u8],
		) -> std::task::Poll<std::io::Result<usize>> {
			std::task::Poll::Ready(Ok(buf.len()))
		}

		fn poll_flush(
			self: std::pin::Pin<&mut Self>,
			_cx: &mut std::task::Context<'_>,
		) -> std::task::Poll<std::io::Result<()>> {
			std::task::Poll::Ready(Ok(()))
		}

		fn poll_shutdown(
			self: std::pin::Pin<&mut Self>,
			_cx: &mut std::task::Context<'_>,
		) -> std::task::Poll<std::io::Result<()>> {
			std::task::Poll::Ready(Ok(()))
		}
	}

	/// One read buffer must serve the whole relay, not one per chunk.
	///
	/// The previous loop body re-created the buffer after every successful read
	/// (`local_buf = vec![0u8; 65535]`), allocating *and* zeroing 64 KiB per
	/// chunk. That new allocation is taken while the buffer it replaces is
	/// still alive, so consecutive reads cannot observe the same address — the
	/// same probe passes only when the relay keeps one buffer.
	///
	/// This drives the real relay loop ([`relay_local_and_naive`]) with a
	/// stream double; no Cronet engine, I/O thread, or runtime thread is
	/// involved, so nothing else in this test binary can perturb the
	/// observation.
	#[tokio::test]
	async fn relay_reuses_one_read_buffer_instead_of_reallocating_per_chunk() {
		const CHUNKS: usize = 8;

		let bases = Arc::new(std::sync::Mutex::new(Vec::<usize>::new()));
		let chunks: std::collections::VecDeque<Vec<u8>> = (0..CHUNKS).map(|i| vec![i as u8 + 1; 64]).collect();
		let mut stream = ReadBufAddressProbe {
			chunks,
			bases: Arc::clone(&bases),
		};

		let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(64);
		let (read_tx, mut read_rx) = mpsc::channel(64);
		let (done_tx, done_rx) = oneshot::channel();
		let worker = tokio::spawn(async move {
			let mut received = Vec::new();
			while let Some(chunk) = write_rx.recv().await {
				received.push(chunk);
			}
			let _ = done_tx.send(Ok(()));
			drop(read_tx);
			received
		});

		relay_local_and_naive(&mut stream, write_tx, &mut read_rx, done_rx)
			.await
			.unwrap();

		let observed = bases.lock().unwrap().clone();
		assert_eq!(
			observed.len(),
			CHUNKS + 1,
			"every chunk and the EOF read must have been handed a buffer"
		);
		assert!(
			observed.iter().all(|base| *base == observed[0]),
			"one buffer must serve the whole relay, but the reads saw distinct buffers: {observed:?}"
		);

		// The chunks must still arrive whole and in order.
		let received = worker.await.unwrap();
		assert_eq!(received.len(), CHUNKS);
		for (i, chunk) in received.iter().enumerate() {
			assert_eq!(chunk, &vec![i as u8 + 1; 64], "chunk {i} must arrive unchanged");
		}
	}

	/// A refused bridge I/O thread must be reported through the caller's
	/// `eyre::Result`, not turned into a task-wide panic.
	///
	/// Both bridge spawn sites used `Builder::spawn(..).expect(..)`, which
	/// unwound as soon as the OS refused a thread. `spawn_io_thread_with` only
	/// became able to report that as a `Result` in this change, so this
	/// fails-before: the error path did not exist, and the spawn could not be
	/// *offered* the refused thread at all.
	#[test]
	fn a_refused_io_thread_is_reported_instead_of_panicking() {
		let mut offered: Vec<String> = Vec::new();

		let e = spawn_io_thread_with(
			BRIDGE_IO_THREAD_NAME,
			|name, _body| {
				offered.push(name.to_string());
				Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "thread limit reached"))
			},
			|| unreachable!("a refused thread must not be started"),
		)
		.context("spawn wind-naive-io thread")
		.expect_err("a refused thread must surface as an error");

		assert!(
			e.to_string().starts_with("spawn wind-naive-io thread"),
			"the spawn failure must keep the bridge's context: {e}"
		);
		// `eyre` renders only the outermost context with `Display`, but keeps
		// the refused-thread error as the report's cause, so the operator can
		// still see *why* the thread was refused.
		let chain = format!("{e:?}");
		assert!(
			chain.contains("thread limit reached"),
			"the OS error must stay in the report's cause chain: {chain}"
		);
		assert_eq!(
			offered,
			vec![BRIDGE_IO_THREAD_NAME.to_string()],
			"the bridge's thread name must be used"
		);
	}

	/// Failing to spawn the *reaper* must not panic either: `JoinSession::drop`
	/// calls it on the async worker's unwind-free path, and a panic there
	/// aborts the process when the drop is itself running during an unwind.
	///
	/// This test runs outside a tokio runtime on purpose — that is the branch
	/// that spawns the plain reaper thread, and so the only one where the
	/// refusal has to be absorbed.
	#[test]
	fn a_refused_reaper_thread_is_logged_instead_of_panicking() {
		let (tx, rx) = std::sync::mpsc::channel::<()>();
		let handle = std::thread::spawn(move || {
			let _ = tx.send(());
		});
		let _ = rx.recv_timeout(std::time::Duration::from_secs(5));

		let attempted = std::cell::Cell::new(false);
		reap_blocking_thread_with(handle, |_name, _body| {
			attempted.set(true);
			Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "thread limit reached"))
		});
		assert!(attempted.get(), "the reaper must have attempted its plain spawn");
	}

	#[cfg(windows)]
	#[test]
	fn windows_default_paths_live_next_to_the_executable() {
		let exe_dir = std::path::Path::new(r"C:\Program Files\clash-rs");
		let expected: Vec<String> = ["libcronet.dll", "cronet.dll"]
			.iter()
			.map(|name| exe_dir.join(name).to_string_lossy().into_owned())
			.collect();
		assert_eq!(windows_cronet_paths(Some(exe_dir)), expected);

		let bare: Vec<String> = ["libcronet.dll", "cronet.dll"]
			.iter()
			.map(|name| (*name).to_string())
			.collect();
		assert_eq!(windows_cronet_paths(None), bare);
	}
}

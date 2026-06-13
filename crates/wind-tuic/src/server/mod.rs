//! Backend-agnostic TUIC server core.
//!
//! This is the TUIC inbound protocol logic — auth handshake, the three parallel
//! accept loops (datagram / uni / bi), command dispatch, and per-association
//! UDP session management — written **once** generic over
//! [`wind_quic::QuicConnection`]. Both the quinn and quiche backends construct
//! their endpoint, accept an established connection, and hand it to
//! [`serve_connection`]; everything above the QUIC handle is shared.
//!
//! It is the generalization of the former quinn-only `quinn::inbound` server
//! (the reference behavior) and the replacement for the bespoke `wind-tuiche`
//! driver.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use arc_swap::ArcSwapOption;
use eyre::Context as _;
use moka::future::Cache;
use tokio::{
	io::{AsyncRead, AsyncReadExt as _},
	sync::{Notify, mpsc},
};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument as _, error, info, warn};
use uuid::Uuid;
use wind_core::{
	InboundCallback,
	udp::{UdpPacket, UdpStream as CoreUdpStream},
};
use wind_quic::{QuicConnection, QuicError};

use crate::proto::{CmdType, Command, UdpStream};

#[cfg(feature = "masquerade")]
mod masquerade;

/// Configuration for the HTTP/3 masquerade.
///
/// Kept dependency-free (just the upstream URL) so it threads through the
/// always-compiled [`serve_connection`] even when the `masquerade` feature is
/// off. The actual reverse-proxy engine lives in the feature-gated
/// [`masquerade`] module.
#[derive(Clone, Debug)]
pub struct MasqueradeConfig {
	/// Upstream site to reverse-proxy non-TUIC HTTP/3 requests to,
	/// e.g. `https://example.com`.
	pub upstream: String,
}

async fn spawn_logged(label: &str, fut: impl std::future::Future<Output = eyre::Result<()>>) {
	if let Err(err) = fut.await {
		error!("{label} error: {err:?}");
	}
}

/// Wait for the connection to be authenticated. Returns `true` once a UUID is
/// set; returns `false` if the auth timeout elapses first. Callers that get
/// `false` must drop the request.
async fn ensure_authed<C: QuicConnection>(ctx: &InboundCtx<C>) -> bool {
	if ctx.uuid.load().is_some() {
		return true;
	}
	if tokio::time::timeout(ctx.auth_timeout, ctx.auth_notify.notified())
		.await
		.is_err()
	{
		return false;
	}
	ctx.uuid.load().is_some()
}

/// Drive an `accept`-style call in a loop until the connection errors or
/// `cancel` fires. Each accepted value is handed to `handle`; the loop exits on
/// connection error (benign closes logged at debug) or cancellation (silent).
async fn acceptor_loop<A, AccFut, HFut, AccFn, HFn>(
	cancel: CancellationToken,
	label: &'static str,
	mut accept: AccFn,
	mut handle: HFn,
) where
	AccFn: FnMut() -> AccFut,
	HFn: FnMut(A) -> HFut,
	AccFut: std::future::Future<Output = Result<A, QuicError>>,
	HFut: std::future::Future<Output = ()>,
{
	loop {
		let result = tokio::select! {
			_ = cancel.cancelled() => return,
			r = accept() => r,
		};
		match result {
			Err(e) => {
				// `ApplicationClosed`, `LocallyClosed`, and `TimedOut` are normal
				// lifecycle events; log at debug instead of error so legitimate
				// disconnects don't muddy operator logs.
				if matches!(
					&e,
					QuicError::ApplicationClosed { .. } | QuicError::LocallyClosed | QuicError::TimedOut
				) {
					tracing::debug!("{label} loop ending after benign connection close: {e:?}");
				} else {
					error!("{label} error: {e:?}");
				}
				return;
			}
			Ok(v) => handle(v).await,
		}
	}
}

struct InboundCtx<C: QuicConnection> {
	conn: C,
	uuid: ArcSwapOption<Uuid>,
	auth_notify: Arc<Notify>,
	users: Arc<HashMap<Uuid, String>>,
	auth_timeout: Duration,
	udp_sessions: Cache<u16, UdpSession<C>>,
	/// Parent of every per-UDP-session cancel token. Cancelling this tears down
	/// all live bridge tasks at once (used when the parent connection
	/// terminates).
	udp_root_cancel: CancellationToken,
}

/// Per-UDP-session state stored in the LRU cache.
///
/// `cancel` is a child of `InboundCtx::udp_root_cancel` and is wired into the
/// three bridge tasks via `tokio::select!`. When the session is evicted —
/// either by an explicit `Dissociate` or by LRU/capacity pressure — the moka
/// `async_eviction_listener` cancels it, so the bridge tasks exit promptly
/// instead of forming a self-sustaining cycle that outlives the cache entry.
struct UdpSession<C: QuicConnection> {
	tuic_stream: Arc<UdpStream<C>>,
	cancel: CancellationToken,
}

impl<C: QuicConnection> Clone for UdpSession<C> {
	fn clone(&self) -> Self {
		Self {
			tuic_stream: self.tuic_stream.clone(),
			cancel: self.cancel.clone(),
		}
	}
}

/// Per-connection ceiling on concurrent UDP associations. Bounds per-connection
/// memory: each session spawns three tasks plus channels, so an unbounded space
/// would let one authenticated peer pin a large amount of background work.
const MAX_UDP_SESSIONS_PER_CONN: u64 = 1024;

/// The first thing a freshly-handshaked peer sends, raced across all three
/// transports to classify the connection — the TUIC `Auth` is **not**
/// guaranteed to arrive first (a `Connect` bidi, a heartbeat datagram, or QUIC
/// reordering can beat it), so we cannot assume the first event is a uni `Auth`
/// stream.
enum FirstEvent<C: QuicConnection> {
	Uni(C::RecvStream),
	Bi(C::SendStream, C::RecvStream),
	Datagram(bytes::Bytes),
}

/// A first event classified as TUIC, with the peeked header bytes replayed for
/// the stream variants, handed to the matching handler.
enum TuicFirst<C: QuicConnection> {
	Uni(wind_quic::PrefixedRecv<C::RecvStream>),
	Bi(C::SendStream, wind_quic::PrefixedRecv<C::RecvStream>),
	Datagram(bytes::Bytes),
}

/// Whether a 2-byte prefix is TUIC framing: `[VER, CmdType]` with `CmdType` in
/// `Auth..=Heartbeat` (0..=4). An HTTP/3 stream-type / frame-type byte won't
/// satisfy both, so this distinguishes the two even when an h3 stream happens
/// to start with `VER`.
fn is_tuic_prefix(prefix: [u8; 2]) -> bool {
	prefix[0] == crate::proto::VER && prefix[1] <= u8::from(CmdType::Heartbeat)
}

/// Read the 2-byte classifier prefix from a stream (`None` if it closes first).
async fn read_prefix<R: AsyncRead + Unpin>(recv: &mut R) -> Option<[u8; 2]> {
	let mut prefix = [0u8; 2];
	recv.read_exact(&mut prefix).await.ok().map(|_| prefix)
}

/// Hand a non-TUIC connection to the HTTP/3 masquerade (when enabled), passing
/// any first stream the classifier already consumed so the h3 server can replay
/// it. Closes the connection when the masquerade is disabled or compiled out.
async fn dispatch_masquerade<C: QuicConnection>(
	conn: C,
	masq: Option<&MasqueradeConfig>,
	first_uni: Option<wind_quic::PrefixedRecv<C::RecvStream>>,
	first_bidi: Option<(C::SendStream, wind_quic::PrefixedRecv<C::RecvStream>)>,
	remote_addr: SocketAddr,
	cancel: CancellationToken,
) {
	#[cfg(feature = "masquerade")]
	if let Some(cfg) = masq {
		info!("connection from {} is not TUIC; serving HTTP/3 masquerade", remote_addr);
		if let Err(e) = masquerade::run_masquerade(conn, first_uni, first_bidi, cfg, cancel).await {
			tracing::debug!("masquerade for {} ended: {e:?}", remote_addr);
		}
		return;
	}
	let _ = (masq, first_uni, first_bidi, cancel);
	tracing::debug!(
		"connection from {} is not TUIC and masquerade is disabled; closing",
		remote_addr
	);
	conn.close(0, b"");
}

/// Drive an established TUIC connection: spawn the auth-timeout guard and the
/// datagram/uni/bi accept loops, then run until the peer disconnects or
/// `cancel` fires. Backend-agnostic — both backends call this after their
/// handshake.
pub async fn serve_connection<C, CB>(
	conn: C,
	remote_addr: SocketAddr,
	users: Arc<HashMap<Uuid, String>>,
	auth_timeout: Duration,
	callback: CB,
	cancel: CancellationToken,
	masq: Option<MasqueradeConfig>,
) where
	C: QuicConnection,
	CB: InboundCallback,
{
	// --- Classify the connection: real TUIC vs HTTP/3 masquerade ---
	//
	// Both negotiate the `h3` ALPN, so we inspect the first thing the peer sends.
	// The first event may be a uni stream, a bidi stream, or a datagram (the TUIC
	// `Auth` is not guaranteed to arrive first), so race all three. We then peek
	// the first two bytes: TUIC framing is `[VER, CmdType]` (see `is_tuic_prefix`),
	// while an HTTP/3 client's streams begin with an h3 stream-type / frame-type
	// byte. The peeked bytes are replayed via `PrefixedRecv` so neither the TUIC
	// parser nor the h3 adapter loses any data.
	let first = tokio::select! {
		_ = cancel.cancelled() => return,
		r = tokio::time::timeout(auth_timeout, async {
			tokio::select! {
				res = conn.accept_uni() => res.map(FirstEvent::<C>::Uni),
				res = conn.accept_bi() => res.map(|(s, r)| FirstEvent::<C>::Bi(s, r)),
				res = conn.read_datagram() => res.map(FirstEvent::<C>::Datagram),
			}
		}) => r,
	};
	let first = match first {
		Ok(Ok(ev)) => ev,
		Ok(Err(e)) => {
			tracing::debug!("connection from {} closed before first event: {e:?}", remote_addr);
			return;
		}
		Err(_) => {
			// Nothing within the window: classification is impossible, so fall back
			// to the masquerade (a silent prober still sees a web server) or close.
			return dispatch_masquerade(conn, masq.as_ref(), None, None, remote_addr, cancel).await;
		}
	};

	let tuic_first: TuicFirst<C> = match first {
		FirstEvent::Uni(mut recv) => {
			let Some(prefix) = read_prefix(&mut recv).await else { return };
			let recv = wind_quic::PrefixedRecv::new(bytes::Bytes::copy_from_slice(&prefix), recv);
			if is_tuic_prefix(prefix) {
				TuicFirst::Uni(recv)
			} else {
				return dispatch_masquerade(conn, masq.as_ref(), Some(recv), None, remote_addr, cancel).await;
			}
		}
		FirstEvent::Bi(send, mut recv) => {
			let Some(prefix) = read_prefix(&mut recv).await else { return };
			let recv = wind_quic::PrefixedRecv::new(bytes::Bytes::copy_from_slice(&prefix), recv);
			if is_tuic_prefix(prefix) {
				TuicFirst::Bi(send, recv)
			} else {
				return dispatch_masquerade(conn, masq.as_ref(), None, Some((send, recv)), remote_addr, cancel).await;
			}
		}
		FirstEvent::Datagram(dg) => {
			if dg.len() >= 2 && is_tuic_prefix([dg[0], dg[1]]) {
				TuicFirst::Datagram(dg)
			} else {
				return dispatch_masquerade(conn, masq.as_ref(), None, None, remote_addr, cancel).await;
			}
		}
	};

	let udp_root_cancel = cancel.child_token();

	// Eviction listener fires for both explicit `remove()` (via Dissociate) and
	// capacity/LRU pressure. Cancel the session's token so the bridge tasks
	// unstick from their channel waits and shut down promptly.
	let eviction_cancel = move |_k: Arc<u16>, v: UdpSession<C>, _cause| -> moka::notification::ListenerFuture {
		Box::pin(async move {
			v.cancel.cancel();
		})
	};
	let udp_sessions = Cache::builder()
		.max_capacity(MAX_UDP_SESSIONS_PER_CONN)
		.async_eviction_listener(eviction_cancel)
		.build();

	let connection = Arc::new(InboundCtx {
		conn,
		uuid: ArcSwapOption::empty(),
		auth_notify: Arc::new(Notify::new()),
		users,
		auth_timeout,
		udp_sessions,
		udp_root_cancel,
	});

	// Authentication timeout: close the connection if no UUID is set in time.
	{
		let conn_auth = connection.clone();
		let auth_cancel = cancel.clone();
		tokio::spawn(
			async move {
				tokio::select! {
					_ = tokio::time::sleep(auth_timeout) => {
						if conn_auth.uuid.load().is_none() {
							warn!("Connection from {} authentication timeout", remote_addr);
							conn_auth.conn.close(0, b"auth timeout");
						}
					}
					_ = auth_cancel.cancelled() => {}
					_ = conn_auth.conn.closed() => {}
				}
			}
			.in_current_span(),
		);
	}

	// One cancellation token shared by all acceptor tasks; fired after the
	// parent loop exits so `InboundCtx` (with its per-connection UDP session
	// cache) is dropped instead of leaking until server shutdown.
	let acceptor_cancel = cancel.child_token();

	// Datagram acceptor. Pre-auth datagrams are handled inline (serially) so an
	// unauthenticated peer can't spawn unbounded tasks parked on `auth_notify`;
	// once authed, each datagram is dispatched in parallel so a slow outbound
	// queue can't block the read loop.
	{
		let conn = connection.clone();
		let cb = callback.clone();
		let dg_cancel = acceptor_cancel.clone();
		tokio::spawn(
			async move {
				acceptor_loop(
					dg_cancel,
					"Read datagram",
					|| conn.conn.read_datagram(),
					|datagram| {
						let conn = conn.clone();
						let cb = cb.clone();
						async move {
							if conn.uuid.load().is_some() {
								tokio::spawn(
									spawn_logged("Datagram", handle_datagram(conn, datagram, cb))
										.instrument(tracing::debug_span!("datagram")),
								);
							} else if let Err(e) = handle_datagram(conn, datagram, cb).await {
								error!("Datagram error: {e:?}");
							}
						}
					},
				)
				.await;
			}
			.in_current_span(),
		);
	}

	// Uni stream acceptor.
	{
		let conn = connection.clone();
		let cb = callback.clone();
		let uni_cancel = acceptor_cancel.clone();
		tokio::spawn(
			async move {
				acceptor_loop(
					uni_cancel,
					"Accept uni",
					|| conn.conn.accept_uni(),
					|recv| {
						let conn = conn.clone();
						let cb = cb.clone();
						async move {
							tokio::spawn(
								spawn_logged("Uni stream", handle_uni_stream(conn, recv, cb))
									.instrument(tracing::debug_span!("uni_stream")),
							);
						}
					},
				)
				.await;
			}
			.in_current_span(),
		);
	}

	// Bi stream acceptor.
	{
		let conn = connection.clone();
		let cb = callback.clone();
		let bi_cancel = acceptor_cancel.clone();
		tokio::spawn(
			async move {
				acceptor_loop(
					bi_cancel,
					"Accept bi",
					|| conn.conn.accept_bi(),
					|(send, recv)| {
						let conn = conn.clone();
						let cb = cb.clone();
						async move {
							tokio::spawn(
								spawn_logged("Bi stream", handle_bi_stream(conn, send, recv, cb))
									.instrument(tracing::debug_span!("bi_stream")),
							);
						}
					},
				)
				.await;
			}
			.in_current_span(),
		);
	}

	// Process the first event already consumed during classification (with any
	// peeked header bytes replayed). Subsequent events are handled by the acceptor
	// loops above.
	{
		let conn = connection.clone();
		let cb = callback.clone();
		match tuic_first {
			TuicFirst::Uni(recv) => {
				tokio::spawn(
					spawn_logged("Uni stream", handle_uni_stream(conn, recv, cb))
						.instrument(tracing::debug_span!("uni_stream")),
				);
			}
			TuicFirst::Bi(send, recv) => {
				tokio::spawn(
					spawn_logged("Bi stream", handle_bi_stream(conn, send, recv, cb))
						.instrument(tracing::debug_span!("bi_stream")),
				);
			}
			TuicFirst::Datagram(dg) => {
				tokio::spawn(
					spawn_logged("Datagram", handle_datagram(conn, dg, cb)).instrument(tracing::debug_span!("datagram")),
				);
			}
		}
	}

	// Exit on either server shutdown or peer disconnect.
	tokio::select! {
		_ = cancel.cancelled() => {
			connection.conn.close(0, b"server shutdown");
			info!("Connection from {} closed by server shutdown", remote_addr);
		}
		_ = connection.conn.closed() => {
			info!("Connection from {} closed", remote_addr);
		}
	}
	acceptor_cancel.cancel();
}

async fn handle_uni_stream<C: QuicConnection, CB: InboundCallback>(
	ctx: Arc<InboundCtx<C>>,
	mut recv: impl AsyncRead + Unpin + Send + 'static,
	callback: CB,
) -> eyre::Result<()> {
	let mut header_buf = [0u8; 2];
	recv.read_exact(&mut header_buf)
		.await
		.map_err(|e| eyre::eyre!("Failed to read uni stream header: {}", e))?;
	let header = crate::proto::decode_header(&mut &header_buf[..], "uni stream")?;

	match header.command {
		CmdType::Auth => {
			let mut body = [0u8; 16 + 32];
			recv.read_exact(&mut body)
				.await
				.map_err(|e| eyre::eyre!("Failed to read auth body: {}", e))?;
			let cmd = crate::proto::decode_command(CmdType::Auth, &mut &body[..], "uni stream")?;
			if let Command::Auth { uuid, token } = cmd {
				handle_auth(&ctx, uuid, token).await?;
			}
		}
		cmd_type => {
			if !ensure_authed(&ctx).await {
				warn!(
					command = ?cmd_type,
					"Uni stream rejected: not authenticated within {:?}",
					ctx.auth_timeout
				);
				return Ok(());
			}

			match cmd_type {
				CmdType::Packet => {
					let mut cmd_body = [0u8; 8];
					recv.read_exact(&mut cmd_body)
						.await
						.map_err(|e| eyre::eyre!("Failed to read packet command: {}", e))?;
					let cmd = crate::proto::decode_command(CmdType::Packet, &mut &cmd_body[..], "uni stream")?;
					let Command::Packet {
						assoc_id,
						pkt_id,
						frag_total,
						frag_id,
						size,
					} = cmd
					else {
						unreachable!("decode_command(Packet, ..) must return Command::Packet");
					};

					// Read address (capped at ~258 bytes).
					let addr = read_address_exact(&mut recv)
						.await
						.wrap_err("Failed to read uni stream packet address")?;

					// Payload bounded by u16 size (≤ 65535).
					let mut payload = vec![0u8; size as usize];
					if size > 0 {
						recv.read_exact(&mut payload)
							.await
							.map_err(|e| eyre::eyre!("Failed to read packet payload: {}", e))?;
					}
					let payload = bytes::Bytes::from(payload);

					let target_addr = match crate::proto::address_to_target(addr) {
						Ok(t) => t,
						Err(_) => wind_core::types::TargetAddr::IPv4(std::net::Ipv4Addr::UNSPECIFIED, 0),
					};
					handle_udp_packet(&ctx, assoc_id, pkt_id, frag_total, frag_id, target_addr, payload, &callback).await?;
				}
				CmdType::Dissociate => {
					let mut body = [0u8; 2];
					recv.read_exact(&mut body)
						.await
						.map_err(|e| eyre::eyre!("Failed to read dissociate body: {}", e))?;
					let cmd = crate::proto::decode_command(CmdType::Dissociate, &mut &body[..], "uni stream")?;
					if let Command::Dissociate { assoc_id } = cmd {
						handle_dissociate(&ctx, assoc_id).await?;
					}
				}
				CmdType::Heartbeat => {
					tracing::trace!("Received heartbeat from {:?}", ctx.uuid.load());
				}
				other => {
					warn!("Unexpected command on uni stream: {:?}", other);
				}
			}
		}
	}

	Ok(())
}

async fn handle_bi_stream<C: QuicConnection, CB: InboundCallback>(
	connection: Arc<InboundCtx<C>>,
	send: C::SendStream,
	mut recv: impl AsyncRead + Unpin + Send + 'static,
	callback: CB,
) -> eyre::Result<()> {
	if !ensure_authed(&connection).await {
		warn!("Bi stream rejected: not authenticated within {:?}", connection.auth_timeout);
		return Ok(());
	}

	let mut header_buf = [0u8; 2];
	recv.read_exact(&mut header_buf)
		.await
		.map_err(|e| eyre::eyre!("Failed to read header: {}", e))?;
	let mut buf = &header_buf[..];

	let header = crate::proto::decode_header(&mut buf, "bi stream")?;

	match header.command {
		CmdType::Connect => {
			let _cmd = crate::proto::decode_command(CmdType::Connect, &mut [].as_ref(), "bi stream")?;

			let addr = read_address_exact(&mut recv)
				.await
				.wrap_err("Failed to read connect address")?;

			let target_addr = crate::proto::address_to_target(addr)?;

			info!(target = %target_addr, "TCP connect");

			// Join the recv/send halves into one duplex stream for the relay.
			let stream = tokio::io::join(recv, send);

			callback.handle_tcpstream(target_addr, stream).await?;
		}
		_ => {
			warn!("Unexpected command on bi stream: {:?}", header.command);
		}
	}

	Ok(())
}

async fn handle_datagram<C: QuicConnection, CB: InboundCallback>(
	connection: Arc<InboundCtx<C>>,
	data: bytes::Bytes,
	callback: CB,
) -> eyre::Result<()> {
	if !ensure_authed(&connection).await {
		warn!("Datagram rejected: not authenticated within {:?}", connection.auth_timeout);
		return Ok(());
	}

	let mut buf = data;

	let header = crate::proto::decode_header(&mut buf, "datagram")?;

	match header.command {
		CmdType::Packet => {
			let cmd = crate::proto::decode_command(CmdType::Packet, &mut buf, "datagram")?;

			if let Command::Packet {
				assoc_id,
				pkt_id,
				frag_total,
				frag_id,
				size,
			} = cmd
			{
				let addr = crate::proto::decode_address(&mut buf, "datagram packet")?;
				if buf.len() < size as usize {
					return Err(eyre::eyre!("datagram payload truncated: need {}, have {}", size, buf.len()));
				}
				let payload = buf.split_to(size as usize);

				let target_addr = match crate::proto::address_to_target(addr) {
					Ok(t) => t,
					Err(_) => wind_core::types::TargetAddr::IPv4(std::net::Ipv4Addr::UNSPECIFIED, 0),
				};

				tracing::debug!(
					assoc_id,
					pkt_id,
					frag = format_args!("{}/{}", frag_id, frag_total),
					target = %target_addr,
					payload_len = payload.len(),
					"UDP datagram received",
				);

				handle_udp_packet(
					&connection,
					assoc_id,
					pkt_id,
					frag_total,
					frag_id,
					target_addr,
					payload,
					&callback,
				)
				.await?;
			}
		}
		CmdType::Heartbeat => {
			tracing::trace!("UDP heartbeat received");
		}
		other => {
			tracing::debug!(command = ?other, "unexpected datagram command");
		}
	}

	Ok(())
}

async fn handle_auth<C: QuicConnection>(connection: &InboundCtx<C>, uuid: Uuid, token: [u8; 32]) -> eyre::Result<()> {
	// Look the user up, but never short-circuit on an unknown UUID — that would
	// give an attacker both a timing oracle (skipped keying-material export) and
	// an error-message oracle that reveals whether a UUID exists. Always run the
	// export against either the real password or a fixed dummy and a constant-time
	// comparison; both failure paths return the same generic error.
	const DUMMY_PASSWORD: &[u8] = b"\x00\x00\x00\x00\x00\x00\x00\x00";
	let (password_bytes, user_known) = match connection.users.get(&uuid) {
		Some(pw) => (pw.as_bytes(), true),
		None => (DUMMY_PASSWORD, false),
	};

	let mut expected_token = [0u8; 32];
	let export_ok = connection
		.conn
		.export_keying_material(&mut expected_token, uuid.as_bytes(), password_bytes)
		.await
		.is_ok();

	// Constant-time comparison: never short-circuit on first differing byte.
	let mut diff: u8 = 0;
	for (a, b) in token.iter().zip(expected_token.iter()) {
		diff |= a ^ b;
	}
	let token_ok = diff == 0;

	if !(user_known && export_ok && token_ok) {
		// Single generic error for "unknown user", "bad token", and "export
		// failed" — do not leak which one triggered.
		return Err(eyre::eyre!("Invalid authentication"));
	}

	connection.uuid.store(Some(Arc::new(uuid)));
	connection.auth_notify.notify_waiters();
	info!(uuid = %uuid, "authenticated");

	Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_udp_packet<C: QuicConnection, CB: InboundCallback>(
	ctx: &Arc<InboundCtx<C>>,
	assoc_id: u16,
	pkt_id: u16,
	frag_total: u8,
	frag_id: u8,
	target_addr: wind_core::types::TargetAddr,
	payload: bytes::Bytes,
	callback: &CB,
) -> eyre::Result<()> {
	if frag_total == 0 {
		tracing::debug!(assoc_id, pkt_id, "dropping packet with frag_total=0");
		return Ok(());
	}

	let tuic_stream = get_or_create_session(ctx, assoc_id, callback).await?;

	if frag_total == 1 {
		tracing::trace!(assoc_id, pkt_id, target = %target_addr, len = payload.len(), "UDP packet → outbound");
		tuic_stream
			.receive_packet(UdpPacket {
				source: None,
				target: target_addr,
				payload,
			})
			.await?;
	} else if let Some(complete) = tuic_stream
		.process_fragment(assoc_id, pkt_id, frag_total, frag_id, payload, None, target_addr)
		.await
	{
		tracing::debug!(assoc_id, pkt_id, frag_total, target = %complete.target, len = complete.payload.len(), "UDP packet reassembled → outbound");
		tuic_stream.receive_packet(complete).await?;
	}

	Ok(())
}

/// Get an existing UDP session for `assoc_id` or create a new one.
async fn get_or_create_session<C: QuicConnection, CB: InboundCallback>(
	ctx: &Arc<InboundCtx<C>>,
	assoc_id: u16,
	callback: &CB,
) -> eyre::Result<Arc<UdpStream<C>>> {
	if let Some(session) = ctx.udp_sessions.get(&assoc_id).await {
		return Ok(session.tuic_stream.clone());
	}

	let cb = callback.clone();
	let conn = ctx.conn.clone();
	let session_cancel = ctx.udp_root_cancel.child_token();
	let session = ctx
		.udp_sessions
		.entry(assoc_id)
		.or_insert_with(async {
			info!("Creating new UDP session for assoc_id {}", assoc_id);

			let (reassembled_tx, reassembled_rx) = crossfire::mpmc::bounded_async::<UdpPacket>(128);

			let (to_outbound_tx, to_outbound_rx) = mpsc::channel::<UdpPacket>(100);
			let (from_outbound_tx, mut from_outbound_rx) = mpsc::channel::<UdpPacket>(100);

			let tuic_stream = Arc::new(UdpStream::new(conn, assoc_id, reassembled_tx));

			let outbound_stream = CoreUdpStream {
				tx: from_outbound_tx,
				rx: to_outbound_rx,
			};

			// Bridge reassembled packets -> outbound with backpressure.
			let cancel_a = session_cancel.clone();
			tokio::spawn(
				async move {
					loop {
						tokio::select! {
							biased;
							_ = cancel_a.cancelled() => break,
							res = reassembled_rx.recv() => {
								let packet = match res {
									Ok(p) => p,
									Err(_) => break,
								};
								tokio::select! {
									_ = cancel_a.cancelled() => break,
									send_res = tokio::time::timeout(Duration::from_secs(5), to_outbound_tx.send(packet)) => {
										match send_res {
											Ok(Ok(())) => {}
											Ok(Err(mpsc::error::SendError(_))) => break,
											Err(_) => {
												warn!("UDP outbound queue full (assoc {}), dropping packet after 5s", assoc_id);
											}
										}
									}
								}
							}
						}
					}
				}
				.in_current_span(),
			);

			{
				let response_stream = tuic_stream.clone();
				let cancel_b = session_cancel.clone();
				tokio::spawn(
					async move {
						loop {
							tokio::select! {
								biased;
								_ = cancel_b.cancelled() => break,
								maybe_packet = from_outbound_rx.recv() => {
									let Some(packet) = maybe_packet else { break };
									if let Err(e) = response_stream.send_packet(packet).await {
										warn!("Failed to send UDP response (assoc {}): {}", assoc_id, e);
										break;
									}
								}
							}
						}
					}
					.in_current_span(),
				);
			}

			{
				let cancel_c = session_cancel.clone();
				tokio::spawn(
					async move {
						// `handle_udpstream` typically runs forever; race the
						// session-cancel token so it exits with the rest of the
						// session instead of holding the callback's resources
						// hostage after eviction/dissociate.
						tokio::select! {
							_ = cancel_c.cancelled() => {}
							res = cb.handle_udpstream(outbound_stream) => {
								if let Err(e) = res {
									error!("UDP stream handler error (assoc {}): {}", assoc_id, e);
								}
							}
						}
					}
					.in_current_span(),
				);
			}

			UdpSession {
				tuic_stream,
				cancel: session_cancel,
			}
		})
		.await;

	Ok(session.into_value().tuic_stream.clone())
}

async fn read_address_exact<R: AsyncRead + Unpin>(recv: &mut R) -> eyre::Result<crate::proto::Address> {
	let mut type_byte = [0u8; 1];
	recv.read_exact(&mut type_byte)
		.await
		.map_err(|e| eyre::eyre!("Failed to read address type: {}", e))?;

	match type_byte[0] {
		0xFF => Ok(crate::proto::Address::None),
		0x01 => {
			let mut ip_bytes = [0u8; 4];
			recv.read_exact(&mut ip_bytes)
				.await
				.map_err(|e| eyre::eyre!("Failed to read IPv4 address: {}", e))?;
			let mut port_buf = [0u8; 2];
			recv.read_exact(&mut port_buf)
				.await
				.map_err(|e| eyre::eyre!("Failed to read IPv4 port: {}", e))?;
			Ok(crate::proto::Address::IPv4(
				std::net::Ipv4Addr::from(ip_bytes),
				u16::from_be_bytes(port_buf),
			))
		}
		0x02 => {
			let mut ip_bytes = [0u8; 16];
			recv.read_exact(&mut ip_bytes)
				.await
				.map_err(|e| eyre::eyre!("Failed to read IPv6 address: {}", e))?;
			let mut port_buf = [0u8; 2];
			recv.read_exact(&mut port_buf)
				.await
				.map_err(|e| eyre::eyre!("Failed to read IPv6 port: {}", e))?;
			Ok(crate::proto::Address::IPv6(
				std::net::Ipv6Addr::from(ip_bytes),
				u16::from_be_bytes(port_buf),
			))
		}
		0x00 => {
			// AddressType::Domain — 1-byte length + <length> bytes + 2-byte port
			let mut len_byte = [0u8; 1];
			recv.read_exact(&mut len_byte)
				.await
				.map_err(|e| eyre::eyre!("Failed to read domain length: {}", e))?;
			let domain_len = len_byte[0] as usize;

			let mut domain = vec![0u8; domain_len];
			recv.read_exact(&mut domain)
				.await
				.map_err(|e| eyre::eyre!("Failed to read domain address: {}", e))?;

			let mut port_buf = [0u8; 2];
			recv.read_exact(&mut port_buf)
				.await
				.map_err(|e| eyre::eyre!("Failed to read domain port: {}", e))?;
			let port = u16::from_be_bytes(port_buf);

			let domain_str = String::from_utf8(domain).map_err(|_| eyre::eyre!("Invalid UTF-8 domain address"))?;
			Ok(crate::proto::Address::Domain(domain_str, port))
		}
		t => Err(eyre::eyre!("Unknown address type byte 0x{:02x}", t)),
	}
}

/// Handle UDP dissociate
async fn handle_dissociate<C: QuicConnection>(connection: &InboundCtx<C>, assoc_id: u16) -> eyre::Result<()> {
	connection.udp_sessions.remove(&assoc_id).await;
	info!("Dissociated UDP session {}", assoc_id);
	Ok(())
}

//! Session outcomes and heartbeat transitions shared by both QUIC backends.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Buf;
use moka::future::Cache;
use tokio::io::AsyncReadExt as _;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument as _, info, warn};
use wind_core::{AppContext, types::TargetAddr};
use wind_quic::QuicConnection;

use super::ClientTaskExt;
use crate::proto::{ClientProtoExt, UdpStream as TuicUdpStream};

/// Upper bound on a single TUIC UDP command frame read from a uni stream:
/// header (2) + command (8) + longest address (259) + max payload (`u16`).
const MAX_PACKET_FRAME: usize = 10 + 259 + u16::MAX as usize;

#[derive(Debug, PartialEq, Eq)]
enum SessionEnd {
	Shutdown,
	Lost,
}

/// The supervisor closes the old connection before it may publish a
/// replacement.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SessionTransition {
	Shutdown,
	StopAfterLoss,
	Reconnect,
}

impl SessionTransition {
	fn decide(end: SessionEnd, shutting_down: bool, reconnect: bool) -> Self {
		match end {
			SessionEnd::Shutdown => Self::Shutdown,
			SessionEnd::Lost if shutting_down => Self::Shutdown,
			SessionEnd::Lost if reconnect => Self::Reconnect,
			SessionEnd::Lost => Self::StopAfterLoss,
		}
	}
}

/// Run the accept loops and stop all session children before allowing a
/// reconnect.
pub(crate) async fn run_session<C: QuicConnection>(
	ctx: &Arc<AppContext>,
	conn: &C,
	udp_session: &Cache<u16, Arc<TuicUdpStream<C>>>,
	heartbeat: Duration,
	shutdown: &CancellationToken,
	reconnect: bool,
	peer: SocketAddr,
) -> SessionTransition {
	let end = {
		let session = shutdown.child_token();
		let _stop_children = session.clone().drop_guard();
		poll_session(ctx, conn, udp_session, heartbeat, session, shutdown).await
	};
	let end = match end {
		Ok(end) => end,
		Err(error) => {
			warn!(target: "tuic_out", %peer, "Session ended with error: {error:?}");
			SessionEnd::Lost
		}
	};
	let transition = SessionTransition::decide(end, shutdown.is_cancelled(), reconnect);
	let reason: &[u8] = match transition {
		SessionTransition::Shutdown => b"client shutdown",
		SessionTransition::StopAfterLoss => {
			warn!(target: "tuic_out", %peer, "Reconnect disabled; connection will not be re-established");
			b"client connection lost"
		}
		SessionTransition::Reconnect => {
			warn!(target: "tuic_out", %peer, "Connection lost; attempting to reconnect");
			b"reconnecting"
		}
	};
	conn.close(0, reason);
	transition
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Heartbeat {
	Healthy,
	Retrying(u8),
	Lost,
}

impl Heartbeat {
	/// A successful heartbeat clears the streak. The third consecutive
	/// failure ends the session and lets its supervisor decide whether to
	/// retry.
	fn observe(self, result: eyre::Result<()>) -> Self {
		const LIMIT: u8 = 3;
		let previous = match self {
			Self::Healthy => 0,
			Self::Retrying(failures) => failures,
			Self::Lost => return Self::Lost,
		};
		match result {
			Ok(()) => {
				if previous > 0 {
					info!(target: "tuic_out", "Heartbeat succeeded after {previous} failures");
				}
				Self::Healthy
			}
			Err(error) => {
				let failures = previous.saturating_add(1);
				info!(target: "tuic_out", "Heartbeat failed ({failures}/{LIMIT}): {error}");
				if failures >= LIMIT {
					Self::Lost
				} else {
					Self::Retrying(failures)
				}
			}
		}
	}
}

/// Drive one connection's heartbeat and incoming-stream handling until the
/// connection drops, heartbeats fail repeatedly, or shutdown fires.
async fn poll_session<C: QuicConnection>(
	ctx: &Arc<AppContext>,
	conn: &C,
	udp_session: &Cache<u16, Arc<TuicUdpStream<C>>>,
	heartbeat_interval: Duration,
	session_cancel: CancellationToken,
	shutdown: &CancellationToken,
) -> eyre::Result<SessionEnd> {
	let (mut datagram_rx, mut bi_rx, mut uni_rx) = conn.handle_incoming(ctx.clone(), session_cancel.clone()).await?;

	let mut hb_interval = tokio::time::interval(heartbeat_interval);
	let mut heartbeat = Heartbeat::Healthy;
	hb_interval.tick().await;

	loop {
		tokio::select! {
			_ = shutdown.cancelled() => {
				info!(target: "tuic_out", "Heartbeat poll cancelled");
				return Ok(SessionEnd::Shutdown);
			}
			_ = conn.closed() => {
				info!(target: "tuic_out", "Connection closed");
				return Ok(SessionEnd::Lost);
			}
			_ = hb_interval.tick() => {
				heartbeat = heartbeat.observe(conn.send_heartbeat().await);
				if heartbeat == Heartbeat::Lost {
					return Ok(SessionEnd::Lost);
				}
			}
			Some(_) = bi_rx.recv() => {
				warn!(target: "tuic_out", "Received bi-directional stream on Outbound");
			}
			Some(buf) = datagram_rx.recv() => {
				info!(target: "tuic_out", "Received datagram: {} bytes", buf.len());
				dispatch_incoming_udp(udp_session, buf).await;
			}
			Some(mut recv) = uni_rx.recv() => {
				// QUIC relay mode delivers UDP responses on uni streams; read
				// (bounded) and feed the matching association, mirroring the
				// datagram path above.
				let udp_session = udp_session.clone();
				let read_cancel = session_cancel.clone();
				ctx.tasks.spawn(
					async move {
						let mut data = Vec::new();
						let mut limited = (&mut recv).take(MAX_PACKET_FRAME as u64);
						tokio::select! {
							_ = read_cancel.cancelled() => {}
							result = limited.read_to_end(&mut data) => match result {
								Ok(_) => dispatch_incoming_udp(&udp_session, bytes::Bytes::from(data)).await,
								Err(e) => warn!(target: "tuic_out", "Failed to read UDP stream: {e}"),
							}
						}
					}
					.in_current_span(),
				);
			}
		}
	}
}

/// Decode one incoming `Packet` command (from a datagram or a uni stream) and
/// deliver the reassembled packet to the matching UDP association.
pub(crate) async fn dispatch_incoming_udp<C: QuicConnection>(
	udp_session: &Cache<u16, Arc<TuicUdpStream<C>>>,
	mut buf: bytes::Bytes,
) {
	let header = match crate::proto::decode_header(&mut buf, "datagram") {
		Ok(h) => h,
		Err(e) => {
			warn!(target: "tuic_out", "Failed to decode header: {e}");
			return;
		}
	};

	let cmd = match crate::proto::decode_command(header.command, &mut buf, "datagram") {
		Ok(c) => c,
		Err(e) => {
			warn!(target: "tuic_out", "Failed to decode command: {e}");
			return;
		}
	};

	let crate::proto::Command::Packet {
		assoc_id,
		pkt_id,
		frag_total,
		frag_id,
		size,
	} = cmd
	else {
		warn!(target: "tuic_out", "Received non-Packet command in datagram: {cmd:?}");
		return;
	};

	let addr = match crate::proto::decode_address(&mut buf, "UDP packet") {
		Ok(a) => a,
		Err(e) => {
			warn!(target: "tuic_out", "Failed to decode address: {e}");
			return;
		}
	};

	// `size` is attacker-controlled; `copy_to_bytes` panics when
	// `size > buf.remaining()`, so validate before slicing.
	let size = size as usize;
	if buf.remaining() < size {
		warn!(
			target: "tuic_out",
			"Packet command claims {size} bytes of payload but only {} remain — dropping",
			buf.remaining()
		);
		return;
	}
	let payload = buf.copy_to_bytes(size);

	let (target, has_address) = match crate::proto::address_to_target(addr) {
		Ok(t) => (t, true),
		Err(_) => (TargetAddr::IPv4(std::net::Ipv4Addr::UNSPECIFIED, 0), false),
	};

	// `frag_id` is a raw wire byte, so widen it before the 1-based display:
	// `frag_id + 1` overflows `u8` for a peer-sent `0xFF` (panic under
	// `overflow-checks`, silent wrap to `0` in release).
	if has_address {
		info!(target: "tuic_out", "Received UDP packet: assoc={assoc_id:#06x}, pkt={pkt_id}, frag={}/{frag_total}, size={size}, target={target}",
			u16::from(frag_id) + 1);
	} else {
		info!(target: "tuic_out", "Received UDP fragment: assoc={assoc_id:#06x}, pkt={pkt_id}, frag={}/{frag_total}, size={size} (no address - non-first fragment)",
			u16::from(frag_id) + 1);
	}

	if let Some(tuic_udp_stream) = udp_session.get(&assoc_id).await {
		let complete_packet = if frag_total > 1 {
			tuic_udp_stream
				.process_fragment(assoc_id, pkt_id, frag_total, frag_id, payload, None, target)
				.await
		} else {
			Some(wind_core::udp::UdpPacket {
				source: None,
				target,
				payload,
			})
		};

		if let Some(packet) = complete_packet
			&& let Err(e) = tuic_udp_stream.receive_packet(packet).await
		{
			warn!(target: "tuic_out", "Failed to send packet to UDP session {assoc_id:#06x}: {e}");
		}
	} else {
		warn!(target: "tuic_out", "Received UDP packet for unknown association {assoc_id:#06x}");
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn shutdown_wins_over_reconnect_after_loss() {
		use SessionTransition::*;
		for enabled in [true, false] {
			assert_eq!(SessionTransition::decide(SessionEnd::Shutdown, false, enabled), Shutdown);
			assert_eq!(SessionTransition::decide(SessionEnd::Lost, true, enabled), Shutdown);
		}
		assert_eq!(SessionTransition::decide(SessionEnd::Lost, false, false), StopAfterLoss);
		assert_eq!(SessionTransition::decide(SessionEnd::Lost, false, true), Reconnect);
	}

	#[test]
	fn only_consecutive_failures_end_the_session() {
		let failed = || Err(eyre::eyre!("send failed"));
		let retry = Heartbeat::Healthy.observe(failed()).observe(failed());
		assert_eq!(retry, Heartbeat::Retrying(2));
		let recovered = retry.observe(Ok(()));
		assert_eq!(recovered, Heartbeat::Healthy);
		assert_eq!(recovered.observe(failed()), Heartbeat::Retrying(1));
		let lost = retry.observe(failed());
		assert_eq!(lost, Heartbeat::Lost);
		assert_eq!(lost.observe(Ok(())), Heartbeat::Lost);
	}
}

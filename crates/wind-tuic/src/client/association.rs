//! An association owns its slot and the connection on which it must dissociate.

use std::{
	sync::{
		Arc,
		atomic::{AtomicU16, Ordering},
	},
	time::Duration,
};

use moka::{future::Cache, ops::compute::Op};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument as _, info, warn};
use wind_core::{
	AppContext,
	udp::{UdpPacket, UdpStream as LocalStream},
};
use wind_quic::QuicConnection;

use crate::proto::{ClientProtoExt, UdpRelayMode, UdpStream, forward_remote_packet};

const ABANDONED_DISSOCIATE_GRACE: Duration = Duration::from_secs(5);

type Sessions<C> = Cache<u16, Arc<UdpStream<C>>>;

pub(crate) struct AssociationOptions {
	pub mode: UdpRelayMode,
	pub gc_interval: Duration,
	pub gc_lifetime: Duration,
}

struct RegisteredAssociation<C: QuicConnection> {
	id: u16,
	stream: Arc<UdpStream<C>>,
	connection: C,
	sessions: Sessions<C>,
}

pub(crate) async fn run<C: QuicConnection>(
	ctx: &AppContext,
	token: &CancellationToken,
	sessions: &Sessions<C>,
	counter: &AtomicU16,
	connection: C,
	options: AssociationOptions,
	local: LocalStream,
) -> eyre::Result<()> {
	let cancel = token.child_token();
	let _cancel_on_drop = cancel.clone().drop_guard();
	let shutdown = ctx.token.clone();
	let sessions = sessions.clone();
	let first = counter.fetch_add(1, Ordering::SeqCst);
	// Registration and teardown run in the same tracked task. Dropping the
	// caller cancels the relay but cannot interrupt a cache update or cleanup.
	ctx.tasks
		.spawn(
			async move {
				let (tx, rx) = mpsc::channel(256);
				let register = RegisteredAssociation::register(first, sessions, connection, tx, &options, &cancel);
				let Some(association) = register.await? else { return Ok(()) };
				tokio::select! {
					_ = cancel.cancelled() => {}
					_ = shutdown.cancelled() => {}
					_ = association.connection.closed() => {}
					_ = association.relay(local, rx, options.gc_interval) => {}
				}
				association.finish(&cancel, &shutdown).await;
				Ok(())
			}
			.in_current_span(),
		)
		.await?
}

impl<C: QuicConnection> RegisteredAssociation<C> {
	async fn register(
		first: u16,
		sessions: Sessions<C>,
		connection: C,
		tx: mpsc::Sender<UdpPacket>,
		options: &AssociationOptions,
		cancel: &CancellationToken,
	) -> eyre::Result<Option<Self>> {
		for offset in 0..=u16::MAX {
			if cancel.is_cancelled() {
				return Ok(None);
			}
			let id = first.wrapping_add(offset);
			let entry = sessions
				.entry(id)
				.or_insert_with(async {
					Arc::new(
						UdpStream::new(connection.clone(), id, tx.clone())
							.with_relay_mode(options.mode)
							.with_gc_lifetime(options.gc_lifetime),
					)
				})
				.await;
			if entry.is_fresh() {
				info!(target: "tuic_out", "Creating new UDP association: {id:#06x}");
				return Ok(Some(Self {
					id,
					stream: entry.into_value(),
					connection,
					sessions,
				}));
			}
		}
		eyre::bail!(
			"UDP association id exhausted ({} concurrent sessions on this outbound)",
			sessions.entry_count()
		)
	}

	async fn relay(&self, mut local: LocalStream, mut incoming: mpsc::Receiver<UdpPacket>, interval: Duration) {
		let id = self.id;
		let mut gc = tokio::time::interval(interval);
		gc.tick().await;
		loop {
			tokio::select! {
				packet = incoming.recv() => {
					let Some(packet) = packet else { break };
					if let Err(error) = local.tx.send(packet).await {
						warn!(target: "tuic_out", "Failed to send UDP packet to local socket (assoc {id:#06x}): {error:?}");
						break;
					}
					info!(target: "tuic_out", "Received UDP packet forward to local (assoc {id:#06x})");
				}
				packet = local.rx.recv() => {
					let Some(packet) = packet else { break };
					if forward_remote_packet(&self.stream, packet, id).await.is_break() { break }
				}
				_ = gc.tick() => self.stream.collect_garbage().await,
			}
		}
	}

	async fn finish(self, cancel: &CancellationToken, shutdown: &CancellationToken) {
		let Self {
			id,
			stream,
			connection,
			sessions,
		} = self;
		// Keep this ID reserved while queuing Dissociate on its original
		// connection. When the caller leaves, give the transport a
		// brief chance to queue the notification even if opening a uni
		// stream takes another driver poll.
		sessions
			.entry(id)
			.and_compute_with(|current| async move {
				if !current.is_some_and(|entry| Arc::ptr_eq(entry.value(), &stream)) {
					return Op::Nop;
				}
				tokio::select! {
					biased;
					result = connection.drop_udp(id) => {
						if let Err(error) = result {
							info!(target: "tuic_out", "Error dropping UDP association {id:#06x}: {error}");
						}
					}
					_ = shutdown.cancelled() => {}
					_ = async {
						cancel.cancelled().await;
						tokio::time::sleep(ABANDONED_DISSOCIATE_GRACE).await;
					} => {
						warn!(target: "tuic_out", "Timed out dropping UDP association {id:#06x}");
					}
				}
				Op::Remove
			})
			.await;
	}
}

#[cfg(all(test, feature = "server"))]
mod tests {
	use super::*;
	use crate::server::tests::DummyConn;

	fn options() -> AssociationOptions {
		AssociationOptions {
			mode: UdpRelayMode::Native,
			gc_interval: Duration::from_secs(1),
			gc_lifetime: Duration::from_secs(30),
		}
	}

	#[tokio::test]
	async fn racing_registrations_wrap_without_replacing_a_live_slot() {
		let sessions = Sessions::new(u64::from(u16::MAX) + 1);
		let (tx, _rx) = mpsc::channel(1);
		let options = options();
		let cancel = CancellationToken::new();
		let register = || {
			RegisteredAssociation::register(
				u16::MAX,
				sessions.clone(),
				DummyConn::default(),
				tx.clone(),
				&options,
				&cancel,
			)
		};
		let (one, two) = tokio::join!(register(), register());
		let (one, two) = (one.unwrap().unwrap(), two.unwrap().unwrap());
		let mut ids = [one.id, two.id];
		ids.sort();
		assert_eq!(ids, [0, u16::MAX]);
		one.finish(&cancel, &cancel).await;
		assert!(Arc::ptr_eq(&sessions.get(&two.id).await.unwrap(), &two.stream));
		two.finish(&cancel, &cancel).await;
		assert!(sessions.get(&0).await.is_none() && sessions.get(&u16::MAX).await.is_none());
	}

	#[tokio::test(start_paused = true)]
	async fn abandoned_caller_releases_its_id_when_dissociate_cannot_open_a_stream() {
		let ctx = AppContext::default();
		let sessions = Sessions::new(1);
		let started = CancellationToken::new();
		let conn = DummyConn::with_blocked_uni(started.clone());
		let (replies, _read_replies) = mpsc::channel(1);
		let (requests, rx) = mpsc::channel(1);
		drop(requests); // End the relay normally, leaving only the remote notification pending.
		let counter = AtomicU16::new(8);
		let mut owner = Box::pin(run(
			&ctx,
			&ctx.token,
			&sessions,
			&counter,
			conn,
			options(),
			LocalStream { tx: replies, rx },
		));
		tokio::select! {
			result = &mut owner => panic!("dissociation should be pending: {result:?}"),
			_ = started.cancelled() => {}
		}
		tokio::time::advance(ABANDONED_DISSOCIATE_GRACE * 2).await;
		assert!(sessions.contains_key(&8));
		drop(owner);
		ctx.tasks.close();
		tokio::time::timeout(ABANDONED_DISSOCIATE_GRACE * 2, ctx.tasks.wait())
			.await
			.unwrap();
		assert!(!sessions.contains_key(&8));
	}
}

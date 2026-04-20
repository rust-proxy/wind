use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use crossfire::{AsyncRx, spsc};
use quinn::{RecvStream, SendStream};
use tokio_util::sync::CancellationToken;
use wind_core::{AppContext, info, warn};

use crate::Error;

/// Size of the single-producer single-consumer buffer for QUIC streams.
/// Larger buffers reduce backpressure stalls on bursty workloads at the cost
/// of a small amount of extra memory per connection.
const SPSC_BUFFER_SIZE: usize = 64;

type IncomingRx = (
	AsyncRx<spsc::Array<Bytes>>,
	AsyncRx<spsc::Array<(SendStream, RecvStream)>>,
	AsyncRx<spsc::Array<RecvStream>>,
);

/// Generic helper to spawn a task that handles incoming items from a QUIC
/// connection and forwards them to a channel
async fn spawn_handler<T, F, Fut>(
	ctx: Arc<AppContext>,
	connection: quinn::Connection,
	cancel_token: CancellationToken,
	accept_fn: F,
	name: &'static str,
) -> AsyncRx<spsc::Array<T>>
where
	T: Send + Unpin + 'static,
	F: Fn(quinn::Connection) -> Fut + Send + 'static,
	Fut: std::future::Future<Output = Result<T, quinn::ConnectionError>> + Send,
{
	let (tx, rx) = spsc::bounded_async(SPSC_BUFFER_SIZE);

	ctx.tasks.spawn(async move {
		loop {
			tokio::select! {
				res = accept_fn(connection.clone()) => {
					let item = match res {
						Err(e) => {
							warn!("Connection error in {} handler: {e:?}", name);
							break;
						}
						Ok(item) => item,
					};

					info!("Accepted new {}", name);
					if let Err(e) = tx.send_timeout(item, Duration::from_secs(1)).await {
						warn!("{} channel send failed (receiver dropped or timeout): {e:?}", name);
						break;
					}
				}
				_ = cancel_token.cancelled() => {
					info!("Cancellation requested for {} task", name);
					break;
				}
			}
		}
	});

	rx
}

pub trait ClientTaskExt {
	async fn handle_incoming(&self, ctx: Arc<AppContext>, cancel_token: CancellationToken) -> Result<IncomingRx, Error>;
}

impl ClientTaskExt for quinn::Connection {
	async fn handle_incoming(&self, ctx: Arc<AppContext>, cancel_token: CancellationToken) -> Result<IncomingRx, Error> {
		// Spawn task for handling datagrams
		let datagram_rx = spawn_handler(
			ctx.clone(),
			self.clone(),
			cancel_token.clone(),
			|conn| async move { conn.read_datagram().await },
			"datagram",
		)
		.await;

		// Spawn task for handling bidirectional streams
		let bi_rx = spawn_handler(
			ctx.clone(),
			self.clone(),
			cancel_token.clone(),
			|conn| async move { conn.accept_bi().await },
			"bi-directional stream",
		)
		.await;

		// Spawn task for handling unidirectional streams
		let uni_rx = spawn_handler(
			ctx.clone(),
			self.clone(),
			cancel_token,
			|conn| async move { conn.accept_uni().await },
			"uni-directional stream",
		)
		.await;

		// Return the tuple of receivers for datagrams, bidirectional, and
		// unidirectional streams
		Ok((datagram_rx, bi_rx, uni_rx))
	}
}

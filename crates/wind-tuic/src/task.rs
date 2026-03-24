use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use crossfire::AsyncRx;
use quinn::{RecvStream, SendStream};
use tokio_util::sync::CancellationToken;
use wind_core::{AppContext, info};

use crate::Error;

/// Size of the single-producer single-consumer buffer for QUIC streams
/// This controls how many elements can be buffered in the channel
/// before backpressure is applied
const SPSC_BUFFER_SIZE: usize = 16;

type IncomingRx = (AsyncRx<Bytes>, AsyncRx<(SendStream, RecvStream)>, AsyncRx<RecvStream>);

/// Generic helper to spawn a task that handles incoming items from a QUIC connection
/// and forwards them to a channel
async fn spawn_handler<T, F, Fut>(
	ctx: Arc<AppContext>,
	connection: quinn::Connection,
	cancel_token: CancellationToken,
	accept_fn: F,
	name: &'static str,
) -> AsyncRx<T>
where
	T: Send + Unpin + 'static,
	F: Fn(quinn::Connection) -> Fut + Send + 'static,
	Fut: std::future::Future<Output = Result<T, quinn::ConnectionError>> + Send,
{
	let (tx, rx) = crossfire::spsc::bounded_async(SPSC_BUFFER_SIZE);

	ctx.tasks.spawn(async move {
		loop {
			tokio::select! {
				res = accept_fn(connection.clone()) => {
					let item = match res {
						Err(e) => unimplemented!("unhandled error {e:?}"),
						Ok(item) => item,
					};
					
					info!("Accepted new {}", name);
					if let Err(e) = tx.send_timeout(item, Duration::from_secs(1)).await {
						unimplemented!("unhandled error {e:?}");
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

//! HTTP/3 masquerade: serve non-TUIC (real HTTP/3) clients as a reverse proxy.
//!
//! When the connection classifier in [`super`] decides a peer is speaking actual
//! HTTP/3 rather than TUIC (its first stream byte isn't the TUIC version `0x05`),
//! it hands the connection here. We run a real HTTP/3 server over the
//! backend-agnostic [`wind_quic::h3_adapter`] and reverse-proxy every request to
//! a configured upstream site, relaying the response back. To an active prober
//! the server is indistinguishable from a normal HTTP/3 web server.

use std::sync::{Arc, OnceLock};

use bytes::{Buf, Bytes, BytesMut};
use http_body_util::{BodyExt as _, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::{
	client::legacy::{Client, connect::HttpConnector},
	rt::TokioExecutor,
};
use tokio_util::sync::CancellationToken;
use tracing::debug;
use wind_quic::{
	QuicConnection, QuicRecvStream,
	h3_adapter::{self, H3Conn},
};

use super::MasqueradeConfig;

/// Pooled HTTP/1.1(+TLS) client to the upstream site.
type HttpsClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Install the process-wide rustls crypto provider exactly once (mirrors
/// `wind_quic`'s `ensure_provider`).
fn ensure_provider() {
	static INSTALLED: OnceLock<()> = OnceLock::new();
	INSTALLED.get_or_init(|| {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	});
}

/// Build the upstream rustls config once (platform verifier + HTTP/1.1 ALPN).
fn build_tls() -> rustls::ClientConfig {
	use rustls_platform_verifier::BuilderVerifierExt as _;

	let provider = rustls::crypto::CryptoProvider::get_default()
		.expect("crypto provider installed by ensure_provider")
		.clone();
	let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
		.with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
		.expect("client protocol versions")
		.with_platform_verifier()
		.expect("client platform verifier")
		.with_no_client_auth();
	cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
	cfg
}

/// A shared, lazily-built reverse-proxy client. The expensive part (loading the
/// platform root store) happens once; probers are rare, so a single global client
/// is plenty.
fn shared_client() -> HttpsClient {
	static CLIENT: OnceLock<HttpsClient> = OnceLock::new();
	CLIENT
		.get_or_init(|| {
			ensure_provider();
			let https = hyper_rustls::HttpsConnectorBuilder::new()
				.with_tls_config(build_tls())
				.https_or_http()
				.enable_http1()
				.build();
			Client::builder(TokioExecutor::new()).build(https)
		})
		.clone()
}

/// The parsed upstream target (scheme + authority).
struct Upstream {
	scheme: http::uri::Scheme,
	authority: http::uri::Authority,
}

impl Upstream {
	fn parse(s: &str) -> eyre::Result<Self> {
		let uri: http::Uri = s.parse().map_err(|e| eyre::eyre!("invalid masquerade upstream URI {s:?}: {e}"))?;
		let scheme = uri.scheme().cloned().unwrap_or(http::uri::Scheme::HTTPS);
		let authority = uri
			.authority()
			.cloned()
			.ok_or_else(|| eyre::eyre!("masquerade upstream {s:?} has no host"))?;
		Ok(Self { scheme, authority })
	}
}

/// Run the HTTP/3 masquerade server over `conn`. `first_control` is the peer's
/// first stream (its peeked byte already replayed). Returns when the peer
/// disconnects or `cancel` fires.
pub async fn run_masquerade<C: QuicConnection>(
	conn: C,
	first_control: Box<dyn QuicRecvStream>,
	cfg: &MasqueradeConfig,
	cancel: CancellationToken,
) -> eyre::Result<()> {
	let upstream = Arc::new(Upstream::parse(&cfg.upstream)?);
	let client = shared_client();

	let adapter = h3_adapter::server_connection(conn, first_control);
	let mut h3conn = h3::server::builder()
		.build(adapter)
		.await
		.map_err(|e| eyre::eyre!("h3 server build failed: {e}"))?;

	loop {
		let resolver = tokio::select! {
			_ = cancel.cancelled() => break,
			res = h3conn.accept() => match res {
				Ok(Some(r)) => r,
				Ok(None) => break,
				Err(e) => {
					debug!("masquerade accept ended: {e}");
					break;
				}
			},
		};

		let up = upstream.clone();
		let cl = client.clone();
		tokio::spawn(async move {
			if let Err(e) = handle_request::<C>(resolver, up, cl).await {
				debug!("masquerade request error: {e:?}");
			}
		});
	}

	Ok(())
}

/// Resolve one HTTP/3 request, forward it to the upstream, and relay the
/// response back over the request stream.
async fn handle_request<C: QuicConnection>(
	resolver: h3::server::RequestResolver<H3Conn<C>, Bytes>,
	upstream: Arc<Upstream>,
	client: HttpsClient,
) -> eyre::Result<()> {
	let (req, mut stream) = resolver
		.resolve_request()
		.await
		.map_err(|e| eyre::eyre!("resolve_request: {e}"))?;

	// Drain the request body (usually empty for a probe's GET).
	let mut body = BytesMut::new();
	while let Some(mut chunk) = stream.recv_data().await.map_err(|e| eyre::eyre!("recv_data: {e}"))? {
		while chunk.has_remaining() {
			let c = chunk.chunk();
			body.extend_from_slice(c);
			let n = c.len();
			chunk.advance(n);
		}
	}

	let out_req = build_upstream_request(&req, body.freeze(), &upstream)?;

	match client.request(out_req).await {
		Ok(resp) => {
			let (parts, body) = resp.into_parts();
			let collected = body
				.collect()
				.await
				.map_err(|e| eyre::eyre!("reading upstream body: {e}"))?
				.to_bytes();

			let mut builder = http::Response::builder().status(parts.status);
			for (k, v) in parts.headers.iter() {
				if is_hop_by_hop(k) {
					continue;
				}
				builder = builder.header(k, v);
			}
			let response = builder.body(()).map_err(|e| eyre::eyre!("building h3 response: {e}"))?;

			stream
				.send_response(response)
				.await
				.map_err(|e| eyre::eyre!("send_response: {e}"))?;
			if !collected.is_empty() {
				stream.send_data(collected).await.map_err(|e| eyre::eyre!("send_data: {e}"))?;
			}
			stream.finish().await.map_err(|e| eyre::eyre!("finish: {e}"))?;
		}
		Err(e) => {
			// Upstream unreachable: still answer like a web server (502) rather
			// than resetting, so the masquerade holds.
			debug!("masquerade upstream request failed: {e}");
			let response = http::Response::builder()
				.status(http::StatusCode::BAD_GATEWAY)
				.body(())
				.expect("502 response is valid");
			let _ = stream.send_response(response).await;
			let _ = stream.finish().await;
		}
	}

	Ok(())
}

/// Translate the incoming HTTP/3 request into an HTTP/1.1 request to the
/// upstream: keep method + path + most headers, but point it at the upstream
/// authority and rewrite `Host`.
fn build_upstream_request(
	req: &http::Request<()>,
	body: Bytes,
	up: &Upstream,
) -> eyre::Result<http::Request<Full<Bytes>>> {
	let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
	let uri = http::Uri::builder()
		.scheme(up.scheme.clone())
		.authority(up.authority.clone())
		.path_and_query(pq)
		.build()
		.map_err(|e| eyre::eyre!("building upstream URI: {e}"))?;

	let mut builder = http::Request::builder().method(req.method()).uri(uri);
	for (k, v) in req.headers().iter() {
		if is_hop_by_hop(k) || k == http::header::HOST || k == http::header::CONTENT_LENGTH {
			continue;
		}
		builder = builder.header(k, v);
	}
	builder = builder.header(http::header::HOST, up.authority.as_str());

	builder
		.body(Full::new(body))
		.map_err(|e| eyre::eyre!("building upstream request: {e}"))
}

/// Hop-by-hop headers that must not be forwarded across a proxy (RFC 9110 §7.6.1)
/// plus framing headers HTTP/3 manages itself.
fn is_hop_by_hop(name: &http::header::HeaderName) -> bool {
	use http::header;
	*name == header::CONNECTION
		|| *name == header::TRANSFER_ENCODING
		|| *name == header::UPGRADE
		|| *name == header::TE
		|| *name == header::TRAILER
		|| *name == header::PROXY_AUTHENTICATE
		|| *name == header::PROXY_AUTHORIZATION
		|| name.as_str().eq_ignore_ascii_case("keep-alive")
}

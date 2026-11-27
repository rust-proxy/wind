//! File-backed HTTP-01 certificate provisioning and renewal via `instant-acme`.
//!
//! Unlike the resolver-based
//! [`start_acme_with_cert`](crate::start_acme_with_cert) flow (which
//! keeps a `rustls-acme` state machine running for background renewal), this
//! provisions or renews a certificate and writes the PEM
//! certificate chain and private key to disk. Backends that load TLS material
//! from file paths (e.g. the quiche/tokio-quiche QUIC listeners) consume the
//! on-disk PEMs or subscribe to complete pairs through [`watch_acme_cert`].

use std::{
	collections::HashMap,
	path::{Path, PathBuf},
	sync::Arc,
};

use axum::{
	Router,
	extract::{Path as AxumPath, State},
	http::{HeaderValue, StatusCode, header},
	response::{IntoResponse, Response},
	routing::get,
};
use eyre::{Context, Result};
use instant_acme::{
	Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, Order,
	OrderStatus, RetryPolicy,
};
use serde::{Deserialize, Serialize};
use tokio::{
	net::TcpListener,
	sync::{RwLock, watch},
};
use tracing::{debug, info, instrument, warn};
use x509_parser::pem::{Pem, parse_x509_pem};

type ChallengeMap = Arc<RwLock<HashMap<String, String>>>;

/// ACME account credentials as persisted next to the certificate key.
///
/// `instant_acme::AccountCredentials` is opaque but serializable; the directory
/// URL is stored alongside it because the credentials themselves do not expose
/// which ACME directory they belong to, and reusing a staging account against
/// production (or vice versa) would silently target the wrong server.
#[derive(Deserialize, Serialize)]
struct StoredAccount {
	directory_url: String,
	credentials: AccountCredentials,
}

/// File the account credentials are persisted to for a given key path.
///
/// The account is per certificate/key pair, so it lives next to the key file:
/// `/etc/wind/example.com.key` → `/etc/wind/example.com.account.json`.
fn account_credentials_path(key_path: &Path) -> PathBuf {
	key_path.with_extension("account.json")
}

/// Read persisted account credentials for `directory_url`.
///
/// Returns `None` when nothing is stored yet, when the stored data is
/// unreadable, or when the stored account belongs to a different ACME
/// directory; in all of those cases the caller must register a fresh account
/// (which then overwrites the file, so a damaged file heals on the next run).
/// Credentials are a private key, so the file is written owner-only on Unix
/// (see [`crate::write_key_file`]).
async fn load_stored_credentials(path: &Path, directory_url: &str) -> Option<AccountCredentials> {
	if !path.exists() {
		return None;
	}

	let raw = match tokio::fs::read_to_string(path).await {
		Ok(raw) => raw,
		Err(err) => {
			warn!(error = %err, path = %path.display(), "cannot read stored ACME account credentials, registering a new account");
			return None;
		}
	};
	let stored: StoredAccount = match serde_json::from_str(&raw) {
		Ok(stored) => stored,
		Err(err) => {
			warn!(error = %err, path = %path.display(), "stored ACME account credentials are unreadable, registering a new account");
			return None;
		}
	};

	if stored.directory_url != directory_url {
		warn!(
			stored = %stored.directory_url,
			requested = %directory_url,
			"stored ACME account belongs to a different directory, registering a new account"
		);
		return None;
	}

	Some(stored.credentials)
}

/// Persist account credentials so later runs (including renewals) reuse the
/// same account instead of registering a new one each time.
async fn store_credentials(path: &Path, directory_url: &str, credentials: AccountCredentials) -> Result<()> {
	if let Some(parent) = path.parent() {
		tokio::fs::create_dir_all(parent).await?;
	}

	let stored = StoredAccount {
		directory_url: directory_url.to_owned(),
		credentials,
	};
	let encoded = serde_json::to_vec_pretty(&stored).context("serialize ACME account credentials")?;
	crate::write_key_file(path, &encoded).await
}

/// Register a new ACME account and persist its credentials.
///
/// A failure to persist is reported but not fatal: the account already exists
/// on the server, and aborting here would only leave it orphaned.
async fn create_and_store_account(contact: &[String], directory_url: &str, credentials_path: &Path) -> Result<Account> {
	let (account, credentials) = Account::builder()?
		.create(
			&NewAccount {
				contact: &contact.iter().map(String::as_str).collect::<Vec<_>>(),
				terms_of_service_agreed: true,
				only_return_existing: false,
			},
			directory_url.to_owned(),
			None,
		)
		.await
		.context("Failed to create ACME account")?;

	if let Err(err) = store_credentials(credentials_path, directory_url, credentials).await {
		warn!(
			error = %err,
			path = %credentials_path.display(),
			"failed to persist ACME account credentials; a later run may register another account"
		);
	}

	Ok(account)
}

async fn handle_challenge(State(challenges): State<ChallengeMap>, AxumPath(token): AxumPath<String>) -> Response {
	let Some(key_auth) = challenges.read().await.get(&token).cloned() else {
		return StatusCode::NOT_FOUND.into_response();
	};
	debug!(%token, "serving challenge");
	(
		StatusCode::OK,
		[(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"))],
		key_auth,
	)
		.into_response()
}

/// Own the challenge listener until completion or cancellation of the order.
fn spawn_challenge_server(
	listener: TcpListener,
	challenges: ChallengeMap,
	shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> tokio_util::task::AbortOnDropHandle<std::io::Result<()>> {
	let app = Router::new()
		.route("/.well-known/acme-challenge/{token}", get(handle_challenge))
		.with_state(challenges);
	tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
		axum::serve(listener, app)
			.with_graceful_shutdown(async move {
				let _ = shutdown_rx.await;
			})
			.await
	}))
}

/// Completes pending HTTP-01 challenges using a short-lived server on port 80.
async fn complete_http01_challenges(order: &mut Order) -> Result<()> {
	let challenges: ChallengeMap = Arc::new(RwLock::new(HashMap::new()));
	let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

	// Bind `[::]` (dual-stack on Linux, the ACME deployment target) rather than
	// IPv4-only `0.0.0.0`: Let's Encrypt validates AAAA records over IPv6 when
	// present, and this matches the resolver flow's bind. Falls back to IPv4 if
	// the host has no IPv6 stack.
	let listener = match TcpListener::bind("[::]:80").await {
		Ok(l) => l,
		Err(_) => TcpListener::bind("0.0.0.0:80").await.context(
			"Failed to bind port 80 for ACME challenge. Ensure port 80 is open and you are running as root (or use authbind).",
		)?,
	};

	info!("HTTP-01 challenge server listening on :80");
	let server_handle = spawn_challenge_server(listener, challenges.clone(), shutdown_rx);

	let mut authorizations = order.authorizations();
	while let Some(result) = authorizations.next().await {
		let mut authz = result?;
		if authz.status == AuthorizationStatus::Valid {
			continue;
		}

		let mut challenge = authz
			.challenge(ChallengeType::Http01)
			.ok_or_else(|| eyre::eyre!("No HTTP-01 challenge found"))?;

		let token = challenge.token.to_string();
		let key_auth = challenge.key_authorization().as_str().to_string();

		// Register the response before telling Let's Encrypt the challenge is
		// ready.
		challenges.write().await.insert(token, key_auth);
		challenge.set_ready().await?;
	}

	info!("polling for order ready...");
	let status = order.poll_ready(&RetryPolicy::default()).await?;

	let _ = shutdown_tx.send(());
	// Slow HTTP peers must not keep a completed renewal alive indefinitely.
	let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server_handle).await;

	if status != OrderStatus::Ready {
		eyre::bail!("ACME order invalid or failed: {:?}", status);
	}

	Ok(())
}

pub(crate) fn cert_not_after(chain: &[u8]) -> Result<time::OffsetDateTime> {
	let (_, pem) = parse_x509_pem(chain).map_err(|e| eyre::eyre!("parsing certificate PEM: {e}"))?;
	Ok(pem.parse_x509()?.validity().not_after.to_datetime())
}

pub(crate) fn should_renew(not_after: time::OffsetDateTime, now: time::OffsetDateTime) -> bool {
	const RENEW_BEFORE_DAYS: i64 = 30;
	not_after <= now + time::Duration::days(RENEW_BEFORE_DAYS)
}

/// A complete PEM certificate chain and its corresponding private key.
/// Intentionally does not implement Debug to keep the private key out of logs.
#[derive(PartialEq, Eq)]
pub struct CertificatePem {
	pub chain: Vec<u8>,
	pub key: Vec<u8>,
}

impl CertificatePem {
	fn expiry(&self) -> Result<time::OffsetDateTime> {
		use rcgen::PublicKeyData as _;
		let mut chain = Pem::iter_from_buffer(&self.chain);
		let pem = chain.next().ok_or_else(|| eyre::eyre!("empty certificate chain"))??;
		let cert = pem.parse_x509().context("parsing certificate DER")?;
		for issuer in chain {
			issuer?.parse_x509().context("parsing intermediate certificate DER")?;
		}
		let key = rcgen::KeyPair::from_pem(std::str::from_utf8(&self.key)?).context("parsing private key")?;
		eyre::ensure!(
			cert.public_key().raw == key.subject_public_key_info(),
			"certificate/key mismatch"
		);
		Ok(cert.validity().not_after.to_datetime())
	}

	async fn cached(cert: &Path, key: &Path) -> Result<Option<(Self, time::OffsetDateTime)>> {
		let pair = tokio::try_join!(tokio::fs::read(cert), tokio::fs::read(key));
		let (chain, key) = match pair {
			Ok(pair) => pair,
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
			Err(e) => return Err(e).context("reading cached certificate/key"),
		};
		let pem = Self { chain, key };
		match pem.expiry() {
			Ok(expiry) => Ok(Some((pem, expiry))),
			Err(err) => {
				warn!(error = %err, "unusable cached certificate/key; provisioning a replacement");
				Ok(None)
			}
		}
	}
}

/// Supply an initial identity and watch for subsequent HTTP-01 renewals. A
/// still-valid cached certificate can serve traffic while an order is retried.
/// The worker checks daily and renews within 30 days of expiry. Failed checks
/// retry after one hour. Use one watcher per certificate/key path pair and
/// clone the receiver for additional consumers. Dropping the last receiver
/// cancels any pending challenge and releases its listener.
pub async fn watch_acme_cert(
	hostname: &str,
	email: Option<&str>,
	cert_path: &Path,
	key_path: &Path,
	staging: bool,
) -> Result<watch::Receiver<Arc<CertificatePem>>> {
	let cached = CertificatePem::cached(cert_path, key_path).await?;
	let now = time::OffsetDateTime::now_utc();
	let (initial, check_now) = match cached {
		Some((pem, expiry)) if expiry > now => (pem, should_renew(expiry, now)),
		_ => (issue_certificate(hostname, email, cert_path, key_path, staging).await?, false),
	};
	let (sender, receiver) = watch::channel(Arc::new(initial));
	let (hostname, email) = (hostname.to_owned(), email.map(str::to_owned));
	let (cert_path, key_path) = (cert_path.to_owned(), key_path.to_owned());
	tokio::spawn(async move {
		let refresh = || current_or_renew(&hostname, email.as_deref(), &cert_path, &key_path, staging);
		tokio::select! {
			biased;
			_ = sender.closed() => {}
			_ = renew_loop(&sender, check_now, refresh) => {}
		}
	});
	Ok(receiver)
}

const CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
const RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);

async fn renew_loop<F: Future<Output = Result<CertificatePem>>>(
	sender: &watch::Sender<Arc<CertificatePem>>,
	check_now: bool,
	refresh: impl Fn() -> F,
) {
	let mut delay = if check_now {
		std::time::Duration::ZERO
	} else {
		CHECK_INTERVAL
	};
	loop {
		tokio::time::sleep(delay).await;
		match refresh().await {
			Ok(pem) => {
				sender.send_if_modified(|current| {
					if **current == pem {
						return false;
					}
					*current = Arc::new(pem);
					true
				});
				delay = CHECK_INTERVAL;
			}
			Err(err) => {
				warn!(error = %err, "HTTP-01 renewal check failed; retrying in one hour");
				delay = RETRY_INTERVAL;
			}
		}
	}
}

/// Provision (or renew) an ACME certificate via HTTP-01, writing the PEM cert
/// chain and private key to disk. If a fresh certificate already exists on disk
/// (more than 30 days from expiry) this is a no-op.
///
/// The ACME account credentials are persisted next to `key_path` (see
/// [`account_credentials_path`]) and reused on subsequent calls, so renewals do
/// not register a new account every time. Credentials belonging to a different
/// ACME directory (staging vs. production) are ignored rather than reused.
#[instrument(name = "acme", skip_all, fields(hostname = %hostname))]
pub async fn ensure_acme_cert(
	hostname: &str,
	email: Option<&str>,
	cert_path: &Path,
	key_path: &Path,
	staging: bool,
) -> Result<()> {
	current_or_renew(hostname, email, cert_path, key_path, staging).await?;
	Ok(())
}

async fn current_or_renew(
	hostname: &str,
	email: Option<&str>,
	cert_path: &Path,
	key_path: &Path,
	staging: bool,
) -> Result<CertificatePem> {
	if let Some((pem, expiry)) = CertificatePem::cached(cert_path, key_path).await?
		&& !should_renew(expiry, time::OffsetDateTime::now_utc())
	{
		return Ok(pem);
	}
	issue_certificate(hostname, email, cert_path, key_path, staging).await
}

#[instrument(name = "acme_issue", skip_all, fields(%hostname))]
async fn issue_certificate(
	hostname: &str,
	email: Option<&str>,
	cert_path: &Path,
	key_path: &Path,
	staging: bool,
) -> Result<CertificatePem> {
	let contact: Vec<String> = email.into_iter().map(|e| format!("mailto:{e}")).collect();

	let directory_url = if staging {
		info!("using Let's Encrypt STAGING directory");
		LetsEncrypt::Staging.url().to_owned()
	} else {
		LetsEncrypt::Production.url().to_owned()
	};

	let credentials_path = account_credentials_path(key_path);
	let account = match load_stored_credentials(&credentials_path, &directory_url).await {
		Some(credentials) => match Account::builder()?.from_credentials(credentials).await {
			Ok(account) => {
				info!(path = %credentials_path.display(), "reusing stored ACME account credentials");
				account
			}
			Err(err) => {
				warn!(
					error = %err,
					path = %credentials_path.display(),
					"stored ACME account credentials are unusable, registering a new account"
				);
				create_and_store_account(&contact, &directory_url, &credentials_path).await?
			}
		},
		None => create_and_store_account(&contact, &directory_url, &credentials_path).await?,
	};

	let identifiers = vec![Identifier::Dns(hostname.to_string())];
	let mut order = account
		.new_order(&NewOrder::new(&identifiers))
		.await
		.context("Failed to create ACME order")?;

	let state = order.state();
	if !matches!(state.status, OrderStatus::Pending | OrderStatus::Ready) {
		eyre::bail!("Unexpected order state: {:?}", state.status);
	}

	if matches!(state.status, OrderStatus::Pending) {
		complete_http01_challenges(&mut order).await?;
	}

	info!("finalizing order...");
	let private_key_pem = order.finalize().await?;
	// `poll_certificate` returns the PEM-encoded certificate chain (leaf +
	// intermediates), which is required by quiche/tokio-quiche for H3.
	let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;

	let pem = CertificatePem {
		chain: cert_chain_pem.into_bytes(),
		key: private_key_pem.into_bytes(),
	};
	pem.expiry().context("invalid issued certificate/key")?;
	let (cert, key) = (cert_path.to_owned(), key_path.to_owned());
	let pem = tokio::task::spawn_blocking(move || -> Result<_> {
		persist_pair(&cert, &key, &pem)?;
		Ok(pem)
	})
	.await??;
	info!("cert issued and saved");
	Ok(pem)
}

fn persist_pair(cert: &Path, key: &Path, pem: &CertificatePem) -> Result<()> {
	let (cert_file, cert) = stage_pem(cert, &pem.chain, false)?;
	let (key_file, key) = stage_pem(key, &pem.key, true)?;
	eyre::ensure!(cert != key, "certificate and private key require distinct paths");
	let previous = match std::fs::read(&key) {
		Ok(bytes) => Some(stage_pem(&key, &bytes, true)?.0),
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
		Err(e) => return Err(e).context("backing up current private key"),
	};
	// Publish the expiry last. A failed rename restores the old key. If the
	// process dies between renames, cached() detects the mismatch on restart.
	key_file.persist(&key).context("installing renewed private key")?;
	if let Err(err) = cert_file.persist(cert) {
		match previous {
			Some(old) => {
				old.persist(key).context("restoring previous private key")?;
			}
			None => std::fs::remove_file(key).context("removing unpublished private key")?,
		}
		return Err(err).context("installing renewed certificate");
	}
	Ok(())
}

fn stage_pem(path: &Path, contents: &[u8], private: bool) -> Result<(tempfile::NamedTempFile, PathBuf)> {
	use std::io::Write as _;
	let path = if path.is_symlink() {
		path.canonicalize()?
	} else {
		path.to_owned()
	};
	let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
	std::fs::create_dir_all(dir)?;
	let path = dir
		.canonicalize()?
		.join(path.file_name().ok_or_else(|| eyre::eyre!("missing PEM filename"))?);
	let mut builder = tempfile::Builder::new();
	#[cfg(unix)]
	if !private {
		use std::os::unix::fs::PermissionsExt as _;
		let mode = match std::fs::metadata(&path) {
			Ok(meta) => meta.permissions().mode() & 0o666,
			Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0o666,
			Err(err) => return Err(err.into()),
		};
		builder.permissions(std::fs::Permissions::from_mode(mode));
	}
	#[cfg(not(unix))]
	let _ = private;
	let mut file = builder.prefix(".acme-").tempfile_in(dir)?;
	file.write_all(contents)?;
	file.as_file().sync_all()?;
	Ok((file, path))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn failed_certificate_install_restores_the_old_key() -> Result<()> {
		let dir = tempfile::tempdir()?;
		let key = dir.path().join("key.pem");
		let cert = dir.path().join("cert.pem");
		let pair = CertificatePem {
			key: b"new key".to_vec(),
			chain: b"new cert".to_vec(),
		};
		std::fs::create_dir(&cert)?; // Cannot replace a directory with a certificate file.
		assert!(persist_pair(&cert, &key, &pair).is_err());
		assert!(!key.exists());
		std::fs::write(&key, b"previous key")?;
		assert!(persist_pair(&cert, &key, &pair).is_err());
		assert_eq!(std::fs::read(&key)?, b"previous key");
		std::fs::remove_dir(&cert)?;
		persist_pair(&cert, &key, &pair)?;
		assert_eq!(std::fs::read(cert)?, pair.chain);
		assert_eq!(std::fs::read(key)?, pair.key);
		Ok(())
	}

	#[tokio::test(start_paused = true)]
	async fn renewal_retries_without_replacing_the_live_pair_and_skips_unchanged_pairs() {
		use std::sync::atomic::{AtomicUsize, Ordering};
		let pair = |generation| CertificatePem {
			chain: vec![generation],
			key: vec![generation],
		};
		let (sender, mut receiver) = watch::channel(Arc::new(pair(1)));
		let attempts = Arc::new(AtomicUsize::new(0));
		let count = attempts.clone();
		let task = tokio::spawn(async move {
			renew_loop(&sender, true, || {
				std::future::ready(match count.fetch_add(1, Ordering::SeqCst) {
					0 => Err(eyre::eyre!("temporary CA failure")),
					_ => Ok(pair(2)),
				})
			})
			.await;
		});
		tokio::task::yield_now().await;
		tokio::time::advance(std::time::Duration::from_secs(1)).await;
		tokio::task::yield_now().await;
		assert_eq!(attempts.load(Ordering::SeqCst), 1);
		assert!(!receiver.has_changed().unwrap());
		assert_eq!(receiver.borrow().key, [1]);
		tokio::time::advance(RETRY_INTERVAL).await;
		receiver.changed().await.unwrap();
		assert_eq!(receiver.borrow_and_update().chain, [2]);
		tokio::time::advance(CHECK_INTERVAL).await;
		tokio::task::yield_now().await;
		assert_eq!(attempts.load(Ordering::SeqCst), 3);
		assert!(!receiver.has_changed().unwrap());
		task.abort();
	}

	#[tokio::test]
	async fn watcher_seeds_from_a_matching_pair_and_releases_it_on_drop() -> Result<()> {
		let dir = tempfile::tempdir()?;
		let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
		crate::selfsigned::ensure_self_signed_cert_files("localhost", &cert, &key).await?;
		let receiver = watch_acme_cert("localhost", None, &cert, &key, true).await?;
		let initial = Arc::downgrade(&receiver.borrow());
		let disk = tokio::fs::read(&cert).await?;
		assert_eq!(receiver.borrow().chain, disk);
		drop(receiver);
		tokio::task::yield_now().await;
		assert!(initial.upgrade().is_none());
		let mut broken_chain = disk.clone();
		broken_chain.extend_from_slice(b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n");
		tokio::fs::write(&cert, broken_chain).await?;
		assert!(CertificatePem::cached(&cert, &key).await?.is_none());
		tokio::fs::write(&cert, disk).await?;
		tokio::fs::write(&key, rcgen::KeyPair::generate()?.serialize_pem()).await?;
		assert!(CertificatePem::cached(&cert, &key).await?.is_none());
		Ok(())
	}

	#[tokio::test]
	async fn dropping_challenge_task_releases_listener() -> Result<()> {
		let listener = TcpListener::bind("127.0.0.1:0").await?;
		let addr = listener.local_addr()?;
		let (_shutdown, receiver) = tokio::sync::oneshot::channel();
		let task = spawn_challenge_server(listener, Arc::new(RwLock::new(HashMap::new())), receiver);
		let _peer = tokio::net::TcpStream::connect(addr).await?;
		drop(task);
		tokio::time::timeout(std::time::Duration::from_secs(2), async {
			loop {
				if let Ok(listener) = TcpListener::bind(addr).await {
					break listener;
				}
				tokio::task::yield_now().await;
			}
		})
		.await?;
		Ok(())
	}

	#[test]
	fn renews_when_certificate_expires_within_thirty_days() {
		let now = time::OffsetDateTime::now_utc();
		assert!(should_renew(now + time::Duration::days(10), now));
		assert!(should_renew(now + time::Duration::days(30), now));
		assert!(should_renew(now - time::Duration::days(1), now));
		assert!(!should_renew(now + time::Duration::days(45), now));
	}

	#[tokio::test]
	async fn expiring_cached_certificate_is_available_before_background_issuance() -> Result<()> {
		let mut params = rcgen::CertificateParams::new(vec!["example.test".to_owned()])?;
		params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(2);
		let key = rcgen::KeyPair::generate()?;
		let pem = CertificatePem {
			chain: params.self_signed(&key)?.pem().into_bytes(),
			key: key.serialize_pem().into_bytes(),
		};
		let dir = tempfile::tempdir()?;
		let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
		persist_pair(&cert, &key, &pem)?;
		let receiver = watch_acme_cert("example.test", None, &cert, &key, true).await?;
		assert_eq!(receiver.borrow().chain, pem.chain);
		Ok(())
	}

	#[test]
	fn parses_certificate_not_after_from_pem() {
		let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(42);
		let mut params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
		params.not_after = not_after;
		let key_pair = rcgen::KeyPair::generate().unwrap();
		let cert = params.self_signed(&key_pair).unwrap();

		let pem = CertificatePem {
			chain: cert.pem().into_bytes(),
			key: key_pair.serialize_pem().into_bytes(),
		};
		let parsed = pem.expiry().unwrap();
		assert_eq!(parsed.unix_timestamp(), not_after.unix_timestamp());
	}

	/// Synthetic credentials shaped exactly like `AccountCredentials`
	/// serializes (base64url PKCS#8 key). Deserialization only base64-decodes
	/// the key, so the account-reuse path is covered without valid key material
	/// and without contacting a real CA.
	const SYNTHETIC_CREDENTIALS: &str =
		r#"{"id":"https://acme.test/acct/1","key_pkcs8":"AAECAwQFBgcICQ","directory":"https://acme.test/directory"}"#;

	const STAGING_DIRECTORY: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
	const PRODUCTION_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

	fn synthetic_credentials() -> AccountCredentials {
		serde_json::from_str(SYNTHETIC_CREDENTIALS).expect("synthetic credentials deserialize")
	}

	fn unique_temp_dir(label: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!("wind-acme-http01-{}-{label}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		dir
	}

	#[test]
	fn account_credentials_path_sits_next_to_the_key_file() {
		assert_eq!(
			account_credentials_path(Path::new("/etc/wind/example.com.key")),
			PathBuf::from("/etc/wind/example.com.account.json")
		);
		assert_eq!(account_credentials_path(Path::new("key")), PathBuf::from("key.account.json"));
	}

	#[tokio::test]
	async fn stored_account_credentials_are_reused_for_the_same_directory() {
		let dir = unique_temp_dir("reuse");
		let path = account_credentials_path(&dir.join("example.com.key"));

		store_credentials(&path, PRODUCTION_DIRECTORY, synthetic_credentials())
			.await
			.unwrap();

		let loaded = load_stored_credentials(&path, PRODUCTION_DIRECTORY)
			.await
			.expect("a stored account for the same directory must be reused");
		assert_eq!(
			serde_json::to_value(&loaded).unwrap(),
			serde_json::to_value(synthetic_credentials()).unwrap()
		);

		let _ = std::fs::remove_dir_all(&dir);
	}

	#[tokio::test]
	async fn stored_account_credentials_are_ignored_for_another_directory() {
		let dir = unique_temp_dir("directory-mismatch");
		let path = account_credentials_path(&dir.join("example.com.key"));

		store_credentials(&path, STAGING_DIRECTORY, synthetic_credentials())
			.await
			.unwrap();

		assert!(load_stored_credentials(&path, PRODUCTION_DIRECTORY).await.is_none());
		assert!(load_stored_credentials(&path, STAGING_DIRECTORY).await.is_some());

		let _ = std::fs::remove_dir_all(&dir);
	}

	#[tokio::test]
	async fn missing_account_credentials_file_means_a_new_account() {
		let dir = unique_temp_dir("missing");
		let path = account_credentials_path(&dir.join("example.com.key"));

		assert!(load_stored_credentials(&path, PRODUCTION_DIRECTORY).await.is_none());
	}

	#[tokio::test]
	async fn damaged_account_credentials_file_means_a_new_account() {
		let dir = unique_temp_dir("damaged");
		let path = account_credentials_path(&dir.join("example.com.key"));
		tokio::fs::create_dir_all(&dir).await.unwrap();
		tokio::fs::write(&path, b"{ not json").await.unwrap();

		assert!(load_stored_credentials(&path, PRODUCTION_DIRECTORY).await.is_none());

		// The replacement account overwrites the damaged file, so the file
		// heals instead of forcing a new account on every later run.
		store_credentials(&path, PRODUCTION_DIRECTORY, synthetic_credentials())
			.await
			.unwrap();
		assert!(load_stored_credentials(&path, PRODUCTION_DIRECTORY).await.is_some());

		let _ = std::fs::remove_dir_all(&dir);
	}

	#[cfg(unix)]
	#[tokio::test]
	async fn stored_account_credentials_are_owner_only() {
		use std::os::unix::fs::PermissionsExt;

		let dir = unique_temp_dir("permissions");
		let path = account_credentials_path(&dir.join("example.com.key"));
		store_credentials(&path, PRODUCTION_DIRECTORY, synthetic_credentials())
			.await
			.unwrap();

		let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
		assert_eq!(mode, 0o600);

		let _ = std::fs::remove_dir_all(&dir);
	}
}

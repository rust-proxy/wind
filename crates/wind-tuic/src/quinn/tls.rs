use std::sync::Arc;

use rustls::{
	crypto::CryptoProvider,
	pki_types::{CertificateDer, ServerName, UnixTime},
};
use wind_core::warn;

use crate::{Error, quinn::outbound::TuicOutboundOpts};

#[allow(clippy::result_large_err)]
pub(crate) fn tls_config(_servername: &str, opts: &TuicOutboundOpts) -> Result<rustls::ClientConfig, Error> {
	use rustls::ClientConfig;
	use rustls_platform_verifier::BuilderVerifierExt;

	let arc_crypto_provider = CryptoProvider::get_default().expect("Unable to find default crypto provider");
	let mut config = if opts.skip_cert_verify {
		warn!(
			target: "[TLS]",
			"skip_cert_verify=true: server certificate verification is DISABLED. \
			 This is insecure and allows trivial MITM of the upstream relay."
		);
		ClientConfig::builder()
			.dangerous()
			.with_custom_certificate_verifier(SkipServerVerification::new())
			.with_no_client_auth()
	} else {
		ClientConfig::builder_with_provider(arc_crypto_provider.clone())
			.with_protocol_versions(&[&rustls::version::TLS13])?
			.with_platform_verifier()?
			.with_no_client_auth()
	};

	// Honour caller-supplied ALPN list. Empty list falls back to "h3" for backward
	// compatibility with existing deployments; previously this was hardcoded and
	// silently ignored `opts.alpn`.
	let mut alpn: Vec<Vec<u8>> = opts.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
	if alpn.is_empty() {
		alpn.push(b"h3".to_vec());
	}
	config.alpn_protocols = alpn;

	Ok(config)
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
	fn new() -> Arc<Self> {
		Arc::new(Self(
			rustls::crypto::CryptoProvider::get_default()
				.expect("CryptoProvider not found")
				.clone(),
		))
	}
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
	fn verify_server_cert(
		&self,
		_end_entity: &CertificateDer<'_>,
		_intermediates: &[CertificateDer<'_>],
		_server_name: &ServerName<'_>,
		_ocsp: &[u8],
		_now: UnixTime,
	) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
		Ok(rustls::client::danger::ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
	}

	fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
		self.0.signature_verification_algorithms.supported_schemes()
	}
}

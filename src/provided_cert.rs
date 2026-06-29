//! Bring-your-own TLS certificate for the built-in HTTP handler
//! (onyums ROADMAP Phase 3 — "Bring-your-own cert").
//!
//! Every [`Tls`](crate::Tls) mode serves HTTPS; by default the certificate is an
//! auto-generated self-signed one. Some clients and browsers prefer a CA-signed
//! `.onion` certificate (e.g. from HARICA), so this type lets an operator supply
//! their own certificate chain and private key as PEM. Parsing and validation
//! happen *eagerly* at construction — `from_pem` builds the `rustls`
//! [`ServerConfig`](rustls::ServerConfig) up front, so a malformed or unusable
//! cert/key pair is a clean `Result::Err` at configuration time rather than a
//! surprise when the first circuit arrives. This is fully offline-testable: no
//! live Tor network is needed to confirm a PEM pair is acceptable.

use std::sync::Arc;

use anyhow::{bail, Result};
use tokio_rustls::rustls::{self, pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer}};

/// A caller-supplied TLS certificate chain and private key, parsed and validated
/// into a ready-to-serve `rustls` [`ServerConfig`](rustls::ServerConfig).
///
/// Construct one with [`ProvidedCert::from_pem`] and hand it to
/// [`Tls::Provided`](crate::Tls::Provided). Cloning is cheap — the validated
/// config is shared behind an [`Arc`], so threading the certificate through the
/// builder costs no re-parsing.
#[derive(Clone)]
pub struct ProvidedCert {
	config: Arc<rustls::ServerConfig>,
}

impl ProvidedCert {
	/// Parse and validate a PEM certificate chain and private key into a usable
	/// TLS server configuration.
	///
	/// `cert_pem` may contain one or more concatenated `CERTIFICATE` blocks (leaf
	/// first, then any intermediates); `key_pem` must contain exactly one private
	/// key (PKCS#8, PKCS#1, or SEC1). The pair is assembled into a `rustls`
	/// [`ServerConfig`](rustls::ServerConfig) immediately, so any problem is
	/// reported here.
	///
	/// # Errors
	/// Returns an error if the certificate PEM parses to no certificates, the
	/// certificate or key PEM is malformed, or `rustls` rejects the pair (for
	/// example an unsupported key algorithm).
	pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self> {
		let cert_chain = CertificateDer::pem_slice_iter(cert_pem)
			.collect::<std::result::Result<Vec<_>, _>>()
			.map_err(|e| anyhow::anyhow!("failed to parse certificate PEM: {e}"))?;
		if cert_chain.is_empty() {
			bail!("certificate PEM contained no certificates");
		}
		let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| anyhow::anyhow!("failed to parse private-key PEM: {e}"))?;
		let config = rustls::ServerConfig::builder()
			.with_no_client_auth()
			.with_single_cert(cert_chain, key)
			.map_err(|e| anyhow::anyhow!("provided certificate and key are not usable: {e}"))?;
		Ok(Self { config: Arc::new(config) })
	}

	/// The shared, validated `rustls` server configuration. Cloning the returned
	/// [`Arc`] is how the TLS acceptor is built without re-parsing the PEM.
	#[must_use]
	pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
		self.config.clone()
	}
}

// Manual `Debug` so `Tls` (which derives `Debug`) can hold a `ProvidedCert`
// without printing — or even being able to print — private key material.
impl std::fmt::Debug for ProvidedCert {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ProvidedCert").finish_non_exhaustive()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rcgen::generate_simple_self_signed;

	/// A fresh, valid self-signed cert/key PEM pair for an onion-style SAN.
	fn sample_pem() -> (String, String) {
		let ck = generate_simple_self_signed(vec!["example.onion".to_string()]).expect("rcgen self-signed");
		(ck.cert.pem(), ck.signing_key.serialize_pem())
	}

	#[test]
	fn from_pem_accepts_a_valid_self_signed_pair() {
		let (cert, key) = sample_pem();
		let provided = ProvidedCert::from_pem(cert.as_bytes(), key.as_bytes()).expect("a valid PEM pair should parse");
		// The validated config is real and shareable.
		let _config = provided.server_config();
	}

	#[test]
	fn from_pem_rejects_an_empty_certificate_chain() {
		let (_, key) = sample_pem();
		let err = ProvidedCert::from_pem(b"", key.as_bytes()).expect_err("empty cert PEM must be rejected");
		assert!(err.to_string().contains("no certificates"), "unexpected error: {err}");
	}

	#[test]
	fn from_pem_rejects_a_garbage_private_key() {
		let (cert, _) = sample_pem();
		let result = ProvidedCert::from_pem(cert.as_bytes(), b"-----BEGIN PRIVATE KEY-----\n!!!not base64!!!\n-----END PRIVATE KEY-----\n");
		assert!(result.is_err(), "a malformed private key must be rejected");
	}

	#[test]
	fn from_pem_rejects_a_non_pem_certificate() {
		let (_, key) = sample_pem();
		let result = ProvidedCert::from_pem(b"this is not a certificate", key.as_bytes());
		assert!(result.is_err(), "non-PEM certificate input must be rejected");
	}

	#[test]
	fn server_config_hands_out_the_same_shared_config() {
		let (cert, key) = sample_pem();
		let provided = ProvidedCert::from_pem(cert.as_bytes(), key.as_bytes()).expect("valid PEM");
		let a = provided.server_config();
		let b = provided.server_config();
		assert!(Arc::ptr_eq(&a, &b), "server_config should share one validated config, not rebuild it");
	}

	#[test]
	fn debug_does_not_leak_key_material() {
		let (cert, key) = sample_pem();
		let provided = ProvidedCert::from_pem(cert.as_bytes(), key.as_bytes()).expect("valid PEM");
		let rendered = format!("{provided:?}");
		assert!(rendered.contains("ProvidedCert"), "debug should name the type: {rendered}");
		assert!(!rendered.contains("PRIVATE KEY"), "debug must not print key material: {rendered}");
	}
}

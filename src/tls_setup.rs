//! TLS acceptor assembly for the HTTP handler (onyums ROADMAP Phase 3 TLS-first
//! transport; extracted from `lib.rs` as a slice of the Phase 0 module split).
//!
//! [`tls_acceptor`] resolves the [`Tls`] policy into the [`TlsAcceptor`] the serve loop
//! hands each accepted stream: a caller-supplied chain under [`Tls::Provided`], or a
//! freshly generated self-signed certificate for the onion address under
//! [`Tls::Upgrade`]/[`Tls::Strict`] ([`self_signed_server_config`]).
//!
//! This is the *assembly* half of the TLS path and it is entirely offline — no network,
//! no Tor — so it is unit-testable here. Only the act of accepting a live stream with
//! the resulting acceptor touches the live path.
//!
//! On the self-signed certificate: it provides encryption and the browser
//! secure-context semantics a real web app depends on, **not** WebPKI-trusted
//! authentication. The `.onion` address — a hash of the service's public key — is what
//! authenticates the service; see the README's "Why TLS *inside* Tor?".

use std::sync::Arc;

use anyhow::{Context, Result};
use rcgen::generate_simple_self_signed;
use tokio_rustls::{
	rustls, rustls::pki_types::{pem::PemObject, PrivateKeyDer, PrivatePkcs8KeyDer}, TlsAcceptor
};

use crate::{address::OnionAddress, tls_policy::Tls};

/// Resolve the [`Tls`] policy into the acceptor the HTTP handler serves with.
///
/// [`Tls::Provided`] serves the caller-supplied config, already parsed and validated
/// once in `ProvidedCert::from_pem` — so a bad cert/key pair is a startup error rather
/// than a per-connection surprise. Every other mode auto-generates a self-signed
/// certificate for the onion address: TLS is on in every mode, and the policy only
/// decides how strictly plaintext is refused.
///
/// # Errors
/// Returns an error if the self-signed certificate or its `rustls` config cannot be
/// built (see [`self_signed_server_config`]).
pub fn tls_acceptor(address: &OnionAddress, tls: &Tls) -> Result<TlsAcceptor> {
	let server_config = match tls {
		Tls::Provided(cert) => cert.server_config(),
		Tls::Upgrade | Tls::Strict => Arc::new(self_signed_server_config(address)?),
	};
	Ok(TlsAcceptor::from(server_config))
}

/// The subject-alternative-name list for the onion service's self-signed certificate.
///
/// A browser reaching `https://<address>.onion` validates the name it asked for, which
/// is the **full host including the `.onion` suffix** — the bare 56-character base32
/// key would be a name mismatch on top of the expected self-signed warning. Split out
/// from [`self_signed_server_config`] so the name that ends up in the certificate is
/// unit-testable without parsing X.509 back out of a `rustls` config.
fn subject_alt_names(address: &OnionAddress) -> Vec<String> {
	vec![address.host().to_string()]
}

/// Build a `rustls` server config with a freshly generated self-signed certificate for
/// the onion address — the default when the caller did not bring their own.
///
/// The certificate's SAN is the bare 56-character onion host (no `.onion` suffix
/// handling beyond what [`OnionAddress::host`] already normalises), so a browser
/// reaching `https://<address>.onion` sees a certificate that matches the name it
/// asked for.
///
/// # Errors
/// Returns an error if `rcgen` cannot generate the certificate, if its key does not
/// re-parse as PKCS#8, or if `rustls` rejects the cert/key pair.
pub fn self_signed_server_config(address: &OnionAddress) -> Result<rustls::ServerConfig> {
	// Fallible, not `unwrap`: this runs on the launch path, and rcgen rejects a SAN it
	// cannot encode. A panic here would take down the caller's process for what is a
	// perfectly reportable configuration error.
	let cert = generate_simple_self_signed(subject_alt_names(address)).with_context(|| format!("failed to generate a self-signed certificate for {address}"))?;

	let key_der = PrivatePkcs8KeyDer::from_pem_slice(cert.signing_key.serialize_pem().as_bytes()).map_err(|e| anyhow::anyhow!("failed to convert the generated signing key to DER: {e:?}"))?;
	let server_config = rustls::ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(vec![cert.cert.der().clone()], PrivateKeyDer::Pkcs8(key_der))
		.map_err(|e| anyhow::anyhow!("failed to build the rustls server config for {address}: {e:?}"))?;
	Ok(server_config)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::provided_cert::ProvidedCert;

	/// A syntactically well-formed 56-character onion host for the tests below.
	fn address() -> OnionAddress {
		OnionAddress::normalized("examplereturnsavalidacceptorpaddingxxxxxxxxxxxxxxxxxxxxx")
	}

	fn provided_cert(address: &OnionAddress) -> ProvidedCert {
		let ck = rcgen::generate_simple_self_signed(vec![address.host().to_string()]).expect("rcgen");
		ProvidedCert::from_pem(ck.cert.pem().as_bytes(), ck.signing_key.serialize_pem().as_bytes()).expect("valid PEM")
	}

	#[test]
	fn tls_acceptor_builds_from_a_provided_certificate() {
		// The acceptor builds offline for both the self-signed and provided paths.
		let address = address();
		tls_acceptor(&address, &Tls::Provided(provided_cert(&address))).expect("provided-cert acceptor");
		tls_acceptor(&address, &Tls::Upgrade).expect("self-signed acceptor");
	}

	#[test]
	fn every_tls_mode_yields_an_acceptor() {
		// TLS is on in *every* mode — the policy decides how strictly plaintext is
		// refused, never whether the transport is encrypted. A mode that failed to build
		// an acceptor would be a hole in that promise.
		let address = address();
		tls_acceptor(&address, &Tls::Upgrade).expect("Upgrade must yield an acceptor");
		tls_acceptor(&address, &Tls::Strict).expect("Strict must yield an acceptor");
		tls_acceptor(&address, &Tls::Provided(provided_cert(&address))).expect("Provided must yield an acceptor");
	}

	#[test]
	fn the_certificate_name_is_the_full_onion_host() {
		// The name in the cert must be what a browser asks for — the full
		// `<base32>.onion` host. The bare base32 key would be a name mismatch on top of
		// the expected self-signed warning, which is a much more confusing failure.
		let address = address();
		let sans = subject_alt_names(&address);
		assert_eq!(sans, vec![address.host().to_string()], "the SAN is the address's host");
		assert_eq!(sans.len(), 1, "exactly one name: the onion host");
		// `contains` rather than `ends_with`: clippy::pedantic reads a literal starting
		// with '.' as a file-extension comparison. The exact value is pinned by the
		// assert_eq above and by `the_certificate_name_survives_an_unsuffixed_address`.
		assert!(sans[0].contains(".onion"), "the SAN must carry the .onion suffix: {sans:?}");
		assert!(!sans[0].starts_with("https://") && !sans[0].contains('/'), "a SAN is a host, not a URL: {sans:?}");
	}

	#[test]
	fn the_certificate_name_survives_an_unsuffixed_address() {
		// `OnionAddress::normalized` appends the suffix, so a caller passing a bare
		// base32 name still gets a certificate a browser will match.
		let bare = OnionAddress::normalized("examplereturnsavalidacceptorpaddingxxxxxxxxxxxxxxxxxxxxx");
		assert_eq!(subject_alt_names(&bare), vec!["examplereturnsavalidacceptorpaddingxxxxxxxxxxxxxxxxxxxxx.onion".to_string()]);
	}

	#[test]
	fn self_signed_config_builds_repeatedly() {
		// Each launch mints its own certificate; the generation path must be re-runnable
		// (two services in one process, or a restart) rather than relying on any
		// one-shot state.
		let address = address();
		self_signed_server_config(&address).expect("first call");
		self_signed_server_config(&address).expect("second call");
	}
}

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
use p256::{
	ecdsa::{Signature, SigningKey, signature::Signer}, pkcs8::EncodePrivateKey
};
use rcgen::{CertificateParams, PublicKeyData, SignatureAlgorithm};
use tokio_rustls::{
	TlsAcceptor, rustls, rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer}
};

use crate::{address::OnionAddress, tls_policy::Tls};

/// A pure-Rust P-256 signing key, standing in for the `ring`-backed key pair rcgen
/// would otherwise use (onyums ROADMAP Phase 2 — "100% Rust, no FFI, ever").
///
/// **Why this exists.** rcgen's default `crypto` feature signs with `ring`, which
/// vendors C and assembly and needs a C toolchain — and until this landed it was the
/// *last* C library in onyums' dependency graph, kept alive solely to mint the
/// self-signed certificate on the launch path. rcgen does not require it: the
/// [`rcgen::SigningKey`] and [`PublicKeyData`] traits sit outside the `crypto`
/// feature, so a caller may bring any signer. This is that signer, over `RustCrypto`'s
/// `p256` — no C, no build script.
///
/// **The two encodings that have to be exactly right**, both mirrored from rcgen's own
/// `ring` implementation rather than guessed:
/// - [`PublicKeyData::der_bytes`] must be the **X9.62 uncompressed point**
///   (`0x04 || x || y`), because rcgen wraps it in the `SubjectPublicKeyInfo` BIT STRING
///   itself — handing it a full SPKI here would nest one inside another and produce a
///   certificate no client can parse.
/// - [`rcgen::SigningKey::sign`] must return an **ASN.1 DER `ECDSA-Sig-Value`**, because
///   [`rcgen::PKCS_ECDSA_P256_SHA256`] maps to ring's `ECDSA_P256_SHA256_ASN1_SIGNING`.
///   The fixed-width `r || s` form that `Signature::to_bytes` returns would be accepted
///   silently by rcgen and rejected by every verifier.
///
/// Both are covered by tests below, and — more convincingly — by the existing
/// end-to-end TLS tests, in which a real `rustls` client completes a handshake against
/// a certificate minted here. A malformed key or signature cannot survive that.
struct P256SigningKey {
	key: SigningKey,
	/// The X9.62 uncompressed public point, cached because [`PublicKeyData::der_bytes`]
	/// returns a borrow and the encoded point is computed, not stored, in `p256`.
	public_point: Vec<u8>,
}

impl P256SigningKey {
	/// Generate a fresh P-256 key.
	///
	/// The scalar comes from the workspace's `rand` rather than `p256`'s own
	/// `SigningKey::random`, deliberately: `random` is generic over `rand_core`'s
	/// `CryptoRng`, which would couple onyums' `rand` major to whichever one `p256`
	/// tracks. Feeding raw bytes to `from_slice` keeps the two independent.
	/// `from_slice` rejects a scalar outside `[1, n-1]`; the chance is about 2^-32 per
	/// draw, so retrying a few times is both sufficient and honest (rather than
	/// `expect`-ing a draw that is merely overwhelmingly likely).
	fn generate() -> Result<Self> {
		use rand::Rng as _;
		for _ in 0..8 {
			let mut scalar = [0u8; 32];
			rand::rng().fill_bytes(&mut scalar);
			if let Ok(key) = SigningKey::from_slice(&scalar) {
				let public_point = key.verifying_key().to_sec1_point(false).as_bytes().to_vec();
				return Ok(Self { key, public_point });
			}
		}
		anyhow::bail!("failed to generate a P-256 signing key: eight consecutive draws fell outside the curve order, which should be impossible — suspect the random source")
	}

	/// The private key as PKCS#8 DER, the form `rustls` wants.
	fn to_pkcs8_der(&self) -> Result<PrivatePkcs8KeyDer<'static>> {
		let der = self.key.to_pkcs8_der().map_err(|e| anyhow::anyhow!("failed to encode the generated P-256 key as PKCS#8: {e}"))?;
		Ok(PrivatePkcs8KeyDer::from(der.as_bytes().to_vec()))
	}
}

impl PublicKeyData for P256SigningKey {
	fn der_bytes(&self) -> &[u8] {
		&self.public_point
	}

	fn algorithm(&self) -> &'static SignatureAlgorithm {
		&rcgen::PKCS_ECDSA_P256_SHA256
	}
}

impl rcgen::SigningKey for P256SigningKey {
	fn sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
		let signature: Signature = self.key.sign(msg);
		Ok(signature.to_der().as_bytes().to_vec())
	}
}

/// A self-signed `(certificate_pem, private_key_pem)` pair for `host`, for tests across
/// the crate that need a plausible BYO certificate.
///
/// Lives here rather than in each test module because it is the one place that knows how
/// to mint a certificate now that rcgen's `crypto` feature — and its
/// `generate_simple_self_signed` convenience — is switched off.
#[cfg(test)]
pub fn test_self_signed_pem(host: &str) -> (String, String) {
	let key = P256SigningKey::generate().expect("P-256 keygen");
	let params = certificate_params(vec![host.to_string()]).expect("certificate params");
	let cert = params.self_signed(&key).expect("self-signed certificate");
	let key_pem = key.key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).expect("PKCS#8 PEM").to_string();
	(cert.pem(), key_pem)
}

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

/// Certificate parameters for `sans`, with a random serial number.
///
/// The serial is set explicitly because rcgen only mints one itself under its `crypto`
/// feature, which onyums switches off to keep `ring` out of the tree — without this,
/// every certificate build fails with `MissingSerialNumber`. That is a load-bearing
/// detail rather than boilerplate: RFC 5280 requires a positive serial, and CA/Browser
/// Forum guidance wants ≥64 bits of entropy in it, so this draws 16 random bytes and
/// clears the top bit of the first (a leading 1 would make the DER INTEGER negative,
/// and a leading zero octet would waste a byte).
///
/// # Errors
/// Returns an error if rcgen rejects a subject-alternative name it cannot encode.
fn certificate_params(sans: Vec<String>) -> Result<CertificateParams> {
	use rand::Rng as _;
	let mut serial = [0u8; 16];
	rand::rng().fill_bytes(&mut serial);
	serial[0] &= 0x7f;
	let mut params = CertificateParams::new(sans).context("failed to assemble certificate parameters")?;
	params.serial_number = Some(rcgen::SerialNumber::from(serial.to_vec()));
	Ok(params)
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
	let signing_key = P256SigningKey::generate()?;
	let params = certificate_params(subject_alt_names(address)).with_context(|| format!("failed to assemble certificate parameters for {address}"))?;
	let cert = params.self_signed(&signing_key).with_context(|| format!("failed to generate a self-signed certificate for {address}"))?;

	// Straight from the signer, not round-tripped through PEM: the old path serialised
	// the key to PEM only to parse it back into DER on the next line.
	let key_der = signing_key.to_pkcs8_der()?;
	// See `ProvidedCert::from_pem` for why this precedes the builder rather than trusting
	// the launch path: `ServerConfig::builder()` panics, not errors, when no process
	// default is installed and the crate features name two providers. This one is
	// reachable from `serve()` on the shared-client branch, which never calls
	// `setup_tor_client`.
	crate::tor_client::install_crypto_provider();
	let server_config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.der().clone()], PrivateKeyDer::Pkcs8(key_der)).map_err(|e| anyhow::anyhow!("failed to build the rustls server config for {address}: {e:?}"))?;
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

	/// The public half rcgen receives must be the **X9.62 uncompressed point**, not a
	/// `SubjectPublicKeyInfo`: rcgen wraps it in the SPKI BIT STRING itself. Handing it
	/// an SPKI would nest one inside another — a certificate that still *builds* and
	/// that no client can parse, which is the worst failure shape available here.
	#[test]
	fn the_signer_hands_rcgen_a_raw_uncompressed_point_not_an_spki() {
		let key = P256SigningKey::generate().expect("keygen");
		let point = key.der_bytes();
		assert_eq!(point.len(), 65, "an uncompressed P-256 point is 1 tag byte + two 32-byte coordinates; an SPKI would be longer and a compressed point 33 bytes");
		assert_eq!(point[0], 0x04, "0x04 is the X9.62 tag for an uncompressed point; 0x30 here would mean a DER SEQUENCE, i.e. an SPKI slipped through");
	}

	/// The signature must be an **ASN.1 DER `ECDSA-Sig-Value`**, because
	/// `PKCS_ECDSA_P256_SHA256` is ring's `..._ASN1_SIGNING` variant. The fixed-width
	/// `r || s` form is the easy mistake: it is exactly 64 bytes, rcgen accepts whatever
	/// bytes it is given, and only a *verifier* would ever object.
	#[test]
	fn the_signer_produces_an_asn1_der_signature_not_a_fixed_width_pair() {
		use p256::ecdsa::signature::Verifier as _;
		use rcgen::SigningKey as _;

		let key = P256SigningKey::generate().expect("keygen");
		let sig = key.sign(b"a message to sign").expect("sign");
		assert_eq!(sig[0], 0x30, "a DER ECDSA-Sig-Value opens with SEQUENCE (0x30); a raw r||s pair would start with a coordinate byte");
		assert_eq!(usize::from(sig[1]), sig.len() - 2, "the SEQUENCE length must cover exactly the rest of the encoding");
		assert_ne!(sig.len(), 64, "64 bytes is the fixed-width r||s form, which rcgen would embed silently and every verifier would reject");
		// And it must actually verify under the matching public key — the property the
		// shape checks above only approximate.
		let parsed = p256::ecdsa::Signature::from_der(&sig).expect("signature parses as DER");
		key.key.verifying_key().verify(b"a message to sign", &parsed).expect("signature verifies under its own public key");
	}

	fn provided_cert(address: &OnionAddress) -> ProvidedCert {
		let (cert_pem, key_pem) = test_self_signed_pem(address.host());
		ProvidedCert::from_pem(cert_pem.as_bytes(), key_pem.as_bytes()).expect("valid PEM")
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

	/// The default acceptor path has the same obligation as `ProvidedCert::from_pem`:
	/// it builds a rustls `ServerConfig`, and that builder panics when no process
	/// default provider is installed and two provider features are unified in the graph.
	/// It is reachable from `serve()` on the shared-client branch, which never calls
	/// `setup_tor_client` — so it installs the provider itself. (Postcondition only; a
	/// provider cannot be uninstalled to reproduce the panic — see the twin test in
	/// `provided_cert`.)
	#[test]
	fn self_signed_config_leaves_a_crypto_provider_installed() {
		self_signed_server_config(&address()).expect("self-signed config");
		assert!(tokio_rustls::rustls::crypto::CryptoProvider::get_default().is_some(), "self_signed_server_config must guarantee a process-default CryptoProvider before building a ServerConfig");
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

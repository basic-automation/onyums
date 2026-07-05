//! Client-authorization keypair generation for v3 restricted discovery (onyums
//! ROADMAP Phase 2).
//!
//! Restricted discovery encrypts the onion-service descriptor to a set of
//! authorized clients' x25519 public keys, so a client not on the allowlist
//! cannot even *discover* the service — introduction points and keys stay hidden
//! from everyone else. Onboarding a client is a two-sided ceremony: the client
//! generates an x25519 keypair, keeps the **secret** half to configure its Tor
//! client, and hands the **public** half to the operator, who authorizes it via
//! [`OnionServiceBuilder::authorized_clients`](crate::OnionServiceBuilder::authorized_clients).
//! [`onyums_skin::ClientAuthKey`] models the public half (the operator side);
//! this module is the *client* side — it mints the keypair in the first place.
//!
//! The keypair is generated in-tree with arti's own `tor-llcrypto` curve25519 —
//! the same x25519 family Arti parses into `HsClientDescEncKey` — so there is no
//! second, divergent crypto stack and no new dependency. As in the
//! [`vanity`](crate::vanity) miner we avoid arti's `random_from_rng` (pinned to a
//! different `rand_core` major than the workspace `rand`) and instead draw a
//! 32-byte secret from the workspace CSPRNG, building the `StaticSecret` from it.
//!
//! Everything here is offline and Tor-free, so the whole module is unit-testable
//! with no live network.

use rand::RngCore;
use tor_llcrypto::pk::curve25519::{PublicKey, StaticSecret};

use crate::{ClientAuthKey, OnionAddress};

/// The `descriptor:x25519:` prefix Tor writes before the base32 key in both the
/// server-side `<name>.auth` file and the client-side `.auth_private` line.
const KEY_PREFIX: &str = "descriptor:x25519:";

/// RFC 4648 base32 alphabet (uppercase) — the encoding Tor and
/// [`ClientAuthKey`] use for x25519 client-auth keys.
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A generated v3 client-authorization keypair for restricted discovery.
///
/// The [`public_key`](Self::public_key) half is handed to the service operator and
/// authorized via [`OnionServiceBuilder::authorized_clients`](crate::OnionServiceBuilder::authorized_clients);
/// the secret half stays with the client and is installed into its Tor
/// `ClientOnionAuthDir` as an [`auth_private_line`](Self::auth_private_line).
///
/// Holds secret key material, so it does not derive [`Debug`] automatically — the
/// manual impl redacts the secret.
#[derive(Clone)]
pub struct ClientAuthKeypair {
	/// The raw 32-byte x25519 secret. Never rendered by `Debug`.
	secret: [u8; 32],
	/// The public half, always derived from `secret` so the two stay consistent.
	public: ClientAuthKey,
}

impl ClientAuthKeypair {
	/// Generate a fresh keypair from the workspace CSPRNG.
	#[must_use]
	pub fn generate() -> Self {
		let mut secret = [0u8; 32];
		rand::rng().fill_bytes(&mut secret);
		Self::from_secret_bytes(secret)
	}

	/// Reconstruct a keypair from a known 32-byte x25519 secret — e.g. to re-derive
	/// the public half from a client's stored `.auth_private` key. The public key is
	/// always computed from the secret via curve25519, so the two cannot drift apart.
	#[must_use]
	pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
		let static_secret = StaticSecret::from(secret);
		let public = PublicKey::from(&static_secret);
		Self { secret, public: ClientAuthKey::from_bytes(*public.as_bytes()) }
	}

	/// The public half, ready to authorize into a
	/// [`RestrictedDiscovery`](crate::RestrictedDiscovery) allowlist or render as the
	/// server-side `<name>.auth` line.
	#[must_use]
	pub const fn public_key(&self) -> ClientAuthKey {
		self.public
	}

	/// The raw 32-byte x25519 secret key. Treat as sensitive key material.
	#[must_use]
	pub const fn secret_bytes(&self) -> [u8; 32] {
		self.secret
	}

	/// The bare base32 encoding of the secret key (no `descriptor:x25519:` prefix) —
	/// 52 uppercase RFC 4648 characters, unpadded.
	#[must_use]
	pub fn secret_base32(&self) -> String {
		base32_encode(&self.secret)
	}

	/// The canonical `descriptor:x25519:<BASE32>` line carrying the *secret* key —
	/// the form Tor's client-auth tooling recognizes.
	#[must_use]
	pub fn secret_descriptor_line(&self) -> String {
		format!("{KEY_PREFIX}{}", self.secret_base32())
	}

	/// The full client-side `.auth_private` file body for `address`:
	/// `<56-char-onion>:descriptor:x25519:<BASE32-secret>`. A Tor client drops this
	/// into its `ClientOnionAuthDir` to unlock the restricted service. The `.onion`
	/// suffix is stripped, as Tor's format expects the bare 56-character host.
	#[must_use]
	pub fn auth_private_line(&self, address: &OnionAddress) -> String {
		let host = address.as_str().trim_end_matches(".onion");
		format!("{host}:{KEY_PREFIX}{}", self.secret_base32())
	}
}

impl std::fmt::Debug for ClientAuthKeypair {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ClientAuthKeypair").field("public", &self.public).field("secret", &"<redacted>").finish()
	}
}

/// Encode bytes as RFC 4648 base32 (uppercase, unpadded). Mirrors the encoding
/// [`ClientAuthKey::to_base32`] uses on the public side, so a keypair's public and
/// secret keys render in one consistent format; the
/// `keypair_public_base32_matches_client_auth_key` test pins the two together.
fn base32_encode(bytes: &[u8]) -> String {
	let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
	let mut buffer: u64 = 0;
	let mut bits: u32 = 0;
	for &b in bytes {
		buffer = (buffer << 8) | u64::from(b);
		bits += 8;
		while bits >= 5 {
			bits -= 5;
			let idx = ((buffer >> bits) & 0x1f) as usize;
			out.push(BASE32_ALPHABET[idx] as char);
		}
	}
	if bits > 0 {
		let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
		out.push(BASE32_ALPHABET[idx] as char);
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A fixed secret so the derived values are deterministic across runs.
	const SECRET: [u8; 32] = [
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	];

	#[test]
	fn from_secret_bytes_is_deterministic_and_round_trips() {
		let a = ClientAuthKeypair::from_secret_bytes(SECRET);
		let b = ClientAuthKeypair::from_secret_bytes(SECRET);
		assert_eq!(a.secret_bytes(), SECRET);
		assert_eq!(a.secret_bytes(), b.secret_bytes());
		assert_eq!(a.public_key(), b.public_key());
	}

	#[test]
	fn public_key_is_the_curve25519_image_of_the_secret() {
		// The public key the keypair exposes must equal the x25519 base-point
		// multiplication of the secret, computed independently here.
		let expected = PublicKey::from(&StaticSecret::from(SECRET));
		let pair = ClientAuthKeypair::from_secret_bytes(SECRET);
		assert_eq!(pair.public_key().as_bytes(), expected.as_bytes());
	}

	#[test]
	fn keypair_public_base32_matches_client_auth_key() {
		// Cross-crate format contract: our base32 encoder agrees with skin's
		// ClientAuthKey rendering, so a generated public key round-trips through the
		// `descriptor:x25519:` allowlist byte-identically.
		let pair = ClientAuthKeypair::from_secret_bytes(SECRET);
		let key = pair.public_key();
		assert_eq!(base32_encode(key.as_bytes()), key.to_base32());
		// And the public key parses back from its own canonical line.
		let line = key.to_string();
		let reparsed: ClientAuthKey = line.parse().expect("canonical line parses");
		assert_eq!(reparsed, key);
	}

	#[test]
	fn secret_descriptor_line_is_prefixed_base32() {
		let pair = ClientAuthKeypair::from_secret_bytes(SECRET);
		let line = pair.secret_descriptor_line();
		let b32 = line.strip_prefix("descriptor:x25519:").expect("has the descriptor prefix");
		assert_eq!(b32, pair.secret_base32());
		// 32 bytes → 52 unpadded base32 chars.
		assert_eq!(b32.len(), 52);
		assert!(b32.bytes().all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c)));
	}

	#[test]
	fn auth_private_line_carries_the_bare_host_and_secret() {
		let pair = ClientAuthKeypair::from_secret_bytes(SECRET);
		let address = OnionAddress::normalized("abcdefghij.onion");
		let line = pair.auth_private_line(&address);
		let (host, rest) = line.split_once(':').expect("host:descriptor split");
		assert_eq!(host, "abcdefghij");
		assert!(!host.ends_with(".onion"));
		assert_eq!(rest, pair.secret_descriptor_line());
	}

	#[test]
	fn generate_produces_distinct_valid_keypairs() {
		let a = ClientAuthKeypair::generate();
		let b = ClientAuthKeypair::generate();
		// Two fresh draws differ with overwhelming probability.
		assert_ne!(a.secret_bytes(), b.secret_bytes());
		assert_ne!(a.public_key(), b.public_key());
		// A freshly generated public key renders a valid canonical allowlist line.
		let reparsed: ClientAuthKey = a.public_key().to_string().parse().expect("generated key parses");
		assert_eq!(reparsed, a.public_key());
	}

	#[test]
	fn debug_redacts_the_secret() {
		let pair = ClientAuthKeypair::from_secret_bytes(SECRET);
		let shown = format!("{pair:?}");
		assert!(shown.contains("<redacted>"));
		assert!(!shown.contains(&pair.secret_base32()));
	}
}

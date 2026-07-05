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

use crate::{ClientAuthKey, OnionAddress, RestrictedDiscovery};

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

	/// Parse a `descriptor:x25519:<BASE32>` line carrying a *secret* key back into a
	/// keypair, re-deriving the public half. This is the inverse of
	/// [`secret_descriptor_line`](Self::secret_descriptor_line), completing the
	/// import/export round-trip — an operator (or a client re-reading its own config)
	/// can recover the keypair, and hence the authorized public key, from the stored
	/// secret line.
	///
	/// Surrounding whitespace is trimmed; the `descriptor:x25519:` prefix is required.
	///
	/// # Errors
	/// Returns [`ClientAuthKeypairError`] if the prefix is missing, the base32 is
	/// malformed or non-canonical, or the key is not 32 bytes.
	pub fn from_secret_descriptor_line(line: &str) -> Result<Self, ClientAuthKeypairError> {
		let b32 = line.trim().strip_prefix(KEY_PREFIX).ok_or(ClientAuthKeypairError::MissingPrefix)?;
		let bytes = base32_decode(b32)?;
		let secret: [u8; 32] = bytes.as_slice().try_into().map_err(|_| ClientAuthKeypairError::WrongLength(bytes.len()))?;
		Ok(Self::from_secret_bytes(secret))
	}

	/// Parse a full client-side `.auth_private` file body
	/// `<host>:descriptor:x25519:<BASE32-secret>` — the inverse of
	/// [`auth_private_line`](Self::auth_private_line) — returning the derived keypair
	/// and the [`OnionAddress`] it is scoped to. The host is taken verbatim (with a
	/// `.onion` suffix normalized on) exactly as [`auth_private_line`] wrote it; like
	/// [`OnionAddress::normalized`] it is not re-validated as a real v3 address.
	///
	/// # Errors
	/// Returns [`ClientAuthKeypairError::MissingHost`] if there is no `<host>:` prefix,
	/// otherwise the same errors as [`from_secret_descriptor_line`](Self::from_secret_descriptor_line).
	pub fn from_auth_private_line(line: &str) -> Result<(OnionAddress, Self), ClientAuthKeypairError> {
		let (host, descriptor) = line.trim().split_once(':').ok_or(ClientAuthKeypairError::MissingHost)?;
		let keypair = Self::from_secret_descriptor_line(descriptor)?;
		Ok((OnionAddress::normalized(host), keypair))
	}
}

/// Why parsing a [`ClientAuthKeypair`] from its text form failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAuthKeypairError {
	/// A `.auth_private` line had no `<host>:` prefix before the descriptor.
	MissingHost,
	/// The descriptor did not start with `descriptor:x25519:`.
	MissingPrefix,
	/// A character outside the RFC 4648 base32 alphabet was found (the byte offset
	/// into the base32 portion).
	InvalidChar(usize),
	/// Trailing (padding) bits after the last full byte were non-zero — a
	/// non-canonical encoding.
	NonCanonical,
	/// The key decoded to a length other than the required 32 bytes.
	WrongLength(usize),
}

impl std::fmt::Display for ClientAuthKeypairError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::MissingHost => write!(f, "`.auth_private` line must start with `<host>:`"),
			Self::MissingPrefix => write!(f, "client-auth secret must start with `{KEY_PREFIX}`"),
			Self::InvalidChar(pos) => write!(f, "invalid base32 character at position {pos}"),
			Self::NonCanonical => write!(f, "non-canonical base32: trailing bits are not zero"),
			Self::WrongLength(len) => write!(f, "client-auth secret must be 32 bytes, got {len}"),
		}
	}
}

impl std::error::Error for ClientAuthKeypairError {}

/// Provision a fresh authorized client for restricted discovery in one step.
///
/// Generates a keypair, authorizes its **public** half into `allowlist` under
/// `nickname`, and returns the keypair so the operator can hand the client its
/// [`auth_private_line`](ClientAuthKeypair::auth_private_line).
///
/// This is the onboarding capstone tying [`ClientAuthKeypair::generate`] to the
/// [`RestrictedDiscovery`] allowlist the
/// [`authorized_clients`](crate::OnionServiceBuilder::authorized_clients) builder
/// consumes. If `nickname` was already authorized, its key is replaced — the
/// returned keypair is the one now in effect. Only the public half is retained by
/// the service; the secret lives solely in the returned keypair and must reach the
/// client over a trusted channel.
pub fn provision_client(allowlist: &mut RestrictedDiscovery, nickname: impl Into<String>) -> ClientAuthKeypair {
	let keypair = ClientAuthKeypair::generate();
	allowlist.authorize(nickname, keypair.public_key());
	keypair
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

/// Decode an RFC 4648 base32 string (either case, unpadded) into bytes, rejecting
/// out-of-alphabet characters and non-zero trailing (padding) bits. The inverse of
/// [`base32_encode`].
fn base32_decode(s: &str) -> Result<Vec<u8>, ClientAuthKeypairError> {
	let mut out = Vec::with_capacity(s.len() * 5 / 8);
	let mut buffer: u64 = 0;
	let mut bits: u32 = 0;
	for (i, c) in s.bytes().enumerate() {
		let val = base32_value(c).ok_or(ClientAuthKeypairError::InvalidChar(i))?;
		buffer = (buffer << 5) | u64::from(val);
		bits += 5;
		if bits >= 8 {
			bits -= 8;
			out.push(((buffer >> bits) & 0xff) as u8);
		}
	}
	if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
		return Err(ClientAuthKeypairError::NonCanonical);
	}
	Ok(out)
}

/// Map one base32 character (either case) to its 5-bit value, or `None` if it is
/// not in the RFC 4648 alphabet.
const fn base32_value(c: u8) -> Option<u8> {
	match c {
		b'A'..=b'Z' => Some(c - b'A'),
		b'a'..=b'z' => Some(c - b'a'),
		b'2'..=b'7' => Some(c - b'2' + 26),
		_ => None,
	}
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
	fn secret_descriptor_line_round_trips() {
		let pair = ClientAuthKeypair::from_secret_bytes(SECRET);
		let line = pair.secret_descriptor_line();
		let parsed = ClientAuthKeypair::from_secret_descriptor_line(&line).expect("parses");
		assert_eq!(parsed.secret_bytes(), pair.secret_bytes());
		assert_eq!(parsed.public_key(), pair.public_key());
		// Whitespace tolerance.
		let padded = format!("  {line}\n");
		assert_eq!(ClientAuthKeypair::from_secret_descriptor_line(&padded).expect("parses").secret_bytes(), SECRET);
	}

	#[test]
	fn auth_private_line_round_trips() {
		let pair = ClientAuthKeypair::from_secret_bytes(SECRET);
		let address = OnionAddress::normalized("abcdefghij.onion");
		let line = pair.auth_private_line(&address);
		let (parsed_addr, parsed) = ClientAuthKeypair::from_auth_private_line(&line).expect("parses");
		assert_eq!(parsed_addr.as_str(), address.as_str());
		assert_eq!(parsed.secret_bytes(), SECRET);
		assert_eq!(parsed.public_key(), pair.public_key());
	}

	#[test]
	fn parse_rejects_malformed_input() {
		use ClientAuthKeypairError as E;
		// Missing prefix.
		assert_eq!(ClientAuthKeypair::from_secret_descriptor_line("x25519:AAAA").unwrap_err(), E::MissingPrefix);
		// Out-of-alphabet character (`1` is not in the base32 alphabet).
		assert!(matches!(ClientAuthKeypair::from_secret_descriptor_line("descriptor:x25519:1111"), Err(E::InvalidChar(_))));
		// Wrong length: valid base32 but not 32 bytes.
		assert!(matches!(ClientAuthKeypair::from_secret_descriptor_line("descriptor:x25519:AAAA"), Err(E::WrongLength(_))));
		// `.auth_private` line with no host prefix.
		assert_eq!(ClientAuthKeypair::from_auth_private_line("descriptorx25519nohost").unwrap_err(), E::MissingHost);
	}

	#[test]
	fn base32_round_trips_and_rejects_noncanonical() {
		let decoded = base32_decode(&base32_encode(&SECRET)).expect("round trips");
		assert_eq!(decoded, SECRET);
		// `AB` decodes to one byte with non-zero trailing bits → non-canonical.
		assert_eq!(base32_decode("AB"), Err(ClientAuthKeypairError::NonCanonical));
	}

	#[test]
	fn provision_client_authorizes_the_public_half() {
		let mut allowlist = RestrictedDiscovery::new();
		let keypair = provision_client(&mut allowlist, "alice");
		// The allowlist now carries exactly the public half under the nickname.
		assert_eq!(allowlist.len(), 1);
		assert_eq!(allowlist.key_for("alice"), Some(&keypair.public_key()));
		assert!(allowlist.is_authorized(&keypair.public_key()));
		// The `.auth` file body matches the keypair's public canonical line.
		let files = allowlist.to_auth_files();
		assert_eq!(files.get("alice.auth").map(String::as_str), Some(format!("{}\n", keypair.public_key()).as_str()));
	}

	#[test]
	fn provision_client_replaces_an_existing_nickname() {
		let mut allowlist = RestrictedDiscovery::new();
		let first = provision_client(&mut allowlist, "bob");
		let second = provision_client(&mut allowlist, "bob");
		assert_eq!(allowlist.len(), 1);
		// The nickname now maps to the second keypair; the first is displaced.
		assert_eq!(allowlist.key_for("bob"), Some(&second.public_key()));
		assert!(!allowlist.is_authorized(&first.public_key()));
	}

	#[test]
	fn debug_redacts_the_secret() {
		let pair = ClientAuthKeypair::from_secret_bytes(SECRET);
		let shown = format!("{pair:?}");
		assert!(shown.contains("<redacted>"));
		assert!(!shown.contains(&pair.secret_base32()));
	}
}

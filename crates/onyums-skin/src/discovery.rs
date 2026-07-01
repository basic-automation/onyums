//! Restricted-discovery orchestration: the strongest, upstream gate.
//!
//! Tor v3 onion services support **client authorization** (a.k.a. restricted
//! discovery): the service encrypts its descriptor to an allowlist of client
//! `x25519` public keys, so a client not on the list cannot even *discover* the
//! service — the allowlist is enforced in descriptor crypto, before any rendezvous
//! circuit is built and before a single byte of application traffic arrives. It is
//! the one gate that sits entirely *upstream* of Skin's HTTP challenge / PoW / WAF
//! layers.
//!
//! Skin does not perform the crypto — Arti does, driven by onyums. What lives here
//! is the **orchestration**: a pure-Rust, offline-testable model of the authorized-
//! client set that onyums can hand to Arti's restricted-discovery config or render
//! into Tor's on-disk `authorized_clients/` files. This module is the "policy as
//! data" half; wiring it into the live Arti config is a host-integration step.
//!
//! The canonical text form of a client key is Tor's `descriptor:x25519:<BASE32>`
//! (RFC 4648 base32 of the 32-byte public key, uppercase, unpadded) — the exact
//! line an `authorized_clients/<name>.auth` file contains. See `ROADMAP.md`
//! (Phase 5, "Restricted-discovery orchestration").

use std::collections::BTreeMap;

/// The `descriptor:x25519:` prefix that precedes the base32 key in Tor's canonical
/// client-authorization text form.
const KEY_PREFIX: &str = "descriptor:x25519:";

/// RFC 4648 base32 alphabet (uppercase, no padding) — Tor's on-the-wire form for
/// client-auth keys.
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A Tor v3 onion-service client-authorization public key: a 32-byte `x25519`
/// public key.
///
/// This is the identity an operator adds to the restricted-discovery allowlist. It
/// round-trips losslessly through Tor's canonical `descriptor:x25519:<BASE32>` text
/// form via [`FromStr`](std::str::FromStr) / [`Display`](std::fmt::Display), so a
/// key copied from an `authorized_clients/*.auth` file parses directly and re-renders
/// byte-identically.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientAuthKey([u8; 32]);

impl ClientAuthKey {
	/// Wrap 32 raw `x25519` public-key bytes.
	#[must_use]
	pub const fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// The raw 32-byte public key.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}

	/// The bare base32 encoding of the key (no `descriptor:x25519:` prefix) — 52
	/// uppercase RFC 4648 characters, unpadded.
	#[must_use]
	pub fn to_base32(&self) -> String {
		base32_encode(&self.0)
	}

	/// Parse a key from its bare base32 form (the part after `descriptor:x25519:`),
	/// accepting either letter case. Rejects non-alphabet characters and any encoding
	/// that does not decode to exactly 32 bytes.
	pub fn from_base32(s: &str) -> Result<Self, ClientAuthKeyError> {
		let bytes = base32_decode(s)?;
		let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| ClientAuthKeyError::WrongLength(v.len()))?;
		Ok(Self(arr))
	}
}

impl std::fmt::Display for ClientAuthKey {
	/// Renders the canonical Tor form: `descriptor:x25519:<BASE32>`.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{KEY_PREFIX}{}", self.to_base32())
	}
}

impl std::str::FromStr for ClientAuthKey {
	type Err = ClientAuthKeyError;

	/// Parse the canonical `descriptor:x25519:<BASE32>` form. Surrounding whitespace
	/// is trimmed; the `descriptor:x25519:` prefix is required (this is the exact line
	/// stored in an `authorized_clients/*.auth` file). To parse a bare base32 key with
	/// no prefix, use [`from_base32`](Self::from_base32).
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let s = s.trim();
		let b32 = s.strip_prefix(KEY_PREFIX).ok_or(ClientAuthKeyError::MissingPrefix)?;
		Self::from_base32(b32)
	}
}

/// Why parsing a [`ClientAuthKey`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAuthKeyError {
	/// The canonical form did not start with `descriptor:x25519:`.
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

impl std::fmt::Display for ClientAuthKeyError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::MissingPrefix => write!(f, "client-auth key must start with `{KEY_PREFIX}`"),
			Self::InvalidChar(pos) => write!(f, "invalid base32 character at position {pos}"),
			Self::NonCanonical => write!(f, "non-canonical base32: trailing bits are not zero"),
			Self::WrongLength(len) => write!(f, "client-auth key must be 32 bytes, got {len}"),
		}
	}
}

impl std::error::Error for ClientAuthKeyError {}

/// Encode bytes as RFC 4648 base32 (uppercase, unpadded).
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

/// Decode an RFC 4648 base32 string (accepting either case, unpadded) into bytes.
/// Rejects out-of-alphabet characters and non-zero trailing bits.
fn base32_decode(s: &str) -> Result<Vec<u8>, ClientAuthKeyError> {
	let mut out = Vec::with_capacity(s.len() * 5 / 8);
	let mut buffer: u64 = 0;
	let mut bits: u32 = 0;
	for (i, c) in s.bytes().enumerate() {
		let val = base32_value(c).ok_or(ClientAuthKeyError::InvalidChar(i))?;
		buffer = (buffer << 5) | u64::from(val);
		bits += 5;
		if bits >= 8 {
			bits -= 8;
			out.push((buffer >> bits) as u8);
		}
	}
	// Any leftover bits (< 8) are padding and must be zero for a canonical encoding.
	if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
		return Err(ClientAuthKeyError::NonCanonical);
	}
	Ok(out)
}

/// Map one base32 character (either case) to its 5-bit value, or `None` if it is not
/// in the RFC 4648 alphabet.
const fn base32_value(c: u8) -> Option<u8> {
	match c {
		b'A'..=b'Z' => Some(c - b'A'),
		b'a'..=b'z' => Some(c - b'a'),
		b'2'..=b'7' => Some(c - b'2' + 26),
		_ => None,
	}
}

/// An operator-managed allowlist of authorized client keys for restricted discovery.
///
/// Each client is stored under a short **nickname** (the file stem Tor uses in
/// `authorized_clients/<nickname>.auth`), mapping to its [`ClientAuthKey`]. The map is
/// ordered ([`BTreeMap`]) so rendering to config/files is deterministic. This is pure
/// data — enforcement happens in Arti's descriptor crypto; onyums reads this set to
/// build that config. See the module docs.
#[derive(Clone, Debug, Default)]
pub struct RestrictedDiscovery {
	clients: BTreeMap<String, ClientAuthKey>,
}

impl RestrictedDiscovery {
	/// An empty allowlist. With no clients, restricted discovery is effectively "off"
	/// until the host decides how to treat an empty set — Skin does not impose that
	/// policy here.
	#[must_use]
	pub fn new() -> Self {
		Self { clients: BTreeMap::new() }
	}

	/// Authorize `key` under `nickname`, returning the previous key if that nickname
	/// was already present (an update). The nickname is the `.auth` file stem.
	pub fn authorize(&mut self, nickname: impl Into<String>, key: ClientAuthKey) -> Option<ClientAuthKey> {
		self.clients.insert(nickname.into(), key)
	}

	/// Remove the client stored under `nickname`, returning its key if present.
	pub fn revoke(&mut self, nickname: &str) -> Option<ClientAuthKey> {
		self.clients.remove(nickname)
	}

	/// The key authorized under `nickname`, if any.
	#[must_use]
	pub fn key_for(&self, nickname: &str) -> Option<&ClientAuthKey> {
		self.clients.get(nickname)
	}

	/// Whether `key` is authorized under *any* nickname — the allowlist membership
	/// test. Restricted discovery is a key-level gate, so identity is the key, not the
	/// nickname.
	#[must_use]
	pub fn is_authorized(&self, key: &ClientAuthKey) -> bool {
		self.clients.values().any(|k| k == key)
	}

	/// Number of authorized clients.
	#[must_use]
	pub fn len(&self) -> usize {
		self.clients.len()
	}

	/// Whether the allowlist is empty.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.clients.is_empty()
	}

	/// Iterate the authorized `(nickname, key)` pairs in nickname order.
	pub fn iter(&self) -> impl Iterator<Item = (&str, &ClientAuthKey)> {
		self.clients.iter().map(|(name, key)| (name.as_str(), key))
	}

	/// Render the allowlist as Tor's on-disk `authorized_clients/` files: a map from
	/// `<nickname>.auth` to that file's one-line `descriptor:x25519:<BASE32>\n` body.
	///
	/// The host (onyums) writes these into the service's `authorized_clients/`
	/// directory (or points Arti's restricted-discovery `key_dirs` at a directory it
	/// materializes). Deterministic (nickname-ordered) so re-rendering an unchanged
	/// allowlist produces byte-identical files.
	#[must_use]
	pub fn to_auth_files(&self) -> BTreeMap<String, String> {
		self.clients.iter().map(|(name, key)| (format!("{name}.auth"), format!("{key}\n"))).collect()
	}

	/// The single `descriptor:x25519:<BASE32>` line for `nickname`, if authorized —
	/// the body of that client's `.auth` file, without a trailing newline.
	#[must_use]
	pub fn auth_line(&self, nickname: &str) -> Option<String> {
		self.clients.get(nickname).map(ToString::to_string)
	}

	/// Parse the contents of an `authorized_clients/<nickname>.auth` file and authorize
	/// the client it names under `nickname`, returning the previous key if that nickname
	/// was already present.
	///
	/// The file format is Tor's: a `descriptor:x25519:<BASE32>` line. Blank lines and
	/// `#` comments are ignored; the first key line is used. An empty file (no key line)
	/// is an [`AuthFileError::Empty`].
	pub fn authorize_auth_file(&mut self, nickname: impl Into<String>, contents: &str) -> Result<Option<ClientAuthKey>, AuthFileError> {
		let key = parse_auth_file(contents)?;
		Ok(self.authorize(nickname, key))
	}
}

/// Parse the contents of a Tor `authorized_clients/*.auth` file into a
/// [`ClientAuthKey`]. Blank lines and lines beginning with `#` are skipped; the first
/// remaining line is parsed as a canonical `descriptor:x25519:<BASE32>` key.
pub fn parse_auth_file(contents: &str) -> Result<ClientAuthKey, AuthFileError> {
	for line in contents.lines() {
		let line = line.trim();
		if line.is_empty() || line.starts_with('#') {
			continue;
		}
		return line.parse().map_err(AuthFileError::Key);
	}
	Err(AuthFileError::Empty)
}

/// Why parsing a `.auth` file failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthFileError {
	/// The file had no key line (only blanks/comments, or was empty).
	Empty,
	/// The key line failed to parse.
	Key(ClientAuthKeyError),
}

impl std::fmt::Display for AuthFileError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Empty => write!(f, "authorized-client file has no `descriptor:x25519:` key line"),
			Self::Key(e) => write!(f, "authorized-client file: {e}"),
		}
	}
}

impl std::error::Error for AuthFileError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Empty => None,
			Self::Key(e) => Some(e),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::str::FromStr;

	/// A deterministic 32-byte key (0,1,2,…,31) and its known canonical form.
	fn sample_key() -> ClientAuthKey {
		let mut bytes = [0u8; 32];
		for (i, b) in bytes.iter_mut().enumerate() {
			*b = i as u8;
		}
		ClientAuthKey::from_bytes(bytes)
	}

	#[test]
	fn base32_matches_rfc4648_test_vectors() {
		// RFC 4648 §10 vectors.
		assert_eq!(base32_encode(b""), "");
		assert_eq!(base32_encode(b"f"), "MY");
		assert_eq!(base32_encode(b"fo"), "MZXQ");
		assert_eq!(base32_encode(b"foo"), "MZXW6");
		assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
		assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
		assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
	}

	#[test]
	fn base32_decodes_rfc4648_test_vectors() {
		assert_eq!(base32_decode("MY").unwrap(), b"f");
		assert_eq!(base32_decode("MZXW6").unwrap(), b"foo");
		assert_eq!(base32_decode("MZXW6YTBOI").unwrap(), b"foobar");
	}

	#[test]
	fn key_round_trips_through_canonical_form() {
		let key = sample_key();
		let text = key.to_string();
		assert!(text.starts_with("descriptor:x25519:"));
		// 32 bytes -> 52 base32 chars.
		assert_eq!(text.len(), "descriptor:x25519:".len() + 52);
		let parsed = ClientAuthKey::from_str(&text).unwrap();
		assert_eq!(parsed, key);
	}

	#[test]
	fn base32_of_key_is_uppercase_and_unpadded() {
		let b32 = sample_key().to_base32();
		assert_eq!(b32.len(), 52);
		assert!(b32.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
		assert!(!b32.contains('='));
	}

	#[test]
	fn parse_accepts_lowercase_base32() {
		let key = sample_key();
		let lower = format!("descriptor:x25519:{}", key.to_base32().to_lowercase());
		assert_eq!(ClientAuthKey::from_str(&lower).unwrap(), key);
	}

	#[test]
	fn parse_trims_surrounding_whitespace() {
		let key = sample_key();
		let padded = format!("  {}\n", key);
		assert_eq!(ClientAuthKey::from_str(&padded).unwrap(), key);
	}

	#[test]
	fn parse_rejects_missing_prefix() {
		let bare = sample_key().to_base32();
		assert_eq!(ClientAuthKey::from_str(&bare), Err(ClientAuthKeyError::MissingPrefix));
	}

	#[test]
	fn parse_rejects_wrong_length() {
		// A valid-but-short base32 ("MY" decodes to 1 byte) is not 32 bytes.
		let err = ClientAuthKey::from_str("descriptor:x25519:MY").unwrap_err();
		assert_eq!(err, ClientAuthKeyError::WrongLength(1));
	}

	#[test]
	fn parse_rejects_invalid_char() {
		// '1', '8', '0', '9' are not in the RFC 4648 base32 alphabet.
		let bad = format!("descriptor:x25519:{}1", "A".repeat(51));
		match ClientAuthKey::from_str(&bad) {
			Err(ClientAuthKeyError::InvalidChar(pos)) => assert_eq!(pos, 51),
			other => panic!("expected InvalidChar, got {other:?}"),
		}
	}

	#[test]
	fn allowlist_authorize_revoke_and_membership() {
		let mut acl = RestrictedDiscovery::new();
		assert!(acl.is_empty());
		let key = sample_key();

		assert_eq!(acl.authorize("alice", key), None);
		assert_eq!(acl.len(), 1);
		assert!(acl.is_authorized(&key));
		assert_eq!(acl.key_for("alice"), Some(&key));

		// Re-authorizing the same nickname reports the previous key.
		let other = ClientAuthKey::from_bytes([9u8; 32]);
		assert_eq!(acl.authorize("alice", other), Some(key));
		assert!(!acl.is_authorized(&key));
		assert!(acl.is_authorized(&other));

		assert_eq!(acl.revoke("alice"), Some(other));
		assert!(acl.is_empty());
		assert_eq!(acl.revoke("alice"), None);
	}

	#[test]
	fn allowlist_iterates_in_nickname_order() {
		let mut acl = RestrictedDiscovery::new();
		acl.authorize("charlie", ClientAuthKey::from_bytes([3u8; 32]));
		acl.authorize("alice", ClientAuthKey::from_bytes([1u8; 32]));
		acl.authorize("bob", ClientAuthKey::from_bytes([2u8; 32]));
		let names: Vec<&str> = acl.iter().map(|(n, _)| n).collect();
		assert_eq!(names, vec!["alice", "bob", "charlie"]);
	}

	#[test]
	fn renders_auth_files_named_and_bodied() {
		let mut acl = RestrictedDiscovery::new();
		let key = sample_key();
		acl.authorize("alice", key);
		let files = acl.to_auth_files();
		assert_eq!(files.len(), 1);
		let body = files.get("alice.auth").expect("alice.auth present");
		assert_eq!(body, &format!("descriptor:x25519:{}\n", key.to_base32()));
		assert_eq!(acl.auth_line("alice"), Some(key.to_string()));
		assert_eq!(acl.auth_line("nobody"), None);
	}

	#[test]
	fn auth_file_round_trips_through_the_allowlist() {
		let mut src = RestrictedDiscovery::new();
		src.authorize("alice", sample_key());
		src.authorize("bob", ClientAuthKey::from_bytes([7u8; 32]));

		// Materialize files, then load each back into a fresh allowlist by file stem.
		let mut loaded = RestrictedDiscovery::new();
		for (name, body) in src.to_auth_files() {
			let nickname = name.strip_suffix(".auth").unwrap().to_string();
			assert_eq!(loaded.authorize_auth_file(nickname, &body).unwrap(), None);
		}
		let a: Vec<_> = src.iter().collect();
		let b: Vec<_> = loaded.iter().collect();
		assert_eq!(a, b);
	}

	#[test]
	fn parse_auth_file_skips_comments_and_blanks() {
		let key = sample_key();
		let contents = format!("# generated by onyums\n\n{key}\n");
		assert_eq!(parse_auth_file(&contents).unwrap(), key);
	}

	#[test]
	fn parse_auth_file_rejects_empty_and_keyless() {
		assert_eq!(parse_auth_file(""), Err(AuthFileError::Empty));
		assert_eq!(parse_auth_file("# only a comment\n\n"), Err(AuthFileError::Empty));
	}

	#[test]
	fn parse_auth_file_surfaces_key_error() {
		match parse_auth_file("descriptor:x25519:MY") {
			Err(AuthFileError::Key(ClientAuthKeyError::WrongLength(1))) => {}
			other => panic!("expected wrapped WrongLength, got {other:?}"),
		}
	}
}

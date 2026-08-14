//! Vanity `.onion` address mining (onyums ROADMAP Phase 1 — stable identity).
//!
//! A v3 onion address *is* the service's ed25519 public key: it is the base32
//! encoding of `pubkey || checksum || version` (rend-spec-v3 §6). "Mining" a
//! vanity address means generating candidate keypairs until the derived address
//! starts with a prefix the operator wants. Nothing in arti does this for you, so
//! onyums builds it in — it is the most self-contained piece of the Phase 1
//! identity story.
//!
//! The address derivation here reuses arti's own [`HsId`] formatting, so a mined
//! address is *exactly* the address arti will serve from the matching key — there
//! is no second, possibly-divergent re-implementation of the encoding to drift out
//! of sync. We never call arti's `Keypair::generate` (it is pinned to a different
//! `rand_core` major than the workspace `rand`); instead we draw a 32-byte ed25519
//! seed from the workspace CSPRNG and build the keypair from it with
//! [`Keypair::from_bytes`]. That seed *is* the importable secret key.
//!
//! Mining is offline and Tor-free, so the whole module is unit-testable with no
//! live network. Wiring a mined key into the launched service's keystore is a
//! later, live-Tor slice; this module produces the key material and the address.

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, bail};
use rand::Rng;
use safelog::DisplayRedacted;
use tor_hscrypto::pk::{HsId, HsIdKey};
use tor_llcrypto::pk::ed25519::{ExpandedKeypair, Keypair};

use crate::OnionAddress;

/// The number of base32 characters in the address part of a v3 `.onion` name
/// (before the `.onion` suffix) — the longest possible vanity prefix.
const ONION_ADDRESS_LEN: usize = 56;

/// The 32-byte tag that prefixes the secret-key material in a Tor
/// `hs_ed25519_secret_key` file — the 29-byte ASCII label
/// `"== ed25519v1-secret: type0 =="` padded to 32 bytes with three NULs. This is
/// the exact tag C tor writes and arti's `CTorServiceKeystore` validates, so a
/// blob onyums renders is byte-identical to one Tor produces, and vice versa.
const HS_ED25519_SECRET_TAG: &[u8; 32] = b"== ed25519v1-secret: type0 ==\x00\x00\x00";

/// Total length of a Tor `hs_ed25519_secret_key` file: the 32-byte
/// `HS_ED25519_SECRET_TAG` followed by the 64-byte *expanded* secret key.
const HS_ED25519_SECRET_FILE_LEN: usize = HS_ED25519_SECRET_TAG.len() + 64;

/// A mined keypair together with the `.onion` address it produces.
///
/// Holds the secret key, so it does not derive [`Debug`] (the manual impl
/// redacts the secret) and should be handled like any other private key.
pub struct VanityKey {
	address: OnionAddress,
	/// The 32-byte ed25519 secret seed. This is the bring-your-own-identity form:
	/// `Keypair::from_bytes(&seed)` reproduces the key, and the address.
	secret_key: [u8; 32],
}

impl VanityKey {
	/// The `.onion` address this key produces — exactly what arti will serve.
	#[must_use]
	pub const fn address(&self) -> &OnionAddress {
		&self.address
	}

	/// The 32-byte ed25519 secret seed.
	///
	/// This is the compact "bring your own key" representation: feeding it back to
	/// [`Keypair::from_bytes`] reconstructs the keypair and the same address.
	#[must_use]
	pub const fn secret_key_bytes(&self) -> [u8; 32] {
		self.secret_key
	}

	/// The 64-byte *expanded* secret key (scalar followed by hash prefix).
	///
	/// This is the form arti's HS identity keystore stores, matching the C tor
	/// implementation — the shape a later "load a mined key into the keystore"
	/// slice will need.
	#[must_use]
	pub fn expanded_secret_key_bytes(&self) -> [u8; 64] {
		ExpandedKeypair::from(&Keypair::from_bytes(&self.secret_key)).to_secret_key_bytes()
	}

	/// Render this key as the contents of a Tor `hs_ed25519_secret_key` file (the
	/// 96-byte tag + expanded-key blob).
	///
	/// Writing these bytes to `hs_ed25519_secret_key` produces a file byte-identical
	/// to one C tor or arti would write for the same identity, so a mined vanity key
	/// can be backed up or loaded into any Tor implementation — and
	/// [`address_from_tor_secret_key_file`] reads it straight back to the same
	/// [`address`](Self::address).
	#[must_use]
	pub fn to_tor_secret_key_file(&self) -> [u8; HS_ED25519_SECRET_FILE_LEN] {
		tor_secret_key_file_from_expanded(self.expanded_secret_key_bytes())
	}
}

impl std::fmt::Debug for VanityKey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("VanityKey").field("address", &self.address).field("secret_key", &"<redacted>").finish()
	}
}

/// Validate a desired vanity prefix against the v3 onion-address alphabet.
///
/// The address part is RFC 4648 base32, rendered lowercase, so the only legal
/// characters are `a`–`z` and `2`–`7`. A prefix with any other character can
/// never match an address and would make the miner spin forever.
///
/// # Errors
/// Returns an error if the prefix is empty, longer than the 56-character address,
/// or contains a character outside the lowercase base32 alphabet.
pub fn validate_prefix(prefix: &str) -> Result<()> {
	if prefix.is_empty() {
		bail!("vanity prefix must not be empty");
	}
	if prefix.len() > ONION_ADDRESS_LEN {
		bail!("vanity prefix is longer than a {ONION_ADDRESS_LEN}-character onion address");
	}
	if let Some(bad) = prefix.chars().find(|c| !matches!(c, 'a'..='z' | '2'..='7')) {
		bail!("vanity prefix character {bad:?} is not in the onion-address alphabet (lowercase a-z and 2-7)");
	}
	Ok(())
}

/// Derive the `.onion` address for a candidate seed, reusing arti's own [`HsId`]
/// rendering so the result matches what arti serves.
fn address_for_seed(seed: &[u8; 32]) -> (OnionAddress, String) {
	let keypair = Keypair::from_bytes(seed);
	let hsid = HsId::from(HsIdKey::from(keypair.verifying_key()));
	let rendered = hsid.display_unredacted().to_string();
	(OnionAddress::normalized(&rendered), rendered)
}

/// Derive the `.onion` address an existing 32-byte ed25519 secret *seed* will
/// serve.
///
/// This is the compact "bring your own identity" check: given the secret seed of
/// an onion service you already run, compute the address onyums would serve from
/// it, so you can confirm a migration preserves your address *before* wiring the
/// key into the keystore. Uses the same arti-canonical derivation as the miner.
#[must_use]
pub fn address_from_secret_seed(seed: &[u8; 32]) -> OnionAddress {
	address_for_seed(seed).0
}

/// Derive the `.onion` address from a 64-byte *expanded* ed25519 secret key — the
/// form arti's HS keystore (and C tor's `hs_ed25519_secret_key`) stores: the
/// secret scalar followed by its hash prefix.
///
/// Unlike a 32-byte seed, an expanded key need not be derivable from any seed, so
/// this is the path for migrating a key exported from an existing onion service.
///
/// # Errors
/// Returns an error if the bytes are not a valid expanded ed25519 secret key.
pub fn address_from_expanded_secret(bytes: [u8; 64]) -> Result<OnionAddress> {
	let keypair = ExpandedKeypair::from_secret_key_bytes(bytes).ok_or_else(|| anyhow::anyhow!("invalid expanded ed25519 secret key"))?;
	let hsid = HsId::from(HsIdKey::from(*keypair.public()));
	Ok(OnionAddress::normalized(&hsid.display_unredacted().to_string()))
}

/// Extract the 64-byte *expanded* ed25519 secret key from the raw contents of a
/// Tor `hs_ed25519_secret_key` file.
///
/// This is the on-disk identity format both C tor and arti's `CTorServiceKeystore`
/// use: a 32-byte `HS_ED25519_SECRET_TAG` tag followed by the 64-byte expanded
/// secret key (secret scalar || hash prefix), for a total of
/// `HS_ED25519_SECRET_FILE_LEN` bytes. Reading this file is the first step of
/// migrating an existing onion service into onyums without changing its address.
///
/// The bytes are validated fully: the exact length, the exact tag, and that the
/// trailing 64 bytes are a well-formed expanded ed25519 keypair — so a truncated
/// or corrupted file is rejected here, offline, rather than at launch.
///
/// # Errors
/// Returns an error if the blob is the wrong length, carries the wrong tag, or does
/// not contain a valid expanded ed25519 secret key.
pub fn expanded_secret_from_tor_file(bytes: &[u8]) -> Result<[u8; 64]> {
	if bytes.len() != HS_ED25519_SECRET_FILE_LEN {
		bail!("hs_ed25519_secret_key must be {HS_ED25519_SECRET_FILE_LEN} bytes (32-byte tag + 64-byte expanded key), got {}", bytes.len());
	}
	let (tag, key) = bytes.split_at(HS_ED25519_SECRET_TAG.len());
	if tag != HS_ED25519_SECRET_TAG.as_slice() {
		bail!("hs_ed25519_secret_key has the wrong tag: not a Tor ed25519v1-secret type0 key file");
	}
	// The length was checked to be exactly `HS_ED25519_SECRET_FILE_LEN` (96) above and
	// the tag is 32 bytes, so `key` is exactly 64 bytes — `copy_from_slice` cannot
	// mismatch, keeping this path panic-free.
	let mut expanded = [0_u8; 64];
	expanded.copy_from_slice(key);
	// Reject a key that carries the right tag but garbage material, so the error is
	// caught here rather than surfacing as a launch failure later.
	ExpandedKeypair::from_secret_key_bytes(expanded).ok_or_else(|| anyhow::anyhow!("hs_ed25519_secret_key does not contain a valid expanded ed25519 secret key"))?;
	Ok(expanded)
}

/// Derive the `.onion` address a Tor `hs_ed25519_secret_key` file will serve.
///
/// The bring-your-own-identity migration check for operators moving an existing
/// onion service into onyums: point this at the service's `hs_ed25519_secret_key`
/// file contents and it returns the exact address onyums would serve from that key,
/// so a migration can be confirmed to preserve the address *before* the key is wired
/// into the keystore. Parses with [`expanded_secret_from_tor_file`] and derives with
/// the same arti-canonical path as the miner.
///
/// # Errors
/// Returns an error if the blob is not a valid Tor `hs_ed25519_secret_key` file (see
/// [`expanded_secret_from_tor_file`]).
pub fn address_from_tor_secret_key_file(bytes: &[u8]) -> Result<OnionAddress> {
	address_from_expanded_secret(expanded_secret_from_tor_file(bytes)?)
}

/// Render a 64-byte *expanded* ed25519 secret key as the contents of a Tor
/// `hs_ed25519_secret_key` file.
///
/// The inverse of [`expanded_secret_from_tor_file`]: prepends the 32-byte
/// `HS_ED25519_SECRET_TAG` to the expanded key, yielding the exact 96-byte blob C
/// tor and arti's keystore expect. Use it to export an onyums-held identity (e.g. a
/// [`mined`](VanityKey) one) into the standard on-disk format — for a backup, or to
/// seed another service — so a key can round-trip out of and back into any Tor
/// implementation without changing its address.
///
/// This does not re-validate the input: callers hold an expanded key they already
/// derived (from a seed or [`expanded_secret_from_tor_file`]), so it is
/// well-formed by construction.
#[must_use]
pub fn tor_secret_key_file_from_expanded(expanded: [u8; 64]) -> [u8; HS_ED25519_SECRET_FILE_LEN] {
	let mut out = [0_u8; HS_ED25519_SECRET_FILE_LEN];
	out[..HS_ED25519_SECRET_TAG.len()].copy_from_slice(HS_ED25519_SECRET_TAG);
	out[HS_ED25519_SECRET_TAG.len()..].copy_from_slice(&expanded);
	out
}

/// Draw one candidate key and return it iff its address begins with `prefix`.
fn try_one(rng: &mut impl Rng, prefix: &str) -> Option<VanityKey> {
	let mut seed = [0_u8; 32];
	rng.fill_bytes(&mut seed);
	let (address, rendered) = address_for_seed(&seed);
	if rendered.starts_with(prefix) { Some(VanityKey { address, secret_key: seed }) } else { None }
}

/// Mine an onion address whose base32 part starts with `prefix`, drawing fresh
/// keypairs until one matches. Single-threaded and unbounded.
///
/// Each extra prefix character multiplies the expected work by 32, so long
/// prefixes can run for a very long time; use [`mine_within`] to bound the
/// search, or the parallel miner for more throughput.
///
/// # Errors
/// Returns an error if `prefix` is not a valid onion-address prefix (see
/// [`validate_prefix`]).
pub fn mine(prefix: &str) -> Result<VanityKey> {
	validate_prefix(prefix)?;
	let mut rng = rand::rng();
	loop {
		if let Some(key) = try_one(&mut rng, prefix) {
			return Ok(key);
		}
	}
}

/// Mine an onion address with a bounded number of attempts.
///
/// Returns `Ok(Some(key))` on the first match, or `Ok(None)` if `max_attempts`
/// candidates were tried without one — the bounded counterpart to [`mine`] for
/// callers that must not block indefinitely.
///
/// # Errors
/// Returns an error if `prefix` is not a valid onion-address prefix (see
/// [`validate_prefix`]).
pub fn mine_within(prefix: &str, max_attempts: u64) -> Result<Option<VanityKey>> {
	validate_prefix(prefix)?;
	let mut rng = rand::rng();
	for _ in 0..max_attempts {
		if let Some(key) = try_one(&mut rng, prefix) {
			return Ok(Some(key));
		}
	}
	Ok(None)
}

/// One mining worker: draw candidates until it finds a match or another worker
/// signals (via `found`) that it already has one.
fn mine_worker(prefix: &str, found: &AtomicBool) -> Option<VanityKey> {
	let mut rng = rand::rng();
	loop {
		if found.load(Ordering::Relaxed) {
			return None;
		}
		if let Some(key) = try_one(&mut rng, prefix) {
			// Tell the other workers to stop; the search is over.
			found.store(true, Ordering::Relaxed);
			return Some(key);
		}
	}
}

/// Mine a vanity onion address across multiple threads, returning the first match
/// any worker finds.
///
/// `threads` is the worker count; pass `0` to use all available cores
/// ([`std::thread::available_parallelism`], falling back to 1). The ed25519
/// derivation that dominates each attempt is CPU-bound and embarrassingly
/// parallel, so throughput scales close to linearly with cores — the whole point
/// of mining anything longer than a couple of characters. Unbounded, like
/// [`mine`]: a long prefix can still run for a very long time.
///
/// # Errors
/// Returns an error if `prefix` is not a valid onion-address prefix (see
/// [`validate_prefix`]).
pub fn mine_parallel(prefix: &str, threads: usize) -> Result<VanityKey> {
	validate_prefix(prefix)?;
	let threads = if threads == 0 { std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get) } else { threads };

	let found = AtomicBool::new(false);
	// `scope` lets the workers borrow `prefix` and `found` directly off the stack
	// and joins them all before returning, so no `Arc` or `'static` bound is needed.
	let winner = std::thread::scope(|s| {
		let handles: Vec<_> = (0..threads).map(|_| s.spawn(|| mine_worker(prefix, &found))).collect();
		handles.into_iter().find_map(|h| h.join().ok().flatten())
	});

	// One worker only returns `None` after another set `found`, so an unbounded
	// search over a valid prefix always yields at least one winner.
	winner.ok_or_else(|| anyhow::anyhow!("vanity mining ended without a match"))
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;

	use super::*;

	#[test]
	fn validate_prefix_accepts_legal_alphabet() {
		assert!(validate_prefix("a").is_ok());
		assert!(validate_prefix("abcdefghijklmnopqrstuvwxyz234567").is_ok());
	}

	#[test]
	fn validate_prefix_rejects_empty() {
		assert!(validate_prefix("").is_err());
	}

	#[test]
	fn validate_prefix_rejects_out_of_alphabet() {
		// Uppercase, and the digits 0/1/8/9 are not in base32.
		assert!(validate_prefix("A").is_err());
		assert!(validate_prefix("test0").is_err());
		assert!(validate_prefix("test1").is_err());
		assert!(validate_prefix("test8").is_err());
		assert!(validate_prefix("test9").is_err());
	}

	#[test]
	fn validate_prefix_rejects_too_long() {
		let too_long = "a".repeat(ONION_ADDRESS_LEN + 1);
		assert!(validate_prefix(&too_long).is_err());
	}

	#[test]
	fn derivation_matches_artis_own_parser() {
		// Derive an address from a generated key, then parse it back with arti's
		// canonical `HsId::from_str`. Equality proves our derivation is the exact
		// encoding arti will serve and accept — not a divergent re-implementation.
		let mut seed = [0_u8; 32];
		rand::rng().fill_bytes(&mut seed);
		let keypair = Keypair::from_bytes(&seed);
		let hsid = HsId::from(HsIdKey::from(keypair.verifying_key()));
		let rendered = hsid.display_unredacted().to_string();

		let parsed = HsId::from_str(&rendered).expect("our rendered address must parse as a valid HsId");
		assert_eq!(parsed, hsid, "round-tripped HsId must equal the original");
		let base32 = rendered.strip_suffix(".onion").expect("rendered address must end in .onion");
		assert_eq!(base32.len(), ONION_ADDRESS_LEN);
	}

	#[test]
	fn mined_address_matches_prefix() {
		// A single base32 character matches roughly 1 in 32 keys, so a few thousand
		// attempts find one with overwhelming probability.
		let key = mine_within("a", 50_000).expect("valid prefix").expect("should find a 1-char match within 50k tries");
		let base32 = key.address().as_str().strip_suffix(".onion").unwrap();
		assert!(base32.starts_with('a'), "address {} should start with 'a'", key.address());
	}

	#[test]
	fn secret_seed_reproduces_address() {
		let key = mine_within("a", 50_000).expect("valid prefix").expect("should find a match");
		// Rebuilding the keypair from the stored 32-byte seed must yield the same
		// address — i.e. the secret we hand back really controls that address.
		let (rebuilt, _) = address_for_seed(&key.secret_key_bytes());
		assert_eq!(&rebuilt, key.address());
	}

	#[test]
	fn expanded_secret_reproduces_public_key() {
		let key = mine_within("a", 50_000).expect("valid prefix").expect("should find a match");
		// The 64-byte expanded form must rebuild to the same public key (and thus
		// the same address) arti's keystore would derive from it.
		let expanded = ExpandedKeypair::from_secret_key_bytes(key.expanded_secret_key_bytes()).expect("valid expanded secret");
		let hsid = HsId::from(HsIdKey::from(*expanded.public()));
		let rendered = hsid.display_unredacted().to_string();
		assert_eq!(OnionAddress::normalized(&rendered), *key.address());
	}

	#[test]
	fn mine_parallel_finds_match() {
		let key = mine_parallel("a", 4).expect("should find a 1-char match across 4 threads");
		let base32 = key.address().as_str().strip_suffix(".onion").unwrap();
		assert!(base32.starts_with('a'), "address {} should start with 'a'", key.address());
		// The returned secret must really control the returned address.
		let (rebuilt, _) = address_for_seed(&key.secret_key_bytes());
		assert_eq!(&rebuilt, key.address());
	}

	#[test]
	fn mine_parallel_zero_threads_uses_all_cores() {
		// `0` means "auto" — must still validate and find a match, never panic.
		let key = mine_parallel("a", 0).expect("auto thread count should find a match");
		let base32 = key.address().as_str().strip_suffix(".onion").unwrap();
		assert!(base32.starts_with('a'));
	}

	#[test]
	fn mine_parallel_rejects_bad_prefix() {
		assert!(mine_parallel("NOT_BASE32", 2).is_err());
	}

	#[test]
	fn byo_secret_seed_derives_the_mined_address() {
		// A mined key's stored seed, fed back through the public BYO helper, must
		// yield the exact address it was mined for.
		let key = mine_within("a", 50_000).expect("valid prefix").expect("should find a match");
		let derived = address_from_secret_seed(&key.secret_key_bytes());
		assert_eq!(&derived, key.address());
	}

	#[test]
	fn byo_expanded_secret_derives_the_mined_address() {
		// The 64-byte expanded form (the keystore/C-tor migration shape) must derive
		// the same address as the compact seed it came from.
		let key = mine_within("a", 50_000).expect("valid prefix").expect("should find a match");
		let derived = address_from_expanded_secret(key.expanded_secret_key_bytes()).expect("valid expanded secret");
		assert_eq!(&derived, key.address());
	}

	#[test]
	fn byo_distinct_seeds_yield_distinct_addresses() {
		let a = address_from_secret_seed(&[1_u8; 32]);
		let b = address_from_secret_seed(&[2_u8; 32]);
		assert_ne!(a, b, "different secret seeds must produce different addresses");
	}

	#[test]
	fn tor_file_round_trips_a_mined_key_to_the_same_address() {
		// Export a mined key to the Tor `hs_ed25519_secret_key` format, then read it
		// back: the parsed expanded key and derived address must equal the originals.
		// This is the full migration loop — mine → write file → (re)import.
		let key = mine_within("a", 50_000).expect("valid prefix").expect("should find a match");
		let blob = key.to_tor_secret_key_file();
		assert_eq!(blob.len(), HS_ED25519_SECRET_FILE_LEN);
		assert_eq!(&blob[..HS_ED25519_SECRET_TAG.len()], HS_ED25519_SECRET_TAG.as_slice(), "the blob must carry the canonical Tor tag");

		let parsed = expanded_secret_from_tor_file(&blob).expect("our own rendered file must parse");
		assert_eq!(parsed, key.expanded_secret_key_bytes(), "the round-tripped expanded key must match");
		let address = address_from_tor_secret_key_file(&blob).expect("our own rendered file must yield an address");
		assert_eq!(&address, key.address(), "the round-tripped address must equal the mined one");
	}

	#[test]
	fn tor_file_render_matches_the_free_function() {
		// The `VanityKey` convenience method is exactly the free renderer applied to
		// the key's expanded bytes.
		let key = mine_within("a", 50_000).expect("valid prefix").expect("should find a match");
		assert_eq!(key.to_tor_secret_key_file(), tor_secret_key_file_from_expanded(key.expanded_secret_key_bytes()));
	}

	#[test]
	fn tor_file_rejects_wrong_length() {
		// A truncated blob (tag + a too-short key) is rejected on length before any
		// tag or key validation.
		let short = vec![0_u8; HS_ED25519_SECRET_FILE_LEN - 1];
		let err = expanded_secret_from_tor_file(&short).expect_err("a short blob must be rejected");
		assert!(err.to_string().contains("bytes"), "unexpected error: {err}");
	}

	#[test]
	fn tor_file_rejects_wrong_tag() {
		// A correctly-sized blob with the wrong tag (e.g. the public-key tag) is
		// rejected as not a secret-key file.
		let key = mine_within("a", 50_000).expect("valid prefix").expect("should find a match");
		let mut blob = key.to_tor_secret_key_file();
		blob[3] = b'X'; // corrupt the tag
		let err = expanded_secret_from_tor_file(&blob).expect_err("a wrong tag must be rejected");
		assert!(err.to_string().contains("tag"), "unexpected error: {err}");
	}

	#[test]
	fn mine_within_can_report_no_match() {
		// A 4-character prefix is ~1 in a million; a single attempt almost never hits
		// it, so this exercises the `Ok(None)` exhaustion path deterministically.
		let outcome = mine_within("test", 1).expect("valid prefix");
		assert!(outcome.is_none(), "one attempt should not find a 4-char vanity match");
	}
}

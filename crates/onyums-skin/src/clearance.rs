//! Stateless, signed clearance tokens — the synthetic per-client identity.
//!
//! A clearance is minted after a client clears a gate and is the key the rate
//! limiter counts on (never an IP). It carries no server-side state; the token is
//! self-verifying via HMAC-SHA256 / JWT. See `ROADMAP.md`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Opaque per-grant identifier; the rate-limit / quota key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TokenId(pub String);

/// Clearance tiers, mirroring Cloudflare's tiered-clearance model: a higher level
/// satisfies lower-level gates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClearanceLevel {
	/// Cleared a timed tarpit (no client compute).
	Patience,
	/// Cleared a server-rendered CAPTCHA (no JS).
	Captcha,
	/// Cleared a proof-of-work challenge.
	Pow,
}

impl ClearanceLevel {
	/// Stable wire encoding for the token payload.
	fn as_u8(self) -> u8 {
		match self {
			ClearanceLevel::Patience => 0,
			ClearanceLevel::Captcha => 1,
			ClearanceLevel::Pow => 2,
		}
	}

	/// Inverse of [`as_u8`](Self::as_u8); `None` for unknown codes.
	fn from_u8(code: u8) -> Option<Self> {
		match code {
			0 => Some(ClearanceLevel::Patience),
			1 => Some(ClearanceLevel::Captcha),
			2 => Some(ClearanceLevel::Pow),
			_ => None,
		}
	}
}

/// A stateless, signed proof that a client cleared a gate.
#[derive(Clone, Debug)]
pub struct Clearance {
	pub id: TokenId,
	pub issued: SystemTime,
	pub expires: SystemTime,
	pub level: ClearanceLevel,
}

/// Mints and verifies stateless signed clearance tokens.
pub trait ClearanceStore: Send + Sync {
	/// Mint a signed token granting `level` for `ttl`.
	fn mint(&self, level: ClearanceLevel, ttl: Duration) -> String;
	/// Verify a token's signature and expiry, returning the `Clearance` it carries.
	fn verify(&self, token: &str) -> Option<Clearance>;
}

/// Domain-separation label for [`HmacClearanceStore::derived`]: binds a derived signing
/// key to this crate and key version, so the same shared secret used elsewhere (or a future
/// key format) cannot collide with a clearance-signing key.
const DERIVE_LABEL: &[u8] = b"onyums-skin/clearance-signing/v1";

/// Default [`ClearanceStore`]: a stateless token signed with HMAC-SHA256.
///
/// The token wire form is `base64url(payload).base64url(tag)`, where the payload is
/// `id|issued|expires|level` (all ASCII) and the tag is
/// `HMAC-SHA256(secret, payload)`. Verification is constant-time
/// ([`Mac::verify_slice`]) and checks expiry against the wall clock. No server-side
/// state is kept, so the secret is the only thing that must be protected.
///
/// **Multi-instance honoring & rotation (ROADMAP Phase 5).** Because verification needs only
/// the secret, an Onionbalance fleet honors each other's tokens by sharing one signing key.
/// Two ways to coordinate:
/// - [`derived`](Self::derived): every backend derives the *same* signing key from one shared
///   secret (a config passphrase) plus a context label — no need to distribute a raw 32-byte
///   key, and the derivation is domain-separated.
/// - [`with_verify_key`](Self::with_verify_key): add verify-only keys so a backend mints with
///   the new key while still accepting tokens minted under a previous key — zero-downtime key
///   rotation across the fleet.
///
/// The minted `id` is a fresh random 128-bit value, suitable as the rate-limiter key
/// and as a `jti` for a future single-use replay cache.
#[derive(Clone)]
pub struct HmacClearanceStore {
	/// The key used to **mint** (and to verify) tokens.
	secret: Vec<u8>,
	/// Additional keys accepted on **verify** only, tried after [`secret`](Self::secret).
	/// Used for key rotation / honoring tokens from backends on an older key.
	extra_verify: Vec<Vec<u8>>,
}

impl HmacClearanceStore {
	/// Build a store over an explicit signing secret (any length).
	pub fn new(secret: impl Into<Vec<u8>>) -> Self {
		Self { secret: secret.into(), extra_verify: Vec::new() }
	}

	/// Build a store whose signing key is **derived** from a shared `secret` and a `context`
	/// label via `HMAC-SHA256(secret, DERIVE_LABEL ‖ context)`. The derivation is
	/// deterministic, so every Onionbalance backend configured with the same `secret` and
	/// `context` produces the *identical* 256-bit signing key and thus honors each other's
	/// tokens — without distributing a raw key. The `context` (e.g. the service name or a key
	/// epoch) gives domain separation between unrelated deployments or rotation generations.
	#[must_use]
	pub fn derived(secret: &[u8], context: &[u8]) -> Self {
		Self::new(derive_key(secret, context))
	}

	/// Build a store over a freshly generated random 256-bit secret. The secret is
	/// process-local; restart or multi-instance setups that must honor each other's
	/// tokens should use [`new`](Self::new) or [`derived`](Self::derived) with a shared
	/// secret instead.
	#[must_use]
	pub fn generate() -> Self {
		let mut secret = vec![0u8; 32];
		rand::rng().fill_bytes(&mut secret);
		Self { secret, extra_verify: Vec::new() }
	}

	/// Add a verify-only key, returning `self` for chaining. Tokens minted under this key
	/// (e.g. by a fleet member on a previous secret, or before a rotation) still verify, but
	/// this store keeps minting under its primary secret. Add several to
	/// span an entire rotation window.
	#[must_use]
	pub fn with_verify_key(mut self, secret: impl Into<Vec<u8>>) -> Self {
		self.extra_verify.push(secret.into());
		self
	}

	/// `HMAC-SHA256(secret, payload)` under the primary signing key.
	fn tag(&self, payload: &[u8]) -> Vec<u8> {
		let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts a key of any length");
		mac.update(payload);
		mac.finalize().into_bytes().to_vec()
	}

	/// Serialize and sign a fully-formed [`Clearance`]. Shared by [`mint`](Self::mint)
	/// and exercised directly in tests (e.g. to craft an already-expired token).
	fn sign(&self, clearance: &Clearance) -> String {
		let payload = format!("{}|{}|{}|{}", clearance.id.0, unix_secs(clearance.issued), unix_secs(clearance.expires), clearance.level.as_u8());
		let tag = self.tag(payload.as_bytes());
		format!("{}.{}", URL_SAFE_NO_PAD.encode(payload.as_bytes()), URL_SAFE_NO_PAD.encode(tag))
	}
}

impl ClearanceStore for HmacClearanceStore {
	fn mint(&self, level: ClearanceLevel, ttl: Duration) -> String {
		let mut id = [0u8; 16];
		rand::rng().fill_bytes(&mut id);
		let issued = SystemTime::now();
		let clearance = Clearance { id: TokenId(URL_SAFE_NO_PAD.encode(id)), issued, expires: issued + ttl, level };
		self.sign(&clearance)
	}

	fn verify(&self, token: &str) -> Option<Clearance> {
		let (payload_b64, tag_b64) = token.split_once('.')?;
		let payload = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
		let tag = URL_SAFE_NO_PAD.decode(tag_b64).ok()?;

		// Constant-time signature check before trusting any field. Try the primary key, then
		// any verify-only keys (rotation / multi-backend honoring); accept on the first match.
		let signed = verify_tag(&self.secret, &payload, &tag) || self.extra_verify.iter().any(|key| verify_tag(key, &payload, &tag));
		if !signed {
			return None;
		}

		let payload = std::str::from_utf8(&payload).ok()?;
		let mut fields = payload.split('|');
		let id = fields.next()?.to_owned();
		let issued = from_unix_secs(fields.next()?.parse().ok()?);
		let expires = from_unix_secs(fields.next()?.parse().ok()?);
		let level = ClearanceLevel::from_u8(fields.next()?.parse().ok()?)?;
		if fields.next().is_some() {
			return None; // trailing garbage
		}

		// Reject expired tokens even though the signature is valid.
		if expires <= SystemTime::now() {
			return None;
		}

		Some(Clearance { id: TokenId(id), issued, expires, level })
	}
}

/// Constant-time check that `tag` is `HMAC-SHA256(secret, payload)`.
fn verify_tag(secret: &[u8], payload: &[u8], tag: &[u8]) -> bool {
	let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts a key of any length");
	mac.update(payload);
	mac.verify_slice(tag).is_ok()
}

/// Derive a 256-bit signing key from a shared `secret` and a `context` label:
/// `HMAC-SHA256(secret, DERIVE_LABEL ‖ context)`. Deterministic and domain-separated, so
/// every backend with the same inputs gets the same key. See [`HmacClearanceStore::derived`].
fn derive_key(secret: &[u8], context: &[u8]) -> Vec<u8> {
	let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts a key of any length");
	mac.update(DERIVE_LABEL);
	mac.update(context);
	mac.finalize().into_bytes().to_vec()
}

/// Seconds since the Unix epoch, saturating at 0 for pre-epoch times (which never
/// occur for minted tokens).
fn unix_secs(t: SystemTime) -> u64 {
	t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Inverse of [`unix_secs`].
fn from_unix_secs(secs: u64) -> SystemTime {
	UNIX_EPOCH + Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn mint_then_verify_roundtrips() {
		let store = HmacClearanceStore::generate();
		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		let clearance = store.verify(&token).expect("freshly minted token must verify");
		assert_eq!(clearance.level, ClearanceLevel::Pow);
		assert!(clearance.expires > clearance.issued);
	}

	#[test]
	fn each_mint_has_a_unique_id() {
		let store = HmacClearanceStore::generate();
		let a = store.verify(&store.mint(ClearanceLevel::Pow, Duration::from_secs(60))).unwrap();
		let b = store.verify(&store.mint(ClearanceLevel::Pow, Duration::from_secs(60))).unwrap();
		assert_ne!(a.id, b.id);
	}

	#[test]
	fn tampered_payload_is_rejected() {
		let store = HmacClearanceStore::generate();
		let token = store.mint(ClearanceLevel::Captcha, Duration::from_secs(300));
		let (payload_b64, tag_b64) = token.split_once('.').unwrap();
		// Re-encode a payload claiming a higher level, keep the original tag.
		let forged_payload = {
			let mut p = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
			*p.last_mut().unwrap() = b'2'; // level Captcha(1) -> Pow(2)
			URL_SAFE_NO_PAD.encode(p)
		};
		let forged = format!("{forged_payload}.{tag_b64}");
		assert!(store.verify(&forged).is_none());
	}

	#[test]
	fn wrong_secret_does_not_verify() {
		let minter = HmacClearanceStore::new(b"secret-a".to_vec());
		let other = HmacClearanceStore::new(b"secret-b".to_vec());
		let token = minter.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		assert!(minter.verify(&token).is_some());
		assert!(other.verify(&token).is_none());
	}

	#[test]
	fn expired_token_is_rejected_despite_valid_signature() {
		let store = HmacClearanceStore::generate();
		let issued = SystemTime::now() - Duration::from_secs(7200);
		let expired = Clearance { id: TokenId("dGVzdA".to_owned()), issued, expires: issued + Duration::from_secs(60), level: ClearanceLevel::Pow };
		let token = store.sign(&expired);
		assert!(store.verify(&token).is_none());
	}

	#[test]
	fn malformed_tokens_are_rejected() {
		let store = HmacClearanceStore::generate();
		assert!(store.verify("").is_none());
		assert!(store.verify("no-dot-here").is_none());
		assert!(store.verify("!!!.@@@").is_none());
	}

	#[test]
	fn derived_stores_from_one_shared_secret_honor_each_others_tokens() {
		// Two Onionbalance backends configured with the same passphrase + context derive the
		// same signing key, so a token minted at one verifies at the other.
		let backend_a = HmacClearanceStore::derived(b"fleet-passphrase", b"my-service");
		let backend_b = HmacClearanceStore::derived(b"fleet-passphrase", b"my-service");
		let token = backend_a.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		assert!(backend_b.verify(&token).is_some(), "a sibling backend must honor the token");
	}

	#[test]
	fn derived_key_is_domain_separated_by_context() {
		// The same passphrase under a different context yields a different key → no honoring.
		let svc1 = HmacClearanceStore::derived(b"fleet-passphrase", b"service-1");
		let svc2 = HmacClearanceStore::derived(b"fleet-passphrase", b"service-2");
		let token = svc1.mint(ClearanceLevel::Captcha, Duration::from_secs(300));
		assert!(svc1.verify(&token).is_some());
		assert!(svc2.verify(&token).is_none(), "a different context must not honor the token");
	}

	#[test]
	fn verify_only_key_accepts_tokens_from_a_previous_secret() {
		// Rotation: the fleet moves to `new`, but a backend still on `old` minted this token.
		// A rotated store mints under `new` yet lists `old` as a verify-only key.
		let old = HmacClearanceStore::new(b"old-secret".to_vec());
		let rotated = HmacClearanceStore::new(b"new-secret".to_vec()).with_verify_key(b"old-secret".to_vec());
		let old_token = old.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		assert!(rotated.verify(&old_token).is_some(), "the old key is still accepted during rotation");
	}

	#[test]
	fn rotated_store_mints_only_under_the_primary_key() {
		// A store with primary `new` + verify-only `old` mints tokens an old-only backend
		// rejects (it mints under `new`), while a new-only backend accepts them.
		let old_only = HmacClearanceStore::new(b"old-secret".to_vec());
		let new_only = HmacClearanceStore::new(b"new-secret".to_vec());
		let rotated = HmacClearanceStore::new(b"new-secret".to_vec()).with_verify_key(b"old-secret".to_vec());
		let token = rotated.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		assert!(new_only.verify(&token).is_some(), "minted under the new (primary) key");
		assert!(old_only.verify(&token).is_none(), "not minted under the old key");
	}

	#[test]
	fn unknown_key_still_rejected_with_verify_keys_present() {
		// Adding verify keys must not turn the store into an accept-all: a token from an
		// unrelated secret is still rejected.
		let store = HmacClearanceStore::new(b"primary".to_vec()).with_verify_key(b"secondary".to_vec());
		let stranger = HmacClearanceStore::new(b"stranger".to_vec());
		let token = stranger.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		assert!(store.verify(&token).is_none());
	}
}

//! Stateless, signed clearance tokens — the synthetic per-client identity.
//!
//! A clearance is minted after a client clears a gate and is the key the rate
//! limiter counts on (never an IP). It carries no server-side state; the token is
//! self-verifying via HMAC-SHA256 / JWT. See `ROADMAP.md`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::RngCore;
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

/// Default [`ClearanceStore`]: a stateless token signed with HMAC-SHA256.
///
/// The token wire form is `base64url(payload).base64url(tag)`, where the payload is
/// `id|issued|expires|level` (all ASCII) and the tag is
/// `HMAC-SHA256(secret, payload)`. Verification is constant-time
/// ([`Mac::verify_slice`]) and checks expiry against the wall clock. No server-side
/// state is kept, so the secret is the only thing that must be protected — and shared
/// across instances for multi-backend honoring (ROADMAP Phase 5).
///
/// The minted `id` is a fresh random 128-bit value, suitable as the rate-limiter key
/// and as a `jti` for a future single-use replay cache.
#[derive(Clone)]
pub struct HmacClearanceStore {
	secret: Vec<u8>,
}

impl HmacClearanceStore {
	/// Build a store over an explicit signing secret (any length).
	pub fn new(secret: impl Into<Vec<u8>>) -> Self {
		Self { secret: secret.into() }
	}

	/// Build a store over a freshly generated random 256-bit secret. The secret is
	/// process-local; restart or multi-instance setups that must honor each other's
	/// tokens should use [`new`](Self::new) with a shared secret instead.
	#[must_use]
	pub fn generate() -> Self {
		let mut secret = vec![0u8; 32];
		rand::rng().fill_bytes(&mut secret);
		Self { secret }
	}

	/// `HMAC-SHA256(secret, payload)`.
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

		// Constant-time signature check before trusting any field.
		let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts a key of any length");
		mac.update(&payload);
		mac.verify_slice(&tag).ok()?;

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
}

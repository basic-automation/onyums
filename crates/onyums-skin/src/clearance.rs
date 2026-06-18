//! Stateless, signed clearance tokens — the synthetic per-client identity.
//!
//! A clearance is minted after a client clears a gate and is the key the rate
//! limiter counts on (never an IP). It carries no server-side state; the token is
//! self-verifying via HMAC-SHA256 / JWT. See `ROADMAP.md`.

use std::time::{Duration, SystemTime};

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

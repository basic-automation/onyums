//! Token/circuit-keyed rate limiting.
//!
//! Reuses `governor` (whose key is generic over `Hash + Eq`), counting on the
//! clearance [`TokenId`] (preferred) or
//! [`CircuitId`](crate::circuit::CircuitId) (fallback) — never an IP. Because a fresh
//! token costs a fresh gate solve, identity rotation is bounded by PoW cost. The
//! limiter lands in onyums-skin v0.1; see `ROADMAP.md`.

use governor::DefaultKeyedRateLimiter;
// Re-export the load-bearing `governor` types so downstream users can construct a
// `Quota` without risking a version skew (DX principle in the ROADMAP).
pub use governor::Quota;

use crate::clearance::TokenId;

/// A token-keyed request rate limiter.
///
/// Each distinct [`TokenId`] gets its own independent GCRA bucket; an un-cleared
/// client therefore cannot spend another token's budget, and a fresh token (which
/// costs a fresh gate solve) is the only way to obtain fresh budget — that asymmetry
/// is the whole point of keying on the clearance rather than a forgeable IP.
pub struct SkinRateLimit {
	limiter: DefaultKeyedRateLimiter<TokenId>,
}

impl SkinRateLimit {
	/// Build a limiter enforcing `quota` per [`TokenId`].
	#[must_use]
	pub fn new(quota: Quota) -> Self {
		Self { limiter: DefaultKeyedRateLimiter::keyed(quota) }
	}

	/// Convenience constructor for a simple "`max` requests per second, burst `max`"
	/// quota.
	#[must_use]
	pub fn per_second(max: std::num::NonZeroU32) -> Self {
		Self::new(Quota::per_second(max))
	}

	/// Account for one request from `key`. Returns `true` if it is within quota and
	/// should be served, `false` if it should be throttled (429 / re-challenge).
	#[must_use]
	pub fn check(&self, key: &TokenId) -> bool {
		self.limiter.check_key(key).is_ok()
	}

	/// Drop per-key state that has fully replenished, reclaiming memory. Safe to call
	/// periodically from a maintenance task; never affects in-flight budgets.
	pub fn retain_recent(&self) {
		self.limiter.retain_recent();
	}
}

#[cfg(test)]
mod tests {
	use std::num::NonZeroU32;

	use super::*;

	fn key(s: &str) -> TokenId {
		TokenId(s.to_owned())
	}

	#[test]
	fn allows_within_burst_then_throttles() {
		let rl = SkinRateLimit::per_second(NonZeroU32::new(3).unwrap());
		let k = key("client");
		// The bucket starts full: the first `burst` requests pass.
		assert!(rl.check(&k));
		assert!(rl.check(&k));
		assert!(rl.check(&k));
		// Replenishment within the test's microseconds is negligible, so the 4th is
		// throttled.
		assert!(!rl.check(&k));
	}

	#[test]
	fn keys_have_independent_buckets() {
		let rl = SkinRateLimit::per_second(NonZeroU32::new(1).unwrap());
		let a = key("a");
		let b = key("b");
		assert!(rl.check(&a));
		assert!(!rl.check(&a)); // a is now exhausted
		assert!(rl.check(&b)); // b is unaffected by a
	}
}

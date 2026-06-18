//! Token/circuit-keyed rate limiting.
//!
//! Reuses `governor` (whose key is generic over `Hash + Eq`), counting on the
//! clearance [`TokenId`](crate::clearance::TokenId) (preferred) or
//! [`CircuitId`](crate::circuit::CircuitId) (fallback) — never an IP. Because a fresh
//! token costs a fresh gate solve, identity rotation is bounded by PoW cost. The
//! limiter lands in onyums-skin v0.1; see `docs/skin.md` §4.4.

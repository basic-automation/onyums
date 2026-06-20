//! # onyums-skin
//!
//! A framework-agnostic, "Cloudflare for Tor" abuse-defense layer for onion services:
//! a challenge / proof-of-work gate, stateless clearance tokens as a synthetic
//! per-client identity, token/circuit-keyed rate limiting, no-JS fallbacks, and a
//! per-circuit policy hook the host (onyums) wires to Arti's `RendRequest` /
//! `StreamRequest`.
//!
//! **Status: Phase 1 (gate core) implemented.** The framework-agnostic HTTP gate is
//! live and usable by any axum app — see [`Skin::secure_default`] for the one-line
//! secure setup, or [`Skin::builder`] to tune it. It ships the [`Hashcash`] proof-of-
//! work [`Challenge`] with a JS interstitial, stateless HMAC [`Clearance`] tokens, a
//! [`PatienceChallenge`] no-JS fallback, a [`ChallengeChain`] fallback selector,
//! token-keyed [`SkinRateLimit`], and the [`SkinLayer`] tower middleware that wires
//! them together with single-use replay protection on solved puzzles. The Tor
//! dimension ([`CircuitPolicy`], Phase 2) and the WAF (Phase 3) remain trait/skeleton
//! stage; the architecture and full plan are pinned in this crate's `ROADMAP.md`.

// Phase 2+ surface (CircuitPolicy, and not-yet-wired builder/limiter helpers) is public
// API that downstreams and later phases consume, but unused within the crate today.
#![allow(dead_code)]

pub mod challenge;
pub mod circuit;
pub mod clearance;
pub mod difficulty;
pub mod layer;
pub mod observe;
pub mod ratelimit;
pub mod waf;

pub use challenge::{
	Challenge, ChallengeChain, Gate, patience::PatienceChallenge, pow::{Hashcash, Pow, PowChallenge, Puzzle}
};
pub use circuit::{
	AccountingCircuitPolicy, CircuitAction, CircuitId, CircuitPolicy, CircuitStats, Clock, ManualClock, StreamTarget, SystemClock
};
pub use clearance::{Clearance, ClearanceLevel, ClearanceStore, HmacClearanceStore, TokenId};
pub use difficulty::AdaptiveDifficulty;
pub use layer::{Skin, SkinBuilder, SkinLayer, SkinService};
pub use observe::{CapturingSink, FanoutSink, MetricsSink, NullSink, SecurityEvent, SecurityEventSink, SecurityMetrics, Severity, TracingSink};
pub use ratelimit::{Quota, SkinRateLimit};
pub use waf::{Rule, Verdict, Waf, WafCategory, WafMatch};

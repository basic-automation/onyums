//! # onyums-skin
//!
//! A framework-agnostic, "Cloudflare for Tor" abuse-defense layer for onion services:
//! a challenge / proof-of-work gate, stateless clearance tokens as a synthetic
//! per-client identity, token/circuit-keyed rate limiting, no-JS fallbacks, and a
//! per-circuit policy hook the host (onyums) wires to Arti's `RendRequest` /
//! `StreamRequest`.
//!
//! **Status: Phases 1–4 implemented.** See [`Skin::secure_default`] for the one-line
//! secure setup, or [`Skin::builder`] to tune it.
//!
//! - **Phase 1 — gate core.** The [`Hashcash`] proof-of-work [`Challenge`] with a JS
//!   interstitial, stateless HMAC [`Clearance`] tokens, a [`PatienceChallenge`] no-JS
//!   fallback, a [`ChallengeChain`] fallback selector, token-keyed [`SkinRateLimit`],
//!   and the [`SkinLayer`] tower middleware that wires them together with single-use
//!   replay protection on solved puzzles.
//! - **Phase 2 — Tor dimension.** A [`CircuitPolicy`] trait with per-circuit accounting
//!   ([`AccountingCircuitPolicy`], [`CircuitStats`]) and [`AdaptiveDifficulty`] /
//!   [`ShapeDifficulty`] PoW-difficulty control.
//! - **Phase 3 — WAF.** A pure-Rust signature engine ([`Waf`]) over `regex` + `aho-corasick`
//!   with a starter ruleset, percent-decode normalization, and OWASP-CRS-style
//!   [`anomaly_score`] block mode.
//! - **Phase 4 — observability.** Typed [`SecurityEvent`]s through a [`SecurityEventSink`]
//!   ([`MetricsSink`]/[`SecurityMetrics`], [`FanoutSink`], [`TracingSink`]) and request-shape
//!   baselining ([`ShapeBaseline`]).
//!
//! - **Phase 5 — frontier (in progress).** JA4H-style HTTP request fingerprinting
//!   ([`Ja4hFingerprint`]) — a cluster/identify key over the request shape that survives
//!   the loss of IP and TLS — heuristic request-shape bot detection ([`BotHeuristics`],
//!   the only Cloudflare bot signal that survives Tor), and an opt-in EquiX PoW backend
//!   (Tor's own Equi-X puzzle via the pure-Rust `equix` crate, behind the LGPL-gated
//!   `equix` feature; `Hashcash` remains the default `Pow`).
//!
//! The remaining Phase 5 work (a `wirefilter` rule-expression front-end,
//! restricted-discovery orchestration, multi-instance clearance coordination) is tracked
//! in this crate's `ROADMAP.md`, which pins the full architecture and plan.

// Phase 2+ surface (CircuitPolicy, and not-yet-wired builder/limiter helpers) is public
// API that downstreams and later phases consume, but unused within the crate today.
#![allow(dead_code)]

pub mod bot;
pub mod challenge;
pub mod circuit;
pub mod clearance;
pub mod difficulty;
pub mod fingerprint;
pub mod layer;
pub mod observe;
pub mod profile;
pub mod ratelimit;
pub mod shape;
pub mod waf;

pub use bot::{BotAssessment, BotHeuristics, BotSignal};
#[cfg(feature = "equix")]
pub use ::equix::{Runtime, RuntimeOption};
#[cfg(feature = "equix")]
pub use challenge::equix::EquiX;
pub use challenge::{
	Challenge, ChallengeChain, Gate, patience::PatienceChallenge, pow::{Hashcash, Pow, PowChallenge, Puzzle}
};
pub use circuit::{
	AccountingCircuitPolicy, CircuitAction, CircuitId, CircuitPolicy, CircuitStats, Clock, ManualClock, StreamTarget, SystemClock
};
pub use clearance::{Clearance, ClearanceLevel, ClearanceStore, HmacClearanceStore, TokenId};
pub use difficulty::{AdaptiveDifficulty, BotDifficulty, ShapeDifficulty};
pub use fingerprint::Ja4hFingerprint;
pub use layer::{Skin, SkinBuilder, SkinLayer, SkinService};
pub use observe::{CapturingSink, FanoutSink, MetricsSink, NullSink, SecurityEvent, SecurityEventSink, SecurityMetrics, Severity, TracingSink};
pub use profile::ClientProfile;
pub use ratelimit::{Quota, SkinRateLimit};
pub use shape::{RequestShape, ShapeBaseline};
pub use waf::{Rule, Verdict, Waf, WafCategory, WafMatch, anomaly_score};

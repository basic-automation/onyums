//! # onyums-skin
//!
//! A framework-agnostic, "Cloudflare for Tor" abuse-defense layer for onion services:
//! a challenge / proof-of-work gate, stateless clearance tokens as a synthetic
//! per-client identity, token/circuit-keyed rate limiting, no-JS fallbacks, and a
//! per-circuit policy hook the host (onyums) wires to Arti's `RendRequest` /
//! `StreamRequest`.
//!
//! **Status: scaffolding.** The architecture, component decisions, and full API are
//! pinned in this crate's `ROADMAP.md`. The types exported here are
//! the v0.1 skeleton; method bodies are intentionally unimplemented until v0.1 lands.

#![allow(dead_code)]

pub mod challenge;
pub mod circuit;
pub mod clearance;
pub mod ratelimit;

pub use challenge::{
	Challenge, Gate, patience::PatienceChallenge, pow::{Hashcash, Pow, Puzzle}
};
pub use circuit::{CircuitAction, CircuitId, CircuitPolicy, StreamTarget};
pub use clearance::{Clearance, ClearanceLevel, ClearanceStore, HmacClearanceStore, TokenId};
pub use ratelimit::{Quota, SkinRateLimit};

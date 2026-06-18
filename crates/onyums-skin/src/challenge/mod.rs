//! Pluggable, no-JS-aware challenge gates.
//!
//! A [`Challenge`] decides what to do with an un-cleared request: pass it, present
//! an interstitial, or reject it. Built-in implementations are PoW (needs JS),
//! server-rendered CAPTCHA (no JS), and a patience tarpit (no JS). See
//! the crate `ROADMAP.md`.

use axum::http::request::Parts;
use axum::response::Response;

use crate::clearance::ClearanceLevel;

pub mod pow;

/// Outcome of presenting/evaluating a gate.
pub enum Gate {
    /// Mint a clearance token at this level.
    Pass(ClearanceLevel),
    /// Serve the interstitial (PoW page, CAPTCHA image, tarpit, ...).
    Present(Response),
    /// Refuse the request.
    Reject,
}

/// A pluggable gate presented to un-cleared clients.
pub trait Challenge: Send + Sync {
    /// Decide what to do for an un-cleared request.
    fn issue(&self, req: &Parts) -> Gate;
    /// Validate a submitted solution (PoW nonce, CAPTCHA answer, ...).
    fn verify(&self, req: &Parts) -> bool;
    /// Whether this challenge requires client-side JS/WASM. Drives selection of a
    /// no-JS fallback for Tor "Safer"/"Safest" clients.
    fn needs_js(&self) -> bool;
}

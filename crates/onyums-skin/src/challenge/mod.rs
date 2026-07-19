//! Pluggable, no-JS-aware challenge gates.
//!
//! A [`Challenge`] decides what to do with an un-cleared request: pass it, present
//! an interstitial, or reject it. Built-in implementations are PoW (needs JS),
//! server-rendered CAPTCHA (no JS), and a patience tarpit (no JS). See
//! the crate `ROADMAP.md`.

use axum::{http::request::Parts, response::Response};

use crate::clearance::ClearanceLevel;

pub mod captcha;
#[cfg(feature = "equix")]
pub mod equix;
pub mod patience;
mod png;
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

/// An ordered fallback chain of challenges.
///
/// This is how Skin guarantees a no-JS client always has a working path (the no-JS
/// strategy in `ROADMAP.md`): the chain is ordered by preference — typically a cheap
/// JS proof-of-work first, then no-JS fallbacks (server-rendered CAPTCHA, patience
/// tarpit) — and [`select`](Self::select) returns the first challenge whose JS
/// requirement the client can satisfy.
///
/// The host decides whether the client can run JS (from configuration or a request
/// hint) and passes it as `client_has_js`; reliable JS detection over a Tor circuit
/// is an open question and is intentionally left to the caller rather than guessed
/// from request headers here.
pub struct ChallengeChain {
	challenges: Vec<Box<dyn Challenge>>,
}

impl ChallengeChain {
	/// Build a chain from challenges in preference order (most-preferred first).
	#[must_use]
	pub fn new(challenges: Vec<Box<dyn Challenge>>) -> Self {
		Self { challenges }
	}

	/// The first challenge appropriate for the client. When `client_has_js` is
	/// `false`, challenges that require JS are skipped. Returns `None` if the chain is
	/// empty or every challenge needs JS the client lacks.
	#[must_use]
	pub fn select(&self, client_has_js: bool) -> Option<&dyn Challenge> {
		self.challenges.iter().map(Box::as_ref).find(|challenge| client_has_js || !challenge.needs_js())
	}

	/// Issue the selected challenge's decision, or [`Gate::Reject`] if no challenge
	/// fits the client (e.g. a no-JS client against a JS-only chain — fail closed).
	#[must_use]
	pub fn issue(&self, req: &Parts, client_has_js: bool) -> Gate {
		match self.select(client_has_js) {
			Some(challenge) => challenge.issue(req),
			None => Gate::Reject,
		}
	}

	/// Accept the request if *any* challenge in the chain validates it — whichever
	/// gate the client actually solved, regardless of which one would be issued now.
	#[must_use]
	pub fn verify(&self, req: &Parts) -> bool {
		self.challenges.iter().any(|challenge| challenge.verify(req))
	}
}

#[cfg(test)]
mod tests {
	use axum::{http::Request, response::IntoResponse};

	use super::*;

	/// A challenge stub with fixed `needs_js` / `verify` answers; `issue` always
	/// presents.
	struct Stub {
		needs_js: bool,
		verifies: bool,
	}

	impl Challenge for Stub {
		fn issue(&self, _req: &Parts) -> Gate {
			Gate::Present(().into_response())
		}

		fn verify(&self, _req: &Parts) -> bool {
			self.verifies
		}

		fn needs_js(&self) -> bool {
			self.needs_js
		}
	}

	fn bare_parts() -> Parts {
		Request::builder().body(()).unwrap().into_parts().0
	}

	#[test]
	fn select_prefers_first_when_client_has_js() {
		let chain = ChallengeChain::new(vec![Box::new(Stub { needs_js: true, verifies: false }), Box::new(Stub { needs_js: false, verifies: false })]);
		assert!(chain.select(true).expect("a challenge fits").needs_js());
	}

	#[test]
	fn select_skips_js_challenges_for_no_js_client() {
		let chain = ChallengeChain::new(vec![Box::new(Stub { needs_js: true, verifies: false }), Box::new(Stub { needs_js: false, verifies: false })]);
		assert!(!chain.select(false).expect("a no-JS fallback fits").needs_js());
	}

	#[test]
	fn no_js_client_against_js_only_chain_fails_closed() {
		let chain = ChallengeChain::new(vec![Box::new(Stub { needs_js: true, verifies: false })]);
		assert!(chain.select(false).is_none());
		assert!(matches!(chain.issue(&bare_parts(), false), Gate::Reject));
	}

	#[test]
	fn fitting_client_is_presented_an_interstitial() {
		let chain = ChallengeChain::new(vec![Box::new(Stub { needs_js: false, verifies: false })]);
		assert!(matches!(chain.issue(&bare_parts(), false), Gate::Present(_)));
	}

	#[test]
	fn verify_accepts_if_any_challenge_validates() {
		let chain = ChallengeChain::new(vec![Box::new(Stub { needs_js: true, verifies: false }), Box::new(Stub { needs_js: false, verifies: true })]);
		assert!(chain.verify(&bare_parts()));
	}

	#[test]
	fn verify_rejects_when_no_challenge_validates() {
		let chain = ChallengeChain::new(vec![Box::new(Stub { needs_js: false, verifies: false })]);
		assert!(!chain.verify(&bare_parts()));
	}
}

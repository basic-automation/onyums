//! The patience tarpit — a no-JS, zero-client-compute fallback gate.
//!
//! Tor Browser "Safer"/"Safest" disable JS *and* WASM, so the PoW challenge cannot
//! run there. The tarpit degrades instead of failing: it serves an interstitial that
//! reloads itself after a fixed delay via `<meta http-equiv="refresh">` — no script,
//! no compute. The cost a bot pays is wall-clock time, the only resource a no-JS
//! client can be made to spend.
//!
//! It is **stateless**: the "you started waiting at T" ticket is a short-lived signed
//! [`Clearance`](crate::clearance::Clearance) at [`ClearanceLevel::Patience`], carried
//! in a cookie. On reload the cookie returns; the gate passes once the clearance's
//! `issued` instant is at least `delay` in the past. Reusing the clearance signer
//! means a client cannot forge an older `issued` to skip the wait.
//!
//! Carrier choice: a cookie (`skin_patience`). The cookie-vs-signed-path question and
//! Tor Browser's per-circuit cookie behavior are open questions tracked in
//! `ROADMAP.md`; the tarpit commits to a cookie for now.

use std::time::{Duration, SystemTime};

use axum::{
	http::{HeaderValue, StatusCode, header, request::Parts}, response::{Html, IntoResponse, Response}
};

use super::{Challenge, Gate};
use crate::clearance::{ClearanceLevel, ClearanceStore};

/// Cookie carrying the signed patience ticket.
const TICKET_COOKIE: &str = "skin_patience";

/// Extra lifetime granted to the ticket beyond `delay`, so a client that reloads a
/// little late still finds its ticket valid.
const TTL_GRACE: Duration = Duration::from_secs(300);

/// A no-JS timed tarpit. Generic over the [`ClearanceStore`] used to sign the
/// wait-ticket (typically the same store the rest of Skin mints clearances with).
pub struct PatienceChallenge<S: ClearanceStore> {
	store: S,
	delay: Duration,
}

impl<S: ClearanceStore> PatienceChallenge<S> {
	/// Build a tarpit that makes a client wait `delay` before passing.
	pub fn new(store: S, delay: Duration) -> Self {
		Self { store, delay }
	}

	/// Age of a ticket whose clearance was issued at `issued`, saturating at zero for
	/// clocks that appear to run backwards.
	fn age(issued: SystemTime) -> Duration {
		SystemTime::now().duration_since(issued).unwrap_or(Duration::ZERO)
	}

	/// The interstitial: a no-JS page that reloads after `refresh_secs` seconds and
	/// (re)arms the ticket cookie.
	fn wait_page(&self, refresh_secs: u64, token: &str) -> Response {
		let body = format!("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta http-equiv=\"refresh\" content=\"{refresh_secs}\">\n<title>Checking your connection…</title>\n</head>\n<body>\n<h1>Please wait…</h1>\n<p>This page will continue automatically in {refresh_secs} second(s). No JavaScript is required.</p>\n</body>\n</html>\n");
		let mut resp = (StatusCode::SERVICE_UNAVAILABLE, Html(body)).into_response();
		let cookie = format!("{TICKET_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict");
		// The token is base64url + '.', always a valid header value; fall back to
		// presenting without the cookie rather than panicking if that ever changes.
		if let Ok(value) = HeaderValue::from_str(&cookie) {
			resp.headers_mut().insert(header::SET_COOKIE, value);
		}
		resp
	}
}

/// Read the patience ticket out of the request's `Cookie` header, if present.
fn read_ticket(req: &Parts) -> Option<String> {
	let cookies = req.headers.get(header::COOKIE)?.to_str().ok()?;
	cookies.split(';').find_map(|pair| pair.trim().strip_prefix(&format!("{TICKET_COOKIE}=")).map(str::to_owned))
}

impl<S: ClearanceStore> Challenge for PatienceChallenge<S> {
	fn issue(&self, req: &Parts) -> Gate {
		// A valid, sufficiently-aged ticket clears the tarpit.
		if let Some(token) = read_ticket(req)
			&& let Some(clearance) = self.store.verify(&token)
			&& clearance.level == ClearanceLevel::Patience
		{
			let age = Self::age(clearance.issued);
			if age >= self.delay {
				return Gate::Pass(ClearanceLevel::Patience);
			}
			// Still waiting: re-present with the same ticket, refreshing for the
			// remaining time.
			let remaining = (self.delay - age).as_secs().max(1);
			return Gate::Present(self.wait_page(remaining, &token));
		}
		// No (valid) ticket: mint one and start the clock. The TTL outlives the wait
		// by `TTL_GRACE` so a slightly-late reload still verifies.
		let token = self.store.mint(ClearanceLevel::Patience, self.delay + TTL_GRACE);
		Gate::Present(self.wait_page(self.delay.as_secs().max(1), &token))
	}

	fn verify(&self, req: &Parts) -> bool {
		read_ticket(req).and_then(|token| self.store.verify(&token)).is_some_and(|clearance| clearance.level == ClearanceLevel::Patience && Self::age(clearance.issued) >= self.delay)
	}

	fn needs_js(&self) -> bool {
		false
	}

	fn granted_level(&self) -> ClearanceLevel {
		ClearanceLevel::Patience
	}
}

#[cfg(test)]
mod tests {
	use axum::http::Request;

	use super::*;
	use crate::clearance::HmacClearanceStore;

	/// Build request `Parts` carrying the given `Cookie` header value.
	fn parts_with_cookie(cookie: &str) -> Parts {
		Request::builder().header(header::COOKIE, cookie).body(()).unwrap().into_parts().0
	}

	/// Build request `Parts` with no cookies.
	fn bare_parts() -> Parts {
		Request::builder().body(()).unwrap().into_parts().0
	}

	/// Pull the `skin_patience` token out of a `Set-Cookie` response header.
	fn token_from_response(resp: &Response) -> String {
		let set = resp.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
		set.split(';').next().unwrap().strip_prefix(&format!("{TICKET_COOKIE}=")).unwrap().to_owned()
	}

	#[test]
	fn needs_js_is_false() {
		let chal = PatienceChallenge::new(HmacClearanceStore::generate(), Duration::from_secs(5));
		assert!(!chal.needs_js());
	}

	#[test]
	fn first_visit_presents_and_sets_cookie() {
		let chal = PatienceChallenge::new(HmacClearanceStore::generate(), Duration::from_secs(5));
		match chal.issue(&bare_parts()) {
			Gate::Present(resp) => {
				assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
				assert!(resp.headers().contains_key(header::SET_COOKIE));
			}
			_ => panic!("first visit must present the interstitial"),
		}
	}

	#[test]
	fn reload_passes_once_delay_elapsed() {
		// delay = 0: the ticket is immediately old enough on reload.
		let chal = PatienceChallenge::new(HmacClearanceStore::generate(), Duration::ZERO);
		let token = match chal.issue(&bare_parts()) {
			Gate::Present(resp) => token_from_response(&resp),
			_ => panic!("first visit must present"),
		};
		let reload = parts_with_cookie(&format!("{TICKET_COOKIE}={token}"));
		assert!(matches!(chal.issue(&reload), Gate::Pass(ClearanceLevel::Patience)));
		assert!(chal.verify(&reload));
	}

	#[test]
	fn reload_still_waits_before_delay() {
		// A long delay: a freshly-minted ticket is not yet old enough.
		let chal = PatienceChallenge::new(HmacClearanceStore::generate(), Duration::from_secs(3600));
		let token = match chal.issue(&bare_parts()) {
			Gate::Present(resp) => token_from_response(&resp),
			_ => panic!("first visit must present"),
		};
		let reload = parts_with_cookie(&format!("{TICKET_COOKIE}={token}"));
		assert!(matches!(chal.issue(&reload), Gate::Present(_)));
		assert!(!chal.verify(&reload));
	}

	#[test]
	fn garbage_cookie_is_treated_as_no_ticket() {
		let chal = PatienceChallenge::new(HmacClearanceStore::generate(), Duration::from_secs(5));
		let req = parts_with_cookie(&format!("{TICKET_COOKIE}=not-a-real-token"));
		// issue mints a fresh ticket (presents); verify rejects the forgery.
		assert!(matches!(chal.issue(&req), Gate::Present(_)));
		assert!(!chal.verify(&req));
	}
}

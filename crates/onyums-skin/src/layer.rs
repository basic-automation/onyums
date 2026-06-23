//! `SkinLayer` — the tower middleware that ties the gate together.
//!
//! On the HTTP path this is the whole Phase-1 gate: for each request it checks for a
//! valid clearance cookie, and if none is present it presents a [`Challenge`]
//! (proof-of-work for JS clients, a no-JS fallback otherwise) instead of the app. A
//! Skin-owned submission route verifies a solved challenge, mints a stateless
//! [`Clearance`], and redirects the client back — after which the clearance cookie
//! carries the synthetic identity that the [`SkinRateLimit`] counts on.
//!
//! The layer order is the one in the crate `ROADMAP.md`'s request lifecycle: WAF
//! inspect → clearance-check → (submission verify) → challenge → rate-limit. The WAF
//! is optional (off unless a [`Waf`] is configured) and, when present, runs first and
//! unconditionally — a signature attack is refused before any clearance or gate work,
//! even on an already-cleared circuit.
//!
//! The middleware is framework-agnostic: it is a plain [`tower_layer::Layer`] over any
//! axum service, so a non-Tor app gets the gate by `Router::layer`-ing it on. The
//! Tor-specific per-circuit dimension is a separate `CircuitPolicy` (Phase 2).

use std::{
	future::Future, num::NonZeroU32, pin::Pin, sync::Arc, task::{Context, Poll}, time::Duration
};

use axum::{
	body::Body, http::{HeaderValue, StatusCode, header, request::Parts}, response::{IntoResponse, Response}
};
use http_body_util::{BodyExt, Limited};
use rand::RngCore;
use tower_layer::Layer;
use tower_service::Service;

use crate::{
	challenge::{Challenge, ChallengeChain, Gate, patience::PatienceChallenge, pow::{Hashcash, PowChallenge}}, clearance::{Clearance, ClearanceLevel, ClearanceStore, HmacClearanceStore}, observe::{SecurityEvent, SecurityEventSink, TracingSink}, ratelimit::SkinRateLimit, waf::{Verdict, Waf, WafMatch}
};

/// Default cookie carrying the minted clearance token.
const DEFAULT_COOKIE: &str = "skin_clearance";
/// Default Skin-owned route the interstitial submits solutions to. Must match the
/// submit path configured on the JS [`PowChallenge`](crate::challenge::pow::PowChallenge).
const DEFAULT_SUBMIT_PATH: &str = "/.skin/pow";
/// Default page a freshly-cleared client is redirected to.
const DEFAULT_RETURN_PATH: &str = "/";
/// Default lifetime of a minted clearance.
const DEFAULT_CLEARANCE_TTL: Duration = Duration::from_secs(3600);

/// Default PoW difficulty for [`Skin::secure_default`] — a few hundred ms of browser
/// work, negligible server-side. Tune via the builder under load.
const DEFAULT_DIFFICULTY: u32 = 18;
/// Default no-JS patience-tarpit wait for [`Skin::secure_default`].
const DEFAULT_PATIENCE_DELAY: Duration = Duration::from_secs(5);
/// Default per-token request rate for [`Skin::secure_default`].
const DEFAULT_RATE_PER_SEC: u32 = 30;

/// The assembled, immutable gate configuration shared (behind an [`Arc`]) by every
/// cloned [`SkinService`]. Build one with [`Skin::builder`].
pub struct Skin {
	store: Arc<dyn ClearanceStore>,
	challenge: ChallengeChain,
	ratelimit: Option<SkinRateLimit>,
	waf: Option<Waf>,
	sink: Arc<dyn SecurityEventSink>,
	cookie_name: String,
	submit_path: String,
	return_path: String,
	clearance_ttl: Duration,
	client_has_js: bool,
}

impl Skin {
	/// Start building a gate.
	#[must_use]
	pub fn builder() -> SkinBuilder {
		SkinBuilder::default()
	}

	/// The batteries-included secure gate, in one call: a JS proof-of-work challenge
	/// with a no-JS patience-tarpit fallback (so a Tor "Safer"/"Safest" client always
	/// has a path), token-keyed rate limiting, and a fresh random signing store.
	///
	/// This is the "secure and complete by default" entry point — relax it by building
	/// with [`Skin::builder`] instead (lower difficulty, no rate limit, a shared store
	/// for multi-instance honoring, ...). Note the store is process-local, so minted
	/// clearances do not survive a restart; pass a shared [`HmacClearanceStore`] via the
	/// builder when that matters.
	///
	/// ```
	/// use axum::{Router, routing::get};
	/// use onyums_skin::Skin;
	///
	/// let app: Router = Router::new().route("/", get(|| async { "hello" }));
	/// // One line turns the app into a PoW-gated, rate-limited, no-JS-capable service.
	/// let gated: Router = app.layer(Skin::secure_default().into_layer());
	/// # let _ = gated;
	/// ```
	#[must_use]
	pub fn secure_default() -> Skin {
		let store = HmacClearanceStore::generate();
		let mut pow_secret = [0u8; 32];
		rand::rng().fill_bytes(&mut pow_secret);
		let rate = SkinRateLimit::per_second(NonZeroU32::new(DEFAULT_RATE_PER_SEC).expect("DEFAULT_RATE_PER_SEC is nonzero"));
		Skin::builder()
			.store(Arc::new(store.clone()))
			.challenge(Box::new(PowChallenge::new(Hashcash, pow_secret.to_vec(), DEFAULT_DIFFICULTY)))
			.challenge(Box::new(PatienceChallenge::new(store, DEFAULT_PATIENCE_DELAY)))
			.rate_limit(rate)
			.waf(Waf::starter())
			.build()
	}

	/// Turn this gate into a [`SkinLayer`] for `Router::layer`.
	#[must_use]
	pub fn into_layer(self) -> SkinLayer {
		SkinLayer { skin: Arc::new(self) }
	}

	/// Read and verify the clearance cookie, if any.
	fn read_clearance(&self, parts: &Parts) -> Option<Clearance> {
		let cookies = parts.headers.get(header::COOKIE)?.to_str().ok()?;
		let prefix = format!("{}=", self.cookie_name);
		let token = cookies.split(';').find_map(|pair| pair.trim().strip_prefix(&prefix).map(str::to_owned))?;
		self.store.verify(&token)
	}

	/// Present the appropriate challenge, minting a clearance directly when the
	/// challenge self-clears (e.g. an aged patience ticket).
	fn present_challenge(&self, parts: &Parts) -> Response {
		match self.challenge.issue(parts, self.client_has_js) {
			Gate::Pass(level) => {
				// A self-clearing challenge (e.g. an aged patience ticket) is a pass.
				self.sink.record(&SecurityEvent::ChallengePassed { level });
				self.cleared_redirect(&self.store.mint(level, self.clearance_ttl))
			}
			Gate::Present(resp) => {
				self.sink.record(&SecurityEvent::ChallengeIssued { client_has_js: self.client_has_js });
				resp
			}
			Gate::Reject => {
				self.sink.record(&SecurityEvent::ChallengeUnavailable);
				(StatusCode::FORBIDDEN, "No challenge available for this client.").into_response()
			}
		}
	}

	/// A 303 redirect back to the return path, setting the clearance cookie.
	fn cleared_redirect(&self, token: &str) -> Response {
		let mut resp = Response::builder().status(StatusCode::SEE_OTHER).header(header::LOCATION, &self.return_path).body(Body::empty()).expect("redirect with a static location is always valid");
		let cookie = format!("{}={token}; Path=/; HttpOnly; SameSite=Strict", self.cookie_name);
		// The token is base64url + '.', always a valid header value; degrade to a
		// cookieless redirect rather than panicking if that ever changes.
		if let Ok(value) = HeaderValue::from_str(&cookie) {
			resp.headers_mut().insert(header::SET_COOKIE, value);
		}
		resp
	}

	/// The core, synchronous gate decision for one request. Kept free of any tower /
	/// async machinery so it is directly unit-testable.
	fn decide(&self, parts: &Parts) -> Decision {
		// 0. WAF inspection runs first and unconditionally: a signature attack is
		//    refused before any clearance or gate work, even on a cleared circuit. (The
		//    request *body*, when body inspection is enabled, is scanned later in `call`,
		//    after the gate clears the request — only forwarded traffic carries a body to
		//    the app, so gated traffic never pays the buffering cost.)
		if let Some(waf) = &self.waf
			&& let Verdict::Block(m) = waf.inspect(parts)
		{
			self.sink.record(&waf_block_event(&m));
			return Decision::Respond(waf_block_response(&m));
		}

		// 1. Already cleared? Rate-limit on the token id, then forward.
		if let Some(clearance) = self.read_clearance(parts) {
			if let Some(rl) = &self.ratelimit
				&& !rl.check(&clearance.id)
			{
				self.sink.record(&SecurityEvent::RateLimited { token: clearance.id });
				return Decision::Respond((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded.").into_response());
			}
			return Decision::Forward;
		}

		// 2. A submission to the Skin-owned route: verify and, on success, mint.
		if parts.uri.path() == self.submit_path {
			if self.challenge.verify(parts) {
				// Phase 1: the submission route is the JS PoW path, so the minted level
				// is Pow. When CAPTCHA lands as a second submitting gate, the level
				// should come from the verifying challenge rather than be assumed here.
				self.sink.record(&SecurityEvent::ChallengePassed { level: ClearanceLevel::Pow });
				let token = self.store.mint(ClearanceLevel::Pow, self.clearance_ttl);
				return Decision::Respond(self.cleared_redirect(&token));
			}
			// A bad/again submission re-presents the challenge (which itself emits a
			// ChallengeIssued event).
			self.sink.record(&SecurityEvent::ChallengeFailed);
			return Decision::Respond(self.present_challenge(parts));
		}

		// 3. No clearance: gate the request.
		Decision::Respond(self.present_challenge(parts))
	}
}

/// The `403` served when a [`Waf`] rule fires (on a request field or its body). A
/// scoring-mode block names the aggregate anomaly score that crossed the threshold.
fn waf_block_response(m: &WafMatch) -> Response {
	let body = match m.score {
		Some(score) => format!("Blocked by WAF rule {} ({}); request anomaly score {score}.", m.rule_id, m.category.name()),
		None => format!("Blocked by WAF rule {} ({}).", m.rule_id, m.category.name()),
	};
	(StatusCode::FORBIDDEN, body).into_response()
}

/// The structured [`SecurityEvent`] for a WAF block, built from the firing match. The
/// match carries the aggregate anomaly score when it came from a scoring-mode block.
fn waf_block_event(m: &WafMatch) -> SecurityEvent {
	SecurityEvent::WafBlock { rule_id: m.rule_id, category: m.category, location: m.location.clone(), score: m.score }
}

/// Outcome of [`Skin::decide`]: either serve a Skin response directly, or let the
/// request through to the wrapped application.
enum Decision {
	/// Serve this response without touching the inner app (interstitial, redirect,
	/// 403, 429).
	Respond(Response),
	/// The client is cleared — forward to the wrapped service.
	Forward,
}

/// A [`tower_layer::Layer`] that wraps a service with the Skin gate. Cheap to clone
/// (an [`Arc`]).
#[derive(Clone)]
pub struct SkinLayer {
	skin: Arc<Skin>,
}

impl<S> Layer<S> for SkinLayer {
	type Service = SkinService<S>;

	fn layer(&self, inner: S) -> SkinService<S> {
		SkinService { skin: self.skin.clone(), inner }
	}
}

/// The [`SkinLayer`]-wrapped service.
#[derive(Clone)]
pub struct SkinService<S> {
	skin: Arc<Skin>,
	inner: S,
}

impl<S> Service<axum::extract::Request> for SkinService<S>
where
	S: Service<axum::extract::Request, Response = Response> + Clone + Send + 'static,
	S::Future: Send + 'static,
{
	type Response = Response;
	type Error = S::Error;
	type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.inner.poll_ready(cx)
	}

	fn call(&mut self, req: axum::extract::Request) -> Self::Future {
		let skin = self.skin.clone();
		// Clone-and-swap so the future drives a service instance that is `poll_ready`,
		// the canonical tower middleware pattern.
		let clone = self.inner.clone();
		let mut inner = std::mem::replace(&mut self.inner, clone);
		Box::pin(async move {
			let (parts, body) = req.into_parts();
			match skin.decide(&parts) {
				Decision::Respond(resp) => Ok(resp),
				Decision::Forward => {
					// The request cleared the gate. If body inspection is enabled, buffer
					// up to the cap and scan it before it reaches the app — a body over the
					// cap is refused rather than forwarded uninspected.
					let body = match skin.waf.as_ref().and_then(Waf::body_cap) {
						Some(cap) => match Limited::new(body, cap).collect().await {
							Ok(collected) => {
								let bytes = collected.to_bytes();
								if let Some(waf) = &skin.waf
									&& let Verdict::Block(m) = waf.inspect_body(&bytes)
								{
									skin.sink.record(&waf_block_event(&m));
									return Ok(waf_block_response(&m));
								}
								Body::from(bytes)
							}
							Err(_) => return Ok((StatusCode::PAYLOAD_TOO_LARGE, "Request body exceeds the WAF inspection limit.").into_response()),
						},
						None => body,
					};
					inner.call(axum::extract::Request::from_parts(parts, body)).await
				}
			}
		})
	}
}

/// Builder for [`Skin`]. Secure-by-default: an unset signing store is a fresh random
/// HMAC store, and a gate with no explicitly-added challenge is a hard 403 (fail
/// closed) rather than open — callers add at least one [`Challenge`].
pub struct SkinBuilder {
	store: Option<Arc<dyn ClearanceStore>>,
	challenges: Vec<Box<dyn Challenge>>,
	ratelimit: Option<SkinRateLimit>,
	waf: Option<Waf>,
	sink: Option<Arc<dyn SecurityEventSink>>,
	cookie_name: String,
	submit_path: String,
	return_path: String,
	clearance_ttl: Duration,
	client_has_js: bool,
}

impl Default for SkinBuilder {
	fn default() -> Self {
		Self { store: None, challenges: Vec::new(), ratelimit: None, waf: None, sink: None, cookie_name: DEFAULT_COOKIE.to_owned(), submit_path: DEFAULT_SUBMIT_PATH.to_owned(), return_path: DEFAULT_RETURN_PATH.to_owned(), clearance_ttl: DEFAULT_CLEARANCE_TTL, client_has_js: true }
	}
}

impl SkinBuilder {
	/// Use an explicit clearance store (e.g. one over a secret shared across
	/// instances). Defaults to a fresh random [`HmacClearanceStore`].
	#[must_use]
	pub fn store(mut self, store: Arc<dyn ClearanceStore>) -> Self {
		self.store = Some(store);
		self
	}

	/// Append a challenge to the fallback chain (most-preferred first — typically the
	/// JS PoW gate, then no-JS fallbacks).
	#[must_use]
	pub fn challenge(mut self, challenge: Box<dyn Challenge>) -> Self {
		self.challenges.push(challenge);
		self
	}

	/// Rate-limit cleared requests, keyed on the clearance token id (never an IP).
	#[must_use]
	pub fn rate_limit(mut self, limiter: SkinRateLimit) -> Self {
		self.ratelimit = Some(limiter);
		self
	}

	/// Route structured [`SecurityEvent`](crate::observe::SecurityEvent)s to a custom
	/// [`SecurityEventSink`] (metrics, audit log, alerting). Defaults to
	/// [`TracingSink`](crate::observe::TracingSink), which logs them under the
	/// `onyums_skin::security` target; pass [`NullSink`](crate::observe::NullSink) to opt
	/// out entirely.
	#[must_use]
	pub fn events(mut self, sink: Arc<dyn SecurityEventSink>) -> Self {
		self.sink = Some(sink);
		self
	}

	/// Inspect requests with a [`Waf`] ahead of the gate (off by default). A blocked
	/// request gets a `403` and never reaches the clearance check, the challenge, or
	/// the app. Use [`Waf::starter`] for the built-in ruleset (as
	/// [`Skin::secure_default`] does) or a custom [`Waf`].
	#[must_use]
	pub fn waf(mut self, waf: Waf) -> Self {
		self.waf = Some(waf);
		self
	}

	/// Override the clearance cookie name (default `skin_clearance`).
	#[must_use]
	pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
		self.cookie_name = name.into();
		self
	}

	/// Override the submission route (default `/.skin/pow`); must match the PoW
	/// challenge's submit path.
	#[must_use]
	pub fn submit_path(mut self, path: impl Into<String>) -> Self {
		self.submit_path = path.into();
		self
	}

	/// Override where a cleared client is redirected (default `/`).
	#[must_use]
	pub fn return_path(mut self, path: impl Into<String>) -> Self {
		self.return_path = path.into();
		self
	}

	/// Override how long a minted clearance is valid (default 1 hour).
	#[must_use]
	pub fn clearance_ttl(mut self, ttl: Duration) -> Self {
		self.clearance_ttl = ttl;
		self
	}

	/// Whether to assume the client can run JavaScript when selecting a challenge from
	/// the chain (default `true`). Reliable per-request JS detection over Tor is an open
	/// question (see `ROADMAP.md`); the host decides.
	#[must_use]
	pub fn client_has_js(mut self, has_js: bool) -> Self {
		self.client_has_js = has_js;
		self
	}

	/// Finish building the gate.
	#[must_use]
	pub fn build(self) -> Skin {
		Skin { store: self.store.unwrap_or_else(|| Arc::new(HmacClearanceStore::generate())), challenge: ChallengeChain::new(self.challenges), ratelimit: self.ratelimit, waf: self.waf, sink: self.sink.unwrap_or_else(|| Arc::new(TracingSink)), cookie_name: self.cookie_name, submit_path: self.submit_path, return_path: self.return_path, clearance_ttl: self.clearance_ttl, client_has_js: self.client_has_js }
	}
}

#[cfg(test)]
mod tests {
	use axum::{Router, http::Request, routing::get};
	use http_body_util::BodyExt;
	use tower_service::Service;

	use super::*;
	use crate::{
		challenge::{patience::PatienceChallenge, pow::{Hashcash, PowChallenge, Puzzle}}, clearance::ClearanceStore, observe::CapturingSink, ratelimit::SkinRateLimit
	};

	/// Test difficulty kept low so the in-test PoW solve returns instantly.
	const TEST_DIFFICULTY: u32 = 8;

	/// A gate with the default PoW challenge over a known store, returning the store so
	/// tests can mint/verify clearance cookies directly.
	fn pow_gate() -> (Skin, Arc<HmacClearanceStore>) {
		let store = Arc::new(HmacClearanceStore::new(b"layer-test-secret".to_vec()));
		let skin = Skin::builder().store(store.clone()).challenge(Box::new(PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY))).build();
		(skin, store)
	}

	fn bare_parts(path: &str) -> Parts {
		Request::builder().uri(path).body(()).unwrap().into_parts().0
	}

	fn parts_with_cookie(path: &str, cookie: &str) -> Parts {
		Request::builder().uri(path).header(header::COOKIE, cookie).body(()).unwrap().into_parts().0
	}

	#[test]
	fn secure_default_gates_uncleared_requests() {
		// The one-call gate must challenge an uncleared request, never forward it.
		let skin = Skin::secure_default();
		assert!(matches!(skin.decide(&bare_parts("/")), Decision::Respond(_)));
	}

	#[test]
	fn uncleared_request_is_challenged() {
		let (skin, _store) = pow_gate();
		match skin.decide(&bare_parts("/")) {
			Decision::Respond(resp) => assert_eq!(resp.status(), StatusCode::OK), // PoW interstitial
			Decision::Forward => panic!("an uncleared request must be challenged, not forwarded"),
		}
	}

	#[test]
	fn valid_clearance_cookie_forwards() {
		let (skin, store) = pow_gate();
		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		let parts = parts_with_cookie("/", &format!("{DEFAULT_COOKIE}={token}"));
		assert!(matches!(skin.decide(&parts), Decision::Forward));
	}

	#[test]
	fn forged_cookie_is_challenged_not_forwarded() {
		let (skin, _store) = pow_gate();
		// A token signed by a different secret must not clear.
		let other = HmacClearanceStore::new(b"not-the-secret".to_vec());
		let token = other.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		let parts = parts_with_cookie("/", &format!("{DEFAULT_COOKIE}={token}"));
		assert!(matches!(skin.decide(&parts), Decision::Respond(_)));
	}

	/// Pull a `var NAME="value";` literal out of the interstitial HTML body.
	fn js_var<'a>(html: &'a str, name: &str) -> &'a str {
		let needle = format!("var {name}=\"");
		let start = html.find(&needle).expect("interstitial embeds the variable") + needle.len();
		let rest = &html[start..];
		&rest[..rest.find('"').expect("variable literal is terminated")]
	}

	#[tokio::test]
	async fn solved_submission_mints_clearance_and_redirects() {
		let (skin, store) = pow_gate();

		// Issue a puzzle through the same challenge config the gate runs, parse the
		// embedded seed + signed envelope out of the interstitial, and solve it.
		let pow = PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY);
		let html = match pow.issue(&bare_parts("/")) {
			Gate::Present(resp) => String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap(),
			_ => panic!("PoW issues an interstitial"),
		};
		let seed_hex = js_var(&html, "SEED");
		let envelope = js_var(&html, "PUZZLE").to_owned();
		let mut seed = [0u8; 32];
		for (i, byte) in seed.iter_mut().enumerate() {
			*byte = u8::from_str_radix(&seed_hex[i * 2..i * 2 + 2], 16).unwrap();
		}
		let nonce = Hashcash.solve(&Puzzle { seed, difficulty: TEST_DIFFICULTY });
		let nonce_b64 = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, nonce);

		// Submit to the Skin-owned route; the gate must mint a clearance and redirect.
		let submission = bare_parts(&format!("{DEFAULT_SUBMIT_PATH}?puzzle={envelope}&nonce={nonce_b64}"));
		let resp = match skin.decide(&submission) {
			Decision::Respond(resp) => resp,
			Decision::Forward => panic!("a fresh submission has no clearance cookie, so it cannot forward"),
		};
		assert_eq!(resp.status(), StatusCode::SEE_OTHER);
		assert_eq!(resp.headers().get(header::LOCATION).unwrap(), DEFAULT_RETURN_PATH);

		// The Set-Cookie must carry a clearance that the gate's store actually verifies.
		let set_cookie = resp.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
		let token = set_cookie.split(';').next().unwrap().strip_prefix(&format!("{DEFAULT_COOKIE}=")).unwrap();
		let clearance = store.verify(token).expect("minted clearance must verify");
		assert_eq!(clearance.level, ClearanceLevel::Pow);
	}

	#[test]
	fn bad_submission_re_presents_the_challenge() {
		let (skin, _store) = pow_gate();
		let submission = bare_parts(&format!("{DEFAULT_SUBMIT_PATH}?puzzle=AAAA.BBBB&nonce=AAAA"));
		match skin.decide(&submission) {
			// Re-presents the JS interstitial (no clearance minted).
			Decision::Respond(resp) => {
				assert_eq!(resp.status(), StatusCode::OK);
				assert!(resp.headers().get(header::SET_COOKIE).is_none_or(|c| !c.to_str().unwrap().starts_with(DEFAULT_COOKIE)));
			}
			Decision::Forward => panic!("a bad submission must not forward"),
		}
	}

	#[test]
	fn rate_limited_cleared_request_gets_429() {
		let store = Arc::new(HmacClearanceStore::new(b"rl-secret".to_vec()));
		let skin = Skin::builder().store(store.clone()).challenge(Box::new(PowChallenge::new(Hashcash, b"p".to_vec(), TEST_DIFFICULTY))).rate_limit(SkinRateLimit::per_second(std::num::NonZeroU32::new(1).unwrap())).build();
		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		let cookie = format!("{DEFAULT_COOKIE}={token}");

		// First request within the burst forwards.
		assert!(matches!(skin.decide(&parts_with_cookie("/", &cookie)), Decision::Forward));
		// The bucket is now drained; a second immediate request is throttled.
		let mut throttled = false;
		for _ in 0..5 {
			if let Decision::Respond(resp) = skin.decide(&parts_with_cookie("/", &cookie)) {
				assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
				throttled = true;
				break;
			}
		}
		assert!(throttled, "a flood of cleared requests on one token must eventually be throttled");
	}

	#[test]
	fn no_js_client_falls_back_to_patience() {
		// A no-JS client against a [PoW, Patience] chain must get the no-JS tarpit, not
		// a JS interstitial.
		let store = Arc::new(HmacClearanceStore::new(b"nojs-secret".to_vec()));
		let skin = Skin::builder().store(store.clone()).client_has_js(false).challenge(Box::new(PowChallenge::new(Hashcash, b"p".to_vec(), TEST_DIFFICULTY))).challenge(Box::new(PatienceChallenge::new((*store).clone(), Duration::from_secs(5)))).build();
		match skin.decide(&bare_parts("/")) {
			// The patience interstitial answers 503 with a Set-Cookie ticket.
			Decision::Respond(resp) => {
				assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
				assert!(resp.headers().contains_key(header::SET_COOKIE));
			}
			Decision::Forward => panic!("a no-JS uncleared request must be challenged"),
		}
	}

	#[tokio::test]
	async fn cleared_request_reaches_the_inner_app() {
		let (skin, store) = pow_gate();
		let app = Router::new().route("/", get(|| async { "hello from the app" }));
		let mut svc = skin.into_layer().layer(app);

		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		let req = Request::builder().uri("/").header(header::COOKIE, format!("{DEFAULT_COOKIE}={token}")).body(Body::empty()).unwrap();
		let resp = svc.call(req).await.unwrap();
		assert_eq!(resp.status(), StatusCode::OK);
		let body = resp.into_body().collect().await.unwrap().to_bytes();
		assert_eq!(&body[..], b"hello from the app");
	}

	#[tokio::test]
	async fn uncleared_request_never_reaches_the_inner_app() {
		let (skin, _store) = pow_gate();
		let app = Router::new().route("/", get(|| async { "SECRET" }));
		let mut svc = skin.into_layer().layer(app);

		let req = Request::builder().uri("/").body(Body::empty()).unwrap();
		let resp = svc.call(req).await.unwrap();
		// The interstitial, not the app's body.
		assert_eq!(resp.status(), StatusCode::OK);
		let body = resp.into_body().collect().await.unwrap().to_bytes();
		assert!(!body.windows(6).any(|w| w == b"SECRET"), "the protected app body must not leak to an uncleared client");
	}

	/// A gate with the starter WAF and a PoW challenge over a known store.
	fn waf_gate() -> (Skin, Arc<HmacClearanceStore>) {
		let store = Arc::new(HmacClearanceStore::new(b"waf-test-secret".to_vec()));
		let skin = Skin::builder()
			.store(store.clone())
			.challenge(Box::new(PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY)))
			.waf(crate::waf::Waf::starter())
			.build();
		(skin, store)
	}

	#[test]
	fn waf_blocks_signature_attack_with_403() {
		let (skin, _store) = waf_gate();
		// An XSS payload in a header value is a hard 403, not the PoW interstitial (200).
		// (The WAF inspects raw request strings; this is the un-encoded literal form.)
		let parts = Request::builder().uri("/").header("user-agent", "<script>alert(1)</script>").body(()).unwrap().into_parts().0;
		match skin.decide(&parts) {
			Decision::Respond(resp) => assert_eq!(resp.status(), StatusCode::FORBIDDEN),
			Decision::Forward => panic!("a signature attack must be blocked, not forwarded"),
		}
	}

	#[test]
	fn waf_runs_ahead_of_clearance() {
		// Even a validly-cleared client cannot smuggle a signature attack through: the
		// WAF refuses it before the clearance check forwards.
		let (skin, store) = waf_gate();
		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		let parts = parts_with_cookie("/files/../../etc/passwd", &format!("{DEFAULT_COOKIE}={token}"));
		match skin.decide(&parts) {
			Decision::Respond(resp) => assert_eq!(resp.status(), StatusCode::FORBIDDEN),
			Decision::Forward => panic!("the WAF must block a cleared client's attack ahead of forwarding"),
		}
	}

	#[test]
	fn waf_lets_benign_uncleared_request_through_to_the_gate() {
		// A clean request still reaches the normal gate (challenged, not 403).
		let (skin, _store) = waf_gate();
		match skin.decide(&bare_parts("/articles/hello-world")) {
			Decision::Respond(resp) => assert_eq!(resp.status(), StatusCode::OK), // PoW interstitial
			Decision::Forward => panic!("an uncleared benign request is challenged"),
		}
	}

	/// A gate whose WAF also inspects request bodies up to `cap` bytes, over a known store.
	fn waf_body_gate(cap: usize) -> (Skin, Arc<HmacClearanceStore>) {
		let store = Arc::new(HmacClearanceStore::new(b"waf-body-secret".to_vec()));
		let skin = Skin::builder()
			.store(store.clone())
			.challenge(Box::new(PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY)))
			.waf(crate::waf::Waf::starter().inspect_body_up_to(cap))
			.build();
		(skin, store)
	}

	#[tokio::test]
	async fn waf_blocks_signature_in_cleared_request_body() {
		// A cleared client cannot smuggle an attack through the request body either.
		let (skin, store) = waf_body_gate(64 * 1024);
		let app = Router::new().route("/post", get(|| async { "app" }));
		let mut svc = skin.into_layer().layer(app);

		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		let req = Request::builder().uri("/post").header(header::COOKIE, format!("{DEFAULT_COOKIE}={token}")).body(Body::from("comment=<script>steal()</script>")).unwrap();
		let resp = svc.call(req).await.unwrap();
		assert_eq!(resp.status(), StatusCode::FORBIDDEN);
	}

	#[tokio::test]
	async fn waf_lets_benign_cleared_body_reach_the_app() {
		let (skin, store) = waf_body_gate(64 * 1024);
		let app = Router::new().route("/post", get(|| async { "app saw it" }));
		let mut svc = skin.into_layer().layer(app);

		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		let req = Request::builder().uri("/post").header(header::COOKIE, format!("{DEFAULT_COOKIE}={token}")).body(Body::from("name=Ada&message=hello")).unwrap();
		let resp = svc.call(req).await.unwrap();
		assert_eq!(resp.status(), StatusCode::OK);
		let body = resp.into_body().collect().await.unwrap().to_bytes();
		assert_eq!(&body[..], b"app saw it");
	}

	#[tokio::test]
	async fn oversize_body_is_refused_with_413() {
		// A body larger than the inspection cap is refused, not forwarded uninspected.
		let (skin, store) = waf_body_gate(16);
		let app = Router::new().route("/post", get(|| async { "app" }));
		let mut svc = skin.into_layer().layer(app);

		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		let req = Request::builder().uri("/post").header(header::COOKIE, format!("{DEFAULT_COOKIE}={token}")).body(Body::from("x".repeat(1024))).unwrap();
		let resp = svc.call(req).await.unwrap();
		assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
	}

	#[tokio::test]
	async fn body_not_inspected_when_disabled() {
		// The default gate (no body inspection) forwards an attack-laden body untouched —
		// proving body inspection is genuinely opt-in.
		let (skin, store) = pow_gate();
		let app = Router::new().route("/post", get(|| async { "app" }));
		let mut svc = skin.into_layer().layer(app);

		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		let req = Request::builder().uri("/post").header(header::COOKIE, format!("{DEFAULT_COOKIE}={token}")).body(Body::from("<script>x</script>")).unwrap();
		let resp = svc.call(req).await.unwrap();
		assert_eq!(resp.status(), StatusCode::OK); // reached the app, not 403
	}

	#[test]
	fn no_waf_by_default_leaves_gate_behaviour_unchanged() {
		// Without a configured WAF, a payload that the starter ruleset would block is
		// merely challenged like any other uncleared request (no 403).
		let (skin, _store) = pow_gate();
		match skin.decide(&bare_parts("/files/../../etc/passwd")) {
			Decision::Respond(resp) => assert_eq!(resp.status(), StatusCode::OK),
			Decision::Forward => panic!("uncleared request is challenged"),
		}
	}

	/// A gate over a known store, the starter WAF, a per-token rate limit, and a
	/// [`CapturingSink`] returned alongside so tests can read the emitted events.
	fn observed_gate(rate: u32) -> (Skin, Arc<HmacClearanceStore>, CapturingSink) {
		let store = Arc::new(HmacClearanceStore::new(b"observe-secret".to_vec()));
		let sink = CapturingSink::new();
		let skin = Skin::builder()
			.store(store.clone())
			.challenge(Box::new(PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY)))
			.waf(crate::waf::Waf::starter())
			.rate_limit(SkinRateLimit::per_second(std::num::NonZeroU32::new(rate).unwrap()))
			.events(Arc::new(sink.clone()))
			.build();
		(skin, store, sink)
	}

	#[test]
	fn waf_block_emits_a_security_event() {
		let (skin, _store, sink) = observed_gate(30);
		let parts = Request::builder().uri("/").header("user-agent", "<script>alert(1)</script>").body(()).unwrap().into_parts().0;
		let _ = skin.decide(&parts);
		let events = sink.events();
		assert_eq!(events.len(), 1, "exactly one WAF block event");
		match &events[0] {
			SecurityEvent::WafBlock { category, location, .. } => {
				assert_eq!(*category, crate::waf::WafCategory::Xss);
				assert!(location.starts_with("header:"), "the match location names the offending header, got {location}");
			}
			other => panic!("expected a WafBlock event, got {other:?}"),
		}
	}

	#[test]
	fn rate_limit_trip_emits_an_event_carrying_the_token() {
		let (skin, store, sink) = observed_gate(1);
		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		let id = store.verify(&token).unwrap().id;
		let cookie = format!("{DEFAULT_COOKIE}={token}");

		// Drain the burst, then flood until throttled.
		assert!(matches!(skin.decide(&parts_with_cookie("/", &cookie)), Decision::Forward));
		for _ in 0..5 {
			if let Decision::Respond(_) = skin.decide(&parts_with_cookie("/", &cookie)) {
				break;
			}
		}

		let events = sink.events();
		assert!(events.iter().any(|e| matches!(e, SecurityEvent::RateLimited { token } if *token == id)), "a throttled request emits a RateLimited event carrying the offending token, got {events:?}");
		// A forwarded (un-throttled) request emits nothing.
		assert!(events.iter().all(|e| matches!(e, SecurityEvent::RateLimited { .. })), "only rate-limit events were expected on this path, got {events:?}");
	}

	#[test]
	fn cleared_benign_request_emits_no_event() {
		let (skin, store, sink) = observed_gate(30);
		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		assert!(matches!(skin.decide(&parts_with_cookie("/", &format!("{DEFAULT_COOKIE}={token}"))), Decision::Forward));
		assert!(sink.is_empty(), "a clean, within-rate, cleared request is not a security event");
	}

	#[tokio::test]
	async fn waf_body_block_emits_a_security_event() {
		// A signature in the request body (inspected after the gate clears) also emits.
		let store = Arc::new(HmacClearanceStore::new(b"observe-body-secret".to_vec()));
		let sink = CapturingSink::new();
		let skin = Skin::builder()
			.store(store.clone())
			.challenge(Box::new(PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY)))
			.waf(crate::waf::Waf::starter().inspect_body_up_to(64 * 1024))
			.events(Arc::new(sink.clone()))
			.build();
		let mut svc = skin.into_layer().layer(Router::new().route("/post", get(|| async { "app" })));

		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		let req = Request::builder().uri("/post").header(header::COOKIE, format!("{DEFAULT_COOKIE}={token}")).body(Body::from("c=<script>steal()</script>")).unwrap();
		let resp = svc.call(req).await.unwrap();
		assert_eq!(resp.status(), StatusCode::FORBIDDEN);

		let events = sink.events();
		assert_eq!(events.len(), 1);
		assert!(matches!(&events[0], SecurityEvent::WafBlock { location, .. } if location == "body"));
	}

	#[test]
	fn uncleared_request_emits_challenge_issued() {
		let (skin, _store, sink) = observed_gate(30);
		let _ = skin.decide(&bare_parts("/"));
		let events = sink.events();
		assert_eq!(events, vec![SecurityEvent::ChallengeIssued { client_has_js: true }]);
	}

	#[test]
	fn bad_submission_emits_failed_then_reissued() {
		let (skin, _store, sink) = observed_gate(30);
		// A garbage submission fails verification, then the gate re-presents the challenge.
		let _ = skin.decide(&bare_parts(&format!("{DEFAULT_SUBMIT_PATH}?puzzle=AAAA.BBBB&nonce=AAAA")));
		let events = sink.events();
		assert_eq!(events, vec![SecurityEvent::ChallengeFailed, SecurityEvent::ChallengeIssued { client_has_js: true }]);
	}

	#[test]
	fn no_available_challenge_emits_unavailable() {
		// A JS-only chain against a no-JS client has no fitting challenge: the gate rejects
		// and emits ChallengeUnavailable.
		let store = Arc::new(HmacClearanceStore::new(b"unavail-secret".to_vec()));
		let sink = CapturingSink::new();
		let skin = Skin::builder()
			.store(store.clone())
			.client_has_js(false)
			.challenge(Box::new(PowChallenge::new(Hashcash, b"p".to_vec(), TEST_DIFFICULTY)))
			.events(Arc::new(sink.clone()))
			.build();
		match skin.decide(&bare_parts("/")) {
			Decision::Respond(resp) => assert_eq!(resp.status(), StatusCode::FORBIDDEN),
			Decision::Forward => panic!("a no-JS client against a JS-only chain must be rejected"),
		}
		assert_eq!(sink.events(), vec![SecurityEvent::ChallengeUnavailable]);
	}

	#[tokio::test]
	async fn solved_submission_emits_challenge_passed() {
		let store = Arc::new(HmacClearanceStore::new(b"pass-secret".to_vec()));
		let sink = CapturingSink::new();
		let skin = Skin::builder().store(store.clone()).challenge(Box::new(PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY))).events(Arc::new(sink.clone())).build();

		// Issue, solve, and submit a real PoW puzzle (mirrors the mint/redirect test).
		let pow = PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY);
		let html = match pow.issue(&bare_parts("/")) {
			Gate::Present(resp) => String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap(),
			_ => panic!("PoW issues an interstitial"),
		};
		let seed_hex = js_var(&html, "SEED");
		let envelope = js_var(&html, "PUZZLE").to_owned();
		let mut seed = [0u8; 32];
		for (i, byte) in seed.iter_mut().enumerate() {
			*byte = u8::from_str_radix(&seed_hex[i * 2..i * 2 + 2], 16).unwrap();
		}
		let nonce = Hashcash.solve(&Puzzle { seed, difficulty: TEST_DIFFICULTY });
		let nonce_b64 = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, nonce);
		let _ = skin.decide(&bare_parts(&format!("{DEFAULT_SUBMIT_PATH}?puzzle={envelope}&nonce={nonce_b64}")));

		assert_eq!(sink.events(), vec![SecurityEvent::ChallengePassed { level: ClearanceLevel::Pow }]);
	}
}

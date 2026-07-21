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
	cache::{CacheKey, CachedResponse, ResponseCache, cache_control_ttl, is_cacheable_method}, challenge::{
		Challenge, ChallengeChain, Gate, captcha::CaptchaChallenge, patience::PatienceChallenge, pow::{Hashcash, PowChallenge}
	}, clearance::{Clearance, ClearanceLevel, ClearanceStore, HmacClearanceStore}, edge::{EdgeDecision, EdgeRules, HeaderMutation, apply_response_headers}, observe::{SecurityEvent, SecurityEventSink, TracingSink}, ratelimit::SkinRateLimit, waf::{Verdict, Waf, WafMatch}
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
	edge: Option<EdgeRules>,
	cache: Option<Arc<ResponseCache>>,
	sink: Arc<dyn SecurityEventSink>,
	cookie_name: String,
	submit_path: String,
	return_path: String,
	clearance_ttl: Duration,
	client_has_js: bool,
	/// Minimum clearance tier that forwards. A cleared client below this tier is
	/// re-challenged for a higher one rather than served. Defaults to
	/// [`ClearanceLevel::Patience`] (the lowest tier), so every clearance forwards —
	/// today's behaviour — until an operator raises it.
	min_clearance: ClearanceLevel,
}

impl Skin {
	/// Start building a gate.
	#[must_use]
	pub fn builder() -> SkinBuilder {
		SkinBuilder::default()
	}

	/// The batteries-included secure gate, in one call: a JS proof-of-work challenge
	/// degrading to a no-JS server-rendered CAPTCHA and then a patience tarpit (so a Tor
	/// "Safer"/"Safest" client always has a path — a human-verification tier first, the
	/// timed tarpit as the last resort), token-keyed rate limiting, and a fresh random
	/// signing store.
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
		let mut captcha_secret = [0u8; 32];
		rand::rng().fill_bytes(&mut captcha_secret);
		let rate = SkinRateLimit::per_second(NonZeroU32::new(DEFAULT_RATE_PER_SEC).expect("DEFAULT_RATE_PER_SEC is nonzero"));
		// The fallback chain, most-preferred first: JS PoW → no-JS CAPTCHA → no-JS tarpit.
		// All three submit to the one Skin-owned route (`DEFAULT_SUBMIT_PATH`); the chain
		// disambiguates by which challenge's `verify` accepts the submission, and mints that
		// challenge's own clearance level.
		Skin::builder()
			.store(Arc::new(store.clone()))
			.challenge(Box::new(PowChallenge::new(Hashcash, pow_secret.to_vec(), DEFAULT_DIFFICULTY)))
			// The CAPTCHA advertises the no-visual escape because a non-visual tarpit tier sits
			// behind it in this chain — a low-vision no-JS client can fall through to it.
			.challenge(Box::new(CaptchaChallenge::new(captcha_secret.to_vec()).with_submit_path(DEFAULT_SUBMIT_PATH).with_no_image_escape(true)))
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

		// 1. Edge rules run ahead of the gate: a matching redirect or block short-circuits
		//    the request without ever minting a clearance or solving a challenge, while
		//    header transforms accumulate and ride out on the eventual forwarded response
		//    (see [`crate::edge`]). WAF inspection still runs first (above) so a signature
		//    attack cannot be smuggled past inspection by an edge rule.
		let edge_headers = match &self.edge {
			Some(edge) => match edge.evaluate(parts) {
				EdgeDecision::Forward { response_headers } => response_headers,
				short_circuit => return Decision::Respond(short_circuit.into_response().expect("a redirect/block edge decision always yields a response")),
			},
			None => Vec::new(),
		};

		// 2. Already cleared at a sufficient tier? Rate-limit on the token id, then forward.
		//    A clearance *below* the required minimum tier (`min_clearance`) does not forward:
		//    it falls through to be re-challenged for a higher tier, so an operator can demand
		//    "CAPTCHA-or-better" (or PoW-only) under attack. The tiers are ordered
		//    Patience < Captcha < Pow; the default minimum is Patience, so every clearance
		//    forwards until an operator raises it.
		// A clearance below the required tier — like no clearance at all — falls through to the
		// challenge/submission path to earn a higher one (it does not forward).
		if let Some(clearance) = self.read_clearance(parts)
			&& clearance.level >= self.min_clearance
		{
			if let Some(rl) = &self.ratelimit
				&& !rl.check(&clearance.id)
			{
				self.sink.record(&SecurityEvent::RateLimited { token: clearance.id });
				return Decision::Respond((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded.").into_response());
			}
			return Decision::Forward { response_headers: edge_headers };
		}

		// 3. A submission to the Skin-owned route: verify and, on success, mint at the level
		//    the *verifying* challenge grants — a PoW solve mints Pow, a CAPTCHA solve mints
		//    Captcha — so the token and the event stream read honestly per gate.
		if parts.uri.path() == self.submit_path {
			if let Some(level) = self.challenge.verify(parts) {
				self.sink.record(&SecurityEvent::ChallengePassed { level });
				let token = self.store.mint(level, self.clearance_ttl);
				return Decision::Respond(self.cleared_redirect(&token));
			}
			// A bad/again submission re-presents the challenge (which itself emits a
			// ChallengeIssued event).
			self.sink.record(&SecurityEvent::ChallengeFailed);
			return Decision::Respond(self.present_challenge(parts));
		}

		// 4. No clearance: gate the request.
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
	/// The client is cleared — forward to the wrapped service, then apply any buffered
	/// edge [`HeaderMutation`]s to the response it produces.
	Forward {
		/// Edge header transforms to apply to the app's response, in match order.
		response_headers: Vec<HeaderMutation>,
	},
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
	type Error = S::Error;
	type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;
	type Response = Response;

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
				Decision::Forward { response_headers } => {
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

					// Response cache (opt-in). Only safe/idempotent GET/HEAD are cacheable, so
					// derive a key only for those. A fresh hit is served straight from the store —
					// the inner router never runs — with the request's edge transforms re-applied,
					// since cached entries hold the raw app response (edge headers are per-request).
					let cache_key = skin.cache.as_ref().filter(|_| is_cacheable_method(&parts.method)).map(|_| CacheKey::from_parts(&parts));
					if let (Some(cache), Some(key)) = (&skin.cache, &cache_key)
						&& let Some(hit) = cache.get(key)
					{
						let mut resp = hit.into_response();
						apply_response_headers(&response_headers, resp.headers_mut());
						return Ok(resp);
					}

					let mut resp = inner.call(axum::extract::Request::from_parts(parts, body)).await?;

					// Store a cacheable app response for next time, honoring its `Cache-Control`
					// (a `no-store`/`no-cache`/`private` or absent/`max-age=0` response is never
					// cached). Buffer the body once to store it, then rebuild the response.
					if let (Some(cache), Some(key)) = (&skin.cache, cache_key)
						&& let Some(ttl) = cache_control_ttl(resp.headers())
					{
						let (rparts, rbody) = resp.into_parts();
						let bytes = match rbody.collect().await {
							Ok(collected) => collected.to_bytes(),
							// A body that fails mid-collect cannot be cached; surface a bare 502
							// rather than a truncated response.
							Err(_) => return Ok((StatusCode::BAD_GATEWAY, "Upstream response body error.").into_response()),
						};
						cache.store(key, CachedResponse::new(rparts.status, rparts.headers.clone(), bytes.to_vec()), ttl);
						resp = Response::from_parts(rparts, Body::from(bytes));
					}

					// Apply the edge header transforms the ruleset accumulated for this request.
					if !response_headers.is_empty() {
						apply_response_headers(&response_headers, resp.headers_mut());
					}
					Ok(resp)
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
	edge: Option<EdgeRules>,
	cache: Option<Arc<ResponseCache>>,
	sink: Option<Arc<dyn SecurityEventSink>>,
	cookie_name: String,
	submit_path: String,
	return_path: String,
	clearance_ttl: Duration,
	client_has_js: bool,
	min_clearance: ClearanceLevel,
}

impl Default for SkinBuilder {
	fn default() -> Self {
		Self {
			store: None,
			challenges: Vec::new(),
			ratelimit: None,
			waf: None,
			edge: None,
			cache: None,
			sink: None,
			cookie_name: DEFAULT_COOKIE.to_owned(),
			submit_path: DEFAULT_SUBMIT_PATH.to_owned(),
			return_path: DEFAULT_RETURN_PATH.to_owned(),
			clearance_ttl: DEFAULT_CLEARANCE_TTL,
			client_has_js: true,
			// The lowest tier, so any clearance forwards by default (opt up, never down).
			min_clearance: ClearanceLevel::Patience,
		}
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

	/// Route structured [`SecurityEvent`]s to a custom
	/// [`SecurityEventSink`] (metrics, audit log, alerting). Defaults to
	/// [`TracingSink`], which logs them under the
	/// `onyums_skin::security` target; pass [`NullSink`](crate::observe::NullSink) to opt
	/// out entirely.
	#[must_use]
	pub fn events(mut self, sink: Arc<dyn SecurityEventSink>) -> Self {
		self.sink = Some(sink);
		self
	}

	/// Install a set of [`EdgeRules`] that run ahead of the gate
	/// (off by default). A matching redirect or block short-circuits the request before any
	/// clearance or challenge work; matching header transforms are applied to the response
	/// the app produces for a cleared request. The WAF (when configured) still inspects
	/// first, so an edge rule can never carry a signature attack past inspection.
	///
	/// The canonical use is the HTTP→HTTPS upgrade
	/// ([`EdgeRules::https_upgrade`](crate::edge::EdgeRules::https_upgrade)), which the host
	/// installs only on its plaintext listener (Skin cannot see the scheme from the request
	/// — see the [`edge`](crate::edge) module docs).
	#[must_use]
	pub fn edge_rules(mut self, rules: EdgeRules) -> Self {
		self.edge = Some(rules);
		self
	}

	/// Serve cleared `GET`/`HEAD` requests from a bounded, TTL-expiring
	/// [`ResponseCache`] (off by default). A fresh hit is
	/// served without running the inner router — a latency win on a hot path over the
	/// expensive rendezvous round-trip. Only responses the app marks cacheable via
	/// `Cache-Control` (a positive `max-age`, not `no-store`/`no-cache`/`private`) are
	/// stored; the cache runs *after* the gate, so an uncleared client is still challenged
	/// before any hit is served. Edge header transforms are re-applied per request, never
	/// cached.
	#[must_use]
	pub fn response_cache(mut self, cache: ResponseCache) -> Self {
		self.cache = Some(Arc::new(cache));
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

	/// Require a minimum [`ClearanceLevel`] to forward a request (default
	/// [`ClearanceLevel::Patience`], the lowest tier — so every clearance forwards). The tiers
	/// are ordered `Patience < Captcha < Pow`; a cleared client holding a token *below* the
	/// minimum is re-challenged for a higher tier instead of being served. This is the "opt up
	/// under attack" knob the tiered clearance model exists for — e.g.
	/// `min_clearance_level(ClearanceLevel::Captcha)` demands human verification (a timed tarpit
	/// ticket no longer suffices), `ClearanceLevel::Pow` demands a JS proof-of-work.
	///
	/// **Trade-off, by design:** setting a minimum above what a client can reach locks that
	/// client out — a no-JS client cannot satisfy `Pow`, so it will be re-challenged
	/// indefinitely. That is the deliberate cost of shedding load under attack; pair a high
	/// minimum with a challenge chain that offers the required tier to the clients you intend to
	/// keep.
	#[must_use]
	pub fn min_clearance_level(mut self, level: ClearanceLevel) -> Self {
		self.min_clearance = level;
		self
	}

	/// Finish building the gate.
	#[must_use]
	pub fn build(self) -> Skin {
		Skin {
			store: self.store.unwrap_or_else(|| Arc::new(HmacClearanceStore::generate())),
			challenge: ChallengeChain::new(self.challenges),
			ratelimit: self.ratelimit,
			waf: self.waf,
			edge: self.edge,
			cache: self.cache,
			sink: self.sink.unwrap_or_else(|| Arc::new(TracingSink)),
			cookie_name: self.cookie_name,
			submit_path: self.submit_path,
			return_path: self.return_path,
			clearance_ttl: self.clearance_ttl,
			client_has_js: self.client_has_js,
			min_clearance: self.min_clearance,
		}
	}
}

#[cfg(test)]
mod tests {
	use axum::{Router, http::Request, routing::get};
	use http_body_util::BodyExt;
	use tower_service::Service;

	use super::*;
	use crate::{
		challenge::{
			patience::PatienceChallenge, pow::{Hashcash, PowChallenge, Puzzle}
		}, clearance::{ClearanceLevel, ClearanceStore}, observe::CapturingSink, ratelimit::SkinRateLimit
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
			Decision::Forward { .. } => panic!("an uncleared request must be challenged, not forwarded"),
		}
	}

	#[test]
	fn valid_clearance_cookie_forwards() {
		let (skin, store) = pow_gate();
		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		let parts = parts_with_cookie("/", &format!("{DEFAULT_COOKIE}={token}"));
		assert!(matches!(skin.decide(&parts), Decision::Forward { .. }));
	}

	#[test]
	fn min_clearance_level_gates_lower_tiers() {
		// With a minimum of Captcha, a Pow or Captcha clearance forwards, but a Patience
		// (tarpit-only) clearance is re-challenged rather than served — the "opt up under attack"
		// knob realizing the tiered clearance model.
		let store = Arc::new(HmacClearanceStore::new(b"min-tier-secret".to_vec()));
		let skin = Skin::builder()
			.store(store.clone())
			.challenge(Box::new(PowChallenge::new(Hashcash, b"p".to_vec(), TEST_DIFFICULTY)))
			.min_clearance_level(ClearanceLevel::Captcha)
			.build();
		let cookie = |token: &str| parts_with_cookie("/", &format!("{DEFAULT_COOKIE}={token}"));

		let pow = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		assert!(matches!(skin.decide(&cookie(&pow)), Decision::Forward { .. }), "Pow (>= Captcha) forwards");
		let captcha = store.mint(ClearanceLevel::Captcha, Duration::from_secs(300));
		assert!(matches!(skin.decide(&cookie(&captcha)), Decision::Forward { .. }), "Captcha (== min) forwards");
		let patience = store.mint(ClearanceLevel::Patience, Duration::from_secs(300));
		assert!(matches!(skin.decide(&cookie(&patience)), Decision::Respond(_)), "Patience (< Captcha) is re-challenged, not forwarded");
	}

	#[test]
	fn default_min_clearance_forwards_every_tier() {
		// The default minimum is the lowest tier, so a Patience clearance still forwards —
		// the min-tier gate is opt-in and changes nothing until raised.
		let store = Arc::new(HmacClearanceStore::new(b"default-min-secret".to_vec()));
		let skin = Skin::builder().store(store.clone()).challenge(Box::new(PowChallenge::new(Hashcash, b"p".to_vec(), TEST_DIFFICULTY))).build();
		let patience = store.mint(ClearanceLevel::Patience, Duration::from_secs(300));
		assert!(matches!(skin.decide(&parts_with_cookie("/", &format!("{DEFAULT_COOKIE}={patience}"))), Decision::Forward { .. }));
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
			Decision::Forward { .. } => panic!("a fresh submission has no clearance cookie, so it cannot forward"),
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
	fn submission_mints_the_verifying_challenges_level() {
		// The layer must mint the level the *verifying* challenge grants, not a hardcoded
		// one. A patience tarpit (delay 0) grants Patience, so a valid aged ticket submitted
		// to the Skin route must mint a *Patience*-level clearance — proving the level now
		// flows from the gate that actually cleared, per the Challenge::granted_level wiring.
		let store = Arc::new(HmacClearanceStore::new(b"lvl-secret".to_vec()));
		let skin = Skin::builder().store(store.clone()).challenge(Box::new(PatienceChallenge::new((*store).clone(), Duration::ZERO))).build();
		// A freshly-minted patience ticket is immediately old enough at delay 0.
		let ticket = store.mint(ClearanceLevel::Patience, Duration::from_secs(300));
		let submission = parts_with_cookie(DEFAULT_SUBMIT_PATH, &format!("skin_patience={ticket}"));
		let resp = match skin.decide(&submission) {
			Decision::Respond(resp) => resp,
			Decision::Forward { .. } => panic!("a fresh submission has no clearance cookie, so it cannot forward"),
		};
		assert_eq!(resp.status(), StatusCode::SEE_OTHER);
		let set_cookie = resp.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
		let token = set_cookie.split(';').next().unwrap().strip_prefix(&format!("{DEFAULT_COOKIE}=")).unwrap();
		let clearance = store.verify(token).expect("minted clearance must verify");
		assert_eq!(clearance.level, ClearanceLevel::Patience, "the minted level must match the challenge that verified, not a hardcoded Pow");
	}

	#[tokio::test]
	async fn no_js_client_is_served_the_captcha_tier() {
		use crate::challenge::captcha::CaptchaChallenge;

		// The secure_default chain shape (PoW → CAPTCHA → tarpit) with JS assumed off: an
		// uncleared no-JS client must be served the CAPTCHA (a no-JS image form), skipping
		// the JS PoW and stopping before the last-resort tarpit.
		let store = Arc::new(HmacClearanceStore::new(b"nojs-secret".to_vec()));
		let skin = Skin::builder()
			.store(store.clone())
			.challenge(Box::new(PowChallenge::new(Hashcash, b"p".to_vec(), TEST_DIFFICULTY)))
			.challenge(Box::new(CaptchaChallenge::new(b"c".to_vec()).with_submit_path(DEFAULT_SUBMIT_PATH)))
			.challenge(Box::new(PatienceChallenge::new((*store).clone(), Duration::from_secs(5))))
			.client_has_js(false)
			.build();
		let resp = match skin.decide(&bare_parts("/")) {
			Decision::Respond(resp) => resp,
			Decision::Forward { .. } => panic!("an uncleared request must be challenged"),
		};
		let body = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
		assert!(body.contains("data:image/png;base64,"), "the no-JS client gets the CAPTCHA image, not the PoW solver or the tarpit");
		assert!(!body.contains("function sha256"), "must not serve the JS PoW solver to a no-JS client");
	}

	#[tokio::test]
	async fn no_visual_escape_routes_a_no_js_client_to_the_tarpit() {
		// The accessibility escape end to end through the gate: a no-JS client that clicks
		// "continue without the image" (the request carries the no-visual marker) is served
		// the non-visual patience tarpit — a 503 wait page with a `skin_patience` ticket —
		// rather than the CAPTCHA image it cannot read. Same chain shape as secure_default.
		use crate::challenge::{NO_VISUAL_HINT, captcha::CaptchaChallenge};

		let store = Arc::new(HmacClearanceStore::new(b"escape-secret".to_vec()));
		let skin = Skin::builder()
			.store(store.clone())
			.challenge(Box::new(PowChallenge::new(Hashcash, b"p".to_vec(), TEST_DIFFICULTY)))
			.challenge(Box::new(CaptchaChallenge::new(b"c".to_vec()).with_submit_path(DEFAULT_SUBMIT_PATH).with_no_image_escape(true)))
			.challenge(Box::new(PatienceChallenge::new((*store).clone(), Duration::from_secs(5))))
			.client_has_js(false)
			.build();

		// Without the hint: the CAPTCHA image tier.
		let plain = match skin.decide(&bare_parts("/")) {
			Decision::Respond(resp) => String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap(),
			Decision::Forward { .. } => panic!("an uncleared request must be challenged"),
		};
		assert!(plain.contains("data:image/png;base64,"), "no hint ⇒ the CAPTCHA image");

		// With the hint: the tarpit, identified by its `skin_patience` Set-Cookie and no image.
		let escaped = match skin.decide(&bare_parts(&format!("/?{NO_VISUAL_HINT}=1"))) {
			Decision::Respond(resp) => resp,
			Decision::Forward { .. } => panic!("an uncleared escaping request must be challenged"),
		};
		assert_eq!(escaped.status(), StatusCode::SERVICE_UNAVAILABLE, "the tarpit answers 503");
		let set_cookie = escaped.headers().get(header::SET_COOKIE).map(|c| c.to_str().unwrap().to_owned());
		assert!(set_cookie.is_some_and(|c| c.starts_with("skin_patience=")), "the escape lands on the patience tarpit (its ticket cookie), not the CAPTCHA");
		let body = String::from_utf8(escaped.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
		assert!(!body.contains("data:image/png;base64,"), "the escaping client must not be served the image it cannot see");
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
			Decision::Forward { .. } => panic!("a bad submission must not forward"),
		}
	}

	#[test]
	fn rate_limited_cleared_request_gets_429() {
		let store = Arc::new(HmacClearanceStore::new(b"rl-secret".to_vec()));
		let skin = Skin::builder().store(store.clone()).challenge(Box::new(PowChallenge::new(Hashcash, b"p".to_vec(), TEST_DIFFICULTY))).rate_limit(SkinRateLimit::per_second(std::num::NonZeroU32::new(1).unwrap())).build();
		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		let cookie = format!("{DEFAULT_COOKIE}={token}");

		// First request within the burst forwards.
		assert!(matches!(skin.decide(&parts_with_cookie("/", &cookie)), Decision::Forward { .. }));
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
			Decision::Forward { .. } => panic!("a no-JS uncleared request must be challenged"),
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
		let skin = Skin::builder().store(store.clone()).challenge(Box::new(PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY))).waf(crate::waf::Waf::starter()).build();
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
			Decision::Forward { .. } => panic!("a signature attack must be blocked, not forwarded"),
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
			Decision::Forward { .. } => panic!("the WAF must block a cleared client's attack ahead of forwarding"),
		}
	}

	#[test]
	fn waf_lets_benign_uncleared_request_through_to_the_gate() {
		// A clean request still reaches the normal gate (challenged, not 403).
		let (skin, _store) = waf_gate();
		match skin.decide(&bare_parts("/articles/hello-world")) {
			Decision::Respond(resp) => assert_eq!(resp.status(), StatusCode::OK), // PoW interstitial
			Decision::Forward { .. } => panic!("an uncleared benign request is challenged"),
		}
	}

	/// A gate whose WAF also inspects request bodies up to `cap` bytes, over a known store.
	fn waf_body_gate(cap: usize) -> (Skin, Arc<HmacClearanceStore>) {
		let store = Arc::new(HmacClearanceStore::new(b"waf-body-secret".to_vec()));
		let skin = Skin::builder().store(store.clone()).challenge(Box::new(PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY))).waf(crate::waf::Waf::starter().inspect_body_up_to(cap)).build();
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
			Decision::Forward { .. } => panic!("uncleared request is challenged"),
		}
	}

	/// A gate over a known store, the starter WAF, a per-token rate limit, and a
	/// [`CapturingSink`] returned alongside so tests can read the emitted events.
	fn observed_gate(rate: u32) -> (Skin, Arc<HmacClearanceStore>, CapturingSink) {
		let store = Arc::new(HmacClearanceStore::new(b"observe-secret".to_vec()));
		let sink = CapturingSink::new();
		let skin = Skin::builder().store(store.clone()).challenge(Box::new(PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY))).waf(crate::waf::Waf::starter()).rate_limit(SkinRateLimit::per_second(std::num::NonZeroU32::new(rate).unwrap())).events(Arc::new(sink.clone())).build();
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

	#[tokio::test]
	async fn scoring_mode_block_surfaces_score_end_to_end() {
		// A scoring-threshold WAF wired into the live service: a request tripping SQLi (5)
		// in the query and XSS (4) in a header sums to 9 >= threshold 8, so it is blocked,
		// the emitted event carries the aggregate score, and the 403 body names it.
		let store = Arc::new(HmacClearanceStore::new(b"observe-score-secret".to_vec()));
		let sink = CapturingSink::new();
		let skin = Skin::builder().store(store.clone()).challenge(Box::new(PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY))).waf(crate::waf::Waf::starter().scoring_threshold(8)).events(Arc::new(sink.clone())).build();
		let mut svc = skin.into_layer().layer(Router::new().route("/", get(|| async { "app" })));

		// Uncleared is fine: WAF inspection runs first, before the clearance gate.
		let req = Request::builder().uri("/items?q=1%20OR%201=1").header("user-agent", "<script>x</script>").body(Body::empty()).unwrap();
		let resp = svc.call(req).await.unwrap();
		assert_eq!(resp.status(), StatusCode::FORBIDDEN);
		let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
		assert!(String::from_utf8_lossy(&body).contains("anomaly score 9"), "the 403 names the aggregate score, got {:?}", String::from_utf8_lossy(&body));

		let events = sink.events();
		assert_eq!(events.len(), 1);
		assert!(matches!(&events[0], SecurityEvent::WafBlock { score: Some(9), category: crate::waf::WafCategory::Sqli, .. }), "the scored block event carries score 9 and names the dominant SQLi rule, got {events:?}");
	}

	#[tokio::test]
	async fn tuned_category_weight_flips_scoring_block_end_to_end() {
		// A lone XSS header scores its default weight 4, under a threshold of 8, so a scoring
		// WAF lets it past inspection (it is then merely challenged like any uncleared
		// request — no WAF block). Raising the XSS weight to 8 via `set_category_weight` makes
		// the same single hit reach the threshold, and it is now blocked end-to-end with the
		// override reflected in both the 403 body and the emitted event — the operator's
		// severity knob, no threshold change.
		let xss_req = || Request::builder().uri("/").header("user-agent", "<script>x</script>").body(Body::empty()).unwrap();

		// Baseline: default XSS weight 4 < threshold 8 → WAF does not block.
		let base_sink = CapturingSink::new();
		let base = Skin::builder().store(Arc::new(HmacClearanceStore::new(b"tune-base-secret".to_vec()))).challenge(Box::new(PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY))).waf(crate::waf::Waf::starter().scoring_threshold(8)).events(Arc::new(base_sink.clone())).build();
		let mut base_svc = base.into_layer().layer(Router::new().route("/", get(|| async { "app" })));
		let base_resp = base_svc.call(xss_req()).await.unwrap();
		assert_ne!(base_resp.status(), StatusCode::FORBIDDEN, "below threshold, the WAF does not block");
		assert!(base_sink.events().iter().all(|e| !matches!(e, SecurityEvent::WafBlock { .. })), "no WAF block at the default weight");

		// Tuned: XSS weight 8 >= threshold 8 → the same request is now blocked.
		let tuned_sink = CapturingSink::new();
		let tuned = Skin::builder().store(Arc::new(HmacClearanceStore::new(b"tune-secret".to_vec()))).challenge(Box::new(PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY))).waf(crate::waf::Waf::starter().scoring_threshold(8).set_category_weight(crate::waf::WafCategory::Xss, 8)).events(Arc::new(tuned_sink.clone())).build();
		let mut tuned_svc = tuned.into_layer().layer(Router::new().route("/", get(|| async { "app" })));
		let tuned_resp = tuned_svc.call(xss_req()).await.unwrap();
		assert_eq!(tuned_resp.status(), StatusCode::FORBIDDEN);
		let body = axum::body::to_bytes(tuned_resp.into_body(), usize::MAX).await.unwrap();
		assert!(String::from_utf8_lossy(&body).contains("anomaly score 8"), "the 403 names the tuned aggregate score, got {:?}", String::from_utf8_lossy(&body));
		let events = tuned_sink.events();
		assert_eq!(events.len(), 1);
		assert!(matches!(&events[0], SecurityEvent::WafBlock { score: Some(8), category: crate::waf::WafCategory::Xss, .. }), "the tuned scored block carries score 8 and names XSS, got {events:?}");
	}

	#[test]
	fn rate_limit_trip_emits_an_event_carrying_the_token() {
		let (skin, store, sink) = observed_gate(1);
		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		let id = store.verify(&token).unwrap().id;
		let cookie = format!("{DEFAULT_COOKIE}={token}");

		// Drain the burst, then flood until throttled.
		assert!(matches!(skin.decide(&parts_with_cookie("/", &cookie)), Decision::Forward { .. }));
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
		assert!(matches!(skin.decide(&parts_with_cookie("/", &format!("{DEFAULT_COOKIE}={token}"))), Decision::Forward { .. }));
		assert!(sink.is_empty(), "a clean, within-rate, cleared request is not a security event");
	}

	#[tokio::test]
	async fn waf_body_block_emits_a_security_event() {
		// A signature in the request body (inspected after the gate clears) also emits.
		let store = Arc::new(HmacClearanceStore::new(b"observe-body-secret".to_vec()));
		let sink = CapturingSink::new();
		let skin = Skin::builder().store(store.clone()).challenge(Box::new(PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY))).waf(crate::waf::Waf::starter().inspect_body_up_to(64 * 1024)).events(Arc::new(sink.clone())).build();
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
		let skin = Skin::builder().store(store.clone()).client_has_js(false).challenge(Box::new(PowChallenge::new(Hashcash, b"p".to_vec(), TEST_DIFFICULTY))).events(Arc::new(sink.clone())).build();
		match skin.decide(&bare_parts("/")) {
			Decision::Respond(resp) => assert_eq!(resp.status(), StatusCode::FORBIDDEN),
			Decision::Forward { .. } => panic!("a no-JS client against a JS-only chain must be rejected"),
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

	/// A gate with an edge ruleset ahead of the PoW gate, over a known store.
	fn edge_gate(rules: crate::edge::EdgeRules) -> (Skin, Arc<HmacClearanceStore>) {
		let store = Arc::new(HmacClearanceStore::new(b"edge-test-secret".to_vec()));
		let skin = Skin::builder().store(store.clone()).challenge(Box::new(PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY))).edge_rules(rules).build();
		(skin, store)
	}

	#[test]
	fn edge_redirect_short_circuits_ahead_of_the_gate() {
		// An uncleared request that matches an edge redirect is 301'd, never challenged: the
		// edge rule fires before any clearance or PoW work.
		let (skin, _store) = edge_gate(crate::edge::EdgeRules::https_upgrade());
		let parts = Request::builder().uri("/login?next=/home").header(header::HOST, "svc.onion").body(()).unwrap().into_parts().0;
		match skin.decide(&parts) {
			Decision::Respond(resp) => {
				assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
				assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "https://svc.onion/login?next=/home");
			}
			Decision::Forward { .. } => panic!("an edge redirect must short-circuit, not forward"),
		}
	}

	#[test]
	fn edge_block_short_circuits_uncleared_and_cleared_alike() {
		use crate::edge::{EdgeAction, EdgeMatch, EdgeRules};
		let (skin, store) = edge_gate(EdgeRules::new().push(EdgeMatch::PathPrefix("/admin".into()), EdgeAction::Block(StatusCode::FORBIDDEN)));
		// Uncleared: blocked outright rather than challenged.
		match skin.decide(&bare_parts("/admin/panel")) {
			Decision::Respond(resp) => assert_eq!(resp.status(), StatusCode::FORBIDDEN),
			Decision::Forward { .. } => panic!("an edge block must short-circuit"),
		}
		// Even a validly-cleared client is blocked (the edge rule runs ahead of the forward).
		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		match skin.decide(&parts_with_cookie("/admin/panel", &format!("{DEFAULT_COOKIE}={token}"))) {
			Decision::Respond(resp) => assert_eq!(resp.status(), StatusCode::FORBIDDEN),
			Decision::Forward { .. } => panic!("an edge block must short-circuit even for a cleared client"),
		}
	}

	#[test]
	fn edge_header_transform_forwards_and_rides_out_on_the_response() {
		use axum::http::{HeaderName, HeaderValue};

		use crate::edge::{EdgeAction, EdgeMatch, EdgeRules};
		// A SetHeader edge rule does not short-circuit — a cleared request forwards carrying
		// the mutation.
		let rules = EdgeRules::new().push(EdgeMatch::Any, EdgeAction::SetHeader(HeaderName::from_static("x-frame-options"), HeaderValue::from_static("DENY")));
		let (skin, store) = edge_gate(rules);
		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		match skin.decide(&parts_with_cookie("/", &format!("{DEFAULT_COOKIE}={token}"))) {
			Decision::Forward { response_headers } => assert_eq!(response_headers.len(), 1, "the header transform is buffered onto the forward"),
			Decision::Respond(_) => panic!("a header transform must not short-circuit"),
		}
	}

	#[tokio::test]
	async fn edge_header_transform_is_applied_to_the_app_response() {
		use axum::http::{HeaderName, HeaderValue};

		use crate::edge::{EdgeAction, EdgeMatch, EdgeRules};
		let rules = EdgeRules::new().push(EdgeMatch::Any, EdgeAction::SetHeader(HeaderName::from_static("x-frame-options"), HeaderValue::from_static("DENY"))).push(EdgeMatch::Any, EdgeAction::RemoveHeader(HeaderName::from_static("server")));
		let (skin, store) = edge_gate(rules);
		let app = Router::new().route("/", get(|| async { ([(HeaderName::from_static("server"), "onyums")], "hello") }));
		let mut svc = skin.into_layer().layer(app);

		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		let req = Request::builder().uri("/").header(header::COOKIE, format!("{DEFAULT_COOKIE}={token}")).body(Body::empty()).unwrap();
		let resp = svc.call(req).await.unwrap();
		assert_eq!(resp.status(), StatusCode::OK);
		assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY", "the edge Set rides out on the app response");
		assert!(!resp.headers().contains_key("server"), "the edge Remove strips the app's header");
		let body = resp.into_body().collect().await.unwrap().to_bytes();
		assert_eq!(&body[..], b"hello");
	}

	#[tokio::test]
	async fn edge_redirect_reaches_the_client_through_the_service() {
		// End to end: an uncleared request over the layered service is redirected, never
		// touching the inner app.
		let (skin, _store) = edge_gate(crate::edge::EdgeRules::https_upgrade());
		let app = Router::new().route("/secret", get(|| async { "SECRET" }));
		let mut svc = skin.into_layer().layer(app);

		let req = Request::builder().uri("/secret").header(header::HOST, "svc.onion").body(Body::empty()).unwrap();
		let resp = svc.call(req).await.unwrap();
		assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
		assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "https://svc.onion/secret");
		let body = resp.into_body().collect().await.unwrap().to_bytes();
		assert!(!body.windows(6).any(|w| w == b"SECRET"), "a redirected request must not reach the inner app");
	}

	#[test]
	fn waf_blocks_ahead_of_a_matching_edge_redirect() {
		use crate::edge::EdgeRules;
		// A request that both trips the WAF and matches a (would-be) edge redirect is blocked
		// by the WAF: inspection runs before edge evaluation, so an edge rule can never carry
		// a signature attack past the WAF.
		let store = Arc::new(HmacClearanceStore::new(b"edge-waf-secret".to_vec()));
		let skin = Skin::builder().store(store).challenge(Box::new(PowChallenge::new(Hashcash, b"puzzle-secret".to_vec(), TEST_DIFFICULTY))).waf(crate::waf::Waf::starter()).edge_rules(EdgeRules::https_upgrade()).build();
		let parts = Request::builder().uri("/files/../../etc/passwd").header(header::HOST, "svc.onion").body(()).unwrap().into_parts().0;
		match skin.decide(&parts) {
			Decision::Respond(resp) => assert_eq!(resp.status(), StatusCode::FORBIDDEN, "the WAF block wins over the edge redirect"),
			Decision::Forward { .. } => panic!("a signature attack must be blocked, not forwarded"),
		}
	}

	#[test]
	fn no_edge_rules_by_default_leaves_forward_unchanged() {
		// Without an edge ruleset, a cleared request forwards with no header mutations.
		let (skin, store) = pow_gate();
		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		match skin.decide(&parts_with_cookie("/", &format!("{DEFAULT_COOKIE}={token}"))) {
			Decision::Forward { response_headers } => assert!(response_headers.is_empty()),
			Decision::Respond(_) => panic!("a cleared request forwards"),
		}
	}

	/// An app whose `/` handler counts its invocations and marks the response cacheable, so a
	/// cache hit is provable by the counter not advancing. Returns the shared counter.
	fn counting_cacheable_app() -> (Router, Arc<std::sync::atomic::AtomicUsize>) {
		let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
		let counter = hits.clone();
		let app = Router::new().route(
			"/",
			get(move || {
				let counter = counter.clone();
				async move {
					let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
					([(header::CACHE_CONTROL, "max-age=60")], format!("hit {n}"))
				}
			}),
		);
		(app, hits)
	}

	/// A cleared request over a cache-enabled gate, reused across the cache tests.
	fn cleared_get(store: &HmacClearanceStore) -> Request<Body> {
		let token = store.mint(ClearanceLevel::Pow, Duration::from_secs(300));
		Request::builder().uri("/").header(header::COOKIE, format!("{DEFAULT_COOKIE}={token}")).body(Body::empty()).unwrap()
	}

	#[tokio::test]
	async fn cache_serves_repeat_get_without_re_running_the_app() {
		use std::sync::atomic::Ordering;
		let store = Arc::new(HmacClearanceStore::new(b"cache-secret".to_vec()));
		let skin = Skin::builder().store(store.clone()).challenge(Box::new(PowChallenge::new(Hashcash, b"p".to_vec(), TEST_DIFFICULTY))).response_cache(ResponseCache::new(8)).build();
		let (app, hits) = counting_cacheable_app();
		let mut svc = skin.into_layer().layer(app);

		// First cleared GET runs the app and populates the cache.
		let first = svc.call(cleared_get(&store)).await.unwrap();
		assert_eq!(first.status(), StatusCode::OK);
		let first_body = first.into_body().collect().await.unwrap().to_bytes();
		assert_eq!(&first_body[..], b"hit 0");
		assert_eq!(hits.load(Ordering::SeqCst), 1);

		// Second identical GET is served from the cache — same body, app not re-run.
		let second = svc.call(cleared_get(&store)).await.unwrap();
		let second_body = second.into_body().collect().await.unwrap().to_bytes();
		assert_eq!(&second_body[..], b"hit 0", "the cached body is served verbatim");
		assert_eq!(hits.load(Ordering::SeqCst), 1, "a cache hit must not re-run the inner app");
	}

	#[tokio::test]
	async fn cache_does_not_store_without_cache_control() {
		use std::sync::atomic::Ordering;
		// An app that never sets Cache-Control is never cached: every request re-runs it.
		let store = Arc::new(HmacClearanceStore::new(b"cache-nocc-secret".to_vec()));
		let skin = Skin::builder().store(store.clone()).challenge(Box::new(PowChallenge::new(Hashcash, b"p".to_vec(), TEST_DIFFICULTY))).response_cache(ResponseCache::new(8)).build();
		let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
		let counter = hits.clone();
		let app = Router::new().route(
			"/",
			get(move || {
				let counter = counter.clone();
				async move {
					counter.fetch_add(1, Ordering::SeqCst);
					"uncacheable"
				}
			}),
		);
		let mut svc = skin.into_layer().layer(app);

		let _ = svc.call(cleared_get(&store)).await.unwrap();
		let _ = svc.call(cleared_get(&store)).await.unwrap();
		assert_eq!(hits.load(Ordering::SeqCst), 2, "a response with no Cache-Control is never cached");
	}

	#[tokio::test]
	async fn cache_never_serves_an_uncleared_client() {
		use std::sync::atomic::Ordering;
		// Populate the cache via a cleared request, then prove an uncleared client is still
		// challenged (gets the interstitial, not the cached body).
		let store = Arc::new(HmacClearanceStore::new(b"cache-gate-secret".to_vec()));
		let skin = Skin::builder().store(store.clone()).challenge(Box::new(PowChallenge::new(Hashcash, b"p".to_vec(), TEST_DIFFICULTY))).response_cache(ResponseCache::new(8)).build();
		let (app, hits) = counting_cacheable_app();
		let mut svc = skin.into_layer().layer(app);

		let _ = svc.call(cleared_get(&store)).await.unwrap();
		assert_eq!(hits.load(Ordering::SeqCst), 1);

		// No clearance cookie → the gate challenges before the cache is ever consulted.
		let uncleared = Request::builder().uri("/").body(Body::empty()).unwrap();
		let resp = svc.call(uncleared).await.unwrap();
		let body = resp.into_body().collect().await.unwrap().to_bytes();
		assert!(!body.windows(5).any(|w| w == b"hit 0"), "the cached body must never leak to an uncleared client");
	}

	#[tokio::test]
	async fn cache_hit_still_gets_edge_header_transforms() {
		use axum::http::{HeaderName, HeaderValue};

		use crate::edge::{EdgeAction, EdgeMatch, EdgeRules};
		// A cached hit is served with the request's edge transforms freshly applied (they are
		// not part of the stored entry).
		let store = Arc::new(HmacClearanceStore::new(b"cache-edge-secret".to_vec()));
		let rules = EdgeRules::new().push(EdgeMatch::Any, EdgeAction::SetHeader(HeaderName::from_static("x-frame-options"), HeaderValue::from_static("DENY")));
		let skin = Skin::builder().store(store.clone()).challenge(Box::new(PowChallenge::new(Hashcash, b"p".to_vec(), TEST_DIFFICULTY))).edge_rules(rules).response_cache(ResponseCache::new(8)).build();
		let (app, _hits) = counting_cacheable_app();
		let mut svc = skin.into_layer().layer(app);

		let _ = svc.call(cleared_get(&store)).await.unwrap(); // populate
		let hit = svc.call(cleared_get(&store)).await.unwrap(); // served from cache
		assert_eq!(hit.headers().get("x-frame-options").unwrap(), "DENY", "edge transforms apply to a cache hit too");
	}
}

//! Heuristic bot detection on request shape (Phase 5 — frontier defenses).
//!
//! Cloudflare's bot management is largely ML over signals an onion service never sees — IP
//! reputation, ASN, JA3/JA4 TLS fingerprints, behavioural history. The *one* family of bot
//! signals that survives Tor is **identity-free request-shape pattern matching**: a real
//! browser (including Tor Browser at "Safer"/"Safest") emits a full, conventional set of
//! request headers — a `User-Agent`, `Accept`, `Accept-Language`, `Accept-Encoding` — while a
//! scripted client (`curl`, `python-requests`, `wget`, a bespoke flood) emits a sparse,
//! tell-tale set or an explicit tool `User-Agent`. [`BotHeuristics`] scores that gap.
//!
//! **No-JS users are not bots.** Disabling JavaScript/WASM (Tor "Safest") does **not** strip
//! request headers — a no-JS browser still sends the full conventional header set — so these
//! heuristics never punish the no-JS client the rest of the crate is built to serve. They key
//! purely on request *structure*, the no-IP analog of Cloudflare's surviving bot signal.
//!
//! **Conservative by design, an input not a verdict.** Every weight is deliberately low and
//! the assessment is *explainable* — it reports exactly which [`BotSignal`]s fired — because a
//! false positive over Tor is costly. Like [`ShapeBaseline`](crate::shape::ShapeBaseline)'s
//! deviation, a bot score is one input to difficulty tuning, **never a hard block on its own**.

use std::fmt;

use axum::http::{header, request::Parts};

/// Substrings (matched case-insensitively against the `User-Agent`) that name a non-browser
/// HTTP client. Conservative and high-signal: each is a tool that self-identifies, never a
/// token a real Tor Browser UA contains.
const NON_BROWSER_UA_TOKENS: &[&str] = &["curl/", "wget/", "python-requests", "python-urllib", "go-http-client", "java/", "libwww", "scrapy", "httpclient", "okhttp", "axios", "node-fetch", "got (", "aiohttp", "httpx", "powershell", "winhttp", "lwp::"];

/// Substrings (matched case-insensitively against the `User-Agent`) that name a browser
/// **automation / headless** framework. Distinct from [`NON_BROWSER_UA_TOKENS`]: these often
/// ride a browser-shaped UA (a full Mozilla string) yet still self-identify, so they earn
/// their own signal even when the request otherwise looks like a browser.
const AUTOMATION_UA_TOKENS: &[&str] = &["headlesschrome", "phantomjs", "slimerjs", "selenium", "webdriver", "playwright", "puppeteer", "electron/", "cypress", "splash"];

/// Default header count at or below which the request is flagged [`BotSignal::SparseHeaders`].
/// A real browser sends well above this; a bare scripted request often sends only a handful.
const DEFAULT_SPARSE_HEADER_THRESHOLD: usize = 4;

/// One identity-free request-shape signal that a request may be from a scripted client. Each
/// carries a [`weight`](Self::weight) and a human-readable [`description`](Self::description)
/// so an assessment can explain *why* a request looked automated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BotSignal {
	/// No `User-Agent` header at all — every real browser sends one.
	NoUserAgent,
	/// The `User-Agent` names a known non-browser HTTP client (see [`NON_BROWSER_UA_TOKENS`]).
	NonBrowserUserAgent,
	/// The `User-Agent` names a browser automation / headless framework (see
	/// [`AUTOMATION_UA_TOKENS`]) — a strong bot signal even behind a browser-shaped UA.
	AutomationUserAgent,
	/// No `Accept` header — browsers always send one; many scripts omit it.
	NoAccept,
	/// No `Accept-Language` header — Tor Browser pins one; many scripts omit it.
	NoAcceptLanguage,
	/// No `Accept-Encoding` header — browsers always advertise compression; scripts often don't.
	NoAcceptEncoding,
	/// The request carries an unusually small header set (see the sparse-header threshold).
	SparseHeaders,
}

impl BotSignal {
	/// All signal variants, for iteration and table-sizing.
	pub const ALL: [Self; 7] = [Self::NoUserAgent, Self::NonBrowserUserAgent, Self::AutomationUserAgent, Self::NoAccept, Self::NoAcceptLanguage, Self::NoAcceptEncoding, Self::SparseHeaders];

	/// The suspicion weight this signal contributes to a [`BotAssessment::score`]. The
	/// `User-Agent` signals are the strongest; the missing-`Accept-*` signals are weaker
	/// because a few legitimate clients omit them. Weights are intentionally conservative.
	#[must_use]
	pub const fn weight(self) -> f64 {
		match self {
			Self::NonBrowserUserAgent | Self::AutomationUserAgent => 0.6,
			Self::NoUserAgent => 0.5,
			Self::NoAccept => 0.25,
			Self::SparseHeaders => 0.2,
			Self::NoAcceptLanguage | Self::NoAcceptEncoding => 0.15,
		}
	}

	/// A short, operator-facing explanation of the signal.
	#[must_use]
	pub const fn description(self) -> &'static str {
		match self {
			Self::NoUserAgent => "no User-Agent header",
			Self::NonBrowserUserAgent => "User-Agent names a non-browser HTTP client",
			Self::AutomationUserAgent => "User-Agent names a browser automation/headless framework",
			Self::NoAccept => "no Accept header",
			Self::NoAcceptLanguage => "no Accept-Language header",
			Self::NoAcceptEncoding => "no Accept-Encoding header",
			Self::SparseHeaders => "unusually small header set",
		}
	}
}

impl fmt::Display for BotSignal {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.description())
	}
}

/// The result of assessing one request: a clamped suspicion [`score`](Self::score) in
/// `[0.0, 1.0]` and the list of [`signals`](Self::signals) that drove it. An empty signal
/// list means a conventional, browser-shaped request (score `0.0`).
#[derive(Clone, Debug, PartialEq)]
pub struct BotAssessment {
	/// Suspicion in `[0.0, 1.0]` — the clamped sum of fired signal weights. `0.0` for a
	/// browser-shaped request, approaching `1.0` for an obviously scripted one.
	pub score: f64,
	/// The signals that fired, in [`BotSignal::ALL`] order. Drives explainability.
	pub signals: Vec<BotSignal>,
}

impl BotAssessment {
	/// Whether the score meets or exceeds `threshold`. A convenience for difficulty tuning;
	/// the crate never turns this into a hard block on its own.
	#[must_use]
	pub fn is_suspicious(&self, threshold: f64) -> bool {
		self.score >= threshold
	}
}

/// A conservative, explainable request-shape bot scorer. Stateless and identity-free; share
/// one instance across the request path. Tune the sparse-header threshold with
/// [`sparse_header_threshold`](Self::sparse_header_threshold).
#[derive(Clone, Debug)]
pub struct BotHeuristics {
	sparse_header_threshold: usize,
}

impl BotHeuristics {
	/// A scorer with the default sparse-header threshold.
	#[must_use]
	pub const fn new() -> Self {
		Self { sparse_header_threshold: DEFAULT_SPARSE_HEADER_THRESHOLD }
	}

	/// Set the header count at or below which [`BotSignal::SparseHeaders`] fires. Lower is
	/// more permissive (fewer requests flagged sparse).
	#[must_use]
	pub const fn sparse_header_threshold(mut self, threshold: usize) -> Self {
		self.sparse_header_threshold = threshold;
		self
	}

	/// Assess a parsed request's [`Parts`], returning the fired signals and a clamped score.
	#[must_use]
	pub fn assess(&self, parts: &Parts) -> BotAssessment {
		let mut signals = Vec::new();

		match parts.headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()) {
			None => signals.push(BotSignal::NoUserAgent),
			Some(ua) => {
				let lowered = ua.to_ascii_lowercase();
				// A CLI/library UA and an automation-framework UA are distinct signals; a UA can
				// in principle trip both (e.g. a custom tool that also embeds "webdriver").
				if NON_BROWSER_UA_TOKENS.iter().any(|token| lowered.contains(token)) {
					signals.push(BotSignal::NonBrowserUserAgent);
				}
				if AUTOMATION_UA_TOKENS.iter().any(|token| lowered.contains(token)) {
					signals.push(BotSignal::AutomationUserAgent);
				}
			}
		}
		if !parts.headers.contains_key(header::ACCEPT) {
			signals.push(BotSignal::NoAccept);
		}
		if !parts.headers.contains_key(header::ACCEPT_LANGUAGE) {
			signals.push(BotSignal::NoAcceptLanguage);
		}
		if !parts.headers.contains_key(header::ACCEPT_ENCODING) {
			signals.push(BotSignal::NoAcceptEncoding);
		}
		// Count distinct header names (keys() yields each name once).
		if parts.headers.keys().count() <= self.sparse_header_threshold {
			signals.push(BotSignal::SparseHeaders);
		}

		// Keep the reported order canonical (BotSignal::ALL order) regardless of check order.
		signals.sort_by_key(|s| BotSignal::ALL.iter().position(|x| x == s).unwrap_or(usize::MAX));

		let score = signals.iter().map(|s| s.weight()).sum::<f64>().clamp(0.0, 1.0);
		BotAssessment { score, signals }
	}
}

impl Default for BotHeuristics {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use axum::http::Request;

	use super::*;

	fn parts(builder: axum::http::request::Builder) -> Parts {
		builder.body(()).unwrap().into_parts().0
	}

	/// A conventional browser-shaped request (the kind Tor Browser sends, JS on or off).
	fn browser() -> axum::http::request::Builder {
		Request::builder().method("GET").uri("/").header("host", "x.onion").header("user-agent", "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0").header("accept", "text/html,application/xhtml+xml").header("accept-language", "en-US,en;q=0.5").header("accept-encoding", "gzip, deflate, br").header("connection", "keep-alive")
	}

	#[test]
	fn conventional_browser_request_scores_zero() {
		let a = BotHeuristics::new().assess(&parts(browser()));
		assert!(a.signals.is_empty(), "browser fired {:?}", a.signals);
		assert_eq!(a.score, 0.0);
		assert!(!a.is_suspicious(0.5));
	}

	#[test]
	fn no_js_browser_is_not_flagged() {
		// Disabling JS does not strip request headers — a "Safest" browser still sends the
		// full conventional set, so it must not look like a bot.
		let safest = browser(); // identical header shape; JS state is invisible server-side
		let a = BotHeuristics::new().assess(&parts(safest));
		assert_eq!(a.score, 0.0);
	}

	#[test]
	fn curl_request_is_highly_suspicious() {
		// curl: tool UA, only host+user-agent+accept(*/*) → non-browser UA, no lang, no
		// encoding, sparse headers.
		let a = BotHeuristics::new().assess(&parts(Request::builder().uri("/").header("host", "x.onion").header("user-agent", "curl/8.0.1").header("accept", "*/*")));
		assert!(a.signals.contains(&BotSignal::NonBrowserUserAgent));
		assert!(a.signals.contains(&BotSignal::NoAcceptLanguage));
		assert!(a.signals.contains(&BotSignal::NoAcceptEncoding));
		assert!(a.signals.contains(&BotSignal::SparseHeaders));
		assert!(a.is_suspicious(0.8), "score was {}", a.score);
	}

	#[test]
	fn missing_user_agent_fires_no_user_agent_not_non_browser() {
		let a = BotHeuristics::new().assess(&parts(Request::builder().uri("/").header("host", "x").header("accept", "*/*")));
		assert!(a.signals.contains(&BotSignal::NoUserAgent));
		assert!(!a.signals.contains(&BotSignal::NonBrowserUserAgent));
	}

	#[test]
	fn score_is_clamped_to_one() {
		// No UA + no Accept + no lang + no encoding + sparse = 0.5+0.25+0.15+0.15+0.2 = 1.25 → 1.0.
		let a = BotHeuristics::new().assess(&parts(Request::builder().uri("/")));
		assert_eq!(a.score, 1.0);
	}

	#[test]
	fn signals_are_reported_in_canonical_order() {
		let a = BotHeuristics::new().assess(&parts(Request::builder().uri("/")));
		let positions: Vec<usize> = a.signals.iter().map(|s| BotSignal::ALL.iter().position(|x| x == s).unwrap()).collect();
		let mut sorted = positions.clone();
		sorted.sort_unstable();
		assert_eq!(positions, sorted, "signals must be in BotSignal::ALL order");
	}

	#[test]
	fn sparse_threshold_is_tunable() {
		// browser() sends 7 headers. A threshold of 7 flags it sparse; the default (4) does not.
		let req = parts(browser());
		assert!(!BotHeuristics::new().assess(&req).signals.contains(&BotSignal::SparseHeaders));
		let strict = BotHeuristics::new().sparse_header_threshold(7);
		assert!(strict.assess(&parts(browser())).signals.contains(&BotSignal::SparseHeaders));
	}

	#[test]
	fn each_signal_has_a_nonzero_weight_and_description() {
		for s in BotSignal::ALL {
			assert!(s.weight() > 0.0, "{s:?} weight");
			assert!(!s.description().is_empty(), "{s:?} description");
			assert_eq!(s.to_string(), s.description());
		}
	}

	#[test]
	fn headless_browser_is_flagged_as_automation_not_cli_tool() {
		// HeadlessChrome rides a full browser-shaped UA + header set, so the only thing that
		// gives it away is the automation token — and it must be AutomationUserAgent, not the
		// CLI-tool NonBrowserUserAgent.
		let a = BotHeuristics::new().assess(&parts(browser().header("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36")));
		// browser() already set a UA; appending leaves the original first — assess a fresh request.
		let fresh = BotHeuristics::new().assess(&parts(Request::builder().uri("/").header("host", "x.onion").header("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/120.0 Safari/537.36").header("accept", "text/html").header("accept-language", "en-US").header("accept-encoding", "gzip").header("connection", "keep-alive")));
		assert!(fresh.signals.contains(&BotSignal::AutomationUserAgent));
		assert!(!fresh.signals.contains(&BotSignal::NonBrowserUserAgent));
		// Otherwise browser-shaped, so automation is essentially the sole driver.
		assert!((fresh.score - BotSignal::AutomationUserAgent.weight()).abs() < f64::EPSILON);
		// (the first `a` request just confirms a no-panic path with the appended UA)
		let _ = a;
	}

	#[test]
	fn automation_frameworks_are_detected() {
		for ua in ["PhantomJS/2.1", "selenium webdriver", "Playwright/1.40", "Mozilla/5.0 Cypress", "Splash/3.5"] {
			let assessed = BotHeuristics::new().assess(&parts(Request::builder().uri("/").header("host", "x.onion").header("user-agent", ua).header("accept", "*/*").header("accept-language", "en").header("accept-encoding", "gzip").header("connection", "keep-alive")));
			assert!(assessed.signals.contains(&BotSignal::AutomationUserAgent), "{ua} not detected");
		}
	}

	#[test]
	fn known_tool_uas_are_detected() {
		// A fresh request per UA (appending to browser() would leave the original UA first).
		for ua in ["python-requests/2.31", "Go-http-client/1.1", "Wget/1.21", "okhttp/4.9", "Scrapy/2.5"] {
			let a = BotHeuristics::new().assess(&parts(Request::builder().uri("/").header("host", "x.onion").header("user-agent", ua).header("accept", "*/*").header("accept-language", "en").header("accept-encoding", "gzip").header("connection", "keep-alive")));
			assert!(a.signals.contains(&BotSignal::NonBrowserUserAgent), "{ua} not detected");
		}
	}
}

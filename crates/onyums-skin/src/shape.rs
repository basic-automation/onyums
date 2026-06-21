//! Request-shape feature extraction (Phase 4 — request-shape baselining).
//!
//! Cloudflare's adaptive DDoS defense baselines the *normal* distribution of request
//! features and flags deviation; its `dosd` logic self-selects the most discriminating
//! field. Over Tor almost every field that drives that — client IP, ASN, geo, the TLS
//! fingerprint — is gone (see `ROADMAP.md`). What survives is the **HTTP request shape**:
//! the method, the path's structure, the *set* of headers the client sends, the presence
//! of a cookie, and the user-agent. A pinned-fingerprint client like Tor Browser sends a
//! small, canonical shape; a scripted flood (curl, a bespoke bot) sends a distinctly
//! different one. [`RequestShape`] extracts those Tor-surviving dimensions into a stable
//! [`fingerprint`](RequestShape::fingerprint) that [`ShapeBaseline`](crate::shape) can
//! tally to learn "normal" and score deviation — the no-IP analog of Cloudflare's
//! request-shape baselining.
//!
//! **Why the header *set*, not the wire order.** JA4H keys on the raw on-the-wire header
//! order, but axum/hyper parse headers into an [`http::HeaderMap`] whose iteration order is
//! not the wire order, so that signal is unavailable post-parse. We key on the sorted,
//! de-duplicated *set* of header names instead — still a real fingerprint (Tor Browser
//! emits a fixed canonical set; a bot's set differs) and stable across requests.

use std::{
	collections::HashMap,
	sync::Mutex,
	time::{Duration, Instant},
};

use axum::http::request::Parts;

use crate::circuit::{Clock, SystemClock};

/// The largest user-agent prefix retained in a [`RequestShape`]. Legitimate Tor clients
/// pin a short UA; capping bounds the memory a pathological UA can cost the baseline's
/// frequency table without losing discriminating power.
const MAX_UA_LEN: usize = 160;

/// The Tor-surviving HTTP dimensions of one request, extracted from its [`Parts`].
///
/// Every field is identity-free network-wise — there is no IP, ASN, geo, or TLS data here,
/// only the shape of the HTTP request itself, which is all an onion service can observe.
/// Construct with [`from_parts`](Self::from_parts); fold many requests' [`fingerprint`](Self::fingerprint)s
/// into a [`ShapeBaseline`] to learn the normal distribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestShape {
	/// The request method, uppercased (`GET`, `POST`, …).
	pub method: String,
	/// Number of non-empty path segments (`/a/b/c` → 3, `/` → 0).
	pub path_depth: usize,
	/// Whether the final path segment carries a file extension (a `.` after its start).
	pub path_has_extension: bool,
	/// The header names present, lowercased, de-duplicated, and **sorted** for stability
	/// (the wire order is lost after parsing — see the module docs).
	pub header_names: Vec<String>,
	/// Whether the request carries a `Cookie` header (a returning/cleared client usually
	/// does; a fresh flood usually does not).
	pub has_cookie: bool,
	/// The user-agent, lowercased and capped at [`MAX_UA_LEN`]; `None` if absent. Over Tor
	/// the legitimate UA set is tiny (Tor Browser pins it), so an odd or missing UA stands
	/// out sharply.
	pub ua: Option<String>,
}

impl RequestShape {
	/// Extract the request shape from a parsed request's [`Parts`].
	#[must_use]
	pub fn from_parts(parts: &Parts) -> Self {
		let path = parts.uri.path();
		let mut segments = path.split('/').filter(|s| !s.is_empty());
		let path_depth = path.split('/').filter(|s| !s.is_empty()).count();
		let path_has_extension = segments.next_back().is_some_and(|last| {
			// A leading dot (a dotfile) is not an extension; require a dot after the start.
			last.rfind('.').is_some_and(|i| i > 0)
		});

		let mut header_names: Vec<String> = parts.headers.keys().map(|name| name.as_str().to_ascii_lowercase()).collect();
		header_names.sort_unstable();
		header_names.dedup();

		let has_cookie = parts.headers.contains_key(axum::http::header::COOKIE);
		let ua = parts.headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok()).map(|s| {
			let mut ua = s.to_ascii_lowercase();
			ua.truncate(MAX_UA_LEN);
			ua
		});

		Self {
			method: parts.method.as_str().to_ascii_uppercase(),
			path_depth,
			path_has_extension,
			header_names,
			has_cookie,
			ua,
		}
	}

	/// A stable, canonical string key over the shape's dimensions — the fingerprint a
	/// [`ShapeBaseline`] tallies. Two requests with the same method, path structure, header
	/// set, cookie presence, and UA share a fingerprint; any difference splits them.
	///
	/// The format is internal and not a stability guarantee across crate versions; it is a
	/// key for in-process frequency counting, not a wire format.
	#[must_use]
	pub fn fingerprint(&self) -> String {
		format!(
			"m={}|d={}|x={}|c={}|h={}|u={}",
			self.method,
			self.path_depth,
			u8::from(self.path_has_extension),
			u8::from(self.has_cookie),
			self.header_names.join(","),
			self.ua.as_deref().unwrap_or("-"),
		)
	}
}

/// Default decay window: every `window` of elapsed time, the baseline's learned weights
/// are multiplied by [`DEFAULT_DECAY`], so recent traffic dominates without wiping history.
const DEFAULT_WINDOW: Duration = Duration::from_secs(10);
/// Default per-window decay factor (exponential aging).
const DEFAULT_DECAY: f64 = 0.5;
/// Default minimum total weight before the baseline scores deviation. Below it the model is
/// "still learning" and returns `0.0`, so a cold start does not flag every fresh shape.
const DEFAULT_MIN_OBSERVATIONS: f64 = 20.0;
/// Cap on decay iterations after a long idle gap — beyond this the old weights are
/// effectively zero (`DEFAULT_DECAY`^64 ≈ 0), so we clear instead of looping.
const MAX_DECAY_STEPS: u32 = 64;

/// A rolling, exponentially-aged frequency model of [`RequestShape`] fingerprints that
/// scores how far an incoming request deviates from recently-observed "normal" traffic.
///
/// This is the no-IP analog of Cloudflare's request-shape baselining (see the module docs):
/// it learns the distribution of [`fingerprint`](RequestShape::fingerprint)s and reports a
/// deviation in `[0.0, 1.0]` for each request — `0.0` for a shape that matches the bulk of
/// recent traffic, approaching `1.0` for a never-before-seen shape. An onion service's
/// legitimate traffic clusters tightly on a handful of pinned Tor Browser shapes, so the
/// **share-complement** used here (the fraction of recent traffic that did *not* share this
/// request's shape) is a sound deviation proxy in this setting.
///
/// **Honest limits.** A genuinely multi-modal normal (many distinct legitimate shapes, none
/// dominant) dilutes the signal — every shape then has a small share and scores high. That
/// is why the score is *one input to difficulty tuning, never a hard block*: it nudges PoW
/// effort, it does not gate a request on its own.
///
/// Aging is driven by an injectable [`Clock`], so the model is deterministically testable
/// with [`ManualClock`](crate::circuit::ManualClock) and never needs to sleep. `Send + Sync`;
/// the host shares one instance across the request path.
pub struct ShapeBaseline {
	window: Duration,
	decay: f64,
	min_observations: f64,
	clock: Box<dyn Clock>,
	state: Mutex<BaselineState>,
}

#[derive(Default)]
struct BaselineState {
	/// Decayed weight per fingerprint.
	counts: HashMap<String, f64>,
	/// Sum of all decayed weights (kept incrementally to avoid re-summing the map).
	total: f64,
	/// When the weights were last decayed; `None` until the first observation.
	last_decay: Option<Instant>,
}

impl ShapeBaseline {
	/// A baseline with the default 10-second decay window, `0.5` per-window decay, and a
	/// 20-observation learning floor.
	#[must_use]
	pub fn new() -> Self {
		Self {
			window: DEFAULT_WINDOW,
			decay: DEFAULT_DECAY,
			min_observations: DEFAULT_MIN_OBSERVATIONS,
			clock: Box::new(SystemClock),
			state: Mutex::new(BaselineState::default()),
		}
	}

	/// Set the decay window — the period over which learned weights are multiplied by the
	/// [`decay`](Self::decay) factor. Shorter forgets faster.
	#[must_use]
	pub const fn window(mut self, window: Duration) -> Self {
		self.window = window;
		self
	}

	/// Set the per-window decay factor, clamped to `(0.0, 1.0]`. `1.0` never forgets;
	/// smaller forgets faster.
	#[must_use]
	pub fn decay(mut self, decay: f64) -> Self {
		self.decay = decay.clamp(f64::MIN_POSITIVE, 1.0);
		self
	}

	/// Set the minimum total weight before deviation is scored. Below it the model returns
	/// `0.0` (still learning), so a cold start does not flag every fresh shape.
	#[must_use]
	pub fn min_observations(mut self, min: f64) -> Self {
		self.min_observations = min.max(0.0);
		self
	}

	/// Replace the time source (default [`SystemClock`]). Use
	/// [`ManualClock`](crate::circuit::ManualClock) in tests.
	#[must_use]
	pub fn with_clock(mut self, clock: Box<dyn Clock>) -> Self {
		self.clock = clock;
		self
	}

	/// The deviation score for `shape` against the current baseline, without recording it.
	/// `0.0` while still learning ([`min_observations`](Self::min_observations) not yet met)
	/// or for a shape that matches all recent traffic; approaches `1.0` for a novel shape.
	#[must_use]
	pub fn score(&self, shape: &RequestShape) -> f64 {
		let now = self.clock.now();
		let mut state = self.lock();
		self.age(&mut state, now);
		Self::deviation(&state, &shape.fingerprint(), self.min_observations)
	}

	/// Record `shape` into the baseline and return its deviation **measured against prior
	/// traffic** (before this request is folded in). This is the method the gate calls per
	/// request: it both learns and scores in one locked pass.
	pub fn observe(&self, shape: &RequestShape) -> f64 {
		let now = self.clock.now();
		let fp = shape.fingerprint();
		let mut state = self.lock();
		self.age(&mut state, now);
		let deviation = Self::deviation(&state, &fp, self.min_observations);
		*state.counts.entry(fp).or_insert(0.0) += 1.0;
		state.total += 1.0;
		deviation
	}

	/// Total decayed weight currently held — the effective number of recent observations.
	#[must_use]
	pub fn total_weight(&self) -> f64 {
		let now = self.clock.now();
		let mut state = self.lock();
		self.age(&mut state, now);
		state.total
	}

	/// How many distinct fingerprints the baseline is currently tracking.
	#[must_use]
	pub fn distinct(&self) -> usize {
		let now = self.clock.now();
		let mut state = self.lock();
		self.age(&mut state, now);
		state.counts.len()
	}

	/// Share-complement deviation: `1 - weight(fp)/total`, or `0.0` while still learning.
	fn deviation(state: &BaselineState, fp: &str, min_observations: f64) -> f64 {
		if state.total < min_observations {
			return 0.0;
		}
		let weight = state.counts.get(fp).copied().unwrap_or(0.0);
		(1.0 - weight / state.total).clamp(0.0, 1.0)
	}

	/// Apply exponential decay for every whole `window` elapsed since the last aging, and
	/// drop fingerprints whose weight has decayed to negligible.
	fn age(&self, state: &mut BaselineState, now: Instant) {
		let Some(last) = state.last_decay else {
			state.last_decay = Some(now);
			return;
		};
		let elapsed = now.saturating_duration_since(last);
		let steps = (elapsed.as_secs_f64() / self.window.as_secs_f64()) as u32;
		if steps == 0 {
			return;
		}
		state.last_decay = Some(last + self.window * steps);
		if steps >= MAX_DECAY_STEPS {
			// Effectively zero after this many halvings — start fresh.
			state.counts.clear();
			state.total = 0.0;
			return;
		}
		let factor = self.decay.powi(steps as i32);
		state.total = 0.0;
		state.counts.retain(|_, w| {
			*w *= factor;
			let keep = *w >= 1e-6;
			if keep {
				state.total += *w;
			}
			keep
		});
	}

	fn lock(&self) -> std::sync::MutexGuard<'_, BaselineState> {
		self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
	}
}

impl Default for ShapeBaseline {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use axum::http::Request;

	fn parts(builder: axum::http::request::Builder) -> Parts {
		builder.body(()).unwrap().into_parts().0
	}

	#[test]
	fn extracts_method_and_path_structure() {
		let s = RequestShape::from_parts(&parts(Request::builder().method("post").uri("/api/v1/items")));
		assert_eq!(s.method, "POST");
		assert_eq!(s.path_depth, 3);
		assert!(!s.path_has_extension);

		let root = RequestShape::from_parts(&parts(Request::builder().uri("/")));
		assert_eq!(root.path_depth, 0);
		assert!(!root.path_has_extension);
	}

	#[test]
	fn detects_file_extension_but_not_dotfile() {
		let file = RequestShape::from_parts(&parts(Request::builder().uri("/assets/app.css")));
		assert!(file.path_has_extension);

		// A leading-dot last segment is a dotfile, not an extension.
		let dotfile = RequestShape::from_parts(&parts(Request::builder().uri("/.well-known/x")));
		assert!(!dotfile.path_has_extension);
		let dotfile2 = RequestShape::from_parts(&parts(Request::builder().uri("/dir/.env")));
		assert!(!dotfile2.path_has_extension);
	}

	#[test]
	fn header_names_are_sorted_lowercased_and_unique() {
		let s = RequestShape::from_parts(&parts(
			Request::builder().uri("/").header("User-Agent", "x").header("Accept", "*/*").header("Cookie", "skin=1"),
		));
		assert_eq!(s.header_names, vec!["accept".to_owned(), "cookie".to_owned(), "user-agent".to_owned()]);
		assert!(s.has_cookie);
		assert_eq!(s.ua.as_deref(), Some("x"));
	}

	#[test]
	fn no_cookie_no_ua_is_represented() {
		let s = RequestShape::from_parts(&parts(Request::builder().uri("/x").header("accept", "*/*")));
		assert!(!s.has_cookie);
		assert_eq!(s.ua, None);
		assert_eq!(s.fingerprint(), "m=GET|d=1|x=0|c=0|h=accept|u=-");
	}

	#[test]
	fn ua_is_capped_in_length() {
		let long = "U".repeat(MAX_UA_LEN + 50);
		let s = RequestShape::from_parts(&parts(Request::builder().uri("/").header("user-agent", long)));
		assert_eq!(s.ua.as_deref().map(str::len), Some(MAX_UA_LEN));
	}

	#[test]
	fn identical_shapes_share_a_fingerprint_differences_split() {
		let a = RequestShape::from_parts(&parts(Request::builder().uri("/a/b").header("user-agent", "bot").header("accept", "*/*")));
		let b = RequestShape::from_parts(&parts(Request::builder().uri("/c/d").header("accept", "*/*").header("user-agent", "bot")));
		// Same method, depth, header set, cookie-ness, UA → same fingerprint (path *values* differ, structure does not).
		assert_eq!(a.fingerprint(), b.fingerprint());

		// A different UA splits them.
		let c = RequestShape::from_parts(&parts(Request::builder().uri("/a/b").header("user-agent", "firefox").header("accept", "*/*")));
		assert_ne!(a.fingerprint(), c.fingerprint());
	}

	// --- ShapeBaseline ---

	use std::sync::Arc;

	use crate::circuit::ManualClock;

	/// Shares one [`ManualClock`] between the test driver and the baseline.
	struct ArcClock(Arc<ManualClock>);
	impl Clock for ArcClock {
		fn now(&self) -> Instant {
			self.0.now()
		}
	}

	fn shape(uri: &str, ua: &str) -> RequestShape {
		RequestShape::from_parts(&parts(Request::builder().uri(uri).header("user-agent", ua)))
	}

	fn baseline_with(min: f64) -> (ShapeBaseline, Arc<ManualClock>) {
		let clock = Arc::new(ManualClock::new());
		let b = ShapeBaseline::new().window(Duration::from_secs(10)).decay(0.5).min_observations(min).with_clock(Box::new(ArcClock(clock.clone())));
		(b, clock)
	}

	#[test]
	fn cold_start_does_not_flag_until_min_observations() {
		let (b, _clock) = baseline_with(5.0);
		// First four observations are below the learning floor → deviation 0.
		for _ in 0..4 {
			assert_eq!(b.observe(&shape("/", "tor")), 0.0);
		}
		// Total weight is now 4 (< 5), still learning.
		assert_eq!(b.total_weight(), 4.0);
		// A fifth identical observation crosses the floor; an identical shape is fully normal.
		assert_eq!(b.observe(&shape("/", "tor")), 0.0);
	}

	#[test]
	fn novel_shape_scores_high_against_established_baseline() {
		let (b, _clock) = baseline_with(10.0);
		// Establish a dominant "normal" shape.
		for _ in 0..20 {
			b.observe(&shape("/", "tor"));
		}
		// The normal shape barely deviates.
		assert!(b.score(&shape("/", "tor")) < 0.05, "normal shape should be ~0");
		// A never-seen shape deviates almost fully (its share of the 20-weight baseline is 0).
		let novel = b.score(&shape("/admin", "curl/8.0"));
		assert!(novel > 0.95, "novel shape should be ~1, got {novel}");
	}

	#[test]
	fn distinct_tracks_fingerprint_count() {
		let (b, _clock) = baseline_with(0.0);
		b.observe(&shape("/", "a"));
		b.observe(&shape("/", "a"));
		b.observe(&shape("/", "b"));
		assert_eq!(b.distinct(), 2);
		assert_eq!(b.total_weight(), 3.0);
	}

	#[test]
	fn decay_ages_out_old_traffic() {
		let (b, clock) = baseline_with(0.0);
		for _ in 0..16 {
			b.observe(&shape("/", "old"));
		}
		assert_eq!(b.total_weight(), 16.0);
		// One window halves the weights; two windows quarter them.
		clock.advance(Duration::from_secs(20));
		assert!((b.total_weight() - 4.0).abs() < 1e-9, "16 * 0.5^2 = 4");
	}

	#[test]
	fn long_idle_gap_clears_to_avoid_stale_baseline() {
		let (b, clock) = baseline_with(0.0);
		for _ in 0..8 {
			b.observe(&shape("/", "old"));
		}
		// A very long idle gap (well past MAX_DECAY_STEPS windows) resets the model.
		clock.advance(Duration::from_secs(10 * (MAX_DECAY_STEPS as u64 + 5)));
		assert_eq!(b.total_weight(), 0.0);
		assert_eq!(b.distinct(), 0);
	}

	#[test]
	fn decay_factor_is_clamped_into_unit_range() {
		// A decay of 0 would erase everything each window; it is clamped to a positive value,
		// and 2.0 is clamped down to 1.0 (never forgets).
		let never = ShapeBaseline::new().decay(2.0);
		assert!((never.decay - 1.0).abs() < f64::EPSILON);
		let tiny = ShapeBaseline::new().decay(0.0);
		assert!(tiny.decay > 0.0);
	}
}

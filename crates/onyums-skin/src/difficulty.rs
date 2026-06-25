//! Adaptive proof-of-work difficulty driven by app-observed request rate.
//!
//! The intro-layer PoW effort Arti negotiates is **not** surfaced to the application
//! (see `ROADMAP.md`), so the only signal Skin has for "are we under attack?" is the
//! request rate it observes itself. [`AdaptiveDifficulty`] turns that signal into a
//! PoW difficulty (leading-zero-bits, the unit [`Pow`](crate::challenge::pow::Pow)
//! puzzles use): dormant (a low `baseline`) under normal load, ramped toward `max`
//! as the observed rate climbs into attack territory. This mirrors Tor's own PoW
//! effort control loop, one layer up.
//!
//! The rate is measured over a fixed window read from an injectable
//! [`Clock`](crate::circuit::Clock), so the controller is deterministically testable
//! with [`ManualClock`](crate::circuit::ManualClock) and never needs to sleep.

use std::{
	sync::{Arc, Mutex},
	time::{Duration, Instant},
};

use axum::http::request::Parts;

use crate::{
	bot::BotHeuristics,
	circuit::{Clock, SystemClock},
	observe::{SecurityEvent, SecurityEventSink},
	shape::{RequestShape, ShapeBaseline},
};

/// Default rate window.
const DEFAULT_WINDOW: Duration = Duration::from_secs(1);

/// A request-rate → PoW-difficulty controller.
///
/// Difficulty is a function of the number of requests observed in the current fixed
/// window:
/// - at or below `low_rate` requests/window → `baseline` (often `0`, i.e. dormant),
/// - at or above `high_rate` requests/window → `max`,
/// - in between → linearly interpolated.
///
/// The controller is `Send + Sync`; the host calls [`record_request`](Self::record_request)
/// on every observed request and reads [`current_difficulty`](Self::current_difficulty)
/// when minting a puzzle. The window is fixed: the running count resets when `window`
/// elapses, so the difficulty tracks the *current* window's request count (a one-window
/// memory, the standard fixed-window behaviour).
pub struct AdaptiveDifficulty {
	baseline: u32,
	max: u32,
	low_rate: u64,
	high_rate: u64,
	window: Duration,
	clock: Box<dyn Clock>,
	state: Mutex<RateWindow>,
}

#[derive(Default)]
struct RateWindow {
	/// Start of the current window; `None` until the first observation.
	start: Option<Instant>,
	/// Requests counted in the current window.
	count: u64,
}

impl AdaptiveDifficulty {
	/// A controller that ramps from `baseline` difficulty to `max` as the observed
	/// rate climbs, over a default 1-second window with `low_rate = 0` and
	/// `high_rate = max(1, max as u64 * 8)` so a sane curve exists without tuning.
	///
	/// `max` is clamped to be at least `baseline`.
	#[must_use]
	pub fn new(baseline: u32, max: u32) -> Self {
		let max = max.max(baseline);
		Self {
			baseline,
			max,
			low_rate: 0,
			high_rate: (u64::from(max) * 8).max(1),
			window: DEFAULT_WINDOW,
			clock: Box::new(SystemClock),
			state: Mutex::new(RateWindow::default()),
		}
	}

	/// Set the request-rate band: at or below `low` requests/window difficulty is
	/// `baseline`, at or above `high` it is `max`. `high` is clamped above `low`.
	#[must_use]
	pub fn rate_band(mut self, low: u64, high: u64) -> Self {
		self.low_rate = low;
		self.high_rate = high.max(low + 1);
		self
	}

	/// Set the measurement window (default one second).
	#[must_use]
	pub const fn window(mut self, window: Duration) -> Self {
		self.window = window;
		self
	}

	/// Replace the time source (default [`SystemClock`]). Use
	/// [`ManualClock`](crate::circuit::ManualClock) in tests.
	#[must_use]
	pub fn with_clock(mut self, clock: Box<dyn Clock>) -> Self {
		self.clock = clock;
		self
	}

	/// Record one observed request, rolling the window if it has elapsed.
	pub fn record_request(&self) {
		let now = self.clock.now();
		let mut state = self.lock();
		self.roll(&mut state, now);
		state.count += 1;
	}

	/// Requests counted in the current window (rolling it first if elapsed). The raw
	/// signal behind [`current_difficulty`](Self::current_difficulty), exposed for
	/// observability.
	#[must_use]
	pub fn observed_rate(&self) -> u64 {
		let now = self.clock.now();
		let mut state = self.lock();
		self.roll(&mut state, now);
		state.count
	}

	/// The PoW difficulty for the current observed rate.
	#[must_use]
	pub fn current_difficulty(&self) -> u32 {
		self.difficulty_for(self.observed_rate())
	}

	/// Map a request rate to a difficulty along the configured band.
	fn difficulty_for(&self, rate: u64) -> u32 {
		if rate <= self.low_rate {
			return self.baseline;
		}
		if rate >= self.high_rate {
			return self.max;
		}
		// Linear interpolation in u128 to avoid overflow, then back to u32.
		let span_rate = u128::from(self.high_rate - self.low_rate);
		let span_diff = u128::from(self.max - self.baseline);
		let over = u128::from(rate - self.low_rate);
		let added = over * span_diff / span_rate;
		self.baseline + u32::try_from(added).unwrap_or(self.max - self.baseline)
	}

	/// Reset the window if `window` has elapsed since it started.
	fn roll(&self, state: &mut RateWindow, now: Instant) {
		let elapsed = state.start.is_some_and(|start| now.saturating_duration_since(start) >= self.window);
		if state.start.is_none() || elapsed {
			state.start = Some(now);
			state.count = 0;
		}
	}

	fn lock(&self) -> std::sync::MutexGuard<'_, RateWindow> {
		self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
	}
}

/// Default deviation band: below `0.3` deviation difficulty stays at baseline, at/above
/// `0.9` it is maxed.
const DEFAULT_LOW_DEV: f64 = 0.3;
const DEFAULT_HIGH_DEV: f64 = 0.9;
/// Default deviation at/above which a [`SecurityEvent::ShapeAnomaly`] is emitted.
const DEFAULT_EMIT_THRESHOLD: f64 = 0.5;

/// A PoW-difficulty controller driven by **deviation from the learned request-shape
/// baseline**, the complement to [`AdaptiveDifficulty`]'s raw-rate signal and the second
/// half of the Phase-4 "Done when" (difficulty driven by deviation-from-baseline, not just
/// request rate — see `ROADMAP.md`).
///
/// It owns a [`ShapeBaseline`]: each [`observe`](Self::observe) folds a request's shape into
/// the baseline, reads the resulting deviation in `[0.0, 1.0]`, and maps it to a difficulty:
/// - at or below `low_dev` deviation → `baseline` (a shape matching normal traffic costs
///   nothing extra),
/// - at or above `high_dev` deviation → `max` (a maximally novel shape pays full effort),
/// - in between → linearly interpolated.
///
/// When deviation reaches `emit_threshold`, a [`SecurityEvent::ShapeAnomaly`] is recorded to
/// the configured sink (if any). Because the baseline returns `0.0` while still learning,
/// difficulty stays at `baseline` during cold start — no false flagging of early traffic.
///
/// `Send + Sync`; the host shares one instance and calls `observe` per request when minting
/// a puzzle. Use [`ShapeDifficulty::with_baseline`] to inject a clock-controlled baseline in
/// tests.
pub struct ShapeDifficulty {
	baseline: u32,
	max: u32,
	low_dev: f64,
	high_dev: f64,
	emit_threshold: f64,
	shapes: ShapeBaseline,
	sink: Option<Arc<dyn SecurityEventSink>>,
}

impl ShapeDifficulty {
	/// A controller ramping from `baseline` to `max` difficulty as request-shape deviation
	/// climbs across the default `0.3..0.9` band, emitting a [`SecurityEvent::ShapeAnomaly`]
	/// at deviation `>= 0.5`. `max` is clamped to at least `baseline`. Starts with a fresh
	/// default [`ShapeBaseline`].
	#[must_use]
	pub fn new(baseline: u32, max: u32) -> Self {
		Self {
			baseline,
			max: max.max(baseline),
			low_dev: DEFAULT_LOW_DEV,
			high_dev: DEFAULT_HIGH_DEV,
			emit_threshold: DEFAULT_EMIT_THRESHOLD,
			shapes: ShapeBaseline::new(),
			sink: None,
		}
	}

	/// Set the deviation band: at or below `low` deviation difficulty is `baseline`, at or
	/// above `high` it is `max`. Both are clamped to `[0.0, 1.0]` and `high` is kept strictly
	/// above `low`.
	#[must_use]
	pub fn dev_band(mut self, low: f64, high: f64) -> Self {
		self.low_dev = low.clamp(0.0, 1.0);
		self.high_dev = high.clamp(0.0, 1.0).max(self.low_dev + f64::EPSILON);
		self
	}

	/// Set the deviation at/above which a [`SecurityEvent::ShapeAnomaly`] is emitted
	/// (clamped to `[0.0, 1.0]`).
	#[must_use]
	pub fn emit_threshold(mut self, threshold: f64) -> Self {
		self.emit_threshold = threshold.clamp(0.0, 1.0);
		self
	}

	/// Replace the internal [`ShapeBaseline`] (e.g. one with a [`ManualClock`](crate::circuit::ManualClock)
	/// or tuned decay/window).
	#[must_use]
	pub fn with_baseline(mut self, baseline: ShapeBaseline) -> Self {
		self.shapes = baseline;
		self
	}

	/// Route emitted [`SecurityEvent::ShapeAnomaly`] events to `sink`. Without one, anomalies
	/// still raise difficulty but emit no event.
	#[must_use]
	pub fn events(mut self, sink: Arc<dyn SecurityEventSink>) -> Self {
		self.sink = Some(sink);
		self
	}

	/// The shared baseline, for observability (`total_weight`, `distinct`).
	#[must_use]
	pub const fn baseline(&self) -> &ShapeBaseline {
		&self.shapes
	}

	/// Fold `shape` into the baseline, emit a [`SecurityEvent::ShapeAnomaly`] if its
	/// deviation is at/above `emit_threshold`, and return the PoW difficulty for that
	/// deviation. The per-request entry point.
	pub fn observe(&self, shape: &RequestShape) -> u32 {
		let deviation = self.shapes.observe(shape);
		if deviation >= self.emit_threshold
			&& let Some(sink) = &self.sink
		{
			sink.record(&SecurityEvent::shape_anomaly(deviation));
		}
		self.difficulty_for(deviation)
	}

	/// Map a deviation score to a difficulty along the configured band, without recording.
	#[must_use]
	pub fn difficulty_for(&self, deviation: f64) -> u32 {
		if deviation <= self.low_dev {
			return self.baseline;
		}
		if deviation >= self.high_dev {
			return self.max;
		}
		let frac = (deviation - self.low_dev) / (self.high_dev - self.low_dev);
		let span = f64::from(self.max - self.baseline);
		self.baseline + (frac * span).round() as u32
	}
}

/// Default bot-suspicion band: below `0.3` difficulty stays at baseline, at/above `0.9` it is
/// maxed.
const DEFAULT_LOW_BOT: f64 = 0.3;
const DEFAULT_HIGH_BOT: f64 = 0.9;
/// Default suspicion at/above which a [`SecurityEvent::BotFlagged`] is emitted.
const DEFAULT_BOT_EMIT_THRESHOLD: f64 = 0.5;

/// A PoW-difficulty controller driven by **request-shape bot suspicion**, the third signal
/// alongside [`AdaptiveDifficulty`]'s raw rate and [`ShapeDifficulty`]'s deviation-from-baseline
/// (see `ROADMAP.md` Phase 5 — heuristic bot detection as a difficulty input).
///
/// It owns a [`BotHeuristics`] scorer: each [`assess`](Self::assess) scores a request's shape
/// in `[0.0, 1.0]` and maps it to a difficulty:
/// - at or below `low_score` suspicion → `baseline` (a browser-shaped request costs nothing
///   extra),
/// - at or above `high_score` suspicion → `max` (an obviously scripted request pays full
///   effort),
/// - in between → linearly interpolated.
///
/// When suspicion reaches `emit_threshold`, a [`SecurityEvent::BotFlagged`] is recorded to the
/// configured sink (if any). Unlike [`ShapeDifficulty`] there is no learning phase — the
/// heuristics are stateless — so a no-JS browser (which still sends a full header set) reads as
/// `0.0` and stays at `baseline` from the first request. Bot suspicion is an *input* to
/// difficulty, never a hard block on its own.
///
/// `Send + Sync`; the host shares one instance and calls `assess` per request when minting a
/// puzzle.
pub struct BotDifficulty {
	baseline: u32,
	max: u32,
	low_score: f64,
	high_score: f64,
	emit_threshold: f64,
	heuristics: BotHeuristics,
	sink: Option<Arc<dyn SecurityEventSink>>,
}

impl BotDifficulty {
	/// A controller ramping from `baseline` to `max` difficulty as bot suspicion climbs across
	/// the default `0.3..0.9` band, emitting a [`SecurityEvent::BotFlagged`] at suspicion
	/// `>= 0.5`. `max` is clamped to at least `baseline`. Uses a default [`BotHeuristics`].
	#[must_use]
	pub fn new(baseline: u32, max: u32) -> Self {
		Self {
			baseline,
			max: max.max(baseline),
			low_score: DEFAULT_LOW_BOT,
			high_score: DEFAULT_HIGH_BOT,
			emit_threshold: DEFAULT_BOT_EMIT_THRESHOLD,
			heuristics: BotHeuristics::new(),
			sink: None,
		}
	}

	/// Set the suspicion band: at or below `low` difficulty is `baseline`, at or above `high` it
	/// is `max`. Both are clamped to `[0.0, 1.0]` and `high` is kept strictly above `low`.
	#[must_use]
	pub fn score_band(mut self, low: f64, high: f64) -> Self {
		self.low_score = low.clamp(0.0, 1.0);
		self.high_score = high.clamp(0.0, 1.0).max(self.low_score + f64::EPSILON);
		self
	}

	/// Set the suspicion at/above which a [`SecurityEvent::BotFlagged`] is emitted (clamped to
	/// `[0.0, 1.0]`).
	#[must_use]
	pub fn emit_threshold(mut self, threshold: f64) -> Self {
		self.emit_threshold = threshold.clamp(0.0, 1.0);
		self
	}

	/// Replace the internal [`BotHeuristics`] (e.g. one with a tuned sparse-header threshold).
	#[must_use]
	pub fn with_heuristics(mut self, heuristics: BotHeuristics) -> Self {
		self.heuristics = heuristics;
		self
	}

	/// Route emitted [`SecurityEvent::BotFlagged`] events to `sink`. Without one, flagged
	/// requests still raise difficulty but emit no event.
	#[must_use]
	pub fn events(mut self, sink: Arc<dyn SecurityEventSink>) -> Self {
		self.sink = Some(sink);
		self
	}

	/// The shared heuristics, for inspection.
	#[must_use]
	pub const fn heuristics(&self) -> &BotHeuristics {
		&self.heuristics
	}

	/// Score `parts` with the heuristics, emit a [`SecurityEvent::BotFlagged`] if its suspicion
	/// is at/above `emit_threshold`, and return the PoW difficulty for that suspicion. The
	/// per-request entry point.
	pub fn assess(&self, parts: &Parts) -> u32 {
		let assessment = self.heuristics.assess(parts);
		if assessment.score >= self.emit_threshold
			&& let Some(sink) = &self.sink
		{
			sink.record(&SecurityEvent::bot_flagged(&assessment));
		}
		self.difficulty_for(assessment.score)
	}

	/// Map a suspicion score to a difficulty along the configured band, without scoring a
	/// request or emitting.
	#[must_use]
	pub fn difficulty_for(&self, score: f64) -> u32 {
		if score <= self.low_score {
			return self.baseline;
		}
		if score >= self.high_score {
			return self.max;
		}
		let frac = (score - self.low_score) / (self.high_score - self.low_score);
		let span = f64::from(self.max - self.baseline);
		self.baseline + (frac * span).round() as u32
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use super::*;
	use crate::circuit::ManualClock;

	/// Shares one [`ManualClock`] between the test driver and the controller.
	struct ArcClock(Arc<ManualClock>);
	impl Clock for ArcClock {
		fn now(&self) -> Instant {
			self.0.now()
		}
	}

	fn with_manual(baseline: u32, max: u32) -> (AdaptiveDifficulty, Arc<ManualClock>) {
		let clock = Arc::new(ManualClock::new());
		let ctrl = AdaptiveDifficulty::new(baseline, max)
			.rate_band(2, 10)
			.window(Duration::from_secs(1))
			.with_clock(Box::new(ArcClock(clock.clone())));
		(ctrl, clock)
	}

	#[test]
	fn dormant_at_or_below_low_rate() {
		let (ctrl, _clock) = with_manual(0, 20);
		// No traffic at all.
		assert_eq!(ctrl.current_difficulty(), 0);
		// Up to low_rate (2) requests stays at baseline.
		ctrl.record_request();
		ctrl.record_request();
		assert_eq!(ctrl.observed_rate(), 2);
		assert_eq!(ctrl.current_difficulty(), 0);
	}

	#[test]
	fn maxes_out_at_or_above_high_rate() {
		let (ctrl, _clock) = with_manual(4, 20);
		for _ in 0..10 {
			ctrl.record_request();
		}
		assert_eq!(ctrl.observed_rate(), 10);
		assert_eq!(ctrl.current_difficulty(), 20);
	}

	#[test]
	fn interpolates_between_band_edges() {
		let (ctrl, _clock) = with_manual(0, 16);
		// band low=2, high=10 → span 8 over the rate; midpoint rate 6 → 4/8 of 16 = 8.
		for _ in 0..6 {
			ctrl.record_request();
		}
		assert_eq!(ctrl.observed_rate(), 6);
		assert_eq!(ctrl.current_difficulty(), 8);
	}

	#[test]
	fn window_roll_returns_to_baseline() {
		let (ctrl, clock) = with_manual(0, 20);
		for _ in 0..10 {
			ctrl.record_request();
		}
		assert_eq!(ctrl.current_difficulty(), 20);
		// Once the window elapses with no new traffic, difficulty collapses to baseline.
		clock.advance(Duration::from_secs(1));
		assert_eq!(ctrl.observed_rate(), 0);
		assert_eq!(ctrl.current_difficulty(), 0);
	}

	#[test]
	fn max_clamped_to_at_least_baseline() {
		// max below baseline is clamped up; difficulty never dips under baseline.
		let ctrl = AdaptiveDifficulty::new(10, 3);
		assert_eq!(ctrl.current_difficulty(), 10);
	}

	#[test]
	fn rate_band_high_clamped_above_low() {
		// A degenerate band (high <= low) must not divide by zero.
		let clock = Arc::new(ManualClock::new());
		let ctrl = AdaptiveDifficulty::new(0, 8)
			.rate_band(5, 5)
			.with_clock(Box::new(ArcClock(clock.clone())));
		for _ in 0..6 {
			ctrl.record_request();
		}
		// high was clamped to low+1 = 6, so rate 6 is at/above max.
		assert_eq!(ctrl.current_difficulty(), 8);
	}

	// --- ShapeDifficulty (deviation-driven) ---

	use axum::http::Request;

	use crate::{observe::CapturingSink, shape::RequestShape};

	fn req_shape(uri: &str, ua: &str) -> RequestShape {
		RequestShape::from_parts(&Request::builder().uri(uri).header("user-agent", ua).body(()).unwrap().into_parts().0)
	}

	/// A [`ShapeBaseline`] on a shared [`ManualClock`], primed with `n` copies of one
	/// "normal" shape so deviation scoring is active and that shape reads as normal.
	fn primed_baseline(n: usize) -> (ShapeBaseline, Arc<ManualClock>) {
		let clock = Arc::new(ManualClock::new());
		let baseline = ShapeBaseline::new().min_observations(5.0).window(Duration::from_secs(10)).decay(0.5).with_clock(Box::new(ArcClock(clock.clone())));
		for _ in 0..n {
			baseline.observe(&req_shape("/", "tor-browser"));
		}
		(baseline, clock)
	}

	#[test]
	fn difficulty_for_interpolates_across_dev_band() {
		let ctrl = ShapeDifficulty::new(0, 20).dev_band(0.2, 0.8);
		assert_eq!(ctrl.difficulty_for(0.1), 0); // below band → baseline
		assert_eq!(ctrl.difficulty_for(0.2), 0); // at low edge → baseline
		assert_eq!(ctrl.difficulty_for(0.5), 10); // midpoint of 0.2..0.8 → half of 20
		assert_eq!(ctrl.difficulty_for(0.8), 20); // at high edge → max
		assert_eq!(ctrl.difficulty_for(0.95), 20); // above band → max
	}

	#[test]
	fn normal_shape_stays_at_baseline_and_emits_nothing() {
		let (baseline, _clock) = primed_baseline(20);
		let sink = CapturingSink::new();
		let ctrl = ShapeDifficulty::new(2, 24).with_baseline(baseline).events(Arc::new(sink.clone()));
		// The primed normal shape deviates ~0 → baseline difficulty, no anomaly event.
		assert_eq!(ctrl.observe(&req_shape("/", "tor-browser")), 2);
		assert!(sink.is_empty());
	}

	#[test]
	fn novel_shape_raises_difficulty_and_emits_anomaly() {
		let (baseline, _clock) = primed_baseline(20);
		let sink = CapturingSink::new();
		let ctrl = ShapeDifficulty::new(0, 20).with_baseline(baseline).events(Arc::new(sink.clone()));
		// A never-seen shape deviates ~1.0 → max difficulty and an emitted anomaly.
		let diff = ctrl.observe(&req_shape("/wp-login.php", "curl/8.4"));
		assert_eq!(diff, 20);
		let events = sink.events();
		assert_eq!(events.len(), 1);
		match events[0] {
			SecurityEvent::ShapeAnomaly { score_permille } => assert!(score_permille > 900, "expected high deviation, got {score_permille}"),
			ref other => panic!("expected ShapeAnomaly, got {other:?}"),
		}
	}

	#[test]
	fn cold_start_stays_at_baseline() {
		// A baseline still under its learning floor returns deviation 0 → baseline difficulty.
		let clock = Arc::new(ManualClock::new());
		let baseline = ShapeBaseline::new().min_observations(50.0).with_clock(Box::new(ArcClock(clock)));
		let ctrl = ShapeDifficulty::new(3, 30).with_baseline(baseline);
		assert_eq!(ctrl.observe(&req_shape("/anything", "weird-bot")), 3);
	}

	#[test]
	fn no_sink_still_raises_difficulty() {
		let (baseline, _clock) = primed_baseline(20);
		let ctrl = ShapeDifficulty::new(0, 16).with_baseline(baseline); // no events()
		assert_eq!(ctrl.observe(&req_shape("/novel", "bot")), 16);
		// Baseline observability still works through the controller.
		assert!(ctrl.baseline().total_weight() > 20.0);
	}

	#[test]
	fn dev_band_clamps_degenerate_input() {
		// high <= low must not divide by zero; out-of-range clamps into [0,1].
		let ctrl = ShapeDifficulty::new(0, 10).dev_band(0.9, 0.1);
		// high was forced above low, so a mid score still maps sanely (no NaN/panic).
		let d = ctrl.difficulty_for(0.95);
		assert_eq!(d, 10);
	}

	// --- BotDifficulty (bot-suspicion-driven) ---

	fn browser_parts() -> Parts {
		Request::builder()
			.uri("/")
			.header("host", "x.onion")
			.header("user-agent", "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0")
			.header("accept", "text/html")
			.header("accept-language", "en-US,en")
			.header("accept-encoding", "gzip, deflate, br")
			.header("connection", "keep-alive")
			.body(())
			.unwrap()
			.into_parts()
			.0
	}

	fn curl_parts() -> Parts {
		Request::builder().uri("/").header("host", "x.onion").header("user-agent", "curl/8.0.1").header("accept", "*/*").body(()).unwrap().into_parts().0
	}

	#[test]
	fn bot_difficulty_for_interpolates_across_band() {
		let ctrl = BotDifficulty::new(0, 20).score_band(0.2, 0.8);
		assert_eq!(ctrl.difficulty_for(0.1), 0); // below band → baseline
		assert_eq!(ctrl.difficulty_for(0.2), 0); // at low edge → baseline
		assert_eq!(ctrl.difficulty_for(0.5), 10); // midpoint → half of 20
		assert_eq!(ctrl.difficulty_for(0.8), 20); // at high edge → max
		assert_eq!(ctrl.difficulty_for(0.95), 20); // above band → max
	}

	#[test]
	fn browser_request_stays_at_baseline_and_emits_nothing() {
		let sink = CapturingSink::new();
		let ctrl = BotDifficulty::new(2, 24).events(Arc::new(sink.clone()));
		// A browser-shaped request scores 0.0 → baseline, no BotFlagged event.
		assert_eq!(ctrl.assess(&browser_parts()), 2);
		assert!(sink.is_empty());
	}

	#[test]
	fn scripted_request_raises_difficulty_and_emits_bot_flagged() {
		let sink = CapturingSink::new();
		// curl scores ~1.0 (non-browser UA + no lang + no encoding + sparse) → max difficulty.
		let ctrl = BotDifficulty::new(0, 20).events(Arc::new(sink.clone()));
		assert_eq!(ctrl.assess(&curl_parts()), 20);
		let events = sink.events();
		assert_eq!(events.len(), 1);
		match events[0] {
			SecurityEvent::BotFlagged { score_permille, signal_count } => {
				assert!(score_permille >= 900, "expected high suspicion, got {score_permille}");
				assert!(signal_count >= 3, "expected several signals, got {signal_count}");
			}
			ref other => panic!("expected BotFlagged, got {other:?}"),
		}
	}

	#[test]
	fn bot_no_sink_still_raises_difficulty() {
		let ctrl = BotDifficulty::new(0, 16); // no events()
		assert_eq!(ctrl.assess(&curl_parts()), 16);
	}

	#[test]
	fn emit_threshold_gates_events_independent_of_difficulty() {
		let sink = CapturingSink::new();
		// Emit only at near-certainty, but a low band so even mild suspicion maxes difficulty.
		let ctrl = BotDifficulty::new(0, 8).score_band(0.0, 0.1).emit_threshold(0.99).events(Arc::new(sink.clone()));
		// curl maxes difficulty...
		assert_eq!(ctrl.assess(&curl_parts()), 8);
		// ...and clears the 0.99 emit threshold (curl clamps to 1.0).
		assert_eq!(sink.len(), 1);
	}

	#[test]
	fn score_band_clamps_degenerate_input() {
		// high <= low must not divide by zero; out-of-range clamps into [0,1].
		let ctrl = BotDifficulty::new(0, 10).score_band(0.9, 0.1);
		assert_eq!(ctrl.difficulty_for(0.95), 10);
	}

	#[test]
	fn bot_max_clamped_to_at_least_baseline() {
		let ctrl = BotDifficulty::new(10, 3);
		assert_eq!(ctrl.assess(&curl_parts()), 10);
	}
}

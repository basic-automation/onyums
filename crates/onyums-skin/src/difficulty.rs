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
	sync::Mutex,
	time::{Duration, Instant},
};

use crate::circuit::{Clock, SystemClock};

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
}

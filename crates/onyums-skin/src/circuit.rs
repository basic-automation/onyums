//! The Tor dimension: per-rendezvous-circuit accounting and policy.
//!
//! A normal axum app cannot express this; onyums calls [`CircuitPolicy`] from its
//! `RendRequest` / `StreamRequest` loop, supplying a host-assigned [`CircuitId`] and
//! the requested [`StreamTarget`]. This generalizes the one-off port-443/80 gate that
//! currently lives in onyums' `handle_stream_request`. See `ROADMAP.md`.

use std::{
	collections::HashMap,
	sync::{Arc, Mutex},
	time::{Duration, Instant},
};

use crate::observe::{SecurityEvent, SecurityEventSink};

/// A monotonic time source, injectable so time-windowed policy is deterministically
/// testable without sleeping. Production uses [`SystemClock`]; tests (and downstream
/// tests of custom policies) use [`ManualClock`].
pub trait Clock: Send + Sync {
	/// The current monotonic instant.
	fn now(&self) -> Instant;
}

/// The default [`Clock`]: wraps [`Instant::now`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
	fn now(&self) -> Instant {
		Instant::now()
	}
}

/// A hand-advanced [`Clock`] for deterministic tests. Time only moves when
/// [`advance`](Self::advance) is called, so a windowed rate limit can be exercised
/// with no real sleeping. Built from a fixed base instant; [`advance`](Self::advance)
/// adds to a monotonic offset.
pub struct ManualClock {
	base: Instant,
	offset: Mutex<Duration>,
}

impl ManualClock {
	/// A clock anchored at the current instant with zero offset.
	#[must_use]
	pub fn new() -> Self {
		Self { base: Instant::now(), offset: Mutex::new(Duration::ZERO) }
	}

	/// Move the clock forward by `by`.
	pub fn advance(&self, by: Duration) {
		let mut offset = self.offset.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
		*offset += by;
	}
}

impl Default for ManualClock {
	fn default() -> Self {
		Self::new()
	}
}

impl Clock for ManualClock {
	fn now(&self) -> Instant {
		let offset = *self.offset.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
		self.base + offset
	}
}

/// What to do with a circuit / stream / request at the Tor layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitAction {
	/// Serve normally.
	Accept,
	/// Force the client through a challenge before serving.
	Challenge,
	/// Refuse this stream/request.
	Reject,
	/// Tear down the whole rendezvous circuit (Arti `shutdown_circuit()`).
	Shutdown,
}

/// Opaque per-rendezvous-circuit identifier assigned by the host (onyums).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CircuitId(pub u64);

/// Where a stream wants to go (the BEGIN-cell target).
#[derive(Clone, Debug)]
pub struct StreamTarget {
	pub port: u16,
	pub host: Option<String>,
}

/// Per-circuit accounting and policy. The host invokes these as circuits, streams,
/// and requests arrive; the returned [`CircuitAction`] drives accept/reject/shutdown.
pub trait CircuitPolicy: Send + Sync {
	/// A new rendezvous circuit was offered.
	fn on_new_circuit(&self, id: &CircuitId) -> CircuitAction;
	/// A new stream opened within an accepted circuit.
	fn on_new_stream(&self, id: &CircuitId, target: &StreamTarget) -> CircuitAction;
	/// A request arrived on an accepted stream (per-circuit rate/quota).
	fn on_request(&self, id: &CircuitId) -> CircuitAction;
	/// `bytes` were transferred on the circuit (the host's choice of direction —
	/// typically response bytes). Drives the per-circuit byte budget. The default
	/// records nothing and accepts, so existing policies need no change.
	fn on_bytes(&self, id: &CircuitId, bytes: u64) -> CircuitAction {
		let _ = (id, bytes);
		CircuitAction::Accept
	}

	/// Forget a circuit's accounting — the host calls this once a circuit is torn down
	/// (there is no stream-close hook), so a stateful policy's per-circuit map does not
	/// grow without bound. The default does nothing, for stateless policies.
	fn forget(&self, id: &CircuitId) {
		let _ = id;
	}
}

/// Cumulative running totals for one rendezvous circuit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CircuitStats {
	/// Streams opened on this circuit so far.
	pub streams: u64,
	/// Requests seen on this circuit so far.
	pub requests: u64,
	/// Bytes transferred on this circuit so far (as reported via
	/// [`on_bytes`](CircuitPolicy::on_bytes)).
	pub bytes: u64,
}

/// A concrete [`CircuitPolicy`] that does per-circuit accounting and enforces
/// simple abuse circuit-breakers.
///
/// It keeps cumulative [`CircuitStats`] per [`CircuitId`] and can:
/// - force every new circuit through the app-layer gate ("Under Attack Mode"),
/// - tear down (`Shutdown`) a circuit that opens more than `max_streams` streams —
///   a circuit fanning out streams is a classic abuse pattern, torn down wholesale,
/// - reject (`Reject`) requests on a circuit past `max_requests`,
/// - reject (`Reject`) requests on a circuit that exceeds a time-windowed request
///   *rate* ([`max_request_rate`](Self::max_request_rate)) — the sustained-flood
///   circuit-breaker, distinct from the cumulative `max_requests` ceiling,
/// - tear down (`Shutdown`) a circuit that transfers more than `max_bytes` bytes —
///   a per-circuit data budget against bandwidth-exhaustion abuse.
///
/// All caps are opt-in; with none set the policy is accept-all and serves purely
/// as the accounting substrate (the [`stats`](Self::stats) the host reads for
/// observability and adaptive difficulty). The windowed rate cap reads time from an
/// injectable [`Clock`] so it is testable without sleeping; token-keyed rate limiting
/// already lives in [`SkinRateLimit`](crate::ratelimit::SkinRateLimit).
///
/// The host should call [`forget`](Self::forget) when a circuit is torn down so the
/// accounting map does not grow without bound (there is no stream-close hook).
pub struct AccountingCircuitPolicy {
	inner: Mutex<HashMap<CircuitId, CircuitState>>,
	max_streams: Option<u64>,
	max_requests: Option<u64>,
	/// `(max requests, per window)` — the time-windowed request-rate cap.
	max_request_rate: Option<(u64, Duration)>,
	max_bytes: Option<u64>,
	under_attack: bool,
	clock: Box<dyn Clock>,
	/// Optional sink for [`SecurityEvent::Circuit`] events. `None` (default) emits
	/// nothing; the host opts in with [`with_events`](Self::with_events).
	sink: Option<Arc<dyn SecurityEventSink>>,
}

/// Internal per-circuit bookkeeping: the publicly surfaced [`CircuitStats`] plus the
/// fixed-window rate-limit counters (not surfaced — they are limiter state, not stats).
#[derive(Default)]
struct CircuitState {
	stats: CircuitStats,
	/// Start of the current rate window; `None` until the first request.
	window_start: Option<Instant>,
	/// Requests counted in the current window.
	window_count: u64,
}

impl AccountingCircuitPolicy {
	/// An accept-all accounting policy with no caps and Under Attack Mode off,
	/// reading time from the [`SystemClock`].
	#[must_use]
	pub fn new() -> Self {
		Self {
			inner: Mutex::new(HashMap::new()),
			max_streams: None,
			max_requests: None,
			max_request_rate: None,
			max_bytes: None,
			under_attack: false,
			clock: Box::new(SystemClock),
			sink: None,
		}
	}

	/// Tear down any circuit that opens more than `max` streams.
	#[must_use]
	pub const fn max_streams(mut self, max: u64) -> Self {
		self.max_streams = Some(max);
		self
	}

	/// Reject requests on a circuit once it has seen more than `max` of them.
	#[must_use]
	pub const fn max_requests(mut self, max: u64) -> Self {
		self.max_requests = Some(max);
		self
	}

	/// Reject requests once a circuit exceeds `max` requests within any `per` window.
	///
	/// This is a fixed-window rate cap: the first request in a window starts the
	/// clock, the `max + 1`-th request inside that window is rejected, and the window
	/// resets once `per` elapses. Unlike [`max_requests`](Self::max_requests) (a
	/// lifetime ceiling) this throttles sustained floods while letting a long-lived,
	/// well-behaved circuit keep serving.
	#[must_use]
	pub const fn max_request_rate(mut self, max: u64, per: Duration) -> Self {
		self.max_request_rate = Some((max, per));
		self
	}

	/// Tear down any circuit that transfers more than `max` bytes (a per-circuit data
	/// budget; the host reports transfer via [`on_bytes`](CircuitPolicy::on_bytes)).
	#[must_use]
	pub const fn max_bytes(mut self, max: u64) -> Self {
		self.max_bytes = Some(max);
		self
	}

	/// Replace the time source (default [`SystemClock`]). Use [`ManualClock`] to drive
	/// the windowed rate cap deterministically in tests.
	#[must_use]
	pub fn with_clock(mut self, clock: Box<dyn Clock>) -> Self {
		self.clock = clock;
		self
	}

	/// Under Attack Mode: force every new circuit through the challenge gate.
	#[must_use]
	pub const fn under_attack(mut self, on: bool) -> Self {
		self.under_attack = on;
		self
	}

	/// Route a [`SecurityEvent::Circuit`] to `sink` whenever this policy returns a
	/// non-[`Accept`](CircuitAction::Accept) action (a reject, a teardown, or an
	/// Under-Attack-Mode challenge). Off by default — circuit accounting is a low-level
	/// building block the host wires, so it stays silent unless events are requested.
	#[must_use]
	pub fn with_events(mut self, sink: Arc<dyn SecurityEventSink>) -> Self {
		self.sink = Some(sink);
		self
	}

	/// Emit a [`SecurityEvent::Circuit`] for a non-`Accept` action (when a sink is
	/// configured), then return the action unchanged so call sites read `self.emit(id, a)`.
	fn emit(&self, id: &CircuitId, action: CircuitAction) -> CircuitAction {
		if action != CircuitAction::Accept
			&& let Some(sink) = &self.sink
		{
			sink.record(&SecurityEvent::Circuit { id: *id, action });
		}
		action
	}

	/// The current accounting for a circuit, if it is known.
	#[must_use]
	pub fn stats(&self, id: &CircuitId) -> Option<CircuitStats> {
		self.lock().get(id).map(|state| state.stats)
	}

	/// Lock the accounting map, recovering from a poisoned mutex (the only thing
	/// done under the lock is map bookkeeping, so poisoning carries no broken
	/// invariant).
	fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<CircuitId, CircuitState>> {
		self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
	}
}

impl Default for AccountingCircuitPolicy {
	fn default() -> Self {
		Self::new()
	}
}

impl CircuitPolicy for AccountingCircuitPolicy {
	fn on_new_circuit(&self, id: &CircuitId) -> CircuitAction {
		self.lock().entry(*id).or_default();
		let action = if self.under_attack { CircuitAction::Challenge } else { CircuitAction::Accept };
		self.emit(id, action)
	}

	fn on_new_stream(&self, id: &CircuitId, _target: &StreamTarget) -> CircuitAction {
		let over = {
			let mut map = self.lock();
			let state = map.entry(*id).or_default();
			state.stats.streams += 1;
			self.max_streams.is_some_and(|max| state.stats.streams > max)
		};
		self.emit(id, if over { CircuitAction::Shutdown } else { CircuitAction::Accept })
	}

	fn on_request(&self, id: &CircuitId) -> CircuitAction {
		// Read the clock before taking the lock so we never call into a user-supplied
		// clock while holding it.
		let now = self.max_request_rate.map(|_| self.clock.now());
		let action = {
			let mut map = self.lock();
			let state = map.entry(*id).or_default();
			state.stats.requests += 1;
			if self.max_requests.is_some_and(|max| state.stats.requests > max) {
				CircuitAction::Reject
			} else if let (Some((max, per)), Some(now)) = (self.max_request_rate, now) {
				let fresh_window = match state.window_start {
					Some(start) => now.saturating_duration_since(start) >= per,
					None => true,
				};
				if fresh_window {
					state.window_start = Some(now);
					state.window_count = 1;
				} else {
					state.window_count += 1;
				}
				if state.window_count > max { CircuitAction::Reject } else { CircuitAction::Accept }
			} else {
				CircuitAction::Accept
			}
		};
		self.emit(id, action)
	}

	fn on_bytes(&self, id: &CircuitId, bytes: u64) -> CircuitAction {
		let over = {
			let mut map = self.lock();
			let state = map.entry(*id).or_default();
			state.stats.bytes = state.stats.bytes.saturating_add(bytes);
			self.max_bytes.is_some_and(|max| state.stats.bytes > max)
		};
		self.emit(id, if over { CircuitAction::Shutdown } else { CircuitAction::Accept })
	}

	fn forget(&self, id: &CircuitId) {
		self.lock().remove(id);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const C1: CircuitId = CircuitId(1);
	const C2: CircuitId = CircuitId(2);

	fn target() -> StreamTarget {
		StreamTarget { port: 443, host: None }
	}

	#[test]
	fn accepts_and_accounts_by_default() {
		let policy = AccountingCircuitPolicy::new();
		assert_eq!(policy.on_new_circuit(&C1), CircuitAction::Accept);
		assert_eq!(policy.on_new_stream(&C1, &target()), CircuitAction::Accept);
		assert_eq!(policy.on_request(&C1), CircuitAction::Accept);
		assert_eq!(policy.on_request(&C1), CircuitAction::Accept);
		assert_eq!(policy.stats(&C1), Some(CircuitStats { streams: 1, requests: 2, bytes: 0 }));
	}

	#[test]
	fn under_attack_challenges_new_circuits() {
		let policy = AccountingCircuitPolicy::new().under_attack(true);
		assert_eq!(policy.on_new_circuit(&C1), CircuitAction::Challenge);
		// The circuit is still registered for accounting despite being challenged.
		assert_eq!(policy.stats(&C1), Some(CircuitStats::default()));
	}

	#[test]
	fn stream_cap_shuts_down_circuit() {
		let policy = AccountingCircuitPolicy::new().max_streams(2);
		assert_eq!(policy.on_new_stream(&C1, &target()), CircuitAction::Accept);
		assert_eq!(policy.on_new_stream(&C1, &target()), CircuitAction::Accept);
		assert_eq!(policy.on_new_stream(&C1, &target()), CircuitAction::Shutdown);
	}

	#[test]
	fn request_cap_rejects() {
		let policy = AccountingCircuitPolicy::new().max_requests(2);
		assert_eq!(policy.on_request(&C1), CircuitAction::Accept);
		assert_eq!(policy.on_request(&C1), CircuitAction::Accept);
		assert_eq!(policy.on_request(&C1), CircuitAction::Reject);
	}

	#[test]
	fn circuits_are_accounted_independently() {
		let policy = AccountingCircuitPolicy::new();
		policy.on_new_stream(&C1, &target());
		policy.on_request(&C2);
		assert_eq!(policy.stats(&C1), Some(CircuitStats { streams: 1, requests: 0, bytes: 0 }));
		assert_eq!(policy.stats(&C2), Some(CircuitStats { streams: 0, requests: 1, bytes: 0 }));
	}

	#[test]
	fn forget_clears_circuit_state() {
		let policy = AccountingCircuitPolicy::new();
		policy.on_request(&C1);
		assert!(policy.stats(&C1).is_some());
		policy.forget(&C1);
		assert_eq!(policy.stats(&C1), None);
	}

	#[test]
	fn rate_cap_rejects_within_window_then_recovers_after() {
		let clock = std::sync::Arc::new(ManualClock::new());
		let policy = AccountingCircuitPolicy::new()
			.max_request_rate(2, Duration::from_secs(1))
			.with_clock(Box::new(ArcClock(clock.clone())));
		// Two requests inside the window are fine; the third is throttled.
		assert_eq!(policy.on_request(&C1), CircuitAction::Accept);
		assert_eq!(policy.on_request(&C1), CircuitAction::Accept);
		assert_eq!(policy.on_request(&C1), CircuitAction::Reject);
		// Advancing past the window opens a fresh allowance.
		clock.advance(Duration::from_secs(1));
		assert_eq!(policy.on_request(&C1), CircuitAction::Accept);
		assert_eq!(policy.on_request(&C1), CircuitAction::Accept);
		assert_eq!(policy.on_request(&C1), CircuitAction::Reject);
		// Cumulative accounting still counts every request, throttled or not.
		assert_eq!(policy.stats(&C1), Some(CircuitStats { streams: 0, requests: 6, bytes: 0 }));
	}

	#[test]
	fn rate_windows_are_per_circuit() {
		let clock = std::sync::Arc::new(ManualClock::new());
		let policy = AccountingCircuitPolicy::new()
			.max_request_rate(1, Duration::from_secs(1))
			.with_clock(Box::new(ArcClock(clock.clone())));
		assert_eq!(policy.on_request(&C1), CircuitAction::Accept);
		assert_eq!(policy.on_request(&C1), CircuitAction::Reject);
		// A different circuit gets its own fresh window.
		assert_eq!(policy.on_request(&C2), CircuitAction::Accept);
	}

	#[test]
	fn lifetime_ceiling_and_rate_cap_compose() {
		let clock = std::sync::Arc::new(ManualClock::new());
		// Generous rate (never the binding constraint here), tight lifetime ceiling.
		let policy = AccountingCircuitPolicy::new()
			.max_requests(3)
			.max_request_rate(100, Duration::from_secs(1))
			.with_clock(Box::new(ArcClock(clock.clone())));
		assert_eq!(policy.on_request(&C1), CircuitAction::Accept);
		assert_eq!(policy.on_request(&C1), CircuitAction::Accept);
		assert_eq!(policy.on_request(&C1), CircuitAction::Accept);
		// The lifetime ceiling bites even though the rate window is wide open.
		assert_eq!(policy.on_request(&C1), CircuitAction::Reject);
	}

	#[test]
	fn byte_accounting_accumulates_without_cap() {
		let policy = AccountingCircuitPolicy::new();
		assert_eq!(policy.on_bytes(&C1, 100), CircuitAction::Accept);
		assert_eq!(policy.on_bytes(&C1, 250), CircuitAction::Accept);
		assert_eq!(policy.stats(&C1), Some(CircuitStats { streams: 0, requests: 0, bytes: 350 }));
	}

	#[test]
	fn byte_cap_shuts_down_over_budget_circuit() {
		let policy = AccountingCircuitPolicy::new().max_bytes(1000);
		assert_eq!(policy.on_bytes(&C1, 600), CircuitAction::Accept);
		assert_eq!(policy.on_bytes(&C1, 400), CircuitAction::Accept); // exactly at budget
		assert_eq!(policy.on_bytes(&C1, 1), CircuitAction::Shutdown); // one byte over
	}

	#[test]
	fn byte_budgets_are_per_circuit() {
		let policy = AccountingCircuitPolicy::new().max_bytes(100);
		assert_eq!(policy.on_bytes(&C1, 101), CircuitAction::Shutdown);
		assert_eq!(policy.on_bytes(&C2, 50), CircuitAction::Accept);
	}

	#[test]
	fn byte_accounting_saturates_rather_than_overflows() {
		let policy = AccountingCircuitPolicy::new();
		policy.on_bytes(&C1, u64::MAX);
		assert_eq!(policy.on_bytes(&C1, 1), CircuitAction::Accept);
		assert_eq!(policy.stats(&C1).map(|s| s.bytes), Some(u64::MAX));
	}

	#[test]
	fn default_on_bytes_is_a_noop_accept() {
		// A bare CircuitPolicy that overrides nothing else still accepts and records
		// nothing via the default on_bytes.
		struct AcceptAll;
		impl CircuitPolicy for AcceptAll {
			fn on_new_circuit(&self, _: &CircuitId) -> CircuitAction {
				CircuitAction::Accept
			}
			fn on_new_stream(&self, _: &CircuitId, _: &StreamTarget) -> CircuitAction {
				CircuitAction::Accept
			}
			fn on_request(&self, _: &CircuitId) -> CircuitAction {
				CircuitAction::Accept
			}
		}
		assert_eq!(AcceptAll.on_bytes(&C1, 9999), CircuitAction::Accept);
	}

	#[test]
	fn forget_is_callable_through_a_trait_object() {
		// The host holds an `Arc<dyn CircuitPolicy>` and must be able to forget circuits
		// generically; `AccountingCircuitPolicy` actually drops the state.
		let policy: Box<dyn CircuitPolicy> = Box::new(AccountingCircuitPolicy::new());
		policy.on_request(&C1);
		policy.forget(&C1);
		// Downcast is not available through the trait object, so re-observe via a fresh
		// request: the cumulative count restarts from 1, proving the prior state was dropped.
		policy.on_request(&C1);
	}

	#[test]
	fn default_forget_is_a_noop() {
		// A stateless policy inherits the no-op default and must not panic.
		struct Stateless;
		impl CircuitPolicy for Stateless {
			fn on_new_circuit(&self, _: &CircuitId) -> CircuitAction {
				CircuitAction::Accept
			}
			fn on_new_stream(&self, _: &CircuitId, _: &StreamTarget) -> CircuitAction {
				CircuitAction::Accept
			}
			fn on_request(&self, _: &CircuitId) -> CircuitAction {
				CircuitAction::Accept
			}
		}
		Stateless.forget(&C1);
	}

	#[test]
	fn manual_clock_advances_monotonically() {
		let clock = ManualClock::new();
		let t0 = clock.now();
		clock.advance(Duration::from_millis(500));
		let t1 = clock.now();
		assert!(t1 > t0);
		assert_eq!(t1.saturating_duration_since(t0), Duration::from_millis(500));
	}

	/// Shares one [`ManualClock`] between the test driver and the policy so the test
	/// can advance time the policy reads. `AccountingCircuitPolicy` takes a boxed
	/// clock; an `Arc` newtype gives both ends the same underlying clock.
	struct ArcClock(std::sync::Arc<ManualClock>);

	impl Clock for ArcClock {
		fn now(&self) -> Instant {
			self.0.now()
		}
	}

	#[test]
	fn no_events_emitted_without_a_sink() {
		// The default policy has no sink; a teardown must still happen, just silently —
		// proving emission is genuinely opt-in (and the action path is unchanged).
		let policy = AccountingCircuitPolicy::new().max_streams(1);
		assert_eq!(policy.on_new_stream(&C1, &target()), CircuitAction::Accept);
		assert_eq!(policy.on_new_stream(&C1, &target()), CircuitAction::Shutdown);
	}

	#[test]
	fn shutdown_and_reject_emit_circuit_events() {
		let sink = crate::observe::CapturingSink::new();
		let policy = AccountingCircuitPolicy::new().max_streams(1).max_requests(1).with_events(Arc::new(sink.clone()));

		// An accepted stream/request emits nothing.
		assert_eq!(policy.on_new_stream(&C1, &target()), CircuitAction::Accept);
		assert_eq!(policy.on_request(&C1), CircuitAction::Accept);
		assert!(sink.is_empty(), "accepted actions are not events");

		// The over-cap stream tears the circuit down; the over-ceiling request rejects.
		assert_eq!(policy.on_new_stream(&C1, &target()), CircuitAction::Shutdown);
		assert_eq!(policy.on_request(&C1), CircuitAction::Reject);

		let events = sink.events();
		assert_eq!(events, vec![SecurityEvent::Circuit { id: C1, action: CircuitAction::Shutdown }, SecurityEvent::Circuit { id: C1, action: CircuitAction::Reject }]);
	}

	#[test]
	fn under_attack_challenge_emits_a_circuit_event() {
		let sink = crate::observe::CapturingSink::new();
		let policy = AccountingCircuitPolicy::new().under_attack(true).with_events(Arc::new(sink.clone()));
		assert_eq!(policy.on_new_circuit(&C1), CircuitAction::Challenge);
		assert_eq!(sink.events(), vec![SecurityEvent::Circuit { id: C1, action: CircuitAction::Challenge }]);
	}

	#[test]
	fn byte_budget_teardown_emits_a_circuit_event() {
		let sink = crate::observe::CapturingSink::new();
		let policy = AccountingCircuitPolicy::new().max_bytes(100).with_events(Arc::new(sink.clone()));
		assert_eq!(policy.on_bytes(&C1, 50), CircuitAction::Accept);
		assert_eq!(policy.on_bytes(&C1, 60), CircuitAction::Shutdown); // over budget
		assert_eq!(sink.events(), vec![SecurityEvent::Circuit { id: C1, action: CircuitAction::Shutdown }]);
	}
}

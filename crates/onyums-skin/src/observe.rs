//! Structured security events (Phase 4 observability).
//!
//! "You can't tune what you can't see." The gate's interesting decisions — a WAF block,
//! a rate-limit trip, a challenge issued/passed/failed, a circuit torn down — are emitted
//! as a typed [`SecurityEvent`] through a [`SecurityEventSink`], *in addition to* (not
//! instead of) any `tracing` logging. A host that only wants logs gets them from the
//! default [`TracingSink`]; a host that wants metrics, an audit trail, or alerting
//! implements the trait and routes the typed events wherever it likes — without parsing
//! log lines.
//!
//! The events are deliberately IP-free: like the rest of Skin, every field is an
//! identity that survives Tor (a clearance [`TokenId`], a host-assigned [`CircuitId`], a
//! WAF rule id), never a network address. Emission points are wired in [`crate::layer`]
//! (the HTTP gate) and [`crate::circuit`] (the Tor dimension).

use std::sync::{
	Arc, Mutex,
	atomic::{AtomicU64, Ordering},
};

use crate::{
	circuit::{CircuitAction, CircuitId}, clearance::{ClearanceLevel, TokenId}, waf::WafCategory
};

/// How serious a [`SecurityEvent`] is, for log-level routing and operator triage. Ordered
/// from least to most severe so a sink can filter with a simple comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
	/// Routine, expected activity — a challenge issued, a client cleared.
	Info,
	/// A request was refused for hitting a limit (rate limit) — not an attack on its own,
	/// but worth watching in aggregate.
	Notice,
	/// A signature attack was blocked or an abusive circuit was torn down.
	Warning,
}

impl Severity {
	/// A stable, lowercase name for logs and metrics labels.
	#[must_use]
	pub const fn name(self) -> &'static str {
		match self {
			Self::Info => "info",
			Self::Notice => "notice",
			Self::Warning => "warning",
		}
	}
}

/// A typed record of a security-relevant decision the gate made. Carries enough structured
/// context (rule id, clearance level, circuit id) for a host to build metrics or an audit
/// log without re-parsing text. New variants may be added, so match with a wildcard arm.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecurityEvent {
	/// A WAF signature rule fired; the request was refused with `403`.
	WafBlock {
		/// The matched rule's stable id (e.g. `"sqli_union_select"`).
		rule_id: &'static str,
		/// The rule's signature class.
		category: WafCategory,
		/// Which part of the request matched (e.g. `"query"`, `"header:user-agent"`, `"body"`).
		location: String,
	},
	/// A cleared client exceeded its per-token request rate; refused with `429`.
	RateLimited {
		/// The clearance token whose bucket was drained — the synthetic per-client id.
		token: TokenId,
	},
	/// An uncleared client was presented a challenge (the PoW interstitial or a no-JS
	/// fallback).
	ChallengeIssued {
		/// Whether the gate treated the client as JavaScript-capable when selecting from
		/// the fallback chain.
		client_has_js: bool,
	},
	/// A client solved a challenge on the submission route and was granted a clearance.
	ChallengePassed {
		/// The clearance level minted (the strength of the gate the client cleared).
		level: ClearanceLevel,
	},
	/// A challenge submission failed verification; the challenge was re-presented.
	ChallengeFailed,
	/// No challenge in the chain fit the client (e.g. a JS-only chain against a no-JS
	/// client); the request was rejected with `403`.
	ChallengeUnavailable,
	/// A per-circuit policy refused a request/stream or tore a circuit down at the Tor
	/// layer. Only the refusing actions ([`CircuitAction::Reject`] /
	/// [`CircuitAction::Shutdown`] / [`CircuitAction::Challenge`]) are emitted — an
	/// `Accept` is not an event.
	Circuit {
		/// The host-assigned rendezvous-circuit id the action applies to.
		id: CircuitId,
		/// What the policy decided.
		action: CircuitAction,
	},
}

impl SecurityEvent {
	/// A stable, lowercase event kind for logs and metric names (the variant, not its
	/// fields).
	#[must_use]
	pub const fn kind(&self) -> &'static str {
		match self {
			Self::WafBlock { .. } => "waf_block",
			Self::RateLimited { .. } => "rate_limited",
			Self::ChallengeIssued { .. } => "challenge_issued",
			Self::ChallengePassed { .. } => "challenge_passed",
			Self::ChallengeFailed => "challenge_failed",
			Self::ChallengeUnavailable => "challenge_unavailable",
			Self::Circuit { .. } => "circuit_action",
		}
	}

	/// The [`Severity`] of this event, for log-level routing.
	#[must_use]
	pub const fn severity(&self) -> Severity {
		match self {
			Self::WafBlock { .. } => Severity::Warning,
			Self::Circuit { action, .. } => match action {
				// A torn-down circuit is the strongest signal; a reject/challenge is a notice.
				CircuitAction::Shutdown => Severity::Warning,
				_ => Severity::Notice,
			},
			Self::RateLimited { .. } | Self::ChallengeFailed | Self::ChallengeUnavailable => Severity::Notice,
			Self::ChallengeIssued { .. } | Self::ChallengePassed { .. } => Severity::Info,
		}
	}
}

/// A destination for [`SecurityEvent`]s. The host implements this to route typed events
/// into metrics, an audit log, or an alerting pipeline; the default [`TracingSink`] simply
/// logs them. Implementations must be cheap and non-blocking — `record` is called on the
/// request path — and `Send + Sync` so the sink can live behind an [`Arc`] in the shared
/// gate config.
pub trait SecurityEventSink: Send + Sync {
	/// Record one event. Called synchronously on the request path, so do not block (buffer
	/// or send to a channel if the real sink is slow).
	fn record(&self, event: &SecurityEvent);
}

/// The default sink: emit each event through `tracing` at a level matching its
/// [`Severity`], under the `onyums_skin::security` target so a host can filter the security
/// stream apart from ordinary logs.
#[derive(Clone, Copy, Debug, Default)]
pub struct TracingSink;

impl SecurityEventSink for TracingSink {
	fn record(&self, event: &SecurityEvent) {
		match event.severity() {
			Severity::Warning => tracing::warn!(target: "onyums_skin::security", kind = event.kind(), event = ?event, "security event"),
			Severity::Notice => tracing::info!(target: "onyums_skin::security", kind = event.kind(), event = ?event, "security event"),
			Severity::Info => tracing::debug!(target: "onyums_skin::security", kind = event.kind(), event = ?event, "security event"),
		}
	}
}

/// A sink that drops every event — for hosts that want no observability overhead at all.
/// (The gate defaults to [`TracingSink`], so this is an explicit opt-out.)
#[derive(Clone, Copy, Debug, Default)]
pub struct NullSink;

impl SecurityEventSink for NullSink {
	fn record(&self, _event: &SecurityEvent) {}
}

/// A sink that records every event into an in-memory buffer — for tests and small
/// dashboards. Cheaply cloneable; clones share the same buffer.
#[derive(Clone, Default)]
pub struct CapturingSink {
	events: Arc<Mutex<Vec<SecurityEvent>>>,
}

impl CapturingSink {
	/// A fresh, empty capturing sink.
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}

	/// A snapshot copy of the events recorded so far, oldest first.
	#[must_use]
	pub fn events(&self) -> Vec<SecurityEvent> {
		self.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
	}

	/// How many events have been recorded.
	#[must_use]
	pub fn len(&self) -> usize {
		self.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
	}

	/// Whether no events have been recorded yet.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}
}

impl SecurityEventSink for CapturingSink {
	fn record(&self, event: &SecurityEvent) {
		self.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(event.clone());
	}
}

/// A point-in-time snapshot of cumulative security-event counts, one counter per
/// [`SecurityEvent`] variant. Cheap, `Copy`, and IP-free — the numbers an operator
/// watches to see attack pressure and gate health at a glance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SecurityMetrics {
	/// WAF signature blocks ([`SecurityEvent::WafBlock`]), all categories.
	pub waf_blocks: u64,
	/// WAF blocks broken down by [`WafCategory`], indexed by
	/// [`WafCategory::index`]. Read it ergonomically with
	/// [`waf_blocks_in`](Self::waf_blocks_in); the per-index sum equals [`waf_blocks`](Self::waf_blocks).
	pub waf_blocks_by_category: [u64; WafCategory::ALL.len()],
	/// Per-token rate-limit trips ([`SecurityEvent::RateLimited`]).
	pub rate_limited: u64,
	/// Challenges presented ([`SecurityEvent::ChallengeIssued`]).
	pub challenges_issued: u64,
	/// Challenges cleared ([`SecurityEvent::ChallengePassed`]).
	pub challenges_passed: u64,
	/// Challenge submissions that failed verification ([`SecurityEvent::ChallengeFailed`]).
	pub challenges_failed: u64,
	/// Requests with no fitting challenge ([`SecurityEvent::ChallengeUnavailable`]).
	pub challenges_unavailable: u64,
	/// Non-`Accept` circuit-policy decisions ([`SecurityEvent::Circuit`]).
	pub circuit_actions: u64,
}

impl SecurityMetrics {
	/// WAF blocks attributed to one [`WafCategory`] — which attack class is hitting the
	/// service hardest.
	#[must_use]
	pub const fn waf_blocks_in(&self, category: WafCategory) -> u64 {
		self.waf_blocks_by_category[category.index()]
	}

	/// The share of decided challenges that were cleared — `passed / (passed + failed)`.
	/// Returns `None` until at least one challenge has been decided (no submissions yet),
	/// so a fresh gate does not report a misleading `0%`. A low ratio under load is a
	/// bot-flood signal (many failed solves); a high ratio is healthy human traffic.
	#[must_use]
	pub fn challenge_pass_ratio(&self) -> Option<f64> {
		let decided = self.challenges_passed + self.challenges_failed;
		(decided > 0).then(|| self.challenges_passed as f64 / decided as f64)
	}
}

/// A [`SecurityEventSink`] that tallies events into atomic per-variant counters, exposing
/// a [`SecurityMetrics`] [`snapshot`](Self::snapshot) for a metrics endpoint or dashboard.
/// Lock-free on the record path and cheaply cloneable — clones share the same counters, so
/// a host can hand one clone to the gate and keep another to read.
///
/// To both log *and* count, compose this with [`TracingSink`] under a [`FanoutSink`].
#[derive(Clone, Default)]
pub struct MetricsSink {
	inner: Arc<MetricsCounters>,
}

#[derive(Default)]
struct MetricsCounters {
	waf_blocks: AtomicU64,
	waf_by_category: [AtomicU64; WafCategory::ALL.len()],
	rate_limited: AtomicU64,
	challenges_issued: AtomicU64,
	challenges_passed: AtomicU64,
	challenges_failed: AtomicU64,
	challenges_unavailable: AtomicU64,
	circuit_actions: AtomicU64,
}

impl MetricsSink {
	/// A fresh sink with all counters at zero.
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}

	/// Read the current cumulative counts. Counters are read with `Relaxed` ordering, so a
	/// snapshot taken during concurrent recording is internally consistent per counter but
	/// not a single global instant — fine for monitoring.
	#[must_use]
	pub fn snapshot(&self) -> SecurityMetrics {
		let c = &self.inner;
		let mut waf_blocks_by_category = [0u64; WafCategory::ALL.len()];
		for (slot, counter) in waf_blocks_by_category.iter_mut().zip(c.waf_by_category.iter()) {
			*slot = counter.load(Ordering::Relaxed);
		}
		SecurityMetrics {
			waf_blocks: c.waf_blocks.load(Ordering::Relaxed),
			waf_blocks_by_category,
			rate_limited: c.rate_limited.load(Ordering::Relaxed),
			challenges_issued: c.challenges_issued.load(Ordering::Relaxed),
			challenges_passed: c.challenges_passed.load(Ordering::Relaxed),
			challenges_failed: c.challenges_failed.load(Ordering::Relaxed),
			challenges_unavailable: c.challenges_unavailable.load(Ordering::Relaxed),
			circuit_actions: c.circuit_actions.load(Ordering::Relaxed),
		}
	}
}

impl SecurityEventSink for MetricsSink {
	fn record(&self, event: &SecurityEvent) {
		// A WAF block also bumps its per-category counter (the total is counted below).
		if let SecurityEvent::WafBlock { category, .. } = event {
			self.inner.waf_by_category[category.index()].fetch_add(1, Ordering::Relaxed);
		}
		let counter = match event {
			SecurityEvent::WafBlock { .. } => &self.inner.waf_blocks,
			SecurityEvent::RateLimited { .. } => &self.inner.rate_limited,
			SecurityEvent::ChallengeIssued { .. } => &self.inner.challenges_issued,
			SecurityEvent::ChallengePassed { .. } => &self.inner.challenges_passed,
			SecurityEvent::ChallengeFailed => &self.inner.challenges_failed,
			SecurityEvent::ChallengeUnavailable => &self.inner.challenges_unavailable,
			SecurityEvent::Circuit { .. } => &self.inner.circuit_actions,
		};
		counter.fetch_add(1, Ordering::Relaxed);
	}
}

/// A [`SecurityEventSink`] that forwards each event to several sinks in order — so a host
/// can, e.g., both log via [`TracingSink`] and count via [`MetricsSink`] from the gate's
/// single sink slot. Cheaply cloneable (the sink list lives behind an [`Arc`]).
#[derive(Clone)]
pub struct FanoutSink {
	sinks: Arc<Vec<Arc<dyn SecurityEventSink>>>,
}

impl FanoutSink {
	/// Fan out to each of `sinks`, in the given order.
	#[must_use]
	pub fn new(sinks: Vec<Arc<dyn SecurityEventSink>>) -> Self {
		Self { sinks: Arc::new(sinks) }
	}
}

impl SecurityEventSink for FanoutSink {
	fn record(&self, event: &SecurityEvent) {
		for sink in self.sinks.iter() {
			sink.record(event);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn kind_is_stable_per_variant() {
		assert_eq!(SecurityEvent::ChallengeFailed.kind(), "challenge_failed");
		assert_eq!(SecurityEvent::WafBlock { rule_id: "x", category: WafCategory::Sqli, location: "query".to_owned() }.kind(), "waf_block");
		assert_eq!(SecurityEvent::Circuit { id: CircuitId(1), action: CircuitAction::Shutdown }.kind(), "circuit_action");
	}

	#[test]
	fn severity_orders_attacks_above_routine() {
		let block = SecurityEvent::WafBlock { rule_id: "x", category: WafCategory::Xss, location: "body".to_owned() };
		let issued = SecurityEvent::ChallengeIssued { client_has_js: true };
		assert_eq!(block.severity(), Severity::Warning);
		assert_eq!(issued.severity(), Severity::Info);
		assert!(block.severity() > issued.severity());
	}

	#[test]
	fn circuit_shutdown_is_more_severe_than_reject() {
		let shutdown = SecurityEvent::Circuit { id: CircuitId(7), action: CircuitAction::Shutdown };
		let reject = SecurityEvent::Circuit { id: CircuitId(7), action: CircuitAction::Reject };
		assert_eq!(shutdown.severity(), Severity::Warning);
		assert_eq!(reject.severity(), Severity::Notice);
	}

	#[test]
	fn null_sink_drops_events() {
		let sink = NullSink;
		// Nothing to assert beyond "does not panic / does not record" — exercise the path.
		sink.record(&SecurityEvent::ChallengeFailed);
	}

	#[test]
	fn capturing_sink_records_in_order_and_shares_across_clones() {
		let sink = CapturingSink::new();
		assert!(sink.is_empty());
		sink.record(&SecurityEvent::ChallengeIssued { client_has_js: true });

		// A clone shares the same buffer, so it sees the first event and can add a second.
		let clone = sink.clone();
		clone.record(&SecurityEvent::ChallengePassed { level: ClearanceLevel::Pow });

		let events = sink.events();
		assert_eq!(events.len(), 2);
		assert_eq!(sink.len(), 2);
		assert!(!sink.is_empty());
		assert_eq!(events[0], SecurityEvent::ChallengeIssued { client_has_js: true });
		assert_eq!(events[1], SecurityEvent::ChallengePassed { level: ClearanceLevel::Pow });
	}

	#[test]
	fn tracing_sink_records_without_panicking() {
		// No tracing subscriber is installed in unit tests, so this just confirms the sink
		// builds the event and emits at the right level without panicking.
		let sink = TracingSink;
		sink.record(&SecurityEvent::RateLimited { token: TokenId("abc".to_owned()) });
		sink.record(&SecurityEvent::Circuit { id: CircuitId(1), action: CircuitAction::Shutdown });
	}

	#[test]
	fn metrics_sink_tallies_per_variant() {
		let sink = MetricsSink::new();
		assert_eq!(sink.snapshot(), SecurityMetrics::default());

		sink.record(&SecurityEvent::WafBlock { rule_id: "x", category: WafCategory::Sqli, location: "query".to_owned() });
		sink.record(&SecurityEvent::WafBlock { rule_id: "y", category: WafCategory::Xss, location: "body".to_owned() });
		sink.record(&SecurityEvent::ChallengeIssued { client_has_js: true });
		sink.record(&SecurityEvent::ChallengePassed { level: ClearanceLevel::Pow });
		sink.record(&SecurityEvent::ChallengePassed { level: ClearanceLevel::Patience });
		sink.record(&SecurityEvent::ChallengeFailed);
		sink.record(&SecurityEvent::ChallengeUnavailable);
		sink.record(&SecurityEvent::RateLimited { token: TokenId("t".to_owned()) });
		sink.record(&SecurityEvent::Circuit { id: CircuitId(1), action: CircuitAction::Shutdown });

		let m = sink.snapshot();
		assert_eq!(m.waf_blocks, 2);
		assert_eq!(m.rate_limited, 1);
		assert_eq!(m.challenges_issued, 1);
		assert_eq!(m.challenges_passed, 2);
		assert_eq!(m.challenges_failed, 1);
		assert_eq!(m.challenges_unavailable, 1);
		assert_eq!(m.circuit_actions, 1);
		// The two WAF blocks split one Sqli + one Xss.
		assert_eq!(m.waf_blocks_in(WafCategory::Sqli), 1);
		assert_eq!(m.waf_blocks_in(WafCategory::Xss), 1);
		assert_eq!(m.waf_blocks_in(WafCategory::PathTraversal), 0);
	}

	#[test]
	fn waf_category_index_round_trips_and_breakdown_sums_to_total() {
		// The index is a stable bijection over ALL, so array-backed counters are correct.
		for cat in WafCategory::ALL {
			assert_eq!(WafCategory::ALL[cat.index()], cat);
		}

		let sink = MetricsSink::new();
		for _ in 0..3 {
			sink.record(&SecurityEvent::WafBlock { rule_id: "p", category: WafCategory::PathTraversal, location: "target".to_owned() });
		}
		sink.record(&SecurityEvent::WafBlock { rule_id: "s", category: WafCategory::Sqli, location: "query".to_owned() });
		let m = sink.snapshot();
		assert_eq!(m.waf_blocks_in(WafCategory::PathTraversal), 3);
		assert_eq!(m.waf_blocks_in(WafCategory::Sqli), 1);
		// The per-category breakdown sums to the all-categories total.
		assert_eq!(m.waf_blocks_by_category.iter().sum::<u64>(), m.waf_blocks);
	}

	#[test]
	fn metrics_clones_share_counters() {
		let sink = MetricsSink::new();
		let reader = sink.clone();
		sink.record(&SecurityEvent::ChallengeFailed);
		assert_eq!(reader.snapshot().challenges_failed, 1);
	}

	#[test]
	fn challenge_pass_ratio_is_none_until_decided_then_correct() {
		let sink = MetricsSink::new();
		// No submissions decided yet: ratio is undefined, not a misleading 0%.
		assert_eq!(sink.snapshot().challenge_pass_ratio(), None);

		// 3 passed, 1 failed → 0.75. (Issued/unavailable do not move the ratio.)
		sink.record(&SecurityEvent::ChallengeIssued { client_has_js: true });
		for _ in 0..3 {
			sink.record(&SecurityEvent::ChallengePassed { level: ClearanceLevel::Pow });
		}
		sink.record(&SecurityEvent::ChallengeFailed);
		assert_eq!(sink.snapshot().challenge_pass_ratio(), Some(0.75));
	}

	#[test]
	fn fanout_forwards_to_every_sink() {
		// A fanout over a metrics sink and a capturing sink feeds both from one event.
		let metrics = MetricsSink::new();
		let captured = CapturingSink::new();
		let fan = FanoutSink::new(vec![Arc::new(metrics.clone()), Arc::new(captured.clone())]);

		fan.record(&SecurityEvent::ChallengeFailed);
		fan.record(&SecurityEvent::WafBlock { rule_id: "z", category: WafCategory::CommandInjection, location: "query".to_owned() });

		assert_eq!(metrics.snapshot().challenges_failed, 1);
		assert_eq!(metrics.snapshot().waf_blocks, 1);
		assert_eq!(captured.len(), 2);
	}
}

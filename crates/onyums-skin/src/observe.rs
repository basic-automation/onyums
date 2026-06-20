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

use std::sync::{Arc, Mutex};

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
}

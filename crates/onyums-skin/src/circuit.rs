//! The Tor dimension: per-rendezvous-circuit accounting and policy.
//!
//! A normal axum app cannot express this; onyums calls [`CircuitPolicy`] from its
//! `RendRequest` / `StreamRequest` loop, supplying a host-assigned [`CircuitId`] and
//! the requested [`StreamTarget`]. This generalizes the one-off port-443/80 gate that
//! currently lives in onyums' `handle_stream_request`. See `ROADMAP.md`.

use std::{collections::HashMap, sync::Mutex};

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
}

/// Cumulative running totals for one rendezvous circuit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CircuitStats {
	/// Streams opened on this circuit so far.
	pub streams: u64,
	/// Requests seen on this circuit so far.
	pub requests: u64,
}

/// A concrete [`CircuitPolicy`] that does per-circuit accounting and enforces
/// simple abuse circuit-breakers.
///
/// It keeps cumulative [`CircuitStats`] per [`CircuitId`] and can:
/// - force every new circuit through the app-layer gate ("Under Attack Mode"),
/// - tear down (`Shutdown`) a circuit that opens more than `max_streams` streams —
///   a circuit fanning out streams is a classic abuse pattern, torn down wholesale,
/// - reject (`Reject`) requests on a circuit past `max_requests`.
///
/// All caps are opt-in; with none set the policy is accept-all and serves purely
/// as the accounting substrate (the [`stats`](Self::stats) the host reads for
/// observability and adaptive difficulty). Time-windowed *rate* limiting builds on
/// this accounting in a later slice; token-keyed rate limiting already lives in
/// [`SkinRateLimit`](crate::ratelimit::SkinRateLimit).
///
/// The host should call [`forget`](Self::forget) when a circuit is torn down so the
/// accounting map does not grow without bound (there is no stream-close hook).
pub struct AccountingCircuitPolicy {
	inner: Mutex<HashMap<CircuitId, CircuitStats>>,
	max_streams: Option<u64>,
	max_requests: Option<u64>,
	under_attack: bool,
}

impl AccountingCircuitPolicy {
	/// An accept-all accounting policy with no caps and Under Attack Mode off.
	#[must_use]
	pub fn new() -> Self {
		Self { inner: Mutex::new(HashMap::new()), max_streams: None, max_requests: None, under_attack: false }
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

	/// Under Attack Mode: force every new circuit through the challenge gate.
	#[must_use]
	pub const fn under_attack(mut self, on: bool) -> Self {
		self.under_attack = on;
		self
	}

	/// The current accounting for a circuit, if it is known.
	#[must_use]
	pub fn stats(&self, id: &CircuitId) -> Option<CircuitStats> {
		self.lock().get(id).copied()
	}

	/// Drop a circuit's accounting (call when the host tears the circuit down).
	pub fn forget(&self, id: &CircuitId) {
		self.lock().remove(id);
	}

	/// Lock the accounting map, recovering from a poisoned mutex (the only thing
	/// done under the lock is map bookkeeping, so poisoning carries no broken
	/// invariant).
	fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<CircuitId, CircuitStats>> {
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
		if self.under_attack {
			CircuitAction::Challenge
		} else {
			CircuitAction::Accept
		}
	}

	fn on_new_stream(&self, id: &CircuitId, _target: &StreamTarget) -> CircuitAction {
		let mut map = self.lock();
		let stats = map.entry(*id).or_default();
		stats.streams += 1;
		if self.max_streams.is_some_and(|max| stats.streams > max) {
			return CircuitAction::Shutdown;
		}
		CircuitAction::Accept
	}

	fn on_request(&self, id: &CircuitId) -> CircuitAction {
		let mut map = self.lock();
		let stats = map.entry(*id).or_default();
		stats.requests += 1;
		if self.max_requests.is_some_and(|max| stats.requests > max) {
			return CircuitAction::Reject;
		}
		CircuitAction::Accept
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
		assert_eq!(policy.stats(&C1), Some(CircuitStats { streams: 1, requests: 2 }));
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
		assert_eq!(policy.stats(&C1), Some(CircuitStats { streams: 1, requests: 0 }));
		assert_eq!(policy.stats(&C2), Some(CircuitStats { streams: 0, requests: 1 }));
	}

	#[test]
	fn forget_clears_circuit_state() {
		let policy = AccountingCircuitPolicy::new();
		policy.on_request(&C1);
		assert!(policy.stats(&C1).is_some());
		policy.forget(&C1);
		assert_eq!(policy.stats(&C1), None);
	}
}

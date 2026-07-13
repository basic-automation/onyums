//! Per-connection identity threaded to the application (onyums ROADMAP Phase 4 —
//! circuit-isolation controls).
//!
//! [`ConnectionInfo`] is onyums' axum connect-info type: over Tor there is no client IP,
//! so the meaningful identity is the per-rendezvous-circuit id. Extracted from `lib.rs`
//! as a slice of the Phase 0 module split.

use std::net::SocketAddr;

use axum::extract::connect_info::Connected as AxumConnected;
use hyper::{body::Incoming, Request};

/// Per-connection identity threaded to the application via axum's connect-info
/// extractor.
///
/// Over Tor there is no client IP, so [`socket_addr`](Self::socket_addr) is always
/// `None`; the meaningful identity is [`circuit_id`](Self::circuit_id) — the host-assigned
/// id of the rendezvous circuit the request arrived on. Two requests sharing a
/// `circuit_id` came over the same circuit (the closest Tor analogue to "same client
/// connection"), which is the handle for per-circuit isolation of application state. Use
/// the typed helpers ([`is_over_tor`](Self::is_over_tor), [`circuit`](Self::circuit),
/// [`same_circuit`](Self::same_circuit)) rather than matching on the raw fields.
#[derive(Clone, Debug, Default)]
pub struct ConnectionInfo {
	pub circuit_id: Option<String>,
	pub socket_addr: Option<SocketAddr>,
}

impl ConnectionInfo {
	/// Whether this connection arrived over a Tor rendezvous circuit — i.e. a
	/// [`circuit_id`](Self::circuit_id) is known. Always true for onion-served requests;
	/// `false` only for a default/synthetic `ConnectionInfo` (e.g. a request-level test).
	#[must_use]
	pub const fn is_over_tor(&self) -> bool {
		self.circuit_id.is_some()
	}

	/// The per-rendezvous-circuit identifier, if known — the key for isolating
	/// application state per Tor circuit.
	#[must_use]
	pub fn circuit(&self) -> Option<&str> {
		self.circuit_id.as_deref()
	}

	/// Whether `self` and `other` came over the *same* known rendezvous circuit.
	///
	/// Returns `false` if either side's circuit is unknown — an unknown circuit is never
	/// treated as matching, so this is safe to gate circuit-isolation decisions on.
	#[must_use]
	pub fn same_circuit(&self, other: &Self) -> bool {
		matches!((self.circuit(), other.circuit()), (Some(a), Some(b)) if a == b)
	}
}

impl AxumConnected<Request<Incoming>> for ConnectionInfo {
	fn connect_info(target: Request<Incoming>) -> Self {
		// onyums' serve path injects the per-connection `ConnectionInfo` as a request
		// extension; if it is somehow absent, fall back to an empty (non-Tor) info rather
		// than panicking the connection task.
		target.extensions().get::<Self>().cloned().unwrap_or_default()
	}
}

impl AxumConnected<Self> for ConnectionInfo {
	fn connect_info(target: Self) -> Self {
		target
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn connection_info_circuit_isolation_helpers() {
		let a = ConnectionInfo { circuit_id: Some("7".into()), socket_addr: None };
		let a_again = ConnectionInfo { circuit_id: Some("7".into()), socket_addr: None };
		let b = ConnectionInfo { circuit_id: Some("9".into()), socket_addr: None };
		let unknown = ConnectionInfo::default();

		assert!(a.is_over_tor(), "a known circuit id means the request came over Tor");
		assert!(!unknown.is_over_tor(), "a default info is not over Tor");
		assert_eq!(a.circuit(), Some("7"));
		assert_eq!(unknown.circuit(), None);

		assert!(a.same_circuit(&a_again), "the same circuit id is the same circuit");
		assert!(!a.same_circuit(&b), "different circuit ids are different circuits");
		assert!(!a.same_circuit(&unknown), "a known circuit never matches an unknown one");
		assert!(!unknown.same_circuit(&unknown), "two unknown circuits are not a known-same circuit");
	}
}

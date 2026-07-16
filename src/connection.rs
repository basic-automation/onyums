//! Per-connection identity threaded to the application (onyums ROADMAP Phase 4 —
//! circuit-isolation controls).
//!
//! [`ConnectionInfo`] is onyums' axum connect-info type: over Tor there is no client IP,
//! so the meaningful identity is the per-rendezvous-circuit id. Extracted from `lib.rs`
//! as a slice of the Phase 0 module split.

use std::net::SocketAddr;

use axum::extract::connect_info::Connected as AxumConnected;
use hyper::{Request, body::Incoming};

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
///
/// # A circuit id is not an identity
///
/// It is tempting to reach for this as "the user", because it is the only per-client
/// thing Tor leaves you. Do not. The id is **synthetic and short-lived**: onyums mints it
/// per rendezvous circuit (arti exposes no durable circuit identifier), it is forgotten
/// when the circuit's streams drain, and a client can open a new circuit whenever it
/// likes — an attacker most of all. Concretely:
///
/// - **It is not stable for a user.** The same person gets a new id on reconnect, and
///   nothing links the two. Session state keyed on it silently evaporates.
/// - **It is not a limit.** Anything you ration per circuit — a rate limit, a ban, a
///   quota — is rotated around by opening another circuit. It raises cost; it does not
///   deny.
/// - **It is not authentication.** It says two requests shared a circuit, nothing about
///   *who* is on the other end.
///
/// So use it for what it is: isolating per-connection state (a scratch buffer, a
/// per-connection cache) and cheap correlation within one circuit's lifetime. Anything
/// that must outlive a circuit or resist an adversary belongs on something durable — a
/// Skin clearance token (signed, and what Skin's own rate limiting keys on), a
/// restricted-discovery client key, or your application's own session/auth.
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

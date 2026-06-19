//! Pure host-side glue between onyums' rendezvous loop and onyums-skin's
//! [`CircuitPolicy`](onyums_skin::CircuitPolicy).
//!
//! Arti 0.43 surfaces no circuit identifier at the `StreamRequest` layer — the
//! circuit is held privately (`tor_hsservice`'s `StreamRequest` carries it as a private
//! `Arc`, with a literal `// TODO ... accessors ... for circuit`). The only place the
//! per-circuit boundary is visible is one level up, at `RendRequest`: each is exactly
//! one rendezvous circuit, and `RendRequest::accept()` yields *that circuit's* streams.
//! So onyums mints its own [`CircuitId`](onyums_skin::CircuitId) per `RendRequest`.
//!
//! The `RendRequest` / `StreamRequest` types cannot be constructed outside arti, so the
//! loop that drives them is only exercised by the live `test_serve`. This module factors
//! the *decisions* out of that loop into pure functions and a synthetic id allocator, so
//! the policy translation is unit-testable with no live Tor network.

use std::sync::atomic::{AtomicU64, Ordering};

use onyums_skin::{CircuitAction, CircuitId, StreamTarget};

/// Allocates monotonic, process-unique [`CircuitId`]s — one per offered rendezvous
/// circuit, minted at the `RendRequest` boundary (see the module docs for why the id is
/// host-assigned rather than read from arti).
#[derive(Debug, Default)]
pub struct CircuitIdAllocator(AtomicU64);

impl CircuitIdAllocator {
	/// A fresh allocator starting at id `0`.
	#[must_use]
	pub const fn new() -> Self {
		Self(AtomicU64::new(0))
	}

	/// The next unique circuit id. Named `next_id` (not `next`) so it is not mistaken
	/// for an [`Iterator`] method.
	#[must_use]
	pub fn next_id(&self) -> CircuitId {
		CircuitId(self.0.fetch_add(1, Ordering::Relaxed))
	}
}

/// What the rendezvous loop should do with a freshly offered circuit, after consulting
/// [`CircuitPolicy::on_new_circuit`](onyums_skin::CircuitPolicy::on_new_circuit).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitDisposition {
	/// Accept the circuit and serve its streams. `Challenge` lands here too: the
	/// per-circuit layer has no challenge surface of its own, so a challenged circuit is
	/// accepted and the HTTP Skin gate presents the challenge per request.
	Accept,
	/// Do not accept the circuit; dropping the `RendRequest` tears it down before any
	/// stream is served.
	Drop,
}

/// Map a circuit-level [`CircuitAction`] to a [`CircuitDisposition`]. `Reject` and
/// `Shutdown` both mean "don't accept this circuit" — at the `RendRequest` stage there
/// is no distinction, since not accepting it tears it down.
#[must_use]
pub const fn circuit_disposition(action: CircuitAction) -> CircuitDisposition {
	match action {
		CircuitAction::Accept | CircuitAction::Challenge => CircuitDisposition::Accept,
		CircuitAction::Reject | CircuitAction::Shutdown => CircuitDisposition::Drop,
	}
}

/// What the loop should do with a single stream on an accepted circuit, after consulting
/// [`CircuitPolicy::on_new_stream`](onyums_skin::CircuitPolicy::on_new_stream).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamDisposition {
	/// Serve the stream (`Accept`/`Challenge` — the HTTP gate handles `Challenge`).
	Serve,
	/// Reject this stream but keep the circuit (and its other streams) alive.
	Reject,
	/// Tear down the whole rendezvous circuit (arti `shutdown_circuit()`).
	Shutdown,
}

/// Map a stream-level [`CircuitAction`] to a [`StreamDisposition`]. Unlike the
/// circuit-level mapping, `Reject` (drop this one stream) and `Shutdown` (tear down the
/// whole circuit) are distinct here.
#[must_use]
pub const fn stream_disposition(action: CircuitAction) -> StreamDisposition {
	match action {
		CircuitAction::Accept | CircuitAction::Challenge => StreamDisposition::Serve,
		CircuitAction::Reject => StreamDisposition::Reject,
		CircuitAction::Shutdown => StreamDisposition::Shutdown,
	}
}

/// Build skin's [`StreamTarget`] from a BEGIN cell's port. Onion-service BEGIN cells are
/// gated on port (443 TLS / 80 → HTTPS redirect); the host is not consulted by current
/// policy, so it is left `None`.
#[must_use]
pub const fn stream_target(port: u16) -> StreamTarget {
	StreamTarget { port, host: None }
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn allocator_yields_unique_monotonic_ids() {
		let alloc = CircuitIdAllocator::new();
		let ids: Vec<u64> = (0..5).map(|_| alloc.next_id().0).collect();
		assert_eq!(ids, vec![0, 1, 2, 3, 4]);
	}

	#[test]
	fn allocator_is_shareable_across_threads() {
		use std::sync::Arc;
		let alloc = Arc::new(CircuitIdAllocator::new());
		let mut handles = Vec::new();
		for _ in 0..8 {
			let a = alloc.clone();
			handles.push(std::thread::spawn(move || a.next_id().0));
		}
		let mut ids: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
		ids.sort_unstable();
		// 8 threads, each one id, all distinct.
		ids.dedup();
		assert_eq!(ids.len(), 8);
	}

	#[test]
	fn circuit_disposition_accepts_servable_actions() {
		assert_eq!(circuit_disposition(CircuitAction::Accept), CircuitDisposition::Accept);
		assert_eq!(circuit_disposition(CircuitAction::Challenge), CircuitDisposition::Accept);
		assert_eq!(circuit_disposition(CircuitAction::Reject), CircuitDisposition::Drop);
		assert_eq!(circuit_disposition(CircuitAction::Shutdown), CircuitDisposition::Drop);
	}

	#[test]
	fn stream_disposition_distinguishes_reject_from_shutdown() {
		assert_eq!(stream_disposition(CircuitAction::Accept), StreamDisposition::Serve);
		assert_eq!(stream_disposition(CircuitAction::Challenge), StreamDisposition::Serve);
		assert_eq!(stream_disposition(CircuitAction::Reject), StreamDisposition::Reject);
		assert_eq!(stream_disposition(CircuitAction::Shutdown), StreamDisposition::Shutdown);
	}

	#[test]
	fn stream_target_carries_the_port() {
		let t = stream_target(443);
		assert_eq!(t.port, 443);
		assert!(t.host.is_none());
	}
}

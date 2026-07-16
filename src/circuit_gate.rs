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
//! loop that drives them is only exercised by the `--ignored` live-Tor test tier
//! (`live_service_serves_over_the_tor_network_and_shuts_down`). This module factors
//! the *decisions* out of that loop into pure functions and a synthetic id allocator, so
//! the policy translation is unit-testable with no live Tor network.

use std::sync::atomic::{AtomicU64, Ordering};

use onyums_skin::{CircuitAction, CircuitId, StreamTarget};
use tor_proto::stream::IncomingStreamRequest;

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
	/// Serve the stream (`Accept`, or `Challenge` on a reserved HTTP port where the gate
	/// can render the challenge).
	Serve,
	/// Reject this stream but keep the circuit (and its other streams) alive.
	Reject,
	/// Tear down the whole rendezvous circuit (arti `shutdown_circuit()`).
	Shutdown,
}

/// Map a stream-level [`CircuitAction`] to a [`StreamDisposition`], given the stream's
/// destination `port`. Unlike the circuit-level mapping, `Reject` (drop this one stream)
/// and `Shutdown` (tear down the whole circuit) are distinct here.
///
/// `Challenge` is port-sensitive: the challenge is presented by the HTTP Skin gate, which
/// only runs on the reserved HTTP ports (80/443). On a raw port there is no challenge
/// surface, so a `Challenge` **fails closed** to [`Reject`](StreamDisposition::Reject)
/// rather than silently serving the stream ungated — the raw handler never implements the
/// challenge itself (onyums ROADMAP: fix Under-Attack `Challenge` for raw TCP).
#[must_use]
pub const fn stream_disposition(action: CircuitAction, port: u16) -> StreamDisposition {
	match action {
		CircuitAction::Accept => StreamDisposition::Serve,
		CircuitAction::Challenge => {
			if crate::port_router::is_reserved_http_port(port) {
				StreamDisposition::Serve
			} else {
				StreamDisposition::Reject
			}
		}
		CircuitAction::Reject => StreamDisposition::Reject,
		CircuitAction::Shutdown => StreamDisposition::Shutdown,
	}
}

/// The port a client's incoming stream request asks for.
///
/// A `BEGIN` cell carries the target port, and that port is what the whole downstream
/// gate keys on ([`stream_target`] → [`stream_disposition`] → the port dispatch). Every
/// *other* request kind — `BEGIN_DIR` (a directory fetch, meaningless for an onion
/// service) and `RESOLVE` (a DNS lookup, which an onion service has no business
/// answering) — maps to port `0`, which no handler may register and which is not a
/// reserved HTTP port, so it is refused downstream. That mapping is a security decision,
/// not a formality: it is what makes an unexpected request kind fail closed instead of
/// being served by whatever happens to sit on the port it decodes to.
///
/// Lives here rather than inline in the loop because it *is* a decision, and this module
/// exists to hold the loop's decisions where they can be tested (see the module docs).
/// `IncomingStreamRequest` is `#[non_exhaustive]`-shaped from onyums' side, so an
/// unknown future kind lands in the same fail-closed arm.
#[must_use]
pub fn requested_port(request: &IncomingStreamRequest) -> u16 {
	match request {
		IncomingStreamRequest::Begin(begin) => begin.port(),
		_ => 0,
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
	fn requested_port_reads_the_begin_cells_port() {
		// A BEGIN cell is the only request kind an onion-service client should send, and
		// its port is what the entire downstream gate keys on. Constructible offline —
		// `Begin::new` is public — so unlike the loop that consumes it, this decision is
		// testable without live Tor.
		for port in [443, 80, 22, 9735, 65535] {
			let begin = tor_cell::relaycell::msg::Begin::new("example.onion", port, 0).expect("a valid BEGIN cell");
			assert_eq!(requested_port(&IncomingStreamRequest::Begin(begin)), port);
		}
	}

	#[test]
	fn a_non_begin_request_fails_closed_on_port_zero() {
		// BEGIN_DIR (a directory fetch) and RESOLVE (a DNS lookup) are meaningless for an
		// onion service. Mapping them to port 0 is what makes them fail closed: 0 can never
		// be registered as a raw port (`PortRouter::register` rejects it) and is not a
		// reserved HTTP port, so the dispatch refuses them rather than serving them off
		// whatever port they might otherwise decode to.
		let begin_dir = IncomingStreamRequest::BeginDir(tor_cell::relaycell::msg::BeginDir::default());
		assert_eq!(requested_port(&begin_dir), 0, "BEGIN_DIR must not resolve to a servable port");
		assert!(!crate::port_router::is_reserved_http_port(requested_port(&begin_dir)), "port 0 is not a reserved HTTP port, so it is refused");
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
		// On a reserved HTTP port (443) the gate can render a challenge, so Challenge serves.
		assert_eq!(stream_disposition(CircuitAction::Accept, 443), StreamDisposition::Serve);
		assert_eq!(stream_disposition(CircuitAction::Challenge, 443), StreamDisposition::Serve);
		assert_eq!(stream_disposition(CircuitAction::Reject, 443), StreamDisposition::Reject);
		assert_eq!(stream_disposition(CircuitAction::Shutdown, 443), StreamDisposition::Shutdown);
	}

	#[test]
	fn challenge_fails_closed_on_a_raw_port() {
		// A raw (non-80/443) port has no HTTP challenge surface, so Challenge must fail
		// closed to Reject rather than serve the stream ungated.
		assert_eq!(stream_disposition(CircuitAction::Challenge, 9000), StreamDisposition::Reject);
		assert_eq!(stream_disposition(CircuitAction::Challenge, 22), StreamDisposition::Reject);
		assert_eq!(stream_disposition(CircuitAction::Challenge, 0), StreamDisposition::Reject);
		// Both reserved HTTP ports still serve a challenge (the gate presents it there).
		assert_eq!(stream_disposition(CircuitAction::Challenge, 80), StreamDisposition::Serve);
		assert_eq!(stream_disposition(CircuitAction::Challenge, 443), StreamDisposition::Serve);
		// The non-Challenge actions are port-independent — Accept serves, Reject rejects,
		// Shutdown tears down, on HTTP and raw ports alike.
		for port in [80u16, 443, 9000, 0] {
			assert_eq!(stream_disposition(CircuitAction::Accept, port), StreamDisposition::Serve);
			assert_eq!(stream_disposition(CircuitAction::Reject, port), StreamDisposition::Reject);
			assert_eq!(stream_disposition(CircuitAction::Shutdown, port), StreamDisposition::Shutdown);
		}
	}

	#[test]
	fn stream_target_carries_the_port() {
		let t = stream_target(443);
		assert_eq!(t.port, 443);
		assert!(t.host.is_none());
	}
}

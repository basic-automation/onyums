//! A concurrency cap for a raw port (onyums ROADMAP Phase 2 — raw-port security
//! controls).
//!
//! [`ConnectionLimit`] wraps any [`StreamHandler`] and refuses a stream once the port
//! already has `max` connections in flight. It is the enforcement half of the raw-port
//! story whose reporting half is [`PortRouter::exposures`](crate::PortRouter::exposures):
//! a raw port bypasses the Skin gate entirely, so without a cap the only thing bounding
//! concurrent connections to your SSH or Postgres backend is how fast an attacker can
//! open rendezvous circuits.
//!
//! ```rust
//! use onyums::{ConnectionLimit, OnionService, RawTcpHandler, routing::get, Router};
//!
//! # fn f() -> anyhow::Result<()> {
//! let ssh = ConnectionLimit::new(RawTcpHandler::new("127.0.0.1:22"), 4)?;
//! let builder = OnionService::builder()
//!     .router(Router::new().route("/", get(|| async { "hi" })))
//!     .nickname("my_onion")
//!     .route_port(2222, ssh); // at most 4 concurrent SSH connections
//! # Ok(())
//! # }
//! ```
//!
//! **Reject, don't queue.** At capacity a stream is closed immediately rather than
//! parked waiting for a permit. Queueing would convert a connection flood into unbounded
//! memory growth and a latency cliff for the clients already connected — the failure mode
//! a limit exists to prevent. A client that is refused can retry; one stuck in an
//! invisible queue cannot tell the difference between slow and dead.

use std::sync::Arc;

use anyhow::{Result, bail};
use tokio::sync::Semaphore;
use tracing::{Level, event};

use crate::port_router::{OnionStream, ServeFuture, StreamHandler};

/// Caps how many connections a raw port serves at once, refusing the rest.
///
/// Wraps any [`StreamHandler`] — including [`RawTcpHandler`](crate::RawTcpHandler) — and
/// is itself a `StreamHandler`, so it goes straight into
/// [`route_port`](crate::OnionServiceBuilder::route_port).
///
/// The cap is per `ConnectionLimit`, not global: wrap each port in its own to give each
/// backend its own budget (an admin port and a game server rarely deserve the same
/// number).
pub struct ConnectionLimit<H> {
	inner: Arc<H>,
	permits: Arc<Semaphore>,
	max: usize,
}

impl<H> ConnectionLimit<H> {
	/// Cap `inner` at `max` concurrent connections.
	///
	/// # Errors
	/// Returns an error if `max` is `0`, which would refuse every connection and make the
	/// port pointless — far more likely a bug (an unwrapped config value, an arithmetic
	/// slip) than an intent. Rejected here, offline, rather than becoming a port that
	/// silently accepts nothing in production.
	pub fn new(inner: H, max: usize) -> Result<Self> {
		if max == 0 {
			bail!("a connection limit of 0 would refuse every connection; use at least 1, or don't register the port");
		}
		Ok(Self { inner: Arc::new(inner), permits: Arc::new(Semaphore::new(max)), max })
	}

	/// The configured cap.
	#[must_use]
	pub const fn max(&self) -> usize {
		self.max
	}

	/// How many connections are being served right now.
	///
	/// A snapshot for a health endpoint or a log line; it can change the moment it is
	/// read, so treat it as an observation rather than a value to branch on.
	#[must_use]
	pub fn in_flight(&self) -> usize {
		self.max - self.permits.available_permits()
	}

	/// Whether the port is at capacity right now — the next stream would be refused.
	#[must_use]
	pub fn is_saturated(&self) -> bool {
		self.permits.available_permits() == 0
	}
}

impl<H: StreamHandler + 'static> StreamHandler for ConnectionLimit<H> {
	fn serve(&self, stream: OnionStream) -> ServeFuture {
		let permits = Arc::clone(&self.permits);
		let inner = Arc::clone(&self.inner);
		let max = self.max;
		Box::pin(async move {
			// `try_acquire_owned`, not `acquire_owned`: at capacity we refuse rather than
			// queue (see the module docs).
			let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
				// Dropping the stream closes it, which is the refusal the peer observes.
				// Explicit rather than incidental, since this is the security-relevant act.
				drop(stream);
				event!(Level::WARN, "Refused a raw-port connection: already serving the configured maximum of {max} concurrent connection(s).");
				bail!("connection limit reached: {max} concurrent connection(s) already in flight");
			};
			let result = inner.serve(stream).await;
			// Held across the whole connection, so the permit returns however the
			// connection ended — including on an error from the inner handler.
			drop(permit);
			result
		})
	}
}

#[cfg(test)]
mod tests {
	use std::{
		sync::atomic::{AtomicUsize, Ordering}, time::Duration
	};

	use tokio::sync::oneshot;

	use super::*;

	/// A handler that parks until released, so a test can hold connections "in flight"
	/// deterministically rather than racing a sleep.
	struct ParkingHandler {
		started: Arc<AtomicUsize>,
		release: Arc<tokio::sync::Notify>,
	}

	impl StreamHandler for ParkingHandler {
		fn serve(&self, stream: OnionStream) -> ServeFuture {
			let started = Arc::clone(&self.started);
			let release = Arc::clone(&self.release);
			Box::pin(async move {
				started.fetch_add(1, Ordering::SeqCst);
				release.notified().await;
				drop(stream);
				Ok(())
			})
		}
	}

	/// A stream to hand a handler: an in-memory duplex pair stands in for an accepted
	/// onion stream, so none of this needs Tor.
	fn stream() -> OnionStream {
		let (a, _b) = tokio::io::duplex(64);
		Box::pin(a)
	}

	fn parking() -> (ConnectionLimit<ParkingHandler>, Arc<AtomicUsize>, Arc<tokio::sync::Notify>) {
		let started = Arc::new(AtomicUsize::new(0));
		let release = Arc::new(tokio::sync::Notify::new());
		let handler = ParkingHandler { started: Arc::clone(&started), release: Arc::clone(&release) };
		(ConnectionLimit::new(handler, 2).expect("limit of 2"), started, release)
	}

	#[test]
	fn a_zero_limit_is_rejected_offline() {
		// A port that accepts nothing is a bug, and this is caught at construction —
		// before any Tor launch — rather than becoming a silently dead port.
		let err = ConnectionLimit::new(RejectAll, 0).err().expect("0 must be rejected");
		assert!(err.to_string().contains("refuse every connection"), "unexpected error: {err}");
		assert!(ConnectionLimit::new(RejectAll, 1).is_ok(), "1 is the smallest useful limit");
	}

	struct RejectAll;
	impl StreamHandler for RejectAll {
		fn serve(&self, _stream: OnionStream) -> ServeFuture {
			Box::pin(async { Ok(()) })
		}
	}

	#[tokio::test]
	async fn connections_under_the_limit_are_served() {
		let (limit, started, release) = parking();
		let limit = Arc::new(limit);
		assert_eq!(limit.in_flight(), 0);
		assert!(!limit.is_saturated());

		let a = tokio::spawn({
			let l = Arc::clone(&limit);
			async move { l.serve(stream()).await }
		});
		// Wait for the connection to actually be in the handler, rather than sleeping.
		while started.load(Ordering::SeqCst) < 1 {
			tokio::task::yield_now().await;
		}
		assert_eq!(limit.in_flight(), 1, "one permit is taken while the connection runs");
		assert!(!limit.is_saturated(), "the cap is 2");

		release.notify_waiters();
		a.await.expect("task").expect("the served connection succeeds");
	}

	#[tokio::test]
	async fn a_connection_over_the_limit_is_refused_not_queued() {
		// The point of the whole type: at capacity the extra stream is closed *now*, and
		// the refusal is an error the loop can log — it does not sit in a queue growing
		// memory while the peer waits.
		let (limit, started, release) = parking();
		let limit = Arc::new(limit);

		let mut held = Vec::new();
		for _ in 0..2 {
			let l = Arc::clone(&limit);
			held.push(tokio::spawn(async move { l.serve(stream()).await }));
		}
		while started.load(Ordering::SeqCst) < 2 {
			tokio::task::yield_now().await;
		}
		assert!(limit.is_saturated(), "both permits are taken");

		// The third connection must be refused promptly, not parked. If it queued, this
		// would hang until the timeout rather than return.
		let refused = tokio::time::timeout(Duration::from_secs(5), limit.serve(stream())).await.expect("a refusal must not block on a permit");
		let err = refused.expect_err("the third concurrent connection must be refused");
		assert!(err.to_string().contains("connection limit reached"), "unexpected error: {err}");
		assert_eq!(started.load(Ordering::SeqCst), 2, "the refused stream must never reach the inner handler");

		release.notify_waiters();
		for h in held {
			h.await.expect("task").expect("held connection");
		}
	}

	#[tokio::test]
	async fn a_finished_connection_returns_its_permit() {
		// Without this the port would degrade to permanently refusing everything after
		// `max` lifetime connections — a limiter that becomes a denial of service.
		let (limit, started, release) = parking();
		let limit = Arc::new(limit);

		let mut held = Vec::new();
		for _ in 0..2 {
			let l = Arc::clone(&limit);
			held.push(tokio::spawn(async move { l.serve(stream()).await }));
		}
		while started.load(Ordering::SeqCst) < 2 {
			tokio::task::yield_now().await;
		}
		assert!(limit.is_saturated());

		release.notify_waiters();
		for h in held {
			h.await.expect("task").expect("held connection");
		}

		assert_eq!(limit.in_flight(), 0, "permits return once connections finish");
		assert!(!limit.is_saturated(), "the port accepts again");
		// And a fresh connection is genuinely served, not refused.
		let l = Arc::clone(&limit);
		let next = tokio::spawn(async move { l.serve(stream()).await });
		while started.load(Ordering::SeqCst) < 3 {
			tokio::task::yield_now().await;
		}
		release.notify_waiters();
		next.await.expect("task").expect("a connection after the flush is served");
	}

	#[tokio::test]
	async fn a_permit_returns_even_when_the_inner_handler_errors() {
		// The realistic failure — the backend is down, so every connection errors. If the
		// permit leaked on that path the port would wedge shut after `max` failures, which
		// is exactly when you least want it to.
		struct AlwaysErrs;
		impl StreamHandler for AlwaysErrs {
			fn serve(&self, _stream: OnionStream) -> ServeFuture {
				Box::pin(async { anyhow::bail!("backend unreachable") })
			}
		}

		let limit = ConnectionLimit::new(AlwaysErrs, 1).expect("limit");
		for _ in 0..3 {
			let err = limit.serve(stream()).await.expect_err("the inner handler errors");
			assert!(err.to_string().contains("backend unreachable"), "the inner error must propagate: {err}");
			assert_eq!(limit.in_flight(), 0, "the permit must return after an inner error");
		}
	}

	#[tokio::test]
	async fn the_refusal_is_reported_as_an_error_the_loop_can_log() {
		// The rendezvous loop logs a handler's Err; a silent refusal would make a port at
		// capacity indistinguishable from a port with a broken backend.
		struct Parker(std::sync::Mutex<Option<oneshot::Receiver<()>>>);
		impl StreamHandler for Parker {
			fn serve(&self, _stream: OnionStream) -> ServeFuture {
				let rx = self.0.lock().unwrap().take();
				Box::pin(async move {
					if let Some(rx) = rx {
						let _ = rx.await;
					}
					Ok(())
				})
			}
		}

		let (tx, rx) = oneshot::channel::<()>();
		let limit = Arc::new(ConnectionLimit::new(Parker(std::sync::Mutex::new(Some(rx))), 1).expect("limit"));
		let l = Arc::clone(&limit);
		let held = tokio::spawn(async move { l.serve(stream()).await });
		while !limit.is_saturated() {
			tokio::task::yield_now().await;
		}

		let err = limit.serve(stream()).await.expect_err("refused");
		assert!(err.to_string().contains('1'), "the error should name the limit that was hit: {err}");

		let _ = tx.send(());
		held.await.expect("task").expect("held");
	}
}

//! The live rendezvous accept loop (onyums ROADMAP Phase 0 — the `serve_loop.rs`
//! slice of the lib.rs split).
//!
//! Everything here runs only against a live Tor network, and that is the point of
//! giving it its own module: [`serve_circuits`] drives the stream of `RendRequest`s,
//! [`handle_circuit_streams`] runs one rendezvous circuit's streams, and the
//! `handle_*` helpers serve a single accepted stream (TLS + axum on 443, the HTTPS
//! redirect on 80, a registered raw handler elsewhere). The offline decisions they
//! consult are deliberately *not* here — they live in tested modules this one calls:
//! the circuit/stream verdicts in [`circuit_gate`](crate::circuit_gate), the port
//! dispatch in [`port_router`](crate::port_router), the TLS acceptor assembly in
//! [`tls_setup`](crate::tls_setup), and the gate+HSTS composition in
//! [`http_stack`](crate::http_stack).
//!
//! That split is what keeps this module thin: it is the part of onyums that CI cannot
//! run (the live test is `#[ignore]`d — see the README's feature-status matrix), so
//! every decision worth testing is made somewhere else and this code only sequences
//! them.

use std::{future::Future, pin::Pin, sync::Arc};

use anyhow::Result;
use axum::Router;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use http_body_util::Empty;
use hyper::{Request, Response, StatusCode, body::Incoming};
use hyper_util::{
	rt::{TokioExecutor, TokioIo}, service::TowerToHyperService
};
use onyums_skin::{AdaptiveDifficulty, CircuitId, CircuitPolicy};
use tokio_rustls::TlsAcceptor;
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hsservice::{RendRequest, StreamRequest};
use tor_proto::stream::IncomingStreamRequest;
use tower_service::Service;
use tracing::{Level, event, span};

use crate::{
	address::OnionAddress, circuit_gate::{self, CircuitDisposition, CircuitIdAllocator, StreamDisposition}, connection::ConnectionInfo, metrics::CircuitMetrics, port_router::{PortDispatch, PortRouter, StreamHandler}, tls_policy
};

/// The shared, per-service context threaded through the rendezvous loop down to
/// every served stream: the application router, the TLS acceptor, the service
/// address, the plaintext-enforcement policy, the port → handler routing table, and
/// the shared metrics counters.
///
/// Bundled into one cheaply-`Clone` value (the `Router`/`TlsAcceptor`/`Arc` clones
/// are all shallow) so the loop's helpers take a handful of arguments instead of a
/// long, error-prone positional list. The per-circuit [`CircuitPolicy`] is kept
/// separate because it is borrowed (`&dyn`) at the circuit level, not cloned.
#[derive(Clone)]
pub struct ServeContext {
	pub app: Router,
	pub tls_acceptor: TlsAcceptor,
	pub address: OnionAddress,
	pub plaintext: tls_policy::PlaintextPolicy,
	pub port_router: Arc<PortRouter>,
	pub metrics: Arc<CircuitMetrics>,
	/// Optional Skin adaptive-PoW controller, shared with the caller's `Skin`. Each
	/// offered circuit is recorded here (see `circuit_gate::observe_circuit`).
	pub adaptive: Option<Arc<AdaptiveDifficulty>>,
}

/// Drives the rendezvous-circuit loop with a [`CircuitPolicy`], preserving the
/// per-circuit boundary that `tor_hsservice::handle_rend_requests` (the flattener used
/// before) discards.
///
/// Each `RendRequest` is exactly one rendezvous circuit, so the host mints a synthetic
/// [`CircuitId`] per request (arti surfaces none at the stream layer — see
/// [`circuit_gate`]). The policy is consulted at the circuit boundary
/// ([`CircuitPolicy::on_new_circuit`]) before the circuit is accepted, then per stream
/// ([`CircuitPolicy::on_new_stream`]); its [`CircuitAction`](onyums_skin::CircuitAction)
/// drives accept / per-stream reject / whole-circuit teardown. Each circuit's streams
/// are handled on a dedicated task so circuits run concurrently, and the circuit's
/// accounting is dropped via [`CircuitPolicy::forget`] once its stream drains.
pub async fn serve_circuits(rend_requests: impl Stream<Item = RendRequest> + Send + Unpin, ctx: ServeContext, policy: Arc<dyn CircuitPolicy>) -> Result<()> {
	serve_circuits_with(rend_requests, ctx, policy, |streams, id, ctx, policy| async move {
		handle_circuit_streams(streams, id, ctx, policy.as_ref(), |req, ctx, id| async move { handle_stream_request(req, ctx, id).await }).await;
	})
	.await
}

/// What [`handle_circuit_streams`] needs from one stream offered on an accepted circuit.
///
/// The per-stream counterpart to [`IncomingCircuit`], and it exists for the same reason:
/// `tor_hsservice::StreamRequest` wraps a `tor_proto` `IncomingStream` on a live tunnel
/// and has no public constructor, so the loop's per-stream sequencing could not be
/// exercised offline. The trait names the three operations the loop performs on a stream
/// that it does *not* serve; serving is left to a callback so this seam stops short of
/// TLS (see [`handle_circuit_streams`]).
///
/// The inputs are already constructible outside arti, which is what makes a test double
/// possible at all: `IncomingStreamRequest` is a public enum and
/// `tor_cell::relaycell::msg::Begin::new` is public, so a test builds a *real* BEGIN cell
/// rather than approximating one.
pub trait IncomingStreamReq: Send + 'static {
	/// The `BEGIN`/`BEGIN_DIR` cell this stream opened with — the input to
	/// [`circuit_gate::requested_port`].
	fn request(&self) -> &IncomingStreamRequest;

	/// Refuse this stream, leaving the circuit and its other streams alive.
	fn reject(self, reason: End) -> impl Future<Output = Result<()>> + Send;

	/// Tear down the whole rendezvous circuit this stream arrived on. Takes `self` by
	/// value, mirroring arti — the stream is spent either way.
	fn shutdown_circuit(self) -> Result<()>;
}

impl IncomingStreamReq for StreamRequest {
	fn request(&self) -> &IncomingStreamRequest {
		Self::request(self)
	}

	async fn reject(self, reason: End) -> Result<()> {
		Self::reject(self, reason).await.map_err(|e| anyhow::anyhow!("failed to reject stream: {e}"))
	}

	fn shutdown_circuit(self) -> Result<()> {
		Self::shutdown_circuit(self).map_err(|e| anyhow::anyhow!("failed to shut down circuit: {e}"))
	}
}

/// What [`serve_circuits_with`] needs from one offered rendezvous circuit.
///
/// This exists so the loop's *sequencing* can be tested offline. `tor_hsservice`'s
/// [`RendRequest`] has no public constructor and no test double — its fields are
/// private and it is only ever minted by arti from a real INTRODUCE2 on a live
/// tunnel — so the loop could not be exercised without a live Tor network. The trait
/// routes around exactly that: it names the two operations the loop performs on a
/// circuit, the real type implements it, and a test supplies its own implementor.
///
/// The module itself is private (`mod serve_loop;`), so this trait is crate-internal
/// however it is spelled: it is an internal seam, not public API, and must never reach
/// the builder's signature.
///
/// The `Streams` associated type is what the circuit yields once accepted. It is an
/// associated type rather than a bound because [`RendRequest::accept`] returns a
/// *return-position `impl Trait`* whose concrete type cannot be named on stable — the
/// real implementation therefore boxes it (see the impl below).
pub trait IncomingCircuit: Send + 'static {
	/// What one accepted circuit yields: its stream of stream-requests.
	type Streams: Send + 'static;

	/// Accept the circuit, yielding its streams.
	fn accept(self) -> impl Future<Output = Result<Self::Streams>> + Send;

	/// Refuse the circuit without accepting it.
	fn reject(self) -> impl Future<Output = Result<()>> + Send;
}

impl IncomingCircuit for RendRequest {
	// `RendRequest::accept` returns `impl Stream<Item = StreamRequest> + Unpin`, whose
	// concrete type is un-nameable on stable, so it is boxed to give the associated
	// type a name. The box costs one allocation per accepted circuit — once per
	// rendezvous, not per stream or per request.
	type Streams = Pin<Box<dyn Stream<Item = StreamRequest> + Send>>;

	async fn accept(self) -> Result<Self::Streams> {
		let streams = Self::accept(self).await.map_err(|e| anyhow::anyhow!("failed to accept rendezvous circuit: {e}"))?;
		Ok(Box::pin(streams))
	}

	async fn reject(self) -> Result<()> {
		Self::reject(self).await.map_err(|e| anyhow::anyhow!("failed to reject rendezvous circuit: {e}"))
	}
}

/// The generic core of [`serve_circuits`]: everything the loop *decides and sequences*,
/// with the two arti-owned pieces abstracted away — the circuit type behind
/// [`IncomingCircuit`], and what to do with an accepted circuit's streams behind
/// `drive`.
///
/// Splitting it this way is what makes the sequencing testable without a live Tor
/// network, which is the whole point: the per-verdict *decisions* were already covered
/// by [`circuit_gate`](crate::circuit_gate)'s tests, but the ordering around them was
/// not — that a policy-rejected circuit is never accepted and never yields streams,
/// that [`CircuitPolicy::forget`] fires on both the rejected and the drained path, that
/// a circuit is recorded as offered *before* the verdict, and that a failed accept does
/// not count as an accepted circuit. Each of those is a way the loop could regress
/// silently, since CI cannot run it.
pub async fn serve_circuits_with<C, F, Fut>(mut rend_requests: impl Stream<Item = C> + Send + Unpin, ctx: ServeContext, policy: Arc<dyn CircuitPolicy>, drive: F) -> Result<()>
where
	C: IncomingCircuit,
	F: Fn(C::Streams, CircuitId, ServeContext, Arc<dyn CircuitPolicy>) -> Fut + Clone + Send + 'static,
	Fut: Future<Output = ()> + Send + 'static
{
	event!(Level::INFO, "Waiting for incoming rendezvous circuits...");
	let allocator = Arc::new(CircuitIdAllocator::new());
	while let Some(rend_request) = rend_requests.next().await {
		let circuit_span = span!(Level::INFO, "onyums - new_circuit");
		let _circuit_guard = circuit_span.enter();
		let id = allocator.next_id();
		ctx.metrics.record_circuit_offered();
		// Record the circuit as load *before* the policy verdict: a rejected circuit is
		// still evidence of an attack, and only counting accepted ones would let an
		// attacker hold the PoW difficulty down by ensuring their circuits get rejected.
		circuit_gate::observe_circuit(ctx.adaptive.as_deref());

		// Consult the policy at the circuit boundary before accepting.
		if circuit_gate::circuit_disposition(policy.on_new_circuit(&id)) == CircuitDisposition::Drop {
			event!(Level::INFO, "Circuit {} rejected by policy on offer.", id.0);
			ctx.metrics.record_circuit_rejected();
			if let Err(err) = rend_request.reject().await {
				event!(Level::INFO, "Failed to reject circuit {}: {err}", id.0);
			}
			// `on_new_circuit` may have registered accounting for this id; drop it again
			// since the circuit never enters service.
			policy.forget(&id);
			continue;
		}

		let streams = match rend_request.accept().await {
			Ok(streams) => streams,
			Err(err) => {
				event!(Level::INFO, "Failed to accept circuit {}: {err}", id.0);
				continue;
			}
		};
		ctx.metrics.record_circuit_accepted();

		let ctx = ctx.clone();
		let policy = policy.clone();
		let drive = drive.clone();
		tokio::spawn(async move {
			drive(streams, id, ctx, Arc::clone(&policy)).await;
			// The circuit has drained; drop its accounting so the policy's map does not
			// grow without bound (there is no per-stream close hook).
			policy.forget(&id);
			event!(Level::INFO, "Circuit {} closed.", id.0);
		});
	}
	Ok(())
}

/// Handles every stream on one accepted rendezvous circuit, consulting the policy per
/// stream and spawning a task to serve each one the policy admits.
pub async fn handle_circuit_streams<R, F, Fut>(mut streams: impl Stream<Item = R> + Send + Unpin, id: CircuitId, ctx: ServeContext, policy: &dyn CircuitPolicy, serve: F)
where
	R: IncomingStreamReq,
	F: Fn(R, ServeContext, CircuitId) -> Fut + Clone + Send + 'static,
	Fut: Future<Output = Result<()>> + Send + 'static
{
	while let Some(stream_request) = streams.next().await {
		let stream_span = span!(Level::INFO, "onyums - incoming_stream");
		let _stream_guard = stream_span.enter();
		let port = circuit_gate::requested_port(stream_request.request());
		let target = circuit_gate::stream_target(port);

		let disposition = circuit_gate::stream_disposition(policy.on_new_stream(&id, &target), port);
		ctx.metrics.record_stream(disposition);
		match disposition {
			StreamDisposition::Serve => {
				let ctx = ctx.clone();
				let serve = serve.clone();
				tokio::spawn(async move {
					if let Err(err) = serve(stream_request, ctx, id).await {
						event!(Level::INFO, "Connection closed: Error handling stream request: {err}");
					}
				});
			}
			StreamDisposition::Reject => {
				event!(Level::INFO, "Stream on circuit {} rejected by policy.", id.0);
				// Reject just this stream (DONE keeps onyums indistinguishable from other
				// onion services); the circuit and its other streams live on.
				if let Err(err) = stream_request.reject(End::new_with_reason(EndReason::DONE)).await {
					event!(Level::INFO, "Failed to reject stream on circuit {}: {err}", id.0);
				}
			}
			StreamDisposition::Shutdown => {
				event!(Level::INFO, "Tearing down circuit {} by policy.", id.0);
				if let Err(err) = stream_request.shutdown_circuit() {
					event!(Level::INFO, "Failed to shut down circuit {}: {err}", id.0);
				}
				// The whole circuit is gone; stop pulling its streams.
				break;
			}
		}
	}
}

/// Handles a TLS connection on port 443.
pub async fn handle_tls_connection(stream_request: StreamRequest, tls_acceptor: TlsAcceptor, app: Router, circuit_id: CircuitId) -> Result<()> {
	event!(Level::INFO, "Accepting the incoming stream and wrapping it in a TLS stream...");
	let onion_service_stream = stream_request.accept(Connected::new_empty()).await.map_err(|e| anyhow::anyhow!("failed to accept onion service stream: {e}"))?;

	// Surface the host-assigned per-circuit id to the application (and the Skin HTTP
	// gate) via the axum connect-info, replacing the long-hardcoded `None`.
	let connect_info = ConnectionInfo { circuit_id: Some(circuit_id.0.to_string()), socket_addr: None };

	// Accept the TLS connection, logging the specific error on failure
	let tls_onion_service_stream = tls_acceptor.accept(onion_service_stream).await.map_err(|e| anyhow::anyhow!("failed to accept TLS stream: {e:?}"))?;

	// Wrap the stream in a `TokioIo` to make it compatible with tokio's `AsyncRead` and `AsyncWrite`.
	event!(Level::INFO, "Wrapping the stream for tokio compatibility...");
	let stream = TokioIo::new(tls_onion_service_stream);

	// Build the per-connection axum service once, on the current tokio runtime. The
	// previous implementation spawned a fresh OS thread *and* a new current-thread
	// runtime for every hyper request just to drive this `async` setup, joining the
	// thread before returning the response future — a correctness and throughput
	// landmine. `IntoMakeServiceWithConnectInfo` is always ready, so we can await it
	// directly here and reuse the resulting tower service across every request on this
	// connection (keep-alive included).
	let mut make_service = app.into_make_service_with_connect_info::<ConnectionInfo>();
	let tower_service = make_service.call(connect_info).await.expect("IntoMakeServiceWithConnectInfo is infallible");

	// Bridge the tower service into hyper's own `Service` trait without any thread or
	// runtime juggling.
	let hyper_service = TowerToHyperService::new(tower_service);

	// Serve the connection with hyper's `auto::Builder`.
	event!(Level::INFO, "Serving the connection with hyper...");
	hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).serve_connection_with_upgrades(stream, hyper_service).await.map_err(|err| anyhow::anyhow!("Error serving connection: {err}"))
}

/// Handles a plain HTTP request on port 80 by redirecting to HTTPS.
pub async fn handle_http_redirect(stream_request: StreamRequest, requested_host: String) -> Result<()> {
	event!(Level::INFO, "Accepting plain HTTP request on port 80 and redirecting to HTTPS.");
	let onion_service_stream = stream_request.accept(Connected::new_empty()).await.map_err(|e| anyhow::anyhow!("failed to accept onion service stream: {e}"))?;

	let stream = TokioIo::new(onion_service_stream);

	let hyper_service = hyper::service::service_fn(move |req: Request<Incoming>| {
		let host = requested_host.clone();
		let path = req.uri().path_and_query().map_or("", |p| p.as_str());
		let redirect_uri = format!("https://{host}{path}");
		async move { Ok::<_, std::convert::Infallible>(Response::builder().status(StatusCode::MOVED_PERMANENTLY).header("Location", redirect_uri).body(Empty::<Bytes>::new()).unwrap()) }
	});

	hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).http1_only().serve_connection(stream, hyper_service).await.map_err(|err| anyhow::anyhow!("Error serving HTTP redirect: {err}"))
}

// Then handle_stream_request
pub async fn handle_stream_request(stream_request: StreamRequest, ctx: ServeContext, circuit_id: CircuitId) -> Result<()> {
	let handling_request_trace_span = span!(Level::INFO, "onyums - handling_request");
	let _handling_request_trace_guard = handling_request_trace_span.enter();
	// The per-port dispatch is factored into the pure, offline-tested
	// `PortRouter::dispatch`; here we only execute it. The built-in TLS-first
	// decision wins for ports 80/443 (so under a `Reject` plaintext policy the
	// port-80 arm resolves to `Reject`, no plaintext handler at all); any other
	// port resolves to a caller-registered raw handler or, with none, a reject.
	let port = circuit_gate::requested_port(stream_request.request());
	match ctx.port_router.dispatch(port, ctx.plaintext) {
		PortDispatch::ServeHttp => handle_tls_connection(stream_request, ctx.tls_acceptor, ctx.app, circuit_id).await,
		PortDispatch::RedirectToHttps => handle_http_redirect(stream_request, ctx.address.host().to_string()).await,
		PortDispatch::Raw(handler) => {
			let handler = Arc::clone(handler);
			handle_raw_stream(stream_request, handler, port).await
		}
		PortDispatch::Reject => {
			// Reject the incoming request (non-HTTP port with no registered handler,
			// or plaintext under strict TLS).
			event!(Level::INFO, "Rejecting the incoming request {:?}...", stream_request.request());
			stream_request.shutdown_circuit().map_err(|e| anyhow::anyhow!("Failed to shutdown circuit: {e}"))
		}
	}
}

/// Accept a stream on a caller-registered port and hand it to its raw
/// [`StreamHandler`] (onyums ROADMAP Phase 3 — protocol versatility).
///
/// Unlike [`handle_tls_connection`], a raw stream is *not* wrapped in onyums' TLS:
/// the handler's protocol negotiates its own end-to-end security over the
/// onion-encrypted channel. The accepted onion stream is boxed into an
/// [`OnionStream`] and handed to the handler, which owns it for the connection.
pub async fn handle_raw_stream(stream_request: StreamRequest, handler: Arc<dyn StreamHandler>, port: u16) -> Result<()> {
	event!(Level::INFO, "Accepting a raw stream on port {port} for a registered handler...");
	let onion_service_stream = stream_request.accept(Connected::new_empty()).await.map_err(|e| anyhow::anyhow!("failed to accept onion service stream: {e}"))?;
	handler.serve(Box::pin(onion_service_stream)).await
}

#[cfg(test)]
mod tests {
	use std::sync::{
		Arc, Mutex, atomic::{AtomicUsize, Ordering}
	};

	use onyums_skin::{CircuitAction, StreamTarget};

	use super::*;
	use crate::{metrics::CircuitMetrics, port_router::PortRouter, tls_policy::Tls, tls_setup::tls_acceptor};

	/// A syntactically well-formed 56-character onion host, as in `tls_setup`'s tests.
	fn address() -> OnionAddress {
		OnionAddress::normalized("examplereturnsavalidacceptorpaddingxxxxxxxxxxxxxxxxxxxxx")
	}

	/// A `ServeContext` assembled entirely offline: a bare router, a self-signed
	/// acceptor generated in-process by rcgen, and an empty port table.
	fn context(metrics: &Arc<CircuitMetrics>) -> ServeContext {
		let address = address();
		ServeContext {
			app: Router::new(),
			tls_acceptor: tls_acceptor(&address, &Tls::Upgrade).expect("self-signed acceptor assembles offline"),
			address,
			plaintext: tls_policy::PlaintextPolicy::Upgrade,
			port_router: Arc::new(PortRouter::default()),
			metrics: Arc::clone(metrics),
			adaptive: None
		}
	}

	/// What one test circuit did, recorded so the assertions can name it.
	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
	enum CircuitOutcome {
		Accepted,
		Rejected
	}

	/// A test stand-in for `RendRequest`. It records whether it was accepted or
	/// rejected into a shared log, which is what lets a test assert that a circuit the
	/// policy refused was *never* accepted — the ordering property the real loop has
	/// and no offline test could previously observe.
	struct FakeCircuit {
		outcomes: Arc<Mutex<Vec<CircuitOutcome>>>,
		/// When true, `accept()` fails — standing in for arti failing to accept a
		/// circuit that the policy admitted.
		accept_fails: bool
	}

	impl IncomingCircuit for FakeCircuit {
		/// The accepted circuit yields nothing to drive; this slice covers the circuit
		/// layer only, so the streams payload is deliberately a unit.
		type Streams = ();

		// Not `async fn`: there is nothing to await, and the trait only asks for a
		// `Future`, so a ready one is the honest shape.
		fn accept(self) -> impl Future<Output = Result<Self::Streams>> + Send {
			let outcome = if self.accept_fails {
				Err(anyhow::anyhow!("simulated accept failure"))
			} else {
				self.outcomes.lock().expect("not poisoned").push(CircuitOutcome::Accepted);
				Ok(())
			};
			std::future::ready(outcome)
		}

		fn reject(self) -> impl Future<Output = Result<()>> + Send {
			self.outcomes.lock().expect("not poisoned").push(CircuitOutcome::Rejected);
			std::future::ready(Ok(()))
		}
	}

	/// A policy that answers every circuit with a fixed verdict and counts `forget`s.
	struct ScriptedPolicy {
		circuit_verdict: CircuitAction,
		forgotten: Arc<Mutex<Vec<u64>>>
	}

	impl ScriptedPolicy {
		fn scripted(circuit_verdict: CircuitAction) -> (Arc<dyn CircuitPolicy>, Arc<Mutex<Vec<u64>>>) {
			let forgotten = Arc::new(Mutex::new(Vec::new()));
			let policy: Arc<dyn CircuitPolicy> = Arc::new(Self { circuit_verdict, forgotten: Arc::clone(&forgotten) });
			(policy, forgotten)
		}
	}

	impl CircuitPolicy for ScriptedPolicy {
		fn on_new_circuit(&self, _id: &CircuitId) -> CircuitAction {
			self.circuit_verdict
		}

		fn on_new_stream(&self, _id: &CircuitId, _target: &StreamTarget) -> CircuitAction {
			CircuitAction::Accept
		}

		fn on_request(&self, _id: &CircuitId) -> CircuitAction {
			CircuitAction::Accept
		}

		fn forget(&self, id: &CircuitId) {
			self.forgotten.lock().expect("not poisoned").push(id.0);
		}
	}

	/// Run the generic loop over `count` circuits under `verdict`, returning the
	/// circuit outcomes, the ids forgotten, how many times the drive callback ran, and
	/// the metrics snapshot.
	async fn run(verdict: CircuitAction, count: usize, accept_fails: bool) -> (Vec<CircuitOutcome>, Vec<u64>, usize, crate::metrics::ServiceMetrics) {
		let metrics = Arc::new(CircuitMetrics::default());
		let ctx = context(&metrics);
		let (policy, forgotten) = ScriptedPolicy::scripted(verdict);
		let outcomes = Arc::new(Mutex::new(Vec::new()));
		let drives = Arc::new(AtomicUsize::new(0));

		let circuits: Vec<_> = (0..count).map(|_| FakeCircuit { outcomes: Arc::clone(&outcomes), accept_fails }).collect();
		let stream = futures::stream::iter(circuits);

		let drive_count = Arc::clone(&drives);
		serve_circuits_with(stream, ctx, policy, move |(), _id, _ctx, _policy| {
			let drive_count = Arc::clone(&drive_count);
			async move {
				drive_count.fetch_add(1, Ordering::SeqCst);
			}
		})
		.await
		.expect("the loop ends cleanly when the circuit stream ends");

		// The drained-circuit `forget` happens on a spawned task; yield until the
		// spawned work has run rather than sleeping for a fixed duration.
		for _ in 0..64 {
			tokio::task::yield_now().await;
		}

		let outcomes = outcomes.lock().expect("not poisoned").clone();
		let forgotten = forgotten.lock().expect("not poisoned").clone();
		(outcomes, forgotten, drives.load(Ordering::SeqCst), metrics.snapshot())
	}

	#[tokio::test]
	async fn an_accepted_circuit_is_accepted_driven_and_then_forgotten() {
		let (outcomes, forgotten, drives, metrics) = run(CircuitAction::Accept, 3, false).await;
		assert_eq!(outcomes, vec![CircuitOutcome::Accepted; 3]);
		assert_eq!(drives, 3, "every accepted circuit's streams are driven exactly once");
		assert_eq!(forgotten.len(), 3, "each drained circuit's accounting is dropped");
		assert_eq!(metrics.circuits_offered, 3);
		assert_eq!(metrics.circuits_accepted, 3);
		assert_eq!(metrics.circuits_rejected, 0);
	}

	#[tokio::test]
	async fn a_policy_rejected_circuit_is_never_accepted_and_yields_no_streams() {
		let (outcomes, forgotten, drives, metrics) = run(CircuitAction::Reject, 3, false).await;
		// The property that matters: not one `Accepted` in the log. A regression that
		// accepted first and rejected after would still "reject" the circuit, and every
		// counter-only assertion would still pass.
		assert_eq!(outcomes, vec![CircuitOutcome::Rejected; 3]);
		assert_eq!(drives, 0, "a refused circuit must never reach the stream driver");
		assert_eq!(forgotten.len(), 3, "accounting registered by on_new_circuit is dropped again");
		assert_eq!(metrics.circuits_offered, 3, "a refused circuit is still counted as offered");
		assert_eq!(metrics.circuits_accepted, 0);
		assert_eq!(metrics.circuits_rejected, 3);
	}

	#[tokio::test]
	async fn a_shutdown_verdict_refuses_the_circuit_at_the_offer() {
		// `Shutdown` at the circuit boundary means the same thing as `Reject` — there is
		// nothing yet to tear down — and `circuit_gate::circuit_disposition` maps it so.
		// Pinned here because the loop, not the gate, is what acts on it.
		let (outcomes, _forgotten, drives, metrics) = run(CircuitAction::Shutdown, 2, false).await;
		assert_eq!(outcomes, vec![CircuitOutcome::Rejected; 2]);
		assert_eq!(drives, 0);
		assert_eq!(metrics.circuits_rejected, 2);
	}

	#[tokio::test]
	async fn a_failed_accept_is_not_counted_as_an_accepted_circuit() {
		let (outcomes, forgotten, drives, metrics) = run(CircuitAction::Accept, 2, true).await;
		assert!(outcomes.is_empty(), "the fake records neither outcome when accept fails");
		assert_eq!(drives, 0, "no streams are driven for a circuit that never opened");
		assert!(forgotten.is_empty(), "nothing was ever driven, so nothing reaches the drained-circuit forget");
		assert_eq!(metrics.circuits_offered, 2, "the offer happened regardless");
		assert_eq!(metrics.circuits_accepted, 0, "the counter tracks accepts that succeeded, not accepts attempted");
		assert_eq!(metrics.circuits_rejected, 0, "an arti-side accept failure is not a policy rejection");
	}

	#[tokio::test]
	async fn every_circuit_gets_a_distinct_id() {
		let (_outcomes, forgotten, _drives, _metrics) = run(CircuitAction::Reject, 5, false).await;
		let mut ids = forgotten;
		ids.sort_unstable();
		ids.dedup();
		assert_eq!(ids.len(), 5, "the allocator must not reuse an id within one loop run");
	}

	/// What one test stream did, in order.
	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
	enum StreamOutcome {
		Served(u16),
		Rejected(u16),
		ShutDown(u16)
	}

	/// A test stand-in for `StreamRequest`, carrying a *real* BEGIN cell — `Begin::new`
	/// is public, so the port the gate reads is decoded from a genuine cell rather than
	/// mocked around.
	struct FakeStream {
		request: IncomingStreamRequest,
		port: u16,
		outcomes: Arc<Mutex<Vec<StreamOutcome>>>
	}

	impl FakeStream {
		fn new(port: u16, outcomes: &Arc<Mutex<Vec<StreamOutcome>>>) -> Self {
			let begin = tor_cell::relaycell::msg::Begin::new("example.onion", port, 0).expect("a valid BEGIN cell");
			Self { request: IncomingStreamRequest::Begin(begin), port, outcomes: Arc::clone(outcomes) }
		}
	}

	impl IncomingStreamReq for FakeStream {
		fn request(&self) -> &IncomingStreamRequest {
			&self.request
		}

		fn reject(self, _reason: End) -> impl Future<Output = Result<()>> + Send {
			self.outcomes.lock().expect("not poisoned").push(StreamOutcome::Rejected(self.port));
			std::future::ready(Ok(()))
		}

		fn shutdown_circuit(self) -> Result<()> {
			self.outcomes.lock().expect("not poisoned").push(StreamOutcome::ShutDown(self.port));
			Ok(())
		}
	}

	/// Drive `ports` through the per-stream half of the loop under a fixed stream
	/// verdict, returning what happened to each stream and the metrics snapshot.
	async fn run_streams(stream_verdict: CircuitAction, ports: &[u16]) -> (Vec<StreamOutcome>, crate::metrics::ServiceMetrics) {
		struct StreamPolicy(CircuitAction);
		impl CircuitPolicy for StreamPolicy {
			fn on_new_circuit(&self, _id: &CircuitId) -> CircuitAction {
				CircuitAction::Accept
			}

			fn on_new_stream(&self, _id: &CircuitId, _target: &StreamTarget) -> CircuitAction {
				self.0
			}

			fn on_request(&self, _id: &CircuitId) -> CircuitAction {
				CircuitAction::Accept
			}
		}

		let metrics = Arc::new(CircuitMetrics::default());
		let ctx = context(&metrics);
		let policy = StreamPolicy(stream_verdict);
		let outcomes = Arc::new(Mutex::new(Vec::new()));

		let streams: Vec<_> = ports.iter().map(|p| FakeStream::new(*p, &outcomes)).collect();
		let served = Arc::clone(&outcomes);
		handle_circuit_streams(futures::stream::iter(streams), CircuitId(7), ctx, &policy, move |req: FakeStream, _ctx, _id| {
			let served = Arc::clone(&served);
			async move {
				served.lock().expect("not poisoned").push(StreamOutcome::Served(req.port));
				Ok(())
			}
		})
		.await;

		for _ in 0..64 {
			tokio::task::yield_now().await;
		}

		let outcomes = outcomes.lock().expect("not poisoned").clone();
		(outcomes, metrics.snapshot())
	}

	#[tokio::test]
	async fn an_admitted_stream_reaches_the_server_on_the_https_port() {
		let (outcomes, metrics) = run_streams(CircuitAction::Accept, &[443, 443]).await;
		assert_eq!(outcomes, vec![StreamOutcome::Served(443); 2]);
		assert_eq!(metrics.streams_served, 2);
		assert_eq!(metrics.streams_rejected, 0);
	}

	#[tokio::test]
	async fn a_rejected_stream_leaves_the_circuit_alive_for_the_next_one() {
		// The property: rejection is per *stream*. Every stream in the batch is still
		// pulled and refused — the loop must not stop on the first refusal.
		let (outcomes, metrics) = run_streams(CircuitAction::Reject, &[443, 443, 443]).await;
		assert_eq!(outcomes, vec![StreamOutcome::Rejected(443); 3]);
		assert_eq!(metrics.streams_rejected, 3);
		assert_eq!(metrics.streams_served, 0);
	}

	#[tokio::test]
	async fn a_shutdown_verdict_tears_down_the_circuit_and_stops_pulling_streams() {
		// The sequencing property that only this seam can observe: after `Shutdown` the
		// loop must `break`, so the *second* stream is never touched at all. A
		// regression that kept looping would still shut the circuit down and would
		// still pass any counter-only assertion.
		let (outcomes, metrics) = run_streams(CircuitAction::Shutdown, &[443, 443]).await;
		assert_eq!(outcomes, vec![StreamOutcome::ShutDown(443)], "exactly one stream is handled; the loop stops");
		assert_eq!(metrics.streams_shutdown, 1);
	}

	#[tokio::test]
	async fn a_challenge_verdict_is_served_on_http_ports_but_fails_closed_on_a_raw_port() {
		// `Challenge` only means something where the Skin gate can render one — the
		// reserved HTTP ports. On a raw port there is no gate, so it must fail closed
		// to a rejection rather than being served ungated. The decision lives in
		// `circuit_gate::stream_disposition`; this pins that the loop *acts* on it.
		let (http, _) = run_streams(CircuitAction::Challenge, &[443, 80]).await;
		assert_eq!(http, vec![StreamOutcome::Served(443), StreamOutcome::Served(80)]);

		let (raw, metrics) = run_streams(CircuitAction::Challenge, &[22, 6379]).await;
		assert_eq!(raw, vec![StreamOutcome::Rejected(22), StreamOutcome::Rejected(6379)], "a challenge on a raw port must not be served");
		assert_eq!(metrics.streams_rejected, 2);
	}
}

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
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hsservice::{RendRequest, StreamRequest};
use tor_proto::stream::IncomingStreamRequest;
use tower_service::Service;
use tracing::{Level, event, span};

use crate::{
	address::OnionAddress, circuit_gate::{self, CircuitDisposition, CircuitIdAllocator, StreamDisposition}, connection::ConnectionInfo, metrics::CircuitMetrics, port_router::{AsyncStream, PortDispatch, PortRouter, StreamHandler}, tls_policy
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
	/// Optional host-global cap on concurrently-served rendezvous circuits
	/// (onyums ROADMAP Phase 0 — concurrency/backpressure limits). `None` is today's
	/// behaviour: unbounded, one task per circuit.
	///
	/// A permit is taken *after* the policy verdict and held for the circuit's whole
	/// lifetime, so it is released however the circuit ends. At capacity the loop
	/// **refuses** rather than queues — the same stance `ConnectionLimit` takes on raw
	/// ports, and for the same reason: queueing turns a circuit flood into unbounded
	/// memory growth plus a latency cliff for the clients already being served, which
	/// is the exact failure a limit exists to prevent. A refused client can retry; one
	/// parked in an invisible queue cannot tell slow from dead.
	pub max_circuits: Option<Arc<Semaphore>>,
	/// Optional host-global cap on concurrently-served *streams*, across all circuits
	/// (onyums ROADMAP Phase 0 — concurrency/backpressure limits). `None` is today's
	/// behaviour: unbounded.
	///
	/// Complements [`max_circuits`](Self::max_circuits) rather than duplicating it: a
	/// circuit cap bounds how many clients are in service, while this bounds the total
	/// work in flight, which is what actually consumes sockets and memory — one circuit
	/// may open many streams. Same stance at capacity: **refuse this stream**, leaving
	/// the circuit and its other streams alive, exactly as a policy `Reject` does.
	pub max_streams: Option<Arc<Semaphore>>,
	/// Optional ceiling on how long one served stream may run
	/// (onyums ROADMAP Phase 0 — concurrency/backpressure limits). `None` is today's
	/// behaviour: a stream runs until it ends on its own.
	///
	/// This is the limit the two semaphores need to mean anything under an attack that
	/// does not close connections: without it a client can hold a permit forever simply
	/// by going quiet mid-request, so `max_circuits`/`max_streams` bound how many slow
	/// clients it takes to fill the service rather than bounding the damage. A timeout
	/// is what turns a permit into a *lease*.
	///
	/// Deliberately not on by default: a legitimate long-lived stream is a real use of
	/// an onion service (the README's own websocket example is one), so a default here
	/// would silently sever working applications.
	pub handler_timeout: Option<std::time::Duration>,
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

	/// The accepted bidirectional stream. `AsyncRead + AsyncWrite + Send + Unpin` is the
	/// whole contract the serve path needs, which is why a `tokio::io::duplex` pair can
	/// stand in for an accepted onion stream in tests — the same trick `raw_tcp` and
	/// `ConnectionLimit` already rely on.
	type Stream: AsyncStream + 'static;

	/// Accept this stream, answering the client's BEGIN with `connected`.
	fn accept(self, connected: Connected) -> impl Future<Output = Result<Self::Stream>> + Send;

	/// Refuse this stream, leaving the circuit and its other streams alive.
	fn reject(self, reason: End) -> impl Future<Output = Result<()>> + Send;

	/// Tear down the whole rendezvous circuit this stream arrived on. Takes `self` by
	/// value, mirroring arti — the stream is spent either way.
	fn shutdown_circuit(self) -> Result<()>;
}

impl IncomingStreamReq for StreamRequest {
	type Stream = tor_proto::client::stream::DataStream;

	fn request(&self) -> &IncomingStreamRequest {
		Self::request(self)
	}

	async fn accept(self, connected: Connected) -> Result<Self::Stream> {
		Self::accept(self, connected).await.map_err(|e| anyhow::anyhow!("failed to accept onion service stream: {e}"))
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

/// Whether a newly-offered circuit may be served, under the host-global cap.
///
/// Three outcomes rather than an `Option`, because "no limit configured" and "a permit
/// was granted" are different facts that happen to allow the same next step — and
/// collapsing them is how a future edit accidentally starts counting unbounded service as
/// grants.
enum Admission {
	/// No host-global cap is configured; serve without taking a permit.
	Unbounded,
	/// A permit was taken; hold it for the circuit's lifetime.
	Granted(OwnedSemaphorePermit),
	/// The cap is full; refuse this circuit.
	Full,
}

/// Try to take a circuit permit without waiting.
///
/// `try_acquire_owned` is what makes the cap a *refusal* rather than a stall: it never
/// queues, so a circuit arriving at capacity is turned away immediately instead of
/// parking a task and a rendezvous circuit for an unbounded time.
fn admit_circuit(limit: Option<&Arc<Semaphore>>) -> Admission {
	limit.map_or(Admission::Unbounded, |limit| Arc::clone(limit).try_acquire_owned().map_or(Admission::Full, Admission::Granted))
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
	Fut: Future<Output = ()> + Send + 'static,
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

		// Host-global backpressure, after the policy verdict and before any work: a
		// circuit that cannot get a permit is refused outright rather than queued.
		// `try_acquire_owned` never waits, which is what makes this a refusal and not a
		// stall; the permit rides with the spawned task and is released when it ends.
		let permit = match admit_circuit(ctx.max_circuits.as_ref()) {
			Admission::Unbounded => None,
			Admission::Granted(permit) => Some(permit),
			Admission::Full => {
				event!(Level::WARN, "Circuit {} refused: at the host-global concurrency limit.", id.0);
				ctx.metrics.record_circuit_refused_at_capacity();
				if let Err(err) = rend_request.reject().await {
					event!(Level::INFO, "Failed to refuse circuit {}: {err}", id.0);
				}
				policy.forget(&id);
				continue;
			}
		};

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
			// Bound to the task, so the permit returns however the circuit ends —
			// normally, by teardown, or by a panic in the driver.
			let _permit: Option<OwnedSemaphorePermit> = permit;
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
	Fut: Future<Output = Result<()>> + Send + 'static,
{
	while let Some(stream_request) = streams.next().await {
		let stream_span = span!(Level::INFO, "onyums - incoming_stream");
		let _stream_guard = stream_span.enter();
		let port = circuit_gate::requested_port(stream_request.request());
		let target = circuit_gate::stream_target(port);

		let disposition = circuit_gate::stream_disposition(policy.on_new_stream(&id, &target), port);
		match disposition {
			StreamDisposition::Serve => {
				// Host-global stream backpressure. Checked *before* the stream is recorded
				// as served, so a stream refused for capacity is counted once, as a
				// refusal — recording the disposition first would count it as both served
				// and refused, and make the served total a lie.
				let permit = match admit_circuit(ctx.max_streams.as_ref()) {
					Admission::Unbounded => None,
					Admission::Granted(permit) => Some(permit),
					Admission::Full => {
						event!(Level::WARN, "Stream on circuit {} refused: at the host-global stream limit.", id.0);
						ctx.metrics.record_stream_refused_at_capacity();
						// Refuse just this stream; the circuit and its others live on, the
						// same shape as a policy rejection.
						if let Err(err) = stream_request.reject(End::new_with_reason(EndReason::RESOURCELIMIT)).await {
							event!(Level::INFO, "Failed to refuse stream on circuit {}: {err}", id.0);
						}
						continue;
					}
				};
				ctx.metrics.record_stream(disposition);
				let ctx = ctx.clone();
				let serve = serve.clone();
				let timeout = ctx.handler_timeout;
				// Taken before `ctx` moves into the handler future.
				let metrics = Arc::clone(&ctx.metrics);
				tokio::spawn(async move {
					// Held for the stream's lifetime; returned however it ends — which is
					// why the timeout below matters: it bounds that lifetime, so a client
					// that goes quiet cannot hold a permit for ever.
					let _permit: Option<OwnedSemaphorePermit> = permit;
					let handler = serve(stream_request, ctx, id);
					let served = if let Some(limit) = timeout {
						let Ok(result) = tokio::time::timeout(limit, handler).await else {
							event!(Level::WARN, "Stream on circuit {} timed out after {limit:?}; dropping it.", id.0);
							metrics.record_stream_timed_out();
							return;
						};
						result
					} else {
						handler.await
					};
					if let Err(err) = served {
						event!(Level::INFO, "Connection closed: Error handling stream request: {err}");
					}
				});
			}
			StreamDisposition::Reject => {
				ctx.metrics.record_stream(disposition);
				event!(Level::INFO, "Stream on circuit {} rejected by policy.", id.0);
				// Reject just this stream (DONE keeps onyums indistinguishable from other
				// onion services); the circuit and its other streams live on.
				if let Err(err) = stream_request.reject(End::new_with_reason(EndReason::DONE)).await {
					event!(Level::INFO, "Failed to reject stream on circuit {}: {err}", id.0);
				}
			}
			StreamDisposition::Shutdown => {
				ctx.metrics.record_stream(disposition);
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
pub async fn handle_tls_connection<R: IncomingStreamReq>(stream_request: R, tls_acceptor: TlsAcceptor, app: Router, circuit_id: CircuitId) -> Result<()> {
	event!(Level::INFO, "Accepting the incoming stream and wrapping it in a TLS stream...");
	let onion_service_stream = stream_request.accept(Connected::new_empty()).await?;

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
pub async fn handle_http_redirect<R: IncomingStreamReq>(stream_request: R, requested_host: String) -> Result<()> {
	event!(Level::INFO, "Accepting plain HTTP request on port 80 and redirecting to HTTPS.");
	let onion_service_stream = stream_request.accept(Connected::new_empty()).await?;

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
pub async fn handle_stream_request<R: IncomingStreamReq>(stream_request: R, ctx: ServeContext, circuit_id: CircuitId) -> Result<()> {
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
pub async fn handle_raw_stream<R: IncomingStreamReq>(stream_request: R, handler: Arc<dyn StreamHandler>, port: u16) -> Result<()> {
	event!(Level::INFO, "Accepting a raw stream on port {port} for a registered handler...");
	let onion_service_stream = stream_request.accept(Connected::new_empty()).await?;
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
			adaptive: None,
			max_circuits: None,
			max_streams: None,
			handler_timeout: None,
		}
	}

	/// What one test circuit did, recorded so the assertions can name it.
	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
	enum CircuitOutcome {
		Accepted,
		Rejected,
	}

	/// A test stand-in for `RendRequest`. It records whether it was accepted or
	/// rejected into a shared log, which is what lets a test assert that a circuit the
	/// policy refused was *never* accepted — the ordering property the real loop has
	/// and no offline test could previously observe.
	struct FakeCircuit {
		outcomes: Arc<Mutex<Vec<CircuitOutcome>>>,
		/// When true, `accept()` fails — standing in for arti failing to accept a
		/// circuit that the policy admitted.
		accept_fails: bool,
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
		forgotten: Arc<Mutex<Vec<u64>>>,
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
		ShutDown(u16),
	}

	/// A test stand-in for `StreamRequest`, carrying a *real* BEGIN cell — `Begin::new`
	/// is public, so the port the gate reads is decoded from a genuine cell rather than
	/// mocked around.
	struct FakeStream {
		request: IncomingStreamRequest,
		port: u16,
		outcomes: Arc<Mutex<Vec<StreamOutcome>>>,
	}

	impl FakeStream {
		fn new(port: u16, outcomes: &Arc<Mutex<Vec<StreamOutcome>>>) -> Self {
			let begin = tor_cell::relaycell::msg::Begin::new("example.onion", port, 0).expect("a valid BEGIN cell");
			Self { request: IncomingStreamRequest::Begin(begin), port, outcomes: Arc::clone(outcomes) }
		}
	}

	impl IncomingStreamReq for FakeStream {
		// This double covers the *disposition* path only; nothing in its tests accepts a
		// stream, so the accepted type is a duplex half purely to satisfy the bound.
		type Stream = tokio::io::DuplexStream;

		fn request(&self) -> &IncomingStreamRequest {
			&self.request
		}

		fn accept(self, _connected: Connected) -> impl Future<Output = Result<Self::Stream>> + Send {
			std::future::ready(Err(anyhow::anyhow!("FakeStream does not model the accept path; see DuplexStreamReq")))
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

	/// Circuits offered under a host-global cap of `max`, where every admitted circuit
	/// parks in its driver and never finishes — so its permit is still held when the
	/// next circuit is offered. That is the only way to observe the limit: with a driver
	/// that returns immediately the permit is back before the next offer and no cap of
	/// any size would ever be reached.
	async fn run_capped(max: usize, count: usize) -> (Vec<CircuitOutcome>, crate::metrics::ServiceMetrics) {
		let metrics = Arc::new(CircuitMetrics::default());
		let mut ctx = context(&metrics);
		ctx.max_circuits = Some(Arc::new(Semaphore::new(max)));

		let (policy, _forgotten) = ScriptedPolicy::scripted(CircuitAction::Accept);
		let outcomes = Arc::new(Mutex::new(Vec::new()));
		let circuits: Vec<_> = (0..count).map(|_| FakeCircuit { outcomes: Arc::clone(&outcomes), accept_fails: false }).collect();

		let (release_tx, release_rx) = tokio::sync::watch::channel(false);
		let held = release_rx.clone();
		serve_circuits_with(futures::stream::iter(circuits), ctx, policy, move |(), _id, _ctx, _policy| {
			let mut held = held.clone();
			async move {
				// Park until the test releases: the permit stays taken meanwhile.
				while !*held.borrow() {
					if held.changed().await.is_err() {
						break;
					}
				}
			}
		})
		.await
		.expect("the loop ends cleanly when the circuit stream ends");

		// Let the parked drivers finish so the run does not leak tasks.
		let _ = release_tx.send(true);
		for _ in 0..64 {
			tokio::task::yield_now().await;
		}

		let outcomes = outcomes.lock().expect("not poisoned").clone();
		(outcomes, metrics.snapshot())
	}

	#[tokio::test]
	async fn circuits_beyond_the_host_global_limit_are_refused_not_queued() {
		// Two permits, four circuits, none of them finishing: the first two are accepted
		// and the rest must be refused *immediately*. If the loop queued instead of
		// refusing, this test would hang rather than fail — which is precisely the
		// failure mode a cap exists to prevent, so the shape of the assertion matters.
		let (outcomes, metrics) = run_capped(2, 4).await;
		assert_eq!(outcomes, vec![CircuitOutcome::Accepted, CircuitOutcome::Accepted, CircuitOutcome::Rejected, CircuitOutcome::Rejected]);
		assert_eq!(metrics.circuits_offered, 4);
		assert_eq!(metrics.circuits_accepted, 2);
		assert_eq!(metrics.circuits_refused_at_capacity, 2);
		// The refusals are NOT policy rejections — the policy admitted all four.
		assert_eq!(metrics.circuits_rejected, 0, "being full is a fact about the service, not a verdict about the circuit");
	}

	#[tokio::test]
	async fn a_limit_at_or_above_the_offered_load_refuses_nothing() {
		let (outcomes, metrics) = run_capped(4, 4).await;
		assert_eq!(outcomes, vec![CircuitOutcome::Accepted; 4]);
		assert_eq!(metrics.circuits_refused_at_capacity, 0);
		assert_eq!(metrics.circuits_accepted, 4);
	}

	#[tokio::test]
	async fn an_unset_limit_stays_unbounded() {
		// The default must not quietly acquire a ceiling: with no cap, circuits that
		// never finish still all get served.
		let (outcomes, _forgotten, drives, metrics) = run(CircuitAction::Accept, 16, false).await;
		assert_eq!(outcomes.len(), 16);
		assert_eq!(drives, 16);
		assert_eq!(metrics.circuits_refused_at_capacity, 0);
	}

	/// Streams offered under a host-global stream cap of `max`, where every served
	/// stream parks and never finishes — so its permit is still held for the next one.
	async fn run_stream_capped(max: usize, count: usize) -> (Vec<StreamOutcome>, crate::metrics::ServiceMetrics) {
		struct AcceptAll;
		impl CircuitPolicy for AcceptAll {
			fn on_new_circuit(&self, _id: &CircuitId) -> CircuitAction {
				CircuitAction::Accept
			}

			fn on_new_stream(&self, _id: &CircuitId, _target: &StreamTarget) -> CircuitAction {
				CircuitAction::Accept
			}

			fn on_request(&self, _id: &CircuitId) -> CircuitAction {
				CircuitAction::Accept
			}
		}

		let metrics = Arc::new(CircuitMetrics::default());
		let mut ctx = context(&metrics);
		ctx.max_streams = Some(Arc::new(Semaphore::new(max)));

		let outcomes = Arc::new(Mutex::new(Vec::new()));
		let streams: Vec<_> = (0..count).map(|_| FakeStream::new(443, &outcomes)).collect();

		let (release_tx, release_rx) = tokio::sync::watch::channel(false);
		let served = Arc::clone(&outcomes);
		let held = release_rx.clone();
		handle_circuit_streams(futures::stream::iter(streams), CircuitId(9), ctx, &AcceptAll, move |req: FakeStream, _ctx, _id| {
			let served = Arc::clone(&served);
			let mut held = held.clone();
			async move {
				served.lock().expect("not poisoned").push(StreamOutcome::Served(req.port));
				while !*held.borrow() {
					if held.changed().await.is_err() {
						break;
					}
				}
				Ok(())
			}
		})
		.await;

		let _ = release_tx.send(true);
		for _ in 0..64 {
			tokio::task::yield_now().await;
		}

		let outcomes = outcomes.lock().expect("not poisoned").clone();
		(outcomes, metrics.snapshot())
	}

	#[tokio::test]
	async fn streams_beyond_the_host_global_stream_limit_are_refused_not_queued() {
		// Two permits, five streams, none finishing: two served, three refused. As with
		// the circuit cap, a loop that queued would hang here rather than fail.
		let (outcomes, metrics) = run_stream_capped(2, 5).await;
		assert_eq!(outcomes.iter().filter(|o| matches!(o, StreamOutcome::Served(_))).count(), 2);
		assert_eq!(outcomes.iter().filter(|o| matches!(o, StreamOutcome::Rejected(_))).count(), 3);
		assert_eq!(metrics.streams_refused_at_capacity, 3);
		// The refused streams must NOT also show up as served — the disposition is
		// recorded after the permit is taken, precisely so the served total stays true.
		assert_eq!(metrics.streams_served, 2, "a capacity-refused stream is counted once, as a refusal");
		assert_eq!(metrics.streams_rejected, 0, "being full is not a policy verdict");
	}

	#[tokio::test]
	async fn a_stream_limit_at_or_above_the_offered_load_refuses_nothing() {
		let (outcomes, metrics) = run_stream_capped(5, 5).await;
		assert_eq!(outcomes.iter().filter(|o| matches!(o, StreamOutcome::Served(_))).count(), 5);
		assert_eq!(metrics.streams_refused_at_capacity, 0);
		assert_eq!(metrics.streams_served, 5);
	}

	#[tokio::test]
	async fn an_unset_stream_limit_stays_unbounded() {
		// `run_streams` leaves `max_streams` at None; all 12 must be served.
		let (outcomes, metrics) = run_streams(CircuitAction::Accept, &[443; 12]).await;
		assert_eq!(outcomes.len(), 12);
		assert_eq!(metrics.streams_served, 12);
		assert_eq!(metrics.streams_refused_at_capacity, 0);
	}

	#[tokio::test(start_paused = true)]
	async fn a_stream_exceeding_the_handler_timeout_is_dropped_and_counted() {
		struct AcceptAll;
		impl CircuitPolicy for AcceptAll {
			fn on_new_circuit(&self, _id: &CircuitId) -> CircuitAction {
				CircuitAction::Accept
			}

			fn on_new_stream(&self, _id: &CircuitId, _target: &StreamTarget) -> CircuitAction {
				CircuitAction::Accept
			}

			fn on_request(&self, _id: &CircuitId) -> CircuitAction {
				CircuitAction::Accept
			}
		}

		let metrics = Arc::new(CircuitMetrics::default());
		let mut ctx = context(&metrics);
		ctx.handler_timeout = Some(std::time::Duration::from_secs(30));

		let outcomes = Arc::new(Mutex::new(Vec::new()));
		let served = Arc::clone(&outcomes);
		let streams = vec![FakeStream::new(443, &outcomes)];

		handle_circuit_streams(futures::stream::iter(streams), CircuitId(11), ctx, &AcceptAll, move |req: FakeStream, _ctx, _id| {
			let served = Arc::clone(&served);
			async move {
				served.lock().expect("not poisoned").push(StreamOutcome::Served(req.port));
				// Far longer than the timeout. The clock is paused, so this costs no real
				// wall time and the assertion is not a race against a real 30 seconds.
				tokio::time::sleep(std::time::Duration::from_secs(600)).await;
				Ok(())
			}
		})
		.await;

		// Let the spawned task actually start and register its timer *before* moving the
		// clock — advancing first would land before the timeout exists and do nothing.
		for _ in 0..16 {
			tokio::task::yield_now().await;
		}
		tokio::time::advance(std::time::Duration::from_secs(60)).await;
		for _ in 0..16 {
			tokio::task::yield_now().await;
		}

		let snapshot = metrics.snapshot();
		assert_eq!(outcomes.lock().expect("not poisoned").clone(), vec![StreamOutcome::Served(443)], "the stream was admitted and the handler ran");
		assert_eq!(snapshot.streams_served, 1, "it counts as served — it was admitted, it just did not finish");
		assert_eq!(snapshot.streams_timed_out, 1, "and separately as timed out, which is the signal for a slow client");
		assert_eq!(snapshot.streams_rejected, 0, "a timeout is not a policy rejection");
		assert_eq!(snapshot.streams_refused_at_capacity, 0, "nor a capacity refusal");
	}

	#[tokio::test(start_paused = true)]
	async fn an_unset_handler_timeout_never_drops_a_slow_stream() {
		// The default must not acquire a deadline: a long-lived stream (a websocket, say)
		// is a legitimate use of an onion service.
		let (outcomes, metrics) = run_stream_capped(4, 4).await;
		assert_eq!(outcomes.iter().filter(|o| matches!(o, StreamOutcome::Served(_))).count(), 4);
		assert_eq!(metrics.streams_timed_out, 0);
	}

	/// A stream request whose `accept` hands back one half of a `tokio::io::duplex` pair —
	/// the offline stand-in for an accepted onion stream. This is what lets the TLS +
	/// hyper + axum path run with no Tor network: `handle_tls_connection` only ever
	/// needed `AsyncRead + AsyncWrite + Send + Unpin` from arti, and a duplex half is
	/// exactly that.
	struct DuplexStreamReq {
		request: IncomingStreamRequest,
		server_side: tokio::io::DuplexStream,
		/// Set when `accept` is called. The refusal tests assert on *this* rather than on
		/// the returned `Result`: a dispatch regression that wrongly accepted a stream
		/// would then sit waiting on a client that never writes, so a Result-only test
		/// would **hang** instead of failing. Asserting "was never accepted" fails fast
		/// and names the actual defect. (Confirmed by mutation: flipping the plaintext
		/// policy in the strict test does hang the Result-only form.)
		accepted: Arc<std::sync::atomic::AtomicBool>,
	}

	impl DuplexStreamReq {
		fn pair(port: u16) -> (Self, tokio::io::DuplexStream) {
			let (req, client, _accepted) = Self::pair_tracked(port);
			(req, client)
		}

		fn pair_tracked(port: u16) -> (Self, tokio::io::DuplexStream, Arc<std::sync::atomic::AtomicBool>) {
			let begin = tor_cell::relaycell::msg::Begin::new("example.onion", port, 0).expect("a valid BEGIN cell");
			let (client_side, server_side) = tokio::io::duplex(64 * 1024);
			let accepted = Arc::new(std::sync::atomic::AtomicBool::new(false));
			(Self { request: IncomingStreamRequest::Begin(begin), server_side, accepted: Arc::clone(&accepted) }, client_side, accepted)
		}
	}

	impl IncomingStreamReq for DuplexStreamReq {
		type Stream = tokio::io::DuplexStream;

		fn request(&self) -> &IncomingStreamRequest {
			&self.request
		}

		fn accept(self, _connected: Connected) -> impl Future<Output = Result<Self::Stream>> + Send {
			self.accepted.store(true, Ordering::SeqCst);
			std::future::ready(Ok(self.server_side))
		}

		fn reject(self, _reason: End) -> impl Future<Output = Result<()>> + Send {
			std::future::ready(Ok(()))
		}

		fn shutdown_circuit(self) -> Result<()> {
			Ok(())
		}
	}

	/// Accepts any server certificate — the service presents a self-signed cert for its
	/// onion host by design (the onion address is the authenticator), so certificate
	/// verification is not the subject under test here; the served payload is.
	#[derive(Debug)]
	struct AcceptAnyCert;

	impl tokio_rustls::rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
		fn verify_server_cert(&self, _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>, _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>], _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>, _ocsp: &[u8], _now: tokio_rustls::rustls::pki_types::UnixTime) -> std::result::Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error> {
			Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
		}

		fn verify_tls12_signature(&self, _message: &[u8], _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>, _dss: &tokio_rustls::rustls::DigitallySignedStruct) -> std::result::Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
			Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
		}

		fn verify_tls13_signature(&self, _message: &[u8], _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>, _dss: &tokio_rustls::rustls::DigitallySignedStruct) -> std::result::Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
			Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
		}

		fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
			tokio_rustls::rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
		}
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn the_tls_and_axum_serve_path_answers_a_real_request_offline() {
		use tokio::io::{AsyncReadExt, AsyncWriteExt};

		let address = address();
		let acceptor = tls_acceptor(&address, &Tls::Upgrade).expect("self-signed acceptor assembles offline");
		let app = Router::new().route("/", axum::routing::get(|| async { "Hello, World!" }));

		let (stream_request, client_side) = DuplexStreamReq::pair(443);

		// Serve one connection on the "onion" side.
		let server = tokio::spawn(handle_tls_connection(stream_request, acceptor, app, CircuitId(21)));

		// Drive a real rustls client over the other half: handshake, then HTTP/1.1.
		let tls_config = tokio_rustls::rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(AcceptAnyCert)).with_no_client_auth();
		let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
		let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(address.host().to_string()).expect("the onion host is a valid server name");
		let mut tls = connector.connect(server_name, client_side).await.expect("TLS handshake against the self-signed acceptor");

		tls.write_all(
			format!(
				"GET / HTTP/1.1
Host: {}
Connection: close

",
				address.host()
			)
			.as_bytes(),
		)
		.await
		.expect("write request");
		tls.flush().await.expect("flush");

		let mut response = String::new();
		tls.read_to_string(&mut response).await.expect("read response");

		assert!(response.starts_with("HTTP/1.1 200"), "expected a 200, got: {}", response.lines().next().unwrap_or(""));
		assert!(response.contains("Hello, World!"), "the app body must come back through TLS + hyper + axum, got: {response:?}");

		server.await.expect("the serve task joins").expect("serving the connection succeeds");
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn the_port_80_arm_redirects_to_https_offline() {
		use tokio::io::{AsyncReadExt, AsyncWriteExt};

		let (stream_request, mut client_side) = DuplexStreamReq::pair(80);
		let server = tokio::spawn(handle_http_redirect(stream_request, "example.onion".to_string()));

		client_side
			.write_all(
				b"GET /a/b?c=d HTTP/1.1
Host: example.onion
Connection: close

",
			)
			.await
			.expect("write request");
		client_side.flush().await.expect("flush");

		let mut response = String::new();
		client_side.read_to_string(&mut response).await.expect("read response");

		assert!(response.starts_with("HTTP/1.1 301"), "expected a 301, got: {}", response.lines().next().unwrap_or(""));
		// The path and query must survive the redirect — dropping them would silently
		// send every deep link to the site root.
		assert!(response.contains("location: https://example.onion/a/b?c=d") || response.contains("Location: https://example.onion/a/b?c=d"), "redirect must preserve path and query, got: {response:?}");

		let _ = server.await.expect("the redirect task joins");
	}

	/// A `StreamHandler` that echoes back whatever it is sent, upper-cased — so a test can
	/// prove the bytes really traversed the dispatch path rather than merely that a
	/// handler was selected.
	struct ShoutingEcho;

	impl StreamHandler for ShoutingEcho {
		fn serve(&self, mut stream: crate::port_router::OnionStream) -> crate::port_router::ServeFuture {
			Box::pin(async move {
				use tokio::io::{AsyncReadExt, AsyncWriteExt};
				let mut buf = vec![0u8; 1024];
				let n = stream.read(&mut buf).await?;
				stream.write_all(buf[..n].to_ascii_uppercase().as_slice()).await?;
				stream.flush().await?;
				Ok(())
			})
		}
	}

	/// A `ServeContext` whose port table and plaintext policy the caller chooses.
	fn routed_context(metrics: &Arc<CircuitMetrics>, router: PortRouter, plaintext: tls_policy::PlaintextPolicy) -> ServeContext {
		let mut ctx = context(metrics);
		ctx.port_router = Arc::new(router);
		ctx.plaintext = plaintext;
		ctx
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn a_registered_raw_port_reaches_its_handler_offline() {
		use tokio::io::{AsyncReadExt, AsyncWriteExt};

		let mut router = PortRouter::new();
		router.register(9735, Arc::new(ShoutingEcho)).expect("9735 is a legal raw port");

		let metrics = Arc::new(CircuitMetrics::default());
		let ctx = routed_context(&metrics, router, tls_policy::PlaintextPolicy::Upgrade);

		let (stream_request, mut client_side) = DuplexStreamReq::pair(9735);
		let server = tokio::spawn(handle_stream_request(stream_request, ctx, CircuitId(31)));

		client_side.write_all(b"hello raw port").await.expect("write");
		client_side.flush().await.expect("flush");

		let mut response = Vec::new();
		client_side.read_to_end(&mut response).await.expect("read");

		// The bytes went out through the dispatch, into the handler, and back — the raw
		// path is not merely selected, it is connected.
		assert_eq!(response, b"HELLO RAW PORT", "the registered handler must actually see and answer the stream");
		server.await.expect("join").expect("serving the raw stream succeeds");
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn an_unregistered_port_is_refused_rather_than_served() {
		let metrics = Arc::new(CircuitMetrics::default());
		// Empty port table: nothing is registered on 9999.
		let ctx = routed_context(&metrics, PortRouter::new(), tls_policy::PlaintextPolicy::Upgrade);

		let (stream_request, _client_side, accepted) = DuplexStreamReq::pair_tracked(9999);
		// Bounded deliberately. A dispatch regression that accepted this stream would go
		// on to *serve* it and block on a client that never writes, so an unbounded await
		// would hang the suite rather than report a defect (confirmed by mutation).
		tokio::time::timeout(std::time::Duration::from_secs(5), handle_stream_request(stream_request, ctx, CircuitId(32))).await.expect("refusing an unregistered port must return immediately, not start serving it").expect("an unregistered port is a clean refusal, not an error");
		assert!(!accepted.load(Ordering::SeqCst), "an unregistered port must be refused without ever accepting the stream");
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn strict_tls_refuses_the_plaintext_port_instead_of_redirecting() {
		let metrics = Arc::new(CircuitMetrics::default());
		let ctx = routed_context(&metrics, PortRouter::new(), tls_policy::PlaintextPolicy::Reject);

		let (stream_request, _client_side, accepted) = DuplexStreamReq::pair_tracked(80);
		// Bounded for the same reason: falling through to the redirect handler would
		// accept the plaintext stream and then wait on it forever.
		tokio::time::timeout(std::time::Duration::from_secs(5), handle_stream_request(stream_request, ctx, CircuitId(33))).await.expect("strict TLS must refuse port 80 immediately, not accept and serve a redirect on it").expect("strict plaintext policy refuses port 80");
		// The property that matters: under `Tls::Strict` the plaintext stream is never
		// accepted at all — not accepted-then-redirected. Serving a redirect would mean
		// answering on a plaintext circuit, which is exactly what Strict forbids.
		assert!(!accepted.load(Ordering::SeqCst), "strict TLS must refuse port 80 without accepting the plaintext stream");
	}
}

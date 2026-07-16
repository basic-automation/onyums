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

use std::sync::Arc;

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
pub async fn serve_circuits(mut rend_requests: impl Stream<Item = RendRequest> + Send + Unpin, ctx: ServeContext, policy: Arc<dyn CircuitPolicy>) -> Result<()> {
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
		tokio::spawn(async move {
			handle_circuit_streams(streams, id, ctx, policy.as_ref()).await;
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
pub async fn handle_circuit_streams(mut streams: impl Stream<Item = StreamRequest> + Send + Unpin, id: CircuitId, ctx: ServeContext, policy: &dyn CircuitPolicy) {
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
				tokio::spawn(async move {
					if let Err(err) = handle_stream_request(stream_request, ctx, id).await {
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

#![warn(clippy::pedantic, clippy::nursery, clippy::all, clippy::cargo)]
#![allow(clippy::multiple_crate_versions, clippy::module_name_repetitions)]

//! # Onyums
//! Onyums is a simple axum wrapper for serving tor onion services.
//!
//! # Example
//! ```rust
//! use onyums::{serve, routing::get, Router};
//!
//! #[tokio::main]
//! async fn main() {
//!     let app = Router::new().route("/", get(|| async { "Hello, World!" }));
//!
//!     serve(app, "my_onion").await.unwrap();
//! }
//! ```

use std::{net::SocketAddr, sync::Mutex};

use anyhow::{bail, Result};
use arti_client::{config::TorClientConfigBuilder, TorClient};
use axum::extract::connect_info::Connected as AxumConnected;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use http_body_util::Empty;
use hyper::{body::Incoming, Request, Response, StatusCode};
use hyper_util::{
	rt::{TokioExecutor, TokioIo}, service::TowerToHyperService
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hsservice::{config::OnionServiceConfigBuilder, HsNickname, RendRequest, RunningOnionService, StreamRequest};
use tor_proto::client::stream::IncomingStreamRequest;
use tor_rtcompat::tokio::TokioNativeTlsRuntime;
use safelog::DisplayRedacted;
use tower_service::Service;
use tracing::{event, span, Level};
extern crate rcgen;
use std::sync::Arc;

pub use axum::*;
pub use onyums_skin::{self, AccountingCircuitPolicy, CircuitPolicy, Skin};
use onyums_skin::CircuitId;

mod circuit_gate;
mod vanity;
pub use vanity::{mine, mine_parallel, mine_within, validate_prefix, VanityKey};

use circuit_gate::{CircuitDisposition, CircuitIdAllocator, StreamDisposition};
use rcgen::generate_simple_self_signed;
use tokio_rustls::{
	rustls, rustls::pki_types::{pem::PemObject, PrivateKeyDer, PrivatePkcs8KeyDer}, TlsAcceptor
};

/// A Tor v3 onion service address — the service's public identity.
///
/// Normalized to exactly one trailing `.onion` suffix, so it is safe to use
/// directly as a TLS subject-alternative-name or an HTTP redirect host. This is
/// the typed replacement for the stringly-typed, process-global onion name: the
/// address is threaded explicitly from the launched service to the handlers that
/// need it (TLS cert generation, the port-80 → HTTPS redirect) rather than read
/// from a shared `static`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnionAddress(String);

impl OnionAddress {
	/// Normalize a raw onion service name to exactly one trailing `.onion`
	/// suffix, handling a bare name, a single suffix, or accidental repetition.
	///
	/// This *trusts* its input — it only fixes the suffix and does not check that
	/// the name is a real v3 onion address. Use it for names that came from arti
	/// itself (the launched service). For operator- or user-supplied strings,
	/// prefer the validating [`Self::parse`].
	#[must_use]
	pub fn normalized(name: &str) -> Self {
		Self(format!("{}.onion", name.trim_end_matches(".onion")))
	}

	/// Parse and *validate* a v3 `.onion` address.
	///
	/// Unlike [`Self::normalized`], this confirms the string is a real v3 onion
	/// name — correct length, base32 alphabet, checksum, and version — by
	/// round-tripping it through arti's own `HsId` parser, then returns the
	/// canonical lowercase form. The input must be a bare `<base32>.onion` host
	/// (no scheme, path, or subdomain); surrounding whitespace is trimmed.
	///
	/// # Errors
	/// Returns an error if the string is not a valid v3 onion address.
	pub fn parse(address: &str) -> Result<Self> {
		let hsid: tor_hscrypto::pk::HsId = address.trim().parse().map_err(|e| anyhow::anyhow!("invalid v3 onion address: {e}"))?;
		Ok(Self::normalized(&hsid.display_unredacted().to_string()))
	}

	/// The full address, including the `.onion` suffix.
	#[must_use]
	pub fn as_str(&self) -> &str {
		&self.0
	}

	/// The host used for TLS SANs and redirect targets. Identical to
	/// [`Self::as_str`]; named for intent at the call site.
	#[must_use]
	pub fn host(&self) -> &str {
		&self.0
	}

	/// The canonical HTTPS URL for this service.
	///
	/// onyums serves HTTPS on port 443 (with a port-80 → HTTPS redirect), so this
	/// is the URL clients should use.
	#[must_use]
	pub fn https_url(&self) -> String {
		format!("https://{}/", self.0)
	}

	/// The plain-HTTP URL (port 80). onyums redirects this to [`Self::https_url`].
	#[must_use]
	pub fn http_url(&self) -> String {
		format!("http://{}/", self.0)
	}

	/// The value for an [`Onion-Location`] response header (or its
	/// `<meta http-equiv="onion-location">` equivalent): the canonical onion URL a
	/// clearnet site emits to point Tor Browser at its onion equivalent.
	///
	/// [`Onion-Location`]: https://community.torproject.org/onion-services/advanced/onion-location/
	#[must_use]
	pub fn onion_location(&self) -> String {
		self.https_url()
	}

	/// The `(name, value)` pair for the `Onion-Location` response header, ready to
	/// insert into a response. The name is lowercase, as is conventional for HTTP/2.
	#[must_use]
	pub fn onion_location_header(&self) -> (&'static str, String) {
		("onion-location", self.onion_location())
	}
}

impl std::fmt::Display for OnionAddress {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.0)
	}
}

impl From<OnionAddress> for String {
	fn from(address: OnionAddress) -> Self {
		address.0
	}
}

/// Sets up and bootstraps a Tor client.
///
/// Uses onyums-specific state and cache directories (`./tor/onyums/state`,
/// `./tor/onyums/cache`) rather than arti's shared `TorClientConfig::default()`
/// location. This keeps the cache from growing without bound across runs while
/// staying isolated from any sibling arti instance on the machine (e.g. an
/// artiqwest client using `./tor/arti`), avoiding a state-directory collision.
async fn setup_tor_client() -> Result<Arc<TorClient<TokioNativeTlsRuntime>>> {
	event!(Level::INFO, "Creating Tor client...");
	let config = TorClientConfigBuilder::from_directories("./tor/onyums/state", "./tor/onyums/cache")
		.build()
		.map_err(|e| anyhow::anyhow!("Failed to build Tor client config: {e}"))?;
	let runtime = TokioNativeTlsRuntime::current().map_err(|_| anyhow::anyhow!("Failed to get current tokio runtime."))?;
	let client = TorClient::with_runtime(runtime);
	client.config(config).create_bootstrapped().await.map_err(|_| anyhow::anyhow!("Failed to create bootstrapped Tor client."))
}

/// Launches an onion service with the given nickname.
///
/// The returned request stream is self-contained (`use<>`) — it does not borrow
/// the client — so callers can move the client elsewhere (e.g. into a handle)
/// while keeping the stream.
fn launch_onion_service(client: &TorClient<TokioNativeTlsRuntime>, nickname: &str) -> Result<(Arc<RunningOnionService>, impl Stream<Item = RendRequest> + use<>)> {
	event!(Level::INFO, "Launching onion service...");
	let nickname = nickname.parse::<HsNickname>().map_err(|_| anyhow::anyhow!("Failed to parse nickname."))?;
	let svc_cfg = OnionServiceConfigBuilder::default().nickname(nickname).build().map_err(|_| anyhow::anyhow!("Failed to build onion service config."))?;
	client.launch_onion_service(svc_cfg)
		.map_err(|_| anyhow::anyhow!("Failed to launch onion service."))?
		.ok_or_else(|| anyhow::anyhow!("Onion service launch returned None"))
}

/// Retrieves the onion service address from the launched service.
fn get_onion_address(service: &Arc<RunningOnionService>) -> Result<OnionAddress> {
	event!(Level::INFO, "Getting the onion service name...");
	let service_name = service.onion_address().ok_or_else(|| anyhow::anyhow!("Failed to get onion service name."))?.display_unredacted().to_string();
	event!(Level::INFO, "Onion service name: {service_name}");

	let address = OnionAddress::normalized(&service_name);
	event!(Level::INFO, "Cleaned onion service name: {address}");
	Ok(address)
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
async fn serve_circuits(mut rend_requests: impl Stream<Item = RendRequest> + Send + Unpin, app: Router, tls_acceptor: TlsAcceptor, address: OnionAddress, policy: Arc<dyn CircuitPolicy>) -> Result<()> {
	event!(Level::INFO, "Waiting for incoming rendezvous circuits...");
	let allocator = Arc::new(CircuitIdAllocator::new());
	while let Some(rend_request) = rend_requests.next().await {
		let circuit_span = span!(Level::INFO, "onyums - new_circuit");
		let _circuit_guard = circuit_span.enter();
		let id = allocator.next_id();

		// Consult the policy at the circuit boundary before accepting.
		if circuit_gate::circuit_disposition(policy.on_new_circuit(&id)) == CircuitDisposition::Drop {
			event!(Level::INFO, "Circuit {} rejected by policy on offer.", id.0);
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

		let app = app.clone();
		let tls_acceptor = tls_acceptor.clone();
		let address = address.clone();
		let policy = policy.clone();
		tokio::spawn(async move {
			handle_circuit_streams(streams, id, app, tls_acceptor, address, policy.as_ref()).await;
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
async fn handle_circuit_streams(mut streams: impl Stream<Item = StreamRequest> + Send + Unpin, id: CircuitId, app: Router, tls_acceptor: TlsAcceptor, address: OnionAddress, policy: &dyn CircuitPolicy) {
	while let Some(stream_request) = streams.next().await {
		let stream_span = span!(Level::INFO, "onyums - incoming_stream");
		let _stream_guard = stream_span.enter();
		let port = match stream_request.request() {
			IncomingStreamRequest::Begin(begin) => begin.port(),
			_ => 0,
		};
		let target = circuit_gate::stream_target(port);

		match circuit_gate::stream_disposition(policy.on_new_stream(&id, &target)) {
			StreamDisposition::Serve => {
				let app = app.clone();
				let tls_acceptor = tls_acceptor.clone();
				let address = address.clone();
				tokio::spawn(async move {
					if let Err(err) = handle_stream_request(stream_request, tls_acceptor, app, &address, id).await {
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

/// Initializes the onion service and returns the service and request stream.
fn initialize_onion_service(client: &TorClient<TokioNativeTlsRuntime>, nickname: &str) -> Result<(Arc<RunningOnionService>, OnionAddress, impl Stream<Item = RendRequest> + use<>)> {
	let (service, request_stream) = launch_onion_service(client, nickname)?;
	let address = get_onion_address(&service)?;
	Ok((service, address, request_stream))
}

/// A running onion service plus its controls.
///
/// Returned by [`OnionServiceBuilder::serve`]. The accept loop runs on a spawned
/// task; this handle is how you observe readiness, read the stable `.onion`
/// address, and stop the service — the per-service replacement for the old
/// poll-the-global `get_onion_name()` pattern.
///
/// Dropping the handle drops the underlying Tor client and onion service, tearing
/// the service down. Use [`Self::shutdown`] for a graceful stop you can await.
pub struct OnionServiceHandle {
	address: OnionAddress,
	service: Arc<RunningOnionService>,
	// Kept alive so the onion service's background machinery (intro points,
	// descriptor publishing) keeps running for the lifetime of the handle.
	_client: Arc<TorClient<TokioNativeTlsRuntime>>,
	cancel: CancellationToken,
	task: Mutex<Option<JoinHandle<()>>>,
}

impl OnionServiceHandle {
	/// The service's stable `.onion` address.
	#[must_use]
	pub const fn onion_address(&self) -> &OnionAddress {
		&self.address
	}

	/// Resolve once the service is believed to be fully reachable — its
	/// descriptor is published and its introduction points are satisfactory.
	///
	/// This is the meaningful sense of "ready": after it returns, clients can
	/// actually reach the service, unlike the old global which was populated the
	/// instant the address was known (long before the descriptor was up).
	pub async fn ready(&self) {
		if self.service.status().state().is_fully_reachable() {
			return;
		}
		let mut events = self.service.status_events();
		while let Some(status) = events.next().await {
			if status.state().is_fully_reachable() {
				return;
			}
		}
	}

	/// Stop accepting new connections and await the accept loop's exit.
	///
	/// Cancels the spawned accept loop via its [`CancellationToken`] and joins
	/// the task. Idempotent: a second call is a no-op. Full teardown of the Tor
	/// client and onion service happens when the handle is dropped.
	pub async fn shutdown(&self) {
		self.cancel.cancel();
		let task = self.task.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
		if let Some(task) = task {
			let _ = task.await;
		}
	}

	/// Await the accept loop's natural exit without cancelling it.
	///
	/// Used by the blocking [`serve`] wrapper to preserve the historical
	/// "runs until it stops" contract.
	async fn join(&self) {
		let task = self.task.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
		if let Some(task) = task {
			let _ = task.await;
		}
	}
}

/// How the onyums-skin abuse-defense gate is applied to the served router.
///
/// Secure by default: with no explicit choice, the secure-default Skin gate is
/// on. You opt *down* (`no_skin`) or *across* (a custom [`Skin`]), never *up*.
#[derive(Default)]
enum SkinChoice {
	/// Apply [`Skin::secure_default`] — the frontier secure-by-default posture.
	#[default]
	Default,
	/// Apply a caller-supplied gate. Boxed: a `Skin` is much larger than the unit
	/// variants.
	Custom(Box<Skin>),
	/// No Skin gate — an explicit opt-down.
	Disabled,
}

/// Apply the chosen Skin gate to the router. Extracted from `serve` so the gate
/// wiring is testable with `tower::ServiceExt::oneshot` and no live Tor network.
fn apply_skin(app: Router, skin: SkinChoice) -> Router {
	match skin {
		SkinChoice::Default => app.layer(Skin::secure_default().into_layer()),
		SkinChoice::Custom(skin) => app.layer((*skin).into_layer()),
		SkinChoice::Disabled => app,
	}
}

/// Builder for an [`OnionServiceHandle`] — the full secure stack, tuned where you
/// need it.
///
/// Obtain one from [`OnionService::builder`].
#[derive(Default)]
pub struct OnionServiceBuilder {
	router: Option<Router>,
	nickname: Option<String>,
	skin: SkinChoice,
	circuit_policy: Option<Arc<dyn CircuitPolicy>>,
}

impl OnionServiceBuilder {
	/// Set the axum [`Router`] to serve. Required.
	#[must_use]
	pub fn router(mut self, app: Router) -> Self {
		self.router = Some(app);
		self
	}

	/// Set the onion service nickname (its local keystore identity). Required.
	#[must_use]
	pub fn nickname(mut self, nickname: impl Into<String>) -> Self {
		self.nickname = Some(nickname.into());
		self
	}

	/// Replace the default Skin gate with a caller-tuned [`Skin`].
	///
	/// The secure-default gate (`PoW` + no-JS patience fallback + token rate
	/// limiting) is *already on* without this call; use it only to tune the gate,
	/// not to enable it. See [`Skin::builder`].
	#[must_use]
	pub fn skin(mut self, skin: Skin) -> Self {
		self.skin = SkinChoice::Custom(Box::new(skin));
		self
	}

	/// Set the per-rendezvous-circuit [`CircuitPolicy`] driving the Tor-layer gate
	/// (accept / per-stream reject / whole-circuit teardown, plus per-circuit
	/// accounting).
	///
	/// Defaults to an accept-all [`AccountingCircuitPolicy`] — it changes no behaviour
	/// but begins per-circuit accounting. Supply a tuned policy (stream/request/byte
	/// caps, Under Attack Mode) to enforce circuit-level limits the HTTP gate cannot
	/// express. The policy is shared across all circuits, so it must be `Send + Sync`.
	#[must_use]
	pub fn circuit_policy(mut self, policy: Arc<dyn CircuitPolicy>) -> Self {
		self.circuit_policy = Some(policy);
		self
	}

	/// Opt *down*: serve the router with no Skin abuse-defense gate.
	///
	/// An explicit, named relaxation of the secure default — the gate is on
	/// unless you call this.
	#[must_use]
	pub fn no_skin(mut self) -> Self {
		self.skin = SkinChoice::Disabled;
		self
	}

	/// Launch the onion service and return a handle once the address is known.
	///
	/// The Tor client is bootstrapped and the service launched before this
	/// returns, so [`OnionServiceHandle::onion_address`] is immediately
	/// available; the accept loop then runs on a spawned task. Await
	/// [`OnionServiceHandle::ready`] for actual reachability.
	///
	/// # Errors
	/// Returns an error if the router or nickname is unset, the nickname fails to
	/// parse, the Tor client fails to bootstrap, the onion service fails to
	/// launch, or the TLS acceptor fails to build.
	pub async fn serve(self) -> Result<OnionServiceHandle> {
		let serve_trace_span = span!(Level::INFO, "onyums - serve");
		let _info_trace_guard = serve_trace_span.enter();
		event!(Level::INFO, "Setting up onion service...");

		let app = self.router.ok_or_else(|| anyhow::anyhow!("router not set on OnionServiceBuilder"))?;
		let nickname = self.nickname.ok_or_else(|| anyhow::anyhow!("nickname not set on OnionServiceBuilder"))?;

		// Insert the onyums-skin gate ahead of the application on the HTTP path
		// (Phase 2 Skin integration). Secure-by-default unless the caller opted down
		// with `no_skin`. `Router::layer` keeps the `Router` type, so the rest of the
		// serve path is unchanged.
		let app = apply_skin(app, self.skin);

		// The per-circuit Tor-layer gate. Secure-by-default but non-disruptive: an
		// accept-all accounting policy unless the caller supplied a tuned one.
		let policy: Arc<dyn CircuitPolicy> = self.circuit_policy.unwrap_or_else(|| Arc::new(AccountingCircuitPolicy::new()));

		let client = setup_tor_client().await?;
		let (service, address, request_stream) = initialize_onion_service(&client, &nickname)?;
		let tls_acceptor = tls_acceptor(&address)?;

		let cancel = CancellationToken::new();
		let loop_cancel = cancel.clone();
		let loop_address = address.clone();
		let task = tokio::spawn(async move {
			let rend_requests = Box::pin(request_stream);
			tokio::select! {
				() = loop_cancel.cancelled() => {
					event!(Level::INFO, "Onion service accept loop cancelled.");
				}
				result = serve_circuits(rend_requests, app, tls_acceptor, loop_address, policy) => {
					if let Err(err) = result {
						event!(Level::ERROR, "Onion service accept loop ended with error: {err}");
					} else {
						event!(Level::INFO, "Onion service accept loop ended.");
					}
				}
			}
		});

		Ok(OnionServiceHandle { address, service, _client: client, cancel, task: Mutex::new(Some(task)) })
	}
}

/// Entry point for the builder API.
///
/// `OnionService::builder()` returns the same full secure stack `serve()` gives
/// you, with hooks to tune or relax the defaults.
pub struct OnionService;

impl OnionService {
	/// Start building an onion service.
	#[must_use]
	pub fn builder() -> OnionServiceBuilder {
		OnionServiceBuilder::default()
	}
}

/// Serve a web application over an onion service, blocking until it stops.
///
/// A thin wrapper over [`OnionService::builder`] that preserves the original
/// one-line entry point and its "runs until the service stops" contract. For
/// readiness, the address, or graceful shutdown, use the builder directly and
/// hold the returned [`OnionServiceHandle`].
///
/// # Arguments
/// `app` - The axum `Router` to serve.
/// `nickname` - The nickname of the onion service.
///
/// # Returns
/// An `anyhow::Result` indicating success or failure.
///
/// # Errors
/// This function returns an error if any of the following occur:
/// - The nickname fails to parse.
/// - The onion service fails to launch.
/// - The TLS acceptor fails to create.
/// - The Tor client fails to create.
/// - The Tor client fails to bootstrap.
pub async fn serve(app: Router, nickname: &str) -> Result<()> {
	let handle = OnionService::builder().router(app).nickname(nickname).serve().await?;
	// Preserve the historical contract: block until the accept loop stops.
	handle.join().await;
	event!(Level::INFO, "Onion service exited cleanly.");
	bail!("Onion service exited cleanly");
}

/// Handles a TLS connection on port 443.
async fn handle_tls_connection(stream_request: StreamRequest, tls_acceptor: TlsAcceptor, app: Router, circuit_id: CircuitId) -> Result<()> {
	event!(Level::INFO, "Accepting the incoming stream and wrapping it in a TLS stream...");
	let onion_service_stream = stream_request.accept(Connected::new_empty()).await.map_err(|_| anyhow::anyhow!("failed to accept onion service stream"))?;

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
async fn handle_http_redirect(stream_request: StreamRequest, requested_host: String) -> Result<()> {
	event!(Level::INFO, "Accepting plain HTTP request on port 80 and redirecting to HTTPS.");
	let onion_service_stream = stream_request.accept(Connected::new_empty()).await.map_err(|_| anyhow::anyhow!("failed to accept onion service stream"))?;

	let stream = TokioIo::new(onion_service_stream);

	let hyper_service = hyper::service::service_fn(move |req: Request<Incoming>| {
		let host = requested_host.clone();
		let path = req.uri().path_and_query().map_or("", |p| p.as_str());
		let redirect_uri = format!("https://{host}{path}");
		async move { Ok::<_, std::convert::Infallible>(Response::builder().status(StatusCode::MOVED_PERMANENTLY).header("Location", redirect_uri).body(Empty::<Bytes>::new()).unwrap()) }
	});

	hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).http1_only().serve_connection(stream, hyper_service).await.map_err(|err| anyhow::anyhow!("Error serving HTTP redirect: {err}"))
}

#[derive(Clone, Debug, Default)]
pub struct ConnectionInfo {
	pub circuit_id: Option<String>,
	pub socket_addr: Option<SocketAddr>,
}

impl AxumConnected<Request<Incoming>> for ConnectionInfo {
	fn connect_info(target: Request<Incoming>) -> Self {
		Self { circuit_id: target.extensions().get::<Self>().unwrap().circuit_id.clone(), socket_addr: None }
	}
}

impl AxumConnected<Self> for ConnectionInfo {
	fn connect_info(target: Self) -> Self {
		target
	}
}

// Move tls_acceptor function up, before serve
fn tls_acceptor(address: &OnionAddress) -> Result<TlsAcceptor> {
	let subject_alt_names = vec![address.host().to_string()];
	let cert = generate_simple_self_signed(subject_alt_names).unwrap();

	let key_der = match PrivatePkcs8KeyDer::from_pem_slice(cert.signing_key.serialize_pem().as_bytes()) {
		Ok(key_der) => PrivateKeyDer::Pkcs8(key_der),
		Err(e) => {
			event!(Level::ERROR, "Error converting key to der: {e:?}");
			bail!(format!("Error converting key to der: {e:?}"))
		}
	};
	let server_config = match rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()], key_der) {
		Ok(server_config) => server_config,
		Err(e) => {
			event!(Level::ERROR, "Error creating server config: {e:?}");
			bail!(format!("Error creating server config: {e:?}"))
		}
	};
	let acceptor = TlsAcceptor::from(Arc::new(server_config));
	Ok(acceptor)
}

// Then handle_stream_request
async fn handle_stream_request(stream_request: StreamRequest, tls_acceptor: TlsAcceptor, app: Router, address: &OnionAddress, circuit_id: CircuitId) -> Result<()> {
	let handling_request_trace_span = span!(Level::INFO, "onyums - handling_request");
	let _handling_request_trace_guard = handling_request_trace_span.enter();
	match stream_request.request().clone() {
		// Clone request to use `begin` later
		IncomingStreamRequest::Begin(begin) if begin.port() == 443 => {
			// Only handle port 443 for TLS
			handle_tls_connection(stream_request, tls_acceptor, app, circuit_id).await
		}
		IncomingStreamRequest::Begin(begin) if begin.port() == 80 => {
			// Handle Port 80 (Plain HTTP) - Redirect to HTTPS
			handle_http_redirect(stream_request, address.host().to_string()).await
		}
		_ => {
			// Reject the incoming request
			event!(Level::INFO, "Rejecting the incoming request {:?}...", stream_request.request());
			stream_request.shutdown_circuit().map_err(|e| anyhow::anyhow!("Failed to shutdown circuit: {e}"))
		}
	}
}

#[cfg(test)]
mod tests {
	use axum::{routing::get, Router};

	use super::*;

	#[test]
	fn onion_address_normalizes_bare_name() {
		let address = OnionAddress::normalized("abcdef");
		assert_eq!(address.as_str(), "abcdef.onion");
		assert_eq!(address.host(), "abcdef.onion");
	}

	#[test]
	fn onion_address_keeps_single_suffix() {
		let address = OnionAddress::normalized("abcdef.onion");
		assert_eq!(address.as_str(), "abcdef.onion");
	}

	#[test]
	fn onion_address_collapses_repeated_suffix() {
		let address = OnionAddress::normalized("abcdef.onion.onion");
		assert_eq!(address.as_str(), "abcdef.onion");
	}

	#[test]
	fn onion_address_display_and_into_string_match() {
		let address = OnionAddress::normalized("abcdef");
		assert_eq!(address.to_string(), "abcdef.onion");
		let owned: String = address.into();
		assert_eq!(owned, "abcdef.onion");
	}

	#[test]
	fn parse_accepts_a_valid_mined_address_and_canonicalizes() {
		// Mining yields a guaranteed-valid v3 address; `parse` must accept it and
		// round-trip to the same canonical form.
		let key = vanity::mine_within("a", 50_000).expect("valid prefix").expect("should find a match");
		let canonical = key.address().as_str();
		let parsed = OnionAddress::parse(canonical).expect("a mined address must validate");
		assert_eq!(&parsed, key.address());
		// Surrounding whitespace is tolerated.
		let parsed_padded = OnionAddress::parse(&format!("  {canonical}  ")).expect("whitespace should be trimmed");
		assert_eq!(&parsed_padded, key.address());
	}

	#[test]
	fn parse_rejects_invalid_addresses() {
		let key = vanity::mine_within("a", 50_000).expect("valid prefix").expect("should find a match");
		let valid = key.address().as_str();

		// Not an onion domain at all.
		assert!(OnionAddress::parse("example.com").is_err());
		// A bare name with no suffix is not accepted by the strict parser.
		assert!(OnionAddress::parse("abcdef").is_err());
		// A subdomain in front of a valid address is rejected.
		assert!(OnionAddress::parse(&format!("www.{valid}")).is_err());

		// Corrupt the public-key region (first base32 char) so the checksum no
		// longer matches — a single flip is overwhelmingly likely to be rejected.
		let mut chars: Vec<char> = valid.chars().collect();
		chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
		let corrupted: String = chars.into_iter().collect();
		assert!(OnionAddress::parse(&corrupted).is_err(), "a corrupted checksum must be rejected");
	}

	#[test]
	fn url_and_onion_location_helpers_format_correctly() {
		let address = OnionAddress::normalized("abcdef");
		assert_eq!(address.https_url(), "https://abcdef.onion/");
		assert_eq!(address.http_url(), "http://abcdef.onion/");
		assert_eq!(address.onion_location(), "https://abcdef.onion/");
		let (name, value) = address.onion_location_header();
		assert_eq!(name, "onion-location");
		assert_eq!(value, "https://abcdef.onion/");
	}

	#[tokio::test]
	async fn no_skin_passes_requests_through() {
		use tower::ServiceExt as _;

		let app = apply_skin(Router::new().route("/", get(|| async { "ok" })), SkinChoice::Disabled);
		let response = app.oneshot(Request::builder().uri("/").body(axum::body::Body::empty()).unwrap()).await.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
	}

	#[tokio::test]
	async fn default_skin_gates_uncleared_requests() {
		use http_body_util::BodyExt as _;
		use tower::ServiceExt as _;

		// An uncleared request must be intercepted by the gate and never reach the
		// app. The secure-default gate answers with the PoW interstitial (a 200 HTML
		// challenge page), so we assert on the body, not the status: the app's
		// "secret" must not leak, and the challenge page must be served instead.
		let app = apply_skin(Router::new().route("/", get(|| async { "secret" })), SkinChoice::Default);
		let response = app.oneshot(Request::builder().uri("/").body(axum::body::Body::empty()).unwrap()).await.unwrap();
		let body = response.into_body().collect().await.unwrap().to_bytes();
		let body = String::from_utf8_lossy(&body);
		assert!(!body.contains("secret"), "the gated app response must not leak");
		assert!(body.contains("Checking your connection"), "the challenge interstitial should be served, got: {body}");
	}

	#[tokio::test]
	async fn builder_rejects_missing_router() {
		// Validation happens before any Tor bootstrap, so this needs no network.
		let result = OnionService::builder().nickname("no_router").serve().await;
		let err = result.err().expect("missing router should error");
		assert!(err.to_string().contains("router not set"), "unexpected error: {err}");
	}

	#[tokio::test]
	async fn builder_rejects_missing_nickname() {
		let app = Router::new().route("/", get(|| async { "hi" }));
		let result = OnionService::builder().router(app).serve().await;
		let err = result.err().expect("missing nickname should error");
		assert!(err.to_string().contains("nickname not set"), "unexpected error: {err}");
	}

	#[tokio::test]
	async fn test_serve() {
		let tracing_subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).finish();
		tracing::subscriber::set_global_default(tracing_subscriber).expect("setting default subscriber failed");

		let app = Router::new().route("/", get(|| async { "Hello, World!" }));
		let nickname = "onyums-yum-yum-test2";

		match serve(app, nickname).await {
			Ok(()) => (),
			Err(e) => event!(Level::DEBUG, "Error serving onion service: {e}"),
		}
	}
}

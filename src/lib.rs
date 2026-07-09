#![warn(clippy::pedantic, clippy::nursery, clippy::all, clippy::cargo)]
#![allow(clippy::multiple_crate_versions, clippy::module_name_repetitions)]
// onyums contains no `unsafe` of its own — forbid it outright (axum/axum-extra advertise
// the same), so any future `unsafe` is a hard compile error, not a silent regression.
#![forbid(unsafe_code)]

//! # Onyums
//! Onyums is a simple axum wrapper for serving tor onion services.
//!
//! # Example
//! ```rust,no_run
//! use onyums::{serve, routing::get, Router};
//!
//! #[tokio::main]
//! async fn main() {
//!     let app = Router::new().route("/", get(|| async { "Hello, World!" }));
//!
//!     serve(app, "my_onion").await.unwrap();
//! }
//! ```
//! `no_run`: `serve` binds the live Tor network and runs until stopped, so the
//! example is compiled and type-checked but never executed under `cargo test`.

use std::{net::SocketAddr, sync::Mutex};

use anyhow::{bail, Result};
use arti_client::{config::TorClientConfigBuilder, TorClient, TorClientConfig};
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
use tor_hsservice::{
	config::{restricted_discovery::HsClientNickname, OnionServiceConfig, OnionServiceConfigBuilder}, HsNickname, RendRequest, RunningOnionService, StreamRequest
};
use tor_hscrypto::pk::HsClientDescEncKey;
use tor_proto::client::stream::IncomingStreamRequest;
use tor_rtcompat::tokio::TokioNativeTlsRuntime;
use safelog::DisplayRedacted;
use tower_service::Service;
use tracing::{event, span, Level};
extern crate rcgen;
use std::sync::Arc;

pub use axum::*;
pub use onyums_skin::{self, AccountingCircuitPolicy, CircuitPolicy, ClientAuthKey, RestrictedDiscovery, SecurityEvent, SecurityEventSink, Skin};
use onyums_skin::CircuitId;

/// Re-export the arti stack onyums is built on, so downstream crates can depend on the
/// *exact* versions onyums uses without a version skew — the same reason `axum` is
/// re-exported above. If you need arti's `TorClient`, the onion-service config, or the
/// onion key types (e.g. to build a custom [`CircuitPolicy`] or an authorized-clients
/// allowlist from raw keys), reach them through `onyums::arti_client` / `onyums::tor_*`
/// rather than adding your own `arti-client` / `tor-*` dependency.
pub use {arti_client, tor_cell, tor_cert, tor_hscrypto, tor_hsservice, tor_llcrypto, tor_proto, tor_rtcompat};

mod circuit_gate;
mod client_auth;
mod port_router;
mod raw_tcp;
mod provided_cert;
mod tls_policy;
mod vanity;
pub use client_auth::{provision_client, ClientAuthKeypair, ClientAuthKeypairError};
pub use port_router::{AsyncStream, OnionStream, PortDispatch, PortRouter, ServeFuture, StreamHandler};
pub use raw_tcp::RawTcpHandler;
pub use provided_cert::ProvidedCert;
pub use tls_policy::Tls;
pub use vanity::{address_from_expanded_secret, address_from_secret_seed, address_from_tor_secret_key_file, expanded_secret_from_tor_file, mine, mine_parallel, mine_within, tor_secret_key_file_from_expanded, validate_prefix, VanityKey};

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

	/// Render a scannable QR code of the service's canonical HTTPS URL as a
	/// standalone SVG document string.
	///
	/// The QR encodes [`Self::https_url`] — the URL a client should actually open
	/// — so a Tor Browser user can scan it instead of typing 56 base32 characters
	/// by hand. The output is pure text (an `<svg>` document); onyums pulls in no
	/// raster-image dependency for this (`qrcode` is built with its `image`
	/// renderer disabled), keeping the tree pure Rust.
	///
	/// # Panics
	/// Never in practice: the encoded data is a fixed-shape onion URL (~70 bytes),
	/// far below the smallest QR version's capacity, so encoding cannot fail.
	#[must_use]
	pub fn qr_svg(&self) -> String {
		use qrcode::{render::svg, QrCode};
		// The encoded data is a fixed-shape onion URL (~70 bytes), far below the
		// capacity of even the smallest QR version, so construction cannot fail.
		let code = QrCode::new(self.https_url().as_bytes()).expect("an onion URL always fits in a QR code");
		code.render::<svg::Color>().min_dimensions(256, 256).quiet_zone(true).build()
	}

	/// Render a scannable QR code of the service's canonical HTTPS URL as Unicode
	/// text suitable for printing to a terminal.
	///
	/// Like [`Self::qr_svg`] but rendered with half-block characters
	/// (`unicode::Dense1x2`), so an operator can print the address as a QR code
	/// straight to the console — e.g. right after the service reports ready. Each
	/// QR row maps to one line of output.
	///
	/// # Panics
	/// Never in practice, for the same reason as [`Self::qr_svg`]: an onion URL
	/// always fits in a QR code.
	#[must_use]
	pub fn qr_terminal(&self) -> String {
		use qrcode::{render::unicode, QrCode};
		let code = QrCode::new(self.https_url().as_bytes()).expect("an onion URL always fits in a QR code");
		code.render::<unicode::Dense1x2>().quiet_zone(true).build()
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

/// The default persistent onyums state directory — home of the Arti keystore that
/// holds the onion service's v3 identity key, so the `.onion` address is stable
/// across restarts (onyums ROADMAP Phase 1). Kept under `./tor/onyums` rather than
/// arti's shared default so onyums never collides with a sibling arti instance.
const PERSISTENT_STATE_DIR: &str = "./tor/onyums/state";
/// The default onyums cache directory (disposable per arti's `/var/cache` rules).
/// Shared by both the persistent and ephemeral identity modes: the cached network
/// directory is not identity-bearing, so an ephemeral service reuses it to avoid
/// re-downloading the consensus on every throwaway launch.
const CACHE_DIR: &str = "./tor/onyums/cache";

/// Resolve the `(state_dir, cache_dir)` pair for the chosen identity mode
/// (onyums ROADMAP Phase 1).
///
/// Persistent (`ephemeral == false`, the default) returns the fixed
/// [`PERSISTENT_STATE_DIR`], so the keystore — and therefore the `.onion` address —
/// survives restarts. Ephemeral (`ephemeral == true`) returns a *unique*, throwaway
/// state directory under the system temp dir, so each launch starts with an empty
/// keystore, Arti generates a fresh identity key, and the service comes up on a new,
/// disposable address that is never written to the persistent tree. The cache dir is
/// [`CACHE_DIR`] in both modes (it holds no identity material).
///
/// This is a pure function so the directory logic is unit-testable with no live Tor
/// network: the ephemeral path is distinct per call, the persistent path is stable.
fn storage_dirs(ephemeral: bool) -> (String, String) {
	if ephemeral {
		// A unique per-launch suffix (pid + a CSPRNG draw) so two ephemeral services
		// in one process — or successive restarts — never share a keystore and thus
		// never reuse an address. The directory lives under the OS temp tree, outside
		// the persistent `./tor/onyums` state.
		let unique = format!("onyums-ephemeral-{}-{:016x}", std::process::id(), rand::random::<u64>());
		let state_dir = std::env::temp_dir().join(unique);
		(state_dir.to_string_lossy().into_owned(), CACHE_DIR.to_string())
	} else {
		(PERSISTENT_STATE_DIR.to_string(), CACHE_DIR.to_string())
	}
}

/// Assemble a [`TorClientConfig`] for the given state/cache directories.
///
/// Extracted from [`setup_tor_client`] so the config assembly — the offline half of
/// client setup — is unit-testable without bootstrapping the Tor network: `build`
/// only validates and stores the directory paths (the dirs are created and the
/// network reached later, at bootstrap).
///
/// # Errors
/// Returns an error if Arti rejects the directory configuration.
fn tor_client_config(state_dir: &str, cache_dir: &str) -> Result<TorClientConfig> {
	TorClientConfigBuilder::from_directories(state_dir, cache_dir)
		.build()
		.map_err(|e| anyhow::anyhow!("Failed to build Tor client config: {e}"))
}

/// Sets up and bootstraps a Tor client for the given state/cache directories.
///
/// Uses onyums-specific state and cache directories (see [`storage_dirs`]) rather
/// than arti's shared `TorClientConfig::default()` location. This keeps the cache
/// from growing without bound across runs while staying isolated from any sibling
/// arti instance on the machine (e.g. an artiqwest client using `./tor/arti`),
/// avoiding a state-directory collision. For an ephemeral service the caller passes a
/// throwaway temp directory so the service's identity does not persist.
async fn setup_tor_client(state_dir: &str, cache_dir: &str) -> Result<Arc<TorClient<TokioNativeTlsRuntime>>> {
	event!(Level::INFO, "Creating Tor client...");
	let config = tor_client_config(state_dir, cache_dir)?;
	let runtime = TokioNativeTlsRuntime::current().map_err(|e| anyhow::anyhow!("Failed to get current tokio runtime: {e}"))?;
	let client = TorClient::with_runtime(runtime);
	client.config(config).create_bootstrapped().await.map_err(|e| anyhow::anyhow!("Failed to create bootstrapped Tor client: {e}"))
}

/// The unique prefix every ephemeral state directory carries (see [`storage_dirs`]).
/// Cleanup ([`remove_ephemeral_state_dir`]) refuses to delete any directory whose
/// name does not start with this, so a bug that mis-threads a path can never remove
/// a persistent or unrelated directory.
const EPHEMERAL_DIR_PREFIX: &str = "onyums-ephemeral-";

/// Best-effort removal of an ephemeral service's throwaway state directory, so the
/// disposable identity key does not linger on disk after the service stops
/// (onyums ROADMAP Phase 1).
///
/// As a safety belt this only removes a directory whose final component starts with
/// [`EPHEMERAL_DIR_PREFIX`] — the exact shape [`storage_dirs`] mints — so it can
/// never delete the persistent `./tor/onyums/state` tree or any unrelated path even
/// if a wrong path is threaded in. A missing directory is a no-op; a removal failure
/// (e.g. arti still holds a file open on Windows) is logged, not fatal — the OS
/// reclaims the temp tree regardless.
fn remove_ephemeral_state_dir(dir: &std::path::Path) {
	let is_ephemeral = dir.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(EPHEMERAL_DIR_PREFIX));
	if !is_ephemeral {
		event!(Level::WARN, "refusing to remove non-ephemeral state dir {dir:?}");
		return;
	}
	match std::fs::remove_dir_all(dir) {
		Ok(()) => event!(Level::INFO, "removed ephemeral state dir {dir:?}"),
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
		Err(e) => event!(Level::WARN, "failed to remove ephemeral state dir {dir:?}: {e}"),
	}
}

/// Remove an ephemeral state dir *off* the async runtime (onyums ROADMAP Phase 0 —
/// replace synchronous `Drop` cleanup).
///
/// [`remove_ephemeral_state_dir`] calls the blocking [`std::fs::remove_dir_all`]; running
/// it directly in [`OnionServiceHandle::drop`] stalls a tokio worker. When a runtime is
/// in scope this offloads the removal to the blocking pool and returns the
/// `spawn_blocking` handle, so an async caller ([`OnionServiceHandle::shutdown`]) can
/// await completion while [`Drop`] drops the handle and lets the task finish detached.
/// With no runtime there is nothing to stall, so the removal runs inline and the
/// function returns `None`.
fn spawn_ephemeral_cleanup(dir: std::path::PathBuf) -> Option<JoinHandle<()>> {
	if let Ok(handle) = tokio::runtime::Handle::try_current() {
		Some(handle.spawn_blocking(move || remove_ephemeral_state_dir(&dir)))
	} else {
		remove_ephemeral_state_dir(&dir);
		None
	}
}

/// Apply a caller's authorized-clients allowlist to an [`OnionServiceConfigBuilder`]
/// as Arti v3 restricted discovery (onyums ROADMAP Phase 2).
///
/// Restricted discovery encrypts the service descriptor (its introduction points and
/// keys) to the listed clients' x25519 keys, so an unlisted client cannot even
/// *discover* the service — a DoS-resistance measure enforced in descriptor crypto,
/// upstream of every Skin HTTP layer. The allowlist is [`onyums_skin::RestrictedDiscovery`]
/// (the orchestration half built in the skin crate); each entry's canonical
/// `descriptor:x25519:<BASE32>` rendering is parsed straight into Arti's
/// [`HsClientDescEncKey`], and each nickname into an [`HsClientNickname`] slug.
///
/// An empty allowlist is rejected: enabling restricted discovery with no authorized
/// clients would hide the service from *everyone* (and Arti's own config validation
/// rejects it too). Surfaced here so it fails offline, before any Tor bootstrap.
///
/// # Errors
/// Returns an error if the allowlist is empty, a nickname is not a valid Tor client
/// slug, or a key fails to parse into Arti's descriptor-encryption key type.
fn apply_restricted_discovery(cfg: &mut OnionServiceConfigBuilder, allowlist: &RestrictedDiscovery) -> Result<()> {
	if allowlist.is_empty() {
		bail!("authorized_clients allowlist is empty: enabling restricted discovery with no clients would hide the service from everyone. Add at least one client key, or drop authorized_clients() to stay publicly discoverable");
	}
	let rd = cfg.restricted_discovery();
	rd.enabled(true);
	for (nickname, key) in allowlist.iter() {
		let parsed_nickname = nickname.parse::<HsClientNickname>().map_err(|e| anyhow::anyhow!("invalid restricted-discovery client nickname {nickname:?}: {e}"))?;
		// `ClientAuthKey`'s `Display` is the canonical `descriptor:x25519:<BASE32>` line,
		// which is exactly what Arti's `HsClientDescEncKey` parses (case-insensitively).
		let parsed_key = key.to_string().parse::<HsClientDescEncKey>().map_err(|e| anyhow::anyhow!("invalid restricted-discovery key for client {nickname:?}: {e}"))?;
		rd.static_keys().access().push((parsed_nickname, parsed_key));
	}
	Ok(())
}

/// Build the [`OnionServiceConfig`] for `nickname`, applying restricted discovery if
/// the caller supplied an authorized-clients allowlist.
///
/// Everything here is offline: the nickname parse, the restricted-discovery assembly,
/// and Arti's own config validation all run before any Tor bootstrap, so a bad
/// nickname or allowlist fails fast rather than after the network round-trip. Extracted
/// from the launch path so it is unit-testable with no live Tor network.
///
/// # Errors
/// Returns an error if the nickname fails to parse, the restricted-discovery allowlist
/// is invalid (see [`apply_restricted_discovery`]), or the config fails to build.
fn build_onion_service_config(nickname: &str, allowlist: Option<&RestrictedDiscovery>) -> Result<OnionServiceConfig> {
	let nickname = nickname.parse::<HsNickname>().map_err(|e| anyhow::anyhow!("Failed to parse nickname: {e}"))?;
	let mut cfg = OnionServiceConfigBuilder::default();
	cfg.nickname(nickname);
	if let Some(allowlist) = allowlist {
		apply_restricted_discovery(&mut cfg, allowlist)?;
	}
	cfg.build().map_err(|e| anyhow::anyhow!("Failed to build onion service config: {e}"))
}

/// Launches an onion service from an already-built [`OnionServiceConfig`].
///
/// The returned request stream is self-contained (`use<>`) — it does not borrow
/// the client — so callers can move the client elsewhere (e.g. into a handle)
/// while keeping the stream.
fn launch_onion_service(client: &TorClient<TokioNativeTlsRuntime>, svc_cfg: OnionServiceConfig) -> Result<(Arc<RunningOnionService>, impl Stream<Item = RendRequest> + use<>)> {
	event!(Level::INFO, "Launching onion service...");
	client.launch_onion_service(svc_cfg)
		.map_err(|e| anyhow::anyhow!("Failed to launch onion service: {e}"))?
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

/// The shared, per-service context threaded through the rendezvous loop down to
/// every served stream: the application router, the TLS acceptor, the service
/// address, the plaintext-enforcement policy, and the port → handler routing
/// table.
///
/// Bundled into one cheaply-`Clone` value (the `Router`/`TlsAcceptor`/`Arc` clones
/// are all shallow) so the loop's helpers take a handful of arguments instead of a
/// long, error-prone positional list. The per-circuit [`CircuitPolicy`] is kept
/// separate because it is borrowed (`&dyn`) at the circuit level, not cloned.
#[derive(Clone)]
struct ServeContext {
	app: Router,
	tls_acceptor: TlsAcceptor,
	address: OnionAddress,
	plaintext: tls_policy::PlaintextPolicy,
	port_router: Arc<PortRouter>,
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
async fn serve_circuits(mut rend_requests: impl Stream<Item = RendRequest> + Send + Unpin, ctx: ServeContext, policy: Arc<dyn CircuitPolicy>) -> Result<()> {
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
async fn handle_circuit_streams(mut streams: impl Stream<Item = StreamRequest> + Send + Unpin, id: CircuitId, ctx: ServeContext, policy: &dyn CircuitPolicy) {
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

/// Initializes the onion service from a built config and returns the service and
/// request stream.
fn initialize_onion_service(client: &TorClient<TokioNativeTlsRuntime>, svc_cfg: OnionServiceConfig) -> Result<(Arc<RunningOnionService>, OnionAddress, impl Stream<Item = RendRequest> + use<>)> {
	let (service, request_stream) = launch_onion_service(client, svc_cfg)?;
	let address = get_onion_address(&service)?;
	Ok((service, address, request_stream))
}

/// A stable, high-level snapshot of an onion service's reachability
/// (onyums ROADMAP Phase 4 — observability).
///
/// This is onyums' own projection of arti's `#[non_exhaustive]`
/// [`tor_hsservice::status::State`], the same way [`OnionAddress`] and
/// [`ConnectionInfo`] are typed projections of arti primitives: downstreams match on
/// this exhaustively without a wildcard and without breaking when arti adds a state,
/// and read reachability through [`is_reachable`](Self::is_reachable) rather than
/// re-deriving arti's `is_fully_reachable` semantics. Read the current value from a
/// running service via [`OnionServiceHandle::status`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStatus {
	/// Not launched, or shut down. Not reachable.
	Shutdown,
	/// Building introduction points and publishing the descriptor; no significant
	/// problems yet, but not yet reachable. This is the state a freshly launched
	/// service passes through before [`OnionServiceHandle::ready`] resolves.
	Bootstrapping,
	/// Believed fully reachable: satisfied with its introduction points and its
	/// descriptor is up to date.
	Reachable,
	/// Reachable, but running degraded — fewer or less-satisfactory introduction
	/// points than desired, though the descriptor is current.
	DegradedReachable,
	/// Running but unlikely to be reachable right now — recovering from a dead intro
	/// point, a failed descriptor upload, or a similar transient problem.
	Unreachable,
	/// A problem onyums could not recover from. Not fully reachable.
	Broken,
}

impl ServiceStatus {
	/// Whether the service is *believed* to be reachable by clients.
	///
	/// Mirrors arti's `State::is_fully_reachable`: true for [`Reachable`](Self::Reachable)
	/// and [`DegradedReachable`](Self::DegradedReachable). Like arti's, this is a
	/// one-directional implication — `false` does not prove unreachability.
	#[must_use]
	pub const fn is_reachable(self) -> bool {
		matches!(self, Self::Reachable | Self::DegradedReachable)
	}

	/// Whether the service is running reachable but *degraded* — up, with a current
	/// descriptor, but fewer or less-satisfactory introduction points than desired.
	///
	/// A subset of [`is_reachable`](Self::is_reachable): a degraded service still
	/// serves clients, but an operator may want to alarm on it.
	#[must_use]
	pub const fn is_degraded(self) -> bool {
		matches!(self, Self::DegradedReachable)
	}

	/// Whether the service hit a problem onyums could not recover from
	/// ([`Broken`](Self::Broken)) — distinct from the transient
	/// [`Unreachable`](Self::Unreachable), which is expected to recover on its own.
	#[must_use]
	pub const fn is_broken(self) -> bool {
		matches!(self, Self::Broken)
	}

	/// Whether this is a *settled* status the service will not leave on its own:
	/// [`Shutdown`](Self::Shutdown) (stopped) or [`Broken`](Self::Broken) (unrecoverable).
	///
	/// The complement of the states a service passes through or recovers from —
	/// [`Bootstrapping`](Self::Bootstrapping), [`Unreachable`](Self::Unreachable), and the
	/// reachable states — so a caller watching the lifecycle knows when further waiting
	/// is pointless. See [`OnionServiceHandle::wait_until_settled`], which resolves once
	/// the service is either reachable or terminal.
	#[must_use]
	pub const fn is_terminal(self) -> bool {
		matches!(self, Self::Shutdown | Self::Broken)
	}

	/// A short, stable, lowercase operator-facing label for this status — suitable for a
	/// health line or a `/up`-style check. Never changes for a given variant, so it is
	/// safe to match on downstream.
	#[must_use]
	pub const fn label(self) -> &'static str {
		match self {
			Self::Shutdown => "shutdown",
			Self::Bootstrapping => "bootstrapping",
			Self::Reachable => "reachable",
			Self::DegradedReachable => "degraded",
			Self::Unreachable => "unreachable",
			Self::Broken => "broken",
		}
	}

	/// Operational severity rank — `0` is healthiest ([`Reachable`](Self::Reachable)),
	/// higher is worse. Ranks a reachable service healthiest, a degraded-but-reachable
	/// one next, then the not-yet/again-reachable transients
	/// ([`Bootstrapping`](Self::Bootstrapping) before [`Unreachable`](Self::Unreachable)),
	/// then the terminal [`Broken`](Self::Broken) and [`Shutdown`](Self::Shutdown). Total
	/// and distinct across variants; backs [`worst_of`](Self::worst_of).
	const fn severity(self) -> u8 {
		match self {
			Self::Reachable => 0,
			Self::DegradedReachable => 1,
			Self::Bootstrapping => 2,
			Self::Unreachable => 3,
			Self::Broken => 4,
			Self::Shutdown => 5,
		}
	}

	/// The worst (least healthy) status across several services — the aggregate health
	/// of, say, N onion services sharing one Tor client (see
	/// [`OnionServiceBuilder::tor_client`]). Returns `None` for an empty iterator.
	///
	/// Folds by [`severity`](Self::severity), so a single unhealthy service in a fleet is
	/// never masked by its healthy siblings: `worst_of([Reachable, Broken])` is
	/// [`Broken`](Self::Broken).
	#[must_use]
	pub fn worst_of(statuses: impl IntoIterator<Item = Self>) -> Option<Self> {
		statuses.into_iter().max_by_key(|status| status.severity())
	}
}

impl std::fmt::Display for ServiceStatus {
	/// Writes the stable [`label`](Self::label), so `ServiceStatus` drops straight into a
	/// log line or a health response.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(self.label())
	}
}

/// Project arti's `#[non_exhaustive]` onion-service [`State`](tor_hsservice::status::State)
/// onto onyums' stable [`ServiceStatus`].
///
/// An unrecognized future arti state is conservatively reported as
/// [`ServiceStatus::Unreachable`] — onyums never claims reachability for a state it
/// does not understand. Pure and total, so it is unit-testable against every arti
/// state with no live Tor network.
fn project_service_status(state: tor_hsservice::status::State) -> ServiceStatus {
	use tor_hsservice::status::State;
	match state {
		State::Shutdown => ServiceStatus::Shutdown,
		State::Bootstrapping => ServiceStatus::Bootstrapping,
		State::Running => ServiceStatus::Reachable,
		State::DegradedReachable => ServiceStatus::DegradedReachable,
		State::DegradedUnreachable | State::Recovering => ServiceStatus::Unreachable,
		State::Broken => ServiceStatus::Broken,
		// `State` is `#[non_exhaustive]`; treat any state arti adds later as
		// not-reachable until onyums maps it explicitly.
		_ => ServiceStatus::Unreachable,
	}
}

/// The stable *category* of a [`ServiceProblem`], with the owned diagnostic detail
/// stripped.
///
/// A `Copy` discriminant a downstream can match on exhaustively and store cheaply, the
/// way [`ServiceStatus`] is matched (onyums ROADMAP Phase 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceProblemKind {
	/// A fatal runtime error — see [`ServiceProblem::Runtime`].
	Runtime,
	/// A descriptor-upload failure — see [`ServiceProblem::DescriptorUpload`].
	DescriptorUpload,
	/// An introduction-point failure — see [`ServiceProblem::IntroductionPoint`].
	IntroductionPoint,
	/// An unmodelled subsystem — see [`ServiceProblem::Other`].
	Other,
}

impl ServiceProblemKind {
	/// A short, stable, lowercase label for this category — safe to match on downstream
	/// (a health line or an alert rule) because it never changes for a given variant.
	#[must_use]
	pub const fn label(self) -> &'static str {
		match self {
			Self::Runtime => "runtime",
			Self::DescriptorUpload => "descriptor-upload",
			Self::IntroductionPoint => "introduction-point",
			Self::Other => "other",
		}
	}
}

/// The reason a service is running degraded, unreachable, or broken — onyums' stable
/// projection of arti's `#[non_exhaustive]` [`Problem`](tor_hsservice::status::Problem).
///
/// This is the "why" behind a non-[`Reachable`](ServiceStatus::Reachable)
/// [`ServiceStatus`] (onyums ROADMAP Phase 4 — observability).
///
/// arti's `Problem` is `#[non_exhaustive]` and — unlike its `State` — carries **no
/// `Display`** (only `Debug`) in the pinned 0.43 source, so it cannot be surfaced to
/// operators cleanly as-is. This is onyums' typed projection, the same pattern as
/// [`ServiceStatus`]: downstreams match on the stable [`kind`](Self::kind) without a
/// wildcard, and read the operator-facing diagnostic through [`detail`](Self::detail)
/// or [`Display`](std::fmt::Display). Read the current value from a running service via
/// [`OnionServiceHandle::problem`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceProblem {
	/// A fatal runtime error the service could not recover from — the reason behind a
	/// [`Broken`](ServiceStatus::Broken) status. Carries arti's `Debug` diagnostic.
	Runtime(String),
	/// One or more onion-service descriptor uploads failed, so clients may be unable to
	/// find the service until a later upload succeeds.
	DescriptorUpload(String),
	/// One or more introduction points could not be established — the usual reason a
	/// service reads [`Unreachable`](ServiceStatus::Unreachable) or
	/// [`DegradedReachable`](ServiceStatus::DegradedReachable).
	IntroductionPoint(String),
	/// A problem in a subsystem onyums does not model explicitly: arti's `PoW` manager
	/// (only compiled with the experimental `hs-pow-full` feature), or a category a
	/// newer arti adds to its `#[non_exhaustive]` `Problem`. The diagnostic still
	/// carries arti's `Debug` rendering, so the cause is never silently dropped.
	Other(String),
}

impl ServiceProblem {
	/// The stable [`ServiceProblemKind`] of this problem — safe to match on downstream,
	/// unlike the owned diagnostic [`detail`](Self::detail) string.
	#[must_use]
	pub const fn kind(&self) -> ServiceProblemKind {
		match self {
			Self::Runtime(_) => ServiceProblemKind::Runtime,
			Self::DescriptorUpload(_) => ServiceProblemKind::DescriptorUpload,
			Self::IntroductionPoint(_) => ServiceProblemKind::IntroductionPoint,
			Self::Other(_) => ServiceProblemKind::Other,
		}
	}

	/// The operator-facing diagnostic detail — arti's `Debug` rendering of the
	/// underlying problem, since arti's `Problem` exposes no `Display`.
	#[must_use]
	pub fn detail(&self) -> &str {
		match self {
			Self::Runtime(d) | Self::DescriptorUpload(d) | Self::IntroductionPoint(d) | Self::Other(d) => d,
		}
	}

	/// A short, stable, lowercase label for this problem's category — the
	/// [`kind`](Self::kind)'s [`label`](ServiceProblemKind::label).
	#[must_use]
	pub const fn label(&self) -> &'static str {
		self.kind().label()
	}

	/// Whether this is a *fatal* problem the service will not recover from on its own — a
	/// [`Runtime`](Self::Runtime) error, which drives arti to
	/// [`Broken`](ServiceStatus::Broken) — as opposed to the transient descriptor-upload
	/// and introduction-point problems arti retries.
	#[must_use]
	pub const fn is_fatal(&self) -> bool {
		matches!(self, Self::Runtime(_))
	}
}

impl std::fmt::Display for ServiceProblem {
	/// Writes `"<label>: <detail>"` — the stable category plus arti's diagnostic — so a
	/// `ServiceProblem` drops straight into a log line or a degraded-health response.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}: {}", self.label(), self.detail())
	}
}

/// Project arti's `#[non_exhaustive]` [`Problem`](tor_hsservice::status::Problem) onto
/// onyums' stable [`ServiceProblem`], capturing arti's `Debug` rendering as the
/// operator-facing [`detail`](ServiceProblem::detail) (arti exposes no `Display` on
/// `Problem` or its inner errors). Keys only on the variant, so it is unit-testable
/// offline over a constructed `Problem` with no live Tor network. A subsystem onyums
/// does not model — the feature-gated `PoW` manager, or any category a newer arti adds —
/// maps to [`ServiceProblem::Other`] rather than being dropped.
fn project_service_problem(problem: &tor_hsservice::status::Problem) -> ServiceProblem {
	use tor_hsservice::status::Problem;
	match problem {
		Problem::Runtime(e) => ServiceProblem::Runtime(format!("{e:?}")),
		Problem::DescriptorUpload(errs) => ServiceProblem::DescriptorUpload(format!("{errs:?}")),
		Problem::Ipt(errs) => ServiceProblem::IntroductionPoint(format!("{errs:?}")),
		// `Problem` is `#[non_exhaustive]`; the PoW variant (feature-gated off) and any
		// future arti category fall here rather than being silently dropped.
		_ => ServiceProblem::Other(format!("{problem:?}")),
	}
}

/// A consistent point-in-time health snapshot of an onion service (onyums ROADMAP
/// Phase 4 — observability).
///
/// Bundles the [`ServiceStatus`] and, when the service is not fully healthy, the
/// [`ServiceProblem`] explaining why. Read via [`OnionServiceHandle::health`]. The value is derived from a **single** read
/// of arti's status, so the `status` and `problem` are always mutually consistent —
/// unlike calling [`status`](OnionServiceHandle::status) and
/// [`problem`](OnionServiceHandle::problem) separately, which reads arti twice and can
/// straddle a state transition (e.g. read `Reachable` then a just-arrived problem).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceHealth {
	status: ServiceStatus,
	problem: Option<ServiceProblem>,
}

impl ServiceHealth {
	/// The reachability [`ServiceStatus`] at the moment of the snapshot.
	#[must_use]
	pub const fn status(&self) -> ServiceStatus {
		self.status
	}

	/// The active [`ServiceProblem`] explaining a non-healthy status, or `None` when the
	/// service reported no problem at the moment of the snapshot.
	#[must_use]
	pub const fn problem(&self) -> Option<&ServiceProblem> {
		self.problem.as_ref()
	}

	/// Whether the service was believed reachable — the snapshot's
	/// [`ServiceStatus::is_reachable`].
	#[must_use]
	pub const fn is_reachable(&self) -> bool {
		self.status.is_reachable()
	}

	/// Whether the service was *fully* healthy: reachable **and** reporting no active
	/// problem. Stricter than [`is_reachable`](Self::is_reachable), which is still true
	/// for a [`DegradedReachable`](ServiceStatus::DegradedReachable) service carrying a
	/// problem — this is the "all green" check for a `/up`-style endpoint.
	#[must_use]
	pub const fn is_healthy(&self) -> bool {
		self.status.is_reachable() && self.problem.is_none()
	}
}

impl std::fmt::Display for ServiceHealth {
	/// Writes the [`ServiceStatus`] label, and — when a problem is present — the
	/// [`ServiceProblem`] after an em dash, e.g. `"unreachable — introduction-point: []"`
	/// or just `"reachable"`.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match &self.problem {
			Some(problem) => write!(f, "{} — {problem}", self.status),
			None => std::fmt::Display::fmt(&self.status, f),
		}
	}
}

/// Drive a [`ServiceStatus`] stream until the first item satisfying `pred`, returning
/// that status — or `None` if the stream ends first (the underlying service was
/// dropped before the condition was met).
///
/// Extracted from [`OnionServiceHandle::ready`] and its timeout/settle siblings so the
/// wait logic is unit-testable offline over a constructed stream, with no live Tor
/// service (the projection that feeds it is already covered by
/// `service_status_projects_every_arti_state`). Takes the stream by value and pins it
/// internally, so callers hand `status_events()` straight in without an `Unpin` bound.
async fn await_status(events: impl Stream<Item = ServiceStatus>, mut pred: impl FnMut(ServiceStatus) -> bool) -> Option<ServiceStatus> {
	futures::pin_mut!(events);
	while let Some(status) = events.next().await {
		if pred(status) {
			return Some(status);
		}
	}
	None
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
	// descriptor publishing) keeps running for the lifetime of the handle; also handed
	// out by `tor_client()` for launching sibling services on the same bootstrap.
	client: Arc<TorClient<TokioNativeTlsRuntime>>,
	cancel: CancellationToken,
	task: Mutex<Option<JoinHandle<()>>>,
	// Set only for an ephemeral service (see `OnionServiceBuilder::ephemeral`): the
	// throwaway temp state dir, removed when the handle drops so the disposable
	// identity key does not linger on disk. `Mutex<Option<..>>` so `shutdown` can
	// `take()` and await the removal while `Drop` only cleans up what shutdown left.
	ephemeral_state_dir: Mutex<Option<std::path::PathBuf>>,
}

impl OnionServiceHandle {
	/// The service's stable `.onion` address.
	#[must_use]
	pub const fn onion_address(&self) -> &OnionAddress {
		&self.address
	}

	/// This service's Tor client, for launching sibling services on the same bootstrap
	/// (onyums ROADMAP Phase 4 — multiple services on one shared client).
	///
	/// Bootstrap is the slow part of coming up; hand this `Arc` to another
	/// [`OnionServiceBuilder::tor_client`] to bring up more services without a second
	/// bootstrap. Equivalent to sharing an [`OnionService::shared_client`] up front, but
	/// reachable from an already-running handle.
	///
	/// ```rust,no_run
	/// # async fn f() -> anyhow::Result<()> {
	/// use axum::{routing::get, Router};
	/// use onyums::OnionService;
	///
	/// let blog = OnionService::builder()
	///     .router(Router::new().route("/", get(|| async { "blog" })))
	///     .nickname("blog")
	///     .serve()
	///     .await?;
	/// // Launch a sibling on the same bootstrap, then health-check both.
	/// let wiki = OnionService::builder()
	///     .router(Router::new().route("/", get(|| async { "wiki" })))
	///     .nickname("wiki")
	///     .tor_client(blog.tor_client())
	///     .serve()
	///     .await?;
	/// let up = onyums::ServiceStatus::worst_of([blog.status(), wiki.status()]);
	/// println!("fleet: {up:?}, blog ready: {}", blog.is_ready());
	/// # Ok(())
	/// # }
	/// ```
	#[must_use]
	pub fn tor_client(&self) -> Arc<TorClient<TokioNativeTlsRuntime>> {
		self.client.clone()
	}

	/// The service's current high-level [`ServiceStatus`] — a synchronous snapshot
	/// of its reachability, projected from arti's live status (onyums ROADMAP
	/// Phase 4).
	///
	/// Unlike [`ready`](Self::ready), which *awaits* first reachability, this returns
	/// immediately with wherever the service is now — still bootstrapping, reachable,
	/// running degraded, or broken — so a caller can poll or surface health without
	/// blocking. Reflects arti's `is_fully_reachable` semantics via
	/// [`ServiceStatus::is_reachable`].
	#[must_use]
	pub fn status(&self) -> ServiceStatus {
		project_service_status(self.service.status().state())
	}

	/// Whether the service is reachable *right now* — a cheap, non-blocking readiness
	/// check for a health handler (a `/up`-style endpoint), where [`ready`](Self::ready)
	/// would block.
	///
	/// Shorthand for `self.status().is_reachable()`; see
	/// [`ServiceStatus::is_reachable`] for the one-directional semantics (`false` does
	/// not prove unreachability).
	#[must_use]
	pub fn is_ready(&self) -> bool {
		self.status().is_reachable()
	}

	/// The reason the service is currently degraded, unreachable, or broken — its
	/// [`ServiceProblem`] — or `None` when there is no active problem (onyums ROADMAP
	/// Phase 4 — observability).
	///
	/// Pairs with [`status`](Self::status): `status()` reports *what* the reachability
	/// is, `problem()` reports *why* when it is not fully healthy. A
	/// [`Reachable`](ServiceStatus::Reachable) service normally reports `None`; a
	/// [`Broken`](ServiceStatus::Broken) or [`Unreachable`](ServiceStatus::Unreachable)
	/// one carries the arti-observed cause — a failed descriptor upload, dead
	/// introduction points, or a fatal runtime error. Projected from arti's
	/// `#[non_exhaustive]` `current_problem()` through the stable [`ServiceProblem`]
	/// mapping, so the category is matchable downstream and the diagnostic is readable
	/// even though arti's own `Problem` exposes no `Display`.
	#[must_use]
	pub fn problem(&self) -> Option<ServiceProblem> {
		self.service.status().current_problem().map(project_service_problem)
	}

	/// A consistent [`ServiceHealth`] snapshot — the [`status`](Self::status) and the
	/// [`problem`](Self::problem) read together from a single arti status, so they never
	/// straddle a state transition (onyums ROADMAP Phase 4 — observability).
	///
	/// Prefer this to reading `status()` and `problem()` separately when you want a
	/// coherent "what and why" for a health line: those are two independent reads of
	/// arti's live status and can disagree across a transition, whereas `health()`
	/// projects both from the same read.
	#[must_use]
	pub fn health(&self) -> ServiceHealth {
		let raw = self.service.status();
		ServiceHealth {
			status: project_service_status(raw.state()),
			problem: raw.current_problem().map(project_service_problem),
		}
	}

	/// A stream of [`ServiceStatus`] transitions, so a caller can *watch* the
	/// bootstrap → reachable → degraded lifecycle rather than poll
	/// [`status`](Self::status) (onyums ROADMAP Phase 4).
	///
	/// Projects arti's `status_events()` through the same stable, exhaustive
	/// [`ServiceStatus`] mapping as [`status`](Self::status), so downstreams match
	/// without a wildcard and without breaking when arti adds a state. Backed by a
	/// watch channel: the stream yields the current status immediately, then one item
	/// per change (intermediate transitions between polls may be coalesced). The
	/// stream is independent of this handle — it stays live for as long as the
	/// underlying service does.
	pub fn status_events(&self) -> impl Stream<Item = ServiceStatus> + use<> {
		self.service.status_events().map(|status| project_service_status(status.state()))
	}

	/// Resolve once the service is believed to be fully reachable — its
	/// descriptor is published and its introduction points are satisfactory.
	///
	/// This is the meaningful sense of "ready": after it returns, clients can
	/// actually reach the service, unlike the old global which was populated the
	/// instant the address was known (long before the descriptor was up).
	pub async fn ready(&self) {
		if self.status().is_reachable() {
			return;
		}
		// Watch the *projected* status stream — the same `ServiceStatus` mapping as
		// `status()`/`status_events()` — rather than re-deriving arti's
		// `is_fully_reachable` against the raw state, so readiness has one definition
		// (onyums ROADMAP Phase 4: fold `ready()` onto the status stream).
		let _ = await_status(self.status_events(), ServiceStatus::is_reachable).await;
	}

	/// Like [`ready`](Self::ready), but give up after `timeout`: resolve `true` if the
	/// service became reachable within the deadline, `false` if the deadline elapsed
	/// first (or the service was torn down before it reached a reachable state).
	///
	/// Use this at startup so a service that never publishes a usable descriptor — a
	/// broken bootstrap, a hostile network — surfaces as a bounded timeout instead of
	/// hanging [`ready`](Self::ready) forever. On `false` the caller can read
	/// [`status`](Self::status) to distinguish still-[`Bootstrapping`](ServiceStatus::Bootstrapping)
	/// from [`Broken`](ServiceStatus::Broken).
	pub async fn ready_timeout(&self, timeout: std::time::Duration) -> bool {
		if self.status().is_reachable() {
			return true;
		}
		tokio::time::timeout(timeout, await_status(self.status_events(), ServiceStatus::is_reachable)).await.ok().flatten().is_some()
	}

	/// Resolve once the service reaches a *settled* [`ServiceStatus`] and return it:
	/// either reachable, or a terminal failure ([`Broken`](ServiceStatus::Broken) /
	/// [`Shutdown`](ServiceStatus::Shutdown)) it will not leave on its own (onyums
	/// ROADMAP Phase 4).
	///
	/// Unlike [`ready`](Self::ready) — which completes *only* on reachability, and so
	/// blocks indefinitely on a service that broke during bootstrap — this distinguishes
	/// "came up" from "gave up": test [`ServiceStatus::is_reachable`] on the returned
	/// status. Resolves immediately when the service is already settled, and reports
	/// [`Shutdown`](ServiceStatus::Shutdown) if the status stream ends first (the service
	/// was torn down).
	pub async fn wait_until_settled(&self) -> ServiceStatus {
		let current = self.status();
		if current.is_reachable() || current.is_terminal() {
			return current;
		}
		await_status(self.status_events(), |s| s.is_reachable() || s.is_terminal()).await.unwrap_or(ServiceStatus::Shutdown)
	}

	/// Stop accepting new connections and await the accept loop's exit.
	///
	/// Cancels the spawned accept loop via its [`CancellationToken`] and joins
	/// the task. Idempotent: a second call is a no-op. Full teardown of the Tor
	/// client and onion service happens when the handle is dropped.
	///
	/// For an ephemeral service this also removes the throwaway keystore — offloaded to
	/// the blocking pool and awaited here, so a graceful shutdown is a *complete* stop
	/// (the disposable identity is gone before this returns) without the synchronous
	/// `remove_dir_all` that would otherwise stall a runtime worker in [`Drop`].
	pub async fn shutdown(&self) {
		self.cancel.cancel();
		let task = self.task.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
		if let Some(task) = task {
			let _ = task.await;
		}
		// Claim the ephemeral cleanup so `Drop` won't repeat it, and await the off-thread
		// removal so shutdown() fully completes the teardown.
		let dir = self.ephemeral_state_dir.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
		if let Some(dir) = dir
			&& let Some(handle) = spawn_ephemeral_cleanup(dir)
		{
			let _ = handle.await;
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

impl Drop for OnionServiceHandle {
	fn drop(&mut self) {
		// Dropping the handle tears down the onion service and its client; for an
		// ephemeral service, also remove the throwaway keystore so the disposable
		// identity key does not outlive the service on disk. Best-effort and guarded
		// (see `remove_ephemeral_state_dir`). Only cleans up what `shutdown` didn't
		// already claim; offloads the blocking removal to the runtime's blocking pool so
		// dropping a handle inside async code never stalls a worker on `remove_dir_all`.
		let dir = self.ephemeral_state_dir.get_mut().unwrap_or_else(std::sync::PoisonError::into_inner).take();
		if let Some(dir) = dir {
			let _ = spawn_ephemeral_cleanup(dir);
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

/// Add the HSTS response header to every served response when the plaintext
/// policy enforces it ([`tls_policy::PlaintextPolicy::Reject`]), so a conforming
/// client never silently downgrades from HTTPS. A no-op when plaintext is merely
/// upgraded.
///
/// Like [`apply_skin`], this is a plain `Router` transform so it is testable with
/// `tower::ServiceExt::oneshot` and no live Tor network.
fn apply_hsts(app: Router, plaintext: tls_policy::PlaintextPolicy) -> Router {
	match tls_policy::hsts_header(plaintext) {
		Some((name, value)) => app.layer(axum::middleware::map_response(move |mut response: axum::response::Response| async move {
			response.headers_mut().insert(axum::http::HeaderName::from_static(name), axum::http::HeaderValue::from_static(value));
			response
		})),
		None => app,
	}
}

/// Assemble the application-facing HTTP stack exactly as [`OnionServiceBuilder::serve`]
/// layers it: the Skin abuse-defense gate (Phase 2) wrapping the caller's app, then the
/// HSTS response header under a plaintext-reject TLS policy (Phase 3). This is the full
/// request path a client hits *inside* the onion-encrypted TLS stream, minus the TLS
/// transport itself.
///
/// Extracted from `serve` so the *composed* stack — not just its two halves in isolation
/// ([`apply_skin`] / [`apply_hsts`]) — is testable end-to-end with
/// `tower::ServiceExt::oneshot` and no live Tor network. First slice of an
/// in-process/loopback test mode (cross-cutting roadmap item).
fn build_serve_router(app: Router, skin: SkinChoice, plaintext: tls_policy::PlaintextPolicy) -> Router {
	apply_hsts(apply_skin(app, skin), plaintext)
}

/// Assemble a [`PortRouter`] from the builder's `route_port` registrations,
/// surfacing the first invalid registration (reserved/zero port, or a duplicate).
///
/// Extracted from `serve` so the registration validation is unit-testable with no
/// live Tor network.
fn build_port_router(handlers: Vec<(u16, Arc<dyn StreamHandler>)>) -> Result<PortRouter> {
	let mut router = PortRouter::new();
	for (port, handler) in handlers {
		router.register(port, handler)?;
	}
	Ok(router)
}

/// Resolve the per-rendezvous-circuit [`CircuitPolicy`] from the builder's choices.
///
/// The default-policy toggles — Under Attack Mode ([`OnionServiceBuilder::under_attack`])
/// and the circuit-event sink ([`OnionServiceBuilder::circuit_events`]) — configure the
/// *default* [`AccountingCircuitPolicy`]. A caller-supplied
/// [`circuit_policy`](OnionServiceBuilder::circuit_policy) owns those decisions itself, so
/// combining it with either toggle is a configuration error surfaced here — offline, before
/// any Tor bootstrap — rather than silently ignoring one of them. With no custom policy the
/// default accounting policy is returned, in Under Attack Mode iff the toggle is set and
/// emitting circuit events iff a sink was supplied.
///
/// Extracted from `serve` so the resolution is unit-testable with no live Tor network.
fn resolve_circuit_policy(custom: Option<Arc<dyn CircuitPolicy>>, under_attack: bool, events: Option<Arc<dyn SecurityEventSink>>) -> Result<Arc<dyn CircuitPolicy>> {
	if let Some(policy) = custom {
		if under_attack || events.is_some() {
			bail!("the default-policy toggles under_attack()/circuit_events() conflict with a custom circuit_policy(); configure those on your own policy instead");
		}
		return Ok(policy);
	}
	let mut policy = AccountingCircuitPolicy::new().under_attack(under_attack);
	if let Some(sink) = events {
		policy = policy.with_events(sink);
	}
	Ok(Arc::new(policy))
}

/// Reject the one incompatible identity combination before any launch: a caller-shared
/// Tor client ([`OnionServiceBuilder::tor_client`]) together with
/// [`ephemeral`](OnionServiceBuilder::ephemeral).
///
/// A shared client is bootstrapped against a fixed keystore/state directory, so onyums
/// cannot point it at the per-launch throwaway directory `ephemeral` relies on for a
/// disposable identity. Every other pairing is valid (a fresh persistent client, a
/// fresh ephemeral client, or a shared persistent client). Extracted from
/// [`OnionServiceBuilder::serve`] so the rule is unit-testable with no live Tor network.
fn validate_client_choice(ephemeral: bool, has_shared_client: bool) -> Result<()> {
	if ephemeral && has_shared_client {
		bail!("ephemeral() conflicts with tor_client(): a shared Tor client has a fixed keystore and cannot provide a throwaway per-launch identity; use one or the other");
	}
	Ok(())
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
	tls: Tls,
	circuit_policy: Option<Arc<dyn CircuitPolicy>>,
	under_attack: bool,
	circuit_events: Option<Arc<dyn SecurityEventSink>>,
	restricted_discovery: Option<RestrictedDiscovery>,
	raw_handlers: Vec<(u16, Arc<dyn StreamHandler>)>,
	ephemeral: bool,
	// A caller-supplied, already-bootstrapped Tor client to launch this service on,
	// instead of bootstrapping a fresh one (Phase 4 multi-service — bootstrap once,
	// launch N). `None` keeps today's behaviour: `serve` bootstraps its own client.
	tor_client: Option<Arc<TorClient<TokioNativeTlsRuntime>>>,
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

	/// Set the TLS transport posture (onyums ROADMAP Phase 3).
	///
	/// Defaults to [`Tls::Upgrade`] — auto self-signed cert with plaintext HTTP
	/// (port 80) transparently redirected to HTTPS. Pass [`Tls::Strict`] to make
	/// TLS non-negotiable: plaintext circuits are rejected outright (no port-80
	/// handler) and HTTPS responses carry an HSTS header. This is an explicit opt
	/// *down* in client tolerance, never an opt *up* into TLS — TLS is always on.
	/// Pass [`Tls::Provided`] to serve a caller-supplied (e.g. CA-signed)
	/// certificate instead of the auto-generated self-signed one.
	#[must_use]
	pub fn tls(mut self, tls: Tls) -> Self {
		self.tls = tls;
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

	/// Under Attack Mode: force *every new rendezvous circuit* through the Skin
	/// challenge gate before it is served (onyums ROADMAP Phase 2).
	///
	/// This is an explicit opt-*up* into a stricter posture for when the service is
	/// actively under a flood: it configures the default [`AccountingCircuitPolicy`]
	/// so that [`on_new_circuit`](onyums_skin::CircuitPolicy::on_new_circuit) returns
	/// [`Challenge`](onyums_skin::CircuitAction::Challenge) for every circuit, not
	/// only the ones the policy would otherwise flag. Leave it off (the default) for
	/// normal operation.
	///
	/// Conflicts with a custom [`circuit_policy`](Self::circuit_policy): that policy
	/// owns its own Under-Attack decision, so setting both is an error surfaced from
	/// [`Self::serve`] (offline, before any Tor bootstrap). Set Under Attack Mode on
	/// your own policy instead — `AccountingCircuitPolicy::new().under_attack(true)`.
	#[must_use]
	pub const fn under_attack(mut self, on: bool) -> Self {
		self.under_attack = on;
		self
	}

	/// Surface the *circuit-layer* security events — per-circuit rejects, whole-circuit
	/// teardowns, and Under-Attack-Mode challenges — to a [`SecurityEventSink`] (onyums
	/// ROADMAP Phase 2 → Phase 4 observability).
	///
	/// This wires the sink into the default [`AccountingCircuitPolicy`], which otherwise
	/// stays silent. The complementary *HTTP-gate* events (challenge issued/passed/failed,
	/// WAF blocks, rate-limit trips) are configured on the Skin gate itself — build it with
	/// [`Skin::builder`] and call `.events(sink)`, then pass it via [`Self::skin`] — so
	/// feeding one shared sink to both call sites gives you the full observability stream.
	///
	/// Like [`Self::under_attack`], this configures the *default* policy and conflicts with
	/// a custom [`circuit_policy`](Self::circuit_policy) (which owns its own event sink via
	/// `AccountingCircuitPolicy::with_events`); setting both is an error from [`Self::serve`].
	#[must_use]
	pub fn circuit_events(mut self, sink: Arc<dyn SecurityEventSink>) -> Self {
		self.circuit_events = Some(sink);
		self
	}

	/// Enable v3 client authorization / restricted discovery for the listed clients
	/// (onyums ROADMAP Phase 2).
	///
	/// Given an [`onyums_skin::RestrictedDiscovery`] allowlist (nickname → x25519
	/// [`ClientAuthKey`]), the service publishes a descriptor whose introduction
	/// points and keys are encrypted to those clients only. An unlisted client cannot
	/// discover the service at all — `DoS` resistance enforced in descriptor crypto,
	/// upstream of the Skin HTTP gate rather than in place of it.
	///
	/// This is an opt-*down* in reachability (from "anyone with the address" to "only
	/// these clients"), a deliberate, named decision. Omit it to stay publicly
	/// discoverable. An empty allowlist is rejected by [`Self::serve`] — enabling
	/// restricted discovery with no clients would hide the service from everyone.
	///
	/// Build the allowlist from `.auth` files (`RestrictedDiscovery::from_auth_files`)
	/// or by authorizing [`ClientAuthKey`]s directly. Restricted discovery is a
	/// DoS-resistance mechanism, *not* a substitute for authentication: removing a
	/// client does not immediately revoke an already-connected one.
	#[must_use]
	pub fn authorized_clients(mut self, allowlist: RestrictedDiscovery) -> Self {
		self.restricted_discovery = Some(allowlist);
		self
	}

	/// Register a raw [`StreamHandler`] to serve an arbitrary, non-HTTP port over
	/// the onion service (onyums ROADMAP Phase 3 — protocol versatility).
	///
	/// The built-in TLS-enforced HTTP handler always serves port 443 (HTTPS) and
	/// port 80 (HTTPS upgrade/redirect); a raw handler may occupy any *other* port
	/// — one that would otherwise be rejected — letting onyums tunnel gRPC, SSH, a
	/// game server, or Lightning alongside HTTP. For example,
	/// `.route_port(9735, RawTcpHandler::new("127.0.0.1:9735"))`. Registering a
	/// reserved port (80/443), port 0, or the same port twice surfaces an error
	/// from [`Self::serve`].
	///
	/// This is an opt-*up* in protocol reach, not a relaxation of safety: the HTTP
	/// handler and its TLS-first posture are unchanged.
	#[must_use]
	pub fn route_port(mut self, port: u16, handler: impl StreamHandler + 'static) -> Self {
		self.raw_handlers.push((port, Arc::new(handler)));
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

	/// Opt *down*: run a throwaway service whose identity does not persist
	/// (onyums ROADMAP Phase 1).
	///
	/// By default onyums keeps its onion identity key in a persistent keystore
	/// (`./tor/onyums/state`), so the `.onion` address is stable across restarts with
	/// zero configuration. Calling `ephemeral()` instead points the keystore at a
	/// unique, throwaway directory under the system temp dir (see [`storage_dirs`]):
	/// each launch starts with an empty keystore, Arti mints a fresh identity key, and
	/// the service comes up on a new, disposable address that is never written into the
	/// persistent tree.
	///
	/// This is an explicit, named decision — never an unset flag — for services that
	/// *want* a new address every run (a one-shot drop, a test fixture, a service whose
	/// unlinkability across restarts is the point). The disposable network cache is
	/// still shared, so an ephemeral launch does not re-download the consensus.
	#[must_use]
	pub const fn ephemeral(mut self) -> Self {
		self.ephemeral = true;
		self
	}

	/// Launch this service on a caller-supplied, already-bootstrapped Tor client
	/// instead of bootstrapping a fresh one (onyums ROADMAP Phase 4 — multiple services
	/// on one shared client).
	///
	/// Tor bootstrap (fetching the consensus, building circuits) is the slow part of
	/// coming up; a single [`TorClient`] can host any number of onion services, each
	/// keyed by its own nickname in the client's keystore. Bootstrap once with
	/// [`OnionService::shared_client`] (or your own re-exported [`arti_client`] client),
	/// then hand the same `Arc` to several builders so N services share one bootstrap
	/// and one network footprint:
	///
	/// ```rust,no_run
	/// # async fn f() -> anyhow::Result<()> {
	/// use axum::{routing::get, Router};
	/// use onyums::OnionService;
	///
	/// let client = OnionService::shared_client().await?;
	/// let blog = OnionService::builder()
	///     .router(Router::new().route("/", get(|| async { "blog" })))
	///     .nickname("blog")
	///     .tor_client(client.clone())
	///     .serve()
	///     .await?;
	/// let wiki = OnionService::builder()
	///     .router(Router::new().route("/", get(|| async { "wiki" })))
	///     .nickname("wiki")
	///     .tor_client(client)
	///     .serve()
	///     .await?;
	/// # let _ = (blog, wiki);
	/// # Ok(())
	/// # }
	/// ```
	///
	/// Conflicts with [`ephemeral`](Self::ephemeral): a shared client owns a fixed
	/// keystore/state directory, so it cannot also provide the per-launch throwaway
	/// identity `ephemeral` promises — setting both is an error surfaced from
	/// [`Self::serve`] (offline, before any launch).
	#[must_use]
	pub fn tor_client(mut self, client: Arc<TorClient<TokioNativeTlsRuntime>>) -> Self {
		self.tor_client = Some(client);
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

		// Phase 3 protocol versatility: build the port → handler routing table from
		// the caller's `route_port` registrations. Validated here (before any Tor
		// bootstrap) so a bad registration — a reserved/zero port, or a duplicate —
		// fails offline rather than at the first circuit. An empty router reproduces
		// today's HTTP-only behaviour.
		let port_router = Arc::new(build_port_router(self.raw_handlers)?);

		// Insert the onyums-skin gate ahead of the application on the HTTP path
		// (Phase 2 Skin integration) + Phase 3 TLS-first HSTS. Derive the pure, `Copy`
		// plaintext-enforcement decision once (also threaded into the port dispatch
		// below), then assemble the full application-facing stack. Secure-by-default
		// unless the caller opted down with `no_skin`.
		let plaintext = self.tls.plaintext_policy();
		let app = build_serve_router(app, self.skin, plaintext);

		// The per-circuit Tor-layer gate. Secure-by-default but non-disruptive: an
		// accept-all accounting policy unless the caller supplied a tuned one, or the
		// Under Attack Mode toggle asked the default policy to challenge every circuit.
		// A custom policy combined with the toggle is a conflict caught offline here.
		let policy = resolve_circuit_policy(self.circuit_policy, self.under_attack, self.circuit_events)?;

		// Phase 2 v3 client authorization: assemble the onion service config (nickname +
		// optional restricted-discovery allowlist) offline, so a bad nickname or an
		// empty/invalid allowlist fails before any Tor bootstrap. `None` keeps the
		// service publicly discoverable — today's default behaviour.
		let svc_cfg = build_onion_service_config(&nickname, self.restricted_discovery.as_ref())?;

		// Resolve the Tor client (Phase 1 identity mode + Phase 4 multi-service). A
		// caller-shared client (bootstrap once, launch N) is used as-is; otherwise
		// bootstrap a fresh one against the identity-mode directories — for an ephemeral
		// service a unique throwaway under temp whose path the handle removes on drop,
		// else the fixed persistent onyums tree. A shared client cannot be ephemeral
		// (fixed keystore), rejected here before any launch.
		validate_client_choice(self.ephemeral, self.tor_client.is_some())?;
		let (client, ephemeral_state_dir) = if let Some(shared) = self.tor_client {
			(shared, None)
		} else {
			let (state_dir, cache_dir) = storage_dirs(self.ephemeral);
			let ephemeral_state_dir = self.ephemeral.then(|| std::path::PathBuf::from(&state_dir));
			(setup_tor_client(&state_dir, &cache_dir).await?, ephemeral_state_dir)
		};
		let (service, address, request_stream) = initialize_onion_service(&client, svc_cfg)?;
		let tls_acceptor = tls_acceptor(&address, &self.tls)?;

		// Bundle everything the loop threads down to each served stream into one
		// cheaply-cloned context (see [`ServeContext`]).
		let ctx = ServeContext { app, tls_acceptor, address: address.clone(), plaintext, port_router };

		let cancel = CancellationToken::new();
		let loop_cancel = cancel.clone();
		let task = tokio::spawn(async move {
			let rend_requests = Box::pin(request_stream);
			tokio::select! {
				() = loop_cancel.cancelled() => {
					event!(Level::INFO, "Onion service accept loop cancelled.");
				}
				result = serve_circuits(rend_requests, ctx, policy) => {
					if let Err(err) = result {
						event!(Level::ERROR, "Onion service accept loop ended with error: {err}");
					} else {
						event!(Level::INFO, "Onion service accept loop ended.");
					}
				}
			}
		});

		Ok(OnionServiceHandle { address, service, client, cancel, task: Mutex::new(Some(task)), ephemeral_state_dir: Mutex::new(ephemeral_state_dir) })
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

	/// Bootstrap a Tor client to share across several onion services (onyums ROADMAP
	/// Phase 4 — multiple services on one shared client).
	///
	/// Bootstrap is the slow part of coming up; do it once and hand the returned `Arc`
	/// to each builder via [`OnionServiceBuilder::tor_client`] so N services share one
	/// bootstrap and one network footprint. Uses the same persistent onyums state/cache
	/// tree as a default single-service launch, so every service keyed on this client
	/// gets a stable address across restarts. For a bespoke configuration, build a client
	/// from the re-exported [`arti_client`] stack instead and pass it the same way.
	///
	/// # Errors
	/// Returns an error if the Tor client fails to build or bootstrap, or if called
	/// outside a tokio runtime.
	pub async fn shared_client() -> Result<Arc<TorClient<TokioNativeTlsRuntime>>> {
		let (state_dir, cache_dir) = storage_dirs(false);
		setup_tor_client(&state_dir, &cache_dir).await
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
async fn handle_http_redirect(stream_request: StreamRequest, requested_host: String) -> Result<()> {
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

// Move tls_acceptor function up, before serve
fn tls_acceptor(address: &OnionAddress, tls: &Tls) -> Result<TlsAcceptor> {
	// Phase 3 bring-your-own cert: `Tls::Provided` serves the caller-supplied,
	// already-validated config (parsed once in `ProvidedCert::from_pem`); every
	// other mode auto-generates a self-signed certificate for the onion address.
	let server_config = match tls {
		Tls::Provided(cert) => cert.server_config(),
		Tls::Upgrade | Tls::Strict => Arc::new(self_signed_server_config(address)?),
	};
	let acceptor = TlsAcceptor::from(server_config);
	Ok(acceptor)
}

/// Build a `rustls` server config with a freshly generated self-signed
/// certificate for the onion address — the default when the caller did not
/// bring their own.
fn self_signed_server_config(address: &OnionAddress) -> Result<rustls::ServerConfig> {
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
	Ok(server_config)
}

// Then handle_stream_request
async fn handle_stream_request(stream_request: StreamRequest, ctx: ServeContext, circuit_id: CircuitId) -> Result<()> {
	let handling_request_trace_span = span!(Level::INFO, "onyums - handling_request");
	let _handling_request_trace_guard = handling_request_trace_span.enter();
	// The per-port dispatch is factored into the pure, offline-tested
	// `PortRouter::dispatch`; here we only execute it. The built-in TLS-first
	// decision wins for ports 80/443 (so under a `Reject` plaintext policy the
	// port-80 arm resolves to `Reject`, no plaintext handler at all); any other
	// port resolves to a caller-registered raw handler or, with none, a reject.
	let port = match stream_request.request() {
		IncomingStreamRequest::Begin(begin) => begin.port(),
		_ => 0,
	};
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
async fn handle_raw_stream(stream_request: StreamRequest, handler: Arc<dyn StreamHandler>, port: u16) -> Result<()> {
	event!(Level::INFO, "Accepting a raw stream on port {port} for a registered handler...");
	let onion_service_stream = stream_request.accept(Connected::new_empty()).await.map_err(|e| anyhow::anyhow!("failed to accept onion service stream: {e}"))?;
	handler.serve(Box::pin(onion_service_stream)).await
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

	#[test]
	fn qr_svg_is_a_wellformed_svg_document() {
		let address = OnionAddress::normalized("abcdef");
		let svg = address.qr_svg();
		assert!(svg.starts_with("<?xml") || svg.starts_with("<svg"), "should be an SVG document, got: {}", &svg[..svg.len().min(40)]);
		assert!(svg.contains("<svg"), "missing <svg> element");
		assert!(svg.contains("</svg>"), "missing closing </svg>");
		// A real QR renders dark modules as filled rects/paths — a blank/degenerate
		// document would have none.
		assert!(svg.contains("path") || svg.contains("rect"), "SVG has no QR modules");
	}

	#[test]
	fn qr_encoding_is_deterministic_and_address_sensitive() {
		let a = OnionAddress::normalized("abcdef");
		let b = OnionAddress::normalized("ghijkl");
		// Deterministic: same address → identical QR (encoding has no randomness).
		assert_eq!(a.qr_svg(), a.qr_svg());
		assert_eq!(a.qr_terminal(), a.qr_terminal());
		// Address-sensitive: a different URL is encoded into a different QR.
		assert_ne!(a.qr_svg(), b.qr_svg());
		assert_ne!(a.qr_terminal(), b.qr_terminal());
	}

	#[test]
	fn qr_terminal_is_multiline_block_art() {
		let address = OnionAddress::normalized("abcdef");
		let term = address.qr_terminal();
		assert!(!term.is_empty(), "terminal QR must not be empty");
		// Dense1x2 emits one line per two QR rows; a real code is many lines tall.
		assert!(term.lines().count() > 5, "terminal QR should span multiple lines");
	}

	#[tokio::test]
	async fn strict_tls_adds_hsts_header() {
		use tower::ServiceExt as _;

		let app = apply_hsts(Router::new().route("/", get(|| async { "ok" })), Tls::Strict.plaintext_policy());
		let response = app.oneshot(Request::builder().uri("/").body(axum::body::Body::empty()).unwrap()).await.unwrap();
		let hsts = response.headers().get("strict-transport-security").expect("strict mode must emit HSTS");
		assert_eq!(hsts, "max-age=63072000; includeSubDomains");
	}

	#[tokio::test]
	async fn upgrade_tls_omits_hsts_header() {
		use tower::ServiceExt as _;

		let app = apply_hsts(Router::new().route("/", get(|| async { "ok" })), Tls::Upgrade.plaintext_policy());
		let response = app.oneshot(Request::builder().uri("/").body(axum::body::Body::empty()).unwrap()).await.unwrap();
		assert!(response.headers().get("strict-transport-security").is_none(), "upgrade mode must not emit HSTS");
	}

	#[test]
	fn builder_defaults_to_upgrade_tls() {
		let builder = OnionServiceBuilder::default();
		assert!(matches!(builder.tls, Tls::Upgrade));
		let builder = builder.tls(Tls::Strict);
		assert!(matches!(builder.tls, Tls::Strict));
	}

	#[test]
	fn builder_accepts_a_provided_certificate() {
		let ck = rcgen::generate_simple_self_signed(vec!["example.onion".to_string()]).expect("rcgen");
		let provided = ProvidedCert::from_pem(ck.cert.pem().as_bytes(), ck.signing_key.serialize_pem().as_bytes()).expect("valid PEM");
		let builder = OnionServiceBuilder::default().tls(Tls::Provided(provided));
		// A provided cert keeps the forgiving plaintext posture (BYO is orthogonal).
		assert!(matches!(builder.tls, Tls::Provided(_)));
		assert_eq!(builder.tls.plaintext_policy(), tls_policy::PlaintextPolicy::Upgrade);
	}

	#[test]
	fn tls_acceptor_builds_from_a_provided_certificate() {
		let address = OnionAddress::normalized("examplereturnsavalidacceptorpaddingxxxxxxxxxxxxxxxxxxxxx");
		let ck = rcgen::generate_simple_self_signed(vec![address.host().to_string()]).expect("rcgen");
		let provided = ProvidedCert::from_pem(ck.cert.pem().as_bytes(), ck.signing_key.serialize_pem().as_bytes()).expect("valid PEM");
		// The acceptor builds offline for both the self-signed and provided paths.
		tls_acceptor(&address, &Tls::Provided(provided)).expect("provided-cert acceptor");
		tls_acceptor(&address, &Tls::Upgrade).expect("self-signed acceptor");
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

	#[test]
	fn build_port_router_rejects_a_reserved_port() {
		let handlers: Vec<(u16, Arc<dyn StreamHandler>)> = vec![(443, Arc::new(RawTcpHandler::new("127.0.0.1:9000")))];
		// `PortRouter` is not `Debug` (it holds a `dyn StreamHandler`), so take the
		// error via `.err()` rather than `expect_err`.
		let err = build_port_router(handlers).err().expect("443 is reserved for the built-in HTTP handler");
		assert!(err.to_string().contains("reserved"), "unexpected error: {err}");
	}

	#[test]
	fn build_port_router_registers_valid_non_http_ports() {
		let handlers: Vec<(u16, Arc<dyn StreamHandler>)> = vec![
			(9735, Arc::new(RawTcpHandler::new("127.0.0.1:9735"))),
			(2222, Arc::new(RawTcpHandler::new("127.0.0.1:22"))),
		];
		let router = build_port_router(handlers).expect("9735 and 2222 are registerable");
		assert_eq!(router.len(), 2);
		assert!(router.contains_port(9735));
		assert!(router.contains_port(2222));
		// Dispatch routes the registered ports to a raw handler; an unregistered one
		// is still rejected.
		assert!(matches!(router.dispatch(9735, tls_policy::PlaintextPolicy::Upgrade), PortDispatch::Raw(_)));
		assert!(matches!(router.dispatch(8080, tls_policy::PlaintextPolicy::Upgrade), PortDispatch::Reject));
	}

	#[test]
	fn route_port_records_registrations_on_the_builder() {
		let builder = OnionServiceBuilder::default().route_port(9735, RawTcpHandler::new("127.0.0.1:9735"));
		assert_eq!(builder.raw_handlers.len(), 1);
		assert_eq!(builder.raw_handlers[0].0, 9735);
	}

	#[test]
	fn validate_client_choice_only_rejects_ephemeral_shared_client() {
		// A shared Tor client has a fixed keystore, so it cannot also be ephemeral.
		assert!(validate_client_choice(true, true).is_err(), "ephemeral + shared client must conflict");
		// Every other pairing is valid: fresh persistent, fresh ephemeral, shared persistent.
		assert!(validate_client_choice(false, false).is_ok());
		assert!(validate_client_choice(true, false).is_ok());
		assert!(validate_client_choice(false, true).is_ok());
	}

	#[tokio::test]
	async fn builder_route_port_reserved_errors_before_bootstrap() {
		// Router and nickname are both set, so validation reaches the port router —
		// which rejects the reserved port before any Tor bootstrap (offline).
		let app = Router::new().route("/", get(|| async { "hi" }));
		let result = OnionService::builder().router(app).nickname("raw_reserved").route_port(443, RawTcpHandler::new("127.0.0.1:9000")).serve().await;
		let err = result.err().expect("a reserved-port registration should error");
		assert!(err.to_string().contains("reserved"), "unexpected error: {err}");
	}

	#[test]
	fn storage_dirs_persistent_are_the_fixed_onyums_paths() {
		// The default (persistent) identity mode always resolves to the stable
		// onyums directories, so the keystore — and thus the address — survives
		// restarts. Two calls are identical.
		let (state, cache) = storage_dirs(false);
		assert_eq!(state, PERSISTENT_STATE_DIR);
		assert_eq!(cache, CACHE_DIR);
		let (state2, cache2) = storage_dirs(false);
		assert_eq!((state, cache), (state2, cache2), "persistent dirs must be stable across calls");
	}

	#[test]
	fn storage_dirs_ephemeral_are_unique_and_under_temp() {
		// An ephemeral service must never reuse a keystore: each call yields a
		// distinct state dir, located under the OS temp tree and outside the
		// persistent `./tor/onyums` state. The disposable cache is still shared.
		let (state_a, cache_a) = storage_dirs(true);
		let (state_b, _cache_b) = storage_dirs(true);
		assert_ne!(state_a, state_b, "two ephemeral launches must not share a keystore dir");
		assert_ne!(state_a, PERSISTENT_STATE_DIR, "ephemeral state must not be the persistent tree");
		let temp = std::env::temp_dir().to_string_lossy().into_owned();
		assert!(state_a.starts_with(&temp), "ephemeral state {state_a} should live under the temp dir {temp}");
		assert_eq!(cache_a, CACHE_DIR, "the disposable cache is shared across modes");
	}

	#[test]
	fn tor_client_config_builds_offline_for_both_modes() {
		// Config assembly is the offline half of client setup: it must build for
		// both the persistent and ephemeral directory choices with no live Tor
		// network (the dirs are only touched later, at bootstrap).
		let (state, cache) = storage_dirs(false);
		tor_client_config(&state, &cache).expect("persistent client config builds offline");
		let (state, cache) = storage_dirs(true);
		tor_client_config(&state, &cache).expect("ephemeral client config builds offline");
	}

	#[test]
	fn remove_ephemeral_state_dir_removes_our_throwaway_dir() {
		// A directory shaped like one `storage_dirs` mints (populated with a fake
		// keystore file) is removed wholesale.
		let (state, _cache) = storage_dirs(true);
		let dir = std::path::PathBuf::from(&state);
		std::fs::create_dir_all(dir.join("keystore")).expect("create fake ephemeral state");
		std::fs::write(dir.join("keystore").join("hs_ed25519_secret_key"), b"fake").expect("write fake key");
		assert!(dir.exists());
		remove_ephemeral_state_dir(&dir);
		assert!(!dir.exists(), "the ephemeral state dir (and its contents) must be gone");
	}

	#[test]
	fn remove_ephemeral_state_dir_refuses_non_ephemeral_paths() {
		// The safety belt: a directory whose name lacks the ephemeral prefix is never
		// removed, so a mis-threaded path can't delete a persistent tree.
		let guard = std::env::temp_dir().join(format!("onyums-not-ephemeral-{}-{:016x}", std::process::id(), rand::random::<u64>()));
		std::fs::create_dir_all(&guard).expect("create non-ephemeral dir");
		remove_ephemeral_state_dir(&guard);
		assert!(guard.exists(), "a non-ephemeral dir must be left untouched");
		std::fs::remove_dir_all(&guard).ok();
	}

	#[test]
	fn remove_ephemeral_state_dir_is_a_noop_on_missing_dir() {
		// Removing an already-absent ephemeral dir must not panic (idempotent cleanup).
		let (state, _cache) = storage_dirs(true);
		let dir = std::path::PathBuf::from(&state);
		assert!(!dir.exists(), "a freshly-minted ephemeral path does not yet exist");
		remove_ephemeral_state_dir(&dir); // must not panic
	}

	#[test]
	fn spawn_ephemeral_cleanup_runs_inline_without_a_runtime() {
		// Outside any tokio runtime there is nothing to stall: the removal runs inline and
		// the helper reports `None` (nothing to await).
		let (state, _cache) = storage_dirs(true);
		let dir = std::path::PathBuf::from(&state);
		std::fs::create_dir_all(dir.join("keystore")).expect("create fake ephemeral state");
		assert!(dir.exists());
		let handle = spawn_ephemeral_cleanup(dir.clone());
		assert!(handle.is_none(), "with no runtime the removal is inline, not spawned");
		assert!(!dir.exists(), "the ephemeral dir must be gone after an inline cleanup");
	}

	#[tokio::test]
	async fn spawn_ephemeral_cleanup_offloads_to_the_blocking_pool_in_a_runtime() {
		// Inside a runtime the blocking `remove_dir_all` is offloaded (so it never stalls a
		// worker) and the returned handle resolves once the dir is gone — the path
		// `shutdown()` awaits.
		let (state, _cache) = storage_dirs(true);
		let dir = std::path::PathBuf::from(&state);
		std::fs::create_dir_all(dir.join("keystore")).expect("create fake ephemeral state");
		std::fs::write(dir.join("keystore").join("hs_ed25519_secret_key"), b"fake").expect("write fake key");
		assert!(dir.exists());
		let handle = spawn_ephemeral_cleanup(dir.clone()).expect("a live runtime offloads the removal to a task");
		handle.await.expect("the offloaded cleanup task must not panic");
		assert!(!dir.exists(), "the ephemeral dir must be gone after the offloaded cleanup");
	}

	#[test]
	fn spawn_ephemeral_cleanup_still_refuses_non_ephemeral_paths_inline() {
		// The offload path must not weaken the safety belt: a non-ephemeral dir is left
		// untouched even when cleaned up inline.
		let guard = std::env::temp_dir().join(format!("onyums-not-ephemeral-{}-{:016x}", std::process::id(), rand::random::<u64>()));
		std::fs::create_dir_all(&guard).expect("create non-ephemeral dir");
		assert!(spawn_ephemeral_cleanup(guard.clone()).is_none());
		assert!(guard.exists(), "a non-ephemeral dir must survive the cleanup helper");
		std::fs::remove_dir_all(&guard).ok();
	}

	#[test]
	fn builder_defaults_to_persistent_identity() {
		// Stable identity by default (Phase 1): the ephemeral opt-down is off unless
		// explicitly named.
		let builder = OnionServiceBuilder::default();
		assert!(!builder.ephemeral, "identity is persistent by default");
		let builder = builder.ephemeral();
		assert!(builder.ephemeral, "ephemeral() records the throwaway-identity opt-down");
	}

	#[test]
	fn builder_records_under_attack_toggle() {
		let builder = OnionServiceBuilder::default();
		assert!(!builder.under_attack, "Under Attack Mode is off by default");
		let builder = builder.under_attack(true);
		assert!(builder.under_attack, "toggle records on the builder");
	}

	#[test]
	fn under_attack_toggle_challenges_every_circuit() {
		use onyums_skin::CircuitAction;
		// With no custom policy and the toggle on, the resolved default policy
		// challenges every new circuit.
		let policy = resolve_circuit_policy(None, true, None).expect("default policy under attack");
		assert_eq!(policy.on_new_circuit(&CircuitId(1)), CircuitAction::Challenge);
	}

	#[test]
	fn default_circuit_policy_accepts_every_circuit() {
		use onyums_skin::CircuitAction;
		// The default (toggle off) policy is accept-all on a fresh circuit — unchanged
		// behaviour, purely the accounting substrate.
		let policy = resolve_circuit_policy(None, false, None).expect("default accept-all policy");
		assert_eq!(policy.on_new_circuit(&CircuitId(1)), CircuitAction::Accept);
	}

	#[test]
	fn under_attack_conflicts_with_a_custom_circuit_policy() {
		let custom: Arc<dyn CircuitPolicy> = Arc::new(AccountingCircuitPolicy::new());
		let err = resolve_circuit_policy(Some(custom), true, None).err().expect("under_attack + custom policy must conflict");
		assert!(err.to_string().contains("under_attack"), "unexpected error: {err}");
	}

	#[test]
	fn custom_circuit_policy_passes_through_without_the_toggle() {
		use onyums_skin::CircuitAction;
		// A custom policy is handed back untouched when the toggle is off; its own caps
		// (here a stream cap that only trips later) are preserved.
		let custom: Arc<dyn CircuitPolicy> = Arc::new(AccountingCircuitPolicy::new().max_streams(5));
		let policy = resolve_circuit_policy(Some(custom), false, None).expect("custom policy passes through");
		assert_eq!(policy.on_new_circuit(&CircuitId(1)), CircuitAction::Accept);
	}

	#[tokio::test]
	async fn builder_under_attack_conflicts_before_bootstrap() {
		// Router, nickname, a custom policy, and the toggle are all set, so validation
		// reaches the policy resolution — which rejects the conflict before any Tor
		// bootstrap (offline).
		let app = Router::new().route("/", get(|| async { "hi" }));
		let result = OnionService::builder()
			.router(app)
			.nickname("ua_conflict")
			.circuit_policy(Arc::new(AccountingCircuitPolicy::new()))
			.under_attack(true)
			.serve()
			.await;
		let err = result.err().expect("a conflicting under_attack + custom policy should error");
		assert!(err.to_string().contains("under_attack"), "unexpected error: {err}");
	}

	#[test]
	fn skin_client_key_parses_into_arti_descriptor_key() {
		// The cross-crate contract behind restricted-discovery wiring: skin's canonical
		// `descriptor:x25519:<BASE32>` rendering is exactly what Arti's
		// `HsClientDescEncKey` parses, and Arti renders it back identically. Guards
		// against a base32 case / format drift between the two crates.
		let key = ClientAuthKey::from_bytes([13u8; 32]);
		let parsed: HsClientDescEncKey = key.to_string().parse().expect("a skin client key must parse as an Arti client descriptor key");
		assert_eq!(parsed.to_string(), key.to_string(), "Arti must round-trip skin's canonical key form");
	}

	#[test]
	fn builder_records_authorized_clients() {
		let mut allow = RestrictedDiscovery::new();
		allow.authorize("alice", ClientAuthKey::from_bytes([3u8; 32]));
		let builder = OnionServiceBuilder::default().authorized_clients(allow);
		let recorded = builder.restricted_discovery.as_ref().expect("allowlist recorded on the builder");
		assert_eq!(recorded.len(), 1);
	}

	#[test]
	fn restricted_discovery_config_assembles_offline() {
		// A non-empty allowlist assembles into a valid onion service config with no live
		// Tor network — Arti's own config validation runs during `build`.
		let mut allow = RestrictedDiscovery::new();
		allow.authorize("alice", ClientAuthKey::from_bytes([7u8; 32]));
		allow.authorize("bob", ClientAuthKey::from_bytes([42u8; 32]));
		build_onion_service_config("restricted_svc", Some(&allow)).expect("restricted-discovery config builds offline");
	}

	#[test]
	fn config_without_restricted_discovery_still_builds() {
		// The default publicly-discoverable path is unchanged when no allowlist is set.
		build_onion_service_config("plain_svc", None).expect("plain config builds offline");
	}

	#[test]
	fn empty_allowlist_is_rejected_offline() {
		// Enabling restricted discovery with no clients would hide the service from
		// everyone — rejected before any bootstrap.
		let allow = RestrictedDiscovery::new();
		let err = build_onion_service_config("empty_allow", Some(&allow)).expect_err("an empty allowlist must be rejected");
		assert!(err.to_string().contains("empty"), "unexpected error: {err}");
	}

	#[test]
	fn invalid_client_nickname_is_rejected_offline() {
		// A nickname that is not a valid Tor client slug (spaces) surfaces offline as a
		// clear error rather than a late launch failure.
		let mut allow = RestrictedDiscovery::new();
		allow.authorize("not a slug", ClientAuthKey::from_bytes([1u8; 32]));
		let err = build_onion_service_config("bad_nick", Some(&allow)).expect_err("an invalid client nickname must be rejected");
		assert!(err.to_string().contains("nickname"), "unexpected error: {err}");
	}

	#[test]
	fn service_nickname_parse_error_preserves_the_arti_cause() {
		// The service nickname takes the same context-preserving `map_err` as the other
		// Tor-bootstrap sites: a bad nickname surfaces *why* (arti's underlying parse
		// error) appended to onyums' context, not a bare "Failed to parse nickname."
		let err = build_onion_service_config("bad service nickname", None).expect_err("a nickname with spaces must be rejected");
		let msg = err.to_string();
		assert!(msg.starts_with("Failed to parse nickname: "), "missing onyums context: {msg}");
		// The underlying arti `InvalidNickname` Display must be carried, not dropped —
		// the whole point of replacing `map_err(|_| ...)` with `map_err(|e| ...: {e})`.
		assert!(msg.len() > "Failed to parse nickname: ".len(), "arti cause was dropped: {msg}");
	}

	#[tokio::test]
	async fn builder_empty_allowlist_errors_before_bootstrap() {
		// Router and nickname are set, so validation reaches the config assembly, which
		// rejects the empty allowlist before any Tor bootstrap (offline).
		let app = Router::new().route("/", get(|| async { "hi" }));
		let result = OnionService::builder().router(app).nickname("empty_ac").authorized_clients(RestrictedDiscovery::new()).serve().await;
		let err = result.err().expect("an empty authorized_clients allowlist should error");
		assert!(err.to_string().contains("empty"), "unexpected error: {err}");
	}

	#[test]
	fn builder_records_circuit_events_sink() {
		use onyums_skin::CapturingSink;
		let builder = OnionServiceBuilder::default().circuit_events(Arc::new(CapturingSink::new()));
		assert!(builder.circuit_events.is_some(), "the sink is recorded on the builder");
	}

	#[test]
	fn circuit_events_are_emitted_under_attack() {
		use onyums_skin::CapturingSink;
		// A default policy with a sink, under attack: the challenged circuit records one event.
		let sink = Arc::new(CapturingSink::new());
		let policy = resolve_circuit_policy(None, true, Some(sink.clone())).expect("default policy with events");
		assert_eq!(policy.on_new_circuit(&CircuitId(1)), onyums_skin::CircuitAction::Challenge);
		assert_eq!(sink.len(), 1, "the challenged circuit should emit one security event");
	}

	#[test]
	fn circuit_events_silent_when_accepting() {
		use onyums_skin::CapturingSink;
		// With no attack and no cap tripped, an accepted circuit emits nothing — the sink
		// only sees non-Accept actions.
		let sink = Arc::new(CapturingSink::new());
		let policy = resolve_circuit_policy(None, false, Some(sink.clone())).expect("default policy with events");
		let _ = policy.on_new_circuit(&CircuitId(1));
		assert!(sink.is_empty(), "an accepted circuit emits no event");
	}

	#[test]
	fn circuit_events_conflict_with_a_custom_policy() {
		use onyums_skin::CapturingSink;
		let custom: Arc<dyn CircuitPolicy> = Arc::new(AccountingCircuitPolicy::new());
		let err = resolve_circuit_policy(Some(custom), false, Some(Arc::new(CapturingSink::new()))).err().expect("a sink + custom policy must conflict");
		assert!(err.to_string().contains("circuit_policy"), "unexpected error: {err}");
	}

	#[tokio::test]
	async fn serve_router_gates_and_adds_hsts_under_strict_tls() {
		use http_body_util::BodyExt as _;
		use tower::ServiceExt as _;

		// The full serve-path stack under the secure default + strict TLS: an uncleared
		// request is intercepted by the gate (never reaching the app) AND the response
		// carries HSTS. Exercises the composition serve() builds, with no live Tor.
		let app = build_serve_router(Router::new().route("/", get(|| async { "secret" })), SkinChoice::Default, Tls::Strict.plaintext_policy());
		let response = app.oneshot(Request::builder().uri("/").body(axum::body::Body::empty()).unwrap()).await.unwrap();
		let hsts = response.headers().get("strict-transport-security").expect("strict TLS must emit HSTS on the gate's own response");
		assert_eq!(hsts, "max-age=63072000; includeSubDomains");
		let body = response.into_body().collect().await.unwrap().to_bytes();
		assert!(!String::from_utf8_lossy(&body).contains("secret"), "the gated app must not leak through the composed stack");
	}

	#[tokio::test]
	async fn serve_router_no_skin_reaches_app_without_hsts_under_upgrade() {
		use http_body_util::BodyExt as _;
		use tower::ServiceExt as _;

		// Opt-down: no gate + upgrade TLS — the app is reached and no HSTS is added.
		let app = build_serve_router(Router::new().route("/", get(|| async { "reached" })), SkinChoice::Disabled, Tls::Upgrade.plaintext_policy());
		let response = app.oneshot(Request::builder().uri("/").body(axum::body::Body::empty()).unwrap()).await.unwrap();
		assert!(response.headers().get("strict-transport-security").is_none(), "upgrade TLS emits no HSTS");
		let body = response.into_body().collect().await.unwrap().to_bytes();
		assert_eq!(String::from_utf8_lossy(&body), "reached", "no_skin lets the request reach the app");
	}

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

	#[test]
	fn service_status_projects_every_arti_state() {
		use tor_hsservice::status::State;
		// Every known arti onion-service state maps onto onyums' stable projection.
		// If arti adds or renames a state, this stops compiling (the `State` import)
		// or the assertion drifts — a deliberate tripwire for the non_exhaustive enum.
		assert_eq!(project_service_status(State::Shutdown), ServiceStatus::Shutdown);
		assert_eq!(project_service_status(State::Bootstrapping), ServiceStatus::Bootstrapping);
		assert_eq!(project_service_status(State::Running), ServiceStatus::Reachable);
		assert_eq!(project_service_status(State::DegradedReachable), ServiceStatus::DegradedReachable);
		assert_eq!(project_service_status(State::DegradedUnreachable), ServiceStatus::Unreachable);
		assert_eq!(project_service_status(State::Recovering), ServiceStatus::Unreachable);
		assert_eq!(project_service_status(State::Broken), ServiceStatus::Broken);
	}

	#[test]
	fn service_problem_projects_arti_problem_categories() {
		use tor_hsservice::status::Problem;
		// Empty vecs exercise the category mapping without constructing arti's internal
		// error types — the projection keys only on the `Problem` variant. If arti adds
		// or renames a `Problem` category the `_` arm keeps this compiling but the new
		// case reads as `Other`, the conservative default.
		assert_eq!(project_service_problem(&Problem::Ipt(Vec::new())).kind(), ServiceProblemKind::IntroductionPoint);
		assert_eq!(project_service_problem(&Problem::DescriptorUpload(Vec::new())).kind(), ServiceProblemKind::DescriptorUpload);
		// The diagnostic detail is arti's `Debug` rendering, captured (not dropped) even
		// though arti's `Problem` has no `Display`; an empty intro-point error list
		// renders as an empty debug vec.
		assert_eq!(project_service_problem(&Problem::Ipt(Vec::new())).detail(), "[]");
	}

	#[test]
	fn service_problem_surface_is_stable_and_distinct() {
		use ServiceProblem::{DescriptorUpload, IntroductionPoint, Other, Runtime};
		let all = [
			Runtime("boom".into()),
			DescriptorUpload("upload failed".into()),
			IntroductionPoint("no ipts".into()),
			Other("mystery".into()),
		];
		// `detail()` round-trips the diagnostic; `Display` is exactly `"<label>: <detail>"`.
		for p in &all {
			assert!(!p.label().is_empty());
			assert_eq!(p.to_string(), format!("{}: {}", p.label(), p.detail()));
			// The category label is the kind's label.
			assert_eq!(p.label(), p.kind().label());
		}
		assert_eq!(Runtime("boom".into()).detail(), "boom");

		// Labels are distinct across the four categories (a downstream may match on them).
		let labels: std::collections::HashSet<_> = all.iter().map(ServiceProblem::label).collect();
		assert_eq!(labels.len(), all.len(), "labels must be distinct");

		// Only a runtime error is fatal; the retriable problems are not.
		assert!(Runtime("x".into()).is_fatal());
		for p in [DescriptorUpload("x".into()), IntroductionPoint("x".into()), Other("x".into())] {
			assert!(!p.is_fatal(), "{p:?} must not read as fatal");
		}
	}

	#[test]
	fn service_health_bundles_status_and_problem_consistently() {
		use ServiceStatus::{Broken, DegradedReachable, Reachable, Unreachable};

		// Fully healthy: reachable, no problem — Display is just the status label.
		let healthy = ServiceHealth { status: Reachable, problem: None };
		assert_eq!(healthy.status(), Reachable);
		assert!(healthy.is_reachable());
		assert!(healthy.is_healthy());
		assert!(healthy.problem().is_none());
		assert_eq!(healthy.to_string(), "reachable");

		// Reachable but degraded and carrying a problem: reachable, yet not fully healthy.
		let degraded = ServiceHealth { status: DegradedReachable, problem: Some(ServiceProblem::IntroductionPoint("[]".into())) };
		assert!(degraded.is_reachable());
		assert!(!degraded.is_healthy(), "a reachable service carrying a problem is not fully healthy");
		assert_eq!(degraded.problem().map(ServiceProblem::kind), Some(ServiceProblemKind::IntroductionPoint));

		// Broken with a fatal problem: neither reachable nor healthy; Display shows the why.
		let broken = ServiceHealth { status: Broken, problem: Some(ServiceProblem::Runtime("boom".into())) };
		assert!(!broken.is_reachable());
		assert!(!broken.is_healthy());
		assert!(broken.problem().is_some_and(ServiceProblem::is_fatal));
		assert_eq!(broken.to_string(), "broken — runtime: boom");

		// A non-reachable status with no reported problem still renders as just the status.
		let quiet = ServiceHealth { status: Unreachable, problem: None };
		assert_eq!(quiet.to_string(), "unreachable");
		assert!(!quiet.is_healthy());
	}

	#[test]
	fn service_status_reachability_matches_arti_semantics() {
		use tor_hsservice::status::State;
		// onyums' `is_reachable` must agree with arti's own `is_fully_reachable` for
		// every known state — the projection must not change the reachability verdict.
		for state in [State::Shutdown, State::Bootstrapping, State::Running, State::DegradedReachable, State::DegradedUnreachable, State::Recovering, State::Broken] {
			assert_eq!(project_service_status(state).is_reachable(), state.is_fully_reachable(), "reachability disagreement for {state:?}");
		}
		// Spot-check the two reachable states and one non-reachable one directly.
		assert!(ServiceStatus::Reachable.is_reachable());
		assert!(ServiceStatus::DegradedReachable.is_reachable());
		assert!(!ServiceStatus::Bootstrapping.is_reachable());
	}

	#[test]
	fn service_status_predicates_partition_the_lifecycle() {
		use ServiceStatus::{Bootstrapping, Broken, DegradedReachable, Reachable, Shutdown, Unreachable};

		// `is_degraded` is exactly `DegradedReachable`, and it implies reachability.
		assert!(DegradedReachable.is_degraded());
		assert!(DegradedReachable.is_reachable());
		for s in [Shutdown, Bootstrapping, Reachable, Unreachable, Broken] {
			assert!(!s.is_degraded(), "{s:?} must not read as degraded");
		}

		// `is_broken` is exactly `Broken` — never the transient `Unreachable`.
		assert!(Broken.is_broken());
		assert!(!Unreachable.is_broken());

		// `is_terminal` is exactly the settled states, and is disjoint from reachability:
		// a service is never both reachable and terminal.
		assert!(Shutdown.is_terminal());
		assert!(Broken.is_terminal());
		for s in [Bootstrapping, Reachable, DegradedReachable, Unreachable] {
			assert!(!s.is_terminal(), "{s:?} must not read as terminal");
		}
		for s in [Shutdown, Bootstrapping, Reachable, DegradedReachable, Unreachable, Broken] {
			assert!(!(s.is_reachable() && s.is_terminal()), "{s:?} cannot be both reachable and terminal");
		}
	}

	#[test]
	fn service_status_label_and_display_are_stable_and_distinct() {
		use ServiceStatus::{Bootstrapping, Broken, DegradedReachable, Reachable, Shutdown, Unreachable};

		let all = [Shutdown, Bootstrapping, Reachable, DegradedReachable, Unreachable, Broken];
		// `Display` writes the stable `label`.
		for s in all {
			assert_eq!(s.to_string(), s.label());
			assert!(!s.label().is_empty());
		}
		// Labels are pinned (a downstream health check may match on them) and distinct.
		assert_eq!(Reachable.label(), "reachable");
		assert_eq!(DegradedReachable.label(), "degraded");
		assert_eq!(Broken.label(), "broken");
		let labels: std::collections::HashSet<&str> = all.iter().map(|s| s.label()).collect();
		assert_eq!(labels.len(), all.len(), "every status needs a distinct label");
	}

	#[test]
	fn worst_of_surfaces_the_least_healthy_service_in_a_fleet() {
		use ServiceStatus::{Bootstrapping, Broken, DegradedReachable, Reachable, Shutdown, Unreachable};

		// Empty fleet has no aggregate health.
		assert_eq!(ServiceStatus::worst_of([]), None);
		// All-reachable stays reachable; a single element is itself.
		assert_eq!(ServiceStatus::worst_of([Reachable, Reachable]), Some(Reachable));
		assert_eq!(ServiceStatus::worst_of([Bootstrapping]), Some(Bootstrapping));
		// One degraded among reachable surfaces the degradation.
		assert_eq!(ServiceStatus::worst_of([Reachable, DegradedReachable, Reachable]), Some(DegradedReachable));
		// A broken (or shut-down) service is never masked by healthy siblings; Shutdown
		// ranks worst of all.
		assert_eq!(ServiceStatus::worst_of([Reachable, Broken, DegradedReachable]), Some(Broken));
		assert_eq!(ServiceStatus::worst_of([Broken, Shutdown, Reachable]), Some(Shutdown));
		// Bootstrapping (coming up) is treated as less severe than a transient Unreachable.
		assert_eq!(ServiceStatus::worst_of([Bootstrapping, Unreachable]), Some(Unreachable));

		// The severity ranking is total and distinct — no two states share a rank, so the
		// fold is deterministic.
		let all = [Shutdown, Bootstrapping, Reachable, DegradedReachable, Unreachable, Broken];
		let ranks: std::collections::HashSet<u8> = all.iter().map(|s| s.severity()).collect();
		assert_eq!(ranks.len(), all.len(), "every status needs a distinct severity rank");
	}

	#[tokio::test]
	async fn await_status_resolves_on_the_first_match() {
		use ServiceStatus::{Bootstrapping, DegradedReachable, Reachable, Unreachable};

		// Resolves on the first reachable item, returning *which* reachable status it saw.
		let stream = futures::stream::iter([Bootstrapping, Unreachable, Reachable]);
		assert_eq!(await_status(stream, ServiceStatus::is_reachable).await, Some(Reachable));

		// The very first item already matching is returned immediately (mirrors a service
		// that is reachable the moment the caller subscribes).
		let stream = futures::stream::iter([DegradedReachable, Reachable]);
		assert_eq!(await_status(stream, ServiceStatus::is_reachable).await, Some(DegradedReachable));
	}

	#[tokio::test]
	async fn await_status_returns_none_when_the_stream_ends_unmatched() {
		use ServiceStatus::{Bootstrapping, Shutdown, Unreachable};

		// A stream that ends without ever reaching a reachable state (service torn down
		// mid-bootstrap) resolves to `None` rather than hanging — this is why
		// `ready_timeout` reports `false` on a dropped service.
		let stream = futures::stream::iter([Bootstrapping, Unreachable, Shutdown]);
		assert_eq!(await_status(stream, ServiceStatus::is_reachable).await, None);

		let empty = futures::stream::iter(Vec::<ServiceStatus>::new());
		assert_eq!(await_status(empty, ServiceStatus::is_reachable).await, None);
	}

	#[tokio::test]
	async fn await_status_settles_on_reachable_or_terminal() {
		use ServiceStatus::{Bootstrapping, Broken, Reachable, Unreachable};

		// The `wait_until_settled` predicate: a service that *broke* during bootstrap
		// settles on `Broken`, so a caller distinguishes "gave up" from "came up" instead
		// of waiting on reachability that will never arrive.
		let settled = |s: ServiceStatus| s.is_reachable() || s.is_terminal();
		let stream = futures::stream::iter([Bootstrapping, Unreachable, Broken]);
		assert_eq!(await_status(stream, settled).await, Some(Broken));

		// Reachability settles too — the ordinary success path.
		let stream = futures::stream::iter([Bootstrapping, Reachable]);
		assert_eq!(await_status(stream, settled).await, Some(Reachable));

		// Only-ever-transient churn never settles → `None` (which `wait_until_settled`
		// maps to `Shutdown` for a torn-down stream).
		let stream = futures::stream::iter([Bootstrapping, Unreachable, Bootstrapping]);
		assert_eq!(await_status(stream, settled).await, None);
	}

	#[tokio::test]
	async fn await_status_under_timeout_gives_up_on_a_stalled_stream() {
		// The exact composition `ready_timeout` relies on: a status stream that never
		// yields a matching item must elapse rather than block forever. `pending` never
		// resolves, so a short real deadline reliably elapses (no timing race — the
		// future genuinely cannot complete).
		let stalled = futures::stream::pending::<ServiceStatus>();
		let outcome = tokio::time::timeout(std::time::Duration::from_millis(20), await_status(stalled, ServiceStatus::is_reachable)).await;
		assert!(outcome.is_err(), "a stalled stream must time out");
		// And the `ready_timeout` fold of that result reads as not-ready.
		assert!(outcome.ok().flatten().is_none());
	}

	#[test]
	fn arti_stack_is_reexported() {
		// Compile-time proof that the arti stack is reachable through onyums, so a
		// downstream needn't add its own version-skew-prone arti dependency. If any
		// re-export path breaks, this stops compiling.
		type _Client = crate::arti_client::TorClient<crate::tor_rtcompat::tokio::TokioNativeTlsRuntime>;
		type _Key = crate::tor_hscrypto::pk::HsClientDescEncKey;
		type _Cfg = crate::tor_hsservice::config::OnionServiceConfigBuilder;
		type _Cell = crate::tor_cell::relaycell::msg::End;
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

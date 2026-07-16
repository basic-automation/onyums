//! The builder and its launch path (onyums ROADMAP Phase 0 — the closing `builder.rs`
//! slice of the lib.rs split).
//!
//! [`OnionServiceBuilder`] is the crate's front door for anything beyond
//! [`serve`]: it collects the caller's choices — router, nickname, TLS policy, Skin
//! gate, circuit policy, identity mode, authorized clients, raw ports — and
//! [`OnionServiceBuilder::serve`] turns them into a launched service plus its
//! [`OnionServiceHandle`](crate::OnionServiceHandle).
//!
//! The ordering in `serve` is the design: **everything that can fail offline fails
//! before the Tor bootstrap.** A bad nickname, an empty allowlist, a reserved or
//! duplicate port, an `ephemeral()` + `tor_client()` conflict, an Under-Attack toggle
//! against a custom policy — each is rejected by a pure, unit-tested helper
//! ([`resolve_circuit_policy`], [`validate_client_choice`],
//! [`build_onion_service_config`], [`PortRouter::from_registrations`]) before the slow,
//! network-dependent part begins. That is what makes most of this module testable with
//! no live Tor, and why the tests below can cover the builder without one.

use std::sync::Arc;

use anyhow::{bail, Result};
use arti_client::TorClient;
use axum::Router;
use futures::Stream;
use onyums_skin::{AccountingCircuitPolicy, AdaptiveDifficulty, CircuitPolicy, RestrictedDiscovery, SecurityEventSink, Skin};
use safelog::DisplayRedacted;
use tokio_util::sync::CancellationToken;
use tor_hsservice::{
	config::OnionServiceConfig, RendRequest, RunningOnionService
};
use tor_rtcompat::tokio::TokioNativeTlsRuntime;
use tracing::{event, span, Level};

use crate::{
	address::OnionAddress, handle::OnionServiceHandle, http_stack::{build_serve_router, SkinChoice}, metrics::CircuitMetrics, port_router::{PortRouter, StreamHandler}, serve_loop::{serve_circuits, ServeContext}, service_config::build_onion_service_config, tls_policy::Tls, tls_setup::tls_acceptor, tor_client::{claim_ephemeral_dir, setup_tor_client, storage_dirs, sweep_stale_ephemeral_dirs, EphemeralIdentity}
};

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

/// Initializes the onion service from a built config and returns the service and
/// request stream.
fn initialize_onion_service(client: &TorClient<TokioNativeTlsRuntime>, svc_cfg: OnionServiceConfig) -> Result<(Arc<RunningOnionService>, OnionAddress, impl Stream<Item = RendRequest> + use<>)> {
	let (service, request_stream) = launch_onion_service(client, svc_cfg)?;
	let address = get_onion_address(&service)?;
	Ok((service, address, request_stream))
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
	// Shared with the caller's `Skin`: the accept loop records each offered rendezvous
	// circuit here so the PoW difficulty reacts to circuit floods skin cannot see
	// (Phase 2 — feed the adaptive-difficulty signal from onyums-observed circuit rate).
	adaptive_difficulty: Option<Arc<AdaptiveDifficulty>>,
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

	/// Feed onyums-observed rendezvous-circuit arrivals into a Skin
	/// [`AdaptiveDifficulty`] controller (onyums ROADMAP Phase 2).
	///
	/// Skin raises its proof-of-work difficulty from the request rate it observes — but it
	/// only sees requests that reached the HTTP gate. A flood of rendezvous circuits that
	/// never speak HTTP, or that the circuit policy rejects outright, costs you real work
	/// while skin's counter reads zero and its difficulty stays dormant. onyums sits at the
	/// circuit boundary and sees them, so pass the *same* controller here that you gave your
	/// challenge, and both signals drive one difficulty.
	///
	/// ```rust,no_run
	/// # fn f() -> anyhow::Result<()> {
	/// use std::sync::Arc;
	/// use onyums::{onyums_skin::AdaptiveDifficulty, OnionService};
	///
	/// // One controller, shared: the challenge reads it, the accept loop feeds it.
	/// let difficulty = Arc::new(AdaptiveDifficulty::new(8, 22));
	/// let builder = OnionService::builder()
	///     .nickname("my_onion")
	///     .adaptive_difficulty(Arc::clone(&difficulty));
	/// // ...and give `difficulty` to your PowChallenge via `with_adaptive_difficulty`.
	/// # Ok(())
	/// # }
	/// ```
	///
	/// Optional: with no controller the loop records nothing, which is today's behaviour.
	#[must_use]
	pub fn adaptive_difficulty(mut self, controller: Arc<AdaptiveDifficulty>) -> Self {
		self.adaptive_difficulty = Some(controller);
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
	/// [`ClientAuthKey`](crate::ClientAuthKey)), the service publishes a descriptor whose introduction
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
	/// or by authorizing [`ClientAuthKey`](crate::ClientAuthKey)s directly. Restricted discovery is a
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
	/// unique, throwaway directory under the system temp dir (see `storage_dirs`):
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
		let port_router = Arc::new(PortRouter::from_registrations(self.raw_handlers)?);

		// A raw port is the one hole in the secure-by-default posture: its stream goes
		// straight to the handler, so the Skin gate, WAF, rate limiting, and built-in TLS
		// do not apply. Log that at launch — the decision is made in code that may be far
		// from whoever operates the service (ROADMAP Phase 2 — raw-port security
		// controls). A well-known admin/datastore port is named explicitly.
		for exposure in port_router.exposures() {
			event!(Level::WARN, "{}", exposure.message());
		}

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
		let (client, ephemeral) = if let Some(shared) = self.tor_client {
			(shared, None)
		} else {
			let (state_dir, cache_dir) = storage_dirs(self.ephemeral);
			// Before minting another throwaway identity, clear out the ones previous runs
			// left behind. `shutdown`/`Drop` remove *this* run's dir, but neither runs if
			// the process is SIGKILLed or OOM-killed — and no signal handler can change
			// that — so an abandoned identity key would linger indefinitely. The sweep only
			// removes a dir whose owner claim is free, so a long-running sibling's keystore
			// is never touched (ROADMAP Phase 2 — guaranteed ephemeral cleanup).
			if self.ephemeral {
				let swept = sweep_stale_ephemeral_dirs(&std::env::temp_dir());
				if swept > 0 {
					event!(Level::INFO, "Swept {swept} abandoned ephemeral keystore(s) left by previous runs.");
				}
			}
			// `setup_tor_client` creates and hardens the state dir, so the claim — a
			// lockfile *inside* it — is taken after, and held by the handle for the
			// service's lifetime.
			let client = setup_tor_client(&state_dir, &cache_dir).await?;
			let ephemeral = if self.ephemeral {
				let dir = std::path::PathBuf::from(&state_dir);
				let claim = claim_ephemeral_dir(&dir)?;
				Some(EphemeralIdentity::new(dir, claim))
			} else {
				None
			};
			(client, ephemeral)
		};
		let (service, address, request_stream) = initialize_onion_service(&client, svc_cfg)?;
		let tls_acceptor = tls_acceptor(&address, &self.tls)?;

		// Bundle everything the loop threads down to each served stream into one
		// cheaply-cloned context (see [`ServeContext`]). The metrics counters are shared
		// with the handle so `metrics()` reads what the loop increments.
		let metrics = Arc::new(CircuitMetrics::default());
		let ctx = ServeContext { app, tls_acceptor, address: address.clone(), plaintext, port_router, metrics: Arc::clone(&metrics), adaptive: self.adaptive_difficulty };

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

		Ok(OnionServiceHandle::new(address, service, client, cancel, task, metrics, ephemeral))
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


#[cfg(test)]
mod tests {
	use axum::{routing::get, Router};
	use onyums_skin::{CircuitId, ClientAuthKey};

	use super::*;
	use crate::{provided_cert::ProvidedCert, raw_tcp::RawTcpHandler, tls_policy};

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
		let parsed: crate::tor_hscrypto::pk::HsClientDescEncKey = key.to_string().parse().expect("a skin client key must parse as an Arti client descriptor key");
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

}

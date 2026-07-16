//! The running service's handle (onyums ROADMAP Phase 0 — the `handle.rs` slice of
//! the lib.rs split).
//!
//! [`OnionServiceHandle`] is what `OnionServiceBuilder::serve` hands back: the
//! per-service replacement for the old poll-a-global `get_onion_name()` pattern. It
//! owns the live service and its Tor client, and is the one place a caller observes
//! readiness ([`ready`](OnionServiceHandle::ready) and friends), reads health
//! ([`status`](OnionServiceHandle::status) / [`problem`](OnionServiceHandle::problem)
//! / [`health`](OnionServiceHandle::health)), reads counters
//! ([`metrics`](OnionServiceHandle::metrics)), and stops the service
//! ([`shutdown`](OnionServiceHandle::shutdown)).
//!
//! The handle is mostly a *projection* surface: the arti reads it performs are
//! translated by [`status`](crate::status) and [`metrics`](crate::metrics), both of
//! which are offline-tested, so what lives here is lifecycle — the cancellation token,
//! the accept-loop task, and the ephemeral keystore's teardown on drop.

use std::sync::{Arc, Mutex};

use arti_client::TorClient;
use futures::{Stream, StreamExt};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tor_hsservice::RunningOnionService;
use tor_rtcompat::tokio::TokioNativeTlsRuntime;

use crate::{
	address::OnionAddress, metrics::{service_metrics_prometheus, CircuitMetrics, ServiceMetrics}, status::{await_status, project_service_problem, project_service_status, ServiceHealth, ServiceProblem, ServiceStatus}, tor_client::spawn_ephemeral_cleanup
};

/// A running onion service plus its controls.
///
/// Returned by [`OnionServiceBuilder::serve`](crate::OnionServiceBuilder::serve). The accept loop runs on a spawned
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
	// Shared with the accept loop's `ServeContext`; the loop increments, `metrics()`
	// snapshots (onyums ROADMAP Phase 4 — per-service metrics).
	metrics: Arc<CircuitMetrics>,
	// Set only for an ephemeral service (see `OnionServiceBuilder::ephemeral`): the
	// throwaway temp state dir, removed when the handle drops so the disposable
	// identity key does not linger on disk. `Mutex<Option<..>>` so `shutdown` can
	// `take()` and await the removal while `Drop` only cleans up what shutdown left.
	ephemeral_state_dir: Mutex<Option<std::path::PathBuf>>,
}

impl OnionServiceHandle {
	/// Assemble the handle for a service the builder has just launched.
	///
	/// Crate-internal: a handle is only ever minted by
	/// [`OnionServiceBuilder::serve`](crate::OnionServiceBuilder::serve), which is what
	/// makes its fields' invariants hold (the cancellation token drives *that* accept
	/// loop task; the metrics counters are the ones *that* loop increments). Taking the
	/// raw parts and doing the `Mutex` wrapping here keeps those fields private to this
	/// module rather than exposing seven of them to lib.rs.
	pub(crate) const fn new(
		address: OnionAddress,
		service: Arc<RunningOnionService>,
		client: Arc<TorClient<TokioNativeTlsRuntime>>,
		cancel: CancellationToken,
		task: JoinHandle<()>,
		metrics: Arc<CircuitMetrics>,
		ephemeral_state_dir: Option<std::path::PathBuf>,
	) -> Self {
		Self { address, service, client, cancel, task: Mutex::new(Some(task)), metrics, ephemeral_state_dir: Mutex::new(ephemeral_state_dir) }
	}

	/// The service's stable `.onion` address.
	#[must_use]
	pub const fn onion_address(&self) -> &OnionAddress {
		&self.address
	}

	/// This service's Tor client, for launching sibling services on the same bootstrap
	/// (onyums ROADMAP Phase 4 — multiple services on one shared client).
	///
	/// Bootstrap is the slow part of coming up; hand this `Arc` to another
	/// [`OnionServiceBuilder::tor_client`](crate::OnionServiceBuilder::tor_client) to bring up more services without a second
	/// bootstrap. Equivalent to sharing an [`OnionService::shared_client`](crate::OnionService::shared_client) up front, but
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
		ServiceHealth::new(project_service_status(raw.state()), raw.current_problem().map(project_service_problem))
	}

	/// A snapshot of this service's cumulative circuit/stream counters — a
	/// [`ServiceMetrics`] (onyums ROADMAP Phase 4 — per-service metrics).
	///
	/// Counters are monotonic totals since launch, incremented by the accept loop:
	/// circuits offered / accepted / rejected at the circuit-policy gate, and streams
	/// served / rejected / circuit-torn-down at the per-stream gate. Snapshot twice and
	/// subtract for a rate, or expose the raw totals to a Prometheus/OpenTelemetry
	/// exporter. Cheap and non-blocking — a plain atomic read per counter.
	#[must_use]
	pub fn metrics(&self) -> ServiceMetrics {
		self.metrics.snapshot()
	}

	/// This service's [`metrics`](Self::metrics) rendered in the Prometheus text
	/// exposition format, labeled with the service's `.onion` address under the
	/// `service` key (onyums ROADMAP Phase 4 — per-service metrics).
	///
	/// The ready-to-serve body for a single service's `/metrics` endpoint, each series
	/// carrying its `service="…​.onion"` label. Equivalent to
	/// `self.metrics().to_prometheus_labeled(&[("service", self.onion_address().as_str())])`.
	///
	/// For **several** services, do not concatenate these outputs — that repeats each
	/// metric's HELP/TYPE header, which strict Prometheus parsers reject. Use
	/// [`fleet_prometheus`](crate::fleet_prometheus) instead, which emits the headers once.
	#[must_use]
	pub fn metrics_prometheus(&self) -> String {
		service_metrics_prometheus(self.metrics(), &self.address)
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
	pub(crate) async fn join(&self) {
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


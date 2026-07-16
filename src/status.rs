//! Stable projections of an onion service's reachability and health
//! (onyums ROADMAP Phase 4 — observability).
//!
//! [`ServiceStatus`] and [`ServiceProblem`]/[`ServiceProblemKind`] are onyums' own,
//! `#[non_exhaustive]`-proof projections of arti's onion-service `State` and `Problem`,
//! the same pattern as [`OnionAddress`](crate::OnionAddress): downstreams match on them
//! exhaustively without a wildcard and without breaking when arti adds a variant.
//! [`ServiceHealth`] bundles the two from a single arti read. `project_service_status` /
//! `project_service_problem` are the pure, offline-testable mappings, and `await_status`
//! is the stream-wait helper behind [`OnionServiceHandle::ready`](crate::OnionServiceHandle::ready)
//! and its timeout/settle siblings. Extracted from `lib.rs` as a slice of the Phase 0
//! module split.

use futures::{Stream, StreamExt};

/// A stable, high-level snapshot of an onion service's reachability
/// (onyums ROADMAP Phase 4 — observability).
///
/// This is onyums' own projection of arti's `#[non_exhaustive]`
/// [`tor_hsservice::status::State`], the same way [`OnionAddress`](crate::OnionAddress) and
/// [`ConnectionInfo`](crate::ConnectionInfo) are typed projections of arti primitives: downstreams match on
/// this exhaustively without a wildcard and without breaking when arti adds a state,
/// and read reachability through [`is_reachable`](Self::is_reachable) rather than
/// re-deriving arti's `is_fully_reachable` semantics. Read the current value from a
/// running service via [`OnionServiceHandle::status`](crate::OnionServiceHandle::status).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStatus {
	/// Not launched, or shut down. Not reachable.
	Shutdown,
	/// Building introduction points and publishing the descriptor; no significant
	/// problems yet, but not yet reachable. This is the state a freshly launched
	/// service passes through before [`OnionServiceHandle::ready`](crate::OnionServiceHandle::ready) resolves.
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
	/// is pointless. See [`OnionServiceHandle::wait_until_settled`](crate::OnionServiceHandle::wait_until_settled), which resolves once
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
	/// [`OnionServiceBuilder::tor_client`](crate::OnionServiceBuilder::tor_client)). Returns `None` for an empty iterator.
	///
	/// Folds by `severity`, so a single unhealthy service in a fleet is
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
pub const fn project_service_status(state: tor_hsservice::status::State) -> ServiceStatus {
	use tor_hsservice::status::State;
	match state {
		State::Shutdown => ServiceStatus::Shutdown,
		State::Bootstrapping => ServiceStatus::Bootstrapping,
		State::Running => ServiceStatus::Reachable,
		State::DegradedReachable => ServiceStatus::DegradedReachable,
		State::Broken => ServiceStatus::Broken,
		// `DegradedUnreachable` / `Recovering` are the known transient-not-reachable
		// states, and `State` is `#[non_exhaustive]`, so any state arti adds later also
		// reads as not-reachable until onyums maps it explicitly — one arm covers both.
		// `service_status_projects_every_arti_state` pins the per-state mapping (and stops
		// compiling if arti renames a state), so this is the tripwire, not this match.
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
/// [`OnionServiceHandle::problem`](crate::OnionServiceHandle::problem).
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
pub fn project_service_problem(problem: &tor_hsservice::status::Problem) -> ServiceProblem {
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
/// [`ServiceProblem`] explaining why. Read via [`OnionServiceHandle::health`](crate::OnionServiceHandle::health). The value is derived from a **single** read
/// of arti's status, so the `status` and `problem` are always mutually consistent —
/// unlike calling [`status`](crate::OnionServiceHandle::status) and
/// [`problem`](crate::OnionServiceHandle::problem) separately, which reads arti twice and can
/// straddle a state transition (e.g. read `Reachable` then a just-arrived problem).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceHealth {
	status: ServiceStatus,
	problem: Option<ServiceProblem>,
}

impl ServiceHealth {
	/// Bundle a status and its (optional) problem into a snapshot. Crate-internal — the
	/// handle builds this from a single arti read (see [`OnionServiceHandle::health`](crate::OnionServiceHandle::health)) so
	/// the two halves are mutually consistent; downstreams read it, never construct it.
	pub(crate) const fn new(status: ServiceStatus, problem: Option<ServiceProblem>) -> Self {
		Self { status, problem }
	}

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
/// Extracted from [`OnionServiceHandle::ready`](crate::OnionServiceHandle::ready) and its timeout/settle siblings so the
/// wait logic is unit-testable offline over a constructed stream, with no live Tor
/// service (the projection that feeds it is already covered by
/// `service_status_projects_every_arti_state`). Takes the stream by value and pins it
/// internally, so callers hand `status_events()` straight in without an `Unpin` bound.
pub async fn await_status(events: impl Stream<Item = ServiceStatus>, mut pred: impl FnMut(ServiceStatus) -> bool) -> Option<ServiceStatus> {
	futures::pin_mut!(events);
	while let Some(status) = events.next().await {
		if pred(status) {
			return Some(status);
		}
	}
	None
}

#[cfg(test)]
mod tests {
	use super::*;

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
		let all = [Runtime("boom".into()), DescriptorUpload("upload failed".into()), IntroductionPoint("no ipts".into()), Other("mystery".into())];
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
}

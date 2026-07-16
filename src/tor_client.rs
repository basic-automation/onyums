//! Tor client bootstrap and the ephemeral state-directory lifecycle
//! (onyums ROADMAP Phase 1 identity + Phase 0 cleanup-off-the-runtime).
//!
//! [`storage_dirs`] resolves the `(state, cache)` directory pair for the persistent or
//! ephemeral identity mode; [`tor_client_config`]/[`setup_tor_client`] assemble and
//! bootstrap an arti [`TorClient`] against them; [`remove_ephemeral_state_dir`] and
//! [`spawn_ephemeral_cleanup`] tear a throwaway identity's temp keystore down (off the
//! async runtime when one is live). Extracted from `lib.rs` as a slice of the Phase 0
//! module split.

use std::sync::Arc;

use anyhow::Result;
use arti_client::{config::TorClientConfigBuilder, TorClient, TorClientConfig};
use tokio::task::JoinHandle;
use tor_rtcompat::tokio::TokioNativeTlsRuntime;
use tracing::{event, Level};

use crate::keystore_perms::{harden_state_tree, Hardening};

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
pub fn storage_dirs(ephemeral: bool) -> (String, String) {
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
///
/// # Errors
/// Returns an error if the current tokio runtime is unavailable or arti fails to
/// bootstrap a client (e.g. the network is unreachable).
pub async fn setup_tor_client(state_dir: &str, cache_dir: &str) -> Result<Arc<TorClient<TokioNativeTlsRuntime>>> {
	event!(Level::INFO, "Creating Tor client...");
	harden_keystore(std::path::Path::new(state_dir))?;
	let config = tor_client_config(state_dir, cache_dir)?;
	let runtime = TokioNativeTlsRuntime::current().map_err(|e| anyhow::anyhow!("Failed to get current tokio runtime: {e}"))?;
	let client = TorClient::with_runtime(runtime);
	client.config(config).create_bootstrapped().await.map_err(|e| anyhow::anyhow!("Failed to create bootstrapped Tor client: {e}"))
}

/// Create the state directory hardened, and repair a lax one, before arti opens it
/// (onyums ROADMAP Phase 2 — enforce filesystem permissions for the keystore).
///
/// The state tree holds the v3 identity key: whoever can read it can impersonate the
/// `.onion` address. This runs on every bootstrap — persistent *and* ephemeral, since a
/// throwaway identity is still an identity while it lives — and fails closed if the
/// tree cannot be made owner-only. Off Unix the control does not exist; it is logged
/// once at launch so an operator is never told a false "hardened" (see
/// [`keystore_perms`](crate::keystore_perms)).
///
/// # Errors
/// Returns an error if the state directory cannot be created, walked, or hardened.
fn harden_keystore(state_dir: &std::path::Path) -> Result<()> {
	match harden_state_tree(state_dir).map_err(|e| anyhow::anyhow!("Failed to harden the onion-service keystore at {}: {e}", state_dir.display()))? {
		Hardening::Enforced { tightened, inspected } if tightened > 0 => {
			event!(Level::WARN, "Hardened {tightened} of {inspected} path(s) in the keystore {state_dir:?} to owner-only (0700/0600): the onion-service identity key was readable by other local users.");
		}
		Hardening::Enforced { inspected, .. } => {
			event!(Level::DEBUG, "Keystore {state_dir:?} permissions verified owner-only across {inspected} path(s).");
		}
		Hardening::Unsupported => {
			event!(Level::DEBUG, "Keystore permission hardening is a no-op on this platform (no Unix mode model); {state_dir:?} is protected only by the platform's ACLs.");
		}
	}
	Ok(())
}

/// The unique prefix every ephemeral state directory carries (see [`storage_dirs`]).
/// Cleanup ([`remove_ephemeral_state_dir`]) refuses to delete any directory whose
/// name does not start with this, so a bug that mis-threads a path can never remove
/// a persistent or unrelated directory.
const EPHEMERAL_DIR_PREFIX: &str = "onyums-ephemeral-";

/// The lockfile every live ephemeral state dir holds open (see [`claim_ephemeral_dir`]).
const EPHEMERAL_LOCK_FILE: &str = ".onyums-owner.lock";

/// An ephemeral state dir's ownership claim: an open, **locked** file inside it, held
/// for as long as the service lives (onyums ROADMAP Phase 2 — guaranteed ephemeral
/// cleanup).
///
/// The lock is the liveness signal that makes [`sweep_stale_ephemeral_dirs`] safe. An
/// advisory file lock is released by the operating system when the holding process
/// exits — *however* it exits, including `SIGKILL`, the OOM killer, or a power loss, all
/// of which no signal handler can catch. So "can this lock be acquired?" is a reliable
/// proxy for "is the owner gone?" without needing a PID liveness check (which `std`
/// cannot do without FFI, and which this workspace's no-FFI rule forbids).
///
/// Dropping this releases the lock and closes the file. Order matters at cleanup time:
/// the file must be closed *before* the directory is removed, because Windows refuses to
/// remove a directory that still contains an open handle.
#[derive(Debug)]
pub struct EphemeralClaim {
	/// Held purely for its `Drop`: closing the file releases the OS-level lock. Never
	/// read, hence the underscore — the value of this field *is* its lifetime.
	_file: std::fs::File,
}

/// A live ephemeral identity: its throwaway state dir, and the claim proving this
/// process still owns it.
///
/// Held by `OnionServiceHandle` for the service's lifetime. Bundling the two is what
/// makes the teardown ordering unmissable — see [`release`](Self::release).
#[derive(Debug)]
pub struct EphemeralIdentity {
	dir: std::path::PathBuf,
	claim: EphemeralClaim,
}

impl EphemeralIdentity {
	/// Pair a claimed dir with its claim.
	#[must_use]
	pub const fn new(dir: std::path::PathBuf, claim: EphemeralClaim) -> Self {
		Self { dir, claim }
	}

	/// Give up the claim and hand back the directory to remove.
	///
	/// Dropping the claim *before* returning the path is the point, not incidental: the
	/// lockfile lives inside the directory, and Windows refuses to remove a directory
	/// that still holds an open file handle — so a removal that ran while the claim was
	/// alive would silently fail there and leave the identity key on disk. Consuming
	/// `self` means a caller cannot hold the claim and remove the directory at once.
	#[must_use]
	pub fn release(self) -> std::path::PathBuf {
		drop(self.claim);
		self.dir
	}
}

/// Create, harden, and **claim** an ephemeral state dir — before the Tor bootstrap
/// (onyums ROADMAP Phase 2).
///
/// The ordering is the whole point, and getting it wrong is a live-service data race:
/// [`setup_tor_client`] creates the directory and *then* bootstraps, which takes a
/// minute or more. If the claim were taken after that call, the directory would sit
/// unclaimed for the entire bootstrap — and a second ephemeral service launching in that
/// window would run [`sweep_stale_ephemeral_dirs`], see a lockfile-less directory, judge
/// it abandoned, and delete a live service's keystore out from under it while it booted.
///
/// Claiming first closes the window: the directory is never observable by a sweep in an
/// unclaimed state. `setup_tor_client` hardens the tree again afterwards, which is
/// idempotent and also tightens the lockfile itself to `0600`.
///
/// # Errors
/// Returns an error if the directory cannot be created, hardened, or claimed.
pub fn prepare_ephemeral_dir(state_dir: &str) -> Result<EphemeralIdentity> {
	let dir = std::path::PathBuf::from(state_dir);
	harden_state_tree(&dir).map_err(|e| anyhow::anyhow!("failed to create the ephemeral state dir {}: {e}", dir.display()))?;
	let claim = claim_ephemeral_dir(&dir)?;
	Ok(EphemeralIdentity::new(dir, claim))
}

/// Take ownership of a freshly minted ephemeral state dir by locking a file inside it.
///
/// Called once per ephemeral launch, before arti opens the keystore. The returned
/// [`EphemeralClaim`] must be held for the service's lifetime — dropping it releases the
/// claim, which tells a later [`sweep_stale_ephemeral_dirs`] that this directory is
/// abandoned and may be removed.
///
/// # Errors
/// Returns an error if the lockfile cannot be created or locked. A lock that is already
/// held is a genuine error here rather than a race to tolerate: [`storage_dirs`] mints a
/// unique path per launch (pid + a CSPRNG draw), so a *fresh* ephemeral dir whose lock is
/// already taken means something is wrong with that assumption.
pub fn claim_ephemeral_dir(dir: &std::path::Path) -> Result<EphemeralClaim> {
	let path = dir.join(EPHEMERAL_LOCK_FILE);
	let file = std::fs::File::create(&path).map_err(|e| anyhow::anyhow!("failed to create the ephemeral owner lockfile {}: {e}", path.display()))?;
	file.try_lock().map_err(|e| anyhow::anyhow!("failed to lock the ephemeral owner lockfile {}: {e}", path.display()))?;
	Ok(EphemeralClaim { _file: file })
}

/// Remove every abandoned ephemeral state dir left in the system temp tree by a previous
/// run (onyums ROADMAP Phase 2), returning how many were removed.
///
/// The problem this solves: an ephemeral service's throwaway *identity key* is removed on
/// `shutdown`/`Drop`, but neither runs if the process is `SIGKILL`ed, OOM-killed, or the
/// machine loses power — so the key lingers on disk indefinitely. Signal trapping cannot
/// fix that case: `SIGKILL` is by definition uncatchable, and it is the case that matters.
///
/// Instead this runs at *launch* and cleans up after whatever died last time. A directory
/// is removed only if its [`EPHEMERAL_LOCK_FILE`] can be locked — i.e. no live process
/// holds it — so a long-running sibling's keystore is never touched, however long it has
/// been running. That makes this safe in a way an age-based heuristic would not be: "older
/// than an hour" would happily delete the identity of a service that has been up for a
/// week.
///
/// Best-effort by design, and never fatal: a directory that cannot be read or removed is
/// skipped, since failing to tidy up a previous run is not a reason to refuse to start
/// this one.
pub fn sweep_stale_ephemeral_dirs(temp_dir: &std::path::Path) -> usize {
	let Ok(entries) = std::fs::read_dir(temp_dir) else { return 0 };
	let mut removed = 0;
	for entry in entries.flatten() {
		let path = entry.path();
		let is_ephemeral = path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(EPHEMERAL_DIR_PREFIX));
		if !is_ephemeral || !path.is_dir() {
			continue;
		}
		if claim_is_free(&path) {
			// The claim was free, so no live process owns this dir. `claim_is_free` has
			// already dropped its lock/handle, so the removal can take the whole tree
			// (including the lockfile) on Windows too.
			let before = path.exists();
			remove_ephemeral_state_dir(&path);
			if before && !path.exists() {
				removed += 1;
				event!(Level::INFO, "Removed the abandoned ephemeral keystore {path:?} left by a previous run.");
			}
		}
	}
	removed
}

/// Can this ephemeral dir's owner lock be taken — i.e. is its owning process gone?
///
/// A dir with no lockfile at all counts as free: it predates this mechanism, or the
/// process died between creating the directory and claiming it. Either way nothing is
/// holding it.
fn claim_is_free(dir: &std::path::Path) -> bool {
	let path = dir.join(EPHEMERAL_LOCK_FILE);
	if !path.exists() {
		return true;
	}
	let Ok(file) = std::fs::File::open(&path) else { return false };
	// `try_lock` succeeding proves no other process holds it. The lock and the handle are
	// both released as `file` drops at the end of this scope — before any removal.
	file.try_lock().is_ok()
}

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
pub fn remove_ephemeral_state_dir(dir: &std::path::Path) {
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
pub fn spawn_ephemeral_cleanup(dir: std::path::PathBuf) -> Option<JoinHandle<()>> {
	if let Ok(handle) = tokio::runtime::Handle::try_current() {
		Some(handle.spawn_blocking(move || remove_ephemeral_state_dir(&dir)))
	} else {
		remove_ephemeral_state_dir(&dir);
		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;

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

	// ---- Ephemeral ownership claims + the stale-dir sweep (Phase 2). ----

	/// A private temp tree, so a sweep test never sees another test's (or another
	/// process's) ephemeral dirs.
	fn sweep_scratch(tag: &str) -> std::path::PathBuf {
		let dir = std::env::temp_dir().join(format!("onyums-sweep-{}-{tag}-{:016x}", std::process::id(), rand::random::<u64>()));
		std::fs::create_dir_all(&dir).expect("create sweep scratch");
		dir
	}

	/// A directory shaped exactly like one `storage_dirs` mints, holding a fake key.
	fn fake_ephemeral_dir(parent: &std::path::Path) -> std::path::PathBuf {
		let dir = parent.join(format!("{EPHEMERAL_DIR_PREFIX}{}-{:016x}", std::process::id(), rand::random::<u64>()));
		std::fs::create_dir_all(&dir).expect("create fake ephemeral dir");
		std::fs::write(dir.join("hs_ed25519_secret_key"), b"fake identity").expect("write fake key");
		dir
	}

	#[test]
	fn a_claimed_dir_survives_the_sweep() {
		// The case that must never regress: a *live* service's keystore. The claim is held
		// (as it would be for the service's lifetime), so the sweep must leave it alone —
		// no matter how old it is. An age-based heuristic would fail exactly here.
		let scratch = sweep_scratch("live");
		let dir = fake_ephemeral_dir(&scratch);
		let claim = claim_ephemeral_dir(&dir).expect("claim a fresh ephemeral dir");

		assert_eq!(sweep_stale_ephemeral_dirs(&scratch), 0, "a live, claimed dir must not be swept");
		assert!(dir.exists(), "the live service's keystore must survive");
		assert!(dir.join("hs_ed25519_secret_key").exists());
		drop(claim);
		std::fs::remove_dir_all(&scratch).ok();
	}

	#[test]
	fn an_abandoned_dir_is_swept() {
		// The case this exists for: the previous run was SIGKILLed, so its `Drop` never
		// ran and the throwaway identity key is still on disk. Dropping the claim is what
		// the OS does for us when a process dies, however it dies.
		let scratch = sweep_scratch("abandoned");
		let dir = fake_ephemeral_dir(&scratch);
		let claim = claim_ephemeral_dir(&dir).expect("claim");
		drop(claim); // <- the process died; the OS released its lock.

		assert_eq!(sweep_stale_ephemeral_dirs(&scratch), 1, "an unclaimed dir must be swept");
		assert!(!dir.exists(), "the abandoned identity key must be gone");
		std::fs::remove_dir_all(&scratch).ok();
	}

	#[test]
	fn the_sweep_leaves_unrelated_directories_alone() {
		// The sweep runs over the shared system temp tree, so it must key strictly on the
		// ephemeral prefix. Deleting someone else's temp dir would be a serious bug.
		let scratch = sweep_scratch("unrelated");
		let stranger = scratch.join("some-other-tool-cache");
		std::fs::create_dir_all(&stranger).expect("create");
		std::fs::write(stranger.join("data"), b"not ours").expect("write");
		let loose_file = scratch.join(format!("{EPHEMERAL_DIR_PREFIX}not-a-directory"));
		std::fs::write(&loose_file, b"a file, not a dir").expect("write");

		assert_eq!(sweep_stale_ephemeral_dirs(&scratch), 0, "nothing here is a sweepable ephemeral dir");
		assert!(stranger.exists(), "an unrelated directory must be untouched");
		assert!(loose_file.exists(), "a file merely sharing the prefix is not a dir to remove");
		std::fs::remove_dir_all(&scratch).ok();
	}

	#[test]
	fn a_dir_with_no_lockfile_counts_as_abandoned() {
		// Left by a pre-hardening onyums, or by a process that died between creating the
		// directory and claiming it. Nothing holds it, so it is exactly the litter this
		// sweep exists to remove.
		let scratch = sweep_scratch("nolock");
		let dir = fake_ephemeral_dir(&scratch);
		assert!(!dir.join(EPHEMERAL_LOCK_FILE).exists());

		assert_eq!(sweep_stale_ephemeral_dirs(&scratch), 1);
		assert!(!dir.exists());
		std::fs::remove_dir_all(&scratch).ok();
	}

	#[test]
	fn the_sweep_distinguishes_live_from_abandoned_in_one_pass() {
		// The realistic mixed state: this host has one service running and the corpses of
		// two that were killed. One pass must remove exactly the corpses.
		let scratch = sweep_scratch("mixed");
		let live = fake_ephemeral_dir(&scratch);
		let claim = claim_ephemeral_dir(&live).expect("claim the live one");
		let dead_a = fake_ephemeral_dir(&scratch);
		drop(claim_ephemeral_dir(&dead_a).expect("claim then die"));
		let dead_b = fake_ephemeral_dir(&scratch); // never claimed at all

		assert_eq!(sweep_stale_ephemeral_dirs(&scratch), 2, "exactly the two abandoned dirs");
		assert!(live.exists(), "the live service's keystore must survive");
		assert!(!dead_a.exists() && !dead_b.exists(), "both abandoned keystores must be gone");
		drop(claim);
		std::fs::remove_dir_all(&scratch).ok();
	}

	#[test]
	fn the_sweep_is_idempotent_and_quiet_on_an_empty_tree() {
		// It runs on every ephemeral launch, so the common case — nothing to clean — must
		// be a silent no-op, and a second pass must find nothing left.
		let scratch = sweep_scratch("idempotent");
		let dir = fake_ephemeral_dir(&scratch);
		drop(claim_ephemeral_dir(&dir).expect("claim"));

		assert_eq!(sweep_stale_ephemeral_dirs(&scratch), 1);
		assert_eq!(sweep_stale_ephemeral_dirs(&scratch), 0, "a second pass has nothing to do");
		assert_eq!(sweep_stale_ephemeral_dirs(&scratch.join("does-not-exist")), 0, "a missing temp tree is not an error");
		std::fs::remove_dir_all(&scratch).ok();
	}

	#[test]
	fn a_prepared_dir_is_claimed_before_bootstrap_so_a_concurrent_launch_cannot_sweep_it() {
		// Regression test for a real race (found by watching a live `--ignored` run: the
		// service's ephemeral dir sat lockfile-less for the whole ~30min bootstrap).
		//
		// The launch order is: sweep -> create dir -> **bootstrap, which takes minutes** ->
		// claim. With the claim last, the dir is unclaimed for the entire bootstrap, and a
		// second ephemeral service launching in that window sweeps it as abandoned —
		// deleting a live service's keystore while it boots. `prepare_ephemeral_dir`
		// creates+hardens+claims as one step, before bootstrap, so the window never exists.
		let scratch = sweep_scratch("prepare");
		let state_dir = scratch.join(format!("{EPHEMERAL_DIR_PREFIX}{}-{:016x}", std::process::id(), rand::random::<u64>()));

		let identity = prepare_ephemeral_dir(&state_dir.to_string_lossy()).expect("prepare");
		assert!(state_dir.exists(), "the dir must be created");
		assert!(state_dir.join(EPHEMERAL_LOCK_FILE).exists(), "and claimed in the same step");

		// This is what the *other* service's launch would run while ours is still
		// bootstrapping. It must leave ours alone.
		assert_eq!(sweep_stale_ephemeral_dirs(&scratch), 0, "a bootstrapping service's dir must survive a concurrent launch's sweep");
		assert!(state_dir.join("hs_ed25519_secret_key").exists() || state_dir.exists(), "the keystore must still be there");

		// And once the service is gone, the same sweep reclaims it.
		drop(identity);
		assert_eq!(sweep_stale_ephemeral_dirs(&scratch), 1, "once released, it is swept normally");
		assert!(!state_dir.exists());
		std::fs::remove_dir_all(&scratch).ok();
	}

	#[test]
	fn a_claim_is_exclusive() {
		// The claim's whole meaning: while one process holds it, another cannot take it —
		// which is what makes "the lock is free" a sound proxy for "the owner is gone".
		let scratch = sweep_scratch("exclusive");
		let dir = fake_ephemeral_dir(&scratch);
		let held = claim_ephemeral_dir(&dir).expect("first claim");
		assert!(!claim_is_free(&dir), "a held claim must not read as free");
		drop(held);
		assert!(claim_is_free(&dir), "a released claim must read as free");
		std::fs::remove_dir_all(&scratch).ok();
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
}

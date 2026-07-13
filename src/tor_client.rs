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

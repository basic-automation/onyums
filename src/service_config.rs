//! Offline assembly of the arti [`OnionServiceConfig`], including v3 restricted
//! discovery (onyums ROADMAP Phase 2 — abuse resistance).
//!
//! [`build_onion_service_config`] parses the service nickname, folds in a caller's
//! authorized-clients allowlist via [`apply_restricted_discovery`], and runs arti's own
//! config validation — all before any Tor bootstrap, so a bad nickname or allowlist
//! fails fast and offline. Extracted from `lib.rs` as a slice of the Phase 0 module split.

use anyhow::{bail, Result};
use onyums_skin::RestrictedDiscovery;
use tor_hscrypto::pk::HsClientDescEncKey;
use tor_hsservice::{
	config::{restricted_discovery::HsClientNickname, OnionServiceConfig, OnionServiceConfigBuilder}, HsNickname
};

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
pub fn build_onion_service_config(nickname: &str, allowlist: Option<&RestrictedDiscovery>) -> Result<OnionServiceConfig> {
	let nickname = nickname.parse::<HsNickname>().map_err(|e| anyhow::anyhow!("Failed to parse nickname: {e}"))?;
	let mut cfg = OnionServiceConfigBuilder::default();
	cfg.nickname(nickname);
	if let Some(allowlist) = allowlist {
		apply_restricted_discovery(&mut cfg, allowlist)?;
	}
	cfg.build().map_err(|e| anyhow::anyhow!("Failed to build onion service config: {e}"))
}

#[cfg(test)]
mod tests {
	use super::*;
	use onyums_skin::ClientAuthKey;

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
}

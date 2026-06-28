//! Pure, offline-testable TLS-transport policy for the built-in HTTP handler
//! (onyums ROADMAP Phase 3 — TLS-first transport).
//!
//! onyums treats encrypted, certificate-authenticated transport as the default
//! and can *enforce* it. The rendezvous loop has long hardcoded the port
//! handling — 443 → TLS+axum, 80 → HTTP→HTTPS redirect, everything else →
//! reject — leaving no way to make TLS non-negotiable. This module turns that
//! hardcoded behaviour into a [`Tls`] mode plus pure helper functions, so the
//! transport decision is data the live loop merely executes — and one this
//! routine can unit-test with no live Tor network.

/// How the built-in HTTP handler provisions and enforces TLS.
///
/// TLS is the standard here, never an opt-*off*: every variant serves HTTPS on
/// port 443 with an auto-generated self-signed certificate. The variants differ
/// only in how strictly plaintext is treated. This is the Phase 3 "opt *down*,
/// never *up*" knob — the secure default is the most forgiving toward clients,
/// and [`Tls::Strict`] is the explicit tightening.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tls {
	/// Default — auto self-signed cert, and plaintext HTTP on port 80 is
	/// transparently **upgraded** to HTTPS with a `301` redirect. The most
	/// forgiving posture: a client that reaches the service over plain HTTP is
	/// pointed at the HTTPS URL rather than refused.
	#[default]
	Upgrade,
	/// Strict — TLS is non-negotiable. Plaintext circuits are **rejected**
	/// outright (there is no port-80 redirect handler at all), and HTTPS
	/// responses carry an HSTS header so a conforming client never silently
	/// downgrades. For operators who want TLS to be mandatory.
	Strict,
}

/// The HSTS response-header name.
pub const HSTS_HEADER_NAME: &str = "strict-transport-security";

/// The HSTS response-header value onyums emits in [`Tls::Strict`] mode: two
/// years, covering subdomains. No `preload` directive — preload requires the
/// public HSTS-preload registration that does not apply to a `.onion` host.
pub const HSTS_HEADER_VALUE: &str = "max-age=63072000; includeSubDomains";

/// The HSTS `(name, value)` header pair to add to HTTPS responses, or `None`
/// when the mode does not enforce HSTS.
#[must_use]
pub const fn hsts_header(tls: Tls) -> Option<(&'static str, &'static str)> {
	match tls {
		Tls::Strict => Some((HSTS_HEADER_NAME, HSTS_HEADER_VALUE)),
		Tls::Upgrade => None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn default_mode_is_upgrade() {
		assert_eq!(Tls::default(), Tls::Upgrade);
	}

	#[test]
	fn hsts_only_in_strict_mode() {
		assert_eq!(hsts_header(Tls::Upgrade), None);
		assert_eq!(hsts_header(Tls::Strict), Some((HSTS_HEADER_NAME, HSTS_HEADER_VALUE)));
	}

	#[test]
	fn hsts_value_is_a_wellformed_directive() {
		let (name, value) = hsts_header(Tls::Strict).expect("strict mode emits HSTS");
		assert_eq!(name, "strict-transport-security");
		assert!(value.starts_with("max-age="), "HSTS must lead with max-age: {value}");
		assert!(value.contains("includeSubDomains"), "HSTS should cover subdomains: {value}");
		// `.onion` cannot be preloaded; the directive must not claim it.
		assert!(!value.contains("preload"), "preload does not apply to .onion: {value}");
	}
}

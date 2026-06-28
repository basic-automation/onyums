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

/// What the rendezvous loop should do with a BEGIN cell for a given port under a
/// given [`Tls`] mode. The pure, offline-testable counterpart to the live port
/// dispatch in `handle_stream_request`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortAction {
	/// Accept the stream and serve it over TLS + HTTP (the axum app). Port 443.
	ServeTls,
	/// Accept the stream and answer with a `301` redirect to the HTTPS URL.
	/// Port 80 under [`Tls::Upgrade`] only.
	RedirectToHttps,
	/// Reject the stream and tear down the circuit. Any non-HTTP port, plus
	/// port 80 under [`Tls::Strict`] (plaintext is non-negotiable there).
	Reject,
}

/// Decide what to do with a stream for `port` under the chosen `tls` mode.
///
/// Port 443 is always served over TLS. Port 80 is upgraded to HTTPS under
/// [`Tls::Upgrade`] but **rejected** under [`Tls::Strict`] (no plaintext handler
/// at all). Every other port is rejected — the built-in handler is HTTP-only;
/// arbitrary-port `StreamHandler`s are a later Phase 3 slice.
#[must_use]
pub const fn port_action(port: u16, tls: Tls) -> PortAction {
	match (port, tls) {
		(443, _) => PortAction::ServeTls,
		(80, Tls::Upgrade) => PortAction::RedirectToHttps,
		_ => PortAction::Reject,
	}
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
	fn port_443_is_always_served_over_tls() {
		assert_eq!(port_action(443, Tls::Upgrade), PortAction::ServeTls);
		assert_eq!(port_action(443, Tls::Strict), PortAction::ServeTls);
	}

	#[test]
	fn port_80_upgrades_by_default_but_is_rejected_when_strict() {
		assert_eq!(port_action(80, Tls::Upgrade), PortAction::RedirectToHttps);
		assert_eq!(port_action(80, Tls::Strict), PortAction::Reject);
	}

	#[test]
	fn non_http_ports_are_always_rejected() {
		for port in [0_u16, 22, 25, 8080, 9735, 65535] {
			assert_eq!(port_action(port, Tls::Upgrade), PortAction::Reject, "port {port} should be rejected (upgrade)");
			assert_eq!(port_action(port, Tls::Strict), PortAction::Reject, "port {port} should be rejected (strict)");
		}
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

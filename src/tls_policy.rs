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
/// port 443. The default variants differ only in how strictly plaintext is
/// treated — this is the Phase 3 "opt *down*, never *up*" knob, where the secure
/// default is the most forgiving toward clients and [`Tls::Strict`] is the
/// explicit tightening. [`Tls::Provided`] is an orthogonal axis: it swaps the
/// auto-generated self-signed certificate for a caller-supplied (e.g. CA-signed)
/// one without otherwise changing the posture.
///
/// This enum carries a (non-`Copy`) certificate in the [`Tls::Provided`] case;
/// the rendezvous loop never sees it — it threads only the small [`Copy`]
/// [`PlaintextPolicy`] returned by [`Tls::plaintext_policy`].
#[derive(Clone, Debug, Default)]
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
	/// Bring-your-own certificate — serve the caller-supplied certificate chain
	/// and key instead of an auto-generated self-signed one, for CA-signed
	/// `.onion` certificates (e.g. HARICA) that some clients prefer. Plaintext is
	/// treated like [`Tls::Upgrade`] (port 80 redirects to HTTPS, no HSTS);
	/// combining a provided cert with strict plaintext rejection is a future
	/// extension, kept out of the initial variant to keep the BYO axis orthogonal.
	Provided(crate::ProvidedCert),
}

impl Tls {
	/// The pure, `Copy` plaintext-enforcement decision this mode implies.
	///
	/// This is the *only* part of [`Tls`] the rendezvous loop needs: how to
	/// treat a plaintext (port-80) circuit and whether to emit HSTS. Factoring
	/// it out lets the loop thread a small [`Copy`] value while [`Tls`] itself is
	/// free to carry non-`Copy` configuration (the [`Tls::Provided`] certificate)
	/// that only the one-time acceptor build consumes.
	#[must_use]
	pub const fn plaintext_policy(&self) -> PlaintextPolicy {
		match self {
			Self::Upgrade | Self::Provided(_) => PlaintextPolicy::Upgrade,
			Self::Strict => PlaintextPolicy::Reject,
		}
	}
}

/// How the rendezvous loop treats a plaintext (port-80) circuit — the pure,
/// `Copy` enforcement decision threaded through the serve path.
///
/// Separated from [`Tls`] so the loop carries a trivially-copyable value while
/// the builder-facing [`Tls`] mode is free to hold non-`Copy` data (a provided
/// certificate). HSTS emission rides along with [`PlaintextPolicy::Reject`]: a
/// service that refuses plaintext also tells conforming clients never to try it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PlaintextPolicy {
	/// Plaintext HTTP on port 80 is answered with a `301` redirect to HTTPS, and
	/// no HSTS header is emitted. The forgiving default.
	#[default]
	Upgrade,
	/// Plaintext circuits are rejected outright (no port-80 handler), and HTTPS
	/// responses carry HSTS.
	Reject,
}

/// What the rendezvous loop should do with a BEGIN cell for a given port under a
/// given [`PlaintextPolicy`]. The pure, offline-testable counterpart to the live
/// port dispatch in `handle_stream_request`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortAction {
	/// Accept the stream and serve it over TLS + HTTP (the axum app). Port 443.
	ServeTls,
	/// Accept the stream and answer with a `301` redirect to the HTTPS URL.
	/// Port 80 under [`PlaintextPolicy::Upgrade`] only.
	RedirectToHttps,
	/// Reject the stream and tear down the circuit. Any non-HTTP port, plus
	/// port 80 under [`PlaintextPolicy::Reject`] (plaintext is non-negotiable
	/// there).
	Reject,
}

/// Decide what to do with a stream for `port` under the chosen plaintext policy.
///
/// Port 443 is always served over TLS. Port 80 is upgraded to HTTPS under
/// [`PlaintextPolicy::Upgrade`] but **rejected** under [`PlaintextPolicy::Reject`]
/// (no plaintext handler at all). Every other port is rejected — the built-in
/// handler is HTTP-only; arbitrary-port `StreamHandler`s are a later Phase 3
/// slice.
#[must_use]
pub const fn port_action(port: u16, plaintext: PlaintextPolicy) -> PortAction {
	match (port, plaintext) {
		(443, _) => PortAction::ServeTls,
		(80, PlaintextPolicy::Upgrade) => PortAction::RedirectToHttps,
		_ => PortAction::Reject,
	}
}

/// The HSTS response-header name.
pub const HSTS_HEADER_NAME: &str = "strict-transport-security";

/// The HSTS response-header value onyums emits when plaintext is rejected: two
/// years, covering subdomains. No `preload` directive — preload requires the
/// public HSTS-preload registration that does not apply to a `.onion` host.
pub const HSTS_HEADER_VALUE: &str = "max-age=63072000; includeSubDomains";

/// The HSTS `(name, value)` header pair to add to HTTPS responses, or `None`
/// when the policy does not enforce HSTS.
#[must_use]
pub const fn hsts_header(plaintext: PlaintextPolicy) -> Option<(&'static str, &'static str)> {
	match plaintext {
		PlaintextPolicy::Reject => Some((HSTS_HEADER_NAME, HSTS_HEADER_VALUE)),
		PlaintextPolicy::Upgrade => None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn default_mode_is_upgrade() {
		assert!(matches!(Tls::default(), Tls::Upgrade));
	}

	#[test]
	fn plaintext_policy_maps_mode_to_enforcement() {
		assert_eq!(Tls::Upgrade.plaintext_policy(), PlaintextPolicy::Upgrade);
		assert_eq!(Tls::Strict.plaintext_policy(), PlaintextPolicy::Reject);
		assert_eq!(PlaintextPolicy::default(), PlaintextPolicy::Upgrade);

		// A bring-your-own certificate is orthogonal to plaintext strictness: it
		// keeps the forgiving upgrade posture.
		let ck = rcgen::generate_simple_self_signed(vec!["example.onion".to_string()]).expect("rcgen");
		let provided = crate::ProvidedCert::from_pem(ck.cert.pem().as_bytes(), ck.signing_key.serialize_pem().as_bytes()).expect("valid PEM");
		assert_eq!(Tls::Provided(provided).plaintext_policy(), PlaintextPolicy::Upgrade);
	}

	#[test]
	fn port_443_is_always_served_over_tls() {
		assert_eq!(port_action(443, PlaintextPolicy::Upgrade), PortAction::ServeTls);
		assert_eq!(port_action(443, PlaintextPolicy::Reject), PortAction::ServeTls);
	}

	#[test]
	fn port_80_upgrades_by_default_but_is_rejected_when_strict() {
		assert_eq!(port_action(80, PlaintextPolicy::Upgrade), PortAction::RedirectToHttps);
		assert_eq!(port_action(80, PlaintextPolicy::Reject), PortAction::Reject);
	}

	#[test]
	fn non_http_ports_are_always_rejected() {
		for port in [0_u16, 22, 25, 8080, 9735, 65535] {
			assert_eq!(port_action(port, PlaintextPolicy::Upgrade), PortAction::Reject, "port {port} should be rejected (upgrade)");
			assert_eq!(port_action(port, PlaintextPolicy::Reject), PortAction::Reject, "port {port} should be rejected (reject)");
		}
	}

	#[test]
	fn hsts_only_when_plaintext_rejected() {
		assert_eq!(hsts_header(PlaintextPolicy::Upgrade), None);
		assert_eq!(hsts_header(PlaintextPolicy::Reject), Some((HSTS_HEADER_NAME, HSTS_HEADER_VALUE)));
	}

	#[test]
	fn hsts_value_is_a_wellformed_directive() {
		let (name, value) = hsts_header(PlaintextPolicy::Reject).expect("reject policy emits HSTS");
		assert_eq!(name, "strict-transport-security");
		assert!(value.starts_with("max-age="), "HSTS must lead with max-age: {value}");
		assert!(value.contains("includeSubDomains"), "HSTS should cover subdomains: {value}");
		// `.onion` cannot be preloaded; the directive must not claim it.
		assert!(!value.contains("preload"), "preload does not apply to .onion: {value}");
	}
}

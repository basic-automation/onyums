//! The application-facing HTTP stack: the Skin abuse-defense gate and the HSTS
//! response header, composed exactly as `OnionServiceBuilder::serve` layers them
//! (onyums ROADMAP Phase 2 Skin + Phase 3 TLS).
//!
//! [`build_serve_router`] is the full request path a client hits *inside* the
//! onion-encrypted TLS stream, minus the TLS transport itself: [`apply_skin`] wraps the
//! caller's app in the chosen [`SkinChoice`] gate, then [`apply_hsts`] adds the HSTS
//! header under a plaintext-reject policy. Each is a plain `Router` transform, so the
//! composed stack is `tower::ServiceExt::oneshot`-testable with no live Tor network
//! (the first slice of the in-process/loopback test mode). Extracted from `lib.rs` as a
//! slice of the Phase 0 module split.

use axum::Router;
use onyums_skin::Skin;

use crate::tls_policy;

/// How the onyums-skin abuse-defense gate is applied to the served router.
///
/// Secure by default: with no explicit choice, the secure-default Skin gate is
/// on. You opt *down* (`no_skin`) or *across* (a custom [`Skin`]), never *up*.
#[derive(Default)]
pub enum SkinChoice {
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
pub fn apply_skin(app: Router, skin: SkinChoice) -> Router {
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
pub fn apply_hsts(app: Router, plaintext: tls_policy::PlaintextPolicy) -> Router {
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
pub fn build_serve_router(app: Router, skin: SkinChoice, plaintext: tls_policy::PlaintextPolicy) -> Router {
	apply_hsts(apply_skin(app, skin), plaintext)
}

#[cfg(test)]
mod tests {
	use axum::routing::get;
	use http_body_util::BodyExt as _;
	use hyper::{Request, StatusCode};
	use tower::ServiceExt as _;

	use super::*;
	use crate::tls_policy::Tls;

	#[tokio::test]
	async fn strict_tls_adds_hsts_header() {
		let app = apply_hsts(Router::new().route("/", get(|| async { "ok" })), Tls::Strict.plaintext_policy());
		let response = app.oneshot(Request::builder().uri("/").body(axum::body::Body::empty()).unwrap()).await.unwrap();
		let hsts = response.headers().get("strict-transport-security").expect("strict mode must emit HSTS");
		assert_eq!(hsts, "max-age=63072000; includeSubDomains");
	}

	#[tokio::test]
	async fn upgrade_tls_omits_hsts_header() {
		let app = apply_hsts(Router::new().route("/", get(|| async { "ok" })), Tls::Upgrade.plaintext_policy());
		let response = app.oneshot(Request::builder().uri("/").body(axum::body::Body::empty()).unwrap()).await.unwrap();
		assert!(response.headers().get("strict-transport-security").is_none(), "upgrade mode must not emit HSTS");
	}

	#[tokio::test]
	async fn no_skin_passes_requests_through() {
		let app = apply_skin(Router::new().route("/", get(|| async { "ok" })), SkinChoice::Disabled);
		let response = app.oneshot(Request::builder().uri("/").body(axum::body::Body::empty()).unwrap()).await.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
	}

	#[tokio::test]
	async fn default_skin_gates_uncleared_requests() {
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
	async fn serve_router_gates_and_adds_hsts_under_strict_tls() {
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
		// Opt-down: no gate + upgrade TLS — the app is reached and no HSTS is added.
		let app = build_serve_router(Router::new().route("/", get(|| async { "reached" })), SkinChoice::Disabled, Tls::Upgrade.plaintext_policy());
		let response = app.oneshot(Request::builder().uri("/").body(axum::body::Body::empty()).unwrap()).await.unwrap();
		assert!(response.headers().get("strict-transport-security").is_none(), "upgrade TLS emits no HSTS");
		let body = response.into_body().collect().await.unwrap().to_bytes();
		assert_eq!(String::from_utf8_lossy(&body), "reached", "no_skin lets the request reach the app");
	}
}

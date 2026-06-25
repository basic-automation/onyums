//! Unified per-request client profile (Phase 5 — frontier defenses).
//!
//! The Phase 5 request-shape signals — the [`Ja4hFingerprint`] cluster key, the
//! [`RequestShape`] feature vector, and the [`BotAssessment`] suspicion score — are all
//! derived from the same parsed request and are most useful together: the fingerprint
//! *clusters* a client, the bot assessment *scores* it, and the shape feeds the baseline. A
//! [`ClientProfile`] derives all three in one pass over a request's [`Parts`], so the host
//! extracts the Tor-surviving request signals once and gets a single "who is this client"
//! object — the closest an onion service can come to Cloudflare's per-client identity, with
//! no IP, ASN, geo, or TLS fingerprint to lean on.
//!
//! Every field here is identity-free and a *signal*, never a verdict: the profile informs
//! difficulty tuning and clustering, it does not by itself block a request.

use axum::http::request::Parts;

use crate::{bot::{BotAssessment, BotHeuristics}, fingerprint::Ja4hFingerprint, shape::RequestShape};

/// A one-pass bundle of the identity-free, Tor-surviving signals about one request's client.
///
/// Construct with [`from_parts`](Self::from_parts). The [`fingerprint`](Self::fingerprint) is a
/// stable cluster key (clients with the same request structure share it); the
/// [`bot`](Self::bot) assessment scores how scripted the request looks; the
/// [`shape`](Self::shape) is the feature vector a [`ShapeBaseline`](crate::shape::ShapeBaseline)
/// folds in to learn "normal." None is an IP, and none is a hard block on its own.
#[derive(Clone, Debug)]
pub struct ClientProfile {
	/// The JA4H-style cluster/identify key over the request structure.
	pub fingerprint: Ja4hFingerprint,
	/// The Tor-surviving request-shape feature vector (method, path structure, header set,
	/// cookie presence, UA).
	pub shape: RequestShape,
	/// The request-shape bot-suspicion assessment (score + fired signals).
	pub bot: BotAssessment,
}

impl ClientProfile {
	/// Derive the full profile from a parsed request's [`Parts`] in one pass, scoring the bot
	/// signal with `heuristics`. Use [`from_parts_default`](Self::from_parts_default) for the
	/// default scorer.
	#[must_use]
	pub fn from_parts(parts: &Parts, heuristics: &BotHeuristics) -> Self {
		Self {
			fingerprint: Ja4hFingerprint::from_parts(parts),
			shape: RequestShape::from_parts(parts),
			bot: heuristics.assess(parts),
		}
	}

	/// Derive the profile using a default [`BotHeuristics`].
	#[must_use]
	pub fn from_parts_default(parts: &Parts) -> Self {
		Self::from_parts(parts, &BotHeuristics::new())
	}

	/// The stable cluster key — the JA4H `a_b_c_d` string. Clients emitting the same request
	/// structure share it, so a host can group circuits/requests by their originating client
	/// shape without any network identity.
	#[must_use]
	pub fn cluster_key(&self) -> String {
		self.fingerprint.raw()
	}

	/// Whether the bot-suspicion score meets or exceeds `threshold` — a convenience over
	/// [`BotAssessment::is_suspicious`].
	#[must_use]
	pub fn is_suspicious(&self, threshold: f64) -> bool {
		self.bot.is_suspicious(threshold)
	}
}

#[cfg(test)]
mod tests {
	use axum::http::Request;

	use super::*;
	use crate::bot::BotSignal;

	fn parts(builder: axum::http::request::Builder) -> Parts {
		builder.body(()).unwrap().into_parts().0
	}

	#[test]
	fn profile_derives_all_three_signals_in_one_pass() {
		let p = ClientProfile::from_parts_default(&parts(
			Request::builder().method("GET").uri("/api/items").header("host", "x.onion").header("user-agent", "curl/8.0").header("accept", "*/*"),
		));
		// Fingerprint: curl sends no Accept-Language → 0000 language field.
		assert_eq!(&p.fingerprint.a[8..12], "0000");
		// Shape: two path segments.
		assert_eq!(p.shape.path_depth, 2);
		// Bot: curl is flagged.
		assert!(p.bot.signals.contains(&BotSignal::NonBrowserUserAgent));
		assert!(p.is_suspicious(0.5));
		// Cluster key is the fingerprint's raw rendering.
		assert_eq!(p.cluster_key(), p.fingerprint.raw());
	}

	#[test]
	fn same_client_shape_shares_a_cluster_key() {
		// Two requests with the same structure (different path *values*) cluster together.
		let a = ClientProfile::from_parts_default(&parts(Request::builder().uri("/a/b").header("user-agent", "bot").header("accept", "*/*")));
		let b = ClientProfile::from_parts_default(&parts(Request::builder().uri("/c/d").header("accept", "*/*").header("user-agent", "bot")));
		assert_eq!(a.cluster_key(), b.cluster_key());

		// A different client structure splits the cluster.
		let c = ClientProfile::from_parts_default(&parts(Request::builder().uri("/a/b").header("user-agent", "firefox").header("accept", "*/*").header("accept-language", "en")));
		assert_ne!(a.cluster_key(), c.cluster_key());
	}

	#[test]
	fn browser_profile_is_not_suspicious() {
		let p = ClientProfile::from_parts_default(&parts(
			Request::builder()
				.uri("/")
				.header("host", "x.onion")
				.header("user-agent", "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0")
				.header("accept", "text/html")
				.header("accept-language", "en-US,en")
				.header("accept-encoding", "gzip, deflate, br")
				.header("connection", "keep-alive"),
		));
		assert!(!p.is_suspicious(0.5));
		assert_eq!(p.bot.score, 0.0);
	}

	#[test]
	fn custom_heuristics_are_honoured() {
		// A strict sparse-header threshold flags an otherwise-conventional small request.
		let strict = BotHeuristics::new().sparse_header_threshold(8);
		let req = parts(Request::builder().uri("/").header("host", "x").header("user-agent", "Mozilla/5.0").header("accept", "text/html").header("accept-language", "en").header("accept-encoding", "gzip"));
		let p = ClientProfile::from_parts(&req, &strict);
		assert!(p.bot.signals.contains(&BotSignal::SparseHeaders));
	}
}

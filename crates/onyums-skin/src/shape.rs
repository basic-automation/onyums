//! Request-shape feature extraction (Phase 4 — request-shape baselining).
//!
//! Cloudflare's adaptive DDoS defense baselines the *normal* distribution of request
//! features and flags deviation; its `dosd` logic self-selects the most discriminating
//! field. Over Tor almost every field that drives that — client IP, ASN, geo, the TLS
//! fingerprint — is gone (see `ROADMAP.md`). What survives is the **HTTP request shape**:
//! the method, the path's structure, the *set* of headers the client sends, the presence
//! of a cookie, and the user-agent. A pinned-fingerprint client like Tor Browser sends a
//! small, canonical shape; a scripted flood (curl, a bespoke bot) sends a distinctly
//! different one. [`RequestShape`] extracts those Tor-surviving dimensions into a stable
//! [`fingerprint`](RequestShape::fingerprint) that [`ShapeBaseline`](crate::shape) can
//! tally to learn "normal" and score deviation — the no-IP analog of Cloudflare's
//! request-shape baselining.
//!
//! **Why the header *set*, not the wire order.** JA4H keys on the raw on-the-wire header
//! order, but axum/hyper parse headers into an [`http::HeaderMap`] whose iteration order is
//! not the wire order, so that signal is unavailable post-parse. We key on the sorted,
//! de-duplicated *set* of header names instead — still a real fingerprint (Tor Browser
//! emits a fixed canonical set; a bot's set differs) and stable across requests.

use axum::http::request::Parts;

/// The largest user-agent prefix retained in a [`RequestShape`]. Legitimate Tor clients
/// pin a short UA; capping bounds the memory a pathological UA can cost the baseline's
/// frequency table without losing discriminating power.
const MAX_UA_LEN: usize = 160;

/// The Tor-surviving HTTP dimensions of one request, extracted from its [`Parts`].
///
/// Every field is identity-free network-wise — there is no IP, ASN, geo, or TLS data here,
/// only the shape of the HTTP request itself, which is all an onion service can observe.
/// Construct with [`from_parts`](Self::from_parts); fold many requests' [`fingerprint`](Self::fingerprint)s
/// into a [`ShapeBaseline`] to learn the normal distribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestShape {
	/// The request method, uppercased (`GET`, `POST`, …).
	pub method: String,
	/// Number of non-empty path segments (`/a/b/c` → 3, `/` → 0).
	pub path_depth: usize,
	/// Whether the final path segment carries a file extension (a `.` after its start).
	pub path_has_extension: bool,
	/// The header names present, lowercased, de-duplicated, and **sorted** for stability
	/// (the wire order is lost after parsing — see the module docs).
	pub header_names: Vec<String>,
	/// Whether the request carries a `Cookie` header (a returning/cleared client usually
	/// does; a fresh flood usually does not).
	pub has_cookie: bool,
	/// The user-agent, lowercased and capped at [`MAX_UA_LEN`]; `None` if absent. Over Tor
	/// the legitimate UA set is tiny (Tor Browser pins it), so an odd or missing UA stands
	/// out sharply.
	pub ua: Option<String>,
}

impl RequestShape {
	/// Extract the request shape from a parsed request's [`Parts`].
	#[must_use]
	pub fn from_parts(parts: &Parts) -> Self {
		let path = parts.uri.path();
		let mut segments = path.split('/').filter(|s| !s.is_empty());
		let path_depth = path.split('/').filter(|s| !s.is_empty()).count();
		let path_has_extension = segments.next_back().is_some_and(|last| {
			// A leading dot (a dotfile) is not an extension; require a dot after the start.
			last.rfind('.').is_some_and(|i| i > 0)
		});

		let mut header_names: Vec<String> = parts.headers.keys().map(|name| name.as_str().to_ascii_lowercase()).collect();
		header_names.sort_unstable();
		header_names.dedup();

		let has_cookie = parts.headers.contains_key(axum::http::header::COOKIE);
		let ua = parts.headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok()).map(|s| {
			let mut ua = s.to_ascii_lowercase();
			ua.truncate(MAX_UA_LEN);
			ua
		});

		Self {
			method: parts.method.as_str().to_ascii_uppercase(),
			path_depth,
			path_has_extension,
			header_names,
			has_cookie,
			ua,
		}
	}

	/// A stable, canonical string key over the shape's dimensions — the fingerprint a
	/// [`ShapeBaseline`] tallies. Two requests with the same method, path structure, header
	/// set, cookie presence, and UA share a fingerprint; any difference splits them.
	///
	/// The format is internal and not a stability guarantee across crate versions; it is a
	/// key for in-process frequency counting, not a wire format.
	#[must_use]
	pub fn fingerprint(&self) -> String {
		format!(
			"m={}|d={}|x={}|c={}|h={}|u={}",
			self.method,
			self.path_depth,
			u8::from(self.path_has_extension),
			u8::from(self.has_cookie),
			self.header_names.join(","),
			self.ua.as_deref().unwrap_or("-"),
		)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use axum::http::Request;

	fn parts(builder: axum::http::request::Builder) -> Parts {
		builder.body(()).unwrap().into_parts().0
	}

	#[test]
	fn extracts_method_and_path_structure() {
		let s = RequestShape::from_parts(&parts(Request::builder().method("post").uri("/api/v1/items")));
		assert_eq!(s.method, "POST");
		assert_eq!(s.path_depth, 3);
		assert!(!s.path_has_extension);

		let root = RequestShape::from_parts(&parts(Request::builder().uri("/")));
		assert_eq!(root.path_depth, 0);
		assert!(!root.path_has_extension);
	}

	#[test]
	fn detects_file_extension_but_not_dotfile() {
		let file = RequestShape::from_parts(&parts(Request::builder().uri("/assets/app.css")));
		assert!(file.path_has_extension);

		// A leading-dot last segment is a dotfile, not an extension.
		let dotfile = RequestShape::from_parts(&parts(Request::builder().uri("/.well-known/x")));
		assert!(!dotfile.path_has_extension);
		let dotfile2 = RequestShape::from_parts(&parts(Request::builder().uri("/dir/.env")));
		assert!(!dotfile2.path_has_extension);
	}

	#[test]
	fn header_names_are_sorted_lowercased_and_unique() {
		let s = RequestShape::from_parts(&parts(
			Request::builder().uri("/").header("User-Agent", "x").header("Accept", "*/*").header("Cookie", "skin=1"),
		));
		assert_eq!(s.header_names, vec!["accept".to_owned(), "cookie".to_owned(), "user-agent".to_owned()]);
		assert!(s.has_cookie);
		assert_eq!(s.ua.as_deref(), Some("x"));
	}

	#[test]
	fn no_cookie_no_ua_is_represented() {
		let s = RequestShape::from_parts(&parts(Request::builder().uri("/x").header("accept", "*/*")));
		assert!(!s.has_cookie);
		assert_eq!(s.ua, None);
		assert_eq!(s.fingerprint(), "m=GET|d=1|x=0|c=0|h=accept|u=-");
	}

	#[test]
	fn ua_is_capped_in_length() {
		let long = "U".repeat(MAX_UA_LEN + 50);
		let s = RequestShape::from_parts(&parts(Request::builder().uri("/").header("user-agent", long)));
		assert_eq!(s.ua.as_deref().map(str::len), Some(MAX_UA_LEN));
	}

	#[test]
	fn identical_shapes_share_a_fingerprint_differences_split() {
		let a = RequestShape::from_parts(&parts(Request::builder().uri("/a/b").header("user-agent", "bot").header("accept", "*/*")));
		let b = RequestShape::from_parts(&parts(Request::builder().uri("/c/d").header("accept", "*/*").header("user-agent", "bot")));
		// Same method, depth, header set, cookie-ness, UA → same fingerprint (path *values* differ, structure does not).
		assert_eq!(a.fingerprint(), b.fingerprint());

		// A different UA splits them.
		let c = RequestShape::from_parts(&parts(Request::builder().uri("/a/b").header("user-agent", "firefox").header("accept", "*/*")));
		assert_ne!(a.fingerprint(), c.fingerprint());
	}
}

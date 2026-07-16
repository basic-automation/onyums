//! JA4H-style HTTP request fingerprinting (Phase 5 — frontier defenses).
//!
//! Over Tor every network-layer fingerprint Cloudflare keys on — client IP, ASN, geo,
//! the TLS ClientHello (JA3/JA4) — is gone (see `ROADMAP.md`). The **strongest signal
//! that survives** is the shape of the HTTP request itself, and [JA4H][ja4] is the
//! standard, structured way to canonicalize it: a compact, four-part key over the method,
//! HTTP version, cookie/referer presence, header count, primary language, and hashes of
//! the header-name list, cookie field names, and cookie name=value pairs. Two clients that
//! emit the same request structure share a JA4H; a pinned Tor Browser produces a small,
//! stable set of fingerprints while a scripted flood (curl, a bespoke bot) produces a
//! distinctly different one. [`Ja4hFingerprint`] is a cluster/identify key, never a hard
//! block on its own — it is one input to difficulty tuning and the bot heuristics in
//! [`shape`](crate::shape).
//!
//! **The one deviation from the spec — header *order*.** Canonical JA4H hashes the header
//! names in their raw on-the-wire order. axum/hyper parse headers into an
//! [`http::HeaderMap`] whose iteration order is *not* the wire order (the same limitation
//! [`RequestShape`](crate::shape::RequestShape) already documents), so the header-name
//! component here ([`b`](Ja4hFingerprint::b)) hashes the **sorted, de-duplicated set** of
//! names instead. That weakens it relative to a packet-capture JA4H — order is a real
//! discriminator we cannot recover post-parse — but the set is still a stable fingerprint
//! and the rest of the key (method/version/flags/count/lang, the cookie hashes) follows the
//! spec. The cookie components *are* spec-faithful: the `Cookie` header value preserves
//! field order on the wire, and JA4H sorts cookie fields anyway.
//!
//! [ja4]: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md

use std::fmt;

use axum::http::{Version, header, request::Parts};
use sha2::{Digest, Sha256};

/// The sentinel emitted for an empty hash component (no headers, or no cookie). Twelve
/// zeroes mirror JA4H's convention of a zeroed truncated hash when there is nothing to hash.
const EMPTY_HASH: &str = "000000000000";

/// The fixed width of the language sub-field in component [`a`](Ja4hFingerprint::a).
const LANG_LEN: usize = 4;

/// A JA4H-style fingerprint of one HTTP request, in four components
/// (`a`/`b`/`c`/`d`), rendered as `a_b_c_d` by [`Display`]/[`raw`](Self::raw).
///
/// Construct with [`from_parts`](Self::from_parts). The string is a stable in-process
/// cluster key, not a wire format or a cross-version stability guarantee — see the module
/// docs for the header-order deviation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ja4hFingerprint {
	/// Metadata prefix: `[method 2][version 2][cookie 1][referer 1][header-count 2][lang 4]`.
	///
	/// `method` is the lowercased first two letters of the method (`ge`, `po`); `version`
	/// is `09`/`10`/`11`/`20`/`30`; the cookie flag is `c`/`n` and the referer flag `r`/`n`;
	/// the header count excludes `Cookie` and `Referer` and is capped at `99`; `lang` is the
	/// first four alphanumerics of the primary `Accept-Language` value (lowercased), or
	/// `0000` if absent.
	pub a: String,
	/// Truncated SHA-256 (12 hex) of the comma-joined header-name **set** (sorted, lowercased,
	/// `Cookie`/`Referer` excluded), or [`EMPTY_HASH`] when no other headers are present.
	pub b: String,
	/// Truncated SHA-256 (12 hex) of the sorted, comma-joined cookie field **names**, or
	/// [`EMPTY_HASH`] when there is no `Cookie` header.
	pub c: String,
	/// Truncated SHA-256 (12 hex) of the sorted, comma-joined cookie `name=value` pairs, or
	/// [`EMPTY_HASH`] when there is no `Cookie` header.
	pub d: String,
}

impl Ja4hFingerprint {
	/// Compute the JA4H-style fingerprint of a parsed request's [`Parts`].
	#[must_use]
	pub fn from_parts(parts: &Parts) -> Self {
		let has_cookie = parts.headers.contains_key(header::COOKIE);
		let has_referer = parts.headers.contains_key(header::REFERER);

		// Header-name set, excluding the two names whose presence is already encoded as flags.
		let mut names: Vec<String> = parts.headers.keys().filter(|name| *name != header::COOKIE && *name != header::REFERER).map(|name| name.as_str().to_ascii_lowercase()).collect();
		names.sort_unstable();
		names.dedup();

		let method = {
			let m = parts.method.as_str().to_ascii_lowercase();
			let mut prefix: String = m.chars().take(2).collect();
			while prefix.len() < 2 {
				prefix.push('0');
			}
			prefix
		};
		let version = match parts.version {
			Version::HTTP_09 => "09",
			Version::HTTP_10 => "10",
			Version::HTTP_11 => "11",
			Version::HTTP_2 => "20",
			Version::HTTP_3 => "30",
			_ => "00",
		};
		let count = names.len().min(99);
		let a = format!("{method}{version}{cookie}{referer}{count:02}{lang}", cookie = if has_cookie { 'c' } else { 'n' }, referer = if has_referer { 'r' } else { 'n' }, lang = primary_language(parts),);

		let b = if names.is_empty() { EMPTY_HASH.to_owned() } else { hash12(&names.join(",")) };

		let (c, d) = cookie_hashes(parts);

		Self { a, b, c, d }
	}

	/// The canonical `a_b_c_d` rendering — the cluster key.
	#[must_use]
	pub fn raw(&self) -> String {
		format!("{}_{}_{}_{}", self.a, self.b, self.c, self.d)
	}
}

impl fmt::Display for Ja4hFingerprint {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}_{}_{}_{}", self.a, self.b, self.c, self.d)
	}
}

/// First four alphanumerics of the primary `Accept-Language` value, lowercased and
/// right-padded with `0` to a fixed [`LANG_LEN`]; `0000` when the header is absent or empty
/// (e.g. `en-US,fr;q=0.8` → `enus`, `en` → `en00`).
fn primary_language(parts: &Parts) -> String {
	let Some(raw) = parts.headers.get(header::ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()) else {
		return "0".repeat(LANG_LEN);
	};
	// The primary tag is everything before the first list separator or q-value.
	let primary = raw.split(',').next().unwrap_or("").split(';').next().unwrap_or("");
	let mut lang: String = primary.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_lowercase()).take(LANG_LEN).collect();
	if lang.is_empty() {
		return "0".repeat(LANG_LEN);
	}
	while lang.len() < LANG_LEN {
		lang.push('0');
	}
	lang
}

/// The `c` (sorted cookie field names) and `d` (sorted cookie `name=value` pairs) hashes.
/// Both are [`EMPTY_HASH`] when there is no parseable `Cookie` header.
fn cookie_hashes(parts: &Parts) -> (String, String) {
	let Some(cookie) = parts.headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) else {
		return (EMPTY_HASH.to_owned(), EMPTY_HASH.to_owned());
	};

	let mut fields: Vec<(&str, &str)> = cookie
		.split(';')
		.filter_map(|pair| {
			let pair = pair.trim();
			if pair.is_empty() {
				return None;
			}
			// A cookie field is `name=value`; a bare token (no `=`) has an empty value.
			match pair.split_once('=') {
				Some((name, value)) => Some((name.trim(), value.trim())),
				None => Some((pair, "")),
			}
		})
		.collect();
	if fields.is_empty() {
		return (EMPTY_HASH.to_owned(), EMPTY_HASH.to_owned());
	}
	// JA4H sorts cookie fields by name, so order on the wire does not split the fingerprint.
	fields.sort_by(|a, b| a.0.cmp(b.0));

	let names = fields.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(",");
	let pairs = fields.iter().map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>().join(",");
	(hash12(&names), hash12(&pairs))
}

/// Truncated SHA-256: the first six bytes of the digest, hex-encoded to twelve characters —
/// the width JA4H uses for each hash component.
fn hash12(input: &str) -> String {
	let digest = Sha256::digest(input.as_bytes());
	let mut out = String::with_capacity(12);
	for byte in &digest[..6] {
		use fmt::Write;
		let _ = write!(out, "{byte:02x}");
	}
	out
}

#[cfg(test)]
mod tests {
	use axum::http::Request;

	use super::*;

	fn parts(builder: axum::http::request::Builder) -> Parts {
		builder.body(()).unwrap().into_parts().0
	}

	#[test]
	fn metadata_prefix_encodes_method_version_flags_and_count() {
		let fp = Ja4hFingerprint::from_parts(&parts(Request::builder().method("POST").uri("/").header("accept", "*/*").header("user-agent", "x").header("accept-language", "en-US,fr;q=0.8")));
		// po(method) 11(HTTP/1.1) n(no cookie) n(no referer) 02(two headers: accept, user-agent
		// — accept-language counts too → three) enus(language).
		assert_eq!(&fp.a[0..2], "po");
		assert_eq!(&fp.a[2..4], "11");
		assert_eq!(&fp.a[4..5], "n");
		assert_eq!(&fp.a[5..6], "n");
		assert_eq!(&fp.a[6..8], "03");
		assert_eq!(&fp.a[8..12], "enus");
	}

	#[test]
	fn cookie_and_referer_set_their_flags_and_are_excluded_from_the_count() {
		let with = Ja4hFingerprint::from_parts(&parts(Request::builder().uri("/").header("accept", "*/*").header("cookie", "skin=1").header("referer", "http://x.onion/")));
		// c(cookie) r(referer), and only `accept` counts toward the header count.
		assert_eq!(&with.a[4..5], "c");
		assert_eq!(&with.a[5..6], "r");
		assert_eq!(&with.a[6..8], "01");
		// The cookie components are populated, not the empty sentinel.
		assert_ne!(with.c, EMPTY_HASH);
		assert_ne!(with.d, EMPTY_HASH);
	}

	#[test]
	fn absent_cookie_and_lang_use_sentinels() {
		let fp = Ja4hFingerprint::from_parts(&parts(Request::builder().uri("/").header("accept", "*/*")));
		assert_eq!(&fp.a[8..12], "0000");
		assert_eq!(fp.c, EMPTY_HASH);
		assert_eq!(fp.d, EMPTY_HASH);
		// One header (`accept`) → a non-empty b component.
		assert_ne!(fp.b, EMPTY_HASH);
	}

	#[test]
	fn no_other_headers_yields_empty_b() {
		// A request whose only headers are Cookie/Referer (both excluded) has an empty name set.
		let fp = Ja4hFingerprint::from_parts(&parts(Request::builder().uri("/").header("cookie", "a=1")));
		assert_eq!(&fp.a[6..8], "00");
		assert_eq!(fp.b, EMPTY_HASH);
	}

	#[test]
	fn header_name_set_is_order_independent() {
		// Same header *set* in two wire orders → identical fingerprint (the documented
		// set-based deviation: order does not split us, unlike packet-capture JA4H).
		let one = Ja4hFingerprint::from_parts(&parts(Request::builder().uri("/").header("accept", "*/*").header("user-agent", "x")));
		let two = Ja4hFingerprint::from_parts(&parts(Request::builder().uri("/").header("user-agent", "x").header("accept", "*/*")));
		assert_eq!(one, two);
		assert_eq!(one.raw(), two.raw());
	}

	#[test]
	fn cookie_hash_is_order_independent_but_value_sensitive() {
		// JA4H sorts cookie fields, so field order does not change the hash...
		let a = Ja4hFingerprint::from_parts(&parts(Request::builder().uri("/").header("cookie", "b=2; a=1")));
		let b = Ja4hFingerprint::from_parts(&parts(Request::builder().uri("/").header("cookie", "a=1; b=2")));
		assert_eq!(a.c, b.c);
		assert_eq!(a.d, b.d);
		// ...but a different value changes the value hash (d) while the name hash (c) holds.
		let c = Ja4hFingerprint::from_parts(&parts(Request::builder().uri("/").header("cookie", "a=9; b=2")));
		assert_eq!(a.c, c.c);
		assert_ne!(a.d, c.d);
	}

	#[test]
	fn distinct_clients_get_distinct_fingerprints() {
		// A Tor-Browser-shaped request vs a curl-shaped one cluster apart.
		let browser = Ja4hFingerprint::from_parts(&parts(Request::builder().method("GET").uri("/").header("accept", "text/html").header("accept-language", "en-US,en").header("user-agent", "Mozilla/5.0").header("cookie", "skin=abc")));
		let curl = Ja4hFingerprint::from_parts(&parts(Request::builder().method("GET").uri("/").header("accept", "*/*").header("user-agent", "curl/8.0")));
		assert_ne!(browser.raw(), curl.raw());
		assert_eq!(&curl.a[8..12], "0000", "curl sends no Accept-Language");
		assert_eq!(&browser.a[4..5], "c", "browser carries a clearance cookie");
	}

	#[test]
	fn hash12_is_twelve_lowercase_hex() {
		let fp = Ja4hFingerprint::from_parts(&parts(Request::builder().uri("/").header("accept", "*/*")));
		assert_eq!(fp.b.len(), 12);
		assert!(fp.b.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
	}

	#[test]
	fn short_language_is_right_padded() {
		let fp = Ja4hFingerprint::from_parts(&parts(Request::builder().uri("/").header("accept-language", "en")));
		assert_eq!(&fp.a[8..12], "en00");
	}

	#[test]
	fn display_matches_raw() {
		let fp = Ja4hFingerprint::from_parts(&parts(Request::builder().uri("/").header("accept", "*/*")));
		assert_eq!(fp.to_string(), fp.raw());
		assert_eq!(fp.raw().matches('_').count(), 3);
	}
}

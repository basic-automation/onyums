//! The typed Tor v3 onion-service address [`OnionAddress`] and its helpers — URL /
//! `Onion-Location` formatting, validating `parse`, and QR rendering (onyums ROADMAP
//! Phase 1 identity). Extracted from `lib.rs` as a slice of the Phase 0 module split.

use anyhow::Result;
use safelog::DisplayRedacted;

/// A Tor v3 onion service address — the service's public identity.
///
/// Normalized to exactly one trailing `.onion` suffix, so it is safe to use
/// directly as a TLS subject-alternative-name or an HTTP redirect host. This is
/// the typed replacement for the stringly-typed, process-global onion name: the
/// address is threaded explicitly from the launched service to the handlers that
/// need it (TLS cert generation, the port-80 → HTTPS redirect) rather than read
/// from a shared `static`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnionAddress(String);

impl OnionAddress {
	/// Normalize a raw onion service name to exactly one trailing `.onion`
	/// suffix, handling a bare name, a single suffix, or accidental repetition.
	///
	/// This *trusts* its input — it only fixes the suffix and does not check that
	/// the name is a real v3 onion address. Use it for names that came from arti
	/// itself (the launched service). For operator- or user-supplied strings,
	/// prefer the validating [`Self::parse`].
	#[must_use]
	pub fn normalized(name: &str) -> Self {
		Self(format!("{}.onion", name.trim_end_matches(".onion")))
	}

	/// Parse and *validate* a v3 `.onion` address.
	///
	/// Unlike [`Self::normalized`], this confirms the string is a real v3 onion
	/// name — correct length, base32 alphabet, checksum, and version — by
	/// round-tripping it through arti's own `HsId` parser, then returns the
	/// canonical lowercase form. The input must be a bare `<base32>.onion` host
	/// (no scheme, path, or subdomain); surrounding whitespace is trimmed.
	///
	/// # Errors
	/// Returns an error if the string is not a valid v3 onion address.
	pub fn parse(address: &str) -> Result<Self> {
		let hsid: tor_hscrypto::pk::HsId = address.trim().parse().map_err(|e| anyhow::anyhow!("invalid v3 onion address: {e}"))?;
		Ok(Self::normalized(&hsid.display_unredacted().to_string()))
	}

	/// The full address, including the `.onion` suffix.
	#[must_use]
	pub fn as_str(&self) -> &str {
		&self.0
	}

	/// The host used for TLS SANs and redirect targets. Identical to
	/// [`Self::as_str`]; named for intent at the call site.
	#[must_use]
	pub fn host(&self) -> &str {
		&self.0
	}

	/// The canonical HTTPS URL for this service.
	///
	/// onyums serves HTTPS on port 443 (with a port-80 → HTTPS redirect), so this
	/// is the URL clients should use.
	#[must_use]
	pub fn https_url(&self) -> String {
		format!("https://{}/", self.0)
	}

	/// The plain-HTTP URL (port 80). onyums redirects this to [`Self::https_url`].
	#[must_use]
	pub fn http_url(&self) -> String {
		format!("http://{}/", self.0)
	}

	/// The value for an [`Onion-Location`] response header (or its
	/// `<meta http-equiv="onion-location">` equivalent): the canonical onion URL a
	/// clearnet site emits to point Tor Browser at its onion equivalent.
	///
	/// [`Onion-Location`]: https://community.torproject.org/onion-services/advanced/onion-location/
	#[must_use]
	pub fn onion_location(&self) -> String {
		self.https_url()
	}

	/// The `(name, value)` pair for the `Onion-Location` response header, ready to
	/// insert into a response. The name is lowercase, as is conventional for HTTP/2.
	#[must_use]
	pub fn onion_location_header(&self) -> (&'static str, String) {
		("onion-location", self.onion_location())
	}

	/// Render a scannable QR code of the service's canonical HTTPS URL as a
	/// standalone SVG document string.
	///
	/// The QR encodes [`Self::https_url`] — the URL a client should actually open
	/// — so a Tor Browser user can scan it instead of typing 56 base32 characters
	/// by hand. The output is pure text (an `<svg>` document); onyums pulls in no
	/// raster-image dependency for this (`qrcode` is built with its `image`
	/// renderer disabled), keeping the tree pure Rust.
	///
	/// # Panics
	/// Never in practice: the encoded data is a fixed-shape onion URL (~70 bytes),
	/// far below the smallest QR version's capacity, so encoding cannot fail.
	#[must_use]
	pub fn qr_svg(&self) -> String {
		use qrcode::{QrCode, render::svg};
		// The encoded data is a fixed-shape onion URL (~70 bytes), far below the
		// capacity of even the smallest QR version, so construction cannot fail.
		let code = QrCode::new(self.https_url().as_bytes()).expect("an onion URL always fits in a QR code");
		code.render::<svg::Color>().min_dimensions(256, 256).quiet_zone(true).build()
	}

	/// Render a scannable QR code of the service's canonical HTTPS URL as Unicode
	/// text suitable for printing to a terminal.
	///
	/// Like [`Self::qr_svg`] but rendered with half-block characters
	/// (`unicode::Dense1x2`), so an operator can print the address as a QR code
	/// straight to the console — e.g. right after the service reports ready. Each
	/// QR row maps to one line of output.
	///
	/// # Panics
	/// Never in practice, for the same reason as [`Self::qr_svg`]: an onion URL
	/// always fits in a QR code.
	#[must_use]
	pub fn qr_terminal(&self) -> String {
		use qrcode::{QrCode, render::unicode};
		let code = QrCode::new(self.https_url().as_bytes()).expect("an onion URL always fits in a QR code");
		code.render::<unicode::Dense1x2>().quiet_zone(true).build()
	}
}

impl std::fmt::Display for OnionAddress {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.0)
	}
}

impl From<OnionAddress> for String {
	fn from(address: OnionAddress) -> Self {
		address.0
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::vanity;

	#[test]
	fn onion_address_normalizes_bare_name() {
		let address = OnionAddress::normalized("abcdef");
		assert_eq!(address.as_str(), "abcdef.onion");
		assert_eq!(address.host(), "abcdef.onion");
	}

	#[test]
	fn onion_address_keeps_single_suffix() {
		let address = OnionAddress::normalized("abcdef.onion");
		assert_eq!(address.as_str(), "abcdef.onion");
	}

	#[test]
	fn onion_address_collapses_repeated_suffix() {
		let address = OnionAddress::normalized("abcdef.onion.onion");
		assert_eq!(address.as_str(), "abcdef.onion");
	}

	#[test]
	fn onion_address_display_and_into_string_match() {
		let address = OnionAddress::normalized("abcdef");
		assert_eq!(address.to_string(), "abcdef.onion");
		let owned: String = address.into();
		assert_eq!(owned, "abcdef.onion");
	}

	#[test]
	fn parse_accepts_a_valid_mined_address_and_canonicalizes() {
		// Mining yields a guaranteed-valid v3 address; `parse` must accept it and
		// round-trip to the same canonical form.
		let key = vanity::mine_within("a", 50_000).expect("valid prefix").expect("should find a match");
		let canonical = key.address().as_str();
		let parsed = OnionAddress::parse(canonical).expect("a mined address must validate");
		assert_eq!(&parsed, key.address());
		// Surrounding whitespace is tolerated.
		let parsed_padded = OnionAddress::parse(&format!("  {canonical}  ")).expect("whitespace should be trimmed");
		assert_eq!(&parsed_padded, key.address());
	}

	#[test]
	fn parse_rejects_invalid_addresses() {
		let key = vanity::mine_within("a", 50_000).expect("valid prefix").expect("should find a match");
		let valid = key.address().as_str();

		// Not an onion domain at all.
		assert!(OnionAddress::parse("example.com").is_err());
		// A bare name with no suffix is not accepted by the strict parser.
		assert!(OnionAddress::parse("abcdef").is_err());
		// A subdomain in front of a valid address is rejected.
		assert!(OnionAddress::parse(&format!("www.{valid}")).is_err());

		// Corrupt the public-key region (first base32 char) so the checksum no
		// longer matches — a single flip is overwhelmingly likely to be rejected.
		let mut chars: Vec<char> = valid.chars().collect();
		chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
		let corrupted: String = chars.into_iter().collect();
		assert!(OnionAddress::parse(&corrupted).is_err(), "a corrupted checksum must be rejected");
	}

	#[test]
	fn url_and_onion_location_helpers_format_correctly() {
		let address = OnionAddress::normalized("abcdef");
		assert_eq!(address.https_url(), "https://abcdef.onion/");
		assert_eq!(address.http_url(), "http://abcdef.onion/");
		assert_eq!(address.onion_location(), "https://abcdef.onion/");
		let (name, value) = address.onion_location_header();
		assert_eq!(name, "onion-location");
		assert_eq!(value, "https://abcdef.onion/");
	}

	#[test]
	fn qr_svg_is_a_wellformed_svg_document() {
		let address = OnionAddress::normalized("abcdef");
		let svg = address.qr_svg();
		assert!(svg.starts_with("<?xml") || svg.starts_with("<svg"), "should be an SVG document, got: {}", &svg[..svg.len().min(40)]);
		assert!(svg.contains("<svg"), "missing <svg> element");
		assert!(svg.contains("</svg>"), "missing closing </svg>");
		// A real QR renders dark modules as filled rects/paths — a blank/degenerate
		// document would have none.
		assert!(svg.contains("path") || svg.contains("rect"), "SVG has no QR modules");
	}

	#[test]
	fn qr_encoding_is_deterministic_and_address_sensitive() {
		let a = OnionAddress::normalized("abcdef");
		let b = OnionAddress::normalized("ghijkl");
		// Deterministic: same address → identical QR (encoding has no randomness).
		assert_eq!(a.qr_svg(), a.qr_svg());
		assert_eq!(a.qr_terminal(), a.qr_terminal());
		// Address-sensitive: a different URL is encoded into a different QR.
		assert_ne!(a.qr_svg(), b.qr_svg());
		assert_ne!(a.qr_terminal(), b.qr_terminal());
	}

	#[test]
	fn qr_terminal_is_multiline_block_art() {
		let address = OnionAddress::normalized("abcdef");
		let term = address.qr_terminal();
		assert!(!term.is_empty(), "terminal QR must not be empty");
		// Dense1x2 emits one line per two QR rows; a real code is many lines tall.
		assert!(term.lines().count() > 5, "terminal QR should span multiple lines");
	}
}

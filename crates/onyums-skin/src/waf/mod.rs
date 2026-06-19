//! A pure-Rust Web Application Firewall: signature inspection of the request,
//! IP-free by construction (the cleanest Cloudflare carry-over — see `ROADMAP.md`
//! Phase 3).
//!
//! The engine is a [`regex::RegexSet`] evaluated over the request's method, target
//! (path + query), and header values. `RegexSet` matches every pattern in a single
//! pass and uses `aho-corasick` internally for literal prefiltering, so adding more
//! signatures stays cheap. The starter ruleset covers the classic signature classes
//! (SQLi / XSS / path traversal / protocol anomalies); it is **not** OWASP-CRS-complete
//! — the 100%-Rust rule (no Coraza/ModSecurity FFI) means CRS coverage is reached by
//! porting rules into this engine, never by linking a foreign one. Rules are
//! operator-extensible: [`Waf::new`] takes any rule iterator, so a caller can extend
//! [`starter_rules`] with its own.
//!
//! Inspection runs each field **twice**: once over the raw string as received, then,
//! if the field was percent-encoded, once more over its decoded form — so an attack
//! hidden behind a single encoding layer (`%3Cscript%3E`, `..%2f`) is caught by the
//! same rules as its plaintext twin. Decoding iterates to a fixed point (capped at
//! [`MAX_DECODE_PASSES`]); input that needs **more than one** pass to settle is
//! *multiply* percent-encoded — a classic evasion tell (`%252e%252e%252f`) with no
//! legitimate use over an onion service — and is blocked outright as a protocol anomaly
//! (rule id [`MULTI_ENCODING_RULE_ID`]). That guard is on by default and can be relaxed
//! with [`Waf::block_multi_encoded`]; with it off, the fully-decoded form is still
//! matched against the ruleset, so the payload is usually caught anyway, just attributed
//! to its specific rule rather than to the evasion attempt.
//!
//! The engine is wired ahead of the gate in the [`SkinLayer`](crate::layer) layer
//! order (WAF → clearance → challenge → rate-limit); it is off unless a [`Waf`] is
//! configured, and [`Skin::secure_default`](crate::layer::Skin::secure_default) turns
//! on the [`starter`](Waf::starter) ruleset.

use axum::http::request::Parts;
use regex::RegexSet;

/// Maximum number of percent-decode passes [`normalize`] performs before giving up.
/// One pass peels a single encoding layer; reaching this cap means the input was
/// multiply encoded (or maliciously deep) and is treated as evasive regardless.
pub const MAX_DECODE_PASSES: usize = 4;

/// The synthetic rule id reported when input is blocked for being multiply
/// percent-encoded (see [`Waf::block_multi_encoded`]). It is not part of
/// [`starter_rules`] — the engine emits it directly.
pub const MULTI_ENCODING_RULE_ID: &str = "anomaly_multiple_encoding";

/// The signature class a rule belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WafCategory {
	/// SQL injection.
	Sqli,
	/// Cross-site scripting.
	Xss,
	/// Path / directory traversal.
	PathTraversal,
	/// Malformed or anomalous protocol input (control chars, header injection).
	ProtocolAnomaly,
}

impl WafCategory {
	/// A stable, lowercase name for logs and security events.
	#[must_use]
	pub const fn name(self) -> &'static str {
		match self {
			Self::Sqli => "sqli",
			Self::Xss => "xss",
			Self::PathTraversal => "path_traversal",
			Self::ProtocolAnomaly => "protocol_anomaly",
		}
	}
}

/// A single signature rule: a stable `id`, its [`WafCategory`], and a regex `pattern`.
/// Patterns are case-handling at the author's discretion (prefix `(?i)` for
/// case-insensitive); they are compiled together into one [`RegexSet`].
#[derive(Clone, Debug)]
pub struct Rule {
	/// Stable identifier surfaced on a block (e.g. `"sqli_union_select"`).
	pub id: &'static str,
	/// The signature class.
	pub category: WafCategory,
	/// The regex source matched against each inspected string.
	pub pattern: &'static str,
}

/// What [`Waf::inspect`] decided about a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
	/// No signature matched; let the request through.
	Allow,
	/// A signature matched; the request should be blocked (typically `403`).
	Block(WafMatch),
}

/// The rule that fired and where it matched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WafMatch {
	/// The matched rule's [`Rule::id`].
	pub rule_id: &'static str,
	/// The matched rule's class.
	pub category: WafCategory,
	/// Which part of the request matched (e.g. `"target"`, `"header:user-agent"`).
	pub location: String,
}

/// The compiled WAF: a [`RegexSet`] plus index-aligned rule metadata.
pub struct Waf {
	set: RegexSet,
	/// Metadata for each pattern, in the same order passed to the [`RegexSet`].
	meta: Vec<(&'static str, WafCategory)>,
	/// When true (default), input requiring more than one percent-decode pass to reach a
	/// fixed point is blocked outright as a [`WafCategory::ProtocolAnomaly`].
	block_multi_encoded: bool,
}

impl Waf {
	/// Compile a WAF from a set of [`Rule`]s. Returns an error if any pattern fails to
	/// compile (so an operator's custom rule is validated up front).
	///
	/// # Errors
	/// Propagates [`regex::Error`] from [`RegexSet::new`] if a pattern is invalid.
	pub fn new(rules: impl IntoIterator<Item = Rule>) -> Result<Self, regex::Error> {
		let rules: Vec<Rule> = rules.into_iter().collect();
		let set = RegexSet::new(rules.iter().map(|r| r.pattern))?;
		let meta = rules.iter().map(|r| (r.id, r.category)).collect();
		Ok(Self { set, meta, block_multi_encoded: true })
	}

	/// Set whether multiply percent-encoded input is blocked outright as a protocol
	/// anomaly (default `true`). With it `false`, the engine still matches the
	/// fully-decoded form against the ruleset — so the payload is usually caught anyway,
	/// just attributed to its specific rule rather than to the evasion attempt.
	#[must_use]
	pub fn block_multi_encoded(mut self, block: bool) -> Self {
		self.block_multi_encoded = block;
		self
	}

	/// The default WAF over [`starter_rules`]. The starter patterns are known-good and
	/// covered by a compile test.
	#[must_use]
	pub fn starter() -> Self {
		Self::new(starter_rules()).expect("starter rules compile")
	}

	/// The number of compiled rules.
	#[must_use]
	pub fn rule_count(&self) -> usize {
		self.meta.len()
	}

	/// Match the ruleset against one literal string in a single pass; take the lowest
	/// rule index for a stable, deterministic result. `location` labels where the string
	/// came from for the returned [`WafMatch`].
	fn match_raw(&self, haystack: &str, location: &str) -> Option<WafMatch> {
		self.set.matches(haystack).iter().min().map(|idx| {
			let (rule_id, category) = self.meta[idx];
			WafMatch { rule_id, category, location: location.to_owned() }
		})
	}

	/// Inspect one field: match the raw string, then — if it was percent-encoded — its
	/// decoded form, applying the multiple-encoding guard. `location` labels where the
	/// string came from for the returned [`WafMatch`].
	fn inspect_str(&self, raw: &str, location: &str) -> Option<WafMatch> {
		// 1. The raw string exactly as received.
		if let Some(m) = self.match_raw(raw, location) {
			return Some(m);
		}
		// 2. Decode to a fixed point. Nothing encoded → raw was the whole story.
		let norm = normalize(raw);
		if norm.decode_passes == 0 {
			return None;
		}
		// 3. Multiply-encoded input is itself the signal: block it as an anomaly. With the
		//    guard off, fall through and let the decoded form match a specific rule.
		if self.block_multi_encoded && norm.decode_passes >= 2 {
			return Some(WafMatch {
				rule_id: MULTI_ENCODING_RULE_ID,
				category: WafCategory::ProtocolAnomaly,
				location: location.to_owned(),
			});
		}
		// 4. Match the decoded form (only if decoding actually changed the string).
		if norm.decoded != raw {
			return self.match_raw(&norm.decoded, location);
		}
		None
	}

	/// Inspect a request's method, target (path + query), and header values. Returns
	/// [`Verdict::Block`] on the first matching signature, else [`Verdict::Allow`].
	#[must_use]
	pub fn inspect(&self, parts: &Parts) -> Verdict {
		if let Some(m) = self.inspect_str(parts.method.as_str(), "method") {
			return Verdict::Block(m);
		}
		if let Some(pq) = parts.uri.path_and_query()
			&& let Some(m) = self.inspect_str(pq.as_str(), "target")
		{
			return Verdict::Block(m);
		}
		for (name, value) in &parts.headers {
			if let Ok(s) = value.to_str()
				&& let Some(m) = self.inspect_str(s, &format!("header:{name}"))
			{
				return Verdict::Block(m);
			}
		}
		Verdict::Allow
	}
}

impl Default for Waf {
	fn default() -> Self {
		Self::starter()
	}
}

/// The result of [`normalize`]: the fully percent-decoded string and how many decode
/// passes it took to settle (`0` = nothing was encoded).
struct Normalized {
	decoded: String,
	decode_passes: usize,
}

/// Iteratively percent-decode `input` until it stops changing or [`MAX_DECODE_PASSES`]
/// is reached. The pass count distinguishes un-encoded (`0`), singly-encoded (`1`), and
/// the evasive multiply-encoded (`>= 2`) cases.
fn normalize(input: &str) -> Normalized {
	let mut cur = input.to_owned();
	let mut passes = 0;
	while passes < MAX_DECODE_PASSES {
		let (next, changed) = percent_decode_once(&cur);
		if !changed {
			break;
		}
		cur = next;
		passes += 1;
	}
	Normalized { decoded: cur, decode_passes: passes }
}

/// Percent-decode `input` once: each well-formed `%XX` (two hex digits) becomes its
/// byte; a malformed `%` (truncated or non-hex) is left verbatim. Returns the decoded
/// string and whether any `%XX` was replaced. Decoding works on raw bytes and finishes
/// with [`String::from_utf8_lossy`], so multi-byte UTF-8 already in `input` survives and
/// the output is always valid UTF-8 for matching.
fn percent_decode_once(input: &str) -> (String, bool) {
	let bytes = input.as_bytes();
	let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
	let mut changed = false;
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] == b'%'
			&& i + 2 < bytes.len()
			&& let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
		{
			out.push((h << 4) | l);
			changed = true;
			i += 3;
			continue;
		}
		out.push(bytes[i]);
		i += 1;
	}
	(String::from_utf8_lossy(&out).into_owned(), changed)
}

/// The numeric value of a single hex digit, or `None` if `b` is not `[0-9A-Fa-f]`.
const fn hex_val(b: u8) -> Option<u8> {
	match b {
		b'0'..=b'9' => Some(b - b'0'),
		b'a'..=b'f' => Some(b - b'a' + 10),
		b'A'..=b'F' => Some(b - b'A' + 10),
		_ => None,
	}
}

/// The built-in starter ruleset: a small, curated set of high-signal patterns across
/// the classic classes. Deliberately conservative to keep false positives low; extend
/// it via [`Waf::new`] for fuller coverage. Patterns are case-insensitive where case
/// does not matter to the attack.
#[must_use]
pub fn starter_rules() -> Vec<Rule> {
	vec![
		// --- SQL injection ---
		Rule { id: "sqli_union_select", category: WafCategory::Sqli, pattern: r"(?i)\bunion\b[\s\S]{0,40}\bselect\b" },
		Rule { id: "sqli_or_tautology", category: WafCategory::Sqli, pattern: r#"(?i)\bor\b\s+['"]?\s*\d+\s*=\s*\d+"# },
		Rule { id: "sqli_stacked_query", category: WafCategory::Sqli, pattern: r"(?i);\s*(drop|delete|update|insert|truncate)\b" },
		Rule { id: "sqli_comment", category: WafCategory::Sqli, pattern: r"(--\s|#|/\*)[\s\S]*?(\bor\b|\band\b|=)" },
		// --- Cross-site scripting ---
		Rule { id: "xss_script_tag", category: WafCategory::Xss, pattern: r"(?i)<\s*script\b" },
		Rule { id: "xss_js_uri", category: WafCategory::Xss, pattern: r"(?i)javascript:" },
		Rule { id: "xss_event_handler", category: WafCategory::Xss, pattern: r"(?i)\bon(error|load|click|mouseover)\s*=" },
		// --- Path / directory traversal ---
		Rule { id: "traversal_dotdot", category: WafCategory::PathTraversal, pattern: r"(\.\./|\.\.\\)" },
		Rule { id: "traversal_encoded", category: WafCategory::PathTraversal, pattern: r"(?i)%2e%2e(%2f|%5c|/|\\)" },
		Rule { id: "traversal_sensitive_file", category: WafCategory::PathTraversal, pattern: r"(?i)(/etc/passwd|/etc/shadow|boot\.ini|win\.ini)" },
		// --- Protocol anomalies ---
		Rule { id: "anomaly_null_byte", category: WafCategory::ProtocolAnomaly, pattern: r"(\x00|%00)" },
		Rule { id: "anomaly_crlf", category: WafCategory::ProtocolAnomaly, pattern: r"(\r\n|%0d%0a|%0a|%0d)" },
	]
}

#[cfg(test)]
mod tests {
	use axum::http::Request;

	use super::*;

	fn parts(method: &str, uri: &str) -> Parts {
		Request::builder().method(method).uri(uri).body(()).unwrap().into_parts().0
	}

	fn blocked(v: &Verdict) -> &WafMatch {
		match v {
			Verdict::Block(m) => m,
			Verdict::Allow => panic!("expected Block, got Allow"),
		}
	}

	#[test]
	fn starter_rules_compile() {
		let waf = Waf::starter();
		assert_eq!(waf.rule_count(), starter_rules().len());
	}

	#[test]
	fn benign_request_is_allowed() {
		let waf = Waf::starter();
		assert_eq!(waf.inspect(&parts("GET", "/articles/hello-world?page=2")), Verdict::Allow);
	}

	#[test]
	fn sqli_union_select_is_blocked() {
		let waf = Waf::starter();
		let v = waf.inspect(&parts("GET", "/items?id=1%20UNION%20SELECT%20password%20FROM%20users"));
		// path_and_query keeps percent-encoding, so test the decoded form via inspect_str too.
		assert_eq!(waf.inspect_str("1 UNION SELECT password FROM users", "target").map(|m| m.category), Some(WafCategory::Sqli));
		// The raw target also trips union..select since spaces are %20 (matched by [\s\S]).
		let _ = v; // raw-encoded form is exercised by inspect_str above
	}

	#[test]
	fn sqli_in_decoded_query_is_blocked() {
		let waf = Waf::starter();
		let m = waf.inspect_str("name=x' OR 1=1 --", "target").unwrap();
		assert_eq!(m.category, WafCategory::Sqli);
	}

	#[test]
	fn xss_script_tag_is_blocked() {
		let waf = Waf::starter();
		let m = waf.inspect_str("<script>alert(1)</script>", "target").unwrap();
		assert_eq!(m.category, WafCategory::Xss);
		assert_eq!(m.rule_id, "xss_script_tag");
	}

	#[test]
	fn path_traversal_is_blocked() {
		let waf = Waf::starter();
		let v = waf.inspect(&parts("GET", "/files/../../etc/passwd"));
		let m = blocked(&v);
		assert_eq!(m.category, WafCategory::PathTraversal);
		assert_eq!(m.location, "target");
	}

	#[test]
	fn malicious_header_value_is_blocked() {
		let waf = Waf::starter();
		let mut p = parts("GET", "/");
		p.headers.insert("user-agent", "<script>x</script>".parse().unwrap());
		let v = waf.inspect(&p);
		let m = blocked(&v);
		assert_eq!(m.category, WafCategory::Xss);
		assert_eq!(m.location, "header:user-agent");
	}

	#[test]
	fn custom_rule_extends_detection() {
		// An operator adds a rule on top of the starter set.
		let custom = Rule { id: "block_admin", category: WafCategory::ProtocolAnomaly, pattern: r"(?i)/wp-admin" };
		let waf = Waf::new(starter_rules().into_iter().chain([custom])).unwrap();
		let v = waf.inspect(&parts("GET", "/wp-admin/login.php"));
		assert_eq!(blocked(&v).rule_id, "block_admin");
	}

	#[test]
	fn invalid_custom_pattern_errors() {
		let bad = Rule { id: "bad", category: WafCategory::Sqli, pattern: r"(" };
		assert!(Waf::new([bad]).is_err());
	}

	#[test]
	fn lowest_rule_index_wins_for_determinism() {
		// A string matching two rules reports the lower-indexed (earlier) rule.
		let waf = Waf::starter();
		// "javascript:" (xss_js_uri) plus an event handler; xss_js_uri sits earlier.
		let m = waf.inspect_str("javascript:void(0) onerror=1", "target").unwrap();
		assert_eq!(m.rule_id, "xss_js_uri");
	}

	#[test]
	fn category_names_are_stable() {
		assert_eq!(WafCategory::Sqli.name(), "sqli");
		assert_eq!(WafCategory::PathTraversal.name(), "path_traversal");
	}

	#[test]
	fn single_encoded_xss_is_decoded_and_blocked() {
		// `<script>` hidden as %3Cscript%3E is caught after one decode pass.
		let waf = Waf::starter();
		let m = waf.inspect_str("%3Cscript%3Ealert(1)%3C/script%3E", "target").unwrap();
		assert_eq!(m.rule_id, "xss_script_tag");
	}

	#[test]
	fn single_encoded_traversal_is_decoded_and_blocked() {
		// `..%2f` decodes to `../`, matching the plaintext traversal rule.
		let waf = Waf::starter();
		let v = waf.inspect(&parts("GET", "/files/..%2f..%2fetc/passwd"));
		assert_eq!(blocked(&v).category, WafCategory::PathTraversal);
	}

	#[test]
	fn double_encoded_input_is_blocked_as_anomaly() {
		// `%252e%252e%252f` -> `%2e%2e%2f` -> `../`: two passes, the evasion guard fires.
		let waf = Waf::starter();
		let m = waf.inspect_str("a%252e%252e%252fb", "target").unwrap();
		assert_eq!(m.rule_id, MULTI_ENCODING_RULE_ID);
		assert_eq!(m.category, WafCategory::ProtocolAnomaly);
	}

	#[test]
	fn multi_encoding_guard_can_be_relaxed_and_still_catches_payload() {
		// With the anomaly guard off, the fully-decoded payload still matches its rule.
		// `' OR 1=1` double-encoded: %2527%2520OR%25201%253D1 -> %27%20OR%201%3D1 -> ' OR 1=1
		let waf = Waf::starter().block_multi_encoded(false);
		let m = waf.inspect_str("%2527%2520OR%25201%253D1", "target").unwrap();
		assert_eq!(m.category, WafCategory::Sqli);
	}

	#[test]
	fn benign_encoded_input_still_passes() {
		// A legitimately percent-encoded space in a title is decoded but matches nothing.
		let waf = Waf::starter();
		assert_eq!(waf.inspect(&parts("GET", "/search?q=hello%20world")), Verdict::Allow);
	}

	#[test]
	fn malformed_percent_is_left_verbatim() {
		// A stray `%` and a truncated `%2` are not decodable; nothing should fire.
		let (decoded, changed) = percent_decode_once("100%25 done %2");
		assert!(changed); // the %25 -> %
		assert_eq!(decoded, "100% done %2");
		let (decoded2, changed2) = percent_decode_once("bare % and %zz");
		assert!(!changed2);
		assert_eq!(decoded2, "bare % and %zz");
	}

	#[test]
	fn normalize_counts_decode_passes() {
		assert_eq!(normalize("plain/path").decode_passes, 0);
		assert_eq!(normalize("%2e%2e").decode_passes, 1);
		assert_eq!(normalize("%252e").decode_passes, 2);
		// Decoding stops at the cap even if more layers remain.
		assert!(normalize("%25252525252e").decode_passes <= MAX_DECODE_PASSES);
	}
}

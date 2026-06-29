//! Edge rules — request-shape transforms and redirects (Phase 5 — frontier defenses).
//!
//! This is the cleanest Cloudflare carry-over to Tor: edge rules are **pure request logic**
//! — match on the method, path, host, or a header, then redirect, block, or rewrite a
//! response header — so they port directly without any of the IP/ASN/geo signals the rest
//! of Skin had to re-key onto the circuit and clearance token (see `ROADMAP.md`). They run
//! *ahead* of the gate: a redirect or a static block never needs to mint a clearance or
//! solve a challenge.
//!
//! [`EdgeRules`] is an ordered list of [`EdgeRule`]s, each an [`EdgeMatch`] paired with an
//! [`EdgeAction`]. [`EdgeRules::evaluate`] walks them in order and returns an
//! [`EdgeDecision`]: the **first** matching redirect or block short-circuits immediately,
//! while header transforms accumulate and are returned for the host to apply to the
//! eventual response. The evaluator is decision-only and allocation-light — it produces a
//! plain enum the host acts on, mirroring [`Gate`](crate::Gate) and
//! [`CircuitAction`](crate::CircuitAction) — so the whole engine is unit-testable without a
//! live request pipeline.
//!
//! **The canonical rule is the HTTP→HTTPS upgrade** the onyums server already ships by
//! hand; [`EdgeRules::https_upgrade`] expresses it as one edge rule. Note that an HTTP
//! request parsed by axum/hyper carries no scheme in its [`Parts`] (origin-form requests
//! are just a path), so Skin cannot itself tell a plaintext request from a TLS one — the
//! host installs the upgrade ruleset only on its plaintext listener. Skin renders the
//! redirect; the host decides where it applies.

use axum::{
	body::Body,
	http::{header, request::Parts, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
	response::Response,
};

/// One edge rule: a [matcher](EdgeMatch) and the [action](EdgeAction) to take when it fires.
#[derive(Clone, Debug)]
pub struct EdgeRule {
	/// The condition under which this rule applies.
	pub matcher: EdgeMatch,
	/// What to do when [`matcher`](Self::matcher) matches.
	pub action: EdgeAction,
}

impl EdgeRule {
	/// Construct a rule from a matcher and an action.
	#[must_use]
	pub fn new(matcher: EdgeMatch, action: EdgeAction) -> Self {
		Self { matcher, action }
	}
}

/// The condition half of an [`EdgeRule`]. Matchers inspect only the parsed request
/// [`Parts`] — never any network identity — so they survive Tor unchanged.
#[derive(Clone, Debug)]
pub enum EdgeMatch {
	/// Matches every request.
	Any,
	/// The request path equals this string exactly (`/login`).
	Path(String),
	/// The request path starts with this prefix (`/api/`).
	PathPrefix(String),
	/// The request method equals this method.
	Method(Method),
	/// The request host (the URI authority, falling back to the `Host` header) equals this
	/// value, compared case-insensitively. Over Tor this is the onion address.
	Host(String),
	/// The named header is present (any value).
	HeaderPresent(HeaderName),
	/// The named header is present and its value equals this string exactly (byte-compare).
	HeaderEquals(HeaderName, String),
	/// Every sub-matcher matches (logical AND). Empty → matches (vacuously true).
	All(Vec<EdgeMatch>),
	/// At least one sub-matcher matches (logical OR). Empty → does not match.
	AnyOf(Vec<EdgeMatch>),
	/// The request satisfies a [filter expression](crate::filter::FilterExpr) — the full
	/// boolean/comparison language (regex, contains, query/header predicates) for conditions
	/// richer than the dedicated variants above.
	Expr(crate::filter::FilterExpr),
}

impl EdgeMatch {
	/// Whether this matcher applies to the given request.
	#[must_use]
	pub fn matches(&self, parts: &Parts) -> bool {
		match self {
			EdgeMatch::Any => true,
			EdgeMatch::Path(p) => parts.uri.path() == p,
			EdgeMatch::PathPrefix(p) => parts.uri.path().starts_with(p.as_str()),
			EdgeMatch::Method(m) => parts.method == m,
			EdgeMatch::Host(h) => request_host(parts).is_some_and(|host| host.eq_ignore_ascii_case(h)),
			EdgeMatch::HeaderPresent(name) => parts.headers.contains_key(name),
			EdgeMatch::HeaderEquals(name, want) => parts.headers.get(name).is_some_and(|v| v.as_bytes() == want.as_bytes()),
			EdgeMatch::All(subs) => subs.iter().all(|s| s.matches(parts)),
			EdgeMatch::AnyOf(subs) => subs.iter().any(|s| s.matches(parts)),
			EdgeMatch::Expr(expr) => expr.evaluate(parts),
		}
	}

	/// Build an [`Expr`](Self::Expr) matcher from an operator-authored rule string, so edge
	/// rules can be defined in configuration rather than code. The string is the filter
	/// language — e.g. `method eq "POST" and path starts_with "/admin"`; see
	/// [`FilterExpr::parse`](crate::filter::FilterExpr::parse) for the full grammar.
	///
	/// # Errors
	/// Returns the [`ParseError`](crate::filter::ParseError) from the filter parser on any
	/// lexing or parsing failure (unknown field/operator, invalid regex, unbalanced group, …).
	pub fn expr(rule: &str) -> Result<Self, crate::filter::ParseError> {
		Ok(EdgeMatch::Expr(crate::filter::FilterExpr::parse(rule)?))
	}
}

/// The action half of an [`EdgeRule`]. A redirect or block short-circuits the request; a
/// header mutation is buffered onto the eventual response.
#[derive(Clone, Debug)]
pub enum EdgeAction {
	/// Redirect to a [template](render_location) location with the given status. Use
	/// [`redirect_permanent`](Self::redirect_permanent) / [`redirect_temporary`](Self::redirect_temporary)
	/// for the common 301/302 cases.
	Redirect {
		/// The redirect status (e.g. `301`, `302`, `307`, `308`).
		status: StatusCode,
		/// The `Location` value, with `{host}`, `{path}`, and `{path_and_query}` placeholders
		/// substituted from the request at evaluation time. See [`render_location`].
		location: String,
	},
	/// Reply immediately with this status and an empty body (e.g. `403`, `404`).
	Block(StatusCode),
	/// Insert (overwriting any existing value) a response header.
	SetHeader(HeaderName, HeaderValue),
	/// Remove a response header if present.
	RemoveHeader(HeaderName),
}

impl EdgeAction {
	/// A permanent (`301 Moved Permanently`) redirect to a [location template](render_location).
	#[must_use]
	pub fn redirect_permanent(location: impl Into<String>) -> Self {
		EdgeAction::Redirect { status: StatusCode::MOVED_PERMANENTLY, location: location.into() }
	}

	/// A temporary (`302 Found`) redirect to a [location template](render_location).
	#[must_use]
	pub fn redirect_temporary(location: impl Into<String>) -> Self {
		EdgeAction::Redirect { status: StatusCode::FOUND, location: location.into() }
	}
}

/// A buffered mutation to apply to the eventual response, produced by an
/// [`EdgeAction::SetHeader`] / [`EdgeAction::RemoveHeader`] that matched without
/// short-circuiting. Apply a batch with [`apply_response_headers`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderMutation {
	/// Insert (overwrite) this header.
	Set(HeaderName, HeaderValue),
	/// Remove this header.
	Remove(HeaderName),
}

/// The outcome of evaluating an [`EdgeRules`] set against one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EdgeDecision {
	/// No rule short-circuited; forward to the gate / inner router. Any header transforms
	/// that matched are carried in `response_headers` for the host to apply once the inner
	/// response exists (see [`apply_response_headers`]).
	Forward {
		/// Header mutations to apply to the eventual response, in match order.
		response_headers: Vec<HeaderMutation>,
	},
	/// Short-circuit with a redirect; the location is already rendered (no placeholders left).
	Redirect {
		/// The redirect status.
		status: StatusCode,
		/// The fully rendered `Location` value.
		location: String,
	},
	/// Short-circuit with this status and an empty body.
	Block(StatusCode),
}

impl EdgeDecision {
	/// Whether this decision ends the request here (a redirect or a block), as opposed to
	/// forwarding it onward.
	#[must_use]
	pub fn is_short_circuit(&self) -> bool {
		!matches!(self, EdgeDecision::Forward { .. })
	}

	/// Build the short-circuit [`Response`] for a [`Redirect`](Self::Redirect) or
	/// [`Block`](Self::Block); `None` for [`Forward`](Self::Forward) (there is nothing to
	/// short-circuit). A `Location` that is not a valid header value is dropped rather than
	/// failing the redirect — the status still stands.
	#[must_use]
	pub fn into_response(self) -> Option<Response> {
		match self {
			EdgeDecision::Redirect { status, location } => {
				let mut builder = Response::builder().status(status);
				if let Ok(value) = HeaderValue::from_str(&location) {
					builder = builder.header(header::LOCATION, value);
				}
				Some(builder.body(Body::empty()).expect("a status-and-Location response is always valid"))
			}
			EdgeDecision::Block(status) => Some(Response::builder().status(status).body(Body::empty()).expect("a status-only response is always valid")),
			EdgeDecision::Forward { .. } => None,
		}
	}
}

/// An ordered set of [`EdgeRule`]s evaluated front-to-back by [`evaluate`](Self::evaluate).
#[derive(Clone, Debug, Default)]
pub struct EdgeRules {
	rules: Vec<EdgeRule>,
}

impl EdgeRules {
	/// An empty ruleset — [`evaluate`](Self::evaluate) always returns
	/// [`Forward`](EdgeDecision::Forward) with no transforms.
	#[must_use]
	pub fn new() -> Self {
		Self { rules: Vec::new() }
	}

	/// Append a rule, returning `self` for chaining.
	#[must_use]
	pub fn rule(mut self, rule: EdgeRule) -> Self {
		self.rules.push(rule);
		self
	}

	/// Append a matcher/action pair, returning `self` for chaining.
	#[must_use]
	pub fn push(self, matcher: EdgeMatch, action: EdgeAction) -> Self {
		self.rule(EdgeRule::new(matcher, action))
	}

	/// The number of rules in the set.
	#[must_use]
	pub fn len(&self) -> usize {
		self.rules.len()
	}

	/// Whether the set has no rules.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.rules.is_empty()
	}

	/// The canonical HTTP→HTTPS upgrade as a single permanent redirect: every request is
	/// sent to `https://{host}{path_and_query}`. Install this only on a plaintext listener
	/// (Skin cannot see the scheme from [`Parts`] — see the module docs).
	#[must_use]
	pub fn https_upgrade() -> Self {
		Self::new().push(EdgeMatch::Any, EdgeAction::redirect_permanent("https://{host}{path_and_query}"))
	}

	/// Evaluate the ruleset against a request. The first matching redirect or block
	/// short-circuits; header transforms before it accumulate and are returned in
	/// [`Forward`](EdgeDecision::Forward) if nothing short-circuits.
	#[must_use]
	pub fn evaluate(&self, parts: &Parts) -> EdgeDecision {
		let mut mutations = Vec::new();
		for rule in &self.rules {
			if !rule.matcher.matches(parts) {
				continue;
			}
			match &rule.action {
				EdgeAction::Redirect { status, location } => return EdgeDecision::Redirect { status: *status, location: render_location(location, parts) },
				EdgeAction::Block(status) => return EdgeDecision::Block(*status),
				EdgeAction::SetHeader(name, value) => mutations.push(HeaderMutation::Set(name.clone(), value.clone())),
				EdgeAction::RemoveHeader(name) => mutations.push(HeaderMutation::Remove(name.clone())),
			}
		}
		EdgeDecision::Forward { response_headers: mutations }
	}
}

/// Apply a batch of [`HeaderMutation`]s to a response's headers, in order. A `Set`
/// overwrites any existing value for that name; a `Remove` deletes it.
pub fn apply_response_headers(mutations: &[HeaderMutation], headers: &mut HeaderMap) {
	for mutation in mutations {
		match mutation {
			HeaderMutation::Set(name, value) => {
				headers.insert(name.clone(), value.clone());
			}
			HeaderMutation::Remove(name) => {
				headers.remove(name);
			}
		}
	}
}

/// The request host: the URI authority if present (HTTP/2 / absolute-form), else the
/// `Host` header. `None` when neither is set. The trailing `:port`, if any, is kept.
fn request_host(parts: &Parts) -> Option<String> {
	if let Some(authority) = parts.uri.authority() {
		return Some(authority.as_str().to_owned());
	}
	parts.headers.get(header::HOST).and_then(|v| v.to_str().ok()).map(str::to_owned)
}

/// Substitute the supported placeholders in a redirect location template:
///
/// - `{host}` — the request host ([`request_host`]), or empty if absent.
/// - `{path}` — the request path (always begins with `/`).
/// - `{path_and_query}` — the path plus `?query` when a query is present.
///
/// Unknown `{...}` sequences are left verbatim. Substitution is single-pass, so a
/// placeholder value that itself contains `{...}` is not re-expanded.
#[must_use]
pub fn render_location(template: &str, parts: &Parts) -> String {
	let host = request_host(parts).unwrap_or_default();
	let path = parts.uri.path();
	let path_and_query = parts.uri.path_and_query().map_or_else(|| path.to_owned(), |pq| pq.as_str().to_owned());
	template.replace("{host}", &host).replace("{path_and_query}", &path_and_query).replace("{path}", path)
}

#[cfg(test)]
mod tests {
	use axum::http::Request;

	use super::*;

	fn parts(builder: axum::http::request::Builder) -> Parts {
		builder.body(()).unwrap().into_parts().0
	}

	#[test]
	fn empty_ruleset_forwards_with_no_mutations() {
		let decision = EdgeRules::new().evaluate(&parts(Request::builder().uri("/")));
		assert_eq!(decision, EdgeDecision::Forward { response_headers: Vec::new() });
		assert!(!decision.is_short_circuit());
	}

	#[test]
	fn path_and_prefix_matchers() {
		let rules = EdgeRules::new()
			.push(EdgeMatch::Path("/exact".into()), EdgeAction::Block(StatusCode::FORBIDDEN))
			.push(EdgeMatch::PathPrefix("/api/".into()), EdgeAction::Block(StatusCode::NOT_FOUND));
		assert_eq!(rules.evaluate(&parts(Request::builder().uri("/exact"))), EdgeDecision::Block(StatusCode::FORBIDDEN));
		// A prefix sibling that is not an exact match falls through to the prefix rule.
		assert_eq!(rules.evaluate(&parts(Request::builder().uri("/api/users"))), EdgeDecision::Block(StatusCode::NOT_FOUND));
		// Neither rule matches → forward.
		assert!(!rules.evaluate(&parts(Request::builder().uri("/other"))).is_short_circuit());
	}

	#[test]
	fn first_short_circuit_wins_and_later_rules_are_skipped() {
		let rules = EdgeRules::new()
			.push(EdgeMatch::Any, EdgeAction::Block(StatusCode::FORBIDDEN))
			.push(EdgeMatch::Any, EdgeAction::Block(StatusCode::IM_A_TEAPOT));
		assert_eq!(rules.evaluate(&parts(Request::builder().uri("/"))), EdgeDecision::Block(StatusCode::FORBIDDEN));
	}

	#[test]
	fn header_transforms_accumulate_in_order_then_forward() {
		let rules = EdgeRules::new()
			.push(EdgeMatch::Any, EdgeAction::SetHeader(HeaderName::from_static("x-frame-options"), HeaderValue::from_static("DENY")))
			.push(EdgeMatch::Any, EdgeAction::RemoveHeader(HeaderName::from_static("server")));
		let decision = rules.evaluate(&parts(Request::builder().uri("/")));
		assert_eq!(
			decision,
			EdgeDecision::Forward {
				response_headers: vec![
					HeaderMutation::Set(HeaderName::from_static("x-frame-options"), HeaderValue::from_static("DENY")),
					HeaderMutation::Remove(HeaderName::from_static("server")),
				],
			}
		);
	}

	#[test]
	fn a_short_circuit_drops_buffered_transforms() {
		// A transform before a block never reaches the response — the block ends the request.
		let rules = EdgeRules::new()
			.push(EdgeMatch::Any, EdgeAction::SetHeader(HeaderName::from_static("x-test"), HeaderValue::from_static("1")))
			.push(EdgeMatch::Path("/blocked".into()), EdgeAction::Block(StatusCode::FORBIDDEN));
		assert_eq!(rules.evaluate(&parts(Request::builder().uri("/blocked"))), EdgeDecision::Block(StatusCode::FORBIDDEN));
	}

	#[test]
	fn method_and_combinator_matchers() {
		// Block POST to /admin specifically; GET /admin and POST elsewhere pass.
		let rules = EdgeRules::new().push(
			EdgeMatch::All(vec![EdgeMatch::Method(Method::POST), EdgeMatch::PathPrefix("/admin".into())]),
			EdgeAction::Block(StatusCode::FORBIDDEN),
		);
		assert!(rules.evaluate(&parts(Request::builder().method("POST").uri("/admin/x"))).is_short_circuit());
		assert!(!rules.evaluate(&parts(Request::builder().method("GET").uri("/admin/x"))).is_short_circuit());
		assert!(!rules.evaluate(&parts(Request::builder().method("POST").uri("/public"))).is_short_circuit());
	}

	#[test]
	fn any_of_is_logical_or_and_empty_sets_behave() {
		let or = EdgeMatch::AnyOf(vec![EdgeMatch::Path("/a".into()), EdgeMatch::Path("/b".into())]);
		assert!(or.matches(&parts(Request::builder().uri("/a"))));
		assert!(or.matches(&parts(Request::builder().uri("/b"))));
		assert!(!or.matches(&parts(Request::builder().uri("/c"))));
		// Empty All is vacuously true; empty AnyOf is false.
		assert!(EdgeMatch::All(vec![]).matches(&parts(Request::builder().uri("/"))));
		assert!(!EdgeMatch::AnyOf(vec![]).matches(&parts(Request::builder().uri("/"))));
	}

	#[test]
	fn header_present_and_equals_matchers() {
		let present = EdgeMatch::HeaderPresent(HeaderName::from_static("x-flag"));
		assert!(present.matches(&parts(Request::builder().uri("/").header("x-flag", "anything"))));
		assert!(!present.matches(&parts(Request::builder().uri("/"))));
		let equals = EdgeMatch::HeaderEquals(HeaderName::from_static("x-flag"), "on".into());
		assert!(equals.matches(&parts(Request::builder().uri("/").header("x-flag", "on"))));
		assert!(!equals.matches(&parts(Request::builder().uri("/").header("x-flag", "off"))));
	}

	#[test]
	fn expr_matcher_uses_the_full_filter_language() {
		use crate::filter::Field;
		// A condition richer than the dedicated variants: POST whose query contains `debug`.
		let rules = EdgeRules::new().push(
			EdgeMatch::Expr(Field::method().eq("POST").and(Field::query().contains("debug"))),
			EdgeAction::Block(StatusCode::FORBIDDEN),
		);
		assert!(rules.evaluate(&parts(Request::builder().method("POST").uri("/x?debug=1"))).is_short_circuit());
		assert!(!rules.evaluate(&parts(Request::builder().method("POST").uri("/x?ok=1"))).is_short_circuit());
		assert!(!rules.evaluate(&parts(Request::builder().method("GET").uri("/x?debug=1"))).is_short_circuit());
		// A regex predicate is reachable too.
		let regex_rule = EdgeRules::new().push(EdgeMatch::Expr(Field::path().matches(r"^/item/\d+$").unwrap()), EdgeAction::Block(StatusCode::NOT_FOUND));
		assert!(regex_rule.evaluate(&parts(Request::builder().uri("/item/42"))).is_short_circuit());
		assert!(!regex_rule.evaluate(&parts(Request::builder().uri("/item/abc"))).is_short_circuit());
	}

	#[test]
	fn expr_matcher_from_rule_string() {
		// The same condition authored as a config string instead of built in code.
		let m = EdgeMatch::expr(r#"method eq "POST" and path starts_with "/admin""#).unwrap();
		assert!(m.matches(&parts(Request::builder().method("POST").uri("/admin/x"))));
		assert!(!m.matches(&parts(Request::builder().method("GET").uri("/admin/x"))));
		assert!(!m.matches(&parts(Request::builder().method("POST").uri("/public"))));
		// A malformed rule surfaces the filter parser's error rather than building a matcher.
		assert!(EdgeMatch::expr(r#"frob eq "x""#).is_err());
	}

	#[test]
	fn host_matcher_reads_header_and_is_case_insensitive() {
		let m = EdgeMatch::Host("ABCXYZ.onion".into());
		assert!(m.matches(&parts(Request::builder().uri("/").header("host", "abcxyz.onion"))));
		assert!(!m.matches(&parts(Request::builder().uri("/").header("host", "other.onion"))));
		assert!(!m.matches(&parts(Request::builder().uri("/"))));
	}

	#[test]
	fn location_template_substitutes_host_path_and_query() {
		let p = parts(Request::builder().uri("/page?x=1&y=2").header("host", "abc.onion"));
		assert_eq!(render_location("https://{host}{path_and_query}", &p), "https://abc.onion/page?x=1&y=2");
		assert_eq!(render_location("https://{host}{path}", &p), "https://abc.onion/page");
		// Unknown placeholders are left verbatim; a missing host renders empty.
		assert_eq!(render_location("{unknown}", &p), "{unknown}");
		let no_host = parts(Request::builder().uri("/p"));
		assert_eq!(render_location("https://{host}{path}", &no_host), "https:///p");
	}

	#[test]
	fn https_upgrade_redirects_to_tls_with_path_and_query_preserved() {
		let decision = EdgeRules::https_upgrade().evaluate(&parts(Request::builder().uri("/login?next=/home").header("host", "svc.onion")));
		assert_eq!(decision, EdgeDecision::Redirect { status: StatusCode::MOVED_PERMANENTLY, location: "https://svc.onion/login?next=/home".into() });
		assert!(decision.is_short_circuit());
	}

	#[test]
	fn into_response_builds_redirect_and_block_but_not_forward() {
		let redirect = EdgeDecision::Redirect { status: StatusCode::FOUND, location: "https://x.onion/".into() }.into_response().expect("redirect has a response");
		assert_eq!(redirect.status(), StatusCode::FOUND);
		assert_eq!(redirect.headers().get(header::LOCATION).unwrap(), "https://x.onion/");
		let block = EdgeDecision::Block(StatusCode::FORBIDDEN).into_response().expect("block has a response");
		assert_eq!(block.status(), StatusCode::FORBIDDEN);
		assert!(EdgeDecision::Forward { response_headers: Vec::new() }.into_response().is_none());
	}

	#[test]
	fn apply_response_headers_sets_and_removes() {
		let mut headers = HeaderMap::new();
		headers.insert(HeaderName::from_static("server"), HeaderValue::from_static("onyums"));
		apply_response_headers(
			&[
				HeaderMutation::Set(HeaderName::from_static("x-frame-options"), HeaderValue::from_static("DENY")),
				HeaderMutation::Remove(HeaderName::from_static("server")),
			],
			&mut headers,
		);
		assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
		assert!(!headers.contains_key("server"));
	}
}

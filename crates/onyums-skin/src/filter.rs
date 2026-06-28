//! A minimal pure-Rust filter-expression front-end (Phase 3 WAF / Phase 5 edge rules).
//!
//! The WAF roadmap planned `wirefilter` for the rule/expression language, but the only
//! crates.io-published engine (`wirefilter-engine` 0.6.1) drags the **unmaintained `failure`**
//! crate (RUSTSEC-2020-0036) and several superseded deps into a *security* layer — see the
//! `wirefilter` blocker note in `ROADMAP.md`. This module is **resolution path (c)**: a small
//! in-house expression front-end. Signature matching is already covered by the WAF's
//! `regex`/`aho-corasick` engine; the only thing wirefilter added is the boolean/comparison
//! *expression* layer, and that is a typed AST plus a recursive evaluator — no parser
//! dependency, no `failure`, no advisory exception.
//!
//! A [`FilterExpr`] is a tree of field predicates ([`Field`] op [`StrOp`]) combined with
//! `And`/`Or`/`Not`. Fields are restricted to the request dimensions that survive Tor (method,
//! path, query, a named header) — never an IP — so an expression ports unchanged, and the
//! whole engine evaluates against a parsed [`Parts`] with no live pipeline, fully offline.
//! It can express an operator-tunable WAF rule condition or an edge-rule matcher; this slice
//! is the AST and evaluator, the string-syntax parser is a later slice.
//!
//! **Absent-field semantics.** A predicate over a field that is not present (a missing query
//! or header) is **false** for every operator except [`StrOp::Exists`] — the WAF-safe choice
//! of never matching on data that is not there. To match "header absent or not `x`", combine
//! `Not(exists)` with the comparison via [`FilterExpr::or`].

use axum::http::{request::Parts, HeaderName};
use regex::Regex;

/// A request field an expression can test. Limited to the dimensions that survive Tor.
#[derive(Clone, Debug)]
pub enum Field {
	/// The request method (`GET`, `POST`, …). Always present.
	Method,
	/// The request path (always begins with `/`). Always present.
	Path,
	/// The raw query string (without the leading `?`). Absent when there is no query.
	Query,
	/// The named request header's value (UTF-8 lossy-decodable). Absent when not present.
	Header(HeaderName),
}

impl Field {
	/// The `Method` field.
	#[must_use]
	pub fn method() -> Self {
		Field::Method
	}

	/// The `Path` field.
	#[must_use]
	pub fn path() -> Self {
		Field::Path
	}

	/// The `Query` field.
	#[must_use]
	pub fn query() -> Self {
		Field::Query
	}

	/// The named header field.
	#[must_use]
	pub fn header(name: HeaderName) -> Self {
		Field::Header(name)
	}

	/// Resolve this field's value from a request, or `None` when the field is absent.
	#[must_use]
	pub fn resolve(&self, parts: &Parts) -> Option<String> {
		match self {
			Field::Method => Some(parts.method.as_str().to_owned()),
			Field::Path => Some(parts.uri.path().to_owned()),
			Field::Query => parts.uri.query().map(str::to_owned),
			Field::Header(name) => parts.headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned),
		}
	}

	/// `field == value`.
	#[must_use]
	pub fn eq(self, value: impl Into<String>) -> FilterExpr {
		self.predicate(StrOp::Eq(value.into()))
	}

	/// `field != value` (false when the field is absent — see the module docs).
	#[must_use]
	pub fn not_eq(self, value: impl Into<String>) -> FilterExpr {
		self.predicate(StrOp::NotEq(value.into()))
	}

	/// `field contains value` (substring).
	#[must_use]
	pub fn contains(self, value: impl Into<String>) -> FilterExpr {
		self.predicate(StrOp::Contains(value.into()))
	}

	/// `field starts with value`.
	#[must_use]
	pub fn starts_with(self, value: impl Into<String>) -> FilterExpr {
		self.predicate(StrOp::StartsWith(value.into()))
	}

	/// `field ends with value`.
	#[must_use]
	pub fn ends_with(self, value: impl Into<String>) -> FilterExpr {
		self.predicate(StrOp::EndsWith(value.into()))
	}

	/// `field matches regex` — compiles `pattern`, erroring like any other `regex` build.
	pub fn matches(self, pattern: &str) -> Result<FilterExpr, regex::Error> {
		Ok(self.predicate(StrOp::Matches(Regex::new(pattern)?)))
	}

	/// `field is present`.
	#[must_use]
	pub fn exists(self) -> FilterExpr {
		self.predicate(StrOp::Exists)
	}

	fn predicate(self, op: StrOp) -> FilterExpr {
		FilterExpr::Predicate { field: self, op }
	}
}

/// A string comparison applied to a resolved [`Field`] value.
#[derive(Clone, Debug)]
pub enum StrOp {
	/// Equals the given string exactly.
	Eq(String),
	/// Does not equal the given string.
	NotEq(String),
	/// Contains the given substring.
	Contains(String),
	/// Starts with the given prefix.
	StartsWith(String),
	/// Ends with the given suffix.
	EndsWith(String),
	/// Matches the given regular expression anywhere in the value.
	Matches(Regex),
	/// The field is present (the only operator that is true for an absent field, inverted).
	Exists,
}

impl StrOp {
	/// Apply this operator to a resolved field value. An absent value (`None`) is `false` for
	/// every operator except [`Exists`](Self::Exists).
	#[must_use]
	pub fn test(&self, value: Option<&str>) -> bool {
		if let StrOp::Exists = self {
			return value.is_some();
		}
		let Some(value) = value else {
			return false;
		};
		match self {
			StrOp::Eq(s) => value == s,
			StrOp::NotEq(s) => value != s,
			StrOp::Contains(s) => value.contains(s.as_str()),
			StrOp::StartsWith(s) => value.starts_with(s.as_str()),
			StrOp::EndsWith(s) => value.ends_with(s.as_str()),
			StrOp::Matches(re) => re.is_match(value),
			StrOp::Exists => true, // handled above; unreachable here
		}
	}
}

/// A boolean filter expression over request fields. Build leaves with the [`Field`] predicate
/// helpers (e.g. `Field::path().starts_with("/admin")`) and combine with [`and`](Self::and) /
/// [`or`](Self::or) / `!` (the [`Not`](std::ops::Not) impl) or the [`all`] / [`any`] constructors.
#[derive(Clone, Debug)]
pub enum FilterExpr {
	/// A single `field op value` test.
	Predicate {
		/// The field under test.
		field: Field,
		/// The comparison applied to it.
		op: StrOp,
	},
	/// Every sub-expression is true (logical AND). Empty → true (vacuous).
	And(Vec<FilterExpr>),
	/// At least one sub-expression is true (logical OR). Empty → false.
	Or(Vec<FilterExpr>),
	/// The sub-expression is false (logical NOT).
	Not(Box<FilterExpr>),
	/// The constant `true`.
	Always,
	/// The constant `false`.
	Never,
}

impl FilterExpr {
	/// Evaluate the expression against a parsed request.
	#[must_use]
	pub fn evaluate(&self, parts: &Parts) -> bool {
		match self {
			FilterExpr::Predicate { field, op } => op.test(field.resolve(parts).as_deref()),
			FilterExpr::And(subs) => subs.iter().all(|s| s.evaluate(parts)),
			FilterExpr::Or(subs) => subs.iter().any(|s| s.evaluate(parts)),
			FilterExpr::Not(inner) => !inner.evaluate(parts),
			FilterExpr::Always => true,
			FilterExpr::Never => false,
		}
	}

	/// `self AND other`, flattening into an existing top-level `And` to keep the tree shallow.
	#[must_use]
	pub fn and(self, other: FilterExpr) -> FilterExpr {
		match self {
			FilterExpr::And(mut subs) => {
				subs.push(other);
				FilterExpr::And(subs)
			}
			first => FilterExpr::And(vec![first, other]),
		}
	}

	/// `self OR other`, flattening into an existing top-level `Or` to keep the tree shallow.
	#[must_use]
	pub fn or(self, other: FilterExpr) -> FilterExpr {
		match self {
			FilterExpr::Or(mut subs) => {
				subs.push(other);
				FilterExpr::Or(subs)
			}
			first => FilterExpr::Or(vec![first, other]),
		}
	}
}

impl std::ops::Not for FilterExpr {
	type Output = FilterExpr;

	/// `NOT self` — also reachable as the prefix `!expr`.
	fn not(self) -> FilterExpr {
		FilterExpr::Not(Box::new(self))
	}
}

/// Conjunction of several expressions (logical AND); empty is vacuously true.
#[must_use]
pub fn all(exprs: Vec<FilterExpr>) -> FilterExpr {
	FilterExpr::And(exprs)
}

/// Disjunction of several expressions (logical OR); empty is false.
#[must_use]
pub fn any(exprs: Vec<FilterExpr>) -> FilterExpr {
	FilterExpr::Or(exprs)
}

#[cfg(test)]
mod tests {
	use axum::http::Request;

	use super::*;

	fn parts(builder: axum::http::request::Builder) -> Parts {
		builder.body(()).unwrap().into_parts().0
	}

	#[test]
	fn field_resolution() {
		let p = parts(Request::builder().method("POST").uri("/a/b?x=1").header("user-agent", "curl"));
		assert_eq!(Field::method().resolve(&p).as_deref(), Some("POST"));
		assert_eq!(Field::path().resolve(&p).as_deref(), Some("/a/b"));
		assert_eq!(Field::query().resolve(&p).as_deref(), Some("x=1"));
		assert_eq!(Field::header(HeaderName::from_static("user-agent")).resolve(&p).as_deref(), Some("curl"));
		assert_eq!(Field::header(HeaderName::from_static("x-absent")).resolve(&p), None);
		// No query → absent.
		assert_eq!(Field::query().resolve(&parts(Request::builder().uri("/a"))), None);
	}

	#[test]
	fn string_operators_on_present_values() {
		let p = parts(Request::builder().method("GET").uri("/admin/users"));
		assert!(Field::path().eq("/admin/users").evaluate(&p));
		assert!(!Field::path().eq("/admin").evaluate(&p));
		assert!(Field::path().starts_with("/admin").evaluate(&p));
		assert!(Field::path().ends_with("/users").evaluate(&p));
		assert!(Field::path().contains("min/us").evaluate(&p));
		assert!(Field::method().not_eq("POST").evaluate(&p));
		assert!(!Field::method().not_eq("GET").evaluate(&p));
	}

	#[test]
	fn regex_operator() {
		let p = parts(Request::builder().uri("/item/42"));
		assert!(Field::path().matches(r"^/item/\d+$").unwrap().evaluate(&p));
		assert!(!Field::path().matches(r"^/user/\d+$").unwrap().evaluate(&p));
		assert!(Field::method().matches("(").is_err(), "an invalid pattern surfaces the regex error");
	}

	#[test]
	fn absent_field_is_false_except_exists() {
		let p = parts(Request::builder().uri("/"));
		let header = || Field::header(HeaderName::from_static("x-token"));
		assert!(!header().eq("v").evaluate(&p));
		assert!(!header().not_eq("v").evaluate(&p), "absent is false even for not_eq (WAF-safe)");
		assert!(!header().contains("v").evaluate(&p));
		assert!(!header().exists().evaluate(&p));
		// Present → exists is true.
		let with = parts(Request::builder().uri("/").header("x-token", "abc"));
		assert!(header().exists().evaluate(&with));
	}

	#[test]
	fn and_or_not_combinators() {
		let p = parts(Request::builder().method("POST").uri("/admin/x"));
		let rule = Field::method().eq("POST").and(Field::path().starts_with("/admin"));
		assert!(rule.evaluate(&p));
		// Flip the method requirement → no match.
		assert!(!Field::method().eq("GET").and(Field::path().starts_with("/admin")).evaluate(&p));
		// OR matches either branch.
		assert!(Field::path().eq("/nope").or(Field::method().eq("POST")).evaluate(&p));
		// NOT inverts.
		assert!((!Field::method().eq("GET")).evaluate(&p));
	}

	#[test]
	fn and_or_flatten_to_shallow_trees() {
		let expr = Field::method().eq("GET").and(Field::path().eq("/a")).and(Field::query().exists());
		match &expr {
			FilterExpr::And(subs) => assert_eq!(subs.len(), 3, "chained .and flattens into one And node"),
			other => panic!("expected a flat And, got {other:?}"),
		}
		let expr = Field::path().eq("/a").or(Field::path().eq("/b")).or(Field::path().eq("/c"));
		match &expr {
			FilterExpr::Or(subs) => assert_eq!(subs.len(), 3),
			other => panic!("expected a flat Or, got {other:?}"),
		}
	}

	#[test]
	fn all_any_and_constants() {
		let p = parts(Request::builder().method("GET").uri("/x"));
		assert!(all(vec![Field::method().eq("GET"), Field::path().eq("/x")]).evaluate(&p));
		assert!(!all(vec![Field::method().eq("GET"), Field::path().eq("/y")]).evaluate(&p));
		assert!(any(vec![Field::path().eq("/y"), Field::path().eq("/x")]).evaluate(&p));
		// Empty all is vacuously true; empty any is false; constants are constant.
		assert!(all(vec![]).evaluate(&p));
		assert!(!any(vec![]).evaluate(&p));
		assert!(FilterExpr::Always.evaluate(&p));
		assert!(!FilterExpr::Never.evaluate(&p));
	}

	#[test]
	fn header_absent_or_not_equal_via_combinators() {
		// The documented idiom for "header absent OR not equal to v".
		let token = || Field::header(HeaderName::from_static("x-token"));
		let rule = (!token().exists()).or(token().not_eq("v"));
		assert!(rule.evaluate(&parts(Request::builder().uri("/"))), "absent satisfies the rule");
		assert!(rule.evaluate(&parts(Request::builder().uri("/").header("x-token", "other"))), "different value satisfies it");
		assert!(!rule.evaluate(&parts(Request::builder().uri("/").header("x-token", "v"))), "exactly v does not");
	}
}

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

// ---------------------------------------------------------------------------
// String-syntax front-end: lexer
// ---------------------------------------------------------------------------
//
// The typed AST above is what an operator-authored rule string parses into, so
// WAF/edge-rule conditions can be config-driven rather than code-built. The grammar:
//
//   expr      := or_expr
//   or_expr   := and_expr ( ("or" | "||") and_expr )*
//   and_expr  := not_expr ( ("and" | "&&") not_expr )*
//   not_expr  := ("not" | "!") not_expr | primary
//   primary   := "(" expr ")" | "true" | "false" | predicate
//   predicate := field ( "exists" | binop string )
//   field     := "method" | "path" | "query" | "header" "[" (string | ident) "]"
//   binop     := "eq" | "ne" | "!=" | "contains" | "starts_with" | "ends_with" | "matches" | "~"
//
// This section is the lexer; the recursive-descent parser is a later slice.

/// An error from the filter string parser — a lexing or parsing failure with the byte
/// offset into the input where it was detected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
	/// Byte offset into the input string where the problem was detected.
	pub pos: usize,
	/// Human-readable description of the problem.
	pub message: String,
}

impl ParseError {
	fn new(pos: usize, message: impl Into<String>) -> Self {
		ParseError { pos, message: message.into() }
	}
}

impl std::fmt::Display for ParseError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "filter parse error at byte {}: {}", self.pos, self.message)
	}
}

impl std::error::Error for ParseError {}

/// A lexical token of the filter rule string syntax.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
	/// A bare word: a field name, an operator keyword, a constant, or an unquoted header name.
	Ident(String),
	/// A double-quoted string literal, with escape sequences already decoded.
	Str(String),
	/// `(`
	LParen,
	/// `)`
	RParen,
	/// `[`
	LBracket,
	/// `]`
	RBracket,
	/// `~` — the regex-match operator.
	Tilde,
	/// `!` — prefix logical NOT.
	Bang,
	/// `!=` — the not-equal operator.
	BangEq,
	/// `&&` — logical AND.
	AmpAmp,
	/// `||` — logical OR.
	PipePipe,
}

/// A token paired with the byte offset where it began, for error reporting.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Spanned {
	tok: Token,
	pos: usize,
}

/// True for the first byte of a bare identifier (ASCII letter or `_`).
fn is_ident_start(c: u8) -> bool {
	c.is_ascii_alphabetic() || c == b'_'
}

/// True for a continuation byte of a bare identifier — letters, digits, `_`, `-`, `.`
/// (so header names like `user-agent` and operators like `starts_with` lex as one token).
fn is_ident_continue(c: u8) -> bool {
	c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.')
}

/// Decode a double-quoted string literal beginning at `open` (the opening quote). Returns
/// the decoded contents and the byte offset just past the closing quote. Supports the
/// escapes `\"`, `\\`, `\n`, `\t`, `\r`.
fn lex_string(input: &str, open: usize) -> Result<(String, usize), ParseError> {
	let bytes = input.as_bytes();
	let mut out = String::new();
	let mut i = open + 1; // skip the opening quote
	while i < bytes.len() {
		match bytes[i] {
			b'"' => return Ok((out, i + 1)),
			b'\\' => {
				let esc = bytes.get(i + 1).ok_or_else(|| ParseError::new(i, "trailing backslash in string literal"))?;
				let ch = match esc {
					b'"' => '"',
					b'\\' => '\\',
					b'n' => '\n',
					b't' => '\t',
					b'r' => '\r',
					other => return Err(ParseError::new(i, format!("invalid escape `\\{}`", *other as char))),
				};
				out.push(ch);
				i += 2;
			}
			_ => {
				// Copy one whole UTF-8 char so multibyte content survives intact.
				let ch = input[i..].chars().next().expect("byte index is on a char boundary");
				out.push(ch);
				i += ch.len_utf8();
			}
		}
	}
	Err(ParseError::new(open, "unterminated string literal"))
}

/// Tokenize a filter rule string. Whitespace separates tokens and is otherwise ignored.
fn lex(input: &str) -> Result<Vec<Spanned>, ParseError> {
	let bytes = input.as_bytes();
	let mut tokens = Vec::new();
	let mut i = 0;
	while i < bytes.len() {
		let c = bytes[i];
		match c {
			b' ' | b'\t' | b'\r' | b'\n' => i += 1,
			b'(' => {
				tokens.push(Spanned { tok: Token::LParen, pos: i });
				i += 1;
			}
			b')' => {
				tokens.push(Spanned { tok: Token::RParen, pos: i });
				i += 1;
			}
			b'[' => {
				tokens.push(Spanned { tok: Token::LBracket, pos: i });
				i += 1;
			}
			b']' => {
				tokens.push(Spanned { tok: Token::RBracket, pos: i });
				i += 1;
			}
			b'~' => {
				tokens.push(Spanned { tok: Token::Tilde, pos: i });
				i += 1;
			}
			b'!' => {
				if bytes.get(i + 1) == Some(&b'=') {
					tokens.push(Spanned { tok: Token::BangEq, pos: i });
					i += 2;
				} else {
					tokens.push(Spanned { tok: Token::Bang, pos: i });
					i += 1;
				}
			}
			b'&' => {
				if bytes.get(i + 1) == Some(&b'&') {
					tokens.push(Spanned { tok: Token::AmpAmp, pos: i });
					i += 2;
				} else {
					return Err(ParseError::new(i, "lone `&` (use `&&` for AND)"));
				}
			}
			b'|' => {
				if bytes.get(i + 1) == Some(&b'|') {
					tokens.push(Spanned { tok: Token::PipePipe, pos: i });
					i += 2;
				} else {
					return Err(ParseError::new(i, "lone `|` (use `||` for OR)"));
				}
			}
			b'"' => {
				let (s, next) = lex_string(input, i)?;
				tokens.push(Spanned { tok: Token::Str(s), pos: i });
				i = next;
			}
			_ if is_ident_start(c) => {
				let start = i;
				i += 1;
				while i < bytes.len() && is_ident_continue(bytes[i]) {
					i += 1;
				}
				tokens.push(Spanned { tok: Token::Ident(input[start..i].to_owned()), pos: start });
			}
			_ => {
				let ch = input[i..].chars().next().expect("byte index is on a char boundary");
				return Err(ParseError::new(i, format!("unexpected character `{ch}`")));
			}
		}
	}
	Ok(tokens)
}

#[cfg(test)]
mod lex_tests {
	use super::*;

	fn toks(input: &str) -> Vec<Token> {
		lex(input).unwrap().into_iter().map(|s| s.tok).collect()
	}

	#[test]
	fn idents_and_keywords() {
		assert_eq!(toks("method eq starts_with"), vec![Token::Ident("method".into()), Token::Ident("eq".into()), Token::Ident("starts_with".into())]);
		// `-` and `.` continue an ident, so header names lex as one token.
		assert_eq!(toks("user-agent x.y"), vec![Token::Ident("user-agent".into()), Token::Ident("x.y".into())]);
	}

	#[test]
	fn symbols_and_two_char_operators() {
		assert_eq!(toks("( ) [ ] ~ !"), vec![Token::LParen, Token::RParen, Token::LBracket, Token::RBracket, Token::Tilde, Token::Bang]);
		assert_eq!(toks("a != b"), vec![Token::Ident("a".into()), Token::BangEq, Token::Ident("b".into())]);
		assert_eq!(toks("a && b || c"), vec![Token::Ident("a".into()), Token::AmpAmp, Token::Ident("b".into()), Token::PipePipe, Token::Ident("c".into())]);
		// `!` not followed by `=` is a bare Bang.
		assert_eq!(toks("!a"), vec![Token::Bang, Token::Ident("a".into())]);
	}

	#[test]
	fn string_literals_and_escapes() {
		assert_eq!(toks(r#""hello""#), vec![Token::Str("hello".into())]);
		assert_eq!(toks(r#""a\"b\\c\n""#), vec![Token::Str("a\"b\\c\n".into())]);
		// A quoted string can hold characters that are otherwise operators.
		assert_eq!(toks(r#""/admin && (x)""#), vec![Token::Str("/admin && (x)".into())]);
	}

	#[test]
	fn positions_are_tracked() {
		let spanned = lex("method  eq").unwrap();
		assert_eq!(spanned[0].pos, 0);
		assert_eq!(spanned[1].pos, 8, "leading whitespace is skipped but counted in the offset");
	}

	#[test]
	fn lex_errors() {
		assert_eq!(lex(r#""unterminated"#).unwrap_err().pos, 0);
		assert_eq!(lex(r#""bad\escape""#).unwrap_err().message, "invalid escape `\\e`");
		assert_eq!(lex("a & b").unwrap_err().message, "lone `&` (use `&&` for AND)");
		assert_eq!(lex("a | b").unwrap_err().message, "lone `|` (use `||` for OR)");
		assert_eq!(lex("a @ b").unwrap_err().message, "unexpected character `@`");
		assert_eq!(lex("a @ b").unwrap_err().pos, 2);
	}
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

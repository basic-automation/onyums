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
/// the decoded contents and the byte offset just past the closing quote. The escapes
/// `\"`, `\\`, `\n`, `\t`, `\r` decode to their characters; any **other** `\x` is passed
/// through verbatim (backslash kept) so regex patterns — `\w`, `\d`, `\.` — read naturally
/// inside a `matches`/`~` value without doubling every backslash.
fn lex_string(input: &str, open: usize) -> Result<(String, usize), ParseError> {
	let bytes = input.as_bytes();
	let mut out = String::new();
	let mut i = open + 1; // skip the opening quote
	while i < bytes.len() {
		match bytes[i] {
			b'"' => return Ok((out, i + 1)),
			b'\\' => {
				let esc = *bytes.get(i + 1).ok_or_else(|| ParseError::new(i, "trailing backslash in string literal"))?;
				match esc {
					b'"' => out.push('"'),
					b'\\' => out.push('\\'),
					b'n' => out.push('\n'),
					b't' => out.push('\t'),
					b'r' => out.push('\r'),
					// Unknown escape: keep the backslash and the following char verbatim so
					// regex metacharacters survive. `i + 1` is a char boundary (a recognized
					// escape body is ASCII; here we re-read the raw char to stay UTF-8 safe).
					_ => {
						out.push('\\');
						let ch = input[i + 1..].chars().next().expect("byte index is on a char boundary");
						out.push(ch);
						i += 1 + ch.len_utf8();
						continue;
					}
				}
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

// ---------------------------------------------------------------------------
// String-syntax front-end: recursive-descent parser
// ---------------------------------------------------------------------------

/// A short human-readable name for a token, for error messages.
fn describe(tok: &Token) -> String {
	match tok {
		Token::Ident(w) => w.clone(),
		Token::Str(_) => "string literal".to_owned(),
		Token::LParen => "(".to_owned(),
		Token::RParen => ")".to_owned(),
		Token::LBracket => "[".to_owned(),
		Token::RBracket => "]".to_owned(),
		Token::Tilde => "~".to_owned(),
		Token::Bang => "!".to_owned(),
		Token::BangEq => "!=".to_owned(),
		Token::AmpAmp => "&&".to_owned(),
		Token::PipePipe => "||".to_owned(),
	}
}

/// Recursive-descent parser over the token stream produced by [`lex`]. Precedence runs
/// `not` (tightest) → `and` → `or` (loosest); parentheses override it.
struct Parser {
	tokens: Vec<Spanned>,
	pos: usize,
	/// Byte offset just past the input, reported for errors at end-of-input.
	end: usize,
}

impl Parser {
	fn peek(&self) -> Option<&Spanned> {
		self.tokens.get(self.pos)
	}

	/// Consume and return the current token, advancing the cursor.
	fn bump(&mut self) -> Option<Spanned> {
		let t = self.tokens.get(self.pos).cloned();
		if t.is_some() {
			self.pos += 1;
		}
		t
	}

	/// The byte offset to report for an error at the cursor (or end of input).
	fn here(&self) -> usize {
		self.tokens.get(self.pos).map_or(self.end, |s| s.pos)
	}

	/// Consume the current token iff it is `symbol` or the bare keyword `keyword`.
	fn eat_keyword_or_symbol(&mut self, keyword: &str, symbol: &Token) -> bool {
		let matched = match self.peek() {
			Some(s) => s.tok == *symbol || matches!(&s.tok, Token::Ident(w) if w == keyword),
			None => false,
		};
		if matched {
			self.pos += 1;
		}
		matched
	}

	/// Consume the current token iff it equals `tok`, else error with `msg`.
	fn expect(&mut self, tok: &Token, msg: &str) -> Result<(), ParseError> {
		match self.peek() {
			Some(s) if &s.tok == tok => {
				self.pos += 1;
				Ok(())
			}
			Some(s) => Err(ParseError::new(s.pos, msg.to_owned())),
			None => Err(ParseError::new(self.here(), msg.to_owned())),
		}
	}

	/// Consume a string literal, returning its value and start offset, else error.
	fn expect_string(&mut self, msg: &str) -> Result<(String, usize), ParseError> {
		match self.peek() {
			Some(Spanned { tok: Token::Str(s), pos }) => {
				let out = (s.clone(), *pos);
				self.pos += 1;
				Ok(out)
			}
			Some(s) => Err(ParseError::new(s.pos, msg.to_owned())),
			None => Err(ParseError::new(self.here(), msg.to_owned())),
		}
	}

	fn parse_expr(&mut self) -> Result<FilterExpr, ParseError> {
		self.parse_or()
	}

	fn parse_or(&mut self) -> Result<FilterExpr, ParseError> {
		let mut expr = self.parse_and()?;
		while self.eat_keyword_or_symbol("or", &Token::PipePipe) {
			let rhs = self.parse_and()?;
			expr = expr.or(rhs);
		}
		Ok(expr)
	}

	fn parse_and(&mut self) -> Result<FilterExpr, ParseError> {
		let mut expr = self.parse_not()?;
		while self.eat_keyword_or_symbol("and", &Token::AmpAmp) {
			let rhs = self.parse_not()?;
			expr = expr.and(rhs);
		}
		Ok(expr)
	}

	fn parse_not(&mut self) -> Result<FilterExpr, ParseError> {
		if self.eat_keyword_or_symbol("not", &Token::Bang) {
			Ok(!self.parse_not()?)
		} else {
			self.parse_primary()
		}
	}

	fn parse_primary(&mut self) -> Result<FilterExpr, ParseError> {
		let Some(s) = self.peek().cloned() else {
			return Err(ParseError::new(self.here(), "unexpected end of input, expected an expression"));
		};
		match s.tok {
			Token::LParen => {
				self.pos += 1;
				let inner = self.parse_expr()?;
				self.expect(&Token::RParen, "expected `)` to close the group")?;
				Ok(inner)
			}
			Token::Ident(ref w) if w == "true" => {
				self.pos += 1;
				Ok(FilterExpr::Always)
			}
			Token::Ident(ref w) if w == "false" => {
				self.pos += 1;
				Ok(FilterExpr::Never)
			}
			Token::Ident(_) => self.parse_predicate(),
			other => Err(ParseError::new(s.pos, format!("expected a field, `(`, `not`, `true`, or `false`, found `{}`", describe(&other)))),
		}
	}

	fn parse_predicate(&mut self) -> Result<FilterExpr, ParseError> {
		let field = self.parse_field()?;
		let op = self.bump().ok_or_else(|| ParseError::new(self.here(), "expected an operator after the field"))?;

		enum Kind {
			Eq,
			Ne,
			Contains,
			StartsWith,
			EndsWith,
			Matches,
			Exists,
		}
		let kind = match &op.tok {
			Token::Ident(w) => match w.as_str() {
				"eq" => Kind::Eq,
				"ne" => Kind::Ne,
				"contains" => Kind::Contains,
				"starts_with" => Kind::StartsWith,
				"ends_with" => Kind::EndsWith,
				"matches" => Kind::Matches,
				"exists" => Kind::Exists,
				other => return Err(ParseError::new(op.pos, format!("unknown operator `{other}`"))),
			},
			Token::BangEq => Kind::Ne,
			Token::Tilde => Kind::Matches,
			other => return Err(ParseError::new(op.pos, format!("expected an operator, found `{}`", describe(other)))),
		};

		if let Kind::Exists = kind {
			return Ok(field.exists());
		}

		let (value, vpos) = self.expect_string("expected a quoted value after the operator")?;
		match kind {
			Kind::Eq => Ok(field.eq(value)),
			Kind::Ne => Ok(field.not_eq(value)),
			Kind::Contains => Ok(field.contains(value)),
			Kind::StartsWith => Ok(field.starts_with(value)),
			Kind::EndsWith => Ok(field.ends_with(value)),
			Kind::Matches => field.matches(&value).map_err(|e| ParseError::new(vpos, format!("invalid regex: {e}"))),
			Kind::Exists => unreachable!("exists is handled above"),
		}
	}

	fn parse_field(&mut self) -> Result<Field, ParseError> {
		let s = self.bump().ok_or_else(|| ParseError::new(self.here(), "expected a field name"))?;
		match &s.tok {
			Token::Ident(w) => match w.as_str() {
				"method" => Ok(Field::method()),
				"path" => Ok(Field::path()),
				"query" => Ok(Field::query()),
				"header" => self.parse_header_field(),
				other => Err(ParseError::new(s.pos, format!("unknown field `{other}`"))),
			},
			other => Err(ParseError::new(s.pos, format!("expected a field name, found `{}`", describe(other)))),
		}
	}

	/// Parse the `[ name ]` that follows the `header` keyword. The name may be a quoted
	/// string or a bare identifier (so `header[user-agent]` and `header["x-token"]` both work).
	fn parse_header_field(&mut self) -> Result<Field, ParseError> {
		self.expect(&Token::LBracket, "expected `[` after `header`")?;
		let name_tok = self.bump().ok_or_else(|| ParseError::new(self.here(), "expected a header name inside `[...]`"))?;
		let name = match &name_tok.tok {
			Token::Str(s) | Token::Ident(s) => s.clone(),
			other => return Err(ParseError::new(name_tok.pos, format!("expected a header name, found `{}`", describe(other)))),
		};
		self.expect(&Token::RBracket, "expected `]` after the header name")?;
		let header = HeaderName::try_from(name.as_str()).map_err(|_| ParseError::new(name_tok.pos, format!("invalid header name `{name}`")))?;
		Ok(Field::header(header))
	}
}

impl FilterExpr {
	/// Parse an operator-authored rule string into a [`FilterExpr`].
	///
	/// The grammar is a boolean expression over the Tor-surviving request fields. Fields are
	/// `method`, `path`, `query`, and `header[NAME]` (the name quoted or bare). Operators are
	/// `eq`, `ne` (or `!=`), `contains`, `starts_with`, `ends_with`, `matches` (or `~`, regex),
	/// and the unary `exists`. Combine with `and` (`&&`), `or` (`||`), `not` (`!`), and
	/// parentheses; `true`/`false` are the constants. Precedence is `not` → `and` → `or`.
	///
	/// ```
	/// use onyums_skin::filter::FilterExpr;
	/// let rule = FilterExpr::parse(r#"method eq "POST" and path ~ "^/admin""#).unwrap();
	/// # let _ = rule;
	/// ```
	///
	/// # Errors
	/// Returns a [`ParseError`] (carrying the byte offset) on any lexing or parsing failure —
	/// an unknown field/operator, a missing value, an invalid regex or header name, an
	/// unbalanced group, or trailing tokens after a complete expression.
	pub fn parse(input: &str) -> Result<FilterExpr, ParseError> {
		let tokens = lex(input)?;
		let mut parser = Parser { tokens, pos: 0, end: input.len() };
		let expr = parser.parse_expr()?;
		if let Some(s) = parser.peek() {
			return Err(ParseError::new(s.pos, format!("unexpected trailing token `{}`", describe(&s.tok))));
		}
		Ok(expr)
	}
}

/// Parse an operator-authored rule string into a [`FilterExpr`]; see [`FilterExpr::parse`].
///
/// # Errors
/// Propagates the [`ParseError`] from [`FilterExpr::parse`].
pub fn parse(input: &str) -> Result<FilterExpr, ParseError> {
	FilterExpr::parse(input)
}

// ---------------------------------------------------------------------------
// String-syntax front-end: canonical serialization (the parser's inverse)
// ---------------------------------------------------------------------------

/// Write `value` as a double-quoted string literal the lexer round-trips: `"` and `\` are
/// escaped (so a backslash always decodes back to one), and the whitespace controls become
/// `\n`/`\t`/`\r`. Everything else is emitted verbatim.
fn fmt_quoted(f: &mut std::fmt::Formatter<'_>, value: &str) -> std::fmt::Result {
	f.write_str("\"")?;
	for ch in value.chars() {
		match ch {
			'"' => f.write_str("\\\"")?,
			'\\' => f.write_str("\\\\")?,
			'\n' => f.write_str("\\n")?,
			'\t' => f.write_str("\\t")?,
			'\r' => f.write_str("\\r")?,
			_ => write!(f, "{ch}")?,
		}
	}
	f.write_str("\"")
}

/// Write a field in the rule syntax. Header names are always quoted so any HTTP-token
/// character (`!`, `#`, …) round-trips, not just the bare-identifier subset.
fn fmt_field(f: &mut std::fmt::Formatter<'_>, field: &Field) -> std::fmt::Result {
	match field {
		Field::Method => f.write_str("method"),
		Field::Path => f.write_str("path"),
		Field::Query => f.write_str("query"),
		Field::Header(name) => {
			f.write_str("header[")?;
			fmt_quoted(f, name.as_str())?;
			f.write_str("]")
		}
	}
}

/// Write a `field op value` predicate. The canonical form uses the keyword operators
/// (`ne`/`matches`), never the `!=`/`~` symbol aliases.
fn fmt_predicate(f: &mut std::fmt::Formatter<'_>, field: &Field, op: &StrOp) -> std::fmt::Result {
	fmt_field(f, field)?;
	let (keyword, value) = match op {
		StrOp::Exists => return write!(f, " exists"),
		StrOp::Eq(s) => ("eq", s.as_str()),
		StrOp::NotEq(s) => ("ne", s.as_str()),
		StrOp::Contains(s) => ("contains", s.as_str()),
		StrOp::StartsWith(s) => ("starts_with", s.as_str()),
		StrOp::EndsWith(s) => ("ends_with", s.as_str()),
		StrOp::Matches(re) => ("matches", re.as_str()),
	};
	write!(f, " {keyword} ")?;
	fmt_quoted(f, value)
}

impl FilterExpr {
	/// Operator binding tightness, for deciding when a child needs parentheses:
	/// `or` (loosest) < `and` < `not` < atom (predicate/constant, tightest).
	fn precedence(&self) -> u8 {
		match self {
			FilterExpr::Or(_) => 1,
			FilterExpr::And(_) => 2,
			FilterExpr::Not(_) => 3,
			FilterExpr::Predicate { .. } | FilterExpr::Always | FilterExpr::Never => 4,
		}
	}

	/// Render this node, wrapping in parens when it binds looser than its parent context.
	fn write_inner(&self, f: &mut std::fmt::Formatter<'_>, parent: u8) -> std::fmt::Result {
		let wrap = self.precedence() < parent;
		if wrap {
			f.write_str("(")?;
		}
		match self {
			FilterExpr::Always => f.write_str("true")?,
			FilterExpr::Never => f.write_str("false")?,
			FilterExpr::Predicate { field, op } => fmt_predicate(f, field, op)?,
			FilterExpr::Not(inner) => {
				f.write_str("not ")?;
				inner.write_inner(f, 3)?;
			}
			FilterExpr::And(subs) => {
				if subs.is_empty() {
					f.write_str("true")?; // vacuous AND
				} else {
					for (i, s) in subs.iter().enumerate() {
						if i > 0 {
							f.write_str(" and ")?;
						}
						s.write_inner(f, 2)?;
					}
				}
			}
			FilterExpr::Or(subs) => {
				if subs.is_empty() {
					f.write_str("false")?; // vacuous OR
				} else {
					for (i, s) in subs.iter().enumerate() {
						if i > 0 {
							f.write_str(" or ")?;
						}
						s.write_inner(f, 1)?;
					}
				}
			}
		}
		if wrap {
			f.write_str(")")?;
		}
		Ok(())
	}
}

impl std::fmt::Display for FilterExpr {
	/// The canonical rule string — the inverse of [`FilterExpr::parse`]. `parse(expr.to_string())`
	/// re-parses to an equivalent expression, and re-serializing is a fixed point.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.write_inner(f, 0)
	}
}

#[cfg(test)]
mod display_tests {
	use axum::http::Request;

	use super::*;

	fn parts(builder: axum::http::request::Builder) -> Parts {
		builder.body(()).unwrap().into_parts().0
	}

	#[test]
	fn predicates_and_operators_render() {
		assert_eq!(Field::method().eq("POST").to_string(), r#"method eq "POST""#);
		assert_eq!(Field::path().not_eq("/x").to_string(), r#"path ne "/x""#);
		assert_eq!(Field::path().starts_with("/admin").to_string(), r#"path starts_with "/admin""#);
		assert_eq!(Field::query().exists().to_string(), "query exists");
		assert_eq!(Field::header(HeaderName::from_static("user-agent")).contains("curl").to_string(), r#"header["user-agent"] contains "curl""#);
		assert_eq!(FilterExpr::Always.to_string(), "true");
		assert_eq!(FilterExpr::Never.to_string(), "false");
	}

	#[test]
	fn precedence_parenthesizes_only_where_needed() {
		// AND of two atoms: no parens.
		let flat = Field::method().eq("POST").and(Field::path().starts_with("/admin"));
		assert_eq!(flat.to_string(), r#"method eq "POST" and path starts_with "/admin""#);
		// AND whose child is an OR: the OR is wrapped (it binds looser).
		let nested = Field::method().eq("GET").and(Field::path().eq("/a").or(Field::path().eq("/b")));
		assert_eq!(nested.to_string(), r#"method eq "GET" and (path eq "/a" or path eq "/b")"#);
		// NOT over a compound wraps; NOT over an atom does not.
		assert_eq!((!Field::method().eq("GET")).to_string(), r#"not method eq "GET""#);
		assert_eq!((!flat.clone()).to_string(), r#"not (method eq "POST" and path starts_with "/admin")"#);
	}

	#[test]
	fn quoting_round_trips_special_characters() {
		// Backslash and quote in a value are escaped so they decode back to themselves.
		let e = Field::header(HeaderName::from_static("x-v")).eq("a\"b\\c");
		let s = e.to_string();
		assert_eq!(s, r#"header["x-v"] eq "a\"b\\c""#);
		let p = parts(Request::builder().uri("/").header("x-v", "a\"b\\c"));
		assert!(FilterExpr::parse(&s).unwrap().evaluate(&p), "the re-parsed rule matches the original value");
	}

	#[test]
	fn regex_value_round_trips_with_doubled_backslashes() {
		let e = Field::path().matches(r"^/x/\d+$").unwrap();
		let s = e.to_string();
		assert_eq!(s, r#"path matches "^/x/\\d+$""#, "the literal backslash is doubled in canonical form");
		let p = parts(Request::builder().uri("/x/42"));
		assert!(FilterExpr::parse(&s).unwrap().evaluate(&p));
	}

	#[test]
	fn display_is_a_fixed_point_of_parse() {
		// Whatever Display emits, parse accepts, and re-serializing is identical — proving the
		// parser is the inverse of the serializer across the operator and connective surface.
		let canon = |input: &str| FilterExpr::parse(input).unwrap().to_string();
		for input in [
			r#"method eq "POST""#,
			r#"path ~ "^/admin/\w+$""#,
			r#"method != "GET" && path starts_with "/api""#,
			r#"query exists || header[x-token] eq "v""#,
			r#"not (method eq "GET" and (path eq "/a" or path eq "/b"))"#,
			"true",
			"false",
		] {
			let once = canon(input);
			let twice = canon(&once);
			assert_eq!(once, twice, "canonical form of `{input}` must re-parse to itself");
		}
	}
}

#[cfg(test)]
mod parse_tests {
	use axum::http::Request;

	use super::*;

	fn parts(builder: axum::http::request::Builder) -> Parts {
		builder.body(()).unwrap().into_parts().0
	}

	#[test]
	fn simple_predicate_round_trips_through_evaluate() {
		let expr = FilterExpr::parse(r#"method eq "POST""#).unwrap();
		assert!(expr.evaluate(&parts(Request::builder().method("POST").uri("/"))));
		assert!(!expr.evaluate(&parts(Request::builder().method("GET").uri("/"))));
	}

	#[test]
	fn every_operator_parses() {
		let p = parts(Request::builder().method("GET").uri("/admin/users?x=1").header("user-agent", "curl/8"));
		assert!(FilterExpr::parse(r#"path eq "/admin/users""#).unwrap().evaluate(&p));
		assert!(FilterExpr::parse(r#"path ne "/x""#).unwrap().evaluate(&p));
		assert!(FilterExpr::parse(r#"path contains "min/us""#).unwrap().evaluate(&p));
		assert!(FilterExpr::parse(r#"path starts_with "/admin""#).unwrap().evaluate(&p));
		assert!(FilterExpr::parse(r#"path ends_with "/users""#).unwrap().evaluate(&p));
		assert!(FilterExpr::parse(r#"path matches "^/admin/\w+$""#).unwrap().evaluate(&p));
		assert!(FilterExpr::parse(r#"query exists"#).unwrap().evaluate(&p));
		// The `!=` and `~` symbol forms are equivalent to `ne` and `matches`.
		assert!(FilterExpr::parse(r#"path != "/x""#).unwrap().evaluate(&p));
		assert!(FilterExpr::parse(r#"header[user-agent] ~ "^curl/""#).unwrap().evaluate(&p));
	}

	#[test]
	fn header_field_quoted_and_bare() {
		let p = parts(Request::builder().uri("/").header("x-token", "abc"));
		assert!(FilterExpr::parse(r#"header[x-token] eq "abc""#).unwrap().evaluate(&p));
		assert!(FilterExpr::parse(r#"header["x-token"] eq "abc""#).unwrap().evaluate(&p));
		assert!(!FilterExpr::parse(r#"header[x-absent] exists"#).unwrap().evaluate(&p));
	}

	#[test]
	fn precedence_is_not_then_and_then_or() {
		// `a and b or c` parses as `(a and b) or c`.
		let p = parts(Request::builder().method("GET").uri("/c"));
		let expr = FilterExpr::parse(r#"method eq "POST" and path eq "/b" or path eq "/c""#).unwrap();
		assert!(expr.evaluate(&p), "the `or path eq /c` branch matches");
		// `not a and b` parses as `(not a) and b`, not `not (a and b)`.
		let p2 = parts(Request::builder().method("GET").uri("/admin"));
		let expr2 = FilterExpr::parse(r#"not method eq "POST" and path eq "/admin""#).unwrap();
		assert!(expr2.evaluate(&p2));
	}

	#[test]
	fn parentheses_override_precedence() {
		// With parens, `a and (b or c)` requires a AND one of b/c.
		let expr = FilterExpr::parse(r#"method eq "GET" and (path eq "/b" or path eq "/c")"#).unwrap();
		assert!(expr.evaluate(&parts(Request::builder().method("GET").uri("/c"))));
		assert!(!expr.evaluate(&parts(Request::builder().method("POST").uri("/c"))), "method gate fails");
		assert!(!expr.evaluate(&parts(Request::builder().method("GET").uri("/d"))), "neither path branch matches");
	}

	#[test]
	fn symbol_and_keyword_connectives_agree() {
		let p = parts(Request::builder().method("POST").uri("/admin"));
		let kw = FilterExpr::parse(r#"method eq "POST" and path eq "/admin""#).unwrap();
		let sym = FilterExpr::parse(r#"method eq "POST" && path eq "/admin""#).unwrap();
		assert_eq!(kw.evaluate(&p), sym.evaluate(&p));
		assert!(FilterExpr::parse(r#"path eq "/x" || method eq "POST""#).unwrap().evaluate(&p));
		assert!(FilterExpr::parse(r#"!method eq "GET""#).unwrap().evaluate(&p));
	}

	#[test]
	fn constants_parse() {
		let p = parts(Request::builder().uri("/"));
		assert!(FilterExpr::parse("true").unwrap().evaluate(&p));
		assert!(!FilterExpr::parse("false").unwrap().evaluate(&p));
	}

	#[test]
	fn free_function_matches_associated_fn() {
		let p = parts(Request::builder().method("GET").uri("/"));
		assert!(parse(r#"method eq "GET""#).unwrap().evaluate(&p));
	}

	#[test]
	fn parse_errors_report_a_position() {
		// Unknown field / operator.
		assert_eq!(FilterExpr::parse(r#"frob eq "x""#).unwrap_err().message, "unknown field `frob`");
		assert_eq!(FilterExpr::parse(r#"method frob "x""#).unwrap_err().message, "unknown operator `frob`");
		// Missing value.
		assert!(FilterExpr::parse("method eq").unwrap_err().message.contains("quoted value"));
		// Empty input.
		assert!(FilterExpr::parse("   ").unwrap_err().message.contains("end of input"));
		// Trailing tokens.
		assert!(FilterExpr::parse(r#"method eq "x" path eq "y""#).unwrap_err().message.contains("trailing"));
		// Unbalanced group.
		assert!(FilterExpr::parse(r#"(method eq "x""#).unwrap_err().message.contains("close the group"));
		// Invalid regex surfaces with the value's position.
		let err = FilterExpr::parse(r#"path ~ "(""#).unwrap_err();
		assert!(err.message.contains("invalid regex"));
		assert_eq!(err.pos, 7, "the error points at the offending string literal");
		// Invalid header name.
		assert!(FilterExpr::parse(r#"header["bad header"] exists"#).unwrap_err().message.contains("invalid header name"));
	}
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
		// Unknown escapes pass through verbatim so regex metacharacters survive.
		assert_eq!(toks(r#""^/item/\d+$""#), vec![Token::Str(r"^/item/\d+$".into())]);
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
		// A trailing backslash with nothing after it is still an error.
		assert_eq!(lex("\"bad\\").unwrap_err().message, "trailing backslash in string literal");
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

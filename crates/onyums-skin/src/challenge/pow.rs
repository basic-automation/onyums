//! Proof-of-work: a swappable algorithm behind the [`Pow`] trait.
//!
//! The default is SHA-256 hashcash (MIT, pure Rust, near-free server verification) —
//! the correct asymmetry for an access gate. Heavier or "useful-work" backends
//! (Equi-X, RandomX) can implement [`Pow`] behind cargo features; they are never the
//! default. See `ROADMAP.md` §4.3 for the rationale, including why RandomX-WASM
//! mine-to-enter was rejected.

use std::{
	collections::HashMap, sync::{Arc, Mutex}, time::{Duration, SystemTime, UNIX_EPOCH}
};

use axum::{
	http::{StatusCode, request::Parts}, response::{Html, IntoResponse, Response}
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

use super::{Challenge, Gate};
use crate::{difficulty::{AdaptiveDifficulty, ShapeDifficulty}, shape::RequestShape};

type HmacSha256 = Hmac<Sha256>;

/// A PoW puzzle handed to the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Puzzle {
	pub seed: [u8; 32],
	/// Required number of leading zero *bits* in `SHA-256(seed || solution)`.
	pub difficulty: u32,
}

/// A swappable proof-of-work algorithm. Server-side `verify` must be ~free.
pub trait Pow: Send + Sync {
	/// Generate a fresh puzzle at the given difficulty.
	fn new_puzzle(&self, difficulty: u32) -> Puzzle;
	/// Verify a client's solution against a puzzle.
	fn verify(&self, puzzle: &Puzzle, solution: &[u8]) -> bool;
}

/// Default PoW: SHA-256 hashcash (leading-zero-bits over `seed || solution`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Hashcash;

impl Hashcash {
	/// `SHA-256(seed || solution)`.
	fn digest(puzzle: &Puzzle, solution: &[u8]) -> [u8; 32] {
		let mut hasher = Sha256::new();
		hasher.update(puzzle.seed);
		hasher.update(solution);
		hasher.finalize().into()
	}

	/// Brute-force a solution for `puzzle` by incrementing an 8-byte big-endian
	/// counter. This is the reference solver used by the JS interstitial and by
	/// tests; the cost is exponential in `difficulty`, so callers should keep test
	/// difficulties small.
	#[must_use]
	pub fn solve(&self, puzzle: &Puzzle) -> Vec<u8> {
		let mut nonce: u64 = 0;
		loop {
			let solution = nonce.to_be_bytes();
			if leading_zero_bits(&Self::digest(puzzle, &solution)) >= puzzle.difficulty {
				return solution.to_vec();
			}
			// At realistic difficulties a u64 nonce space is always sufficient; the
			// wrap is unreachable in practice but keeps the loop total.
			nonce = nonce.wrapping_add(1);
		}
	}
}

impl Pow for Hashcash {
	fn new_puzzle(&self, difficulty: u32) -> Puzzle {
		let mut seed = [0u8; 32];
		rand::rng().fill_bytes(&mut seed);
		Puzzle { seed, difficulty }
	}

	fn verify(&self, puzzle: &Puzzle, solution: &[u8]) -> bool {
		leading_zero_bits(&Self::digest(puzzle, solution)) >= puzzle.difficulty
	}
}

/// Count the number of leading zero bits across `bytes`, most-significant byte
/// first. Shared with alternate [`Pow`] backends (e.g. the optional EquiX one) so
/// every algorithm reads `difficulty` as the same leading-zero-bit effort target.
pub(crate) fn leading_zero_bits(bytes: &[u8]) -> u32 {
	let mut count = 0;
	for &b in bytes {
		if b == 0 {
			count += 8;
		} else {
			count += b.leading_zeros();
			break;
		}
	}
	count
}

/// Default lifetime of an issued puzzle: long enough for a slow client to solve a
/// modest difficulty, short enough that a stockpiled puzzle goes stale.
const DEFAULT_PUZZLE_TTL: Duration = Duration::from_secs(300);

/// Default Skin-owned route the interstitial submits its solution to.
const DEFAULT_SUBMIT_PATH: &str = "/.skin/pow";

/// A JS proof-of-work [`Challenge`]: hand the client a server-signed puzzle, have the
/// browser brute-force a hashcash nonce, and accept the solution off a Skin-owned
/// submission route.
///
/// **Stateless and unforgeable.** The puzzle is not remembered server-side; instead the
/// seed and difficulty are packed into a signed envelope (`HMAC-SHA256`) handed to the
/// client and echoed back on submission. The client therefore cannot pick its own easy
/// seed, replay a stale puzzle (the envelope carries an expiry), or tamper with the
/// difficulty — [`verify`](Self::verify) re-derives both from the *verified* envelope and
/// ignores anything the client claims separately.
///
/// **No-JS clients.** This challenge requires JavaScript ([`needs_js`](Challenge::needs_js)
/// returns `true`); a [`ChallengeChain`](crate::challenge::ChallengeChain) falls back to
/// the no-JS [`PatienceChallenge`](crate::challenge::patience::PatienceChallenge) or a
/// CAPTCHA for Tor "Safer"/"Safest" clients.
///
/// Carrier for the submission is the query string of the submission route
/// (`?puzzle=<envelope>&nonce=<base64url>`), so verification needs only request
/// [`Parts`] — no body buffering. The minted clearance itself is the
/// [`SkinLayer`](crate)'s job once `verify` returns `true`.
pub struct PowChallenge<P: Pow> {
	pow: P,
	secret: Vec<u8>,
	difficulty: u32,
	/// Optional adaptive controller. When set, issued puzzles use
	/// `max(difficulty, controller.current_difficulty())` — the static `difficulty`
	/// is a floor the controller can raise under load but never lower.
	adaptive: Option<Arc<AdaptiveDifficulty>>,
	/// Optional request-shape controller. When set, the shape of the challenged request
	/// raises difficulty toward its `max` for shapes that deviate from the learned
	/// baseline — complementary to `adaptive`, which keys on raw request *rate*.
	shape: Option<Arc<ShapeDifficulty>>,
	ttl: Duration,
	submit_path: String,
	/// Seeds of puzzles already redeemed, with the instant their entry can be pruned
	/// (the puzzle's own expiry). Enforces single-use so one solve mints one clearance.
	consumed: Mutex<HashMap<[u8; 32], SystemTime>>,
}

impl<P: Pow> PowChallenge<P> {
	/// Build a challenge over `pow` (typically [`Hashcash`]) signing puzzles with
	/// `secret` at the given leading-zero-bit `difficulty`.
	pub fn new(pow: P, secret: impl Into<Vec<u8>>, difficulty: u32) -> Self {
		Self {
			pow,
			secret: secret.into(),
			difficulty,
			adaptive: None,
			shape: None,
			ttl: DEFAULT_PUZZLE_TTL,
			submit_path: DEFAULT_SUBMIT_PATH.to_owned(),
			consumed: Mutex::new(HashMap::new()),
		}
	}

	/// Record `seed` as redeemed, returning `false` if it was already redeemed (a
	/// replay). Expired entries are pruned opportunistically so the map stays bounded by
	/// the number of puzzles outstanding within one TTL window.
	fn consume(&self, seed: [u8; 32], expires: SystemTime) -> bool {
		let mut consumed = self.consumed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
		let now = SystemTime::now();
		consumed.retain(|_, exp| *exp > now);
		if consumed.contains_key(&seed) {
			return false;
		}
		consumed.insert(seed, expires);
		true
	}

	/// Override how long an issued puzzle stays valid (default 5 minutes).
	#[must_use]
	pub fn with_ttl(mut self, ttl: Duration) -> Self {
		self.ttl = ttl;
		self
	}

	/// Override the route the interstitial submits solutions to (default `/.skin/pow`).
	#[must_use]
	pub fn with_submit_path(mut self, path: impl Into<String>) -> Self {
		self.submit_path = path.into();
		self
	}

	/// Drive issued-puzzle difficulty from an [`AdaptiveDifficulty`] controller. Under
	/// normal load the controller is dormant and the configured `difficulty` floor
	/// applies; under load it raises difficulty toward its `max`. The controller never
	/// lowers difficulty below the static floor. Share one `Arc` with the host code
	/// that calls [`record_request`](AdaptiveDifficulty::record_request).
	#[must_use]
	pub fn with_adaptive_difficulty(mut self, controller: Arc<AdaptiveDifficulty>) -> Self {
		self.adaptive = Some(controller);
		self
	}

	/// Drive issued-puzzle difficulty from a [`ShapeDifficulty`] controller — the
	/// request-shape-deviation signal, complementary to [`with_adaptive_difficulty`](Self::with_adaptive_difficulty)'s
	/// rate signal. When the challenged request's shape deviates from the learned baseline,
	/// the controller raises difficulty toward its `max`; a shape matching normal traffic
	/// leaves the static floor in place. The controller never lowers difficulty below the
	/// floor. Observing the request also folds its shape into the controller's baseline.
	#[must_use]
	pub fn with_shape_difficulty(mut self, controller: Arc<ShapeDifficulty>) -> Self {
		self.shape = Some(controller);
		self
	}

	/// The difficulty to issue at right now: the static floor, raised by whichever
	/// controllers are attached (the max of the rate-driven and shape-driven signals). The
	/// shape signal needs the request [`Parts`]; pass `None` to skip it.
	fn current_difficulty(&self, req: Option<&Parts>) -> u32 {
		let mut difficulty = self.difficulty;
		if let Some(adaptive) = &self.adaptive {
			difficulty = difficulty.max(adaptive.current_difficulty());
		}
		if let (Some(shape), Some(req)) = (&self.shape, req) {
			difficulty = difficulty.max(shape.observe(&RequestShape::from_parts(req)));
		}
		difficulty
	}

	/// `HMAC-SHA256(secret, payload)` over the puzzle envelope.
	fn tag(&self, payload: &[u8]) -> Vec<u8> {
		let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts a key of any length");
		mac.update(payload);
		mac.finalize().into_bytes().to_vec()
	}

	/// Generate a fresh puzzle and its signed wire envelope
	/// (`base64url(seed‖difficulty‖expires).base64url(tag)`).
	fn make_puzzle(&self, req: Option<&Parts>) -> (Puzzle, String) {
		let puzzle = self.pow.new_puzzle(self.current_difficulty(req));
		let expires = SystemTime::now() + self.ttl;
		let mut payload = Vec::with_capacity(44);
		payload.extend_from_slice(&puzzle.seed);
		payload.extend_from_slice(&puzzle.difficulty.to_be_bytes());
		payload.extend_from_slice(&unix_secs(expires).to_be_bytes());
		let tag = self.tag(&payload);
		let envelope = format!("{}.{}", URL_SAFE_NO_PAD.encode(&payload), URL_SAFE_NO_PAD.encode(tag));
		(puzzle, envelope)
	}

	/// Recover the [`Puzzle`] and its expiry from a signed envelope, or `None` if the
	/// signature is wrong, the format is malformed, or the puzzle has expired.
	fn open_puzzle(&self, envelope: &str) -> Option<(Puzzle, SystemTime)> {
		let (payload_b64, tag_b64) = envelope.split_once('.')?;
		let payload = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
		let tag = URL_SAFE_NO_PAD.decode(tag_b64).ok()?;
		if payload.len() != 44 {
			return None;
		}

		// Constant-time signature check before trusting any field.
		let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts a key of any length");
		mac.update(&payload);
		mac.verify_slice(&tag).ok()?;

		let mut seed = [0u8; 32];
		seed.copy_from_slice(&payload[0..32]);
		let difficulty = u32::from_be_bytes(payload[32..36].try_into().ok()?);
		let expires = from_unix_secs(u64::from_be_bytes(payload[36..44].try_into().ok()?));
		if expires <= SystemTime::now() {
			return None;
		}
		Some((Puzzle { seed, difficulty }, expires))
	}

	/// Render the JS interstitial that solves `puzzle` and submits the nonce.
	fn interstitial(&self, puzzle: &Puzzle, envelope: &str) -> Response {
		let body = INTERSTITIAL.replace("__SEED__", &hex(&puzzle.seed)).replace("__DIFFICULTY__", &puzzle.difficulty.to_string()).replace("__PUZZLE__", envelope).replace("__SUBMIT__", &self.submit_path);
		(StatusCode::OK, Html(body)).into_response()
	}
}

impl<P: Pow> Challenge for PowChallenge<P> {
	fn issue(&self, req: &Parts) -> Gate {
		let (puzzle, envelope) = self.make_puzzle(Some(req));
		Gate::Present(self.interstitial(&puzzle, &envelope))
	}

	fn verify(&self, req: &Parts) -> bool {
		let Some(query) = req.uri.query() else {
			return false;
		};
		let mut envelope = None;
		let mut nonce_b64 = None;
		for pair in query.split('&') {
			if let Some(v) = pair.strip_prefix("puzzle=") {
				envelope = Some(v);
			} else if let Some(v) = pair.strip_prefix("nonce=") {
				nonce_b64 = Some(v);
			}
		}
		let (Some(envelope), Some(nonce_b64)) = (envelope, nonce_b64) else {
			return false;
		};
		let Some((puzzle, expires)) = self.open_puzzle(envelope) else {
			return false;
		};
		let Ok(nonce) = URL_SAFE_NO_PAD.decode(nonce_b64) else {
			return false;
		};
		if !self.pow.verify(&puzzle, &nonce) {
			return false;
		}
		// Single-use: a correctly-solved puzzle clears exactly once, so one PoW solve
		// cannot be replayed to mint an unbounded number of clearances (and thus
		// unbounded rate-limit budget). The clearance token itself stays multi-use — it
		// is the per-client session identity the rate limiter counts on.
		self.consume(puzzle.seed, expires)
	}

	fn needs_js(&self) -> bool {
		true
	}
}

/// Lowercase-hex encode `bytes` (for embedding the seed in the interstitial).
fn hex(bytes: &[u8]) -> String {
	let mut s = String::with_capacity(bytes.len() * 2);
	for b in bytes {
		s.push(char::from_digit((b >> 4) as u32, 16).expect("nibble < 16"));
		s.push(char::from_digit((b & 0x0f) as u32, 16).expect("nibble < 16"));
	}
	s
}

/// Seconds since the Unix epoch, saturating at 0 for pre-epoch times.
fn unix_secs(t: SystemTime) -> u64 {
	t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Inverse of [`unix_secs`].
fn from_unix_secs(secs: u64) -> SystemTime {
	UNIX_EPOCH + Duration::from_secs(secs)
}

/// The no-dependency interstitial: a self-contained SHA-256 hashcash solver in plain JS.
/// Placeholders (`__SEED__`, `__DIFFICULTY__`, `__PUZZLE__`, `__SUBMIT__`) are filled in
/// per puzzle. The solver mirrors [`Hashcash`] exactly — `SHA-256(seed ‖ nonce)` with an
/// 8-byte big-endian nonce counter — so a browser-found solution verifies server-side.
const INTERSTITIAL: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Checking your connection…</title>
</head>
<body>
<h1>Checking your connection…</h1>
<p id="status">Solving a one-time proof-of-work to keep this service available. This takes a moment and requires no interaction.</p>
<noscript><p>JavaScript is disabled. A no-JavaScript fallback should follow automatically.</p></noscript>
<script>
(function(){
var SEED="__SEED__";var DIFFICULTY=__DIFFICULTY__;var PUZZLE="__PUZZLE__";var SUBMIT="__SUBMIT__";
var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function rotr(x,n){return (x>>>n)|(x<<(32-n));}
function sha256(msg){
var h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
var l=msg.length;var withOne=l+1;var k=(56-withOne%64+64)%64;var total=withOne+k+8;
var m=new Uint8Array(total);m.set(msg);m[l]=0x80;
var dv=new DataView(m.buffer);var bitLen=l*8;
dv.setUint32(total-4,bitLen>>>0,false);dv.setUint32(total-8,Math.floor(bitLen/0x100000000)>>>0,false);
var w=new Uint32Array(64);
for(var off=0;off<total;off+=64){
for(var i=0;i<16;i++){w[i]=dv.getUint32(off+i*4,false);}
for(i=16;i<64;i++){var s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>>3);var s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>>10);w[i]=(w[i-16]+s0+w[i-7]+s1)|0;}
var a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
for(i=0;i<64;i++){var S1=rotr(e,6)^rotr(e,11)^rotr(e,25);var ch=(e&f)^((~e)&g);var t1=(h+S1+ch+K[i]+w[i])|0;var S0=rotr(a,2)^rotr(a,13)^rotr(a,22);var maj=(a&b)^(a&c)^(b&c);var t2=(S0+maj)|0;h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;}
h0=(h0+a)|0;h1=(h1+b)|0;h2=(h2+c)|0;h3=(h3+d)|0;h4=(h4+e)|0;h5=(h5+f)|0;h6=(h6+g)|0;h7=(h7+h)|0;
}
var out=new Uint8Array(32);var odv=new DataView(out.buffer);var hs=[h0,h1,h2,h3,h4,h5,h6,h7];
for(i=0;i<8;i++){odv.setUint32(i*4,hs[i]>>>0,false);}
return out;
}
function lzb(bytes){var c=0;for(var i=0;i<bytes.length;i++){if(bytes[i]===0){c+=8;}else{c+=Math.clz32(bytes[i])-24;break;}}return c;}
function hexToBytes(h){var a=new Uint8Array(h.length/2);for(var i=0;i<a.length;i++){a[i]=parseInt(h.substr(i*2,2),16);}return a;}
function b64url(bytes){var s="";for(var i=0;i<bytes.length;i++){s+=String.fromCharCode(bytes[i]);}return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");}
function solve(){
var seed=hexToBytes(SEED);var buf=new Uint8Array(seed.length+8);buf.set(seed);
var nonce=new Uint8Array(8);var ndv=new DataView(nonce.buffer);
for(var n=0;;n++){ndv.setUint32(4,n>>>0,false);buf.set(nonce,seed.length);if(lzb(sha256(buf))>=DIFFICULTY){return nonce;}}
}
var nonce=solve();
window.location=SUBMIT+"?puzzle="+encodeURIComponent(PUZZLE)+"&nonce="+b64url(nonce);
})();
</script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn leading_zero_bits_counts_across_bytes() {
		assert_eq!(leading_zero_bits(&[0xFF]), 0);
		assert_eq!(leading_zero_bits(&[0x80]), 0);
		assert_eq!(leading_zero_bits(&[0x40]), 1);
		assert_eq!(leading_zero_bits(&[0x01]), 7);
		assert_eq!(leading_zero_bits(&[0x00, 0x80]), 8);
		assert_eq!(leading_zero_bits(&[0x00, 0x01]), 15);
		assert_eq!(leading_zero_bits(&[0x00, 0x00]), 16);
	}

	#[test]
	fn solve_then_verify_roundtrips() {
		let hc = Hashcash;
		let puzzle = hc.new_puzzle(12);
		let solution = hc.solve(&puzzle);
		assert!(hc.verify(&puzzle, &solution));
	}

	#[test]
	fn difficulty_zero_accepts_any_solution() {
		let hc = Hashcash;
		let puzzle = Puzzle { seed: [7u8; 32], difficulty: 0 };
		assert!(hc.verify(&puzzle, b"anything"));
		assert!(hc.verify(&puzzle, b""));
	}

	#[test]
	fn wrong_solution_is_rejected() {
		let hc = Hashcash;
		// A fixed seed with a high difficulty no trivial solution will satisfy.
		let puzzle = Puzzle { seed: [0u8; 32], difficulty: 20 };
		assert!(!hc.verify(&puzzle, b"not-a-valid-nonce"));
	}

	#[test]
	fn solution_is_bound_to_the_seed() {
		let hc = Hashcash;
		let p1 = hc.new_puzzle(12);
		let solution = hc.solve(&p1);
		// The same solution against a different seed should (almost surely) fail.
		let p2 = Puzzle { seed: [0xABu8; 32], difficulty: 12 };
		assert!(!hc.verify(&p2, &solution));
	}
}

#[cfg(test)]
mod challenge_tests {
	use axum::http::Request;

	use super::*;

	/// Keep test difficulty low so the reference solver returns instantly.
	const TEST_DIFFICULTY: u32 = 8;

	fn challenge() -> PowChallenge<Hashcash> {
		PowChallenge::new(Hashcash, b"test-secret".to_vec(), TEST_DIFFICULTY)
	}

	/// Build request `Parts` whose URI carries the given query string.
	fn parts_with_query(query: &str) -> Parts {
		Request::builder().uri(format!("/.skin/pow?{query}")).body(()).unwrap().into_parts().0
	}

	/// Solve `puzzle` and assemble the submission query the interstitial would send.
	fn solved_query(envelope: &str, puzzle: &Puzzle) -> String {
		let nonce = Hashcash.solve(puzzle);
		format!("puzzle={envelope}&nonce={}", URL_SAFE_NO_PAD.encode(nonce))
	}

	#[test]
	fn needs_js_is_true() {
		assert!(challenge().needs_js());
	}

	#[test]
	fn issue_presents_interstitial_embedding_the_puzzle() {
		let chal = challenge();
		match chal.issue(&parts_with_query("")) {
			Gate::Present(resp) => {
				assert_eq!(resp.status(), StatusCode::OK);
			}
			_ => panic!("PoW challenge must present the interstitial"),
		}
	}

	#[test]
	fn solved_submission_verifies() {
		let chal = challenge();
		let (puzzle, envelope) = chal.make_puzzle(None);
		let req = parts_with_query(&solved_query(&envelope, &puzzle));
		assert!(chal.verify(&req));
	}

	#[test]
	fn solved_puzzle_is_single_use() {
		let chal = challenge();
		let (puzzle, envelope) = chal.make_puzzle(None);
		let query = solved_query(&envelope, &puzzle);
		// First redemption clears; replaying the exact same solution does not.
		assert!(chal.verify(&parts_with_query(&query)));
		assert!(!chal.verify(&parts_with_query(&query)), "a solved puzzle must clear at most once");
	}

	#[test]
	fn client_chosen_seed_does_not_help() {
		// A solution must be against the *signed* seed, not one the client supplies.
		let chal = challenge();
		let easy = Puzzle { seed: [0u8; 32], difficulty: 0 };
		let forged_envelope = "AAAA.BBBB"; // unsigned garbage
		let req = parts_with_query(&solved_query(forged_envelope, &easy));
		assert!(!chal.verify(&req));
	}

	#[test]
	fn tampered_envelope_is_rejected() {
		let chal = challenge();
		let (puzzle, envelope) = chal.make_puzzle(None);
		// Flip the last char of the payload (before the '.'), keeping the tag.
		let (payload, tag) = envelope.split_once('.').unwrap();
		let mut chars: Vec<char> = payload.chars().collect();
		let last = chars.last_mut().unwrap();
		*last = if *last == 'A' { 'B' } else { 'A' };
		let forged: String = chars.into_iter().collect();
		let req = parts_with_query(&solved_query(&format!("{forged}.{tag}"), &puzzle));
		assert!(!chal.verify(&req));
	}

	#[test]
	fn wrong_nonce_is_rejected() {
		let chal = challenge();
		let (_puzzle, envelope) = chal.make_puzzle(None);
		let req = parts_with_query(&format!("puzzle={envelope}&nonce={}", URL_SAFE_NO_PAD.encode(b"not-a-solution")));
		assert!(!chal.verify(&req));
	}

	#[test]
	fn expired_puzzle_is_rejected() {
		// A zero TTL means the envelope is already expired when submitted.
		let chal = PowChallenge::new(Hashcash, b"test-secret".to_vec(), 0).with_ttl(Duration::ZERO);
		let (puzzle, envelope) = chal.make_puzzle(None);
		let req = parts_with_query(&solved_query(&envelope, &puzzle));
		assert!(!chal.verify(&req));
	}

	#[test]
	fn missing_query_is_rejected() {
		let chal = challenge();
		let req = Request::builder().uri("/.skin/pow").body(()).unwrap().into_parts().0;
		assert!(!chal.verify(&req));
	}

	#[test]
	fn another_stores_envelope_is_rejected() {
		// A puzzle signed by a different secret must not verify here.
		let mint = PowChallenge::new(Hashcash, b"secret-a".to_vec(), TEST_DIFFICULTY);
		let check = PowChallenge::new(Hashcash, b"secret-b".to_vec(), TEST_DIFFICULTY);
		let (puzzle, envelope) = mint.make_puzzle(None);
		let req = parts_with_query(&solved_query(&envelope, &puzzle));
		assert!(mint.verify(&parts_with_query(&solved_query(&envelope, &puzzle))));
		assert!(!check.verify(&req));
	}

	#[test]
	fn adaptive_difficulty_raises_issued_puzzle_difficulty() {
		use crate::circuit::{Clock, ManualClock};
		use std::time::Instant;

		struct ArcClock(Arc<ManualClock>);
		impl Clock for ArcClock {
			fn now(&self) -> Instant {
				self.0.now()
			}
		}

		let clock = Arc::new(ManualClock::new());
		// Controller ramps 0 -> 20 over rate band [2, 10]/window.
		let ctrl = Arc::new(
			AdaptiveDifficulty::new(0, 20)
				.rate_band(2, 10)
				.window(Duration::from_secs(1))
				.with_clock(Box::new(ArcClock(clock.clone()))),
		);
		// Static floor 4; controller dormant at first.
		let chal = PowChallenge::new(Hashcash, b"sec".to_vec(), 4).with_adaptive_difficulty(ctrl.clone());

		// No load: the floor applies.
		assert_eq!(chal.make_puzzle(None).0.difficulty, 4);

		// Drive the observed rate to/over high_rate; the controller maxes out and the
		// issued difficulty follows (well above the floor).
		for _ in 0..10 {
			ctrl.record_request();
		}
		assert_eq!(chal.make_puzzle(None).0.difficulty, 20);
	}

	#[test]
	fn adaptive_controller_never_lowers_below_floor() {
		// A controller whose max is below the static floor cannot drag difficulty down.
		let ctrl = Arc::new(AdaptiveDifficulty::new(0, 2));
		let chal = PowChallenge::new(Hashcash, b"sec".to_vec(), 9).with_adaptive_difficulty(ctrl);
		assert_eq!(chal.make_puzzle(None).0.difficulty, 9);
	}

	#[test]
	fn shape_difficulty_raises_issued_puzzle_difficulty_for_anomalous_shape() {
		use std::time::Instant;

		use crate::{circuit::{Clock, ManualClock}, shape::{RequestShape, ShapeBaseline}};

		struct ArcClock(Arc<ManualClock>);
		impl Clock for ArcClock {
			fn now(&self) -> Instant {
				self.0.now()
			}
		}

		let normal = || Request::builder().uri("/").header("user-agent", "tor-browser").body(()).unwrap().into_parts().0;
		// A baseline primed with a dominant "normal" shape so deviation scoring is active.
		let clock = Arc::new(ManualClock::new());
		let baseline = ShapeBaseline::new().min_observations(5.0).with_clock(Box::new(ArcClock(clock)));
		for _ in 0..20 {
			baseline.observe(&RequestShape::from_parts(&normal()));
		}
		let shape = Arc::new(ShapeDifficulty::new(0, 18).with_baseline(baseline));
		// Static floor 2; the shape controller can raise toward 18 for novel shapes.
		let chal = PowChallenge::new(Hashcash, b"sec".to_vec(), 2).with_shape_difficulty(shape);

		// A request whose shape matches the baseline stays at the floor.
		assert_eq!(chal.make_puzzle(Some(&normal())).0.difficulty, 2);

		// A never-seen shape deviates fully → difficulty jumps to the controller max.
		let novel = Request::builder().uri("/wp-login.php").header("user-agent", "curl/8.4").body(()).unwrap().into_parts().0;
		assert_eq!(chal.make_puzzle(Some(&novel)).0.difficulty, 18);
	}
}

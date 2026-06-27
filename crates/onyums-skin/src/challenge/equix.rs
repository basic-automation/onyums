//! Optional EquiX proof-of-work backend — Tor's own client-puzzle function.
//!
//! Equi-X (the `equix` crate, LGPL-3.0, pure Rust) is the asymmetric puzzle Tor's v3
//! onion-service PoW is built on: finding a solution costs the client a generated HashX
//! program plus an Equihash-style collision search, while the server verifies one in a
//! single hash pass. This backend is **opt-in** behind the `equix` cargo feature so the
//! default build stays copyleft-free and dependency-light; [`Hashcash`](super::pow::Hashcash)
//! remains the default [`Pow`].
//!
//! # Effort over Equi-X
//!
//! A single Equi-X solution is a *fixed*-cost proof — it carries no tunable difficulty of
//! its own. To honour the [`Pow`] contract (where `difficulty` is a leading-zero-bit
//! target), this backend layers an **effort** check on top, exactly as Tor's PoW protocol
//! does: the client searches over an 8-byte nonce, and a solution counts only when
//! `SHA-256(challenge ‖ solution)` clears `difficulty` leading zero bits. So `difficulty`
//! reads identically to [`Hashcash`](super::pow::Hashcash) — the
//! [`AdaptiveDifficulty`](crate::difficulty::AdaptiveDifficulty) /
//! [`ShapeDifficulty`](crate::difficulty::ShapeDifficulty) controllers drive it the same
//! way — while every individual try also pays the Equi-X base cost.
//!
//! # Wire format
//!
//! A solution is `nonce ‖ equix_solution` = **24 bytes**: an 8-byte big-endian nonce
//! followed by the 16-byte [`equix::SolutionByteArray`]. The challenge handed to Equi-X is
//! `puzzle.seed ‖ nonce` (40 bytes); the seed alone is never the Equi-X challenge, so a
//! solution is bound to both the signed seed and the nonce it was found under.
//!
//! # Browser clients
//!
//! Equi-X has no JavaScript solver here (a browser solver needs WASM, which Tor
//! "Safer"/"Safest" disable), so it leaves [`Pow::interstitial_template`] at the default
//! `None` — a [`PowChallenge`](super::pow::PowChallenge) over EquiX degrades to a static
//! "compatible client required" page rather than borrowing the hashcash solver. This
//! backend targets native or programmatic clients, or a future WASM interstitial;
//! [`Hashcash`](super::pow::Hashcash) stays the JS-interactive default.

use equix::{EquiXBuilder, Runtime, RuntimeOption, SolutionByteArray};
use rand::RngCore;
use sha2::{Digest, Sha256};

use super::pow::{Pow, Puzzle, leading_zero_bits};

/// Length in bytes of the nonce prefix in an EquiX [`Pow`] solution.
const NONCE_LEN: usize = 8;
/// Length in bytes of a serialized Equi-X solution (`equix::Solution::NUM_BYTES`).
const EQUIX_SOLUTION_LEN: usize = 16;
/// Total EquiX [`Pow`] solution length: `nonce ‖ equix_solution`.
const SOLUTION_LEN: usize = NONCE_LEN + EQUIX_SOLUTION_LEN;
/// Length in bytes of the Equi-X challenge: `seed ‖ nonce`.
const CHALLENGE_LEN: usize = 32 + NONCE_LEN;

/// Optional EquiX [`Pow`] backend (Tor's Equi-X puzzle), gated behind the `equix` cargo
/// feature. See the [module docs](self) for the effort-over-Equi-X construction and the
/// `nonce ‖ equix_solution` wire format.
pub struct EquiX {
	/// Which HashX runtime the underlying `equix` builder uses. Defaults to the portable
	/// interpreter ([`RuntimeOption::InterpretOnly`]); the optional pure-Rust JIT needs
	/// the `equix-compiler` feature and is selected via the builder runtime.
	runtime: RuntimeOption,
}

impl Default for EquiX {
	fn default() -> Self {
		// InterpretOnly is portable and needs no executable memory pages; server-side
		// verification cost is dominated by one HashX pass either way.
		Self { runtime: RuntimeOption::InterpretOnly }
	}
}

impl EquiX {
	/// A new EquiX backend using the portable HashX interpreter — the same as
	/// [`EquiX::default`], and the recommended default (no executable memory pages).
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}

	/// A new EquiX backend pinned to the portable HashX interpreter
	/// ([`RuntimeOption::InterpretOnly`]). Explicit alias for [`EquiX::new`] for call
	/// sites that pair it with [`EquiX::with_runtime`].
	#[must_use]
	pub fn interpret_only() -> Self {
		Self::with_runtime(RuntimeOption::InterpretOnly)
	}

	/// A new EquiX backend using `runtime`. The pure-Rust JIT
	/// ([`RuntimeOption::CompileOnly`] / [`RuntimeOption::TryCompile`]) is only compiled
	/// in under the `equix-compiler` feature; without it, `CompileOnly` builds fail and
	/// `TryCompile` falls back to the interpreter.
	#[must_use]
	pub fn with_runtime(runtime: RuntimeOption) -> Self {
		Self { runtime }
	}

	/// The HashX runtime option this backend is configured with. Note this is the
	/// *requested* option; the runtime actually selected for a given challenge (after any
	/// compiler fallback) is reported by [`EquiX::effective_runtime`].
	#[must_use]
	pub fn runtime_option(&self) -> RuntimeOption {
		self.runtime
	}

	/// The HashX runtime `equix` actually selects for `challenge` under this backend's
	/// configuration — the way to confirm the JIT engaged (or fell back to the
	/// interpreter). Returns `None` for the rare challenge HashX rejects on program
	/// constraints.
	#[must_use]
	pub fn effective_runtime(&self, challenge: &[u8]) -> Option<Runtime> {
		self.builder().build(challenge).ok().map(|instance| instance.runtime())
	}

	/// The `equix` builder configured for this backend's runtime.
	fn builder(&self) -> EquiXBuilder {
		let mut builder = EquiXBuilder::new();
		builder.runtime(self.runtime);
		builder
	}

	/// `SHA-256(challenge ‖ solution)` — the effort hash layered over Equi-X.
	fn effort_digest(challenge: &[u8], solution: &SolutionByteArray) -> [u8; 32] {
		let mut hasher = Sha256::new();
		hasher.update(challenge);
		hasher.update(solution);
		hasher.finalize().into()
	}

	/// Brute-force a full `nonce ‖ equix_solution` for `puzzle`: search nonces, solving
	/// Equi-X for `seed ‖ nonce` each time, until a solution also clears the effort
	/// target. This is the reference solver used by tests and native clients; cost grows
	/// with both the Equi-X base cost and `2^difficulty`, so callers should keep test
	/// difficulties small.
	#[must_use]
	pub fn solve(&self, puzzle: &Puzzle) -> Vec<u8> {
		let builder = self.builder();
		let mut nonce: u64 = 0;
		loop {
			let mut challenge = [0u8; CHALLENGE_LEN];
			challenge[..32].copy_from_slice(&puzzle.seed);
			challenge[32..].copy_from_slice(&nonce.to_be_bytes());
			// A small fraction of challenge strings yield no valid HashX program; the
			// `equix` API reports those as an error the solver must skip.
			if let Ok(solutions) = builder.solve(&challenge) {
				for solution in &solutions {
					let bytes = solution.to_bytes();
					if leading_zero_bits(&Self::effort_digest(&challenge, &bytes)) >= puzzle.difficulty {
						let mut out = Vec::with_capacity(SOLUTION_LEN);
						out.extend_from_slice(&nonce.to_be_bytes());
						out.extend_from_slice(&bytes);
						return out;
					}
				}
			}
			nonce = nonce.wrapping_add(1);
		}
	}
}

impl Pow for EquiX {
	fn new_puzzle(&self, difficulty: u32) -> Puzzle {
		let mut seed = [0u8; 32];
		rand::rng().fill_bytes(&mut seed);
		Puzzle { seed, difficulty }
	}

	fn verify(&self, puzzle: &Puzzle, solution: &[u8]) -> bool {
		if solution.len() != SOLUTION_LEN {
			return false;
		}
		let (nonce, equix_bytes) = solution.split_at(NONCE_LEN);
		let mut sol_bytes: SolutionByteArray = [0u8; EQUIX_SOLUTION_LEN];
		sol_bytes.copy_from_slice(equix_bytes);

		let mut challenge = [0u8; CHALLENGE_LEN];
		challenge[..32].copy_from_slice(&puzzle.seed);
		challenge[32..].copy_from_slice(nonce);

		// The Equi-X proof must be well-formed and valid for this exact challenge (this is
		// the costly-to-find, cheap-to-check half) ...
		if self.builder().verify_bytes(&challenge, &sol_bytes).is_err() {
			return false;
		}
		// ... and the solution must also clear the leading-zero-bit effort target, so a
		// raised difficulty actually costs the client more nonce searches.
		leading_zero_bits(&Self::effort_digest(&challenge, &sol_bytes)) >= puzzle.difficulty
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn solve_then_verify_roundtrips() {
		let pow = EquiX::new();
		// Difficulty 0: any well-formed Equi-X solution clears the (empty) effort target.
		let puzzle = pow.new_puzzle(0);
		let solution = pow.solve(&puzzle);
		assert_eq!(solution.len(), SOLUTION_LEN);
		assert!(pow.verify(&puzzle, &solution));
	}

	#[test]
	fn effort_solution_roundtrips() {
		let pow = EquiX::new();
		// A small effort target so the reference solver still returns quickly.
		let puzzle = pow.new_puzzle(4);
		let solution = pow.solve(&puzzle);
		assert!(pow.verify(&puzzle, &solution));
	}

	#[test]
	fn wrong_length_solution_is_rejected() {
		let pow = EquiX::new();
		let puzzle = pow.new_puzzle(0);
		assert!(!pow.verify(&puzzle, b""), "empty solution");
		assert!(!pow.verify(&puzzle, &[0u8; SOLUTION_LEN - 1]), "too short");
		assert!(!pow.verify(&puzzle, &[0u8; SOLUTION_LEN + 1]), "too long");
	}

	#[test]
	fn solution_is_bound_to_the_seed() {
		let pow = EquiX::new();
		let p1 = pow.new_puzzle(0);
		let solution = pow.solve(&p1);
		// The same solution against a different seed reconstructs a different Equi-X
		// challenge, so the proof no longer verifies.
		let p2 = Puzzle { seed: [0xABu8; 32], difficulty: 0 };
		assert!(!pow.verify(&p2, &solution));
	}

	#[test]
	fn tampered_solution_is_rejected() {
		let pow = EquiX::new();
		let puzzle = pow.new_puzzle(0);
		let mut solution = pow.solve(&puzzle);
		// Flip a byte inside the Equi-X solution portion; the proof must fail.
		let last = solution.len() - 1;
		solution[last] ^= 0x01;
		assert!(!pow.verify(&puzzle, &solution));
	}

	#[test]
	fn effort_target_is_enforced() {
		let pow = EquiX::new();
		// Find a valid Equi-X proof with no effort requirement ...
		let easy = pow.new_puzzle(0);
		let solution = pow.solve(&easy);
		assert!(pow.verify(&easy, &solution));
		// ... then demand far more effort of the *same* seed/nonce. The Equi-X proof is
		// still well-formed, but its effort hash (almost surely) misses 24 leading zero
		// bits, so the harder puzzle rejects it.
		let hard = Puzzle { seed: easy.seed, difficulty: 24 };
		assert!(!pow.verify(&hard, &solution));
	}

	#[test]
	fn new_puzzle_draws_distinct_seeds() {
		let pow = EquiX::new();
		assert_ne!(pow.new_puzzle(0).seed, pow.new_puzzle(0).seed);
	}

	#[test]
	fn equix_has_no_browser_solver() {
		// EquiX must keep the trait-default `None`: a browser can't solve it without WASM,
		// so a PowChallenge over it degrades rather than serving a mismatched solver.
		assert!(EquiX::new().interstitial_template().is_none());
	}

	#[test]
	fn default_and_new_are_interpret_only() {
		assert_eq!(EquiX::new().runtime_option(), RuntimeOption::InterpretOnly);
		assert_eq!(EquiX::default().runtime_option(), RuntimeOption::InterpretOnly);
		assert_eq!(EquiX::interpret_only().runtime_option(), RuntimeOption::InterpretOnly);
	}

	#[test]
	fn with_runtime_records_the_requested_option() {
		assert_eq!(EquiX::with_runtime(RuntimeOption::TryCompile).runtime_option(), RuntimeOption::TryCompile);
		assert_eq!(EquiX::with_runtime(RuntimeOption::CompileOnly).runtime_option(), RuntimeOption::CompileOnly);
	}

	#[test]
	fn interpret_only_reports_interpreter_as_effective_runtime() {
		// The configured option must actually reach the `equix` builder, not just be
		// stored: an InterpretOnly backend resolves to the interpreter for a real
		// challenge. (A fixed challenge string here is known to build successfully.)
		let pow = EquiX::interpret_only();
		assert_eq!(pow.effective_runtime(b"onyums-skin equix runtime probe"), Some(Runtime::Interpret));
	}

	#[cfg(feature = "equix-compiler")]
	#[test]
	fn try_compile_backend_still_solves_and_verifies() {
		// With the JIT compiled in, the TryCompile path must remain functionally
		// equivalent to the interpreter for solve/verify.
		let pow = EquiX::with_runtime(RuntimeOption::TryCompile);
		let puzzle = pow.new_puzzle(0);
		let solution = pow.solve(&puzzle);
		assert!(pow.verify(&puzzle, &solution));
	}
}

//! Proof-of-work: a swappable algorithm behind the [`Pow`] trait.
//!
//! The default is SHA-256 hashcash (MIT, pure Rust, near-free server verification) —
//! the correct asymmetry for an access gate. Heavier or "useful-work" backends
//! (Equi-X, RandomX) can implement [`Pow`] behind cargo features; they are never the
//! default. See `ROADMAP.md` §4.3 for the rationale, including why RandomX-WASM
//! mine-to-enter was rejected.

use rand::RngCore;
use sha2::{Digest, Sha256};

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
/// first.
fn leading_zero_bits(bytes: &[u8]) -> u32 {
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

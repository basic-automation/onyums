//! Proof-of-work: a swappable algorithm behind the [`Pow`] trait.
//!
//! The default is SHA-256 hashcash (MIT, pure Rust, near-free server verification) —
//! the correct asymmetry for an access gate. Heavier or "useful-work" backends
//! (Equi-X, RandomX) can implement [`Pow`] behind cargo features; they are never the
//! default. See `docs/skin.md` §4.3 for the rationale, including why RandomX-WASM
//! mine-to-enter was rejected.

/// A PoW puzzle handed to the client.
#[derive(Clone, Debug)]
pub struct Puzzle {
    pub seed: [u8; 32],
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

impl Pow for Hashcash {
    fn new_puzzle(&self, _difficulty: u32) -> Puzzle {
        // TODO(skin v0.1): random 32-byte seed at the requested difficulty.
        unimplemented!("hashcash puzzle generation — see docs/skin.md")
    }

    fn verify(&self, _puzzle: &Puzzle, _solution: &[u8]) -> bool {
        // TODO(skin v0.1): accept iff SHA-256(seed || solution) has >= difficulty
        // leading zero bits.
        unimplemented!("hashcash verification — see docs/skin.md")
    }
}

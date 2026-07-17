//! The text core of the server-rendered, no-JS CAPTCHA fallback.
//!
//! **This is one slice of the planned `CaptchaChallenge`, not the whole thing.** It owns the part
//! that has to be *correct* — generating the puzzle text and deciding whether a submitted
//! answer matches it. Rendering that text to a distorted image, and the [`Challenge`]
//! implementation that serves it, are the next slice; there is deliberately no
//! `impl Challenge` here yet, because a challenge that cannot present itself is not one.
//! See the crate `ROADMAP.md` (Phase 1, `CaptchaChallenge`).
//!
//! [`Challenge`]: super::Challenge

use rand::RngCore;

/// The character set puzzle text is drawn from: **uppercase letters and digits, minus every
/// visually confusable pair**.
///
/// The exclusions are the whole point, and they are what makes this a security-relevant
/// choice rather than a cosmetic one. A CAPTCHA's text is going to be *distorted on purpose*
/// and then read by a human through that distortion, so a glyph pair that is ambiguous when
/// clean is unreadable when warped. For each confusable family, at most one representative
/// is kept:
///
/// - `0`/`O`/`Q`/`D` — the round family; all four dropped.
/// - `1`/`I`/`J`/`L` — the vertical-stroke family; all four dropped.
/// - `2`/`Z`, `8`/`B`, `6`/`G` — dropped entirely (neither member is worth the risk).
/// - `5`/`S` — `5` kept, `S` dropped, since a distorted `S` is the ambiguous half.
///
/// What survives is the 21 glyphs above. The cost is entropy per character
/// (`log2(21) ≈ 4.39` bits vs `log2(36) ≈ 5.17` for the full alphanumeric set) — a real but
/// cheap price, since [`entropy_bits`] shows length buys it back far faster than the
/// alphabet does, and a failed *human* is a far worse outcome here than a slightly shorter
/// search space for a solver that is going to be OCR, not brute force.
pub const CAPTCHA_ALPHABET: &[u8] = b"ACEFHKMNPRTUVWXY34579";

/// The puzzle text for one CAPTCHA, and the authority on whether an answer matches it.
///
/// Hold this server-side (in the challenge's own state or a signed cookie); it is the
/// *answer*, so it must never be handed to the client except as the rendered image.
#[derive(Clone, PartialEq, Eq)]
pub struct CaptchaText(String);

impl CaptchaText {
	/// Generate fresh puzzle text of `len` characters drawn uniformly from
	/// [`CAPTCHA_ALPHABET`], using the OS CSPRNG (the same source the clearance store mints
	/// secrets from).
	///
	/// `len` is clamped to at least 1 — a zero-length CAPTCHA would accept the empty answer
	/// from anyone, which is worse than no gate at all, so it is not a representable state.
	#[must_use]
	pub fn generate(len: usize) -> Self {
		let len = len.max(1);
		let mut bytes = vec![0u8; len];
		rand::rng().fill_bytes(&mut bytes);
		// Modulo-biases toward the first `256 % 21` glyphs. Accepted deliberately: the bias is
		// under half a bit across a 21-glyph alphabet, and the threat here is OCR reading the
		// image, not an attacker exploiting a skewed distribution over a single-use puzzle that
		// expires in minutes. Rejection sampling would buy nothing an attacker cannot already
		// get by solving the image.
		let text = bytes.iter().map(|b| char::from(CAPTCHA_ALPHABET[usize::from(*b) % CAPTCHA_ALPHABET.len()])).collect();
		Self(text)
	}

	/// The puzzle text, for the renderer to draw. Not for sending to a client verbatim.
	#[must_use]
	pub fn as_str(&self) -> &str {
		&self.0
	}

	/// Whether a client-submitted answer matches, under the normalization a human typing
	/// what they saw actually needs: surrounding whitespace trimmed and case folded, because
	/// the image carries no case information a reader could honor and rejecting `abc` for
	/// `ABC` would fail humans for nothing.
	///
	/// The comparison is length-checked first and then folds every byte, so it does not
	/// return early on the first mismatching character. That is a cheap habit rather than a
	/// meaningful defense, and it is worth being honest about which: the answer is
	/// single-use and short-lived, and it arrives over a Tor circuit whose timing noise
	/// dwarfs the signal, so this is not load-bearing the way the clearance token's
	/// HMAC check is.
	#[must_use]
	pub fn matches(&self, submitted: &str) -> bool {
		let submitted = submitted.trim();
		if submitted.len() != self.0.len() {
			return false;
		}
		let mut diff = 0u8;
		for (expected, got) in self.0.bytes().zip(submitted.bytes()) {
			diff |= expected ^ got.to_ascii_uppercase();
		}
		diff == 0
	}
}

impl std::fmt::Debug for CaptchaText {
	/// Redacted: the answer must not reach a log line, and a `#[derive(Debug)]` on a struct
	/// holding one is how it would.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "CaptchaText(<redacted, {} chars>)", self.0.len())
	}
}

/// The entropy of `len` characters drawn from [`CAPTCHA_ALPHABET`], in bits — the size of
/// the guess space a solver faces if it cannot read the image at all.
///
/// Guessing is not the attack a CAPTCHA loses to (OCR is), so this is a floor to sanity
/// check a chosen length against, not a security claim: 6 characters is ~28 bits, which is
/// ample against blind guessing at any rate a rendezvous circuit can sustain.
#[must_use]
pub fn entropy_bits(len: usize) -> f64 {
	#[expect(clippy::cast_precision_loss, reason = "len and the alphabet size are tiny; f64 is exact well past any plausible value")]
	{
		(CAPTCHA_ALPHABET.len() as f64).log2() * len as f64
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn alphabet_excludes_every_confusable_glyph() {
		// The property, asserted rather than eyeballed against the const: no dropped glyph may
		// reappear if someone "helpfully" extends the alphabet later. `5` is absent from this
		// list on purpose — it is the *kept* half of the `5`/`S` pair.
		for confusable in b"01OQDIJL2ZS8B6G" {
			assert!(!CAPTCHA_ALPHABET.contains(confusable), "confusable glyph {} is back in the alphabet", char::from(*confusable));
		}
	}

	#[test]
	fn alphabet_is_unique_and_non_empty() {
		let mut seen = std::collections::HashSet::new();
		for glyph in CAPTCHA_ALPHABET {
			assert!(seen.insert(*glyph), "duplicate glyph {} skews the distribution", char::from(*glyph));
			assert!(glyph.is_ascii_uppercase() || glyph.is_ascii_digit(), "non-uppercase/digit glyph breaks the case-folding contract");
		}
		assert!(!CAPTCHA_ALPHABET.is_empty());
	}

	#[test]
	fn generated_text_has_the_requested_length_and_stays_in_the_alphabet() {
		for len in [1, 5, 6, 12] {
			let text = CaptchaText::generate(len);
			assert_eq!(text.as_str().len(), len);
			assert!(text.as_str().bytes().all(|b| CAPTCHA_ALPHABET.contains(&b)), "generated {} left the alphabet", text.as_str());
		}
	}

	#[test]
	fn zero_length_is_clamped_rather_than_accepting_everything() {
		let text = CaptchaText::generate(0);
		assert_eq!(text.as_str().len(), 1);
		// The point of the clamp: an empty answer must never clear the gate.
		assert!(!text.matches(""));
	}

	#[test]
	fn generation_is_not_deterministic() {
		// A CAPTCHA that repeats is a replay, not a challenge. 12 chars over a 21-glyph
		// alphabet makes a coincidental collision ~2^-52; a seeded/fixed RNG makes it certain.
		let a = CaptchaText::generate(12);
		let b = CaptchaText::generate(12);
		assert_ne!(a.as_str(), b.as_str());
	}

	#[test]
	fn matching_is_case_insensitive_and_whitespace_tolerant() {
		let text = CaptchaText("AC34".to_owned());
		assert!(text.matches("AC34"));
		assert!(text.matches("ac34"), "the image carries no case; rejecting lowercase fails humans for nothing");
		assert!(text.matches("  ac34\n"), "surrounding whitespace is a typing artifact");
	}

	#[test]
	fn matching_rejects_wrong_answers() {
		let text = CaptchaText("AC34".to_owned());
		for wrong in ["AC35", "AC3", "AC344", "", "   ", "XXXX", "a c34"] {
			assert!(!text.matches(wrong), "{wrong:?} must not clear the gate");
		}
	}

	#[test]
	fn debug_does_not_leak_the_answer() {
		// The answer reaching a log line would make the gate free to read for anyone with log
		// access; a plain derive is exactly how that happens.
		let text = CaptchaText("AC34".to_owned());
		let rendered = format!("{text:?}");
		assert!(!rendered.contains("AC34"), "the answer leaked into Debug: {rendered}");
		assert!(rendered.contains("redacted"));
	}

	#[test]
	fn entropy_is_reported_for_sizing_a_length() {
		// ~4.39 bits/char over 21 glyphs, so a 6-char puzzle is ~26 bits against blind guessing.
		assert!((entropy_bits(1) - 4.392_317_4).abs() < 1e-6);
		assert!(entropy_bits(6) > 26.0);
		assert_eq!(entropy_bits(0), 0.0);
	}
}

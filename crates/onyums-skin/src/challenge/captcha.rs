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

use super::png::GrayImage;

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

// --- Rendering: text → distorted grayscale image ---------------------------------------
//
// The part that has to be *correct* (which glyphs, the confusable-free alphabet, matching)
// lives above. This part has to be *hard to read by machine and easy by human* — a
// different bar, met by a hand-drawn 5×7 font, scaling, and a randomized warp/noise pass.
// It stays pure Rust (the font is data, the encoder is `super::png`), so no OCR-resistance
// dependency is taken.

/// A 5-wide × 7-tall bitmap font for [`CAPTCHA_ALPHABET`], **in the same order as that
/// constant**. Each glyph is seven rows; in each row the low five bits are columns
/// left→right (bit 4 = leftmost), a set bit meaning ink.
///
/// The order coupling to `CAPTCHA_ALPHABET` is asserted by a test, so a glyph can never
/// silently map to the wrong character if the alphabet is edited.
const GLYPHS: [[u8; 7]; 21] = [
	// A
	[0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
	// C
	[0b01111, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b01111],
	// E
	[0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111],
	// F
	[0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000],
	// H
	[0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
	// K
	[0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001],
	// M
	[0b10001, 0b11011, 0b10101, 0b10101, 0b10001, 0b10001, 0b10001],
	// N
	[0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001],
	// P
	[0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000],
	// R
	[0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001],
	// T
	[0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100],
	// U
	[0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
	// V
	[0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100],
	// W
	[0b10001, 0b10001, 0b10001, 0b10101, 0b10101, 0b11011, 0b10001],
	// X
	[0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001],
	// Y
	[0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100, 0b00100],
	// 3
	[0b11110, 0b00001, 0b00001, 0b01110, 0b00001, 0b00001, 0b11110],
	// 4
	[0b10001, 0b10001, 0b10001, 0b11111, 0b00001, 0b00001, 0b00001],
	// 5
	[0b11111, 0b10000, 0b10000, 0b11110, 0b00001, 0b00001, 0b11110],
	// 7
	[0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000],
	// 9
	[0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00001, 0b01110],
];

/// The 5×7 bitmap for a glyph, found by its position in [`CAPTCHA_ALPHABET`]. Characters
/// outside the alphabet (which [`CaptchaText`] never generates) render as a solid block, so
/// a stray glyph is visible rather than invisible.
fn glyph_for(c: u8) -> [u8; 7] {
	match CAPTCHA_ALPHABET.iter().position(|&a| a == c) {
		Some(idx) => GLYPHS[idx],
		None => [0b11111; 7],
	}
}

/// Font cell geometry, in source (unscaled) units.
const GLYPH_W: u32 = 5;
const GLYPH_H: u32 = 7;
/// One blank column between glyphs.
const GLYPH_GAP: u32 = 1;
/// Blank rows above/below the glyph row, giving the vertical warp somewhere to push ink
/// into without clipping it at the canvas edge.
const V_MARGIN: u32 = 2;
/// Scale factor from source font units to output pixels.
const SCALE: u32 = 8;

impl CaptchaText {
	/// The undistorted layout: the puzzle text drawn as scaled black glyphs on a white
	/// canvas, with no randomness. Deterministic for a given text — this is the legible
	/// baseline the distortion pass then warps, and the surface tests assert glyph shape
	/// against.
	fn layout(&self) -> GrayImage {
		let n = self.0.chars().count() as u32;
		// Width: n glyph cells, gaps between them, plus a one-glyph side margin each side.
		let cols = n * GLYPH_W + n.saturating_sub(1) * GLYPH_GAP + 2 * GLYPH_W;
		let rows = GLYPH_H + 2 * V_MARGIN;
		let mut img = GrayImage::new(cols * SCALE, rows * SCALE, 255);

		for (i, ch) in self.0.bytes().enumerate() {
			let glyph = glyph_for(ch);
			// Left edge of this cell, in source units (one-glyph margin + i cells).
			let cell_x = GLYPH_W + i as u32 * (GLYPH_W + GLYPH_GAP);
			for (row, bits) in glyph.iter().enumerate() {
				let src_y = V_MARGIN + row as u32;
				for col in 0..GLYPH_W {
					// Bit (GLYPH_W - 1 - col) is column `col` (bit 4 = leftmost).
					if bits & (1 << (GLYPH_W - 1 - col)) != 0 {
						fill_cell(&mut img, (cell_x + col) * SCALE, src_y * SCALE);
					}
				}
			}
		}
		img
	}

	/// Render the puzzle to a distorted grayscale image: [`layout`](Self::layout) warped by
	/// a randomized sine shear in both axes, then speckled with noise dots and a couple of
	/// stroke-through lines. The randomness comes from the OS CSPRNG, so the same text
	/// renders differently every time — a captured image cannot be replayed as a template.
	fn render(&self) -> GrayImage {
		let mut rng = rand::rng();
		let warped = warp(&self.layout(), &mut rng);
		add_noise(warped, &mut rng)
	}

	/// The puzzle rendered to PNG bytes, ready for a `data:` URI or an image route.
	#[must_use]
	pub fn to_png(&self) -> Vec<u8> {
		self.render().to_png()
	}
}

/// Paint one `SCALE × SCALE` source pixel as a block of black ink at output `(ox, oy)`.
fn fill_cell(img: &mut GrayImage, ox: u32, oy: u32) {
	for dy in 0..SCALE {
		for dx in 0..SCALE {
			img.set(ox + dx, oy + dy, 0);
		}
	}
}

/// A random `f64` in `[0, 1)` from the CSPRNG (no `rand` distribution import needed).
fn unit(rng: &mut impl RngCore) -> f64 {
	#[expect(clippy::cast_precision_loss, reason = "53-bit mantissa exactly represents the 53-bit value taken from the u64")]
	{
		(rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64
	}
}

/// Warp `src` by an independent sine shear on each axis: every output column is nudged
/// vertically and every output row horizontally, both by a smoothly varying amount. The
/// amplitudes, frequencies, and phases are randomized so the warp differs each render.
fn warp(src: &GrayImage, rng: &mut impl RngCore) -> GrayImage {
	let w = src.width();
	let h = src.height();
	let amp_y = 1.5 + unit(rng) * f64::from(SCALE) * 0.6; // vertical push, up to ~0.8 cells
	let amp_x = 1.0 + unit(rng) * f64::from(SCALE) * 0.5;
	let freq_y = 1.0 + unit(rng) * 2.0; // whole sine periods across the image
	let freq_x = 1.0 + unit(rng) * 2.0;
	let phase_y = unit(rng) * std::f64::consts::TAU;
	let phase_x = unit(rng) * std::f64::consts::TAU;
	let tau = std::f64::consts::TAU;

	let mut out = GrayImage::new(w, h, 255);
	for y in 0..h {
		for x in 0..w {
			let dy = amp_y * (tau * freq_y * f64::from(x) / f64::from(w) + phase_y).sin();
			let dx = amp_x * (tau * freq_x * f64::from(y) / f64::from(h) + phase_x).sin();
			// Sample the source at the pre-image of this output pixel (nearest neighbour).
			let sx = f64::from(x) + dx;
			let sy = f64::from(y) + dy;
			if sx >= 0.0 && sy >= 0.0 {
				#[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "sx/sy are guarded non-negative; the far edge is bounds-checked inside GrayImage::get, which returns paper out of range")]
				out.set(x, y, src.get(sx.round() as u32, sy.round() as u32));
			}
		}
	}
	out
}

/// Speckle `img` with random dark noise dots and a couple of thin sine "strike-through"
/// lines — cheap texture that ruins connected-component OCR without hiding the glyphs from
/// a human. Returns the same image for call chaining.
fn add_noise(mut img: GrayImage, rng: &mut impl RngCore) -> GrayImage {
	let w = img.width();
	let h = img.height();

	// Salt: ~4% of pixels flipped to a random gray. Dense enough to break thresholding,
	// sparse enough to leave the strokes readable.
	let dots = (u64::from(w) * u64::from(h)) * 4 / 100;
	for _ in 0..dots {
		let x = rng.next_u32() % w.max(1);
		let y = rng.next_u32() % h.max(1);
		let shade = (rng.next_u32() & 0x7F) as u8; // 0..127: dark-ish
		img.set(x, y, shade);
	}

	// Two wavy strike-through lines across the width.
	let tau = std::f64::consts::TAU;
	for _ in 0..2 {
		let base = unit(rng) * f64::from(h);
		let amp = f64::from(h) * 0.15 * unit(rng);
		let freq = 1.0 + unit(rng) * 2.0;
		let phase = unit(rng) * tau;
		for x in 0..w {
			let y = base + amp * (tau * freq * f64::from(x) / f64::from(w) + phase).sin();
			#[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "y is clamped into [0,h) by construction of base+amp within the canvas")]
			let yy = y.max(0.0) as u32;
			// A 2px-thick stroke so it survives the browser's downscaling.
			img.set(x, yy, 0);
			img.set(x, yy + 1, 0);
		}
	}
	img
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

	/// Count ink (non-paper) pixels in an image — a simple legibility/ink proxy for the
	/// render tests, which have no PNG decoder in scope.
	fn ink_pixels(img: &GrayImage) -> u32 {
		let mut ink = 0;
		for y in 0..img.height() {
			for x in 0..img.width() {
				if img.get(x, y) < 255 {
					ink += 1;
				}
			}
		}
		ink
	}

	#[test]
	fn glyph_table_aligns_with_the_alphabet() {
		// The coupling the const comment promises: one glyph per alphabet character, same
		// order. If this drifts, a character renders as some other character's shape.
		assert_eq!(GLYPHS.len(), CAPTCHA_ALPHABET.len(), "every alphabet glyph needs a bitmap and vice-versa");
		for (i, glyph) in GLYPHS.iter().enumerate() {
			let mut ink = 0;
			for row in glyph {
				assert!(*row < 32, "glyph {i} row uses more than 5 columns");
				ink += row.count_ones();
			}
			assert!(ink >= 5, "glyph {} ({}) is nearly blank — likely a transcription slip", i, char::from(CAPTCHA_ALPHABET[i]));
		}
	}

	#[test]
	fn glyph_lookup_is_by_alphabet_position() {
		// 'A' is index 0, '9' is the last; an unknown char is the solid fallback block.
		assert_eq!(glyph_for(b'A'), GLYPHS[0]);
		assert_eq!(glyph_for(b'9'), GLYPHS[GLYPHS.len() - 1]);
		assert_eq!(glyph_for(b'@'), [0b11111; 7], "an off-alphabet char renders as a visible block");
	}

	#[test]
	fn layout_is_deterministic_and_inked() {
		let text = CaptchaText("AC34".to_owned());
		let a = text.layout();
		let b = text.layout();
		assert_eq!((a.width(), a.height()), (b.width(), b.height()));
		// Deterministic: no randomness in layout, so the two are pixel-identical.
		for y in 0..a.height() {
			for x in 0..a.width() {
				assert_eq!(a.get(x, y), b.get(x, y), "layout must be deterministic at ({x},{y})");
			}
		}
		// Dimensions follow the documented formula: 4 cells + 3 gaps + 2-glyph margin, ×SCALE.
		let expected_cols = 4 * GLYPH_W + 3 * GLYPH_GAP + 2 * GLYPH_W;
		assert_eq!(a.width(), expected_cols * SCALE);
		assert_eq!(a.height(), (GLYPH_H + 2 * V_MARGIN) * SCALE);
		assert!(ink_pixels(&a) > 0, "the layout must actually draw the glyphs");
	}

	#[test]
	fn distinct_text_lays_out_differently() {
		let a = CaptchaText("AAAA".to_owned()).layout();
		let b = CaptchaText("5555".to_owned()).layout();
		let differs = (0..a.height()).any(|y| (0..a.width()).any(|x| a.get(x, y) != b.get(x, y)));
		assert!(differs, "two different puzzles must not render to the same glyphs");
	}

	#[test]
	fn render_is_inked_and_still_has_paper() {
		let img = CaptchaText("MHWXY7".to_owned()).render();
		let ink = ink_pixels(&img);
		let total = img.width() * img.height();
		assert!(ink > 0, "a rendered CAPTCHA has ink");
		assert!(ink < total, "a rendered CAPTCHA is not a solid block");
	}

	#[test]
	fn to_png_emits_a_valid_png_header() {
		let png = CaptchaText("AC34".to_owned()).to_png();
		assert_eq!(&png[0..8], &[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'], "PNG signature");
		assert!(png.len() > 100, "a rendered CAPTCHA PNG is more than a header");
	}

	#[test]
	fn render_is_randomized_across_calls() {
		// Distortion + noise are CSPRNG-driven, so the same text renders differently every
		// time; a captured image cannot be replayed as a template. A pixel-identical pair
		// over thousands of noise draws is astronomically unlikely.
		let text = CaptchaText("PRTUVW".to_owned());
		let a = text.to_png();
		let b = text.to_png();
		assert_ne!(a, b, "two renders of the same text must differ");
	}
}

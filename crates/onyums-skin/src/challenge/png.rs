//! A dependency-free grayscale PNG encoder, just enough to serve a CAPTCHA image.
//!
//! The CAPTCHA needs exactly one thing from PNG: turn an 8-bit grayscale pixel buffer
//! into a byte stream a browser will render inside `<img src="data:image/png;base64,…">`.
//! That is a *tiny* slice of PNG, and taking a full image crate for it would re-import the
//! heavy `image` tree the workspace has twice refused (once from `qrcode`, once when
//! auditing the `captcha` crate — see the crate `ROADMAP.md`). So this is hand-rolled and
//! stays pure Rust with no new dependency.
//!
//! The one trick that keeps it small: the IDAT stream is a zlib wrapper around **stored
//! (uncompressed) DEFLATE blocks** (`BTYPE=00`). A CAPTCHA image is a few kilobytes, and a
//! stored stream is a *valid* zlib stream that needs no compressor — every decoder (and
//! every browser) accepts it. We pay a modest size premium (no compression) to avoid
//! pulling in `flate2`/`miniz_oxide`. CRC-32 (chunk integrity) and Adler-32 (the zlib
//! trailer) are both a few lines each.

/// An 8-bit grayscale image: `0` = black ink, `255` = white paper.
///
/// Row-major, `width * height` bytes. Small by construction (a CAPTCHA banner), so it is
/// held as one owned buffer with no tiling.
pub(crate) struct GrayImage {
	width: u32,
	height: u32,
	pixels: Vec<u8>,
}

impl GrayImage {
	/// A `width × height` image filled with `fill` (use `255` for a white canvas to draw
	/// dark ink onto). `width`/`height` are clamped to at least 1 so the buffer is never
	/// empty and the PNG dimensions are always valid.
	pub(crate) fn new(width: u32, height: u32, fill: u8) -> Self {
		let width = width.max(1);
		let height = height.max(1);
		let pixels = vec![fill; (width as usize) * (height as usize)];
		Self { width, height, pixels }
	}

	pub(crate) fn width(&self) -> u32 {
		self.width
	}

	pub(crate) fn height(&self) -> u32 {
		self.height
	}

	/// Set the pixel at `(x, y)` to `value`, ignoring out-of-bounds coordinates so callers
	/// (the rasterizer, the distortion pass) can plot without bounds-checking every write.
	pub(crate) fn set(&mut self, x: u32, y: u32, value: u8) {
		if x < self.width && y < self.height {
			let idx = (y as usize) * (self.width as usize) + (x as usize);
			self.pixels[idx] = value;
		}
	}

	/// The pixel at `(x, y)`, or `255` (paper) for out-of-bounds reads.
	pub(crate) fn get(&self, x: u32, y: u32) -> u8 {
		if x < self.width && y < self.height { self.pixels[(y as usize) * (self.width as usize) + (x as usize)] } else { 255 }
	}

	/// Encode as an 8-bit grayscale PNG (color type 0), returning the complete file bytes.
	pub(crate) fn to_png(&self) -> Vec<u8> {
		let mut out = Vec::new();
		out.extend_from_slice(&PNG_SIGNATURE);

		// IHDR: width, height, bit depth 8, color type 0 (grayscale), default
		// compression/filter/interlace.
		let mut ihdr = Vec::with_capacity(13);
		ihdr.extend_from_slice(&self.width.to_be_bytes());
		ihdr.extend_from_slice(&self.height.to_be_bytes());
		ihdr.push(8); // bit depth
		ihdr.push(0); // color type: grayscale
		ihdr.push(0); // compression: deflate
		ihdr.push(0); // filter method: adaptive (with per-scanline filter bytes)
		ihdr.push(0); // interlace: none
		write_chunk(&mut out, b"IHDR", &ihdr);

		// Raw image data: each scanline is prefixed with a filter-type byte (0 = None).
		let mut raw = Vec::with_capacity((self.width as usize + 1) * self.height as usize);
		for y in 0..self.height {
			raw.push(0); // filter: None
			let start = (y as usize) * (self.width as usize);
			raw.extend_from_slice(&self.pixels[start..start + self.width as usize]);
		}
		write_chunk(&mut out, b"IDAT", &zlib_store(&raw));

		write_chunk(&mut out, b"IEND", &[]);
		out
	}
}

/// The 8-byte PNG file signature.
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];

/// Append a PNG chunk (`length‖type‖data‖CRC`) to `out`. The CRC covers the type and data.
fn write_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
	#[expect(clippy::cast_possible_truncation, reason = "PNG chunk lengths are u32 by spec; a CAPTCHA image is far under 4 GiB")]
	out.extend_from_slice(&(data.len() as u32).to_be_bytes());
	out.extend_from_slice(kind);
	out.extend_from_slice(data);
	let mut crc = Crc32::new();
	crc.update(kind);
	crc.update(data);
	out.extend_from_slice(&crc.finish().to_be_bytes());
}

/// Wrap `data` in a zlib stream built from **stored** (uncompressed) DEFLATE blocks: a
/// 2-byte zlib header, one or more `BTYPE=00` blocks, then the 4-byte Adler-32 trailer.
///
/// Stored blocks cap at 65_535 bytes each, so a large image splits across several; only
/// the final block has `BFINAL=1`.
fn zlib_store(data: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(data.len() + 16);
	// zlib header: CMF=0x78 (deflate, 32K window), FLG=0x01. (0x7801 % 31 == 0, as the
	// spec's check bits require, with no preset dictionary and fastest-compression level.)
	out.push(0x78);
	out.push(0x01);

	const MAX: usize = 65_535;
	if data.is_empty() {
		// A single empty final stored block keeps the stream well-formed.
		out.push(0x01); // BFINAL=1, BTYPE=00
		out.extend_from_slice(&0u16.to_le_bytes()); // LEN
		out.extend_from_slice(&(!0u16).to_le_bytes()); // NLEN = ~LEN
	} else {
		let mut offset = 0;
		while offset < data.len() {
			let end = (offset + MAX).min(data.len());
			let block = &data[offset..end];
			let is_final = end == data.len();
			out.push(u8::from(is_final)); // BFINAL bit, BTYPE=00
			#[expect(clippy::cast_possible_truncation, reason = "block length is capped at MAX = 65_535, which fits u16")]
			let len = block.len() as u16;
			out.extend_from_slice(&len.to_le_bytes()); // LEN
			out.extend_from_slice(&(!len).to_le_bytes()); // NLEN = one's complement of LEN
			out.extend_from_slice(block);
			offset = end;
		}
	}

	out.extend_from_slice(&adler32(data).to_be_bytes());
	out
}

/// Adler-32 checksum of `data` (the zlib trailer over the *uncompressed* bytes).
fn adler32(data: &[u8]) -> u32 {
	const MOD: u32 = 65_521;
	let mut a: u32 = 1;
	let mut b: u32 = 0;
	for &byte in data {
		a = (a + u32::from(byte)) % MOD;
		b = (b + a) % MOD;
	}
	(b << 16) | a
}

/// CRC-32 (IEEE, reflected polynomial `0xEDB88320`) — the PNG per-chunk checksum.
///
/// Table-driven, built once per instance; the images are small enough that a shared static
/// table would not pay for its `OnceLock`.
struct Crc32 {
	table: [u32; 256],
	value: u32,
}

impl Crc32 {
	fn new() -> Self {
		let mut table = [0u32; 256];
		let mut n = 0;
		while n < 256 {
			let mut c = n as u32;
			let mut k = 0;
			while k < 8 {
				c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
				k += 1;
			}
			table[n] = c;
			n += 1;
		}
		Self { table, value: 0xFFFF_FFFF }
	}

	fn update(&mut self, data: &[u8]) {
		for &byte in data {
			let idx = ((self.value ^ u32::from(byte)) & 0xFF) as usize;
			self.value = self.table[idx] ^ (self.value >> 8);
		}
	}

	fn finish(&self) -> u32 {
		self.value ^ 0xFFFF_FFFF
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Decode a stored-block zlib stream back to raw bytes — the inverse of [`zlib_store`],
	/// used only to prove the roundtrip. Because the encoder emits *only* stored blocks, the
	/// decoder is a handful of lines and needs no Huffman machinery.
	fn zlib_unstore(stream: &[u8]) -> Vec<u8> {
		assert!(stream.len() >= 6, "too short to hold a zlib header + trailer");
		assert_eq!(stream[0], 0x78, "zlib CMF");
		let body = &stream[2..stream.len() - 4]; // strip 2-byte header, 4-byte adler
		let mut out = Vec::new();
		let mut i = 0;
		loop {
			let header = body[i];
			let is_final = header & 1 == 1;
			assert_eq!(header & 0b110, 0, "only stored (BTYPE=00) blocks are emitted");
			i += 1;
			let len = u16::from_le_bytes([body[i], body[i + 1]]) as usize;
			let nlen = u16::from_le_bytes([body[i + 2], body[i + 3]]);
			assert_eq!(nlen, !(len as u16), "LEN/NLEN must be complementary");
			i += 4;
			out.extend_from_slice(&body[i..i + len]);
			i += len;
			if is_final {
				break;
			}
		}
		// The trailer must match Adler-32 of the reconstructed bytes.
		let adler = u32::from_be_bytes(stream[stream.len() - 4..].try_into().unwrap());
		assert_eq!(adler, adler32(&out), "adler trailer must checksum the decoded bytes");
		out
	}

	/// Walk the chunk list, verifying every CRC, and return (width, height, decoded pixels).
	fn decode_png(png: &[u8]) -> (u32, u32, Vec<u8>) {
		assert_eq!(&png[0..8], &PNG_SIGNATURE, "PNG signature");
		let mut i = 8;
		let mut dims = None;
		let mut idat = Vec::new();
		let mut saw_iend = false;
		while i < png.len() {
			let len = u32::from_be_bytes(png[i..i + 4].try_into().unwrap()) as usize;
			let kind = &png[i + 4..i + 8];
			let data = &png[i + 8..i + 8 + len];
			let crc = u32::from_be_bytes(png[i + 8 + len..i + 12 + len].try_into().unwrap());
			let mut c = Crc32::new();
			c.update(kind);
			c.update(data);
			assert_eq!(crc, c.finish(), "chunk {} CRC", String::from_utf8_lossy(kind));
			match kind {
				b"IHDR" => {
					let w = u32::from_be_bytes(data[0..4].try_into().unwrap());
					let h = u32::from_be_bytes(data[4..8].try_into().unwrap());
					assert_eq!(data[8], 8, "bit depth 8");
					assert_eq!(data[9], 0, "grayscale color type");
					dims = Some((w, h));
				}
				b"IDAT" => idat.extend_from_slice(data),
				b"IEND" => saw_iend = true,
				_ => {}
			}
			i += 12 + len;
		}
		assert!(saw_iend, "IEND terminator present");
		let (w, h) = dims.expect("IHDR present");
		// Undo the zlib + per-scanline filter-byte framing.
		let raw = zlib_unstore(&idat);
		let mut pixels = Vec::with_capacity((w * h) as usize);
		for y in 0..h as usize {
			let row = y * (w as usize + 1);
			assert_eq!(raw[row], 0, "filter byte is None");
			pixels.extend_from_slice(&raw[row + 1..row + 1 + w as usize]);
		}
		(w, h, pixels)
	}

	#[test]
	fn adler32_matches_known_vectors() {
		// The zlib spec's own examples.
		assert_eq!(adler32(b""), 1);
		assert_eq!(adler32(b"a"), 0x0062_0062);
		assert_eq!(adler32(b"abc"), 0x024D_0127);
		assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
	}

	#[test]
	fn crc32_matches_known_vectors() {
		let mut c = Crc32::new();
		c.update(b"123456789");
		assert_eq!(c.finish(), 0xCBF4_3926, "the canonical CRC-32/ISO-HDLC check value");
		let empty = Crc32::new();
		assert_eq!(empty.finish(), 0, "CRC of no bytes is 0 after the final xor");
	}

	#[test]
	fn png_roundtrips_a_small_gradient() {
		let mut img = GrayImage::new(9, 5, 255);
		for y in 0..img.height() {
			for x in 0..img.width() {
				img.set(x, y, ((x * 20 + y * 10) % 256) as u8);
			}
		}
		let png = img.to_png();
		let (w, h, pixels) = decode_png(&png);
		assert_eq!((w, h), (9, 5));
		assert_eq!(pixels.len(), 45);
		for y in 0..5u32 {
			for x in 0..9u32 {
				assert_eq!(pixels[(y * 9 + x) as usize], ((x * 20 + y * 10) % 256) as u8, "pixel ({x},{y}) survives the roundtrip");
			}
		}
	}

	#[test]
	fn png_roundtrips_a_multi_block_image() {
		// Wider than one stored block's 65_535-byte cap, forcing the split path (and the
		// non-final BFINAL=0 header) to be exercised.
		let mut img = GrayImage::new(300, 300, 0);
		for y in 0..img.height() {
			for x in 0..img.width() {
				img.set(x, y, ((x ^ y) & 0xFF) as u8);
			}
		}
		let png = img.to_png();
		let (w, h, pixels) = decode_png(&png);
		assert_eq!((w, h), (300, 300));
		assert_eq!(pixels.len(), 90_000);
		assert_eq!(pixels[0], 0);
		assert_eq!(pixels[(7 * 300 + 3) as usize], ((7u32 ^ 3) & 0xFF) as u8);
	}

	#[test]
	fn dimensions_are_clamped_away_from_zero() {
		let img = GrayImage::new(0, 0, 128);
		assert_eq!((img.width(), img.height()), (1, 1));
		let (w, h, pixels) = decode_png(&img.to_png());
		assert_eq!((w, h), (1, 1));
		assert_eq!(pixels, vec![128]);
	}

	#[test]
	fn out_of_bounds_writes_are_ignored_and_reads_return_paper() {
		let mut img = GrayImage::new(3, 3, 255);
		img.set(10, 10, 0); // no panic, no effect
		assert_eq!(img.get(10, 10), 255, "out-of-bounds read is paper");
		img.set(1, 1, 0);
		assert_eq!(img.get(1, 1), 0);
	}
}

# Roadmap progress log

Dated entries from the nightly dev routine. Each entry covers every increment landed
that night: the roadmap + item/slice it advances, the files touched, a one-paragraph
summary, the real build/test/clippy counts, what is done vs. still open, an explicit
STOP REASON, and the next step.

---

## 2026-06-18 — onyums-skin Phase 1 gate core (5 increments)

Branch `routine/onyums-2026-06-18` → PR (base `master`). The `onyums-skin` crate began
the night as a compiling skeleton with `unimplemented!()` bodies. This run built out the
bulk of **onyums-skin ROADMAP Phase 1 (Gate core, v0.1)** — the pure-Rust, zero-Tor HTTP
gate. No onyums-server (root) code changed; onyums Phase 0 was intentionally not started
this run (see stop reason). Workspace stayed green throughout.

Note: a human commit `a80af4a docs: add Phase 5 framework layer` (root `ROADMAP.md`,
docs-only) landed on the branch mid-run; it is carried along and does not change Phase 1
priority.

**Increment 0 — style (precursor).** `style(skin): apply rustfmt (hard tabs) to scaffold
modules` — the v0.1 scaffold had landed with 4-space indentation against a `rustfmt.toml`
that mandates `hard_tabs`. Normalized `challenge/mod.rs`, `circuit.rs`, `clearance.rs`,
`lib.rs` so the feature diffs sit on a rustfmt-compliant baseline. No behavior change.

**Increment 1 — Hashcash PoW.** *onyums-skin Phase 1, "Hashcash Pow (SHA-256 leading
zero bits)".* Files: `Cargo.toml`, `crates/onyums-skin/Cargo.toml`,
`src/challenge/pow.rs`. Replaced the `unimplemented!()` Hashcash bodies with a working
pure-Rust PoW over `sha2`: `new_puzzle` draws a random 32-byte seed (`rand`); `verify`
accepts iff `SHA-256(seed || solution)` has ≥ `difficulty` leading zero bits (near-free
server-side); `Hashcash::solve` is the reference brute-force solver for the future JS
interstitial and the tests. Added pure-Rust `sha2` + `rand` to `[workspace.dependencies]`.
**5 unit tests, all pass.**

**Increment 2 — HmacClearanceStore.** *onyums-skin Phase 1, "ClearanceStore over
hmac+sha2 … stateless mint/verify with expiry".* Files: `Cargo.toml`,
`crates/onyums-skin/Cargo.toml`, `src/clearance.rs`, `src/lib.rs`. Default
`ClearanceStore` signed with HMAC-SHA256; wire form `base64url(payload).base64url(tag)`
with payload `id|issued|expires|level`. `verify` checks the signature in constant time
(`Mac::verify_slice`) before trusting fields, then rejects expired tokens. Each `mint`
draws a fresh random 128-bit id (the rate-limit key / future single-use `jti`). Added
pure-Rust `hmac` + `base64`. **6 unit tests** (round-trip, id uniqueness, tampered-payload
forgery rejected, wrong-secret rejected, expired-but-signed rejected, malformed rejected).

**Increment 3 — SkinRateLimit.** *onyums-skin Phase 1, "SkinRateLimit over governor,
keyed on the clearance TokenId".* Files: `Cargo.toml`, `crates/onyums-skin/Cargo.toml`,
`src/ratelimit.rs`, `src/lib.rs`. Wrapped `governor` (the ROADMAP-locked rate-limit
choice) in a `SkinRateLimit` keying an independent GCRA bucket per `TokenId` — never an
IP. API: `new(Quota)`, `per_second(NonZeroU32)`, `check(&TokenId) -> bool`,
`retain_recent()`. Re-exports `governor::Quota` to prevent version skew. **2 unit tests**
(burst honored then throttled; keys have independent buckets).

**Increment 4 — PatienceChallenge.** *onyums-skin Phase 1, "PatienceChallenge (timed
tarpit, zero client compute) as the no-JS fallback".* Files: `src/challenge/patience.rs`
(new), `src/challenge/mod.rs`, `src/lib.rs`. A no-JS timed tarpit: the interstitial
reloads via `<meta http-equiv="refresh">` (no script, no compute). Stateless — the
"started waiting at T" ticket is a short-lived signed Patience-level `Clearance` (reuses
any `ClearanceStore`) in the `skin_patience` cookie; the gate passes once the clearance's
`issued` is `delay` in the past. Signing prevents forging an older `issued`. Carrier =
cookie (the cookie-vs-signed-path open question is noted in-code + ROADMAP). Fixed a
`collapsible_if` clippy warning with a let-chain (no `#![allow]`). **5 unit tests**.

**Increment 5 — ChallengeChain.** *onyums-skin Phase 1, "Challenge trait + Gate, with a
fallback chain".* Files: `src/challenge/mod.rs`, `src/lib.rs`. Ordered fallback selector
guaranteeing a no-JS client always has a path: `select(client_has_js)` returns the first
challenge whose JS requirement the client satisfies; `issue` fails closed
(`Gate::Reject`) when nothing fits; `verify` accepts if *any* challenge validates. JS
detection is the host's call (open question), not guessed from headers. **6 unit tests**.

### Verification (real counts)
- `cargo build --workspace`: **GREEN** (re-run green after each increment; one pre-existing
  transitive-dep future-incompat note for `proc-macro-error2`, not from our code).
- `cargo test -p onyums-skin`: **24 passed; 0 failed; 0 ignored** (final).
- `cargo clippy -p onyums-skin --all-targets`: **no warnings** (the one new `collapsible_if`
  was fixed directly, not allowed).
- onyums lib `test_serve` (real Tor network): **not run** — slow/network-bound by design.

### Done vs. open (onyums-skin Phase 1)
- DONE: Hashcash `Pow`; `HmacClearanceStore` (mint/verify + expiry); `SkinRateLimit`;
  `PatienceChallenge`; `ChallengeChain` fallback selector.
- OPEN: PoW-as-`Challenge` impl + JS interstitial page (needs puzzle-signing to stop
  seed-choice, and a nonce carrier decision); `CaptchaChallenge` (blocked on the `captcha`
  crate license audit — ROADMAP open question); `SkinLayer` tower middleware wiring
  inspect → clearance-check → challenge → rate-limit + the challenge-submission route;
  single-use/replay protection over the minted `jti`.
- NOT STARTED: onyums server Phase 0 (kill `ONION_NAME` singleton, per-request
  thread+runtime fix, readiness/shutdown handle).

**STOP REASON:** Landed 5 verifiable increments (top of the 2–4 bar). The remaining
Phase-1 items are larger, design-heavy integration pieces — the PoW `Challenge` +
interstitial needs a puzzle-signing and nonce-carrier decision, and the `SkinLayer`
middleware is a multi-part wiring slice — each better as its own focused increment than a
rushed sixth at wrap. Workspace is green; nothing is half-landed.

**NEXT STEP:** Implement the PoW `Challenge` (`PowChallenge`): HMAC-sign the puzzle seed
so a client can't pick an easy one, render the JS interstitial that solves it, read the
nonce back from a Skin-owned submission route, and mint a `ClearanceLevel::Pow` clearance
on success. Then the `SkinLayer` tower middleware to chain inspect → clearance → challenge
→ rate-limit.

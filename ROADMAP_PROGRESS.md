# Roadmap progress log

Dated entries from the nightly dev routine. Each entry covers every increment landed
that night: the roadmap + item/slice it advances, the files touched, a one-paragraph
summary, the real build/test/clippy counts, what is done vs. still open, an explicit
STOP REASON, and the next step.

---

## 2026-06-18 (run 3) — finish onyums Phase 0; begin Phase 2 Skin integration (4 increments)

Branch `routine/onyums-2026-06-18-3` → PR (base `master`). Same-day rerun: runs 1
and 2 had merged to `master` (PR #5, head `f71fcf5`), so this run branched fresh
off that updated `master`. It **completed onyums ROADMAP Phase 0** (the last open
items — the `ONION_NAME` singleton and the readiness/shutdown handle), then opened
**onyums Phase 2 (Skin integration)** now that onyums-skin Phase 1 is done: wired
the `SkinLayer` into the served `Router` and built the concrete `CircuitPolicy`
the rendezvous loop will drive. Workspace stayed green and clippy-clean throughout.

**Increment 1 — typed `OnionAddress` + thread it through serve.** *onyums Phase 0
groundwork (toward killing `ONION_NAME`) + Phase 1 "typed OnionAddress" helper.*
Files: `src/lib.rs`. Introduced an `OnionAddress` newtype (normalized to exactly
one trailing `.onion` suffix) and threaded it explicitly from the launched service
to the two consumers that read the global — `tls_acceptor` (cert SAN) and the
port-80→HTTPS redirect — so the serve path no longer touches the `static`.
`get_and_store_onion_name` became the side-effect-free, now-sync `get_onion_address`;
`initialize_onion_service` followed. The global was kept as a write-only compat shim
for `get_onion_name()` *in this increment only* (removed in increment 2), making
this a pure non-breaking refactor. **4 new unit tests** (bare/single/repeated-suffix
normalization, Display/`Into<String>`).

**Increment 2 — per-service handle builder; remove the `ONION_NAME` global.**
*onyums Phase 0, "Kill the global `ONION_NAME` singleton" + "First-class readiness +
graceful shutdown".* Files: `src/lib.rs`, `Cargo.toml`, `Cargo.lock`, `README.md`.
`OnionService::builder().router(app).nickname("x").serve().await?` bootstraps the
client and launches the service (address known immediately), runs the accept loop
on a spawned task, and returns an `OnionServiceHandle` exposing `onion_address()`,
`ready().await` (resolves on arti's status stream reaching *fully reachable* —
descriptor published, intro points satisfactory — the meaningful readiness, not
"address known"), and `shutdown().await` (cancels the loop via a `CancellationToken`
and joins; full teardown on drop). `serve(app, nickname)` is now a thin wrapper
preserving the "blocks until stop" contract. The handle holds the `TorClient` Arc so
the service's background machinery lives for the handle's lifetime; `launch_`/
`initialize_onion_service` gained `+ use<>` so the client can move into the handle
while the stream lives on (edition-2024 RPIT capture). Removed the global and the
public `get_onion_name()` (intended breaking change); README hello-world rewritten
to the builder. Added `tokio-util` (CancellationToken) to the workspace. **2 new
no-Tor unit tests** (builder rejects missing router / missing nickname, validated
before any bootstrap).

**Increment 3 — wire onyums-skin `SkinLayer` into the served Router.** *onyums Phase 2
(Skin integration), "Insert `SkinLayer` into the served `Router`" + "Expose it
through the builder — `.skin(SkinConfig)` … `.no_skin()`".* Files: `src/lib.rs`,
`Cargo.toml`, `Cargo.lock`. Now that onyums-skin Phase 1 is complete, onyums depends
on it (path dep via `[workspace.dependencies]`) and re-exports `onyums_skin` + `Skin`.
The builder gained `.skin(Skin)` (tune) and `.no_skin()` (the explicit opt-*down*);
with no choice, `Skin::secure_default()` (PoW + no-JS patience fallback + token rate
limiting) is applied — secure-by-default, you opt down never up. Modeled as a
`SkinChoice` enum and an extracted `apply_skin(router, choice)` seam. **2 new no-Tor
integration tests** drive the layered `Router` via `tower::ServiceExt::oneshot` (the
roadmap's "test harness without live Tor"): `no_skin` forwards (200 "ok"); the secure
default intercepts an uncleared request with the PoW interstitial and the app body
never leaks. Added a `tower` dev-dependency.

**Increment 4 — `AccountingCircuitPolicy` (skin Phase 2 first slice).** *onyums-skin
ROADMAP Phase 2, "CircuitPolicy + per-circuit accounting … CircuitAction including
Shutdown" + "Under Attack Mode".* Files: `crates/onyums-skin/src/circuit.rs`,
`crates/onyums-skin/src/lib.rs`. The trait/`CircuitAction`/`CircuitId`/`StreamTarget`
already existed; this added the concrete policy onyums' rendezvous loop will drive.
`AccountingCircuitPolicy` keeps cumulative `CircuitStats { streams, requests }` per
`CircuitId` and enforces opt-in circuit-breakers: `under_attack(true)` returns
`Challenge` on every new circuit (Under Attack Mode), `max_streams(n)` tears down a
stream-fanning circuit wholesale (`Shutdown`), `max_requests(n)` `Reject`s requests
past the cap. With no caps it is accept-all accounting substrate (`stats` for
observability/adaptive difficulty); `forget` lets the host drop torn-down circuits
(no stream-close hook). Panic-free under lock poisoning. **6 new unit tests**.

### Verification (real counts)
- `cargo build --workspace`: **GREEN** (re-run green after every increment; the one
  pre-existing `proc-macro-error2` future-incompat note is a transitive dep, not ours).
- `cargo test -p onyums --lib -- --skip test_serve`: **8 passed; 0 failed; 0 ignored**
  (1 filtered out = `test_serve`). Up from 1 (test_serve only) at run start.
- `cargo test -p onyums-skin`: **50 passed; 0 failed; 0 ignored** + **1 doc test passed**
  (up from 44 at run start).
- `cargo clippy --workspace --all-targets`: **0 warnings** (every increment fixed
  clippy directly — `unused async`, `missing_panics_doc`→poison-recover,
  `large_enum_variant`→Box, `derivable_impls`→`#[derive(Default)]`, `doc_markdown`;
  no `#[allow]` added).
- onyums lib `test_serve` (real Tor network): **not run** — slow/network-bound by design.

### Done vs. open
- **onyums Phase 0 (foundational refactors): DONE.** All three bullets are now closed —
  thread+runtime hack (run 2), `ONION_NAME` singleton killed (this run), first-class
  readiness + graceful shutdown handle (this run). `serve()` is a wrapper over the
  builder; the secure one-liner is unchanged.
- **onyums Phase 2 (Skin integration): STARTED.** DONE: `SkinLayer` inserted into the
  Router, secure-default-on with `.skin()`/`.no_skin()` builder controls.
- **onyums-skin Phase 2: STARTED.** DONE: `AccountingCircuitPolicy` (per-circuit
  accounting + caps + Under Attack Mode).
- OPEN (onyums Phase 2): drive `onyums_skin::CircuitPolicy` from `handle_stream_request`
  (map `CircuitAction` onto accept/challenge/reject/`shutdown_circuit`); the **Under
  Attack Mode** builder toggle; feed Skin's adaptive-difficulty signal from observed
  circuit/request rate. **Prerequisite:** onyums must first extract a real per-circuit
  identifier (`ConnectionInfo.circuit_id` is hardcoded `None` today) — that is Phase 4
  "enriched `ConnectionInfo`" and blocks the CircuitPolicy wiring.
- OPEN (onyums-skin Phase 2): time-windowed per-circuit *rate* (this slice is
  cumulative-count caps); per-circuit byte accounting; adaptive PoW difficulty.
- BLOCKED: `CaptchaChallenge` (skin Phase 1) — still on the `captcha` crate license audit.
- NOT STARTED: onyums Phase 1 (identity: `.ephemeral()`, BYO key, vanity mining),
  Phase 3 (TLS-first/strict), Phase 4 (observability/multi-service); skin Phase 3 (WAF).

**STOP REASON:** Landed 4 verifiable increments (top of the 2–4 bar), closing out the
entire onyums Phase 0 and opening Phase 2 Skin integration on both sides of the split.
The natural next item — driving `CircuitPolicy` from onyums' rendezvous loop — is
**blocked on a real prerequisite**: `handle_stream_request` has no per-circuit id to
key the policy on (`ConnectionInfo.circuit_id` is hardcoded `None`), so it needs the
Phase 4 `ConnectionInfo` circuit-id extraction first, and that work lives on the
live-Tor serve path this routine cannot runtime-verify — it deserves a dedicated start,
not a rushed late one. Everything is green, clippy-clean, and fully unit-tested where
no live Tor is required; nothing is half-landed.

**NEXT STEP:** Extract a real per-circuit identifier in onyums (enrich `ConnectionInfo`
so `circuit_id` is populated from the rendezvous/stream layer instead of `None`) — the
Phase 4 plumbing that unblocks Phase 2's `CircuitPolicy` wiring. Then drive
`AccountingCircuitPolicy` from `handle_stream_request`, mapping `CircuitAction::{Accept,
Challenge, Reject, Shutdown}` onto accept / the Skin gate / reject / `shutdown_circuit()`,
and add the **Under Attack Mode** builder toggle. In parallel-tractable, no-Tor work:
the skin-side time-windowed per-circuit rate cap (with an injectable clock for
testability) builds directly on this run's accounting.

---

## 2026-06-18 (run 2) — finish skin Phase 1 gate core + onyums Phase 0 slice (6 increments)

Branch `routine/onyums-2026-06-18-2` → PR (base `master`). Same-day rerun: the morning's
PR #4 (the previous entry) merged to `master`, so this run branched fresh off the updated
`master` (585bdcb). It **completed the onyums-skin Phase 1 gate core** — the PoW
`Challenge`, the `SkinLayer` middleware, replay protection, and the one-call secure
default — then took the first bounded **onyums Phase 0** slice (the per-request
thread+runtime fix) and cleared the root crate's clippy baseline. Workspace stayed green
and clippy-clean throughout.

**Increment 1 — PowChallenge (signed-puzzle JS PoW gate).** *onyums-skin Phase 1,
"Hashcash `Pow` … + the JS interstitial page that solves it."* Files:
`src/challenge/pow.rs`, `src/lib.rs`. The proof-of-work `Challenge`: `make_puzzle` packs
a random seed, difficulty, and expiry into an HMAC-SHA256 envelope handed to the client;
`open_puzzle` re-derives them from the *verified* envelope so a client can't pick an easy
seed, replay a stale puzzle, or downgrade difficulty. Submission rides the query string
(`?puzzle=&nonce=`) so `verify` needs only request `Parts` — no body buffering. `issue`
renders a self-contained interstitial with a plain-JS SHA-256 hashcash solver that mirrors
`Hashcash` exactly. `needs_js()` is true (chain falls back to patience/CAPTCHA for no-JS).
**9 new tests.**

**Increment 2 — SkinLayer gate middleware + builder.** *onyums-skin Phase 1, "`SkinLayer`
(tower middleware) wiring inspect → clearance-check → challenge → rate-limit, plus the
challenge-submission route."* Files: `Cargo.toml`, `crates/onyums-skin/Cargo.toml`,
`src/layer.rs` (new), `src/lib.rs`. `Skin` (Arc-shared config) + `SkinBuilder`
(secure-by-default: unset store ⇒ random HMAC store; empty chain ⇒ fail-closed 403). The
sync core `Skin::decide` runs the ROADMAP lifecycle minus WAF: valid clearance → rate-limit
on token id (429 on trip) → forward; submission to `/.skin/pow` → `verify` → mint clearance
+ 303 redirect with Set-Cookie; else present challenge / 403. `decide` is tower/async-free
(directly testable); `SkinService` is the thin `tower_layer::Layer`/`tower_service::Service`
wrapper (clone-and-swap, no body buffering). Added `tower-layer` to the workspace;
`tower-service`/`tower-layer` as skin deps; `tokio`+`http-body-util` dev-deps. **9 new
tests** incl. two `#[tokio::test]` end-to-end (cleared request reaches the app; uncleared
body never leaks).

**Increment 3 — single-use replay protection.** *onyums-skin Phase 1, "single-use replay
protection."* Files: `src/challenge/pow.rs`. Without it, one solved puzzle could be
resubmitted to mint unlimited clearances (unlimited rate-limit budget), defeating
"cost per identity." `PowChallenge` now records redeemed puzzle seeds in a bounded
`Mutex<HashMap<[u8;32], SystemTime>>`; `verify` clears a solved puzzle exactly once and
rejects replays, pruning entries against each puzzle's own expiry. Single-use on the
*solution*, not the clearance (which stays a multi-use session identity). **1 new test.**

**Increment 4 — Skin::secure_default() + doc example.** *onyums-skin Phase 1 "Done when"
(require the gate in a few lines; no-JS path always works).* Files: `src/layer.rs`,
`src/lib.rs`. One-call gate: JS PoW + no-JS patience fallback + token rate limiting + a
fresh random store, with a runnable doctest. Also refreshed the now-inaccurate crate-level
docs (the header still called the crate unimplemented scaffolding). **1 new unit test + 1
doc test.**

**Increment 5 — onyums Phase 0: drop per-request thread+runtime hack.** *onyums ROADMAP
Phase 0, "Fix the per-request thread+runtime hack."* Files: `src/lib.rs`.
`handle_tls_connection` previously spawned a fresh OS thread *and* a new current-thread
tokio runtime for every hyper request just to drive the async service setup, joining the
thread before returning the response future — the ROADMAP's "correctness and throughput
landmine." Now the per-connection axum service is built once by awaiting the always-ready
`IntoMakeServiceWithConnectInfo` on the existing runtime and bridged to hyper via
`hyper_util::service::TowerToHyperService` — no thread, no nested runtime, no join; the
service is reused across keep-alive requests. Removed the `#[allow(clippy::async_yields_async)]`
the old shape required. Not runtime-tested (live-Tor `test_serve` is network-bound).

**Increment 6 — clear onyums clippy baseline.** *Cross-cutting cleanup enabling Phase 0
work.* Files: `src/lib.rs`, `crates/onyums-skin/Cargo.toml`, `crates/onyums-skin/README.md`
(new). The root crate enables pedantic/nursery/cargo but had six latent warnings (never
surfaced because Phase 0 was untouched). Cleared all six with no `#[allow]`: uninlined
format args (×3), an underscore-bound-then-used `_begin`, a `case_sensitive_file_extension_comparisons`
on the `.onion` suffix normalization (rewritten to `format!("{}.onion",
name.trim_end_matches(".onion"))`, behavior-equivalent and also collapsing accidental
repeats), and onyums-skin's missing `package.readme` (added a README + the key).

### Verification (real counts)
- `cargo build --workspace`: **GREEN** (re-run green after every increment; the one
  pre-existing `proc-macro-error2` future-incompat note is a transitive dep, not our code).
- `cargo test -p onyums-skin`: **44 passed; 0 failed; 0 ignored** + **1 doc test passed**
  (final; up from 24 at start of run).
- `cargo clippy --workspace --all-targets`: **0 code warnings** (onyums root went from 6
  pre-existing → 0; onyums-skin clean throughout; no `#[allow]` added).
- onyums lib `test_serve` (real Tor network): **not run** — slow/network-bound by design.

### Done vs. open
- **onyums-skin Phase 1 (gate core): DONE.** Hashcash `Pow`; `PowChallenge` + JS
  interstitial + signed-puzzle/replay; `HmacClearanceStore`; `SkinRateLimit`;
  `PatienceChallenge`; `ChallengeChain`; `SkinLayer` + `SkinBuilder`; `Skin::secure_default()`.
  The "Done when" criteria are met: a plain axum app gates in one line, mints a stateless
  token, rate-limits by it, and a no-JS client always has a path.
- OPEN (skin Phase 1): `CaptchaChallenge` — still **blocked** on the `captcha` crate
  license audit (ROADMAP open question); not started, no dep added.
- onyums Phase 0: thread+runtime hack **DONE**; **OPEN**: kill the `ONION_NAME` singleton
  and the first-class readiness/graceful-shutdown handle (interdependent — see next step).
- NOT STARTED: skin Phase 2 (CircuitPolicy/Tor dimension), Phase 3 (WAF); onyums Phase 1
  (identity), Phase 2 (Skin integration — consumes the now-built skin API).

**STOP REASON:** Landed 6 verifiable increments (above the 2–4 bar), closing out the entire
onyums-skin Phase 1 gate core plus a clean onyums Phase 0 slice and clippy baseline. The
remaining workable items are either **blocked** (`CaptchaChallenge` on the license audit)
or a **large, interdependent refactor** (the `ONION_NAME` singleton kill is entangled with
the Phase 0 readiness/shutdown handle and ripples through `serve`, `tls_acceptor`,
`handle_stream_request`, and the public `get_onion_name` API — a breaking change best
designed as one focused increment). That refactor touches the live-Tor serve path, which
this routine cannot runtime-verify, so it deserves a dedicated start rather than a rushed
late-night one. Workspace is green and clippy-clean; nothing is half-landed.

**NEXT STEP:** onyums Phase 0 — kill the `ONION_NAME` global. Design a per-service handle
returned from the builder that exposes `onion_address()` / `ready()` / `shutdown()`
(CancellationToken), thread the onion name through `serve → handle_incoming_requests →
handle_stream_request`/`tls_acceptor` instead of the static, and replace the public
`get_onion_name()` poll-the-global pattern. Do it as one focused increment (it is a
breaking API change). Afterwards, onyums Phase 2 can begin wiring the now-complete
`onyums-skin` `SkinLayer` into the served `Router`.

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

# Onyums Skin — Roadmap

`onyums-skin` is a **"Cloudflare for Tor"** abuse-defense layer for onion services: a challenge /
proof-of-work gate, stateless clearance tokens as a synthetic per-client identity, token/circuit-
keyed rate limiting, no-JS fallbacks, a per-circuit policy hook, and (later) a pure-Rust WAF. It is
a standalone, framework-agnostic crate — usable by any `axum` app — that the onyums onion-service
server wires into its rendezvous-circuit loop.

This roadmap is also the crate's design record: it pins the threat model, the locked component
decisions, the API surface, and the phased plan to build them out.

---

## Guiding principles

1. **Tor-native substitutes, not IP-based defense.** Every mechanism Cloudflare keys on an IP is
   re-keyed onto the two handles a Tor onion service actually has: the **per-rendezvous-circuit**
   and an **app-issued clearance token**. If a design needs a client IP, ASN, geo, or TLS
   fingerprint, it is the wrong design for this crate.
2. **Secure and complete by default; you opt *down*, never *up*.** Mirrors onyums' frontier
   posture. The defaults are the safe, maximal configuration — a real gate, real rate limiting,
   real fallbacks. Relaxing them is an explicit, named choice.
3. **Framework-agnostic.** The HTTP half is a `tower`/`axum` `Layer` any app can use, Tor or not.
   The Tor half is a single `CircuitPolicy` trait the host (onyums) drives. The two are decoupled
   so the crate is useful — and testable — without a live Tor network.
4. **No-JS is a first-class client, not an afterthought.** Tor Browser "Safer"/"Safest" disable JS
   *and* WebAssembly. Skin must **degrade, never fail**: a no-JS client always has a path through
   the gate. Cloudflare never solved this; doing so is a differentiator.
5. **Cost, not prevention.** Synthetic identities (tokens, circuits) are inherently rotatable. The
   goal is never to stop rotation — it is to make each fresh identity cost a fresh proof-of-work
   solve. Tune the cost; don't chase an un-winnable absolute.
6. **100% Rust — no FFI, ever.** The entire crate is pure Rust: no C, C++, or Go bindings, no
   `cgo`, no linked system libraries — not in the default build and **not behind a feature flag
   either**. This rules out FFI-only options like a Coraza/ModSecurity WAF binding or a RandomX
   miner: if a capability can't be had in pure Rust, it doesn't ship. Licensing is **MIT** with
   **no copyleft in the default build**; the one feature-gated dependency is the pure-Rust `equix`
   PoW crate, gated for its LGPL license, not for any foreign code.
7. **Honest non-goals.** Skin reproduces the *per-server-logic* half of Cloudflare. It does **not**
   reproduce the global-anycast half: no volumetric L3/4 absorption, no IP/ASN/geo logic, no TLS
   fingerprinting, no global bot ML, no CDN edge distribution. Over Tor the IP-based ones are moot
   anyway, and Tor's rendezvous architecture already provides the origin-masking / no-inbound-ports
   posture Cloudflare Tunnel/Spectrum sell.

---

## The threat model that defines the design

A Tor onion service sees **none** of the signals Cloudflare's defenses are built on:

- **No client IP / ASN / geo.** Connections arrive over a rendezvous circuit; there is no source
  address anywhere in the protocol.
- **No client TLS fingerprint (JA3/JA4).** The app never receives a standard ClientHello.
- **Often no JavaScript or WASM.** Tor Browser "Safer" and "Safest" disable both.
- **The per-rendezvous-circuit is the only stable handle** — and a single client can open many
  circuits, and circuits are mutually indistinguishable. Arti's `RendRequest` exposes only
  `accept()` / `reject()`; `StreamRequest` exposes the requested target (port/host) plus
  `accept()` / `reject()` / `shutdown_circuit()`. PoW effort from the intro layer is **not**
  surfaced to the application.

**What survives, what breaks.** Everything that is pure request-logic (request inspection, header/
redirect rules, caching) ports directly. Everything keyed on network identity must be replaced by
the per-circuit handle plus a clearance token. The strongest *surviving* fingerprint is **JA4H**
(HTTP request shape — header order, method, cookies); the strongest *surviving* abuse economics is
**proof-of-work**; the only forgery-resistant per-client counter key is a **signed token**.

---

## Architecture

### Shape

```
onyums-skin (MIT, pure-Rust default build)
├── tower/axum Layer  ──────────────►  any axum app  (WAF, gate, token check, rate limit)
└── CircuitPolicy hook  ────────────►  onyums wires to RendRequest / StreamRequest
```

A non-Tor axum app gets the WAF / challenge / rate-limit value through the `Layer` alone. onyums
additionally implements `CircuitPolicy` to add the per-circuit dimension a normal HTTP app can't
express.

### Component decisions (locked)

| Component | Decision | Crate / basis | License |
|---|---|---|---|
| PoW | **Build**, pluggable `Pow` trait, **SHA-256 hashcash default** | hand-rolled (~50 LOC); pure-Rust Equi-X as an optional (LGPL) backend | MIT |
| Rate limiter | **Reuse** | `governor` + `tower_governor` (key is generic → key on token) | MIT/Apache |
| Clearance token | **Reuse** | `jsonwebtoken`, or `hmac`+`sha2` for a minimal internal token | MIT |
| No-JS CAPTCHA | **Reuse** | `captcha` / `easy-captcha` (GIF) — server-rendered, no JS | audit `captcha` |
| WAF | **Build** (deferred) | pure Rust: `wirefilter` + `regex` + `aho-corasick` | MIT |
| Orchestration glue | **Build** | this crate | MIT |

**Why hashcash default, not RandomX or Equi-X:** production gates (Anubis, mCaptcha) all use
lightweight throwaway PoW with near-free server verification — the correct asymmetry for an access
gate. SHA-256 hashcash is MIT, pure Rust, no FFI, no copyleft. RandomX-WASM mine-to-enter was
evaluated and rejected: WASM is disabled at Tor "Safer"/"Safest", RandomX can't JIT or do directed
rounding in WASM, browser yield is micro-cents, and browser mining is uniformly flagged as malware.
Equi-X — Tor's own puzzle, available as the pure-Rust (LGPL) `equix` crate — is implementable behind
the `Pow` trait as an opt-in, license-gated feature. A RandomX backend would require C++ FFI and is
therefore ruled out by the 100%-Rust commitment.

### Core API sketch

```rust
// Clearance — the synthetic identity. Stateless, signed; the rate-limiter key.
pub struct Clearance { pub id: TokenId, pub issued: SystemTime, pub expires: SystemTime, pub level: ClearanceLevel }
pub trait ClearanceStore {
    fn mint(&self, level: ClearanceLevel, ttl: Duration) -> String;  // HMAC-SHA256 / JWT
    fn verify(&self, token: &str) -> Option<Clearance>;
}

// Challenge — pluggable, no-JS-aware gate.
pub enum Gate { Pass(ClearanceLevel), Present(Response), Reject }
pub trait Challenge: Send + Sync {
    fn issue(&self, req: &Parts) -> Gate;
    fn verify(&self, req: &Parts) -> bool;
    fn needs_js(&self) -> bool;   // drives no-JS fallback selection
}

// Pow — swappable algorithm; server verify must be ~free.
pub trait Pow: Send + Sync {
    fn new_puzzle(&self, difficulty: u32) -> Puzzle;
    fn verify(&self, puzzle: &Puzzle, solution: &[u8]) -> bool;
}
pub struct Hashcash;   // default; pure-Rust EquiX behind an opt-in (LGPL) feature

// CircuitPolicy — the Tor dimension; onyums drives this.
pub enum CircuitAction { Accept, Challenge, Reject, Shutdown }
pub trait CircuitPolicy: Send + Sync {
    fn on_new_circuit(&self, id: &CircuitId) -> CircuitAction;
    fn on_new_stream(&self, id: &CircuitId, target: &StreamTarget) -> CircuitAction;
    fn on_request(&self, id: &CircuitId) -> CircuitAction;
}
```

Building the gate is plumbing the existing primitives (`governor`, `jsonwebtoken`, `captcha`)
together with the novel glue (challenge issuance, difficulty tuning, single-use/expiry/replay
protection, the interstitial, the no-JS fallback, and binding a solved challenge to a minted token).
That glue has no drop-in Rust library and is the reason this crate exists.

### Request lifecycle

```
incoming circuit ─► CircuitPolicy.on_new_circuit
                      │ Reject/Shutdown ─► drop
                      ▼ Accept/Challenge
   stream ─► CircuitPolicy.on_new_stream (target port/host)
                      ▼
   HTTP request ─► [SkinLayer tower middleware]
        1. WAF inspect (phase 3)        ─► block ─► 403
        2. clearance cookie/path valid? ─► no ─► Challenge.issue ─► interstitial / Reject
        3. rate limit (key=TokenId)     ─► exceeded ─► challenge / 429
        4. pass ─► inner axum Router
```

Challenge submission (PoW nonce / CAPTCHA answer) hits a Skin-owned route, which on
`Challenge.verify` mints a `Clearance` and redirects back.

### Module layout

```
onyums-skin/
├── ROADMAP.md           // this document
├── Cargo.toml
└── src/
    ├── lib.rs           // SkinLayer (tower), builder, re-exports
    ├── clearance.rs     // Clearance, ClearanceStore (hmac/jwt)
    ├── challenge/
    │   ├── mod.rs       // Challenge trait, Gate, chain/fallback
    │   ├── pow.rs       // Pow trait + Hashcash; interstitial page
    │   ├── captcha.rs   // CaptchaChallenge (reuse `captcha`/`easy-captcha`)   [phase 1]
    │   └── patience.rs  // PatienceChallenge (no-JS tarpit)                    [phase 1]
    ├── ratelimit.rs     // SkinRateLimit over `governor`
    ├── circuit.rs       // CircuitPolicy trait, CircuitAction, accounting       [phase 2]
    └── waf/             // wirefilter + regex + aho-corasick                    [phase 3]
```

---

## Phases

### Phase 1 — Gate core — `v0.1`

The HTTP gate, usable by any axum app, with zero Tor coupling.

- `ClearanceStore` over `hmac`+`sha2` (minimal internal token) and/or `jsonwebtoken`; stateless
  mint/verify with expiry and single-use replay protection.
- `Challenge` trait + `Gate`, with a fallback chain.
- `Hashcash` `Pow` (SHA-256 leading-zero-bits) + the JS interstitial page that solves it.
- `CaptchaChallenge` (server-rendered image/GIF, no JS) and `PatienceChallenge` (timed tarpit,
  zero client compute) as the no-JS fallbacks.
- `SkinRateLimit` over `governor`, keyed on the clearance `TokenId`.
- `SkinLayer` (tower middleware) wiring inspect → clearance-check → challenge → rate-limit, plus the
  challenge-submission route.

**Done when:** a plain axum app can, in a few lines, require a PoW-or-CAPTCHA gate that mints a
stateless clearance token and rate-limits by that token; a no-JS client always has a working path;
server-side verification is ~free.

### Phase 2 — Tor dimension & Under Attack Mode — `v0.2`

The per-circuit handle that a normal HTTP app cannot express.

- `CircuitPolicy` + per-circuit accounting (streams, request rate, bytes); `CircuitAction` including
  `Shutdown` → Arti `shutdown_circuit()`.
- onyums adapter wiring `CircuitPolicy` to `RendRequest` / `StreamRequest`, generalizing the
  one-off port-443/80 gate currently in onyums' `handle_stream_request`.
- **Under Attack Mode** — a toggle that forces every new circuit through the gate before serving.
- **Adaptive PoW difficulty** — dormant under normal load, raised under attack, driven by
  app-observable request rate (the intro-layer PoW effort is not exposed by Arti, so the app rate is
  the signal). Mirrors Tor's own PoW effort control loop, one layer up.

**Done when:** onyums can gate per circuit, escalate difficulty under load, cap per-circuit
concurrency, and tear down abusive circuits wholesale.

### Phase 3 — WAF — `v0.3`

Request inspection — 100% IP-free, the cleanest Cloudflare carry-over.

- Pure-Rust engine: `wirefilter` for the rule/expression language, `regex` + `aho-corasick` for
  multi-signature matching, evaluated as a `tower` layer over request URI/method/headers/body.
  > **`wirefilter` dependency blocker (found 2026-06-24).** The only crates.io-published
  > wirefilter is `wirefilter-engine` 0.6.1 (MIT, last released ~2019). It compiles on the
  > current toolchain but transitively pulls in the **unmaintained `failure`** crate
  > (RUSTSEC-2020-0036) plus a duplicate `syn 1.0` / `synstructure 0.12`, and the superseded
  > `cidr 0.1`, `bitstring 0.1`, `memmem 0.1`, `indexmap 1.9`. For a crate whose thesis is a
  > clean, audited, pure-Rust, copyleft-free tree, adding an unmaintained transitive dep to a
  > *security* layer is a human sign-off decision, not a default. **Resolve before adopting:**
  > (a) vendor/fork wirefilter onto a maintained error stack (drop `failure`), (b) accept the
  > dep with an explicit `cargo-deny` advisory exception, or (c) keep the `regex` `RegexSet`
  > engine and build a minimal pure-Rust filter front-end (the rule/expression language is the
  > only thing wirefilter adds — signature matching is already covered). The starter ruleset and
  > anomaly-scoring model below do not depend on this choice.
  >
  > **Pursuing (c) — AST + evaluator landed (2026-06-28).** `filter::FilterExpr` is a typed
  > boolean expression tree (`Field` ∈ {method, path, query, header} — the Tor-surviving
  > dimensions — × `StrOp` ∈ {eq, not_eq, contains, starts/ends_with, regex `Matches`, `Exists`},
  > combined with `And`/`Or`/`Not`/`Always`/`Never`) evaluated directly against `Parts`. No parser
  > dependency, no `failure`, no advisory exception — it replaces only wirefilter's *expression*
  > layer. Absent fields are false except `Exists` (WAF-safe). 9 unit tests. The **string-syntax
  > parser is the next slice**; this AST is what such a parser targets and what operator-tunable
  > WAF/edge rule conditions evaluate.
- A curated starter ruleset (SQLi / XSS / path traversal / OS command injection / SSRF /
  server-side code injection / NoSQL / LDAP / XXE / protocol anomalies); not OWASP-CRS-complete
  at first, but extensible with custom rules, per-rule/category disabling, and operator-tunable
  per-category anomaly weights.
- No Go/cgo/FFI — the 100%-Rust commitment rules out a Coraza/ModSecurity binding outright, so
  OWASP-CRS coverage is reached by porting rules into the pure-Rust engine, never by linking a
  foreign one.

**Done when:** signature attacks are blocked with no IP dependency, rules are operator-extensible,
and the engine runs ahead of the gate in the layer order.

### Phase 4 — Observability & adaptive defense — `v0.4`

You can't tune what you can't see, and adaptivity needs a baseline.

- **Structured security events** — challenge issued/passed/failed, WAF blocks, rate-limit trips,
  circuit teardowns — emitted as typed events, not just `tracing` logs.
- **Per-token / per-circuit metrics** — active circuits, gate pass rates, difficulty in play.
- **Request-shape baselining** — learn the normal distribution of HTTP-only dimensions (UA mix,
  path mix, header shape) and flag deviation, the no-IP analog of Cloudflare's adaptive DDoS
  baselining and its `dosd` "self-select the most discriminating field" logic, restricted to
  fields that survive Tor.
- Feeds onyums' own Phase 4 observability.

**Done when:** an operator can see what is being blocked and why, and adaptive difficulty is driven
by deviation-from-baseline, not just raw request rate.

### Phase 5 — Frontier defenses — `v0.5+`

The research-grade, Tor-specific bets — none have prior art in this environment.

- **JA4H-style HTTP fingerprinting** — cluster/identify clients by request shape (header order,
  method, cookie names), the strongest fingerprint that survives the loss of IP and TLS. A weak
  signal alone, but a useful input to difficulty and bot heuristics.
- **Heuristic bot detection on request shape** — the *only* Cloudflare bot signal that survives Tor
  (identity-free header/UA/request-shape pattern matching); ML bot scoring does not port.
- **Restricted-discovery orchestration** — helpers that bridge onyums' Arti client-authorization
  (restricted discovery, stable in Arti 1.7) into Skin's policy as the strongest, upstream gate: an
  allowlist enforced in descriptor crypto before any traffic arrives.
- **Pluggable PoW backend** — `EquiX`, Tor's own puzzle via the pure-Rust `equix` crate, behind an
  opt-in (LGPL) cargo feature. RandomX "useful-work" mining stays excluded: it would require C++
  FFI, and was independently rejected on Tor-WASM and reputation grounds.
  > **Implemented (2026-06-27).** `challenge::equix::EquiX` implements `Pow` behind the opt-in
  > `equix` feature (`equix` 0.6.2, `default-features = false` → portable HashX interpreter; the
  > pure-Rust JIT is reachable via `equix-compiler`). A single Equi-X solution is fixed-cost, so
  > the backend layers an SHA-256 leading-zero-bit *effort* check over the proof (as Tor's PoW
  > protocol does), making `difficulty` read identically to `Hashcash` and the Adaptive/Shape
  > controllers drive it unchanged. Default build stays copyleft-free. No browser solver (needs
  > WASM); `Hashcash` remains the JS-interactive default.
- **Multi-instance coordination** — share a clearance-signing secret across Onionbalance backends so
  a token minted at one backend is honored at another.
  > **Implemented (2026-06-28).** `HmacClearanceStore::derived(secret, context)` derives the
  > signing key as `HMAC-SHA256(secret, "onyums-skin/clearance-signing/v1" ‖ context)`, so every
  > backend configured with the same passphrase + context produces the identical 256-bit key and
  > honors each other's tokens — no raw-key distribution, domain-separated by context.
  > `with_verify_key` adds verify-only keys so a backend mints under a new secret while still
  > accepting tokens from fleet members on a previous one (zero-downtime rotation); `verify` tries
  > the primary then each extra key, and still rejects an unrelated secret. Pure `hmac`+`sha2`, no
  > new dependency. 5 unit tests (cross-honoring, context separation, rotation accept, mint-under-
  > primary, unknown-key-still-rejected).
- **Edge-rules & caching** — local response cache and transform/redirect middleware (low effort;
  onyums already ships the HTTP→HTTPS upgrade as one such rule).
  > **Transform/redirect half implemented (2026-06-28).** `edge::EdgeRules` is an ordered
  > match→action engine (`EdgeMatch`: path/prefix/method/host/header + All/AnyOf combinators;
  > `EdgeAction`: redirect / block / set-or-remove response header) evaluated to a decision-only
  > `EdgeDecision` ahead of the gate — pure request logic, no IP signals, fully offline-testable.
  > `EdgeRules::https_upgrade()` expresses the canonical HTTP→HTTPS upgrade as one rule (the host
  > installs it on its plaintext listener, since Skin sees no scheme in `Parts`).
  > **Response cache half implemented (2026-06-28).** `cache::ResponseCache` is a bounded,
  > TTL-expiring in-process cache keyed on `(method, host, path+query)` — pure request logic, no
  > IP — over the crate's injectable `Clock` (deterministic expiry tests). Only `GET`/`HEAD` are
  > cacheable; `cache_control_ttl` reads the origin `Cache-Control` so `no-store`/`no-cache`/
  > `private` is never cached and `max-age` is honoured; a full cache purges expired entries then
  > evicts the nearest-to-expiry one. Over an onion service this is a latency win (a rendezvous
  > round-trip is expensive), not the bandwidth/CDN win Skin's non-goals exclude. **The Phase 5
  > edge-rules & caching item is now implemented** (both halves); wiring either into `SkinLayer`
  > is a follow-up host-integration slice.

---

## The no-JS strategy (explicit)

Because Tor "Safer"/"Safest" kill JS *and* WASM, Skin must degrade rather than fail:

1. **Default**: PoW challenge for JS clients (cheap, no tracking).
2. **No-JS detected / configured**: fall back to a **server-rendered CAPTCHA** (answer via a plain
   `<form>`) or a **patience tarpit** (timed delay, zero client compute).
3. **Strongest gate, when applicable**: Tor **restricted discovery** (allowlist of client keys) —
   cryptographic access control *upstream* of any challenge. Managed in onyums/arti config; Skin
   composes with it (Phase 5).

Carrier for the clearance under no-JS — cookie vs. signed URL path segment — is an open question
(below); Tor Browser's per-circuit cookie behavior needs testing.

---

## Licensing

Target **MIT** for the crate, with all default dependencies permissive: `governor`, `jsonwebtoken`,
`hmac`/`sha2`, `captcha` (pending license audit; `easy-captcha` is a fallback), `regex`/
`aho-corasick`, `wirefilter` (Apache-2.0). The crate is **100% pure Rust — no FFI in any build,
default or feature-gated** (this excludes a Coraza/ModSecurity WAF binding and any RandomX backend).
**No copyleft in the default build.** The single feature-gated dependency is the pure-Rust `equix`
PoW crate, gated solely because it is LGPL-3.0, keeping the default build copyleft-free.

---

## Developer experience

- **Re-export the load-bearing types** (e.g. the `governor` key types) so downstream users can't get
  version-skewed.
- **A test harness that needs no live Tor network** — the framework-agnostic `Layer` is testable as
  a plain axum app; the `CircuitPolicy` is a trait that can be driven by a mock loop.
- **Document the opt-downs loudly.** Because the crate is secure-by-default, the docs must make the
  *relaxations* (ephemeral gate, lower difficulty, disabled WAF, single-onion mode) explicit — a
  user should always know what they turned off.

---

## Risks & open questions

- **arti API churn** — restricted discovery and service-PoW are newer in arti; the Tor dimension
  (Phase 2/5) tracks arti's frontier and must budget for breaking bumps.
- **Clearance carrier under no-JS** — cookie vs. signed URL path segment vs. both; Tor Browser
  cookie behavior across circuits needs testing.
- **Circuit ↔ token binding** — should a clearance be pinned to the circuit it was minted on, or
  float across circuits? Pinning is stronger but breaks legitimate circuit rotation.
- **Adaptive-difficulty signal** — app-observable request rate is the only input (intro-layer PoW
  effort is not surfaced by Arti); what window and curve?
- **CAPTCHA license** — audit the `captcha` crate's non-standard license before depending on it.
- **WAF scope** — a hand-rolled pure-Rust ruleset will not reach OWASP-CRS parity quickly; set
  expectations. The 100%-Rust rule means there is no Coraza-FFI escape hatch, so CRS coverage is a
  rule-porting effort.
- **`wirefilter` supply chain** — the published `wirefilter-engine` 0.6.1 drags in the
  unmaintained `failure` crate (RUSTSEC-2020-0036) and several superseded deps (see the Phase 3
  blocker note). Decide vendor-fork vs. advisory-exception vs. a minimal in-house filter
  front-end before the rule-expression language adds this dependency.

---

## Relationship to the onyums roadmap

Skin is the concrete, standalone form of onyums Roadmap **Phase 2 (abuse resistance)** plus its WAF
pillar. The Tor-native layers that live *below* the application — restricted discovery, service-side
PoW, intro/stream rate limits — stay in onyums/arti config (onyums Roadmap Phase 2, pillar 6); Skin
composes with them rather than reimplementing them. See [../../ROADMAP.md](../../ROADMAP.md).

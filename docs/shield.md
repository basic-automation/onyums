# Onyums Shield — design doc

Status: **draft / design**. This document pins the architecture and API surface for onyums's
"Cloudflare for Tor" abuse-defense layer **before** any code is written. It is the output of a
research pass into Cloudflare's defenses, the Tor onion-service threat model, and the Rust crate
ecosystem.

---

## 1. The problem that defines the design

A Tor onion service sees **none** of the signals Cloudflare's defenses are built on:

- **No client IP / ASN / geo.** Connections arrive over a rendezvous circuit; there is no source
  address anywhere in the protocol.
- **No client TLS fingerprint (JA3/JA4).** The app never receives a standard ClientHello.
- **Often no JavaScript.** Tor Browser "Safer" and "Safest" disable JS *and WebAssembly*.
- **The per-rendezvous-circuit is the only stable handle** — and a single client can open many
  circuits, and circuits are mutually indistinguishable. Arti's `RendRequest` exposes only
  `accept()` / `reject()`; `StreamRequest` exposes the requested target (port/host) plus
  `accept()` / `reject()` / `shutdown_circuit()`.

Therefore every IP-keyed mechanism must be replaced by a **Tor-native substitute**: the per-circuit
handle, plus an **app-issued clearance token** that acts as a synthetic, rotatable-but-costly client
identity. Everything that is pure request-logic (WAF, header/redirect rules, caching) ports
directly.

**Honest non-goals.** Shield does *not* reproduce the half of Cloudflare that is a global anycast
network: no volumetric L3/4 absorption, no IP/ASN/geo logic, no TLS fingerprinting, no global bot
ML, no CDN edge distribution. Those are structurally impossible in a single local server, and over
Tor the IP-based ones are moot anyway. Tor's rendezvous architecture already provides the
origin-IP-masking / no-inbound-ports posture that Cloudflare Tunnel/Spectrum sell.

---

## 2. Shape: a standalone crate

Shield is a **separate crate, `onion-shield`**, not code buried in onyums — same split philosophy
as `onyums` and `artiqwest`. It is **framework-agnostic**:

- A **`tower` / `axum` middleware layer** usable by *any* axum app (Tor or not) — this is where the
  WAF, challenge gate, clearance-token check, and rate limiting live.
- A **Tor-aware circuit-policy hook** (`CircuitPolicy`) that onyums wires to `RendRequest` /
  `StreamRequest` for the per-circuit dimension that a normal HTTP app can't express.

onyums depends on `onion-shield` and connects the two halves. A non-Tor user still gets the
WAF/challenge/rate-limit value through the middleware alone.

```
onion-shield (new crate, MIT)
├── tower/axum Layer  ──────────────►  any axum app
└── CircuitPolicy hook  ────────────►  onyums wires to RendRequest/StreamRequest
```

---

## 3. Component decisions (locked)

| Component | Decision | Crate / basis | License |
|---|---|---|---|
| PoW | **Build**, pluggable `Pow` trait, **SHA-256 hashcash default** | hand-rolled (~50 LOC); equix/RandomX as optional backends | MIT |
| Rate limiter | **Reuse** | `governor` + `tower_governor` (key is generic → key on token) | MIT/Apache |
| Clearance token | **Reuse** | `jsonwebtoken`, or `hmac`+`sha2` for a minimal internal token | MIT |
| No-JS CAPTCHA | **Reuse** | `captcha` / `easy-captcha` (GIF) — server-rendered, no JS | audit `captcha` |
| WAF | **Build** (deferred after v1) | pure Rust: `wirefilter` + `regex` + `aho-corasick` | MIT |
| Orchestration glue | **Build** | this crate | MIT |

**Why hashcash default, not RandomX or equix:** production gates (Anubis, mCaptcha) all use
lightweight throwaway PoW with near-free server verification — the correct asymmetry for a gate.
SHA-256 hashcash is MIT, pure Rust, no FFI, no copyleft. RandomX-WASM mine-to-enter was evaluated
and rejected: WASM is disabled at Tor "Safer"/"Safest", RandomX can't JIT or do directed rounding
in WASM, browser yield is micro-cents, and browser mining is uniformly flagged as malware. equix
(BSD-3 at the source; LGPL only in Arti's Rust crate) and a RandomX backend remain implementable
behind the `Pow` trait for anyone who wants them — opt-in, never default.

---

## 4. Core API sketch (illustrative)

### 4.1 Clearance token — the synthetic identity

A stateless, signed token minted after a client clears a gate. It is the rate-limiter key and the
"already cleared" proof. No server-side session store; survives onyums' statelessness. Can ride a
cookie *or* a URL path segment (for no-JS clients that can't set cookies reliably).

```rust
/// A stateless, signed proof that a client cleared a gate. The rate limiter keys on `id`.
pub struct Clearance {
    pub id: TokenId,          // random per-grant id; the rate-limit / quota key
    pub issued: SystemTime,
    pub expires: SystemTime,
    pub level: ClearanceLevel, // Patience < Captcha < Pow  (mirrors CF's tiered clearance)
}

pub trait ClearanceStore {
    fn mint(&self, level: ClearanceLevel, ttl: Duration) -> SignedToken; // HMAC-SHA256 / JWT
    fn verify(&self, token: &str) -> Option<Clearance>;                  // signature + expiry
}
```

### 4.2 Challenge — pluggable gates, no-JS-aware

```rust
/// Outcome of presenting/evaluating a gate.
pub enum Gate {
    Pass(ClearanceLevel),     // mint a token at this level
    Present(http::Response),  // serve the interstitial (PoW page, CAPTCHA image, ...)
    Reject,
}

pub trait Challenge: Send + Sync {
    /// Decide what to do for an un-cleared request.
    fn issue(&self, req: &RequestParts) -> Gate;
    /// Validate a submitted solution (PoW nonce, CAPTCHA answer, ...).
    fn verify(&self, req: &RequestParts) -> bool;
    /// Does this challenge require client-side JS/WASM? Drives no-JS fallback selection.
    fn needs_js(&self) -> bool;
}
```

Built-in `Challenge` implementations, selected by capability:

| Challenge | needs_js | Notes |
|---|---|---|
| `PowChallenge<P: Pow>` | yes | hashcash interstitial; client solves in JS |
| `CaptchaChallenge` | **no** | server-rendered image/GIF; answer via plain `<form>` |
| `PatienceChallenge` | **no** | timed tarpit delay; zero client compute |

A `Challenge` chain can fall back: try PoW; if the client is no-JS, drop to CAPTCHA or patience.

### 4.3 Pow — swappable algorithm, hashcash default

```rust
pub trait Pow: Send + Sync {
    fn new_puzzle(&self, difficulty: u32) -> Puzzle;       // seed + difficulty
    fn verify(&self, puzzle: &Puzzle, solution: &[u8]) -> bool; // must be ~free
}

pub struct Hashcash;          // default: SHA-256 leading-zero-bits, MIT, ~free verify
// pub struct EquiX;          // optional backend (BSD algo; LGPL Rust crate or C FFI)
// pub struct RandomXPool;    // optional, opt-in "useful work" backend — documented caveats
```

Difficulty is **adaptive**: dormant under normal load, raised under attack — mirroring Tor's own
PoW effort control loop, but at the app layer where onyums *can* observe request rate.

### 4.4 Rate limiting — keyed on token or circuit, never IP

```rust
// Reuse `governor`; key is the clearance TokenId (preferred) or CircuitId (fallback).
pub struct ShieldRateLimit {
    by_token: DefaultKeyedRateLimiter<TokenId>,
    by_circuit: DefaultKeyedRateLimiter<CircuitId>,
}
```

`governor`'s key is generic over `Hash + Eq`, so the clearance `TokenId` string drops in directly.
A fresh token costs a fresh gate solve → rotation is bounded by PoW cost. This is the only
forgery-resistant per-client key available without IPs (the research found signed-token/JWT-claim
keying is the one robust option Cloudflare itself has).

### 4.5 CircuitPolicy — the Tor dimension (onyums wires this)

```rust
/// Per-rendezvous-circuit accounting + actions. onyums calls this from its
/// RendRequest/StreamRequest loop; a plain axum app simply doesn't use it.
pub trait CircuitPolicy: Send + Sync {
    fn on_new_circuit(&self, id: CircuitId) -> CircuitAction;       // accept / reject / challenge
    fn on_new_stream(&self, id: CircuitId, target: &StreamTarget) -> CircuitAction;
    fn on_request(&self, id: CircuitId) -> CircuitAction;          // rate/quota per circuit
}

pub enum CircuitAction { Accept, Challenge, Reject, Shutdown } // Shutdown => shutdown_circuit()
```

This generalizes the one-off port-443/80-only logic already in onyums'
`handle_stream_request`.

### 4.6 WAF (deferred, v2)

Pure-Rust request-inspection engine: `wirefilter` for the expression/rule language, `regex` +
`aho-corasick` for multi-signature matching, evaluated as a `tower` layer over request
URI/method/headers/body. Ships a curated starter ruleset (SQLi/XSS/traversal); not OWASP-CRS-complete
at v1. No Go/cgo/FFI — consistent with onyums' clean stable-Rust posture.

---

## 5. Request lifecycle

```
incoming circuit ─► CircuitPolicy.on_new_circuit
                      │ Reject/Shutdown ─► drop
                      ▼ Accept/Challenge
   stream ─► CircuitPolicy.on_new_stream (target port/host)
                      ▼
   HTTP request ─► [Shield tower Layer]
        1. WAF inspect (v2)             ─► block ─► 403
        2. clearance cookie/path valid? ─► no ─► Challenge.issue ─► interstitial / Reject
        3. rate limit (key=TokenId)     ─► exceeded ─► challenge / 429
        4. pass ─► inner axum Router
```

Challenge submission (PoW nonce / CAPTCHA answer) hits a Shield-owned route, which on
`Challenge.verify` mints a `Clearance` and redirects back.

---

## 6. Module layout (`onion-shield`)

```
onion-shield/
├── src/
│   ├── lib.rs            // ShieldLayer (tower), builder, re-exports
│   ├── clearance.rs      // Clearance, ClearanceStore (hmac/jwt)
│   ├── challenge/
│   │   ├── mod.rs        // Challenge trait, Gate, chain/fallback
│   │   ├── pow.rs        // Pow trait + Hashcash; interstitial page
│   │   ├── captcha.rs    // CaptchaChallenge (reuse `captcha`/`easy-captcha`)
│   │   └── patience.rs   // PatienceChallenge (no-JS tarpit)
│   ├── ratelimit.rs      // ShieldRateLimit over `governor`
│   ├── circuit.rs        // CircuitPolicy trait, CircuitAction, accounting
│   └── waf/              // v2: wirefilter + regex + aho-corasick
└── Cargo.toml
```

onyums adds a thin adapter wiring `CircuitPolicy` to `RendRequest`/`StreamRequest` and inserting
`ShieldLayer` into its Router.

---

## 7. The no-JS strategy (explicit)

Because Tor "Safer"/"Safest" kill JS *and* WASM, Shield must degrade rather than fail:

1. **Default**: PoW challenge for JS clients (cheap, no tracking).
2. **No-JS detected / configured**: fall back to a **server-rendered CAPTCHA** (answer via plain
   form) or a **patience tarpit** (timed delay, zero client compute).
3. **Strongest gate, when applicable**: Tor **restricted discovery** (allowlist of client keys,
   stable in Arti 1.7) — cryptographic access control *upstream* of any challenge. Managed in
   onyums config, not Shield.

Supporting no-JS abuse defense is a genuine differentiator: Cloudflare never solved it (every
Cloudflare challenge requires JS).

---

## 8. Licensing

Target: **MIT** for `onion-shield`, all default deps permissive (`governor`, `jsonwebtoken`,
`hmac`/`sha2`, `captcha` pending audit, `regex`/`aho-corasick`, `wirefilter` Apache-2.0). No
copyleft and no FFI in the default build. Optional PoW backends (`equix` Rust crate is LGPL-3.0; a
RandomX backend is BSD-3 algo) live behind cargo features so the default stays clean.

---

## 9. Phasing

- **v0.1 — gate core.** `ClearanceStore`, `Challenge` trait, `Hashcash` PoW + interstitial,
  `CaptchaChallenge`, `PatienceChallenge`, `ShieldRateLimit`, `ShieldLayer` (tower). Pure HTTP;
  usable by any axum app.
- **v0.2 — Tor dimension.** `CircuitPolicy` + accounting; onyums adapter wiring
  `RendRequest`/`StreamRequest`; "Under Attack Mode" toggle; adaptive PoW difficulty.
- **v0.3 — WAF.** `wirefilter`-based engine + curated starter ruleset.
- **Tracks onyums roadmap.** Shield is the concrete form of Onyums Shield pillars 1–5; restricted
  discovery and service-side PoW (pillar 6) stay in onyums/arti config.

---

## 10. Open questions

- **Clearance carrier under no-JS**: cookie vs. signed URL path segment vs. both — Tor Browser
  cookie behavior across circuits needs testing.
- **Circuit ↔ token binding**: should a clearance be pinned to the circuit it was minted on, or
  float across circuits? Pinning is stronger but breaks if a client legitimately rotates circuits.
- **Adaptive difficulty signal**: app-observable request rate is the only input (PoW effort from
  Tor's intro layer is not surfaced by Arti) — what window / curve?
- **CAPTCHA license**: audit the `captcha` crate's non-standard license before depending on it;
  `easy-captcha` may be the safer base.

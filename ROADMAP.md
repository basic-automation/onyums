# Onyums Roadmap: a frontier onion-service framework

Onyums today is a thin axum wrapper with a single public entry point — `serve(app, nickname)` —
that hardcodes essentially every Tor decision: default `TorClientConfig`, a self-signed cert, an
automatic HTTP→HTTPS upgrade, ports 80/443 only, a process-global `ONION_NAME` singleton, and a
fresh `TorClient` per call.

The direction this roadmap commits to: onyums is a **frontier framework** — batteries-included and
secure by default. The hard, Tor-specific machinery (stable identity, abuse resistance, enforced
TLS) is present and on the moment you depend on the crate. You do not assemble safety or capability
from feature flags; you *tune it down* when you have a reason to. We raise the ceiling with advanced
Tor features while making the floor itself fully featured.

## Guiding principles

1. **`serve()` stays a one-liner — and the one-liner is the full secure stack.** The 30-second path
   never regresses, and it already gives you persistent identity, enforced TLS, and abuse defenses.
   Every advanced capability lands behind a builder that *desugars to the same internals*.
2. **Versatility is override, not assembly.** Anything onyums wraps (the `TorClient`,
   `TorClientConfig`, `OnionServiceConfig`, the raw `RunningOnionService`) stays reachable, so power
   users can relax or replace any default — but they start from a complete, secure configuration,
   not an empty one. We already do this philosophically by re-exporting `axum`.
3. **Tor-native assumptions, not HTTP-native ones — with one deliberate exception.** No
   `SocketAddr` leakage, no assuming HTTP is the only protocol. The exception is **TLS: onyums
   treats encrypted, certificate-authenticated transport as the default and can enforce it**
   (see Phase 3). Tor already encrypts the channel, but TLS is still standard here — not optional
   cruft to be stripped away.
4. **Frontier and fully featured out of the gate.** onyums is a batteries-included framework, not
   a minimal kernel you assemble yourself. The advanced, Tor-specific machinery — client auth,
   proof-of-work DoS defense, vanity addresses, restricted discovery, persistent identity — ships
   enabled and ready, not hidden behind opt-in feature flags or a slimming exercise. Depending on
   the crate should mean the hard parts are already there. We accept a heavier dependency tree and
   the cost of tracking arti's frontier as the price of that.
5. **Secure and complete by default; you opt *down*, never *up*.** The defaults are the safe,
   maximal choice — stable address, enforced TLS, DoS defenses live. Relaxing them (ephemeral keys,
   non-strict TLS, disabling a defense) is an explicit, named decision in the builder, never the
   accidental result of an unset flag.

---

## Phase 0 — Foundational refactors (unblock everything else) — target `0.4`

These are not features, but every default-on capability below is blocked on them. They turn the
one-shot `serve()` into a real, observable, controllable service.

- **Kill the global `ONION_NAME` singleton** (`static LazyLock<Mutex<String>>`). It hard-limits the
  crate to **one onion service per process** and forces the awkward poll-the-global readiness loop
  in the README. Replace with a per-service **handle** returned from the builder. This is the
  precondition for multi-service hosting and a shared client (Phase 4).
- **Fix the per-request thread+runtime hack.** `handle_tls_connection` spawns a fresh OS thread
  *and* a new current-thread tokio runtime for every single hyper request, then `.join()`s it.
  That is a correctness and throughput landmine — it should run on the existing runtime via a
  `tower`/`hyper` service directly. It must be fixed before any traffic- or defense-sensitive
  feature (PoW, high traffic) can be trusted.
- **First-class readiness + graceful shutdown.** Return a handle instead of `bail!`-ing forever:

  ```rust
  let handle = OnionService::builder()
      .router(app)
      .nickname("my_onion")
      .serve()
      .await?;                          // full secure stack, no extra config

  handle.ready().await;                 // descriptor published, reachable
  println!("{}", handle.onion_address());
  // ... later
  handle.shutdown().await;              // CancellationToken under the hood
  ```

  `serve(app, nickname)` becomes a three-line wrapper over this builder.

---

## Phase 1 — Stable identity by default — target `0.5`

The `.onion` address *is* the service's public key. A frontier framework should make the address
**stable out of the box**, not leave persistence to chance. (As of 0.3.1 the client already uses a
dedicated `./tor/onyums/state` keystore; this phase makes identity a first-class, intentional part
of the API rather than an implementation detail.)

- **Persistent keystore is the default** → stable address across restarts with zero configuration.
  `.ephemeral()` is the explicit opt-*down* for throwaway services; persistence is never something
  you have to remember to turn on.
- **Bring-your-own identity key** — import an existing v3 HS secret key to migrate a service onto
  onyums without changing its address.
- **Vanity address mining** — generate keys until the address matches a desired prefix,
  parallelized across cores. Built in; nothing in arti does this for you.
- **Address helpers** — typed `OnionAddress`, QR / `Onion-Location` header emission, and clear docs
  that the keystore path is relative to the working directory.

---

## Phase 2 — Abuse resistance, live by default — target `0.6`

Onion services have abuse-resistance primitives no clearnet server has. The frontier stance is that
onyums **ships these active**, not as exotic add-ons an operator has to discover.

- **Proof-of-Work DoS defense** — client puzzles that throttle introduction floods, with effort
  tuning, backed by arti's (experimental) `tor-hspow`. Shipped on by default; the headline anti-DoS
  feature for onion services. Operators tune effort or opt down, they don't opt in.
- **v3 Client Authorization / Restricted Discovery** — only clients holding an authorized key can
  even *discover* (let alone connect to) the service. A one-call builder API
  (`.authorized_clients([...])`) turns an onion service into a cryptographically private endpoint.
  Supported by arti's `tor-hsservice`.
- **Circuit policy & rate caps** — surface intro-point counts, per-circuit connection caps, and a
  policy hook to reject circuits. We already `shutdown_circuit()` in `handle_stream_request` for
  non-80/443 ports — generalize that one-off into a first-class policy callback.

> **Onyums Skin** — the broader "Cloudflare for Tor" abuse-defense layer (challenge/PoW gate,
> stateless clearance tokens, token/circuit-keyed rate limiting, no-JS fallbacks, and a pure-Rust
> WAF) is the major expansion of this phase. It lands as a standalone `onyums-skin` crate. Full
> design, component decisions, and API sketch: [docs/skin.md](docs/skin.md).

---

## Phase 3 — TLS-first transport & protocol versatility — target `0.7`

Today `handle_stream_request` hardcodes port 443 → TLS+axum, port 80 → redirect, everything else →
reject. This phase keeps TLS as the enforced standard for HTTP while opening the service up to
arbitrary protocols.

- **TLS-first, with optional strict enforcement.** onyums already auto-upgrades plaintext HTTP
  (port 80) to HTTPS; this roadmap *doubles down* on TLS as the standard rather than treating it
  as redundant. Even though Tor encrypts and authenticates the channel via the `.onion` key,
  end-to-end TLS adds independent, defense-in-depth cryptographic authentication and — crucially —
  unlocks the browser **secure-context** semantics real apps depend on: WebCrypto, service
  workers, `Secure` / `__Host-` cookies, HTTP/2, and no mixed-content downgrades. The versatility
  is in *how* TLS is provisioned and enforced, never in turning it off for HTTP services:
  - **Default** — auto-generated self-signed cert (today's behavior) with HTTP→HTTPS upgrade on.
  - **Strict mode** (`.tls(Tls::Strict)`) — *reject* plaintext circuits outright instead of
    redirecting (no port-80 handler at all), and emit HSTS. For operators who want TLS to be
    non-negotiable.
  - **Bring-your-own cert** (`.tls(Tls::Provided(cert))`) — for CA-signed `.onion` certificates
    (e.g. HARICA), which some clients and browsers prefer over self-signed.
  Raw-TCP / non-HTTP handlers (below) negotiate their own transport security; the TLS-first stance
  is specifically about the built-in HTTP/WS handler.
- **Arbitrary port → handler mapping.** `.route_port(443, HttpHandler::new(app))`,
  `.route_port(9735, RawTcpHandler::new(...))`. A `StreamHandler` trait lets onyums tunnel *any*
  protocol over an onion service (gRPC, SSH, a game server, Lightning), not just HTTP/WS. The
  TLS-enforced HTTP handler remains the default built-in; raw handlers are the versatility layer.
- **Single onion service mode** — trade server-side anonymity for lower latency where the server
  is not trying to hide (common for high-traffic public onion sites). An explicit opt-down from the
  anonymous default.

---

## Phase 4 — Observability & multi-service — target `0.8`

- **Bootstrap & descriptor-upload progress** as a stream/callback, not just `tracing` logs — so
  `ready()` means "actually published and reachable," and apps can show real status.
- **Per-service metrics on the handle** — active circuits, connection counts, intro-point health,
  PoW effort in play, descriptor republish times.
- **Multiple services on one shared `TorClient`.** Once the singleton is gone, bootstrap *once* and
  launch N onion services on the same client — far cheaper than today's client-per-`serve()`.
  Enables multi-tenant hosting from one process.
- **Circuit-isolation controls** exposed through an enriched `ConnectionInfo` (beyond today's
  `circuit_id` + always-`None` `socket_addr`).

---

## Cross-cutting: developer experience

- **Re-export the arti stack we depend on** (as we do `axum`) so downstreams can't get
  version-skewed.
- **Document the secure defaults loudly.** Because onyums is secure-and-complete by default, the
  docs must make the *opt-downs* (ephemeral identity, non-strict TLS, disabled PoW, single-onion
  mode) explicit and visible — a user should always know what they are turning off.
- **A test harness that doesn't need the live Tor network.** Integration tests currently require
  real bootstrapping (`test_serve` hits the real network and swallows errors). An
  in-process/loopback mode would make onyums testable in CI.

---

## Suggested layered API (full-by-default, override-when-needed)

```
Tier 0  serve(app, "nick")                 the complete secure stack in one line:
                                           persistent identity, enforced/upgraded TLS, abuse defenses on
Tier 1  OnionService::builder()...serve()  tune or relax the defaults (TLS strictness, PoW effort,
                                           authorized clients, BYO cert/key, ephemeral identity)
Tier 2  handle.ready()/.onion_address()/.shutdown()/.metrics()
Tier 3  .with_tor_client(existing)         raw arti escape hatches
        .with_onion_config(OnionServiceConfig)
        .route_port(port, impl StreamHandler)
        raw access to RunningOnionService
```

You descend a tier only to *change* a default, never to *enable* a basic capability.

## Risks to track

- **arti API churn** — PoW and restricted discovery are newer/experimental in arti. Shipping them
  on-by-default means onyums tracks arti's frontier directly; pin versions and budget for breaking
  bumps (we just lived through a 0.39 → 0.43 one).
- **Secure defaults can surprise.** Persistent identity writes keys to disk (working-directory
  relative); strict TLS rejects plaintext; PoW costs clients CPU. Each default is correct, but each
  must be documented as a behavior, not a silent assumption.
- **Keystore format stability** across arti versions (matters for the "stable address" promise).
- **Keep it stable-Rust** — we removed the last nightly gate in 0.3.0; don't let a new dep drag it
  back.

---

Sequencing rationale: Phase 0 is pure enablement; Phases 1–2 deliver the highest-leverage,
default-on, *Tor-specific* differentiators (stable identity + live abuse resistance — things no
clearnet framework offers); Phase 3 enforces TLS while broadening protocol reach; Phase 4 rounds
out observability and scale.

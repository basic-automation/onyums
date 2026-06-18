# Onyums Roadmap: Tor-native power behind a plug-and-play API

Onyums today is a thin axum wrapper with a single public entry point — `serve(app, nickname)` —
that hardcodes essentially every Tor decision: default `TorClientConfig`, default keystore, a
self-signed cert always, ports 80/443 only, a process-global `ONION_NAME` singleton, and a fresh
`TorClient` per call. That simplicity is the selling point, but it is also the ceiling. This
roadmap raises the ceiling without lowering the floor.

## Guiding principles

1. **`serve()` stays a one-liner.** Every advanced capability lands behind a builder that
   *desugars to the same internals*; the 30-second path never regresses.
2. **Always leave an escape hatch.** Anything onyums wraps (the `TorClient`, `TorClientConfig`,
   `OnionServiceConfig`, the raw `RunningOnionService`) must be reachable for power users. We
   already do this philosophically by re-exporting `axum`.
3. **Tor-native assumptions, not HTTP-native ones.** No `SocketAddr` leakage, no assuming TLS is
   necessary, no assuming HTTP is the only protocol.
4. **Feature-flag the heavy/experimental.** The arti `full + static` tree is large and some Tor
   features are experimental in arti — gate them so a minimal build stays lean.

---

## Phase 0 — Foundational refactors (unblock everything else) — target `0.4`

These are not features, but almost every feature below is blocked on them.

- **Kill the global `ONION_NAME` singleton** (`static LazyLock<Mutex<String>>`). It hard-limits the
  crate to **one onion service per process** and forces the awkward poll-the-global readiness loop
  in the README. Replace with a per-service **handle** returned from the builder.
- **Fix the per-request thread+runtime hack.** `handle_tls_connection` spawns a fresh OS thread
  *and* a new current-thread tokio runtime for every single hyper request, then `.join()`s it.
  That is a correctness and throughput landmine — it should run on the existing runtime via a
  `tower`/`hyper` service directly. Must be fixed before any perf-sensitive feature (PoW, high
  traffic).
- **First-class readiness + graceful shutdown.** Return a handle instead of `bail!`-ing forever:

  ```rust
  let handle = OnionService::builder()
      .router(app)
      .nickname("my_onion")
      .serve()
      .await?;

  handle.ready().await;                 // descriptor published, reachable
  println!("{}", handle.onion_address());
  // ... later
  handle.shutdown().await;              // CancellationToken under the hood
  ```

  `serve(app, nickname)` becomes a three-line wrapper over this.

---

## Phase 1 — Identity & addressing — target `0.5`

The `.onion` address *is* the service's public key — the most Tor-specific surface and the
highest-value gap today, since onyums currently leans on arti's default keystore with no control.

- **Persistent, configurable keystore** → stable address across restarts. Expose `.keystore(path)`
  and an explicit `.ephemeral()` opt-out. Address stability is currently implicit and undocumented.
- **Bring-your-own identity key** — import an existing v3 HS secret key (migrate a service onto
  onyums without changing its address).
- **Vanity address mining** (feature `vanity`) — generate keys until the address matches a desired
  prefix, parallelized across cores. Nothing in arti does this for you.
- **Address helpers** — typed `OnionAddress`, QR / `Onion-Location` header emission.

---

## Phase 2 — Access control & abuse resistance — target `0.6`

Tor onion services have abuse-resistance primitives that no clearnet server has. These are the
differentiators.

- **v3 Client Authorization / Restricted Discovery** — only clients holding an authorized key can
  even *discover* (let alone connect to) the service. Builder API to register authorized client
  pubkeys; turns an onion service into a cryptographically private endpoint. Supported by arti's
  `tor-hsservice`.
- **Proof-of-Work DoS defense** (feature `pow`, experimental in arti's `tor-hspow`) — client
  puzzles that throttle introduction floods, with effort tuning. The headline anti-DoS feature for
  onion services.
- **Intro-point count & rate caps** — surface `num_intro_points`, per-circuit connection caps, and
  a hook to reject circuits (we already `shutdown_circuit()` in `handle_stream_request` — generalize
  it into a policy callback).

---

## Phase 3 — Transport & protocol versatility — target `0.7`

Today `handle_stream_request` hardcodes port 443 → TLS+axum, port 80 → redirect, everything else →
reject. Generalize the dispatch.

- **Arbitrary port → handler mapping.** `.route_port(443, HttpHandler::new(app))`,
  `.route_port(9735, RawTcpHandler::new(...))`. A `StreamHandler` trait lets onyums tunnel *any*
  protocol over an onion service (gRPC, SSH, a game server, Lightning), not just HTTP/WS. The HTTP
  handler becomes the default built-in, not the only option.
- **Make TLS optional** (`.tls(Tls::SelfSigned | Tls::Provided(cert) | Tls::None)`). Worth
  surfacing to users: **TLS over Tor is largely redundant** — the onion protocol already provides
  end-to-end encryption and authenticates the server via the `.onion` key. TLS's real value is
  browser secure-context semantics (WebCrypto, service workers, `Secure` cookies) and CA-signed
  `.onion` certs (HARICA). Dropping TLS is both a perf win and a correctness clarification. Default
  stays self-signed for browser friendliness.
- **Single onion service mode** — trade server-side anonymity for lower latency where the server
  is not trying to hide (common for high-traffic public onion sites).

---

## Phase 4 — Observability & multi-service — target `0.8`

- **Bootstrap & descriptor-upload progress** as a stream/callback, not just `tracing` logs — so
  `ready()` can mean "actually published and reachable," and apps can show real status.
- **Per-service metrics on the handle** — active circuits, connection counts, intro-point health,
  descriptor republish times.
- **Multiple services on one shared `TorClient`.** Once the singleton is gone, bootstrap *once* and
  launch N onion services on the same client — far cheaper than today's client-per-`serve()`.
  Enables multi-tenant hosting from one process.
- **Circuit-isolation controls** exposed through `ConnectionInfo` (enrich it beyond `circuit_id` +
  always-`None` `socket_addr`).

---

## Cross-cutting: developer experience

- **Re-export the arti stack we depend on** (as we do `axum`) so downstreams can't get
  version-skewed.
- **Slim feature flags** — let users opt out of `static`/`full` to cut the (large) arti build.
- **A test harness that doesn't need the live Tor network.** Integration tests currently require
  real bootstrapping (`test_serve` hits the real network and swallows errors). An
  in-process/loopback mode would make onyums testable in CI.

---

## Suggested layered API (the "plug-and-play + versatile" spine)

```
Tier 0  serve(app, "nick")                         <- today, never breaks
Tier 1  OnionService::builder()...serve()          <- config without ceremony
Tier 2  handle.ready()/.onion_address()/.shutdown()/.metrics()
Tier 3  .with_tor_client(existing)                 <- escape hatches
        .with_onion_config(OnionServiceConfig)
        .route_port(port, impl StreamHandler)
        raw access to RunningOnionService
```

Each tier is strictly opt-in; you only descend when you need to.

## Risks to track

- **arti API churn** — PoW and restricted discovery are newer/experimental in arti; pin versions
  and gate behind features (we just lived through a 0.39 → 0.43 breaking bump).
- **Keystore format stability** across arti versions (matters for the "stable address" promise).
- **Keep it stable-Rust** — we just removed the last nightly gate; don't let a new dep drag it back.

---

Sequencing rationale: Phase 0 is pure enablement, Phases 1–2 are the highest-leverage
*Tor-specific* differentiators (identity + abuse resistance — things no clearnet framework can
offer), and Phases 3–4 broaden reach.

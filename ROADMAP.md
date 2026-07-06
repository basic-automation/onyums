# Onyums Roadmap

> The single source of truth for the dev routine: a phase-ordered task list. `[ ]` = to do, `[x]` = done.
> Progress is logged in PRs and git history — there is no separate progress file.
> Consumer-facing features and usage live in [README.md](README.md).
> The abuse-defense crate has its own roadmap: [crates/onyums-skin/ROADMAP.md](crates/onyums-skin/ROADMAP.md).

## Phase 0 — Foundational refactors — `0.4`

- [x] Kill the global `ONION_NAME` singleton — per-service handle returned from the builder
- [x] Fix the per-request thread+runtime hack — serve on the existing tokio runtime via a `tower`/`hyper` service
- [x] First-class readiness + graceful shutdown — `OnionServiceHandle` with `ready()` / `onion_address()` / `shutdown()`; `serve(app, nickname)` is a thin wrapper over the builder

## Phase 1 — Stable identity by default — `0.5`

- [x] Persistent keystore is the default (`./tor/onyums/state`) — stable address across restarts with zero configuration
- [x] `.ephemeral()` opt-down for throwaway services (explicit, named decision — never an unset flag) — a unique throwaway temp state dir per launch (offline-verified: `storage_dirs`/`tor_client_config`), removed on handle drop; uses only stable arti features. arti's *in-memory* ephemeral keystore (`ArtiEphemeralKeystore`) is gated behind the experimental, non-semver `ephemeral-keystore` feature and is **not in `full`** (<https://lib.rs/crates/arti-client/features>); onyums' in-process ephemeral tracks arti issue #1186. A future slice could adopt the in-memory keystore for a no-disk identity, at the cost of an experimental feature dep.
- [ ] Bring-your-own identity key — import an existing v3 HS secret key to migrate a service without changing its address
  - *Offline slice landed:* `expanded_secret_from_tor_file` / `address_from_tor_secret_key_file` parse a Tor `hs_ed25519_secret_key` file (32-byte `== ed25519v1-secret: type0 ==` tag + 64-byte expanded key) and derive the exact address it serves; `tor_secret_key_file_from_expanded` / `VanityKey::to_tor_secret_key_file` render the inverse blob. *Next slice (live Tor):* insert the key into the keystore and launch it — via arti's `launch_onion_service_with_hsid` (behind the experimental, non-semver `experimental-api` feature — <https://lib.rs/crates/arti-client/features>) or by mirroring arti's own `arti hss ctor-migrate` C-tor→native-keystore migration utility (Arti 1.4.6, <https://blog.torproject.org/arti_1_4_6_released/>). Needs a decision on taking the experimental-feature dependency.
- [x] Vanity address mining (`mine` / `mine_parallel`) — parallelized across cores
- [x] Address helpers — typed `OnionAddress`, validating `parse`, QR emission (`qr_terminal` / `qr_svg`), `Onion-Location` header pair

## Phase 2 — Abuse resistance, live by default — `0.6`

- [ ] Proof-of-Work DoS defense at the intro layer (arti `tor-hspow`) — on by default, effort tunable, opt-down not opt-in
  - Requires `tor-hsservice`'s **experimental** `hs-pow-full` feature (not in `full`) + `OnionServiceConfigBuilder::enable_pow(true)`; the local 0.43 config exposes `enable_pow`/`pow_rend_queue_depth` but gates the machinery behind that feature — decide before enabling whether to depend on an experimental arti feature.
  - Tor's onion-service PoW v1 is **Equi-X + Blake2b**, effort scales linearly, and the service queues introductions by effort (<https://spec.torproject.org/hspow-spec/v1-equix.html>) — the *same* Equi-X puzzle family onyums-skin already ships behind its opt-in `equix` feature, so the intro-layer effort and the Skin gate can speak one difficulty vocabulary.
- [x] v3 client authorization / restricted discovery — `.authorized_clients([...])` builder API wiring `onyums_skin::RestrictedDiscovery` (`to_auth_files` / `AllowlistDiff`) into the Arti restricted-discovery config
- [x] Client x25519 auth-key generation — `ClientAuthKeypair` (`generate` / `from_secret_bytes`, `public_key` → `ClientAuthKey`, `secret_descriptor_line` / `auth_private_line` render + `from_secret_descriptor_line` / `from_auth_private_line` parse) and the `provision_client(&mut RestrictedDiscovery, nickname)` onboarding capstone. The crypto-dep decision resolves to *Arti's own* `tor-llcrypto` curve25519 (already a workspace dep, the same x25519 family Arti parses into `HsClientDescEncKey`), so no new dependency and no second crypto stack. The `.auth` / `.auth_private` renderings are verified byte-for-byte against Tor's canonical client-auth file format — uppercase base32, `<host>:descriptor:x25519:<key>` (<https://community.torproject.org/onion-services/advanced/client-auth/>). Offline/Tor-free, unit-tested + a runnable onboarding doctest.
- [x] Circuit policy hook — the one-off port gate in `handle_stream_request` generalized into a first-class policy callback
- [x] Skin integration: `SkinLayer` inserted into the served `Router` (secure default **on**)
- [x] Skin integration: `onyums_skin::CircuitPolicy` driven from the rendezvous loop (`CircuitAction::{Accept, Challenge, Reject, Shutdown}`)
- [x] Skin integration: `.skin(...)` / `.no_skin()` / `.circuit_policy(...)` builder surface
- [x] Skin integration: Under Attack Mode toggle on the builder — force every new circuit through the gate
- [ ] Skin integration: feed Skin's adaptive-difficulty signal from onyums-observed circuit/request rate (intro-layer PoW effort is not surfaced by Arti)
- [x] Surface Skin's security events (challenge / WAF / rate-limit / teardown) into the Phase 4 observability stream — circuit-layer events via `.circuit_events(sink)`; HTTP-gate events via `Skin::builder().events(sink)` + `.skin(...)`

## Phase 3 — TLS-first transport & protocol versatility — `0.7`

- [x] `Tls::Upgrade` default — auto-generated self-signed cert, HTTP→HTTPS redirect (TLS on in every mode)
- [x] `Tls::Strict` — reject plaintext circuits outright, emit HSTS
- [x] `Tls::Provided(cert)` — bring-your-own CA-signed `.onion` cert (`ProvidedCert::from_pem` / `from_pem_files`)
- [x] Arbitrary port → handler mapping — `StreamHandler` trait, `.route_port(port, handler)`, `RawTcpHandler`; ports 80/443 reserved for the built-in HTTP handler; reserved/zero/duplicate ports are clean `serve()` errors
- [ ] Runtime-verify the live raw-serve path (routing table, builder validation, and the `RawTcpHandler` proxy are unit-tested offline; the live path needs a real Tor run)
- [ ] Single onion service mode — explicit opt-down trading server-side anonymity for latency **(BLOCKED upstream on arti 0.43)** — the `Anonymity` enum exists (`Anonymity::DangerouslyNonAnonymous`) but the `anonymity` field in `OnionServiceConfig` is commented out in the pinned tor-hsservice 0.43 source ("We could skip this in v1"), so there is no config surface to set it. Re-check when the arti stack is bumped (see cross-cutting).

## Phase 4 — Observability & multi-service — `0.8`

- [ ] Bootstrap & descriptor-upload progress as a stream/callback (so `ready()` provably means published + reachable)
  - *Synchronous slice landed:* `OnionServiceHandle::status() -> ServiceStatus` — a stable, `#[non_exhaustive]`-proof projection of arti's onion-service `State` (Shutdown / Bootstrapping / Reachable / DegradedReachable / Unreachable / Broken, with `is_reachable()` mirroring arti's `is_fully_reachable`), unit-tested against every arti state offline. *Stream slice landed:* `OnionServiceHandle::status_events() -> impl Stream<Item = ServiceStatus>` projects `RunningOnionService::status_events()` through the same tested mapping, so callers watch the bootstrap → reachable → degraded transitions instead of polling (the projection is offline-tested; the live stream *emission* needs a running service). *Next slice:* fold `ready()` onto the same stream, and/or a granular descriptor-upload-progress signal if arti surfaces one finer than its coarse `State`.
- [ ] Per-service metrics on the handle — active circuits, connection counts, intro-point health, PoW effort, descriptor republish times
- [ ] Multiple services on one shared `TorClient` — bootstrap once, launch N onion services
- [x] Circuit-isolation controls via an enriched `ConnectionInfo` — typed `is_over_tor()` / `circuit()` / `same_circuit()` helpers (and a non-panicking connect-info fallback)

## Phase 5 — Framework layer: batteries-included MVC over axum — `0.9+`

No-JS-first, self-contained (no external daemon), every feature designed against the Tor latency budget.

- [ ] Spike (do first): WS-over-Tor reactive prototype — measure update RTT, circuit lifetime/drop rate, reconnect + resync cost; exercise the no-JS tiers (chunked-HTML / `multipart/x-mixed-replace` iframe stream, `<meta refresh>` polling); confirm the current Tor Browser ESR supports Declarative Shadow DOM
- [ ] SFC view layer (`.onyx`) — `<template>` / `<rust>` / `<style scoped>` / `<script>` with the Composition-API model; the lifecycle hook (not the block) decides server vs client execution; worked targets: [examples/guestbook.onyx](examples/guestbook.onyx), [examples/components/Disclosure.onyx](examples/components/Disclosure.onyx), [examples/components/Markdown.onyx](examples/components/Markdown.onyx)
- [ ] `Send + Sync` async reactive runtime on multithreaded tokio (the headline deep build — Leptos/Dioxus cores are sync/`!Send`)
- [ ] Rust→WASM compile path for client-phase `<rust>`
- [ ] Server-side JS engine for server-phase `<script>` — evaluate `boa` vs `rquickjs` vs `deno_core`/`rusty_v8` vs `Nova`/`Kiesel`
- [ ] Server actions — `#[server]`-style fns compiled to axum endpoints, reachable by plain `<form>` POST (no JS) or `fetch`
- [ ] File-based routing (`pages/` → axum routes), layouts + slots
- [ ] `<style scoped>` → Declarative Shadow DOM; custom elements as the island/hydration boundary
- [ ] Typed forms + validation — `axum::Form` + `garde`/`validator`, server-rendered error re-render
- [ ] Flash messages + CSRF — signed/encrypted-cookie flash, per-form CSRF tokens on by default for state-changing requests
- [ ] Live/reactive enhancement, transport-tiered and server-authoritative — WS/SSE island → no-JS iframe stream → `<meta refresh>` floor; coarse-grained, batched updates only
- [ ] Database — Turso by default, query + migration layer (`sqlx` or `sea-orm`), seeds
- [ ] Background jobs — `apalis` on its Turso backend (no Redis)
- [ ] Cache — `moka` in-process
- [ ] Sessions — `tower-sessions` + Turso store + signed/encrypted cookies, composing with Skin clearance tokens
- [ ] Outbound mailer (opt-in) — `lettre` relayed through the embedded arti `TorClient`, enqueued via the jobs queue
- [ ] Auth scaffold — password auth (`argon2` via `password-auth`) + `axum-login` sessions, layered on the Skin gate + restricted discovery
- [ ] Encrypted credentials / typed config — Rails-credentials-style store for HS identity keys / signing secrets / app secrets; `figment` dev/prod profiles
- [ ] `onyums new` / `onyums generate` — scaffolding CLI (`cargo-generate` + `clap`)
- [ ] Dev error pages + `/up` health check
- [ ] Test harness without live Tor — `tower::ServiceExt::oneshot` request-level tests + factory/fixture conventions

Non-goals: no inbound mail server; no heavy asset pipeline; no JS-*required* reactive layer; no ActiveRecord-style metaprogrammed model layer.

## Cross-cutting

- [x] Re-export the arti stack we depend on (as we do `axum`) so downstreams can't version-skew
- [ ] Evaluate upgrading the arti stack — onyums pins `arti-client`/`tor-*` **0.43**, but the Arti release line is now **2.4.0** (2026-06-01, with multiple breaking `TorClient` API changes across the 2.x line, <https://blog.torproject.org/arti_2_4_0_released/>). Restricted discovery was stabilized in Arti **1.7.0** (2025-11, <https://blog.torproject.org/arti_1_7_0_released/>) and stays behind the `restricted-discovery` cargo feature until issue #1795 closes; C-tor→arti restricted-discovery key migration landed in **1.8.0** (<https://blog.torproject.org/arti_1_8_0_released/>). A stack bump likely lands onion-service/PoW fixes relevant to Phase 2 but will require reworking the `TorClient` call sites for the 2.x breaking changes. Gate the bump on the workspace still building green on stable.
- [x] Document the secure defaults and opt-downs loudly (README covers the Skin / TLS / `route_port` opt-downs)
- [ ] In-process/loopback test mode so integration tests don't need the live Tor network (`test_serve` currently hits the real network) — *slice landed:* the composed application-facing stack (`build_serve_router`: gate + HSTS + app) is now `oneshot`-testable offline; *next slice:* a mock `RendRequest`/`StreamRequest` stream to drive `serve_circuits` without Tor

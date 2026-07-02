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
- [ ] `.ephemeral()` opt-down for throwaway services (explicit, named decision — never an unset flag)
- [ ] Bring-your-own identity key — import an existing v3 HS secret key to migrate a service without changing its address
- [x] Vanity address mining (`mine` / `mine_parallel`) — parallelized across cores
- [x] Address helpers — typed `OnionAddress`, validating `parse`, QR emission (`qr_terminal` / `qr_svg`), `Onion-Location` header pair

## Phase 2 — Abuse resistance, live by default — `0.6`

- [ ] Proof-of-Work DoS defense at the intro layer (arti `tor-hspow`) — on by default, effort tunable, opt-down not opt-in
- [x] v3 client authorization / restricted discovery — `.authorized_clients([...])` builder API wiring `onyums_skin::RestrictedDiscovery` (`to_auth_files` / `AllowlistDiff`) into the Arti restricted-discovery config
- [ ] Client x25519 auth-key generation (needs a crypto-dep decision — possibly Arti's job)
- [x] Circuit policy hook — the one-off port gate in `handle_stream_request` generalized into a first-class policy callback
- [x] Skin integration: `SkinLayer` inserted into the served `Router` (secure default **on**)
- [x] Skin integration: `onyums_skin::CircuitPolicy` driven from the rendezvous loop (`CircuitAction::{Accept, Challenge, Reject, Shutdown}`)
- [x] Skin integration: `.skin(...)` / `.no_skin()` / `.circuit_policy(...)` builder surface
- [x] Skin integration: Under Attack Mode toggle on the builder — force every new circuit through the gate
- [ ] Skin integration: feed Skin's adaptive-difficulty signal from onyums-observed circuit/request rate (intro-layer PoW effort is not surfaced by Arti)
- [ ] Surface Skin's security events (challenge / WAF / rate-limit / teardown) into the Phase 4 observability stream

## Phase 3 — TLS-first transport & protocol versatility — `0.7`

- [x] `Tls::Upgrade` default — auto-generated self-signed cert, HTTP→HTTPS redirect (TLS on in every mode)
- [x] `Tls::Strict` — reject plaintext circuits outright, emit HSTS
- [x] `Tls::Provided(cert)` — bring-your-own CA-signed `.onion` cert (`ProvidedCert::from_pem` / `from_pem_files`)
- [x] Arbitrary port → handler mapping — `StreamHandler` trait, `.route_port(port, handler)`, `RawTcpHandler`; ports 80/443 reserved for the built-in HTTP handler; reserved/zero/duplicate ports are clean `serve()` errors
- [ ] Runtime-verify the live raw-serve path (routing table, builder validation, and the `RawTcpHandler` proxy are unit-tested offline; the live path needs a real Tor run)
- [ ] Single onion service mode — explicit opt-down trading server-side anonymity for latency

## Phase 4 — Observability & multi-service — `0.8`

- [ ] Bootstrap & descriptor-upload progress as a stream/callback (so `ready()` provably means published + reachable)
- [ ] Per-service metrics on the handle — active circuits, connection counts, intro-point health, PoW effort, descriptor republish times
- [ ] Multiple services on one shared `TorClient` — bootstrap once, launch N onion services
- [ ] Circuit-isolation controls via an enriched `ConnectionInfo` (beyond `circuit_id` + always-`None` `socket_addr`)

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
- [x] Document the secure defaults and opt-downs loudly (README covers the Skin / TLS / `route_port` opt-downs)
- [ ] In-process/loopback test mode so integration tests don't need the live Tor network (`test_serve` currently hits the real network)

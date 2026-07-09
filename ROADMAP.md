# Onyums Roadmap

> The single source of truth for the dev routine: a phase-ordered task list. `[ ]` = to do, `[x]` = done.
> Progress is logged in PRs and git history — there is no separate progress file.
> Consumer-facing features and usage live in [README.md](README.md).
> The abuse-defense crate has its own roadmap: [crates/onyums-skin/ROADMAP.md](crates/onyums-skin/ROADMAP.md).

## Phase 0 — Foundational refactors — `0.4`

- [x] Kill the global `ONION_NAME` singleton — per-service handle returned from the builder
- [x] Fix the per-request thread+runtime hack — serve on the existing tokio runtime via a `tower`/`hyper` service
- [x] First-class readiness + graceful shutdown — `OnionServiceHandle` with `ready()` / `onion_address()` / `shutdown()`; `serve(app, nickname)` is a thin wrapper over the builder
- [ ] Split src/lib.rs — it's ~108 KB and overloaded with public API types, Tor bootstrap, service lifecycle, status projection, Skin integration, TLS layering, port-router assembly, and builder logic. Break into focused modules: builder.rs, handle.rs, tor_client.rs, service_config.rs, serve_loop.rs, status.rs, http_stack.rs, identity.rs.
- [x] Preserve upstream error contexts — `setup_tor_client`/`launch_onion_service`/the nickname parse and the three `StreamRequest::accept()` sites now use `map_err(|e| anyhow!("...: {e}"))` (was `|_|`), carrying arti's cause through for operators. Offline-tested on the nickname site (the one reachable without live Tor).
- [ ] Add CI — no .github/workflows exists. Add: cargo fmt --check, cargo clippy --all-targets --all-features -D warnings, cargo test --workspace, cargo audit/cargo deny, MSRV check, docs build.
- [ ] Add live Tor integration tests — current tests are offline-only mocks via tower. The roadmap itself flags raw-TCP serve, multi-service, and status-event emission as needing "real Tor runs." Add an --ignored or CI-gated live test tier. — *slice landed:* the tier exists: `live_service_serves_over_the_tor_network_and_shuts_down` (`#[ignore]`, run via `cargo test -- --ignored`) launches an ephemeral service on the real network, then a second Tor client (`allow_onion_addrs` — the serving client's config rejects `.onion` dialing) does an end-to-end HTTPS fetch through a real rendezvous circuit and must get the app body back, then shuts down cleanly, all under timeouts. It replaces the old `test_serve`, which hung the default suite on success (blocking `serve()` with no stop) and swallowed launch errors into a DEBUG log (passed on failure). Live finding baked into the test: arti 0.43 reports `Running` only after descriptor uploads to BOTH HsDir rings succeed, so `ready()`/`is_reachable` lags de-facto reachability by minutes — the e2e fetch, not status, is the pass signal (see the test's doc comment; feeds the arti-upgrade item below); *next slices:* live raw-TCP serve, multi-service on a shared client, status-event emission.
- [ ] Add concurrency/backpressure limits — code spawns a task per rendezvous circuit and per stream without explicit limits. Add configurable semaphores: max circuits, max streams per circuit, max total streams, max body size before WAF inspection, per-handler timeouts.
- [x] Replace synchronous Drop cleanup — `spawn_ephemeral_cleanup` offloads `remove_dir_all` to the blocking pool when a runtime is live (else runs inline); `shutdown()` `take()`s and awaits the removal, `Drop` cleans up only what shutdown left (best-effort, detached). No `remove_dir_all` on a runtime worker.
- [x] Add #![forbid(unsafe_code)] — onyums' own code has no `unsafe` (grep-verified); the crate-level `#![forbid(unsafe_code)]` makes any future `unsafe` a hard compile error. Builds green.
- [ ] Unify dependency tree — #![allow(clippy::multiple_crate_versions)] suggests hyper/tokio/arti version mismatches; reduce compiled binary weight.
- [ ] Explore https://github.com/plabayo/rama and see if it can open any new features for onyums, if so, flush out the roadmap


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
- [ ] Upgrade Arti from pinned 0.43.0 — the project's own roadmap calls the upgrade "a security win" due to medium-severity onion-service DoS fixes in newer versions.
- [ ] Add SECURITY.md — no vulnerability disclosure policy exists. Add supported versions, disclosure contact, expected response timelines.
- [ ] Add cargo audit/cargo deny to CI — non-negotiable for a security-critical crate.
- [x] Zeroize secret material — `ClientAuthKeypair` now `impl Zeroize`/`ZeroizeOnDrop` + `Drop`, wiping the x25519 secret in place on drop (the public half is left intact). `zeroize = "1.8"` added to `[workspace.dependencies]` (pure Rust, already transitive via the dalek stack — no new version). Offline-tested. *Note:* `secret_bytes()` still returns an owned copy the caller must scrub.
- [ ] Enforce filesystem permissions for keystore — default is ./tor/onyums/state with no explicit permission hardening. Document and enforce 0700/0600; fail closed on world-readable key files.
- [ ] Document restricted-discovery limits prominently — the README correctly says it's DoS resistance, not authentication (removing a client doesn't revoke an already-connected one). Make this warning prominent near .authorized_clients() and show how to layer app auth.
- [ ] Label the WAF as best-effort/non-authoritative — a "starter signature ruleset" regex WAF is trivially bypassed. Don't let "abuse defense on by default" imply it's a substitute for a secure app.
- [ ] Add raw-port security controls — RawTcpHandler bypasses the HTTP Skin/WAF entirely. Add per-port allowlists, connection limits, auth hooks, and explicit warnings when exposing SSH/admin services.
- [x] Fix Under-Attack "Challenge" for raw TCP — `stream_disposition(action, port)` is now port-aware: `Challenge` serves only on the reserved HTTP ports (80/443, where the Skin gate renders the challenge) via the new `port_router::is_reserved_http_port`, and **fails closed to Reject** on any raw port. Offline-tested.
- [ ] Treat CircuitId as short-lived only — it's synthetic (Arti doesn't expose a durable circuit identifier); attackers can rotate circuits. Bind longer-lived controls to clearance tokens, client certs, or restricted-discovery keys.
- [ ] Add signal trapping for ephemeral cleanup — OOM/SIGKILL causes temp keystore dirs to linger indefinitely. Bind to SIGINT/SIGTERM via tokio::signal for guaranteed cleanup.
- [ ] Document "double TLS" semantics — Tor encrypts the circuit, but Onyums adds inner TLS so traffic from local Tor exit logic to Axum remains encrypted against local memory snooping. This is a real security property — articulate it.
- [ ] Intro-layer Proof-of-Work is NOT done — blocked on experimental Arti hs-pow-full. Skin PoW is HTTP-layer only; don't imply Tor introduction-point flood protection exists.
- [ ] Live BYO-key launch not done — only offline parse/derive exists. Mark it explicitly as offline-only in README.
- [ ] Single-onion-service mode blocked upstream on Arti 0.43.
- [ ] Monitoring/metrics incomplete — the stable `ServiceProblem` "why is it broken" projection and host-side per-service counters (`ServiceMetrics`: circuits/streams by policy outcome) have landed (see Phase 4). Still TODO: the arti-sourced gauges (active circuits, intro-point health, PoW effort, descriptor republish times — pending arti surfacing them) and a Prometheus/OpenTelemetry exporter over `ServiceMetrics`.

## Phase 3 — TLS-first transport & protocol versatility — `0.7`

- [x] `Tls::Upgrade` default — auto-generated self-signed cert, HTTP→HTTPS redirect (TLS on in every mode)
- [x] `Tls::Strict` — reject plaintext circuits outright, emit HSTS
- [x] `Tls::Provided(cert)` — bring-your-own CA-signed `.onion` cert (`ProvidedCert::from_pem` / `from_pem_files`)
- [x] Arbitrary port → handler mapping — `StreamHandler` trait, `.route_port(port, handler)`, `RawTcpHandler`; ports 80/443 reserved for the built-in HTTP handler; reserved/zero/duplicate ports are clean `serve()` errors
- [ ] Runtime-verify the live raw-serve path (routing table, builder validation, and the `RawTcpHandler` proxy are unit-tested offline; the live path needs a real Tor run)
- [ ] Single onion service mode — explicit opt-down trading server-side anonymity for latency **(BLOCKED upstream on arti 0.43)** — the `Anonymity` enum exists (`Anonymity::DangerouslyNonAnonymous`) but the `anonymity` field in `OnionServiceConfig` is commented out in the pinned tor-hsservice 0.43 source ("We could skip this in v1"), so there is no config surface to set it. Re-check when the arti stack is bumped (see cross-cutting).

## Phase 4 — Observability & multi-service — `0.8`

- [ ] Bootstrap & descriptor-upload progress as a stream/callback (so `ready()` provably means published + reachable)
  - *Synchronous slice landed:* `OnionServiceHandle::status() -> ServiceStatus` — a stable, `#[non_exhaustive]`-proof projection of arti's onion-service `State` (Shutdown / Bootstrapping / Reachable / DegradedReachable / Unreachable / Broken, with `is_reachable()` mirroring arti's `is_fully_reachable`), unit-tested against every arti state offline. *Stream slice landed:* `OnionServiceHandle::status_events() -> impl Stream<Item = ServiceStatus>` projects `RunningOnionService::status_events()` through the same tested mapping, so callers watch the bootstrap → reachable → degraded transitions instead of polling (the projection is offline-tested; the live stream *emission* needs a running service). *ready()-fold slice landed:* `ready()` now watches the projected `status_events()` via the offline-testable `await_status` helper (one definition of reachability shared with `status()`); `ready_timeout(Duration) -> bool` bounds the wait; `wait_until_settled() -> ServiceStatus` resolves on reachable **or** terminal (`Broken`/`Shutdown`) so a broken bootstrap can't hang forever; plus `is_ready()` and richer `ServiceStatus` introspection (`is_degraded`/`is_broken`/`is_terminal`, `label()`/`Display`). *Next slice:* a granular descriptor-upload-progress signal if arti surfaces one finer than its coarse `State`.
- [x] Stable `ServiceProblem` projection on the handle — `OnionServiceHandle::problem() -> Option<ServiceProblem>` projects arti's `#[non_exhaustive]`, `Display`-less `current_problem()` into a stable, matchable enum (`Runtime`/`DescriptorUpload`/`IntroductionPoint`/`Other` + `ServiceProblemKind`), carrying arti's `Debug` as the operator detail; the feature-gated PoW variant and any future arti category fall to `Other`. `ServiceHealth` (via `health()`) bundles `status()` + `problem()` from a single arti read so the "what" and "why" never straddle a transition. Offline-tested against constructed `Problem`s. *(Re-validated against arti-client **0.44.0** — `Problem` still has no `Display`, variants unchanged: <https://docs.rs/tor-hsservice/latest/tor_hsservice/status/enum.Problem.html>.)*
- [ ] Per-service metrics on the handle — active circuits, connection counts, intro-point health, PoW effort, descriptor republish times
  - *Host-side counters slice landed:* `OnionServiceHandle::metrics() -> ServiceMetrics` exposes cumulative circuit/stream counters (offered/accepted/rejected at the circuit-policy gate; served/rejected/circuit-torn-down at the per-stream gate), backed by shared `AtomicU64`s the accept loop increments; `ServiceMetrics::since()` gives a saturating interval delta for rate computation. The counter mechanics are offline-tested; the loop's increment sites are compile-checked only (live-Tor path). *Next slice:* the arti-sourced gauges (intro-point health, PoW effort, descriptor republish times) once arti surfaces them, plus a Prometheus/OpenTelemetry exporter over `ServiceMetrics`.
- [ ] Multiple services on one shared `TorClient` — bootstrap once, launch N onion services
  - *Offline surface landed:* `OnionService::shared_client() -> Arc<TorClient>` bootstraps a reusable client; `OnionServiceBuilder::tor_client(client)` launches a service on it instead of bootstrapping (and `OnionServiceHandle::tor_client()` hands the client out from a running handle for siblings); `ServiceStatus::worst_of([...])` folds N statuses into one worst-case fleet-health signal; `validate_client_choice` rejects the `ephemeral()` + `tor_client()` conflict offline. *Next slice (live Tor):* verify N services actually come up and stay reachable on one shared client — needs a real Tor run, not offline-verifiable.
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
- [ ] CLI / daemon / Docker image — it's library-only. Ship a thin onyums-cli binary so non-Rust users can front existing services as onion services.
- [ ] "automation" features — if the goal is genuinely automation, build a separate onyums-automation project with: declarative inventory, Tor/onion-address host identities, SSH-over-onion transport, idempotent task modules, secret backend integration, playbook format, drift detection, and dry-run/diff/apply. Or build an Ansible connection plugin for onion addresses instead of replacing Ansible.

Non-goals: no inbound mail server; no heavy asset pipeline; no JS-*required* reactive layer; no ActiveRecord-style metaprogrammed model layer.

## Cross-cutting

- [x] Re-export the arti stack we depend on (as we do `axum`) so downstreams can't version-skew
- [ ] Evaluate upgrading the arti stack — onyums pins `arti-client`/`tor-*` **0.43**, but the Arti release line is now **2.5.0** (2026-06-03, <https://blog.torproject.org/arti_2_5_0_released/>), with multiple breaking `TorClient` API changes across the 2.x line (2.4.0, <https://blog.torproject.org/arti_2_4_0_released/>). **2.5.0 fixes two medium-severity onion-service DoS issues — TROVE-2026-024 and TROVE-2026-027 (<https://alternativeto.net/news/2026/7/arti-2-5-brings-stable-counter-galois-onion-default-congestion-control-and-security-fixes/>)** — directly relevant to onyums' Phase 2 DoS posture, so a bump is a security win, not just churn. It also **raises the MSRV to Rust 1.91** (Oct 2025) and stabilizes Counter Galois Onion + default congestion control (transport-level, no onyums API change). Restricted discovery was stabilized in Arti **1.7.0** (2025-11, <https://blog.torproject.org/arti_1_7_0_released/>) and stays behind the `restricted-discovery` cargo feature until issue #1795 closes; C-tor→arti restricted-discovery key migration landed in **1.8.0** (<https://blog.torproject.org/arti_1_8_0_released/>). A stack bump also lands onion-service/PoW fixes relevant to Phase 2 but will require reworking the `TorClient` call sites for the 2.x breaking changes and confirming the CI toolchain is ≥1.91. Gate the bump on the workspace still building green on stable. **Concrete crate target (2026-07-09 check):** the library crate `arti-client` is at **0.44.0** (released 2026-06-30, edition 2024 — <https://lib.rs/crates/arti-client>); onyums pins **0.43.0**, so the near-term move is the single-minor `0.43 → 0.44` bump (the "2.5.0" figure above is the Arti *application* umbrella version, which tracks the 0.4x crate line). Evaluate the 0.44.0 API delta across the `tor-*` 0.44 crates before bumping.
- [x] Document the secure defaults and opt-downs loudly (README covers the Skin / TLS / `route_port` opt-downs)
- [ ] In-process/loopback test mode so integration tests don't need the live Tor network (the live tier — `live_service_serves_over_the_tor_network_and_shuts_down`, `--ignored` — hits the real network) — *slice landed:* the composed application-facing stack (`build_serve_router`: gate + HSTS + app) is now `oneshot`-testable offline; *next slice:* a mock `RendRequest`/`StreamRequest` stream to drive `serve_circuits` without Tor
- [ ] README -> Add a "What this is / what this is NOT" section — make the first sentence unambiguous: "Onyums is a Rust library for serving Axum applications as Tor onion services. It is not a host provisioning/config-management tool." This kills the category confusion at the source.
- [ ] README -> Add an installation section — currently none. Add: cargo add onyums, tokio requirement, MSRV, and the critical selling point that no external Tor daemon is required because Arti is embedded.
- [ ] Fix Cargo metadata — keywords include "SOCKS" and category is web-programming::http-client. This is a server. Correct to web-programming::http-server / network-programming and fix keywords.
- [ ] Sync crates.io with GitHub — crates.io shows v0.2.3 while GitHub latest is v0.3.1. Publish the current release and keep them in lockstep.
- [ ] README -> Add an architecture diagram showing: Tor circuit → rendezvous loop → CircuitPolicy gate → TLS termination → Skin (PoW/WAF/rate-limit) → Axum router.
- [ ] README -> Add a comparison table against real alternatives: arti-axum, tor-hsrproxy, raw Arti, C-tor + nginx/Caddy.
- [ ] README -> Add a status matrix — distinguish: implemented and tested offline / implemented but needs live Tor verification / planned / blocked upstream.
- [ ] README -> Sharpen TLS security wording — "secure and complete by default" overstates; self-signed TLS provides encryption and secure-context mechanics but not browser-trusted authentication. Document: onion address authenticates the service; self-signed TLS ≠ WebPKI trust; use Tls::Provided with CA-signed .onion certs (HARICA) for public services.
- [ ] State MSRV — Cargo.toml uses edition 2024; document the minimum Rust version and enforce in CI.
- [ ] Add a Quick Start / Installation section: `cargo new my-onion-app && cd my-onion-app` `cargo add onyums` Include a complete main.rs.
- [ ] Explain external dependencies explicitly: No external Tor daemon needed (Arti is embedded — this is a selling point being left on the table), First run downloads Tor consensus data, Filesystem paths created (./tor/onyums/state), Outbound network access required
- [ ] Add deployment examples: systemd unit, Dockerfile, minimal container image, persistent volume guidance for keystore, backup/restore of onion identity keys.
- [ ] Add an operator "first successful run" guide: expected bootstrap time, how to print the onion address, how to wait for readiness, how to test from Tor Browser, what to do with self-signed TLS warnings, how to switch to Tls::Provided.
- [ ] Add troubleshooting: Tor bootstrap fails, descriptor never reachable, cert warning, restricted discovery client can't connect, raw TCP backend unreachable, port registration rejected, state directory permission problems.
- [ ] Ship a CLI binary — if broader adoption is the goal, provide onyums serve, onyums status, onyums provision-client, onyums rotate-identity so non-Rust users can front existing services.




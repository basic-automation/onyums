![logo](./assets/onyums-logo.svg)
<br><br>
![docs.rs](https://img.shields.io/docsrs/onyums?style=for-the-badge) ![Crates.io Total Downloads](https://img.shields.io/crates/d/onyums?style=for-the-badge) ![Crates.io License](https://img.shields.io/crates/l/onyums?style=for-the-badge)
<br><br>

Onyums is an axum wrapper for serving tor onion services — secure and complete by default. It bootstraps the Tor client, generates TLS certs, upgrades HTTP to HTTPS, and sits the app behind a built-in abuse-defense gate. It provides the `ConnectionInfo` extractor to differentiate connections made over tor since the concept of `SocketAddrs` does not exist on private connections.

The posture is *secure and complete by default*: the hard, Tor-specific machinery ships enabled, and you opt **down** when you have a reason to — never assemble safety from feature flags.

**What this is:** a Rust library for serving [axum](https://github.com/tokio-rs/axum) applications as Tor onion services, with the Tor client ([Arti](https://gitlab.torproject.org/tpo/core/arti)) embedded — no external `tor` daemon. **What this is not:** a host provisioning / configuration-management tool, a reverse proxy for existing servers, or a SOCKS client. If you want to front an already-running service, that is a planned CLI, not the library.

## Architecture

Every request travels the same secure-by-default path from the Tor network to your
handler. The circuit-level gate runs before any bytes are served; TLS is terminated
inside the onion-encrypted stream; the Skin abuse-defense gate runs before the router:

```
                        Tor network
                             │  rendezvous circuit (RendRequest)
                             ▼
                  ┌───────────────────────┐
                  │   serve loop          │  one task per circuit
                  │   CircuitPolicy gate  │  Accept · Challenge · Reject · Shutdown
                  └──────────┬────────────┘
                             │  accepted stream (StreamRequest)
                             ▼
                  ┌───────────────────────┐
                  │   port dispatch       │  80/443 → HTTP · other → raw handler
                  └────┬──────────────┬───┘
                80/443 │              │ registered raw port
                       ▼              ▼
        ┌───────────────────────┐  ┌───────────────────┐
        │   TLS termination     │  │   RawTcpHandler   │  no Skin / no TLS —
        │   self-signed / BYO   │  │   → local backend │  the backend secures
        │   HTTP→HTTPS · HSTS   │  └───────────────────┘  its own end-to-end
        └──────────┬────────────┘
                   │  decrypted HTTP request
                   ▼
        ┌───────────────────────┐
        │   Skin gate           │  clearance check · PoW → CAPTCHA → tarpit challenge ·
        │   (abuse defense)     │  WAF · rate-limit (keyed on the clearance token)
        └──────────┬────────────┘
                   │  cleared request
                   ▼
             axum Router  →  your handler
```

Each stage is an explicit opt-**down**: `Tls::Strict` rejects plaintext instead of
redirecting, `no_skin()` drops the abuse gate, `under_attack(true)` forces every
circuit through the gate, and `route_port(...)` adds a raw-TCP branch. See the
sections below for each.

## Quick start

From nothing to a live onion service:

```sh
cargo new my-onion-app && cd my-onion-app
cargo add onyums tokio --features tokio/full
```

`src/main.rs` — complete, and it is the whole program:

```rust
use onyums::{OnionService, routing::get, Router};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let app = Router::new().route("/", get(|| async { "Hello from Tor!" }));

	let handle = OnionService::builder()
		.router(app)
		.nickname("my_onion")   // names the identity key in the keystore
		.serve()
		.await?;

	// The address is stable across restarts (the keystore is persisted).
	println!("serving on https://{}", handle.onion_address());

	// Resolves when the descriptor is published and the service is reachable.
	handle.ready().await;
	println!("reachable — open that URL in Tor Browser");

	// Run until Ctrl-C, then stop cleanly.
	tokio::signal::ctrl_c().await?;
	handle.shutdown().await;
	Ok(())
}
```

```sh
cargo run
```

That is the entire secure stack: a self-signed TLS certificate for the address, the
Skin abuse-defense gate, and the WAF are all already on. Expect the first run to
take a minute or two (see [First launch & troubleshooting](#first-launch--troubleshooting)),
and expect a certificate warning in Tor Browser — that one is normal, and
[TLS-first transport](#tls-first-transport) explains why.

### What it needs from the outside

Almost nothing — which is much of the point:

- **No external Tor daemon, no `torrc`, no system service.** The
  [Arti](https://gitlab.torproject.org/tpo/core/arti) Tor client is compiled *into*
  your binary. If you have deployed an onion service behind C-tor before, the thing
  you are looking for to configure is not there, by design.
- **Outbound network access is required** — to reach Tor directory authorities and
  relays. Onyums opens no inbound listener and needs no port forwarded, no public
  IP, and no firewall hole: rendezvous circuits are established *outbound*. A host
  that can make outbound TCP connections can serve an onion service.
- **The first run downloads the Tor network consensus**, which is why it is slower
  than later ones. It is cached (see below) and refreshed as needed.
- **Two directories are created under the process's working directory**:
  `./tor/onyums/state` — the keystore holding the service's identity key. **This is
  the service's identity**: back it up, keep it owner-only (onyums enforces
  `0700`/`0600` on Unix — see [Deployment](#deployment)), and it is what makes the
  address stable across restarts. And `./tor/onyums/cache` — the network consensus,
  disposable and refetched if deleted.
- **A clock that is roughly right.** Tor is sensitive to clock skew; a badly wrong
  system time is a common cause of a bootstrap that never finishes.

**Toolchain:** Rust **edition 2024**, MSRV **1.91** — declared as `rust-version` in
the manifest and enforced in CI. The floor comes from the embedded arti 0.44 stack,
not the edition (edition 2024 alone would need only 1.85). The `onyums-skin` crate,
which carries none of arti, is usable on **1.89**.

## Features

- **One-liner serve** — `serve(app, "nickname")` is the full secure stack; the builder (`OnionService::builder()`) tunes or relaxes it.
- **Abuse defense on by default (Skin)** — a proof-of-work gate, no-JS fallbacks, token-keyed rate limiting, and a pure-Rust WAF, plus an Under Attack Mode toggle and observable security events; see [Abuse defense (Skin)](#abuse-defense-skin--on-by-default).
- **Restricted discovery (v3 client authorization)** — `.authorized_clients(...)` publishes a descriptor only the listed clients can decrypt, so an unlisted client cannot even discover the service; `provision_client(...)` mints a new client's x25519 keypair and renders Tor's canonical `.auth` / `.auth_private` files. See [Restricted discovery](#restricted-discovery--v3-client-authorization).
- **Real readiness + graceful shutdown** — the builder returns an `OnionServiceHandle` with `ready()` (and bounded `ready_timeout()`), `wait_until_settled()` (resolves on reachable *or* a terminal failure, so a broken bootstrap never hangs), a synchronous `status()` snapshot and non-blocking `is_ready()`, a `status_events()` transition stream, the typed `.onion` address, and `shutdown()`.
- **Observability — what, why, and how much** — `status()` says what the service's reachability is, `problem()` says *why* when it isn't healthy (a stable `ServiceProblem` projection of arti's `Display`-less diagnostics), `health()` bundles both from one consistent read, and `metrics()` exposes per-service circuit/stream counters (with `since()` interval deltas) for a `/up` line — plus a built-in Prometheus exporter (`metrics_prometheus()` per service, `fleet_prometheus(...)` for many) ready to serve at `/metrics`.
- **Multiple services on one bootstrap** — bootstrap once with `OnionService::shared_client()` (or reuse a running handle's `tor_client()`), pass it to several builders via `.tor_client(...)`, and aggregate fleet health with `ServiceStatus::worst_of([...])`.
- **TLS-first transport** — auto-generated self-signed certs, automatic HTTP→HTTPS upgrade, strict mode with HSTS, or bring your own CA-signed cert; see [TLS-first transport](#tls-first-transport).
- **Any protocol over the onion service** — `.route_port(port, handler)` tunnels raw TCP / gRPC / SSH / Lightning alongside the built-in TLS HTTP handler, with opt-in raw-port controls (`ConnectionLimit` concurrency caps, `AuthGate` + `SharedSecretAuth` to put authentication in front of an unauthenticated backend); see [Protocol versatility](#protocol-versatility--any-protocol-over-an-onion-service).
- **Stable identity, opt-down to throwaway** — a persistent keystore by default (stable `.onion` across restarts), or `.ephemeral()` for a fresh, disposable address each run; plus vanity-address mining, offline inspection of a Tor `hs_ed25519_secret_key` file (derive the address a key serves — launching *from* an imported key is not yet supported), and address helpers (QR, `Onion-Location`); see [Identity & address helpers](#identity--address-helpers).
- **Websockets over Tor** — with the per-circuit `ConnectionInfo` as the client identity (typed `is_over_tor()` / `circuit()` / `same_circuit()` helpers for per-circuit isolation); see [Websocket example](#websocket-example).
- **Version-skew-proof arti** — the arti stack is re-exported (`onyums::arti_client`, `onyums::tor_hsservice`, `onyums::tor_hscrypto`, …) so downstreams use the exact versions onyums does, just like `axum`.

## How onyums compares

Onyums sits between "thin arti glue" and "a C-tor daemon behind a reverse proxy": a
single embedded-Arti library that adds the TLS-first transport and Tor-native abuse
defense you would otherwise assemble yourself.

| | **onyums** | [arti-axum](https://github.com/jgraef/arti-axum) | [tor-hsrproxy](https://tpo.pages.torproject.net/core/arti/) (`arti hss`) | raw [Arti](https://gitlab.torproject.org/tpo/core/arti) (`arti-client` + `tor-hsservice`) | C-tor + nginx/Caddy |
|---|---|---|---|---|---|
| Serve an **axum app** | ✅ built-in | ✅ built-in | ⚠️ run your own server behind it | ⚠️ write the accept loop yourself | ⚠️ separate app server |
| **Embedded** Tor (no external daemon) | ✅ Arti | ✅ Arti | ✅ Arti | ✅ Arti | ❌ external `tor` daemon |
| **TLS-first** inside the circuit | ✅ auto self-signed / BYO / strict | ❌ | ❌ | ❌ (DIY) | ⚠️ proxy-configured |
| **Abuse defense** (PoW · WAF · rate-limit) | ✅ Skin, on by default | ❌ | ❌ | ❌ | ⚠️ bolt-on proxy modules, not Tor-native |
| **Restricted discovery** (v3 client auth) | ✅ `.authorized_clients(...)` | ❌ | ⚠️ via arti config | ⚠️ via arti config | ⚠️ via `tor` config |
| **Raw-port / multi-protocol** routing | ✅ `.route_port(...)` | ❌ | ✅ (it *is* a port proxy) | ⚠️ DIY | ✅ separate services |
| **Readiness / health / metrics** handle | ✅ `ready()` · `status()` · Prometheus | ❌ | ⚠️ operational, not in-process | ❌ | ⚠️ external monitoring |
| Implementation | 100% Rust | 100% Rust | 100% Rust | 100% Rust | C + proxy |

✅ built-in · ⚠️ possible but you assemble/operate it yourself · ❌ not provided.
Reach for **raw Arti** when you want to build the stack yourself, **tor-hsrproxy** to
front an existing local service with no app code, and **onyums** when you want the
secure-by-default axum→onion path in one library.

## Feature status — how much to trust each of these

Pre-1.0, and the honest answer differs per feature, so here it is per feature. The
distinction that matters most is the middle row group: onyums' automated tests are
**offline** (a `tower`-level harness with no Tor network), so a feature can be fully
unit-tested and still never have been exercised against real Tor by CI. The live
tier exists — `live_service_serves_over_the_tor_network_and_shuts_down`, run
manually with `cargo test -- --ignored` — but it is not part of CI and does not
cover every row below.

| Status | Meaning |
|---|---|
| 🟢 **Tested offline** | Implemented, with automated tests that CI runs on every push. No live Tor involved. |
| 🟡 **Needs live verification** | Implemented and compiles; its logic is unit-tested where it could be isolated, but the code path only truly runs against the real Tor network, which CI does not do. |
| 🔵 **Planned** | Not implemented. |
| 🔴 **Blocked upstream** | Cannot be implemented from here until arti changes. |

| Feature | Status | Notes |
|---|---|---|
| `serve()` / builder API, config validation | 🟢 | Nickname, port, TLS, and client-choice validation all fail offline before any bootstrap. |
| TLS policy (`Upgrade` / `Strict` / `Provided`) | 🟢 | Composition (gate + HSTS + app) is `oneshot`-tested; `ProvidedCert` parses/validates up front. |
| Skin gate, WAF, rate limiting, clearance tokens | 🟢 | 476 unit tests in `onyums-skin`, no Tor needed. Bounded by the WAF's best-effort nature — see [What the gate does *not* do](#what-the-gate-does-not-do). |
| Restricted discovery / client-auth keys | 🟢 | Key generation, `.auth` rendering/parsing, and allowlist assembly are offline-tested and byte-checked against Tor's file format. Descriptor encryption itself is arti's. |
| Identity: persistent + `.ephemeral()` keystore | 🟢 | Directory resolution, uniqueness, and cleanup tested offline. |
| Keystore permission hardening (0700/0600) | 🟢 | Unix-only; the syscall path runs on CI's Linux runner. A no-op on Windows (see [Deployment](#deployment)). |
| Vanity mining, address helpers, QR | 🟢 | Pure computation; derives the exact address arti serves. |
| `ServiceStatus` / `ServiceProblem` projection | 🟢 | Mapping tested against every arti state. The *emission* of transitions is 🟡. |
| Host-side metrics + Prometheus exposition | 🟢 | Counter mechanics and text format tested offline, and the accept loop's circuit/stream increment sites are now covered too (offered-before-verdict, accepted, rejected, served, shut down). |
| **Live serve over Tor** (rendezvous → TLS → app) | 🟡 | The core path: TLS termination and the axum handoff only run against real Tor. The `--ignored` live test covers it and CI does not run it — and note that test is currently unreliable (it has been observed hanging well past its own internal timeouts), so treat this row as genuinely unverified rather than verified-elsewhere. |
| Raw-port serving (`route_port`) | 🟡 | The routing table and the `RawTcpHandler` proxy are offline-tested against a loopback backend; the live path is not. |
| Circuit-policy gate, Under Attack mode | 🟢 | Both the decisions *and* the accept loop's sequencing around them are offline-tested: that a refused circuit is never accepted and yields no streams, that a rejected stream leaves the circuit alive, that a `Shutdown` verdict stops the loop, that a challenge fails closed on a raw port, and that per-circuit accounting is always dropped. What remains live-only is the TLS/serve step itself (next row). |
| Host-global caps (`max_circuits` / `max_streams`) | 🟢 | Refusal-at-capacity, permit release, the unbounded defaults, and the `0` rejections are all offline-tested; refusals are counted separately from policy rejections, and a capacity-refused stream is counted once. |
| Multiple services on one shared client | 🟡 | The offline surface (`shared_client()`, conflict rejection, fleet status) is tested; N-services-actually-reachable is not verified. |
| `status_events()` stream emission | 🟡 | Projection tested; live emission not. `ready()` lags real reachability — see [First launch](#first-launch--troubleshooting). |
| Launching from a **bring-your-own** key | 🔵 | Offline inspection only; you cannot serve an existing `.onion` address yet. |
| Intro-layer PoW (Tor's Equi-X) | 🔵 | Needs arti's experimental `hs-pow-full`. Skin's PoW is HTTP-layer only. |
| Host-global concurrency/backpressure caps | 🔵 | Per-circuit limits exist via `CircuitPolicy`; total circuit/stream semaphores do not. |
| CLI binary, framework layer (Phase 5) | 🔵 | Library only today. |
| Single-onion-service mode | 🔴 | The `anonymity` field is still commented out in tor-hsservice 0.44. |
| arti-sourced gauges (intro-point health, …) | 🔵 | Reachable but not taken: `tor-hsservice` 0.44's `metrics` feature is marked `__is_experimental` (non-semver), the same category as the intro-layer PoW feature. A decision, not a flag. |

Full detail, including what each slice covers, lives in [ROADMAP.md](ROADMAP.md).

## Hello world example

The one-line `serve()` entry point still works and blocks until the service stops:

```rust
use onyums::{serve, routing::get, Router};

#[tokio::main]
async fn main() {
	let app = Router::new().route("/", get(|| async { "Hello, World!" }));
	serve(app, "my_onion").await.unwrap();
}
```

For the address and a real readiness signal, use the builder. It returns an
`OnionServiceHandle` once the address is known; `ready()` resolves when the
descriptor is published and the service is actually reachable (no more polling a
global), and `shutdown()` stops it gracefully:

```rust
use onyums::{OnionService, routing::get, Router};

#[tokio::main]
async fn main() {
	let app = Router::new().route("/", get(|| async { "Hello, World!" }));

	let handle = OnionService::builder()
		.router(app)
		.nickname("my_onion")
		.serve()
		.await
		.unwrap();

	handle.ready().await; // descriptor published, reachable
	println!("Onion Address: {}", handle.onion_address());

	// Poll the current health without blocking (still bootstrapping? degraded? broken?):
	if handle.is_ready() {
		println!("service is reachable");
	}

	// ... serve for a while ...
	handle.shutdown().await; // graceful stop
}
```

`status()` returns a stable `ServiceStatus` — `Shutdown` / `Bootstrapping` /
`Reachable` / `DegradedReachable` / `Unreachable` / `Broken` — onyums' own
projection of arti's onion-service state, so you can surface health at any moment
instead of only awaiting first reachability with `ready()`. Each variant carries
predicates (`is_reachable()`, `is_degraded()`, `is_broken()`, `is_terminal()`) and
a stable `Display` label for a `/up`-style health line.

For startup that must not hang, `ready_timeout(dur)` returns `false` if the
service is not reachable within the deadline, and `wait_until_settled()` resolves
the moment the service is either reachable **or** terminally `Broken`/`Shutdown`
— so a bootstrap that fails surfaces as a settled status instead of an infinite
wait:

```rust
use std::time::Duration;

if handle.ready_timeout(Duration::from_secs(90)).await {
	println!("reachable");
} else {
	// didn't come up in time — inspect why
	println!("not ready: {}", handle.status()); // e.g. "bootstrapping" or "broken"
}
```

When a service is not fully healthy, `status()` says *what* — `problem()` says
*why*. It returns an `Option<ServiceProblem>` projected from arti's onion-service
diagnostics: a stable, matchable category (`Runtime` / `DescriptorUpload` /
`IntroductionPoint` / `Other`, via `.kind()`) plus a readable detail (`.detail()`
/ `Display`). `health()` bundles both into a `ServiceHealth` snapshot read from a
*single* status sample, so the status and its problem never disagree across a
transition:

```rust
let health = handle.health();
if !health.is_healthy() {
	// e.g. "unreachable — introduction-point: ..." or "reachable" when all-green
	eprintln!("degraded: {health}");
}
```

`handle.metrics()` returns a `ServiceMetrics` snapshot of the per-service counters
the accept loop keeps — rendezvous circuits offered / accepted / rejected at the
circuit-policy gate, and streams served / rejected / circuit-torn-down at the
per-stream gate. The counters are monotonic totals, so `later.since(earlier)`
gives the activity over an interval for a rate, and the derived
`circuits_failed_transport()` (offers arti couldn't accept) and `total_streams()`
helpers round out a health line:

```rust
let before = handle.metrics();
// ... serve for a while ...
let rate = handle.metrics().since(before);
println!("{} circuits, {} streams in the last interval", rate.circuits_offered, rate.streams_served);
```

**Prometheus export is built in.** `handle.metrics_prometheus()` renders the
counters in the Prometheus text exposition format, labeled with the service's
`.onion` address — the ready-to-serve body for a `/metrics` endpoint. For several
services, `onyums::fleet_prometheus(...)` folds them into one valid exposition
(each metric's `# HELP`/`# TYPE` header emitted once), which is what you want
instead of concatenating per-service outputs:

```rust
use onyums::fleet_prometheus;

// One service:
let body = handle.metrics_prometheus();

// A whole fleet at a single /metrics endpoint:
let body = fleet_prometheus(
	handles.iter().map(|h| (h.onion_address().as_str(), h.metrics())),
);
// # HELP onyums_circuits_offered_total ...
// # TYPE onyums_circuits_offered_total counter
// onyums_circuits_offered_total{service="abcd….onion"} 42
```

### Multiple services on one bootstrap

Tor bootstrap is the slow part of coming up; a single client can host any number
of onion services, each keyed by its own nickname. Bootstrap once and share it,
then fold the fleet's health into a single worst-case signal:

```rust
use onyums::{OnionService, ServiceStatus, routing::get, Router};

#[tokio::main]
async fn main() {
	let client = OnionService::shared_client().await.unwrap();

	let blog = OnionService::builder()
		.router(Router::new().route("/", get(|| async { "blog" })))
		.nickname("blog")
		.tor_client(client.clone())
		.serve()
		.await
		.unwrap();
	let wiki = OnionService::builder()
		.router(Router::new().route("/", get(|| async { "wiki" })))
		.nickname("wiki")
		.tor_client(client) // or blog.tor_client() from a running handle
		.serve()
		.await
		.unwrap();

	// Aggregate health — one broken service is never masked by healthy siblings.
	if let Some(worst) = ServiceStatus::worst_of([blog.status(), wiki.status()]) {
		println!("fleet: {worst}");
	}
}
```

The shared client's type is `onyums::OnionTorClient` — an alias for arti's
`TorClient<..>` with the runtime onyums bootstraps on. Name the alias rather than
spelling the runtime out: which TLS implementation arti uses for its relay connections
is onyums' choice, not yours, and it is expected to change (see the roadmap's "no FFI"
item). Code written against the alias keeps compiling when it does.


`.ephemeral()` conflicts with `.tor_client(...)` — a shared client has a fixed
keystore and cannot supply a throwaway per-launch identity — and that pairing is
rejected offline, before any launch.

****

## Abuse defense (Skin) — on by default

Onyums bundles [`onyums-skin`](crates/onyums-skin), a "Cloudflare for Tor" abuse-defense layer, and **wires it in by default**. With no extra work, every served router sits behind a secure gate:

- a **proof-of-work** challenge for JavaScript clients (a few hundred ms of browser work to mint a clearance),
- a no-JS **server-rendered CAPTCHA** fallback (a distorted-image human check, answered in a plain GET form) and, behind it, a **patience tarpit** — so a Tor "Safer"/"Safest" client (JS and WASM disabled) always has a path through, with a human-verification tier before the last-resort delay,
- **rate limiting** keyed on a stateless, signed clearance token — a synthetic per-client identity, since there are no client IPs over Tor, and
- a pure-Rust **WAF** with a starter signature ruleset (SQLi / XSS / path traversal / command & code injection / SSRF / protocol anomalies).

The posture is *secure and complete by default*: the gate is on unless you turn it off, and you opt **down** (`no_skin`) or **across** (a custom `Skin`), never up.

### What the gate does *not* do

"Abuse defense on by default" is a floor, not a guarantee. Three limits are worth
stating plainly, because assuming otherwise is how a service gets hurt:

- **The WAF is best-effort and non-authoritative.** It is a *starter signature
  ruleset* — pattern matching over the request. Signature WAFs are bypassable, and
  a determined attacker with time to iterate will get a payload past this one. It
  exists to cut background noise and raise the cost of drive-by scanning; it is
  **not** a substitute for a secure application. Parameterise your queries, encode
  your output, and authorise every request as if the WAF were not there. Treat a
  WAF block as telemetry, not as proof you were safe.
- **The proof-of-work is HTTP-layer only — there is no Tor introduction-point
  PoW.** The challenge is served by the Skin gate *after* a rendezvous circuit has
  already been established, so it raises the cost of hammering your *application*.
  It does nothing about a flood aimed at your introduction points, which is the
  attack Tor's own onion-service PoW (Equi-X, `tor-hspow`) addresses. That lives
  in arti behind an experimental feature and is **not** wired up here (ROADMAP
  Phase 2). If you are being flooded at the intro layer, onyums does not currently
  help.
- **The gate keys on the circuit and the clearance token, not on an identity.**
  There are no client IPs over Tor, so a `CircuitId` is synthetic and an attacker
  can rotate circuits at will. Per-circuit limits are therefore a speed bump, not
  a ban. Bind anything that must be durable to a clearance token, a restricted-
  discovery key, or your own application auth.

```rust
use onyums::{OnionService, Skin, routing::get, Router};

#[tokio::main]
async fn main() {
	let app = Router::new().route("/", get(|| async { "Hello, World!" }));

	let handle = OnionService::builder()
		.router(app)
		.nickname("my_onion")
		// The secure-default gate is ALREADY ON. Use these only to tune or relax it:
		// .skin(Skin::secure_default())        // tune via Skin::builder() (difficulty, store, WAF, ...)
		// .circuit_policy(my_policy)            // per-rendezvous-circuit limits (custom CircuitPolicy)
		// .max_circuits(256)                    // host-global cap: refuse (never queue) circuits beyond N
		// .max_streams(1024)                    // host-global cap on concurrent streams across all circuits
		// .under_attack(true)                   // force EVERY new circuit through the gate (flood mode)
		// .circuit_events(my_sink)              // observe circuit rejects/teardowns/challenges
		// .adaptive_difficulty(controller)      // feed circuit-flood load into Skin's adaptive PoW
		// .authorized_clients(allowlist)        // restricted discovery — only listed clients can reach it
		// .tls(Tls::Strict)                     // make TLS non-negotiable (reject plaintext, emit HSTS)
		// .tls(Tls::Provided(my_cert))          // serve your own CA-signed cert instead of self-signed
		// .route_port(9735, raw_handler)        // serve another protocol (raw TCP, gRPC, SSH, ...) on a non-HTTP port
		// .ephemeral()                          // throwaway identity — a fresh, disposable .onion each run
		// .no_skin()                            // opt out of the gate entirely
		.serve()
		.await
		.unwrap();

	println!("Onion Address: {}", handle.onion_address());
	handle.ready().await;
	handle.shutdown().await;
}
```

The full Skin API (clearance tokens, the challenge chain, the WAF, per-circuit `CircuitPolicy`, adaptive difficulty, and security metrics/events) is re-exported under `onyums::onyums_skin`. The design and roadmap live in [`crates/onyums-skin/ROADMAP.md`](crates/onyums-skin/ROADMAP.md).

****

## Host-global backpressure

`.circuit_policy(...)` bounds what a *single* circuit may do (streams, request rate, byte
budget). `.max_circuits(n)` bounds how many circuits exist at once — without it a service
spawns a task per offered circuit and a flood is bounded only by memory.

At capacity onyums **refuses** the circuit; it never queues it. Queueing would convert a
flood into unbounded memory growth plus a latency cliff for the clients already being
served, which is the failure the cap exists to prevent — and a refused client can retry,
while one parked in an invisible queue cannot tell slow from dead. The permit is taken
after the circuit policy admits the circuit and released when the circuit ends, however
it ends.

Refusals are reported separately from policy rejections, as
`ServiceMetrics::circuits_refused_at_capacity` (`onyums_circuits_refused_at_capacity_total`
in the Prometheus exposition). That distinction is the useful part: a policy rejection is
a verdict about the circuit, while a capacity refusal means the service is full. If you
alarm on the two together, an under-provisioned service looks like one under attack, and
you will tune the wrong knob.

`.max_streams(n)` is the companion cap, on concurrently-served **streams** across every
circuit. It is not a duplicate: the circuit cap bounds how many clients are in service,
this bounds the total work in flight — one circuit may open many streams, so a circuit
cap alone does not bound sockets or memory. A stream refused for capacity gets Tor's
`RESOURCELIMIT` end reason (which says the service is full, rather than claiming the
request was simply done) and leaves the circuit and its other streams alive, exactly as a
policy rejection does. It is counted as `ServiceMetrics::streams_refused_at_capacity`.

Both `max_circuits(0)` and `max_streams(0)` are rejected by `serve()` before any
bootstrap, rather than becoming a live onion address that answers nothing.

Not implemented yet: a max body size before WAF inspection, and per-handler timeouts.

## Restricted discovery — v3 client authorization

For a service with a known, small set of users, `.authorized_clients(...)` enables Tor's **restricted discovery** (v3 client authorization): the service descriptor — its introduction points and keys — is encrypted to the listed clients' x25519 keys, so an *unlisted* client cannot even discover the service. This is DoS resistance enforced in descriptor crypto, upstream of the Skin HTTP gate rather than in place of it.

> **Restricted discovery is not authentication.** It controls who can *find* the
> service, not who may *do* what once they arrive. Read it as an unlisted phone
> number, not a lock on the door:
>
> - **Removing a client does not revoke it.** The allowlist gates descriptor
>   *decryption*, so a removed client keeps working until the descriptor is
>   republished and its existing circuits die — and anyone who already learned the
>   introduction points can keep reaching you meanwhile. There is no session kill.
> - **The key is a bearer credential.** It identifies a *client entry*, not a
>   person; a leaked or shared `.auth_private` is indistinguishable from the real
>   client, and nothing binds it to a request.
> - **Every authorized client is equal.** There are no roles, no per-route
>   permissions, and no audit trail of who did what.
>
> So layer real authentication *inside* the app and treat discovery as the outer
> shell. The two compose — restricted discovery keeps strangers from ever opening a
> circuit, the Skin gate absorbs abuse from those who do, and app auth decides what
> an authenticated user may actually do:
>
> ```rust
> // Restricted discovery says WHO CAN FIND the service.
> // Your app still says WHO THIS IS and WHAT THEY MAY DO.
> let app = Router::new()
> 	.route("/admin", get(admin_page))
> 	.layer(middleware::from_fn(require_login)); // sessions/tokens/mTLS — your call
>
> let handle = OnionService::builder()
> 	.router(app)
> 	.nickname("private_service")
> 	.authorized_clients(allowlist) // outer shell: strangers cannot even discover it
> 	.serve()
> 	.await?;
> ```
>
> A useful test: if leaking one client's `.auth_private` file would be a breach
> rather than an inconvenience, you are relying on restricted discovery for
> authentication and need app auth underneath it.

The allowlist is an `onyums_skin::RestrictedDiscovery`, built from `.auth` files or by authorizing keys directly:

```rust
use onyums::{OnionService, RestrictedDiscovery, ClientAuthKey, routing::get, Router};

#[tokio::main]
async fn main() {
	let app = Router::new().route("/", get(|| async { "authorized clients only" }));

	// nickname → x25519 client key. Load from a Tor `authorized_clients/` dir with
	// `RestrictedDiscovery::from_auth_files(...)`, or authorize keys directly:
	let mut allowlist = RestrictedDiscovery::new();
	allowlist.authorize("alice", ClientAuthKey::from_bytes([/* alice's 32-byte x25519 key */ 0; 32]));

	let handle = OnionService::builder()
		.router(app)
		.nickname("private_service")
		.authorized_clients(allowlist) // an empty allowlist is rejected (would hide it from everyone)
		.serve()
		.await
		.unwrap();

	println!("Onion Address: {}", handle.onion_address());
	handle.shutdown().await;
}
```

This is an explicit opt-*down* in reachability (from "anyone with the address" to "only these clients") — and, per the note above, a discovery control rather than an authentication one.

### Provisioning a new client

The example above *imports* an already-known key. To onboard a brand-new client you first have to **generate** its x25519 keypair. `provision_client` does the whole ceremony in one call — generate the keypair, authorize its public half into the allowlist, and hand you back the keypair so you can give the client its secret:

```rust
use onyums::{provision_client, ClientAuthKeypair, OnionAddress, RestrictedDiscovery};

let mut allowlist = RestrictedDiscovery::new();

// Generate + authorize a fresh client in one step.
let alice = provision_client(&mut allowlist, "alice");

// Operator side: write the server-side `authorized_clients/alice.auth` files.
for (file, body) in allowlist.to_auth_files() {
	// std::fs::write(auth_dir.join(&file), body) ...
	let _ = (file, body);
}

// Client side: give Alice the `.auth_private` line for her Tor `ClientOnionAuthDir`.
let address = OnionAddress::normalized("examplev3address.onion");
let auth_private = alice.auth_private_line(&address);
// -> "examplev3address:descriptor:x25519:<BASE32-secret>"

// The keypair round-trips back out of that line (e.g. to re-derive the public key).
let (_addr, recovered) = ClientAuthKeypair::from_auth_private_line(&auth_private).unwrap();
assert_eq!(recovered.public_key(), alice.public_key());
```

The keypair is minted with arti's own `tor-llcrypto` curve25519 (no extra crypto dependency), and the `.auth` / `.auth_private` renderings match Tor's canonical file formats — so a generated key drops straight into either a native-arti or a C-tor deployment. `ClientAuthKeypair` holds a secret, so its `Debug` is redacted and its secret is **zeroized on drop** (`ZeroizeOnDrop`), scrubbing the disposable x25519 key from memory rather than leaving it behind.

Watching a service come up is a stream, not just a snapshot: `handle.status_events()` yields each `ServiceStatus` transition (bootstrapping → reachable → degraded) so you can react to health changes without polling `status()`.

****

## TLS-first transport

Onyums treats encrypted transport as the standard, never as optional cruft to strip away. **The onion address itself authenticates the service** — a `.onion` is derived from the service's public key, so reaching one cryptographically proves you are talking to that key-holder, no certificate authority required. On top of that, end-to-end TLS — even the default self-signed cert — keeps the app-facing hop encrypted independently of Tor and unlocks the browser **secure-context** semantics real apps depend on (WebCrypto, service workers, `Secure` / `__Host-` cookies, HTTP/2, no mixed-content downgrades). What a self-signed cert does **not** add is WebPKI/browser-trusted authentication *of the certificate* — that job is already done by the onion address; use `Tls::Provided` with a CA-signed `.onion` cert only when a client insists on a publicly-trusted chain. The knob is *how strictly* TLS is enforced, never whether it is on:

- **`Tls::Upgrade` (default)** — an auto-generated self-signed cert, and plaintext HTTP on port 80 is transparently redirected (`301`) to HTTPS. A client that arrives over plain HTTP is pointed at the secure URL rather than refused.
- **`Tls::Strict`** — TLS is non-negotiable. Plaintext circuits are **rejected outright** (there is no port-80 redirect handler at all), and every HTTPS response carries an `Strict-Transport-Security` header (`max-age=63072000; includeSubDomains`) so a conforming client never silently downgrades.
- **`Tls::Provided(cert)`** — serve your **own** certificate chain and key instead of the auto-generated self-signed one, for CA-signed `.onion` certificates (e.g. [HARICA](https://www.harica.gr/)) that some clients and browsers prefer. Build the cert once with `ProvidedCert::from_pem(cert_pem, key_pem)` — it parses and validates the pair up front, so a bad cert/key is a clean error at startup, not a runtime surprise. Bringing your own cert is *orthogonal* to plaintext strictness: it keeps the forgiving `Upgrade` posture (port-80 → HTTPS redirect, no HSTS).

### Why TLS *inside* Tor? ("double encryption")

A fair question, since the Tor circuit is already encrypted and — unlike the
public-internet case — an onion service has **no exit node**: the circuit is
encrypted end to end, all the way to the service. So the inner TLS is not a second
lock against a network eavesdropper; that threat is already handled. What it
actually buys is:

- **Secure-context semantics.** Browsers gate real capabilities on *the scheme in
  the URL bar*, not on how the bytes travelled. Over `http://…onion` you lose
  WebCrypto, service workers, `Secure` / `__Host-` cookie prefixes, HTTP/2, and you
  invite mixed-content blocking. TLS is what makes an onion service a first-class
  web origin.
- **A correct view of the request.** The app sees the `https` scheme and the
  headers it implies, so redirects, cookie flags, `Onion-Location`, and anything
  else that reasons about the scheme behave the way they would anywhere else.
- **Defence in depth against misconfiguration** — a stray plaintext listener, or a
  future deployment where the router is *not* in this process, fails closed under
  `Tls::Strict` rather than quietly serving cleartext.

Being precise about what it does **not** buy, since "double encryption" invites
overclaiming: arti runs in-process and TLS terminates in that same process, so the
inner layer is **not** meaningful protection against an attacker who can read this
process's memory — such an attacker holds the TLS keys *and* the plaintext. Nor is
it protection against a malicious Tor relay, which is already outside the circuit's
end-to-end encryption. And it does not apply to raw ports at all: a
`route_port(...)` handler is deliberately not TLS-wrapped (the onion circuit
already encrypts and authenticates it, and the backend protocol negotiates its own
security).

The honest summary: the onion address authenticates, the circuit encrypts, and the
inner TLS is what makes the browser treat your service like the real web
application it is.

```rust
use onyums::{OnionService, ProvidedCert, Tls, routing::get, Router};

let cert = ProvidedCert::from_pem(
	&std::fs::read("fullchain.pem").unwrap(),
	&std::fs::read("privkey.pem").unwrap(),
).expect("certificate and key are a valid, usable pair");

let handle = OnionService::builder()
	.router(Router::new().route("/", get(|| async { "Hello, World!" })))
	.nickname("my_onion")
	.tls(Tls::Provided(cert)) // serve a CA-signed cert instead of self-signed
	.serve()
	.await
	.unwrap();
```

```rust
use onyums::{OnionService, Tls, routing::get, Router};

#[tokio::main]
async fn main() {
	let app = Router::new().route("/", get(|| async { "Hello, World!" }));

	let handle = OnionService::builder()
		.router(app)
		.nickname("my_onion")
		.tls(Tls::Strict) // opt DOWN in client tolerance — TLS is always on
		.serve()
		.await
		.unwrap();

	println!("Onion Address: {}", handle.onion_address());
	handle.ready().await;
	handle.shutdown().await;
}
```

`.tls(Tls::Strict)` is an explicit opt **down** in client tolerance, never an opt *up* into TLS: TLS is on in every mode.

****

## Protocol versatility — any protocol over an onion service

The built-in handler is the TLS-enforced HTTP/WS app, serving port 443 (HTTPS) and port 80 (the HTTPS upgrade/redirect). But an onion service is just a byte tunnel, so onyums lets you serve **any** protocol on **any other** port with `.route_port(port, handler)` — gRPC, SSH, a game server, Lightning, anything that speaks raw TCP:

```rust
use onyums::{OnionService, RawTcpHandler, routing::get, Router};

let handle = OnionService::builder()
	.router(Router::new().route("/", get(|| async { "Hello, World!" }))) // HTTP on 443/80
	.nickname("my_onion")
	.route_port(9735, RawTcpHandler::new("127.0.0.1:9735")) // Lightning over the onion service
	.route_port(2222, RawTcpHandler::new("127.0.0.1:22"))   // SSH over the onion service
	.serve()
	.await
	.unwrap();
```

`RawTcpHandler` forwards each accepted stream to a local TCP backend and splices the two together until either side closes. The backend protocol negotiates its own end-to-end security over the already-encrypted onion channel — onyums does **not** wrap a raw handler in its TLS, which is reserved for the HTTP handler.

A raw port has no HTTP challenge surface, so when the circuit policy (e.g. Under Attack Mode) returns `Challenge` for a stream bound to a raw port, onyums **fails closed** — the stream is rejected rather than served ungated. The challenge is only presented on the reserved HTTP ports (80/443), where the Skin gate can render it.

Bring your own protocol by implementing the `StreamHandler` trait (one method: `serve(&self, stream: OnionStream) -> ServeFuture`). The TLS-first posture is preserved no matter what you register: ports **80 and 443 stay reserved for the built-in HTTP handler**, so a raw handler may only occupy another (otherwise-rejected) port — registering a reserved port, port 0, or the same port twice is a clean error from `serve()`, not a runtime surprise. This is an opt **up** in protocol reach, never a relaxation of the secure HTTP defaults.

> **A raw port is unguarded — know what you are opening.** The HTTP defaults are
> untouched, but nothing on the HTTP defence path reaches a raw stream: **no Skin
> gate, no PoW/challenge, no WAF, no rate limiting, and no built-in TLS**. The onion
> circuit still encrypts and authenticates the channel, and Tor still makes the port
> unscannable and unreachable without the address — but from the handler inward, the
> backend protocol's own authentication is the only thing standing there.
>
> So `serve()` logs a `WARN` for every registered raw port, naming what does not
> apply, and names the service when the port is a well-known administrative or
> datastore one (SSH, PostgreSQL, Redis, MongoDB, Docker's API, …) — the protocols
> normally bound to loopback *because* they are not built to face hostile traffic.
> Publishing one over an onion service is a legitimate and rather good idea done
> deliberately (a globally reachable admin port with no open firewall port and no IP
> to scan); it is a bad one done by accident, and the log is where the two are told
> apart. If you wrap the port in an `AuthGate` or a `ConnectionLimit` (below), the
> warning says so — *"this handler does apply: a stream authorizer; a connection
> limit of 8"* — rather than pretending the port is wide open. The same data is
> available programmatically via `PortRouter::exposures()` (each exposure carries a
> `HandlerProtection`) / `well_known_sensitive_service(port)` if you would rather
> assert on it in your own startup checks.
>
> Two things worth stating: restricted discovery controls who can *find* the service,
> not who may use a raw port once found; and per-circuit `CircuitPolicy` limits still
> apply at the circuit layer, but a `Challenge` verdict on a raw port **fails closed**
> (rejected, not served ungated) since there is no HTTP surface to render a challenge
> on.

**Cap the concurrency.** Nothing on the HTTP defence path bounds how many connections
reach a raw backend, so the only limit is how fast an attacker can open rendezvous
circuits. `ConnectionLimit` wraps any handler and refuses a stream once the port is at
capacity:

```rust
use onyums::{ConnectionLimit, OnionService, RawTcpHandler, routing::get, Router};

let ssh = ConnectionLimit::new(RawTcpHandler::new("127.0.0.1:22"), 4)?;

let handle = OnionService::builder()
	.router(Router::new().route("/", get(|| async { "hi" })))
	.nickname("my_onion")
	.route_port(2222, ssh)  // at most 4 concurrent SSH connections
	.serve()
	.await?;
```

At capacity the stream is **closed immediately, not queued** — queueing would turn a
connection flood into unbounded memory growth and a latency cliff for the clients
already connected, which is the failure a limit exists to prevent. A refused client can
retry; one parked in an invisible queue cannot tell slow from dead. The cap is per
wrapper, so each port gets its own budget, and `in_flight()` / `is_saturated()` expose
the current state for a health endpoint. A limit of `0` is rejected at construction
rather than becoming a port that silently accepts nothing.

**Put authentication in front of a raw backend.** Many of the services people expose over
an onion service — Redis, a Docker socket, Memcached, an internal admin port — authenticate
weakly or not at all, on the assumption that only loopback can reach them. `AuthGate` puts a
decision in front of the backend: it wraps any handler behind a `StreamAuthorizer` that must
approve a stream *before the backend sees it*. The batteries-included `SharedSecretAuth`
admits a connection only if it opens with a pre-shared secret, which it strips before
forwarding the rest of the stream:

```rust
use onyums::{AuthGate, ConnectionLimit, OnionService, RawTcpHandler, SharedSecretAuth, routing::get, Router};

// The client prepends this secret to the connection; the gate reads it, compares in
// constant time, and forwards only what follows to Redis.
let auth = SharedSecretAuth::new(std::env::var("REDIS_ONION_SECRET")?.into_bytes())?;
let redis = ConnectionLimit::new(AuthGate::new(RawTcpHandler::new("127.0.0.1:6379"), auth), 8)?;

let handle = OnionService::builder()
	.router(Router::new().route("/", get(|| async { "hi" })))
	.nickname("my_onion")
	.route_port(16379, redis)  // authenticated, at most 8 concurrent
	.serve()
	.await?;
```

`AuthGate` **fails closed**: a rejected stream — or an authorizer that errors mid-decision —
is dropped without touching the backend. It composes with `ConnectionLimit` in either order,
and a wrapped port reports what it applies, so the raw-port `WARN` at launch says *"this
handler does apply: a stream authorizer; a connection limit of 8"* instead of pretending the
port is wide open. Implement `StreamAuthorizer` yourself for a custom scheme (a token lookup,
a challenge/response); `SharedSecretAuth` is the ready-made one.

Understand what a shared secret is and is not: it is a **bearer credential shared by every
authorized client** — the same shape and the same caveats as a restricted-discovery key. It
authenticates the channel, not a user; a leaked secret is a breach; and there are no
per-client identities or roles (layer real per-user auth in the backend for that). It adds no
round trip, so it does not defend against replay by an attacker who has already captured the
preamble — but capturing it means compromising an endpoint, since the onion circuit is
encrypted end-to-end.

****

## Identity & address helpers

By default onyums keeps its onion identity key in a persistent keystore
(`./tor/onyums/state`), so the `.onion` address is stable across restarts with zero
configuration. `.ephemeral()` is the explicit opt-**down** to a throwaway identity —
the keystore lives in a unique temp directory, so each launch mints a fresh,
disposable address, and that directory is removed when the handle drops so the
disposable key does not linger on disk.

That covers the graceful exits. It does **not** cover the process being `SIGKILL`ed,
OOM-killed, or the machine losing power — no cleanup code of any kind runs then, and
a signal handler cannot help (`SIGKILL` is uncatchable by definition). So a throwaway
identity key would otherwise sit in your temp directory indefinitely. Instead, each
ephemeral service holds an **owner lock** inside its state directory for as long as it
runs, and each ephemeral launch first sweeps away any `onyums-ephemeral-*` directory
whose lock is free — i.e. whose owning process is gone, however it went. A running
service's keystore is never swept, no matter how long it has been up. In practice: a
crash leaves litter only until your next ephemeral launch, and you never have to
reason about which temp directory belonged to what.

```rust
use onyums::{OnionService, routing::get, Router};

let handle = OnionService::builder()
	.router(Router::new().route("/", get(|| async { "throwaway service" })))
	.nickname("scratch")
	.ephemeral() // fresh, disposable .onion address every run — never persisted
	.serve()
	.await
	.unwrap();
```

**Bring your own identity — inspection only, for now.** Read an existing service's
Tor `hs_ed25519_secret_key` file and derive the exact address it serves; onyums uses
the same encoding arti serves, so the check is exact:

```rust
use onyums::address_from_tor_secret_key_file;

let key_file = std::fs::read("hidden_service/hs_ed25519_secret_key").unwrap();
let address = address_from_tor_secret_key_file(&key_file).expect("valid hs_ed25519_secret_key");
println!("this key serves {address}"); // matches the service's existing address
```

A mined vanity key can also be exported to the same on-disk format
(`VanityKey::to_tor_secret_key_file()`) for backup or to load into any Tor
implementation.

> **This does not yet migrate a service.** What exists is **offline only**: parse a
> key file, derive its address, render the inverse blob. There is no API that loads
> a bring-your-own key into the live keystore and launches on it — so you cannot, in
> onyums today, take an existing `.onion` address and serve it. Launching from an
> imported key needs either arti's `launch_onion_service_with_hsid` (behind an
> experimental, non-semver feature) or a port of arti's `hss ctor-migrate` utility;
> both are open decisions on the ROADMAP (Phase 1). Until then, treat these helpers
> as a *pre-flight check* — verify a key serves the address you expect, back it up,
> confirm a restore — not as a migration path.

`handle.onion_address()` returns a typed `OnionAddress`, not a bare string, with the helpers an onion app actually needs:

```rust
use onyums::OnionAddress;

let address = OnionAddress::normalized("examplehostname");

assert_eq!(address.https_url(), "https://examplehostname.onion/");

// `Onion-Location` header pair, for a clearnet site advertising its onion:
let (name, value) = address.onion_location_header();
assert_eq!(name, "onion-location");

// A scannable QR of the HTTPS URL — print it to a terminal, or embed the SVG.
let _terminal_qr = address.qr_terminal(); // Unicode half-block art
let _svg_qr = address.qr_svg();           // standalone <svg> document
```

`OnionAddress::parse` is the validating constructor for operator- or user-supplied strings (it round-trips through arti's own v3 address parser — length, base32 alphabet, checksum, and version are all checked). Vanity-address mining (`onyums::mine` / `mine_parallel`) generates keys until the derived address matches a desired prefix, parallelized across cores.

****

## First launch & troubleshooting

**What the first run does.** With no `tor` daemon to configure, the embedded Arti
client bootstraps itself: it fetches the Tor network consensus over your outbound
connection and creates `./tor/onyums/state` (the identity keystore) and
`./tor/onyums/cache` (the disposable network directory). Outbound network access and
a roughly correct system clock are required — Tor rejects a consensus it thinks is
expired, so a badly-skewed clock is a common first-run failure.

**Expect readiness to take a moment.** Coming up is more than bootstrapping: Arti
publishes the service descriptor to the responsible directories, and it only reports
the service *reachable* once those uploads land. `ready()` can therefore take a minute
or more on the first launch, and — a real Arti behaviour onyums surfaces honestly —
the reported status can still lag *de-facto* reachability. Use `ready_timeout(dur)` so
startup never blocks forever, and read `status()` / `problem()` to see where it is:

```rust
if handle.ready_timeout(std::time::Duration::from_secs(120)).await {
	println!("reachable at {}", handle.onion_address());
} else {
	// Not up yet — status() says what, problem() says why.
	eprintln!("not ready: {} ({:?})", handle.status(), handle.problem());
}
```

**Testing from Tor Browser.** Open `https://<your-address>.onion/`. With the default
self-signed certificate the browser shows a certificate warning — that is *expected*:
the onion address itself authenticates the service (see [TLS-first transport](#tls-first-transport)),
so the warning is about WebPKI trust of the cert, not about who you are talking to.
Serve a CA-signed `.onion` cert with `Tls::Provided(...)` if you need to avoid the
warning for public users.

**Common problems:**

| Symptom | Likely cause / fix |
|---|---|
| Bootstrap never finishes | No outbound network, or a skewed system clock (fix the clock). |
| `ready()` hangs | Use `ready_timeout(dur)`; then read `problem()` — a persistent `IntroductionPoint` / `DescriptorUpload` problem means the descriptor isn't published yet. |
| Certificate warning in the browser | Expected with self-signed TLS — the address is the authenticator; use `Tls::Provided` for a CA-signed chain. |
| A restricted-discovery client can't connect | Its x25519 key isn't in the allowlist, or its `.auth_private` line is wrong — re-check `provision_client(...)` output. |
| A raw `route_port(...)` backend is unreachable | The local TCP backend isn't listening on the address you forwarded to. |
| `serve()` returns a port error | Ports 80/443 are reserved for the built-in HTTP handler, and a port can't be registered twice or as `0` — this is a clean startup error, not a runtime surprise. |
| Address changed after a restart | You used `.ephemeral()` (throwaway identity by design); drop it to keep the persistent keystore's stable address. |
| Startup fails: "could not be tightened" / "refusing to launch with a locally-readable onion-service identity" | A path in `./tor/onyums/state` is group/other-accessible and this process can't `chmod` it — almost always because the directory is owned by *another* user (ran as root once, now as a service account?). `chown` the tree to the service user. Fail-closed is deliberate: the alternative is serving an identity your other local users can read. See [Keystore permissions](#deployment). |
| Startup fails: "refusing to harden the symlink …" | Something in the state tree is a symlink. Identity material must be a real file — replace the link, or point the working directory at the real location instead. |
| `WARN … Hardened N of M path(s) … to owner-only` | Not an error: onyums repaired a keystore that was readable by other local users (a restore that dropped modes, or a pre-hardening onyums). Worth asking who could read the key before it was fixed. |

****

## Deployment

An onyums service is an ordinary Rust binary — `cargo build --release` and run it.
The one thing that must survive a restart or redeploy is the **identity keystore**
under `./tor/onyums/state` (relative to the process's working directory): it holds the
onion service's secret key, so persisting it keeps the `.onion` address stable. Lose it
and the service comes back on a *new* address.

**systemd** — pin the working directory so `./tor/onyums` always resolves to the same
place, and let it restart on failure:

```ini
# /etc/systemd/system/my-onion.service
[Unit]
Description=My onyums onion service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/my-onion/my-onion
WorkingDirectory=/var/lib/my-onion      # ./tor/onyums/state lives here — keep it
Restart=on-failure
# Hardening: the service only needs its own state dir writable.
DynamicUser=yes
StateDirectory=my-onion

[Install]
WantedBy=multi-user.target
```

**Docker** — build the binary, then mount a **named volume** over the state directory
so the identity outlives the container:

```dockerfile
FROM rust:1-slim AS build
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:stable-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /srv                            # ./tor/onyums/state resolves under here
COPY --from=build /app/target/release/my-onion /usr/local/bin/my-onion
VOLUME ["/srv/tor/onyums/state"]        # persist the identity keystore
CMD ["my-onion"]
```

```sh
docker run -v my-onion-identity:/srv/tor/onyums/state my-onion
```

The `cache` directory (`./tor/onyums/cache`) is disposable — it only holds the Tor
network consensus and is refetched if missing, so it does **not** need a volume.

**Backing up the identity.** To migrate a service to a new host or recover after a
disk loss, back up `./tor/onyums/state` (the keystore) and restore it before first
launch — the address is derived from the key inside it. Confirm a restored key serves
the address you expect *before* wiring it up with `address_from_tor_secret_key_file(...)`
(see [Identity & address helpers](#identity--address-helpers)). Treat this directory as
a secret: it *is* the service's identity.

**Keystore permissions.** Whoever can read the state directory can impersonate your
`.onion` — the address authenticates the key-holder, and that is the key. On Unix,
onyums enforces the convention for private key material on every launch: **`0700` on
directories, `0600` on files**, across the whole state tree. This is not advisory —
it is applied before arti opens the keystore, and it **fails closed**: if a path
cannot be made owner-only, the service refuses to start rather than serve an identity
your other local users can read.

- A tree that is already correct is left alone. A lax one — restored from a `tar`
  that carried `0755`, or created under `umask 022` by an older onyums — is repaired
  in place, with a `WARN` naming how many paths were tightened.
- A *stricter* choice of yours is preserved: a `0400` key stays `0400`.
- A symlink inside the state tree is refused rather than followed.
- **This does not apply on Windows**, which has no Unix mode model (its access
  control is ACL-based and Rust's standard library exposes only a read-only bit).
  There the keystore is protected by whatever the filesystem's ACLs say, and onyums
  logs that the control is not in force rather than claiming a hardening it did not
  perform.

Two operational consequences worth planning for: **your backups must preserve modes**
(`tar -p`, or re-`chmod` on restore — a restore that widens them is repaired but
logged loudly), and **the service must own its state directory**, since a file owned
by another user cannot be tightened by this process and will fail the check. The
systemd unit above gets this right by construction: `DynamicUser=yes` +
`StateDirectory=` hands the service a private directory it owns.

****

## Websocket example

Websockets work over Tor too. Onyums supplies a `ConnectInfo<ConnectionInfo>` so a handler can read the per-rendezvous-circuit id — the stable per-client handle over Tor, where there is no client IP or `SocketAddr`:

```rust
use axum::{
	extract::{ws::{Message, WebSocket, WebSocketUpgrade}, ConnectInfo},
	response::IntoResponse,
	routing::get,
	Router,
};
use futures::{SinkExt, StreamExt};
use onyums::{serve, ConnectionInfo};

#[tokio::main]
async fn main() {
	let app = Router::new().route("/ws", get(ws_handler));
	// Pass the router and the server nickname (used to derive the onion address).
	serve(app, "my_onion").await.unwrap();
}

/// The HTTP GET that opens the websocket handshake. This is the last point where
/// request metadata (headers, and here the Tor circuit id) is available before the
/// protocol switch.
async fn ws_handler(ws: WebSocketUpgrade, ConnectInfo(info): ConnectInfo<ConnectionInfo>) -> impl IntoResponse {
	// Over Tor there is no client IP; the per-circuit id is the connection's identity.
	let who = info.circuit_id.unwrap_or_else(|| "unknown-circuit".to_string());
	println!("websocket client on circuit {who} connected");
	ws.on_upgrade(move |socket| handle_socket(socket, who))
}

/// The per-connection websocket state machine (one task per client).
async fn handle_socket(mut socket: WebSocket, who: String) {
	// Kick things off with a ping.
	if socket.send(Message::Ping(vec![1, 2, 3].into())).await.is_err() {
		return; // client already gone
	}

	// Split so we can read and write concurrently.
	let (mut sender, mut receiver) = socket.split();

	// Push a few server-driven messages, then close.
	let mut send_task = tokio::spawn(async move {
		for i in 0..5 {
			if sender.send(Message::Text(format!("server message {i}").into())).await.is_err() {
				return;
			}
			tokio::time::sleep(std::time::Duration::from_millis(300)).await;
		}
		let _ = sender.close().await;
	});

	// Echo whatever the client sends until it disconnects.
	let mut recv_task = tokio::spawn(async move {
		while let Some(Ok(msg)) = receiver.next().await {
			match msg {
				Message::Text(t) => println!(">>> {who} sent: {t}"),
				Message::Close(_) => break,
				_ => {}
			}
		}
	});

	// If either task ends, abort the other.
	tokio::select! {
		_ = (&mut send_task) => recv_task.abort(),
		_ = (&mut recv_task) => send_task.abort(),
	}
	println!("websocket connection closed");
}
```

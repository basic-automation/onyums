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
        │   Skin gate           │  clearance check · PoW / CAPTCHA challenge ·
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

## Installation

```sh
cargo add onyums tokio --features tokio/full
```

Onyums is a library — add it to an async binary. No external Tor daemon is
required: the [Arti](https://gitlab.torproject.org/tpo/core/arti) Tor client is
embedded, so the first run downloads Tor consensus data over the network and
creates the keystore/cache under `./tor/onyums/` itself. It uses Rust **edition
2024**, so a recent stable toolchain (Rust 1.85 or newer) is required; a pinned,
CI-enforced MSRV is still on the roadmap.

## Features

- **One-liner serve** — `serve(app, "nickname")` is the full secure stack; the builder (`OnionService::builder()`) tunes or relaxes it.
- **Abuse defense on by default (Skin)** — a proof-of-work gate, no-JS fallbacks, token-keyed rate limiting, and a pure-Rust WAF, plus an Under Attack Mode toggle and observable security events; see [Abuse defense (Skin)](#abuse-defense-skin--on-by-default).
- **Restricted discovery (v3 client authorization)** — `.authorized_clients(...)` publishes a descriptor only the listed clients can decrypt, so an unlisted client cannot even discover the service; `provision_client(...)` mints a new client's x25519 keypair and renders Tor's canonical `.auth` / `.auth_private` files. See [Restricted discovery](#restricted-discovery--v3-client-authorization).
- **Real readiness + graceful shutdown** — the builder returns an `OnionServiceHandle` with `ready()` (and bounded `ready_timeout()`), `wait_until_settled()` (resolves on reachable *or* a terminal failure, so a broken bootstrap never hangs), a synchronous `status()` snapshot and non-blocking `is_ready()`, a `status_events()` transition stream, the typed `.onion` address, and `shutdown()`.
- **Observability — what, why, and how much** — `status()` says what the service's reachability is, `problem()` says *why* when it isn't healthy (a stable `ServiceProblem` projection of arti's `Display`-less diagnostics), `health()` bundles both from one consistent read, and `metrics()` exposes per-service circuit/stream counters (with `since()` interval deltas) for a `/up` line — plus a built-in Prometheus exporter (`metrics_prometheus()` per service, `fleet_prometheus(...)` for many) ready to serve at `/metrics`.
- **Multiple services on one bootstrap** — bootstrap once with `OnionService::shared_client()` (or reuse a running handle's `tor_client()`), pass it to several builders via `.tor_client(...)`, and aggregate fleet health with `ServiceStatus::worst_of([...])`.
- **TLS-first transport** — auto-generated self-signed certs, automatic HTTP→HTTPS upgrade, strict mode with HSTS, or bring your own CA-signed cert; see [TLS-first transport](#tls-first-transport).
- **Any protocol over the onion service** — `.route_port(port, handler)` tunnels raw TCP / gRPC / SSH / Lightning alongside the built-in TLS HTTP handler; see [Protocol versatility](#protocol-versatility--any-protocol-over-an-onion-service).
- **Stable identity, opt-down to throwaway** — a persistent keystore by default (stable `.onion` across restarts), or `.ephemeral()` for a fresh, disposable address each run; plus vanity-address mining, bring-your-own-key migration from a Tor `hs_ed25519_secret_key` file, and address helpers (QR, `Onion-Location`); see [Identity & address helpers](#identity--address-helpers).
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

`.ephemeral()` conflicts with `.tor_client(...)` — a shared client has a fixed
keystore and cannot supply a throwaway per-launch identity — and that pairing is
rejected offline, before any launch.

****

## Abuse defense (Skin) — on by default

Onyums bundles [`onyums-skin`](crates/onyums-skin), a "Cloudflare for Tor" abuse-defense layer, and **wires it in by default**. With no extra work, every served router sits behind a secure gate:

- a **proof-of-work** challenge for JavaScript clients (a few hundred ms of browser work to mint a clearance),
- a no-JS **patience tarpit** fallback, so a Tor "Safer"/"Safest" client (JS and WASM disabled) always has a path through,
- **rate limiting** keyed on a stateless, signed clearance token — a synthetic per-client identity, since there are no client IPs over Tor, and
- a pure-Rust **WAF** with a starter signature ruleset (SQLi / XSS / path traversal / command & code injection / SSRF / protocol anomalies).

The posture is *secure and complete by default*: the gate is on unless you turn it off, and you opt **down** (`no_skin`) or **across** (a custom `Skin`), never up.

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
		// .under_attack(true)                   // force EVERY new circuit through the gate (flood mode)
		// .circuit_events(my_sink)              // observe circuit rejects/teardowns/challenges
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

## Restricted discovery — v3 client authorization

For a service with a known, small set of users, `.authorized_clients(...)` enables Tor's **restricted discovery** (v3 client authorization): the service descriptor — its introduction points and keys — is encrypted to the listed clients' x25519 keys, so an *unlisted* client cannot even discover the service. This is DoS resistance enforced in descriptor crypto, upstream of the Skin HTTP gate rather than in place of it.

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

This is an explicit opt-*down* in reachability (from "anyone with the address" to "only these clients"). Restricted discovery is a DoS-resistance mechanism, **not** a substitute for authentication: removing a client does not immediately revoke an already-connected one.

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

Onyums treats encrypted, certificate-authenticated transport as the standard, never as optional cruft to strip away — even though Tor already encrypts the channel, end-to-end TLS adds independent cryptographic authentication and unlocks the browser **secure-context** semantics real apps depend on (WebCrypto, service workers, `Secure` / `__Host-` cookies, HTTP/2, no mixed-content downgrades). The knob is *how strictly* TLS is enforced, never whether it is on:

- **`Tls::Upgrade` (default)** — an auto-generated self-signed cert, and plaintext HTTP on port 80 is transparently redirected (`301`) to HTTPS. A client that arrives over plain HTTP is pointed at the secure URL rather than refused.
- **`Tls::Strict`** — TLS is non-negotiable. Plaintext circuits are **rejected outright** (there is no port-80 redirect handler at all), and every HTTPS response carries an `Strict-Transport-Security` header (`max-age=63072000; includeSubDomains`) so a conforming client never silently downgrades.
- **`Tls::Provided(cert)`** — serve your **own** certificate chain and key instead of the auto-generated self-signed one, for CA-signed `.onion` certificates (e.g. [HARICA](https://www.harica.gr/)) that some clients and browsers prefer. Build the cert once with `ProvidedCert::from_pem(cert_pem, key_pem)` — it parses and validates the pair up front, so a bad cert/key is a clean error at startup, not a runtime surprise. Bringing your own cert is *orthogonal* to plaintext strictness: it keeps the forgiving `Upgrade` posture (port-80 → HTTPS redirect, no HSTS).

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

****

## Identity & address helpers

By default onyums keeps its onion identity key in a persistent keystore
(`./tor/onyums/state`), so the `.onion` address is stable across restarts with zero
configuration. `.ephemeral()` is the explicit opt-**down** to a throwaway identity —
the keystore lives in a unique temp directory, so each launch mints a fresh,
disposable address, and that directory is removed when the handle drops so the
disposable key does not linger on disk:

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

**Bring your own identity.** To migrate an existing service into onyums without
changing its address, read its Tor `hs_ed25519_secret_key` file and confirm the
address *before* wiring anything up — onyums derives it with the same encoding arti
serves, so the check is exact:

```rust
use onyums::address_from_tor_secret_key_file;

let key_file = std::fs::read("hidden_service/hs_ed25519_secret_key").unwrap();
let address = address_from_tor_secret_key_file(&key_file).expect("valid hs_ed25519_secret_key");
println!("this key serves {address}"); // matches the service's existing address
```

A mined vanity key can also be exported to the same on-disk format
(`VanityKey::to_tor_secret_key_file()`) for backup or to load into any Tor
implementation. (Loading a BYO key directly into the live keystore is a
forthcoming slice — it rides on an arti experimental API.)

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

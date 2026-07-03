![logo](./assets/onyums-logo.svg)
<br><br>
![docs.rs](https://img.shields.io/docsrs/onyums?style=for-the-badge) ![Crates.io Total Downloads](https://img.shields.io/crates/d/onyums?style=for-the-badge) ![Crates.io License](https://img.shields.io/crates/l/onyums?style=for-the-badge)
<br><br>

Onyums is an axum wrapper for serving tor onion services — secure and complete by default. It bootstraps the Tor client, generates TLS certs, upgrades HTTP to HTTPS, and sits the app behind a built-in abuse-defense gate. It provides the `ConnectionInfo` extractor to differentiate connections made over tor since the concept of `SocketAddrs` does not exist on private connections.

The posture is *secure and complete by default*: the hard, Tor-specific machinery ships enabled, and you opt **down** when you have a reason to — never assemble safety from feature flags.

## Features

- **One-liner serve** — `serve(app, "nickname")` is the full secure stack; the builder (`OnionService::builder()`) tunes or relaxes it.
- **Abuse defense on by default (Skin)** — a proof-of-work gate, no-JS fallbacks, token-keyed rate limiting, and a pure-Rust WAF, plus an Under Attack Mode toggle and observable security events; see [Abuse defense (Skin)](#abuse-defense-skin--on-by-default).
- **Restricted discovery (v3 client authorization)** — `.authorized_clients(...)` publishes a descriptor only the listed clients can decrypt, so an unlisted client cannot even discover the service; see [Restricted discovery](#restricted-discovery--v3-client-authorization).
- **Real readiness + graceful shutdown** — the builder returns an `OnionServiceHandle` with `ready()`, a synchronous `status()` snapshot (typed `ServiceStatus`), the typed `.onion` address, and `shutdown()`.
- **TLS-first transport** — auto-generated self-signed certs, automatic HTTP→HTTPS upgrade, strict mode with HSTS, or bring your own CA-signed cert; see [TLS-first transport](#tls-first-transport).
- **Any protocol over the onion service** — `.route_port(port, handler)` tunnels raw TCP / gRPC / SSH / Lightning alongside the built-in TLS HTTP handler; see [Protocol versatility](#protocol-versatility--any-protocol-over-an-onion-service).
- **Stable identity, opt-down to throwaway** — a persistent keystore by default (stable `.onion` across restarts), or `.ephemeral()` for a fresh, disposable address each run; plus vanity-address mining, bring-your-own-key migration from a Tor `hs_ed25519_secret_key` file, and address helpers (QR, `Onion-Location`); see [Identity & address helpers](#identity--address-helpers).
- **Websockets over Tor** — with the per-circuit `ConnectionInfo` as the client identity (typed `is_over_tor()` / `circuit()` / `same_circuit()` helpers for per-circuit isolation); see [Websocket example](#websocket-example).
- **Version-skew-proof arti** — the arti stack is re-exported (`onyums::arti_client`, `onyums::tor_hsservice`, `onyums::tor_hscrypto`, …) so downstreams use the exact versions onyums does, just like `axum`.


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
	if handle.status().is_reachable() {
		println!("service is reachable");
	}

	// ... serve for a while ...
	handle.shutdown().await; // graceful stop
}
```

`status()` returns a stable `ServiceStatus` — `Shutdown` / `Bootstrapping` /
`Reachable` / `DegradedReachable` / `Unreachable` / `Broken` — onyums' own
projection of arti's onion-service state, so you can surface health at any moment
instead of only awaiting first reachability with `ready()`.

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

# onyums-skin

A **"Cloudflare for Tor"** abuse-defense layer for onion services: a challenge /
proof-of-work gate, stateless clearance tokens as a synthetic per-client identity,
token/circuit-keyed rate limiting, no-JS fallbacks, a per-circuit policy hook, and
(later) a pure-Rust WAF.

`onyums-skin` is a standalone, framework-agnostic crate — usable by any [`axum`] app —
that the [`onyums`](https://github.com/basic-automation/onyums) onion-service server
wires into its rendezvous-circuit loop. The HTTP half is a `tower`/`axum` `Layer` any
app can use, Tor or not; the Tor half is a single `CircuitPolicy` trait the host drives.

## Status

**Phase 1 (gate core) is implemented.** A plain axum app can require a PoW-or-tarpit
gate that mints a stateless clearance token and rate-limits by it, with a working path
for no-JS (Tor "Safer"/"Safest") clients:

```rust
use axum::{Router, routing::get};
use onyums_skin::Skin;

let app: Router = Router::new().route("/", get(|| async { "hello" }));
let gated: Router = app.layer(Skin::secure_default().into_layer());
```

The Tor dimension (`CircuitPolicy`, Phase 2) and the WAF (Phase 3) are trait/skeleton
stage. See [`ROADMAP.md`](ROADMAP.md) for the threat model, the locked component
decisions, the full API, and the phased plan.

## Principles

- **Tor-native substitutes, not IP-based defense** — every mechanism is re-keyed onto
  the per-rendezvous-circuit and an app-issued clearance token.
- **Secure and complete by default; you opt *down*, never *up*.**
- **No-JS is a first-class client** — Skin degrades (PoW → CAPTCHA → patience tarpit),
  never fails.
- **Cost, not prevention** — a fresh synthetic identity costs a fresh proof-of-work solve.
- **100% Rust — no FFI, ever** (MIT, no copyleft in the default build).

## License

MIT.

[`axum`]: https://crates.io/crates/axum

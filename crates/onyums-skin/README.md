# onyums-skin

A **"Cloudflare for Tor"** abuse-defense layer for onion services: a challenge /
proof-of-work gate, stateless clearance tokens as a synthetic per-client identity,
token/circuit-keyed rate limiting, no-JS fallbacks, a per-circuit policy hook, and
a pure-Rust WAF.

`onyums-skin` is a standalone, framework-agnostic crate — usable by any [`axum`] app —
that the [`onyums`](https://github.com/basic-automation/onyums) onion-service server
wires into its rendezvous-circuit loop. The HTTP half is a `tower`/`axum` `Layer` any
app can use, Tor or not; the Tor half is a single `CircuitPolicy` trait the host drives.

## Status

**Phases 1–4 are implemented; Phase 5 (frontier) is in progress.** A plain axum app
can require a PoW-or-tarpit gate that mints a stateless clearance token and rate-limits
by it, with a working path for no-JS (Tor "Safer"/"Safest") clients:

```rust
use axum::{Router, routing::get};
use onyums_skin::Skin;

let app: Router = Router::new().route("/", get(|| async { "hello" }));
let gated: Router = app.layer(Skin::secure_default().into_layer());
```

Built out: the gate core (PoW/tarpit challenge chain, `hmac`-signed clearance,
`governor` rate limiting), the Tor dimension (`CircuitPolicy` + `AccountingCircuitPolicy`
with Under-Attack Mode and adaptive difficulty), the pure-Rust WAF (`FilterExpr`
expression language + a curated OWASP-CRS-derived ruleset — SQLi (incl. error-based
`EXTRACTVALUE`/`UPDATEXML` and MySQL file/privilege functions) / XSS (incl. dangerous
HTML tags, CSS `-moz-binding`/`behavior:url()` script-binding, and the full
mouse/keyboard/clipboard/drag/media event-handler families) / traversal / SSRF
(incl. Alibaba & Oracle-OCI cloud-metadata endpoints), server-side template injection
across engines and PHP/Java/Node code execution (Spring4Shell class-loader, JS
prototype pollution, Java-deserialization markers), PowerShell download-cradle /
encoded-command RCE and Unix-shell evasion — `$IFS` whitespace plus character-insertion
de-obfuscation (`c'a't`, `c\at`, `who${x}ami`) — network-recon/exfil command coverage,
NoSQL/ORM lookup injection, restricted-file access (incl. AI coding-assistant artifact
dirs like `.claude/`/`.cursor/`), and a `ScannerDetection` class that hard-blocks
self-identifying attack tools (sqlmap/nikto/ghauri/nuclei/ffuf/dalfox/…); input is
normalized against percent-encoding, SQL comment / whitespace padding, HTML character
references, and embedded C0 control chars, so `UNION/**/SELECT`-, `java&#115;cript:`-,
and `<scri\npt>`-style evasions all still trip — anomaly
scoring, and
operator-authored custom rules), observability (typed `SecurityEvent`s, metrics,
request-shape baselining), and
Phase-5 frontier work: JA4H fingerprinting, request-shape bot heuristics, an opt-in
EquiX PoW backend, edge rules and response caching **wired into the gate**, multi-instance
clearance-key coordination, and **restricted-discovery orchestration** (below).

### Tuning the gate — edge rules, caching, custom WAF rules

`Skin::builder()` composes the gate. Edge rules run ahead of the clearance check (a
redirect or block short-circuits before any challenge; header transforms ride out on
the response), a bounded response cache serves cleared `GET`/`HEAD` hits without
re-running the app, and custom WAF rules block request *shapes* the signatures don't
describe — all authored in the same `FilterExpr` string language:

```rust
use onyums_skin::{EdgeRules, ResponseCache, Skin, WafCategory, Waf};

let skin = Skin::builder()
    .waf(
        Waf::starter()
            // Operator rule in the filter language, parsed up front.
            .custom_rule("block_wp_login", WafCategory::ProtocolAnomaly,
                r#"method eq "POST" and path starts_with "/wp-login""#)?,
    )
    // HTTP→HTTPS upgrade (install on the plaintext listener); or any match→action set.
    .edge_rules(EdgeRules::https_upgrade())
    // Serve hot, Cache-Control-cacheable GET/HEAD paths from a bounded in-process store.
    .response_cache(ResponseCache::new(256))
    .build();
```

### Restricted discovery — the strongest, upstream gate

Tor v3 client authorization encrypts the service descriptor to an allowlist of client
`x25519` keys, so an un-listed client cannot even *discover* the service — enforced in
descriptor crypto, before any rendezvous circuit. Skin models the allowlist as pure data
onyums hands to Arti (or materializes as Tor's `authorized_clients/*.auth` files):

```rust
use onyums_skin::{ClientAuthKey, RestrictedDiscovery};

let mut acl = RestrictedDiscovery::new();
// A key copied from an `authorized_clients/*.auth` line parses directly.
let key: ClientAuthKey = "descriptor:x25519:AAAA…".parse()?;
acl.authorize("alice", key);

// Render the on-disk directory Arti reads …
for (filename, body) in acl.to_auth_files() { /* write authorized_clients/<filename> */ }
// … and apply a later change set incrementally, not by rewriting everything.
let diff = acl.diff(&next);
diff.files_to_write();   // <nickname>.auth files to (over)write
diff.files_to_remove();  // .auth files to delete
```

See [`ROADMAP.md`](ROADMAP.md) for the phased task list (what is done and what is next).

## The threat model, in one paragraph

A Tor onion service sees **none** of the signals Cloudflare-style defenses key on: no
client IP / ASN / geo (connections arrive over a rendezvous circuit), no client TLS
fingerprint (the app never receives a ClientHello), and often no JavaScript or WASM
(Tor Browser "Safer"/"Safest" disable both). The per-rendezvous-circuit is the only
stable network handle, and circuits are cheap to rotate. So everything in this crate
keys on the two handles that *do* exist — the circuit and an app-issued signed
clearance token — and the abuse economics are **cost, not prevention**: each fresh
identity costs a fresh proof-of-work solve.

## Component decisions

| Component | Decision | Basis | License |
|---|---|---|---|
| PoW | pluggable `Pow` trait, **SHA-256 hashcash default** | hand-rolled; pure-Rust Equi-X behind the opt-in `equix` feature | MIT (equix: LGPL, gated) |
| Rate limiter | reuse | `governor` (keyed on the clearance token) | MIT/Apache |
| Clearance token | reuse | `hmac` + `sha2` | MIT |
| No-JS fallbacks | server-rendered CAPTCHA + patience tarpit | `captcha` / hand-rolled | MIT |
| WAF | build | `regex` + `aho-corasick` + the in-house `FilterExpr` rule language | MIT |

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

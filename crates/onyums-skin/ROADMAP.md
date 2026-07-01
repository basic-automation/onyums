# Onyums Skin — Roadmap

> The single source of truth for the dev routine on this crate: a phase-ordered task list. `[ ]` = to do, `[x]` = done.
> Progress is logged in PRs and git history — there is no separate progress file.
> What the crate is, its API, and its design posture live in [README.md](README.md).
> The host server's roadmap: [../../ROADMAP.md](../../ROADMAP.md).

## Phase 1 — Gate core — `v0.1`

- [x] `ClearanceStore` over `hmac`+`sha2` — stateless mint/verify with expiry and single-use replay protection
- [x] `Challenge` trait + `Gate`, with a fallback chain
- [x] `Hashcash` `Pow` (SHA-256 leading-zero-bits) + the JS interstitial page that solves it
- [x] `CaptchaChallenge` (server-rendered image, no JS) and `PatienceChallenge` (timed tarpit) as the no-JS fallbacks
- [x] `SkinRateLimit` over `governor`, keyed on the clearance `TokenId`
- [x] `SkinLayer` tower middleware — inspect → clearance-check → challenge → rate-limit, plus the challenge-submission route

## Phase 2 — Tor dimension & Under Attack Mode — `v0.2`

- [x] `CircuitPolicy` + per-circuit accounting (streams, request rate, bytes); `CircuitAction` including `Shutdown`
- [x] onyums adapter wiring `CircuitPolicy` to `RendRequest` / `StreamRequest`
- [x] Under Attack Mode — force every new circuit through the gate before serving
- [x] Adaptive PoW difficulty — dormant under normal load, raised under attack, driven by app-observable request rate

## Phase 3 — WAF — `v0.3`

- [x] Pure-Rust engine — `regex` + `aho-corasick` multi-signature matching as a `tower` layer over URI/method/headers/body, with normalization
- [x] Rule-expression front-end — `filter::FilterExpr` typed AST + evaluator (replaces `wirefilter`, whose published crate drags in the unmaintained `failure` dep, RUSTSEC-2020-0036)
- [x] String-syntax rule parser — lexer + recursive-descent `FilterExpr::parse` / `FromStr`, canonical `Display` as the parser's inverse
- [x] Curated starter ruleset — SQLi / XSS / path traversal / command & code injection / SSRF / NoSQL / LDAP / XXE / protocol anomalies
- [x] Operator control — custom rules, per-rule/category disabling, tunable per-category anomaly weights, anomaly scoring surfaced

## Phase 4 — Observability & adaptive defense — `v0.4`

- [x] Structured security events — challenge issued/passed/failed, WAF blocks, rate-limit trips, circuit teardowns — as typed events
- [x] Per-token / per-circuit metrics — active circuits, gate pass rates, difficulty in play
- [x] Request-shape baselining — learn the normal distribution of Tor-surviving HTTP dimensions and flag deviation
- [x] Deviation-driven adaptive difficulty (feeds onyums' Phase 4 observability)

## Phase 5 — Frontier defenses — `v0.5+`

- [x] JA4H-style HTTP fingerprinting — cluster clients by request shape (header order, method, cookie names)
- [x] Heuristic bot detection on request shape + bot-difficulty
- [x] Restricted-discovery orchestration — `ClientAuthKey` (canonical `descriptor:x25519:<BASE32>` round-trip), `RestrictedDiscovery` allowlist, `.auth` file render/parse/bulk-load, `AllowlistDiff` live reconfiguration
- [x] Pluggable PoW backend — `EquiX` behind the opt-in (LGPL) `equix` feature, with an SHA-256 effort check so `difficulty` reads identically to `Hashcash`
- [x] Multi-instance coordination — `HmacClearanceStore::derived` shared-secret key derivation + `with_verify_key` zero-downtime rotation
- [x] Edge rules — `edge::EdgeRules` match→action engine (redirect / block / header transform), incl. `https_upgrade()`
- [x] Response cache — `cache::ResponseCache`, bounded + TTL-expiring, `Cache-Control`-aware, keyed on `(method, host, path+query)`
- [ ] Wire `edge::EdgeRules` and `cache::ResponseCache` into `SkinLayer` (host-integration slice)
- [ ] WAF custom-rule path adopts `FilterExpr::parse` — operator-authored string rules end to end
- [ ] OWASP-CRS coverage growth — keep porting rules into the pure-Rust engine (no Coraza/FFI escape hatch, ever)

## Open questions (each resolves into a task once decided)

- [ ] Clearance carrier under no-JS — cookie vs signed URL path segment; test Tor Browser's per-circuit cookie behavior
- [ ] Circuit ↔ token binding — pin a clearance to its minting circuit, or float across circuits?
- [ ] Adaptive-difficulty signal tuning — window and curve for the app-observed request rate
- [ ] `captcha` crate license audit (`easy-captcha` as the fallback)

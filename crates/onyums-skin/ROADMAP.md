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
- [x] Wire `edge::EdgeRules` and `cache::ResponseCache` into `SkinLayer` (host-integration slice) — `SkinBuilder::edge_rules(...)` runs the ruleset between WAF inspection and the gate (redirect/block short-circuit, header transforms ride out on the forwarded response); `SkinBuilder::response_cache(...)` serves cleared GET/HEAD hits from a bounded, `Cache-Control`-honoring store without re-running the inner router
- [x] WAF custom-rule path adopts `FilterExpr::parse` — `Waf::custom_rule(id, category, rule_str)` / `custom_expr_rule(...)`: operator-authored whole-request predicates in the filter language, evaluated alongside the signature set (first-match: after the signature fields; scoring: summed in), reporting `location = "custom"`
- [ ] OWASP-CRS coverage growth — keep porting rules into the pure-Rust engine (no Coraza/FFI escape hatch, ever). The engine is `regex`-crate (RE2, linear-time), so it is structurally immune to the catastrophic-backtracking/ReDoS class CRS 4.28.0 had to hand-fix in rules 933160/933161/941140/933180 (<https://www.linuxcompatible.org/story/owasp-crs-v4280-drops-with-critical-security-fixes-and-first-lts-track>)
  - [x] Sensitive-file access signatures from CRS 4.26.0: `.dockerenv`, `.DS_Store`, `META-INF/`, `WEB-INF/`, prefix-guarded `.profile` — `traversal_appserver_files` (<https://www.linuxcompatible.org/story/owasp-crs-4260-released>)
  - [x] Restricted-file access (CRS rule 930130 family): VCS trees (`.git/`/`.svn/`/`.hg/`/`.bzr/`), dotfile configs (`.htaccess`/`.htpasswd`/`web.config`/`.gitignore`/`.env`), and backup/dump artifacts (`.bak`/`.swp`/`.swo`/`.sql`/`.dump`) — `traversal_vcs_config_files` + `traversal_backup_files`
  - [x] Scanner / tool-fingerprint signatures — new `WafCategory::ScannerDetection` hard-blocking self-identifying tools (sqlmap/nikto/ghauri/WhatWAF/nuclei/wpscan/…, ghauri+WhatWAF being the CRS 4.26.0 additions) plus Nmap's NSE probe; complements the softer, score-only `BotHeuristics` (<https://www.linuxcompatible.org/story/owasp-crs-4260-released>)
  - [x] SSRF obfuscated-loopback (hex/octal/IPv4-mapped-IPv6 `127.0.0.1`) + GCP `metadata.google.internal` hostname — `ssrf_obfuscated_loopback` + `ssrf_metadata_hostname`
  - [x] ORM lookup operator injection (CRS 4.28.0) — `nosqli_orm_lookup`: Django/SQLAlchemy double-underscore lookups (`?user__password__startswith=a`, `__contains`/`__regex`/`__gte`/`__isnull`), the ORM analog of the existing Mongo `[$ne]` NoSQL rule (<https://www.linuxcompatible.org/story/owasp-crs-v4280-drops-with-critical-security-fixes-and-first-lts-track>)
  - [x] Quote-based SQLi evasion (CRS 4.28.0) — `sqli_string_tautology`: the quote-wrapped `' OR 'a'='a` / `" AND "x"="x` string tautology the numeric `sqli_or_tautology` misses (same 4.28.0 source)
  - [x] Whitespace/comment-padding normalization — CRS 4.25.0 LTS closed CVE-2026-33691 (rule 933111), a whitespace-padding detection bypass; `strip_sql_comments_collapse_ws` now elides `/* … */` block comments (keeping MySQL `/*! … */` executable payloads) and collapses whitespace runs, matched as a final pass in `inspect_field`/`inspect_field_all`, so `UNION/**/SELECT` and `AND  1=1` padding still trip (<https://www.linuxcompatible.org/story/owasp-crs-4250-lts-and-339-released/>)
  - [x] Double-extension / padded upload-filename signature — `code_double_extension_upload`: the file-upload vector behind CVE-2026-33691, a script extension trailing a benign one (`avatar.jpg.php`), whitespace/`%20`-tolerant (same 4.25.0 source)
  - [x] Shell fork-bomb signature (CRS 4.25.0 LTS, PL2) — `cmdi_fork_bomb`: the `:(){ :|:& };:` recursive self-pipe, distinct from the existing `anomaly_shellshock` `() {` (same 4.25.0 source)
  - [x] PHP code injection (CRS 933xxx port) — `code_php_open_tag` (`<?php`/`<?=`), `code_php_superglobal` (`$_GET`/`$_POST`/…), `code_php_dangerous_call` (phpinfo/shell_exec/passthru/proc_open/pcntl_exec/base64_decode) (<https://coreruleset.org/>)
  - [x] Java/JVM + Node.js code execution (CRS 944xxx / node port) — `code_java_runtime_exec` (`Runtime.getRuntime().exec`, `new ProcessBuilder`), `code_node_child_process` (`require('child_process')`, `child_process.exec/spawn/fork`)
  - [x] SSTI engine-coverage expansion — `code_ssti_erb` (`<%= 7*7 %>`), `code_ssti_hash_delim` (`#{7*7}`), `code_ssti_razor` (`@(7*7)`), `code_ssti_thymeleaf` (`*{7*7}`), broadening the `${}`/`{{}}` pair with the tplmap `N*N` polyglot
  - [x] HTML5 XSS vectors (CRS 941 port) — `xss_html5_event_handler` (animation/transition/pointer/`onbeforetoggle`/… handlers past the classic set) + `xss_dangerous_attribute` (`srcdoc`/`formaction`)
  - [ ] AI coding-assistant artifact protection (CRS **rule 930140**, added 4.24.1, March 2026) — a new 930xxx restricted-files signature blocking AI code-generation tool artifacts; a candidate port alongside `traversal_vcs_config_files`/`traversal_appserver_files`. Investigate the exact file/path set from the CRS repo before porting — the article does not enumerate the patterns (<https://www.linuxcompatible.org/story/owasp-removes-false-positives-and-adds-protection-for-safer-waf-deployments>)
  - [ ] Track CRSLang: CRS is replacing Seclang with a YAML rule language in its next major release (<https://coreruleset.org/>) — a reference point for `FilterExpr`'s string grammar as the operator-facing rule surface. CRS 4.28.0 remains the latest and 4.25.x is the first LTS track (CRS 3.3.x EOL Q3 2026), so peg future ports to the 4.25 LTS + 4.28 baselines

## Open questions (each resolves into a task once decided)

- [ ] Clearance carrier under no-JS — cookie vs signed URL path segment; test Tor Browser's per-circuit cookie behavior
- [ ] Circuit ↔ token binding — pin a clearance to its minting circuit, or float across circuits?
- [ ] Adaptive-difficulty signal tuning — window and curve for the app-observed request rate
- [ ] `captcha` crate license audit (`easy-captcha` as the fallback)

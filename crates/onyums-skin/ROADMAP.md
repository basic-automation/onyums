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
  - [x] AI coding-assistant artifact protection (CRS **rule 930140**, added 4.24.1) — `traversal_ai_assistant_artifacts` blocks the per-tool AI-assistant config dotdirs from CRS's `ai-critical-artifacts.data` `@pmFromFile` set (`.claude/`/`.cursor/`/`.codex/`/`.windsurf/`/`.a0proj/`/`.n8n/`/… + the trailing-slash-less `.qwen_code`/`.crush`), enclosing-slash/dot-segment anchored like `traversal_vcs_config_files` (<https://github.com/coreruleset/coreruleset/blob/main/rules/ai-critical-artifacts.data>)
  - [x] JavaScript prototype pollution (CRS **rule 934130**) — `code_prototype_pollution` (CodeInjection): the `__proto__` sentinel plus the dotted / bracket-chain `constructor.prototype` access forms, a faithful port of CRS's `__proto__|constructor[\s\x0b]*(?:\.|\]?\[)[\s\x0b]*prototype`; the entry gadget for Node prototype-pollution→RCE chains that reach `code_node_child_process` (<https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf>)
  - [x] Spring4Shell class-loader manipulation (CRS **rule 944260**, CVE-2022-22965) — `code_spring4shell` (CodeInjection): the `class.module.classLoader…` data-binding walk that rewrites the Tomcat access-log into a webshell + the `springframework.context.support.FileSystemXmlApplicationContext` SpEL gadget; keyed on the invariant `class.module.classloader` head rather than CRS's exact `.resources.context.parent.pipeline` tail (<https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf>)
  - [x] Java serialized-object variant markers (CRS **rule 944210**) — broadened the existing `code_java_serialized` rule (already matched the raw `rO0AB…` base64 STREAM_MAGIC opener) to the `KztAAU` / `Cs7QAF` gzip/variant openers CRS lists alongside it; case-sensitive, the delivery vehicle for a Commons-Collections-style gadget chain in a cookie/header/body param (<https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf>)
  - [x] PowerShell download-cradle / encoded-command RCE (CRS **rules 932120/932125**) — `cmdi_powershell` (CommandInjection): the vectors the cmd.exe-flavored `cmdi_windows_command` misses — `Invoke-Expression`/`iex(`, the `Net.WebClient().DownloadString` / `Invoke-WebRequest` fileless download cradle, `[Convert]::FromBase64String`, and the `-EncodedCommand`/`-nop`/`-w hidden` launcher flags (<https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf>)
  - [x] Unix `$IFS` whitespace-evasion (CRS **rules 932130/932200**) — `cmdi_ifs_evasion` (CommandInjection): the `$IFS` / `${IFS}` internal-field-separator substitution used to build a space-free command line (`cat${IFS}secret.txt`) past filters that key on literal whitespace; `\b`-tailed so `$IFSomething` / `${IF}` stay clean (<https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf>)
  - [x] Dangerous HTML tags (CRS **rule 941320**) — `xss_dangerous_tag` (Xss): plugin/resource loaders and legacy auto-fire tags past the script/iframe/svg trio — `<object>`/`<embed>`/`<applet>`, `<base>` (base-href hijack), `<bgsound>`/`<marquee>`/`<layer>`, `<frame>`/`<frameset>`, `<isindex>`, `<math>`; left `<form>`/`<meta>`/`<link>`/`<style>` out to avoid rich-text false positives (<https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf>)
  - [x] MySQL privilege/file SQL (CRS **rules 942151/942320 + 942480**) — `sqli_privilege_functions` (Sqli): `PROCEDURE ANALYSE` (info-leak/version-probe) + `LOAD DATA … INFILE` (server-side file read), the vectors the write-only `sqli_into_outfile` and `sqli_oob_exec`'s `load_file` both miss (<https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf>)
  - [x] Error-based SQLi extraction (CRS **rule 942151** function set) — `sqli_error_based` (Sqli): MySQL's `EXTRACTVALUE(` / `UPDATEXML(` (leak query output through a forced parse error), `GTID_SUBSET(`, and the `FLOOR(RAND()` double-query trick — the error-channel exfil path the tautology/union rules miss; `floor(` anchored to the `rand(` pairing so ordinary math stays clean (<https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf>)
  - [x] CSS-context script-binding XSS (CRS **rule 941170**) — `xss_css_binding` (Xss): the two style vectors that run script with no `<script>`/`on*=` — Gecko's deprecated `-moz-binding` (XBL constructor) and IE's `behavior:url(…)` HTC binding; both obsolete legitimately, so their appearance in a reflected `style=`/CSS value is injection (<https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf>)
  - [x] Non-AWS cloud-metadata SSRF — `ssrf_vendor_metadata` (Ssrf): Alibaba Cloud's distinct link-local metadata IP `100.100.100.200` (cloud-agnostic SSRF tooling routinely forgets it) + Oracle OCI's `/opc/v{1,2}/` metadata path (OCI keeps the 169.254 IP but exposes metadata under `/opc/`, so the AWS `/latest/meta-data` path rule doesn't fire) (<https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf>)
  - [ ] Obfuscated `javascript:` / `data:` URI XSS (CRS **rules 941210/941130**) — the HTML-entity / escape-sequence-obfuscated protocol forms (`java&#115;cript:`, `&#x6a;avascript:`) and the `data:text/html` attribute-context variants that the literal `xss_js_uri` / `xss_data_html_uri` rules miss; a next port alongside the just-landed `xss_css_binding` (941170). Needs the decode/normalization pass to run before the match so the entity forms collapse (<https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf>)
  - [ ] CRS 4.28.0 "RCE evasion prefixes" — 4.28.0's release notes call out new RCE-evasion-prefix signatures and the elimination of catastrophic backtracking in Unix-shell evasion detection; enumerate the concrete new 932xxx patterns from the CRS repo/CHANGES.md and port the ones not already covered by `cmdi_ifs_evasion` / `cmdi_powershell` (<https://www.linuxcompatible.org/story/owasp-crs-v4280-drops-with-critical-security-fixes-and-first-lts-track>)
  - [ ] Track CRSLang: CRS is replacing Seclang with a YAML rule language in its next major release (<https://coreruleset.org/>) — a reference point for `FilterExpr`'s string grammar as the operator-facing rule surface. CRS 4.28.0 remains the latest (2026-07-02) and 4.25.x is the first LTS track (CRS 3.3.x EOL Q3 2026), so peg future ports to the 4.25 LTS + 4.28 baselines

## Open questions (each resolves into a task once decided)

- [ ] Clearance carrier under no-JS — cookie vs signed URL path segment; test Tor Browser's per-circuit cookie behavior
- [ ] Circuit ↔ token binding — pin a clearance to its minting circuit, or float across circuits?
- [ ] Adaptive-difficulty signal tuning — window and curve for the app-observed request rate
- [ ] `captcha` crate license audit (`easy-captcha` as the fallback)

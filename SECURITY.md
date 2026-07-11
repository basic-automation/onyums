# Security Policy

Onyums serves application traffic over Tor onion services and ships an
abuse-defense gate, so it is security-critical software. This document says which
versions receive fixes, how to report a vulnerability, and what to expect after
you do.

## Supported versions

Onyums is pre-1.0 and still moving fast. Security fixes land on the latest
released `0.x` minor; there are no long-term-support branches yet.

| Version        | Supported          |
| -------------- | ------------------ |
| latest `0.3.x` | :white_check_mark: |
| `< 0.3`        | :x:                |

If you are pinned to an older release, the remediation is to upgrade to the
current `0.3.x`.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.** Public
disclosure before a fix is available puts every deployed onion service at risk.

Report privately through GitHub's **private vulnerability reporting** for this
repository:

> **Security → Report a vulnerability** at
> <https://github.com/basic-automation/onyums/security/advisories/new>

Include, as far as you can:

- the affected version(s) and platform,
- a description of the issue and its security impact,
- a minimal reproduction or proof of concept,
- any suggested remediation.

If private advisories are unavailable to you, open a normal issue that asks for a
private contact channel **without** any vulnerability detail, and a maintainer
will follow up.

## What to expect

These are targets, not contractual guarantees, for a pre-1.0 volunteer-maintained
project:

- **Acknowledgement** of your report within **5 business days**.
- An initial **assessment and severity triage** within **10 business days**.
- For confirmed issues, a **fix or documented mitigation** coordinated with you
  before public disclosure, and credit in the advisory/release notes unless you
  ask to remain anonymous.

Please allow a reasonable coordinated-disclosure window before publishing
details.

## Scope and known limitations

Some properties are intentional design boundaries, not vulnerabilities. Reports
about the following are welcome as hardening ideas but are documented, expected
behavior:

- **Self-signed TLS is not WebPKI trust.** By default onyums generates a
  self-signed certificate. The `.onion` address authenticates the service; the
  self-signed cert provides encryption and secure-context mechanics, not
  browser-trusted authentication. Use `Tls::Provided` with a CA-signed `.onion`
  certificate for public services.
- **The WAF is best-effort, not authoritative.** The Skin WAF is a signature
  ruleset over a pure-Rust engine; it raises the cost of automated abuse but is
  not a substitute for a secure application. Do not rely on it as your only
  defense.
- **Restricted discovery is DoS resistance, not authentication.** Removing a
  client from the allowlist does not revoke an already-connected client. Layer
  application-level auth for access control.
- **Raw-port handlers bypass the HTTP gate.** Traffic routed via
  `.route_port(...)` does not pass through the Skin WAF / rate limiter; secure
  those services independently.
- **Intro-layer Proof-of-Work is not implemented.** Skin's PoW is HTTP-layer
  only; onyums does not currently provide Tor introduction-point flood protection
  (blocked on experimental Arti features).

See the [README](README.md) and [ROADMAP.md](ROADMAP.md) for the full picture of
what is implemented, what needs live-Tor verification, and what is planned.

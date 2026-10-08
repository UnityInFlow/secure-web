# ADR-008 — injection-scanner integrated as a subprocess in v0.1

Status: Accepted (2026-09-24)

## Context
The scanner is a separate Rust CLI with a stable stdin/JSON contract. Refactoring it into a library before Secure Web exists would block the vertical slice.

## Decision
v0.1 spawns `injection-scanner check - --format json --no-suppress --strict` per document with timeout, input/output caps and typed parsing (`--no-suppress`/`--strict` because `security_text` is untrusted: see `docs/security-policy.md` §4). After v0.1 is proven, extract `injection-scanner-core` and call it in-process (v0.2+).

## Consequences
+ fastest end-to-end path; independent release cycles; exercises the scanner's public contract.
- per-page process spawn cost (measure; target p95 < 20 ms incl. spawn on small pages).

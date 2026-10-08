# ADR-004 — Same-origin crawl scope by default

Status: Accepted (2026-09-24)

## Context
Documentation sites map well to a single origin; following cross-origin links turns a bounded crawl into an open-ended one and multiplies attack surface.

## Decision
Default scope is `SAME_ORIGIN` (scheme + host + port of the root URL). Cross-origin traversal requires `scope: ALLOWLIST` with an explicit `allowedHosts` list. Path include/exclude patterns narrow further.

## Consequences
+ predictable budgets, smaller blast radius.
- multi-host docs (e.g. api.example.com + docs.example.com) need an explicit allowlist.

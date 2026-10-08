# ADR-007 — No browser engine in v0.1

Status: Accepted (2026-09-24)

## Context
Plain HTTP retrieval covers most documentation, blogs, standards and raw text sources. A browser engine adds a large attack surface and needs its own sandbox.

## Decision
v0.1 fetches over HTTP only. Browser rendering (v0.3) will run in an isolated worker and feed DOM snapshots into the same `PageProcessor` pipeline.

## Consequences
+ small, auditable v0.1.
- JavaScript-rendered pages produce thin or empty extractions; report them as such rather than guessing.

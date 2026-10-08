# ADR-006 — Agent reasoning is out of scope (no LLM in core)

Status: Accepted (2026-09-24)

## Context
Secure Web is a trust boundary. An LLM inside it would be nondeterministic, expensive, and itself attackable by the content it inspects.

## Decision
No LLM, embeddings, RAG, vector DB or autonomous research orchestration in Secure Web. The connected agent does all reasoning. A semantic second pass may be evaluated in v0.3 and must never downgrade static HIGH/CRITICAL findings.

## Consequences
+ deterministic, testable gating; corpus metrics are meaningful.
- some subtle injections may pass the static scanner; mitigated by layered controls (sandbox, network policy).

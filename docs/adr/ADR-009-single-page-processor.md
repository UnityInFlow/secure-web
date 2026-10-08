# ADR-009 — Single PageProcessor path for all model-facing content

Status: Accepted (2026-09-24)

## Context
Security bypasses usually arrive through a second code path (a crawler shortcut, a debug endpoint, a browser worker) that forgets one step.

## Decision
`PageProcessor::process` is the only function that sequences guard → fetch → extract → scan → policy → store. `web_open`, the crawler, and any future browser worker or HTTP API call it. Search results get a parallel, equally guarded snippet pipeline in v0.2. The invariant is documented at the function and enforced by crate dependency rules (the crawler cannot import fetch/extract/security implementations).

## Consequences
+ one place to audit.
- every new content source must be adapted into `PageProcessor` inputs rather than shortcutting.

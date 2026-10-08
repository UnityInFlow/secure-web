# ADR-005 — Raw blocked payload is never agent-visible

Status: Accepted (2026-09-24)

## Context
Returning the matched injection text in a "blocked" result would deliver the attack to the model anyway. Logs and corpus files are also model-readable in many setups.

## Decision
Blocked documents are represented only by URL, ids, `reason`, `maxSeverity`, `findingIds` and scanner/policy versions — in MCP results, manifests, metadata, `inspect` output and default logs. Extracted or raw text of any document is retained only under `private-audit/` when `debug.retainRaw` is on, readable only via `secure-web inspect --raw --i-understand`. The type `BlockedDocument` has no text-bearing fields; a canary grep test enforces this end to end.

## Consequences
+ the model never sees blocked content.
- debugging false positives requires operator access outside the agent context.

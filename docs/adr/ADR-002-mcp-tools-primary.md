# ADR-002 — MCP tools are the primary interface

Status: Accepted (2026-09-24)

## Context
Claude Code, Codex, Copilot Agent mode and OpenCode all support MCP; some cloud surfaces support only tools, not resources/prompts. An HTTP API is useful for tests and other services.

## Decision
v0.1 exposes exactly four tools: `web_open`, `web_crawl`, `web_find` (v0.1) and `web_search` (v0.2). No resources or prompts in v0.1. HTTP API (v0.2+) is a thin second adapter over the same application layer, never a separate business path.

## Consequences
+ widest client compatibility, one contract to test.
- no streaming of documents as resources yet; agents read corpus files from disk or via `inline`.

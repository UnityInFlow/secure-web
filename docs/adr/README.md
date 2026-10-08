# Architecture Decision Records

Format: Status / Context / Decision / Consequences. New ADRs are required for any change that affects invariants 1–10 in `CLAUDE.md`. Number sequentially.

| ADR | Title | Status |
|---|---|---|
| 001 | Rust as implementation language | Accepted |
| 002 | MCP tools are the primary interface | Accepted |
| 003 | Scanner failure is fail-closed | Accepted |
| 004 | Same-origin crawl scope by default | Accepted |
| 005 | Raw blocked payload is never agent-visible | Accepted |
| 006 | Agent reasoning is out of scope (no LLM in core) | Accepted |
| 007 | No browser engine in v0.1 | Accepted |
| 008 | injection-scanner integrated as subprocess in v0.1 | Accepted |
| 009 | Single PageProcessor path for all model-facing content | Accepted |
| 010 | URL guard: WHATWG parsing, ambiguous IPv4 literals, embedded IPv4, denylist semantics | Accepted |
| 011 | Test-only loopback allowance for the fixture server | Accepted |
| 012 | Bounded fetcher: pinned connections, raw-text redirect validation, own decompression | Accepted |
| 013 | Bounded extraction: in-crate tokenizer, one parse, scanner sees what the model sees | Accepted |
| 014 | Scanner adapter hardening and the accept-time exposure check | Accepted |
| 015 | Corpus store: generated paths, no-follow atomic writes, checkpoints, private audit | Accepted |
| 016 | Sealed trust-state types, the PageProcessor slice and MCP exposure | Accepted |
| 017 | Unwrap IPv4-translated, 6to4 and Teredo addresses | Accepted |
| 018 | Crawled URLs: raw-text guard input, recorded child URLs, redirect provenance | Accepted |
| 019 | Crawler budgets, cancellation and the `web_crawl` result | Accepted |

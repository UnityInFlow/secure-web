# Task plan — v0.1 secure vertical slice

Work these **in order**. Each task file is self-contained: read it, the contracts it lists, and the
deep-dive sections it lists, then plan → approve → implement → verify. Each PR leaves the binary usable.

| PR | Task file | Issues | Delivers |
|---|---|---|---|
| 01 | `PR-01-bootstrap.md` | SW-001 | workspace, config, CLI skeleton, CI, ADR-001/002 |
| 02 | `PR-02-url-guard.md` | SW-002 | UrlGuard + exhaustive SSRF tests |
| 03 | `PR-03-fetcher.md` | SW-003 | bounded HTTP fetcher, manual redirect validation, fixture server |
| 04 | `PR-04-extractor.md` | SW-004, SW-007 | security_text + display extraction, deterministic Markdown |
| 05 | `PR-05-scanner-policy.md` | SW-005, SW-006 | scanner subprocess adapter, policy engine, fail-closed, no-leak canary |
| 06 | `PR-06-corpus-manifest.md` | SW-008 | corpus store, manifest v1, sanitized paths, provenance |
| 07 | `PR-07-web-open.md` | SW-009 | PageProcessor, MCP server, `web_open`, CLI `open`, contract tests |
| 08 | `PR-08-crawler.md` | SW-010, SW-011 | frontier, scope, canonicalization, budgets, `web_crawl`, cancellation |
| 09 | `PR-09-web-find.md` | SW-012 | lexical find over accepted corpus, `web_find`, CLI `find` |
| 10 | `PR-10-clients-release.md` | SW-013..018 | client docs + integration suite, corpus gates, `inspect`, release |

How to invoke with Claude Code:

```bash
claude "Implement docs/tasks/PR-02-url-guard.md. Follow CLAUDE.md. Start by writing the plan and the failing tests."
```

Status tracking: tick the checklist inside each task file as you go; do not create a separate
status file.

Scope guard: if a task tempts you to add something from `docs/reference/…` §5 (non-goals) or
§68 "explicit out of scope", stop and leave a TODO in `docs/backlog.md` instead.

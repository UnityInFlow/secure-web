# Threat model (v0.1)

Trust domains: **Agent** (powerful, has repo/creds), **Secure Web** (trusted mediator, minimal
secrets), **Internet** (fully attacker-controlled: bodies, headers, titles, snippets, redirects,
filenames, link text, JSON). Every threat below maps to a mitigation and a test that must exist.

| ID | Threat | Mitigation | Test (path) | Task |
|---|---|---|---|---|
| T1 | Direct prompt injection in page text | security_text → injection-scanner → policy BLOCK | `tests/security/injection_direct.rs` | PR-05 |
| T2 | Encoded injection (base64, URL-enc, entities, unicode escapes) | scanner decode pipeline receives security_text incl. entities pre-decoded once | `tests/security/injection_encoded.rs` | PR-05 |
| T3 | Hidden DOM injection (display:none, comments, alt/aria, meta) | hidden text included in security_text before readability cleanup | `tests/security/injection_hidden.rs` | PR-04/05 |
| T4 | Search snippet/title injection | titles in security_text; blocked page emits no title; search results scanned (v0.2) | `tests/security/metadata_title.rs` | PR-04/05 |
| T5 | SSRF to localhost/private/metadata | DNS-resolved IP classification, pinned connect, hostname denylist, IP-literal normalization | `tests/security/ssrf_ranges.rs` | PR-02 |
| T6 | Redirect to private host / rebinding | manual redirect handling, revalidate every hop, no client auto-follow | `tests/security/redirect_private.rs` | PR-03 |
| T7 | Infinite / runaway crawl | depth, pages, bytes, duration budgets checked before each fetch | `tests/crawler/budgets.rs` | PR-08 |
| T8 | Link explosion | bounded frontier, maxLinksPerPage, canonical dedupe, bounded concurrency | `tests/crawler/link_explosion.rs` | PR-08 |
| T9 | Decompression / size bomb | streamed decompression with decompressed-byte cap; abort stream | `tests/security/size_bomb.rs` | PR-03 |
| T10 | Agent bypass via curl/WebFetch | deployment: no egress in enforced mode; hooks/permissions as defense in depth | `docs/client-integration.md` (manual) | PR-10 |
| T11 | Agent reads blocked payload from logs/files | private-audit outside agent mount; default logs never carry bodies; canary grep test | `tests/security/no_leak_canary.rs` | PR-05/06 |
| T12 | Scanner crash/timeout/garbage | fail closed → BLOCK(SCANNER_FAILURE); no bypass config | `tests/security/scanner_fail_closed.rs` | PR-05 |
| T13 | Poisoned metadata (title→path traversal, control chars) | generated ids + slug whitelist; title only in metadata; NFC + control strip | `tests/security/sanitized_paths.rs` | PR-06 |
| T14 | Blocked page seeds crawl with malicious links | `PageOutcome::Blocked` carries no links by type | `tests/crawler/blocked_no_links.rs` | PR-08 |
| T15 | Oversized MCP result / context flooding | never inline crawl content; 64 KB result cap; `web_open.inline` bounded | `tests/contracts/result_size.rs` | PR-07/09 |
| T16 | Config weakening (turn off SSRF/scanner) | validator rejects weakened security config | `tests/core/config_validation.rs` | PR-01 |
| T17 | Stale "safe" under new policy | policy/scanner versions stamped in manifest; find refuses mismatched major scanner version (v0.2 cache) | `tests/contracts/manifest_v1.rs` | PR-06 |

Residual risks (documented, not solved in v0.1): scanner detection gaps (no fuzzing, no semantic
pass), JS-rendered content not fetched, no PDF/archives, developer mode has no network enforcement.

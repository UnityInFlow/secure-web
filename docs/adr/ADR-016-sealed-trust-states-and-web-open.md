# ADR-016 — Sealed trust-state types, the PageProcessor slice and MCP exposure

Status: Accepted (2026-09-25)

## Context
PR-07 wires the first end-to-end path from an agent to the Internet (`web_open`). Three things
were left open by earlier ADRs:

1. `AcceptedDocument` and `ScannedDocument` lived in `secure-web-core` with public fields, so any
   crate could build an "accepted" document from unscanned text, or edit one after `accept()`
   (backlog, PR-01/05/06). `StoreContext.raw` let any caller put arbitrary bytes into the
   private audit.
2. How a page outcome maps onto the `web_open` contract (a normal `BLOCK` result vs an error).
3. How the MCP server is exposed on the network.

## Decision
**Sealed trust states.** `ScannedDocument`, `AcceptedDocument` and `RawContent` move into
`secure_web_security::decision` with private fields and read-only accessors. Rust privacy makes
that module the only code that can construct or modify them: `scan_document` builds the scanned
document, `accept` the accepted one, `scan_and_decide` the raw content (only from the document it
scanned, only when `debug.retainRaw`). `compile_fail` doc tests prove that struct literals,
functional record update and field assignment do not compile outside the module.
`scan_and_decide` returns the findings and scan duration alongside the outcome, so the page
processor never scans twice. `secure-web-store` now depends on `secure-web-security` for these
types (no cycle: security depends on core and extract only).

**One path.** `secure_web_crawl::PageProcessor::process` sequences guard → fetch → extract
(`spawn_blocking`) → `scan_and_decide` → store. The fetcher is built from the same `UrlGuard`
that validates the first URL. An accepted page leaves the processor as a sealed `ExposedPage`
(title, Markdown, final URL copied from the `AcceptedDocument`); `secure-web-mcp` has no
dependency on fetch/security/extract and can only expose those strings (invariant 8 at the MCP
boundary). Guard rejections and ordinary network failures are `Failed` (manifest `failed`);
fetch/extraction policy violations (redirect, size, content type) and scan/policy blocks are
`Blocked` (manifest `blocked`).

**`web_open` mapping.** A block decided on scanned content (`PROMPT_INJECTION`,
`SCANNER_FAILURE`, `POLICY_VIOLATION`) is a normal `status: BLOCK` result with no title, content
or contentPath. A block decided before any content was scanned (`REDIRECT_VIOLATION`,
`CONTENT_TOO_LARGE`, `UNSUPPORTED_CONTENT_TYPE`, `SSRF`, `UNSUPPORTED_SCHEME`) is the matching
error object (`REDIRECT_BLOCKED`, …), because nothing usable was fetched. CLI exit codes: `SAFE`/
`WARN` 0, `BLOCK` 3, `BLOCK` with `SCANNER_FAILURE` 5, errors per the contract table.

**Blocked pages keep only the caller's URL.** A redirect target is chosen by the server: on a
blocked page it was either part of the blocked security text or never scanned. The processor
therefore records a blocked page with `finalUrl: null` whenever the final URL differs from the
requested URL, and with an empty `redirectChain`; the `BLOCK` result, the manifest `blocked`
entry and the metadata file all carry `null`. The requested URL (written by the caller) is kept.
The guard validates the `web_open` argument as written, not a re-serialized parse, so the
raw-text rules (non-canonical IPv4, empty userinfo) apply.

**MCP exposure.** Streamable HTTP binds loopback by default; a non-loopback address is refused
unless `server.allowRemote` (checked by `Config::validate` after a `--listen` override and again
at bind). The transport accepts only `Host: localhost | 127.0.0.1 | ::1` (plus the listen IP with
`allowRemote`) against DNS rebinding; a wildcard listen address (`0.0.0.0`, `::`) is refused
even with `allowRemote`, because no remote client could send it as `Host`, and rejects every request carrying an `Origin` header so no
browser page can drive the server. Duplicate `Host` headers and absolute-form targets are a 400 (rmcp reads only the first `Host`),
and a connection must finish its request head within 10 s (slowloris). Only `/mcp` is served; bodies are capped at 4 MiB (rmcp
default). Concurrent tool calls are bounded by a semaphore (`min(crawl.concurrency, 16)`).
SIGINT/SIGTERM stop accepting, end every session and wait up to 5 s.

## Consequences
+ An `AcceptedDocument` that did not pass `accept()` is a compile error, not a review finding.
+ The store's version/title/decision checks are now unreachable through the public API; they
  stay as defense in depth.
- Tests can no longer hand-build accepted documents; they go through `scan_and_decide` with a
  fixed scanner.
- A browser-based MCP client (e.g. MCP Inspector in direct mode) is refused; it must use a
  non-browser proxy. Deliberate.
- A cancelled `web_open` call can leave a `RUNNING` manifest (the run is not finished); no tool
  result ever references it.

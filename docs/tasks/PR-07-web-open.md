# PR-07 — PageProcessor, MCP server, `web_open` (SW-009)

Read first: `docs/architecture.md` (PageProcessor), `docs/contracts/mcp-contract.md`, `docs/security-policy.md`
§6, §10; ADR-002; deep-dive §10, §11.2, §29, §75–76, §99.

This is the **secure vertical slice**. After this PR the product exists: one URL → guard → fetch →
extract → scan → policy → Markdown → MCP result. Do not touch the crawler.

## Goal
1. `secure-web-crawl::processor::PageProcessor` (yes, it lives in the crawl crate even though
   the crawler comes later — it is the shared path).
2. `secure-web-mcp`: `rmcp` server exposing `web_open` over streamable HTTP (`/mcp`) and stdio.
3. CLI `secure-web open <url> [--inline] [--json]` using the same `PageProcessor`.
4. Contract tests for `tools/list` and `web_open` outputs.

## Design
- `PageProcessor::process(url, ctx) -> PageOutcome` orchestrates exactly the steps in
  `docs/architecture.md`; each step maps its error to `PageOutcome::Failed{code}` or, for
  redirect/SSRF-on-redirect and scanner failure, to `Blocked`. Increment `ctx.budget` bytes after fetch.
  Put the invariant comment from deep-dive §76 above the function.
- `secure-web-mcp::app::App` wires config → `UrlGuard`, `HttpFetcher`, `HtmlExtractor`,
  `SubprocessScanner`, `PolicyEngine`, `FsCorpusStore` → `Arc<PageProcessor>`. Both MCP and CLI
  consume `App`.
- `rmcp`: check current crates.io version; use the `#[tool_router]`/`#[tool]` macros (or the
  equivalent in the pinned version) with `schemars`-derived input structs. Server info name
  `secure-web`. Tool description ends with the §10 sentence. Register **only** `web_open` now;
  `web_crawl`/`web_find` come in PR-08/09.
- `web_open` handler: validate input (`INVALID_ARGUMENT` for bad URL string), create `open_<id>`
  run, call processor with depth 0 and a single-page budget, map `PageOutcome` to the contract
  JSON; `inline` returns truncated Markdown with `truncated` flag. Errors as `isError: true` JSON.
- `serve --listen <addr> [--stdio]`: refuse non-loopback unless `server.allowRemote`. Graceful
  shutdown on SIGINT/SIGTERM.
- CLI exit codes per contract.

## Tests
- `tests/integration/web_open.rs`: spin fixture server + stub scanner + MCP server on an ephemeral
  port; use `rmcp` client (or raw JSON-RPC over HTTP) to call `tools/list` and `web_open` for:
  `/clean/docs/index.html` (SAFE, file exists, Markdown matches snapshot), `/injection/direct`
  (BLOCK, no title/content/contentPath, findingIds), `/redirect/private` (error `REDIRECT_BLOCKED`),
  `http://127.0.0.1:1/` (error `SSRF_BLOCKED`), `/huge` (`CONTENT_TOO_LARGE`), stub `timeout`
  mode (BLOCK SCANNER_FAILURE), `inline=true` truncation, `maxInlineBytes` > hard max → clamped.
- `tests/contracts/mcp_tools_list.rs`: snapshot of `tools/list`.
- `tests/security/no_leak_canary.rs`: extend to grep MCP responses and server logs (capture via
  `tracing-test`) for canaries across all the above calls.
- CLI: `secure-web open <fixture>/injection/direct --json` exits 3 with BLOCK JSON; SAFE exits 0.

## Manual check (record in PR description)
```bash
cargo run -- serve --listen 127.0.0.1:8787
claude mcp add --transport http secure-web http://127.0.0.1:8787/mcp   # Claude Code
# in Claude Code: "use web_open on http://127.0.0.1:<fixture>/clean/docs/index.html"
```
Codex/Copilot connection checks are in PR-10; a quick MCP Inspector check here is enough.

## Done when
- [ ] `PageProcessor` is the only place that sequences guard→fetch→extract→scan→policy→store
- [ ] `web_open` contract snapshot committed; blocked result has no content fields
- [ ] canary grep covers MCP responses and logs
- [ ] `secure-web open` works against fixture; exit codes correct
- [ ] fmt/clippy/test green

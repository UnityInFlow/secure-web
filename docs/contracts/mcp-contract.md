# MCP contract v1

Pinned by `tests/contracts/`. Any change here requires a schema snapshot update in the same PR and
a note in the changelog. Transport: MCP streamable HTTP at `http://127.0.0.1:8787/mcp` (default);
stdio transport also supported (`secure-web serve --stdio`) for hosts that prefer it.

HTTP transport rules (ADR-016): the listener binds loopback unless `server.allowRemote` (a
non-loopback `--listen` without it exits 2, and a wildcard `0.0.0.0`/`::` listen address exits 2
even with it); only `/mcp` is served; the `Host` header must be
`localhost`, `127.0.0.1` or `::1` (plus the listen IP with `allowRemote`) — DNS-rebinding defence;
a request with more than one `Host` header or an absolute-form target is refused (400); a
connection that does not finish its request head within 10 s is closed (this includes a keep-alive
connection left idle for 10 s between requests), and a request whose body
does not arrive in full within 10 s of its head is answered 408 and closed;
any request carrying an `Origin` header is refused (no browser page may drive the server; browser
MCP clients need a non-browser proxy); request bodies are capped at 4 MiB (413). SIGINT/SIGTERM end all
sessions with a 5 s grace period.

Ids: runs are `open_<12 hex>` / `crawl_<12 hex>`, documents `doc_<6 digits>` (unique within a run,
e.g. `doc_000001`). The examples below use these formats.

Server info: `name = "secure-web"`, `version = <crate version>`. Tools only in v0.1 (no
resources/prompts — widest client support).

Naming: tool names are `snake_case`; JSON fields are `camelCase`; enum values are
`SCREAMING_SNAKE_CASE`.

## Common types

```json
"SecurityDecision": "SAFE" | "WARN" | "BLOCK"
"Severity":         "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
"BlockReason":      "PROMPT_INJECTION" | "SSRF" | "UNSUPPORTED_SCHEME" | "UNSUPPORTED_CONTENT_TYPE" |
                    "CONTENT_TOO_LARGE" | "SCANNER_FAILURE" | "REDIRECT_VIOLATION" | "POLICY_VIOLATION"
"SecuritySummary": { "decision": SecurityDecision, "maxSeverity": Severity|null,
                     "findingIds": [string], "scannerVersion": string, "policyVersion": string }
"BlockSummary":    { "url": string, "finalUrl": string|null, "documentId": string,
                     "reason": BlockReason, "maxSeverity": Severity|null, "findingIds": [string] }
```

## `web_open`

Retrieve, inspect and store one URL.

Input:
```json
{ "url": "https://docs.example.com/guide",
  "inline": false,            // optional; when true include bounded clean content in the result
  "maxInlineBytes": 32768 }   // optional, default 32768, hard max 262144
```

Output (accepted):
```json
{ "status": "SAFE",                       // SAFE | WARN
  "documentId": "doc_000001",
  "runId": "open_3f9c1a0b7d2e",
  "url": "https://docs.example.com/guide",
  "finalUrl": "https://docs.example.com/guide/",
  "title": "Guide",
  "contentPath": "/home/u/.secure-web/runs/open_3f9c1a0b7d2e/pages/000001-guide.md",
  "manifestPath": "/home/u/.secure-web/runs/open_3f9c1a0b7d2e/manifest.json",
  "contentBytes": 18234,
  "security": SecuritySummary,
  "content": "…clean markdown…",          // only when inline=true; at most maxInlineBytes bytes (cut on a UTF-8 boundary)
  "truncated": false                       // only when inline=true; true when content was cut
}
```

`maxInlineBytes` above the hard max is clamped to 262144 (not an error); `0` returns empty
content with `truncated: true` for a non-empty page. A bad `url` string (empty, over 8 KiB, not
absolute) or an unknown/ill-typed argument is `INVALID_ARGUMENT`; the error message never echoes
the argument.

Output (blocked) — **no** title, content or contentPath:
```json
{ "status": "BLOCK", "documentId": "doc_000001", "runId": "open_3f9c1a0b7d2e",
  "url": "…", "finalUrl": "…"|null, "block": BlockSummary, "security": SecuritySummary }
```

On a `BLOCK` result, `finalUrl` (top level and in `block`) is `null` whenever the page was
reached through a redirect: the redirect target is server-chosen text that was part of the
blocked security text, so it is never echoed (invariant 4, ADR-016). `url` is the caller's own URL.

`BLOCK` results are only returned for blocks decided on scanned content (`PROMPT_INJECTION`,
`SCANNER_FAILURE`, `POLICY_VIOLATION`). A block decided before any content was scanned is returned
as the matching error object, because nothing usable was fetched (ADR-016):

```text
SSRF -> SSRF_BLOCKED   UNSUPPORTED_SCHEME -> UNSUPPORTED_SCHEME   REDIRECT_VIOLATION -> REDIRECT_BLOCKED
CONTENT_TOO_LARGE -> CONTENT_TOO_LARGE   UNSUPPORTED_CONTENT_TYPE -> UNSUPPORTED_CONTENT_TYPE
```

Such an error's `details` carry `url`, `runId`, `manifestPath`, `documentId` and `reason` (the
`BlockReason` recorded in the manifest's `blocked` list). Other errors (guard rejection of the
first URL, DNS/network failures) carry `url`, `runId` and `manifestPath`; the run's manifest is
`FAILED`. Every `web_open` call creates exactly one `open_<id>` run whose manifest is terminal
(`COMPLETE` or `FAILED`) before the result is returned; a `RUNNING` manifest only remains when the
server died mid-call and is never referenced by a tool result.

Cancellation: when the MCP request is cancelled (`notifications/cancelled`, or the transport's
request context), the page is abandoned wherever it is and the run is finished `CANCELLED` with no
entry; the call ends with error `CRAWL_CANCELLED` (`retryable: true`, details `url`, `runId`,
`manifestPath`; exit 7). A client that cancelled does not wait for it.

## `web_crawl`

Input:
```json
{ "url": "https://docs.example.com",
  "maxDepth": 2,                          // optional, default config, hard max 5
  "maxPages": 100,                        // optional, default config, hard max 1000
  "scope": "SAME_ORIGIN",                 // SAME_ORIGIN (default) | ALLOWLIST
  "allowedHosts": ["docs.example.com"],   // required when scope=ALLOWLIST
  "includePatterns": ["^/docs/"],         // optional path regexes
  "excludePatterns": ["\\.(png|jpg)$"] }  // optional
```

Output:
```json
{ "crawlId": "crawl_f21a9b04c7de",
  "status": "COMPLETE",                   // COMPLETE | LIMIT_REACHED | CANCELLED | FAILED
  "rootUrl": "https://docs.example.com",
  "stats": { "discovered": 132, "fetched": 92, "safe": 88, "warned": 2, "blocked": 2, "failed": 4,
             "totalBytes": 4823001, "durationMs": 8123 },
  "corpusPath": "/home/u/.secure-web/runs/crawl_f21a9b04c7de",
  "manifestPath": "/home/u/.secure-web/runs/crawl_f21a9b04c7de/manifest.json",
  "blocked": [BlockSummary],              // at most 50 entries inline; full list in manifest
  "summary": "Secure Web crawled 92 pages; 2 blocked (prompt injection). Blocked content was not exposed." }
```

Never inline page content. Hard cap on result size: 64 KB.

Arguments: `maxDepth` above 5 is clamped to 5; `maxPages` is clamped to 1..=1000 (the root is
depth 0; `maxPages` counts fetch attempts — stored, blocked and failed). Omitted values come from
the config (`crawl.*`). `allowedHosts` is used only with `scope: ALLOWLIST`, where it must list 1
to 100 host names or IP literals (no ports, paths or userinfo; any port and `http`/`https` match);
it is ignored for `SAME_ORIGIN`. `includePatterns` / `excludePatterns` are at most 20 regexes of at
most 512 bytes each (Rust `regex` syntax, compiled with a size limit), matched against the URL
path of discovered links; the root URL is always fetched. `maxTotalBytes`, `maxDuration`,
`concurrency`, `maxFrontier` and `stripQueryParams` come from the config only. An empty, oversized
(> 8 KiB) or non-absolute `url`, an unknown or ill-typed argument, `ALLOWLIST` without hosts or an
invalid host/pattern is `INVALID_ARGUMENT` (no run is created; the message never echoes the
argument).

Result: `status` is the manifest status. `stats` are the manifest counts (`fetched = safe + warned
+ blocked`, duplicates included) plus `durationMs`. `blocked` lists `BlockSummary` entries in
manifest order: at most 50, and fewer when needed to keep the serialized result within 64 KB (the
manifest lists all). A crawled page's `url` is the resolved link URL, a line of its accepted
parent's scanned text; `finalUrl` is `null` when it differs (ADR-016, ADR-018). `summary` is
generated from counts and reasons only (deep-dive §88):

```text
Secure Web crawled <fetched> page(s); <n> blocked[ (<reason>) | (<reason>: <n>, …)].[ The crawl stopped at a budget limit.| The crawl was cancelled.] Blocked content was not exposed.
```

`LIMIT_REACHED` (a page, byte or duration budget stopped the crawl) and `CANCELLED` (the MCP request
was cancelled; in-flight pages are aborted) are normal results with a valid partial manifest. When
the root URL itself failed before anything was fetched (guard refusal, DNS, network), the run is
`FAILED` and the call returns the root's error object (as for `web_open`) with details `url`,
`crawlId` and `manifestPath`. A `RUNNING` manifest only remains when the server died mid-crawl
and is never referenced by a tool result. Pinned by `tests/integration/web_crawl.rs` (snapshot
`web_crawl_result`).

## `web_find`

Input:
```json
{ "crawlId": "crawl_f21a9b04c7de", "query": "authentication middleware",
  "limit": 10,                            // default 10, max 50
  "includeWarned": true }                 // default true; WARN docs are stored+flagged unless quarantined
```

Output:
```json
{ "crawlId": "crawl_f21a9b04c7de", "query": "…",
  "matches": [ { "documentId": "doc_a1", "path": "pages/000007-authentication.md", "url": "…",
                 "title": "Authentication", "score": 0.91, "decision": "SAFE",
                 "excerpt": "…≤ 512 chars from accepted markdown…", "excerptLine": 42 } ] }
```

Ranking (deterministic, lexical): title match ×4, heading match ×3, exact phrase ×2, token overlap
(case-insensitive, ASCII-folded) ×1; ties broken by path. Only documents with decision
`SAFE`/`WARN` present in the manifest `documents` array are searched. `blocked` entries are never
touched.

## `web_search` (v0.2 — reserved name, not registered in v0.1)

Input `{ "query": string, "limit": 10 }`; output results with `security.status` per entry; blocked
entries omit title/snippet. See deep-dive §11.1, §34.

## Error object (all tools)

Returned as MCP tool error content (`isError: true`) with JSON text:

```json
{ "error": { "code": "SSRF_BLOCKED", "message": "Destination is not allowed", "retryable": false,
             "details": { "url": "…" } } }
```

Codes (contract enum):

```text
INVALID_URL  UNSUPPORTED_SCHEME  DNS_FAILED  SSRF_BLOCKED  REDIRECT_BLOCKED  FETCH_TIMEOUT
FETCH_FAILED  CONTENT_TOO_LARGE  UNSUPPORTED_CONTENT_TYPE  EXTRACTION_FAILED  SCANNER_FAILED
PROMPT_INJECTION_BLOCKED  CRAWL_LIMIT_REACHED  CRAWL_CANCELLED  NOT_FOUND  INVALID_ARGUMENT  INTERNAL
```

Note: a security *block* of a successfully fetched page is a normal (non-error) `web_open` result
with `status: "BLOCK"`. `SSRF_BLOCKED`/`REDIRECT_BLOCKED` are errors because nothing was fetched.
`details.message` must never contain content text.

## CLI exit codes (contract)

```text
0 success (incl. SAFE/WARN)   2 usage/config error   3 security block (BLOCK)   4 fetch/network error
5 scanner failure             6 limit reached (crawl)  7 cancelled              1 internal error
```

Error code → exit code (`impl From<ErrorCode> for i32`, pinned by `tests/core/model.rs`):

```text
2  INVALID_URL  UNSUPPORTED_SCHEME  INVALID_ARGUMENT  NOT_FOUND
3  SSRF_BLOCKED  REDIRECT_BLOCKED  PROMPT_INJECTION_BLOCKED
4  DNS_FAILED  FETCH_TIMEOUT  FETCH_FAILED  CONTENT_TOO_LARGE  UNSUPPORTED_CONTENT_TYPE  EXTRACTION_FAILED
5  SCANNER_FAILED
6  CRAWL_LIMIT_REACHED
7  CRAWL_CANCELLED
1  INTERNAL
```

`secure-web crawl <url> [--depth N] [--max-pages N] [--scope same-origin|allowlist]
[--allow-host H]... [--include REGEX]... [--exclude REGEX]... [--json]` runs `web_crawl` (Ctrl-C
cancels it) and exits 0 for `COMPLETE`, 6 for `LIMIT_REACHED`, 7 for `CANCELLED`, and the table
above for errors (a `FAILED` root, `INVALID_ARGUMENT`). Blocked pages do not change the exit code;
they are listed in the result and the manifest.

`secure-web open <url> [--inline] [--max-inline-bytes N] [--json]` prints the `web_open` result
(`--json`: the exact tool JSON) and exits 0 for `SAFE`/`WARN`, 3 for `BLOCK`, 5 for `BLOCK` with
reason `SCANNER_FAILURE`, and the table above for errors.

A config file that fails to load or validate exits 2. Until a subcommand is implemented it prints
`NOT_IMPLEMENTED: …` on stderr and exits 1 (CLI-only; not an MCP error code).

## Tool description text

Each tool description ends with the agent-facing security sentence from `docs/security-policy.md` §10.

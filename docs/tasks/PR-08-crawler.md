# PR-08 — Crawl frontier + `web_crawl` (SW-010, SW-011)

Read first: `docs/architecture.md` (concurrency, state machines), `docs/contracts/mcp-contract.md`
(`web_crawl`), `docs/threat-model.md` T7/T8/T14; ADR-004; deep-dive §13, §43–45, §82–83.

Precondition: PR-07 green. The crawler **only** calls `PageProcessor::process`; it must contain no
fetch/extract/scan/policy code.

## Goal
`secure-web-crawl::Crawler` with bounded BFS, same-origin/allowlist scope, canonicalization, hard
budgets, bounded concurrency, cancellation, partial manifests; `web_crawl` MCP tool and
`secure-web crawl <url> [--depth N] [--max-pages N] [--scope ...] [--allow-host H]...` CLI.

## Design
- `canonical.rs`: lowercase scheme/host, drop default ports, normalize path (dot segments, percent-
  encoding case), strip fragment, remove `crawl.stripQueryParams`, sort remaining query params. Do
  **not** strip all query params.
- `scope.rs`: `Scope::{SameOrigin{origin}, Allowlist{hosts}}` + include/exclude path regexes
  (compile once, `regex` with size limit). `allows(&Url) -> bool`.
- `frontier.rs`: `VecDeque<(Url, u32)>` + `HashSet<CanonicalUrl>` seen; `push` rejects when
  `len >= maxFrontier` (count as `discovered` but dropped, note in stats).
- `crawler.rs`: 
  ```text
  loop: pop → budget.check() (pages, bytes, elapsed) → if exhausted: status=LIMIT_REACHED, break
        acquire global permit + per-host permit → spawn process(url, ctx) into JoinSet
        on outcome Stored{links}: for l in links: canonical → scope.allows → seen → frontier.push(depth+1) if depth+1 <= maxDepth
        on Blocked/Failed: record, no links (by type)
        Retry-After: re-enqueue once after delay if within budget
  ```
  Track `stats` atomically; `RunWriter.checkpoint()` every 25 stored docs. On `cancel`: stop
  popping, `JoinSet::abort_all`, finish with `CANCELLED`. `maxDuration` via `tokio::time::timeout`
  around the loop → `LIMIT_REACHED`.
- Depth semantics: root = 0; a page at depth `d` is fetched iff `d <= maxDepth`. `maxPages` counts
  fetch attempts (stored + blocked + failed); duplicates by hash still count.
- `web_crawl` handler: validate args (clamp to hard maxes, `ALLOWLIST` requires `allowedHosts`),
  create `crawl_<id>` run, run crawler with a `CancellationToken` tied to the MCP request
  cancellation (rmcp `ct`/request context), return contract JSON; `blocked` list capped at 50;
  result ≤ 64 KB; `summary` string uses the wording in deep-dive §88 (no matched text).
- Long crawl UX: log progress every 10 pages at `info` (counts only).

## Tests (`tests/crawler/*.rs`, `tests/integration/web_crawl.rs`)
- `budgets.rs`: `/depth/0..6` with `maxDepth=3` → exactly 4 fetched; `/links/huge` with
  `maxPages=10` → exactly 10 attempts, status `LIMIT_REACHED`; `maxTotalBytes` small → stops before
  exceeding; `maxDuration=1s` on `/slow` chain → `LIMIT_REACHED` with partial manifest.
- `link_explosion.rs`: `/links/huge` → frontier never exceeds `maxFrontier`; memory bounded; per-URL
  dedupe (`#a`/`#b`, `?utm_source=`) fetches once; `/cycle/a` terminates.
- `blocked_no_links.rs` (T14): `/blocked-with-links` crawl → `fetched == 1`, `blocked == 1`, no
  `/clean/*` fetched.
- `scope.rs`: `/link/c` cross-origin/private/mailto links not followed under `SAME_ORIGIN`;
  `ALLOWLIST` with second fixture host follows; include/exclude patterns.
- `cancel.rs`: cancel token after 3 pages → status `CANCELLED`, manifest valid, `documents.len() >= 1`.
- Integration: full `web_crawl` over the fixture "hostile docs site" (`/clean/docs/*` + one
  `/injection/hidden-css` linked from index): stats correct, injected page absent from `pages/`,
  present in manifest `blocked`, canary grep clean.
- Contract snapshot for `web_crawl` output.

## Carried over from PR-07 (`docs/backlog.md`, target PR-08)
These came out of the PR-07 security review. Each needs a test written before the fix; tick the
backlog line in the same commit.
- **Raw-URL checks for discovered links:** keep each link's href text (resolved against the base)
  and route it through `PageProcessor::process_as_written`, so non-canonical IPv4 spellings and
  empty userinfo `@` are refused for crawled links exactly as for `web_open`.
- **Blocked child URL is attacker text:** decide and document how `blocked[*].url` is recorded for
  crawled pages (contract + ADR); a canary in a child href must not reach MCP output or `runs/`.
- **Unscanned redirect hops:** intermediate hops of an accepted page are written to
  `metadata/*.json` `redirectChain` unscanned. Scan them with `security_text` or drop/normalize
  them (contract + ADR).
- **Remaining IPv6 forms:** block NAT64 local-use `64:ff9b:1::/48` (unwrap), ISATAP `::5efe:a.b.c.d`
  and site-local `fec0::/10` — same guard the crawler relies on; extend ADR-017 and
  `docs/security-policy.md`.
- **Cancellation:** the crawler's `CancellationToken` also covers `web_open` (a cancelled call must
  not leave a `RUNNING` manifest).

## Done when
- [ ] crawler has zero imports from fetch/extract/security crates except types through core
- [ ] all limits exact (tests assert equality, not `<=`)
- [ ] cancellation writes partial manifest
- [ ] `web_crawl` registered; `tools/list` snapshot updated with docs change
- [ ] every "Carried over from PR-07" item fixed with a test, or explicitly re-deferred in `docs/backlog.md`
- [ ] fmt/clippy/test green

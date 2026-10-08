# ADR-019 — Crawler budgets, cancellation and the `web_crawl` result

Status: Accepted (2026-09-26)

## Context
PR-08 adds the crawler (invariant 5: every crawl budget is a hard limit in code; invariant 6: a
blocked page seeds nothing) and exposes it as `web_crawl` and `secure-web crawl`. Three choices
are not fixed by the contract text alone: how the byte budget can be exact when a page's size is
unknown until it is fetched, what cancellation does to a run in flight, and how a crawl whose root
never loaded is reported.

## Decision
1. **Crawler structure.** `secure-web-crawl::Crawler` owns a bounded FIFO frontier
   (`maxFrontier`), a canonical-URL `seen` set (only admitted URLs), and at most
   `crawl.concurrency` (≤ 32) page tasks in a `JoinSet` fed from the frontier — never one task per
   discovered URL. Per-host concurrency stays in the fetcher's host throttle. The crawler module
   imports nothing from fetch/extract/security (a unit test greps its sources); pages go through
   `PageProcessor::process_link` only, and links are taken only from `PageOutcome::Stored`.
2. **Budgets are checked before every attempt.** `maxDepth`: a link found at depth `d` is queued
   only if `d + 1 <= maxDepth`. `maxPages` counts attempts (stored, blocked and failed). Bytes:
   each attempt **reserves** `min(maxPageBytes, maxTotalBytes − fetched − reserved)` and the
   fetch is capped at that reservation (`PageContext::max_fetch_bytes`), so `totalBytes` can never
   exceed `maxTotalBytes`, even with pages in flight. A page larger than its reduced reservation
   is recorded as **failed `CRAWL_LIMIT_REACHED`** (a limit, not a property of the page — it is
   not a `blocked` entry) and scheduling stops. `maxDuration` is checked before every attempt
   (an expired crawl starts no fetch) and aborts in-flight pages. Each ends
   the run `LIMIT_REACHED`, a normal result with a valid partial manifest.
3. **Cancellation finishes the run.** A `CancellationToken` (the rmcp request context's, or the
   CLI's Ctrl-C) is checked before every attempt (a token cancelled before the crawl began starts
   no fetch), stops scheduling, aborts in-flight page tasks (`JoinSet::shutdown`) and finishes
   the run `CANCELLED`; the store's writes are serialized and refuse anything after `finish`, so
   the manifest lists exactly what was recorded. `web_open` races its page against the same kind
   of token and finishes its `open_<id>` run `CANCELLED` with no entry. The MCP handler no longer
   drops a cancelled call's future (which would leave `RUNNING`); it lets the tool finish.
4. **Result mapping.** `COMPLETE`, `LIMIT_REACHED` and `CANCELLED` are normal results (exit 0, 6,
   7). A run whose root failed before anything was fetched is `FAILED` and returned as the root's
   error object (as `web_open` does), exit code per the error table. Blocked pages never change
   the exit code. The inline `blocked` list is capped at 50 and trimmed further (never truncated
   mid-entry) to keep the result within 64 KB; `summary` is built from counts and reason enums
   only (deep-dive §88).

## Consequences
+ Every budget is exact and tested with equality (`tests/crawler/budgets.rs`).
- Near the end of the byte budget, concurrency drops (reservations are conservative), and a page
  that would have fit after an in-flight page released its reservation can be refused.
+ `Retry-After`: a `429`/`503` that carries it is not recorded on the first attempt
  (`PageProcessor::process_link_or_defer`); the crawler retries it **once** after the delay if the
  retry is still within `maxPages` (it counts as an attempt), the byte budget and the deadline
  (the delay must end before `maxDuration`), and not cancelled — otherwise, and whatever the retry
  returns, the page is recorded failed once. A retry holds a concurrency slot while it waits.

# ADR-018 — Crawled URLs: raw-text guard input, recorded child URLs, redirect provenance

Status: Accepted (2026-09-26)

## Context
The crawler (PR-08) is the first component that fetches URLs no caller wrote: every child URL
comes from a page. The PR-07 security review left three questions for it (`docs/backlog.md`):

1. The guard's raw-text rules (a non-canonical IPv4 spelling such as `http://1572395042/`, an
   empty userinfo `http://@host/`) only work on the URL **as written**; parsing rewrites the
   first and drops the second. `PageProcessor::process(url: Url)` validated the re-serialized
   parse, so a crawled link never met those rules.
2. A blocked child page is recorded (`manifest.blocked[*].url`, `metadata/*.json`
   `requestedUrl`) and returned (`web_crawl` `blocked[*].url`) under its requested URL. For
   `web_open` the caller wrote that URL; for a crawled child the page did.
3. The intermediate redirect hops of an **accepted** page were written to `metadata/*.json`
   `redirectChain`, but the scanner never read them: server-chosen text reached `runs/`
   unscanned (invariant 8).

## Decision
1. **Links carry their text as written.** The extractor returns
   `DiscoveredLink { url, as_written }`. `url` is the resolved, fragment-free link (the exposed
   form, a whole line of the scanned `security_text`). `as_written` is the href (fragment cut)
   when it names its own authority, `<base scheme>:` + the href when it is scheme-relative
   (`//host`, `\\host`), and `url` itself when it is path-relative (the authority is the base's,
   validated when the base was fetched) — the same reading the fetcher applies to a redirect
   `Location` (ADR-012). The crawler calls `PageProcessor::process_link`, which refuses a link
   whose text does not parse to exactly `url` (`INVALID_URL`, recorded, no network access) and
   otherwise validates `as_written` through `process_as_written`. `as_written` is never recorded,
   logged or returned; `Debug` prints the host only.
2. **A crawled child is recorded under its resolved URL, which was scanned.** A child is only
   ever discovered on an **accepted** page (`PageOutcome::Stored` is the only variant with
   links, invariant 6), and `accept()` refuses a page unless every link URL is a whole line of
   its scanned `security_text` (ADR-014). So `blocked[*].url` of a crawled page is text the
   scanner already read and passed, exactly like the accepted page's own Markdown; a link whose
   URL carries an injection makes the **parent** blocked, and the child is never discovered.
   `finalUrl` of a blocked page stays withheld when it differs (ADR-016). The root URL is the
   caller's. The raw `as_written` text is not recorded (decision 1).
3. **Only the final redirect hop is recorded.** The page processor keeps only the hop equal to
   the final URL (itself a scanned line) in `redirectChain`; intermediate hops are dropped for
   accepted and blocked pages alike (blocked pages already recorded none, ADR-016). A redirected
   page therefore has `redirectChain: [finalUrl]`, an unredirected one `[]`. Scanning the hops
   instead was rejected: it would put server-chosen text that the model never sees into the
   scanner input purely to be able to store it, and grow `security_text` past its cap on long
   chains.

## Consequences
+ The same guard rules apply to every URL Secure Web fetches, whoever wrote it.
+ Every URL string in `runs/` and in MCP output is either caller-written or scanned.
- Operators lose the intermediate hops of a redirect chain; `requestedUrl` and `finalUrl` remain.
  `debug.retainRaw` does not keep them either (the private audit holds bodies, not headers).
- A link like `http:foo` (read as relative by the resolver, as a host by a standalone parse) is
  refused rather than guessed.

Tests: `tests/extract/links.rs` (`as_written`), `tests/crawler/scope.rs` (raw-text rules on
crawled links), `tests/integration/web_open.rs` (unscanned hops not recorded),
`tests/integration/web_crawl.rs` (canary in a child href never reaches MCP output or `runs/`).

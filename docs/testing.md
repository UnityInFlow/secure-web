# Testing strategy

Secure Web is security infrastructure: tests are corpus-driven, deterministic, offline.

## Ground rules

- No test touches the live Internet. Network tests use the in-process fixture server.
- Security acceptance tests (below) are written **before** the feature that satisfies them; they
  may start `#[ignore]`d only within the same PR that un-ignores them.
- Every `docs/threat-model.md` row has a test file. Every contract in `docs/contracts/` has a
  snapshot test.
- Coverage gate: ≥ 85 % line coverage (`cargo llvm-cov`), enforced in CI from PR-05 onward.

## `tests/support/`

### Fixture server (`fixture_server.rs`)
`axum`/`hyper` server bound to `127.0.0.1:0` (ephemeral port), started per test, serving
`tests/corpus/` plus programmatic routes:

```text
GET /clean/<name>                 static HTML/MD/TXT/JSON from tests/corpus/clean/
GET /injection/direct             HTML with CANARY_DIRECT text in body
GET /injection/base64             HTML with base64-encoded CANARY_B64 instruction
GET /injection/hidden-css         injection inside display:none div  (CANARY_HIDDEN)
GET /injection/comment            injection inside <!-- --> (CANARY_COMMENT)
GET /injection/title              injection in <title> only (CANARY_TITLE)
GET /injection/alt                injection in img alt (CANARY_ALT)
GET /injection/json               application/json containing instruction (CANARY_JSON)
GET /link/a  /link/b  /link/c     link graph: a->b,c ; b->a ; c->(external, private, mailto, fragment)
GET /cycle/a  /cycle/b            a<->b loop
GET /depth/0 .. /depth/6          chain 0->1->2->…->6
GET /links/huge                   page with 50 000 anchors
GET /dup/a  /dup/b                byte-identical content, different URL
GET /redirect/private             302 -> http://127.0.0.1:<port>/clean/a     (must be blocked)
GET /redirect/metadata            302 -> http://169.254.169.254/latest/meta-data/
GET /redirect/loop                302 -> /redirect/loop
GET /redirect/chain/<n>           n hops then /clean/a
GET /redirect/downgrade           302 -> http:// version (when server runs TLS in that test)
GET /huge                         streams 50 MB of text
GET /gzip-bomb                    small gzip body expanding past maxPageBytes
GET /slow                         sleeps past requestTimeout
GET /mime/pdf  /mime/zip          unsupported content types
GET /status/<code>                arbitrary status
GET /blocked-with-links           injection + 20 links to /clean/* (T14)
```

`/redirect/chain/<n>` is exactly `n` redirects before `/clean/a` (`/redirect/chain/0` serves it
directly). `/clean/page-<n>` is generated (link targets of `/links/huge` and
`/blocked-with-links`); other `/clean/<name>` come from `tests/corpus/clean/*/<name>.{html,md,txt,json}`.

The server is a small raw-TCP HTTP/1.1 server (one request per connection) so it can misbehave on
purpose. Tests reach it as `http://fixture.test:<port>/` through a guard built with
`UrlGuard::with_test_fixture` (cargo feature `test-support`, ADR-011); `http://127.0.0.1:<port>/`
itself stays blocked. Extra fetcher routes (PR-03):

```text
GET /redirect/scheme-relative-private   302 -> //127.0.0.1:<port>/clean/a        (blocked)
GET /redirect/backslash-private         302 -> /\127.0.0.1:<port>/clean/a        (blocked)
GET /redirect/obfuscated                302 -> http://1572395042/clean/a         (ambiguous literal)
GET /redirect/localhost                 302 -> http://localhost:<port>/clean/a   (host denied)
GET /redirect/rebind                    302 -> http://rebind.test:<port>/...     (stub DNS: 10.0.0.1)
GET /redirect/userinfo                  302 -> http://user:pw@fixture.test:<port>/clean/a
GET /redirect/absolute                  302 -> http://fixture.test:<port>/clean/a (allowed)
GET /redirect/fragment-loop             302 -> /redirect/fragment-loop#again     (loop)
GET /redirect/canary                    302 -> /clean/a?q=<CANARY_DIRECT>          (blocked on its URL)
GET /redirect/canary-hop                302 -> /redirect/chain/1?q=<CANARY_DIRECT> -> /clean/a (hop never recorded)
GET /redirect/no-location               302 without Location
GET /lying-length/short                 Content-Length: 64, then 8 MiB of body
GET /lying-length/long                  Content-Length: 1 TiB, then 5 bytes
GET /json/big                           2 MiB application/json (> maxJsonBytes)
GET /no-content-type/{html,text,binary} no Content-Type header (sniffing)
GET /encoding/{gzip,deflate}            compressed bodies that must decode
GET /encoding/{br,gzip-gzip}            refused encodings
GET /retry-after/date                   503 with an HTTP-date Retry-After
```

Crawler routes (PR-08):

```text
GET /links/dupes              links to /clean/a#a, #b, ?utm_source=…, and /clean/guide with
                              reordered / dot-segment variants (each target fetched once)
GET /links/raw                a same-origin link written with an empty userinfo `@` (refused by
                              the guard's raw-text rule, never requested) + /clean/a
GET /links/canary-href        a link whose query carries CANARY_ALT (the page itself is blocked)
GET /links/blocked-child      a clean page linking to /injection/direct and /clean/a
GET /links/many-injections    60 links to /injection/direct?n=<i> (blocked-list cap)
GET /links/long-injections    40 links to /injection/direct?n=<i>&pad=<3000 × p> (64 KB cap)
GET /scope/multi              links to http://second.test:<port>/clean/a, /clean/post,
                              /clean/guide, /other/x (second.test: stub DNS -> 127.0.0.1, refused
                              by the guard; the test allowance covers fixture.test only)
GET /slowchain/<n>            answers after 300 ms, links to /slowchain/<n+1> (n <= 50)
GET /clean/docs/index         the hostile docs site: links to /clean/docs/{install,config,api} and
                              /injection/hidden-css; each docs page links back to the index
```

`/mime/*` send their headers and then stall before any body byte, so a test can prove the fetcher
decided on the headers alone. `/status/429` and `/status/503` carry `Retry-After: 7`.

Extraction (PR-04) adds no new routes; it adds clean fixtures that `/clean/<name>` serves like the
others:

```text
GET /clean/layout      tests/corpus/clean/html-edge-cases/layout.html  site chrome (header/nav/aside/footer),
                       <main><article>, table with caption, nested lists, fenced code, quote, entities
GET /clean/post        tests/corpus/clean/blog/post.html               role=banner/navigation/contentinfo,
                       <pre>, <kbd>, <dl>, mailto and fragment links
```

`tests/support/extract.rs` wraps the fetch harness: `fetch_extract(&harness, path)` fetches a route
through the real fetcher and runs `ContentExtractor`; `extract_str` / `extract_html` extract an
in-memory body at a fixed URL (`http://fixture.test/…`, so absolute links are port-independent).

Each canary is a unique random-looking token (e.g. `ZQX-CANARY-7f3a-DIRECT`) defined once in
`tests/support/canaries.rs` and embedded in fixture content. The no-leak test greps every MCP
response body, every file under the run workspace, and captured logs for all canaries.

### Stub scanner (`stub_scanner.rs` + `tests/support/bin/stub-injection-scanner`)
A tiny Rust binary (workspace member `tools/stub-scanner`, not shipped) implementing the
`injection-scanner check - --format json` contract. The stub emits the **real** `injection-scanner
0.1.0` array-of-one-object shape (`tests/contracts/scanner_output.json`, `docs/security-policy.md`
§4) — `[{ "file": "<stdin>", "matches": [...], "suppressed": [], "low_confidence": [], "baselined":
[], "critical_count", "high_count", "medium_count", "low_count" }]` — not a simplified shape, so
the same parser is exercised in stub-backed tests and against the real binary. Behaviour is driven
by `STUB_SCANNER_MODE`:

```text
canary     -> emits CRITICAL finding PI001 (pattern_name "ignore-previous-instructions") for any input
              containing "CANARY"; LOW PI900 for "MILD"; else empty `matches`.
              Exit code follows the real scanner's contract: 1 when `matches` is non-empty, 0 otherwise.
crash      -> exit 101 with garbage on stderr
timeout    -> sleeps 30s
garbage    -> prints "not json {{{"
partial    -> prints half a JSON object then exits 0
huge       -> prints 5 MB of JSON
unexpected-exit -> emits a well-formed, valid `matches`-non-empty array (same shape as `canary`)
              but exits 2. Real scanner behaviour: `--fail-on <severity>` returns exit 2 for a
              finding that parsed fine but sits below the requested bar (`injection-scanner check
              --help`). Secure Web never passes `--fail-on`, so this should not occur in
              production, but the fail-closed rule in §4 ("any other exit code... -> Block") must
              hold even when stdout is perfectly valid JSON, and none of the other modes prove
              that — they all pair a bad exit with unparseable/garbage output.
```

Extra modes (PR-05) for adapter hardening (ADR-014):

```text
canary additions  PI001 for the adapter's end-of-input sentinel line (as the real scanner);
                  MEDIUM PI500 for "STUB-MEDIUM"; a low_confidence entry for "STUB-LOWCONF";
                  "CANARY" is also detected inside base64 runs (/injection/base64).
                  Every match echoes the whole input line in matched_text/context/message/
                  remediation, so a parser that kept any of them would leak the canary.
exit1-clean       valid report with empty `matches`, exit 1          (exit/findings mismatch)
no-read           never reads stdin, prints a clean report, exit 0   (large input -> pipe error,
                                                                      small input -> no sentinel)
partial-read      reads only the first 64 bytes, canary over those   (no sentinel -> block)
wrong-line        canary over all input, line numbers off by one     (sentinel misplaced -> block)
stderr-flood      8 MiB on stderr, then canary behaviour             (over the 64 KiB cap -> block)
stderr-at-cap     exactly 64 KiB on stderr, then canary behaviour    (verdict unchanged)
stderr-over-cap   canary behaviour, then 64 KiB + 1 on stderr         (late flood -> block)
signal            aborts (SIGABRT) after reading stdin
bad-version       `--version` prints non-version text (scans work)   (adapter unavailable)
no-version        `--version` exits 1                                 (adapter unavailable)
timeout           also writes its pid into STUB_SCANNER_PID_DIR when set (reaping test)
structural        canary, plus CRITICAL PI051 when stdin is a bare `{ … }` document containing
                  "STUB-STRUCT" (the sentinel suffix hides it; only the raw pass sees it)
raw-crash         canary when stdin ends with the sentinel suffix, exit 101 otherwise
                                                                     (failing raw pass -> block)
raw-past-end      canary; without the suffix also a finding 2 lines past the input
                                                                     (-> LineOutOfRange, block)
```

The stub rejects any argument list other than `--version` or `check - --format json
--no-suppress --strict` (exit 64), so the adapter's flags are tested too.

`tests/support/scanner.rs` builds the stub once per test binary (`cargo build -p stub-scanner`
into `target/stub-scanner/build`, a separate target dir so it never waits on the outer cargo's
lock), writes one `#!/bin/sh` wrapper per mode that exports `STUB_SCANNER_MODE` and `exec`s the
stub, and points `security.scanner.executable` at the wrapper. It also runs a fixture route
through fetch → extract → scan → `accept()` (`process`, `process_with`, `process_html`), the way
`PageProcessor` will (PR-07). The scanner suites are `cfg(unix)`.

A separate `#[ignore]` suite (`tests/security/scanner_real.rs`) runs the real `injection-scanner`
when `INJECTION_SCANNER_BIN` is set (CI job with the real binary); without the variable it fails
instead of skipping:

```bash
INJECTION_SCANNER_BIN=$(command -v injection-scanner) cargo test --test scanner_real -- --ignored
```

Coverage (CI job `coverage`):

```bash
cargo llvm-cov --locked --workspace --ignore-filename-regex '(^|/)tools/' --fail-under-lines 85
```

Count work, not time: a test that guards against superlinear behaviour asserts on work done,
which machine load and instrumentation cannot change. `secure-web-extract` has test-only work
counters (`src/work.rs`, `#[cfg(test)]`: walk steps, tree-builder stack scans, `href`
resolutions, link-dedupe lookups, bytes searched for verbatim lines) with a budget that panics
as soon as a linear bound is passed; the tests using them live in the crate
(`deeply_nested_inline_and_table_elements_are_bounded`,
`links_huge_is_capped_with_linear_work` in `src/html.rs`), since an integration test cannot
reach `#[cfg(test)]` items. Where a timeout is unavoidable (a scanner subprocess that never
reads stdin), make it a generous backstop and assert the outcome, not the speed.

## Corpus layout

```text
tests/corpus/
  clean/{docs,blog,api-reference,html-edge-cases,markdown,plaintext,json}/    versioned; must produce 0 findings with real scanner
  injection/{direct,encoded,hidden,multiline,metadata,json}/                    each file has a sidecar .expect.json {minSeverity, findingIdsAny}
  crawler/{cycles,duplicate-links,redirect-loops,huge-link-page}/
  network/{localhost,private-ip,redirect-private}/                              URL lists
  snapshots/                                                                    expected Markdown output for clean/ (extraction determinism)
```

Extraction snapshots (`tests/extract/corpus_snapshots.rs`, insta): every file under
`tests/corpus/clean/<dir>/<file>` has `tests/corpus/snapshots/<dir>/<file>.snap` holding the
normalized title and `markdown::render(display)` of the file served at
`http://fixture.test/clean/<stem>`. Adding a clean fixture requires its snapshot:
`INSTA_UPDATE=always cargo test --test corpus_snapshots`, then review the `.snap` diff. In CI
insta never writes snapshots, so a missing or stale one fails.

Extraction tests: `tests/security/injection_hidden.rs` (T3: hidden text scanned, never displayed;
property: every display word is in `security_text`), `tests/security/metadata_title.rs` (T4/T13:
title normalization, slug proptest), `tests/security/extract_bounds.rs` (hostile input stays
bounded; size caps → `CONTENT_TOO_LARGE`), `tests/extract/links.rs`, `tests/extract/display.rs`.

Corpus store tests (PR-06): `tests/support/store.rs` wraps the scanner harness — `add_html`
runs an in-memory page through extract → stub scan → `scan_and_accept` as the writer's next
document and records it (`store` or `record_blocked`) with the `StoreContext` the page processor
will build. `tests/contracts/manifest_v1.rs` (manifest snapshot in
`tests/contracts/snapshots/manifest_v1.snap` + draft 2020-12 schema
`tests/contracts/manifest_v1.schema.json`, validated with `boon`; T17),
`tests/security/sanitized_paths.rs` (T13: hostile titles/URLs, symlinks, audit root),
`tests/store/atomic.rs` (checkpoints; a dropped writer leaves a valid manifest),
`tests/store/dedupe.rs` (`/dup/a` + `/dup/b` → one file), and the corpus test in
`tests/security/no_leak_canary.rs` (T11: canary grep over `runs/`; with `retainRaw` the canaries
exist only under `private-audit/`, mode 0600).

Metrics reported by `cargo test -- --nocapture corpus_metrics`:
`web_injection_block_recall = blocked / total injection fixtures` (target set after corpus ≥ 60
files; CI gate at the committed baseline, never lower it silently) and
`clean_web_false_positive_count = 0` (hard gate) — counting `matches` on `clean/` fixtures that are
**not** covered by a reviewed entry in `tests/corpus/BASELINE.json`. A baseline entry (see PR-10
§10b's PI018 case) names one fixture **and** the exact `pattern_id`(s) it excuses — it is a
per-finding, reviewed exception, never a per-fixture one: it silences only the pinned, already-known
match(es) it lists, not the fixture as a whole. Any other or additional `pattern_id` later found on
that same fixture (a scanner-behavior regression, or new content) is not covered by the entry and
still counts toward the FP gate. A baseline entry is not a way to raise or disable the gate: the
fixture still shows up as detected in `web_injection_block_recall`-style reporting, it is just
excluded from the FP count that must stay at zero — and only for the exact finding(s) it names.

## Security acceptance checklist (must all be green for v0.1)

```text
[ ] http://localhost/ rejected                     [ ] http://127.0.0.1/ rejected
[ ] http://[::1]/ rejected                         [ ] http://10.0.0.1/, 172.16.0.1, 192.168.1.1 rejected
[ ] http://169.254.169.254/ rejected               [ ] http://2130706433/ and http://0x7f000001/ rejected
[ ] http://[::ffff:127.0.0.1]/ rejected            [ ] file:///etc/passwd, data:, javascript: rejected
[ ] host resolving to both public+private IPs rejected
[ ] /redirect/private, /redirect/metadata, /redirect/loop rejected; /redirect/chain/5 ok, /redirect/chain/6 rejected
[ ] scanner crash / timeout / garbage / partial / huge -> BLOCK SCANNER_FAILURE
[ ] scanner binary missing -> BLOCK SCANNER_FAILURE (not panic, not accept)
[ ] no canary string in any MCP response, run file, or log line
[ ] blocked page title absent from output
[ ] /blocked-with-links contributes 0 child URLs
[ ] maxDepth exact (depth/0..6 with maxDepth=3 fetches exactly 4 pages)
[ ] maxPages exact (links/huge with maxPages=10 fetches exactly 10)
[ ] maxTotalBytes exact (stops before exceeding, status LIMIT_REACHED)
[ ] /huge and /gzip-bomb -> CONTENT_TOO_LARGE, memory stays bounded
[ ] same URL fetched once per crawl (fragments/utm stripped); /dup/b deduped by hash
[ ] cross-origin link not followed under SAME_ORIGIN
[ ] cancellation writes partial manifest with status CANCELLED
[ ] manifest.json validates against snapshot schema; contentPath files exist
[ ] web_find never returns text from blocked docs; excerpt ≤ 512 chars
[ ] config with failurePolicy=allow or blockPrivateAddresses=false refuses to start
```

## Contract tests (`tests/contracts/`)

Snapshot (`insta`) of: MCP `tools/list` output (names, descriptions, input schemas), example
outputs for each tool, manifest example, config defaults, error code enum, CLI `--help`, exit codes.
Updating a snapshot requires the corresponding `docs/contracts/*.md` change in the same commit.

## CI (`.github/workflows/ci.yml`)

```text
fmt -> clippy -D warnings -> cargo test --locked --workspace -> contract snapshots -> corpus metrics gate
-> cargo llvm-cov (>=85%) -> cargo audit + cargo deny -> release build (linux x86_64/aarch64, macOS x86_64/arm64)
-> binary smoke (`secure-web --help`, `secure-web open` against fixture) -> perf gate (100 fixture pages < 15 s, scan p95 < 20 ms)
```

Job `real-scanner` (separate, may be `continue-on-error` until stable) downloads a pinned
`injection-scanner` release and runs the `#[ignore]` real-scanner suite + corpus metrics.

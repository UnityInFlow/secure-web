# Architecture (v0.1)

Source of truth for crate boundaries, internal interfaces and the single processing path.
Derived from deep-dive §6, §38–46, §74–79.

## Pipeline

```text
MCP tool / CLI
     |
     v
 PageProcessor::process(url, ctx)
     |
     +-- UrlGuard        parse, scheme check, DNS resolve, IP classify   -> Ssrf / UnsupportedScheme
     +-- HttpFetcher     bounded stream, redirect revalidation, MIME     -> UntrustedDocument
     +-- Extractor       security_text + display StructuredDocument     -> UntrustedDocument (extracted)
     +-- InjectionScanner  subprocess `injection-scanner check - --format json --no-suppress --strict`  -> ScannedDocument
     +-- PolicyEngine    severity -> Safe | Warn | Block                 -> AcceptedDocument | BlockedDocument
     +-- CorpusStore     write Markdown + metadata, update manifest      -> StoredDocument
     |
     v
 PageOutcome { Stored{doc, page: ExposedPage, links} | Blocked(BlockedDocument) | Failed{code, retryable} }
```

The crawler wraps `PageProcessor` in a BFS frontier. It never re-implements any step.

## Workspace layout

```text
secure-web/
├── Cargo.toml                 # [workspace], members below; binary crate at root
├── src/main.rs                # clap CLI: serve | open | crawl | find | inspect | search(v0.2) | connect(v0.2)
├── crates/
│   ├── secure-web-core/       # config, error codes, ids, shared model types, trust-state types
│   ├── secure-web-fetch/      # UrlGuard (ssrf.rs lives in security, fetch calls it), HttpFetcher, redirect, mime, limits
│   ├── secure-web-security/   # ssrf.rs, injection.rs (scanner adapter), policy.rs, decision.rs
│   ├── secure-web-extract/    # tokenizer.rs + dom.rs (bounded parse), html.rs (security_text + display), text.rs, markdown.rs, title.rs
│   ├── secure-web-crawl/      # crawler.rs, frontier.rs, scope.rs, canonical.rs, robots.rs (v0.2)
│   ├── secure-web-store/      # corpus.rs, manifest.rs, find.rs
│   ├── secure-web-search/     # provider.rs (trait only in v0.1; brave/searxng in v0.2)
│   └── secure-web-mcp/        # server.rs, tools/{open,crawl,find,search}.rs, app.rs (PageProcessor wiring)
├── tests/
│   ├── support/               # fixture HTTP server, stub scanner, helpers
│   ├── corpus/                # clean/, injection/, crawler/, network/
│   ├── contracts/             # JSON schema snapshots for tools + manifest
│   ├── security/              # SSRF, redirect, fail-closed, no-leak tests
│   ├── crawler/               # depth/page/byte limits, dedupe, cycles
│   └── integration/           # end-to-end via MCP client against fixture site
├── config/secure-web.example.yaml
└── docs/
```

Dependency direction (no cycles):

```text
core <- fetch, security, extract, store, search, crawl
extract <- security   (accept() renders AcceptedDocument.markdown with extract::markdown::render)
extract <- store      (title::{normalize_title, slug} for page names, markdown::render for the title H1; ADR-015)
security <- store     (the sealed AcceptedDocument / RawContent types live in security::decision; ADR-016)
crawl <- fetch, security, extract, store
mcp   <- crawl, store, search, core  (mcp does NOT depend on fetch/security/extract directly)
main  <- mcp, crawl, store, core
```

## Trust-state types

`UntrustedDocument` and `BlockedDocument` live in `secure-web-core::model`. `ScannedDocument`,
`AcceptedDocument` and `RawContent` live in `secure-web-security::decision` and are **sealed**
(ADR-016): private fields, read-only accessors, constructible only inside that module
(`scan_document`, `accept`, `scan_and_decide`). The field lists below are the logical shape.

```rust
pub struct UntrustedDocument {          // after fetch + extract; never leaves security/extract/crawl crates
    pub requested_url: Url,
    pub final_url: Url,
    pub redirect_chain: Vec<Url>,
    pub http_status: u16,
    pub content_type: ContentType,
    pub retrieved_at: DateTime<Utc>,
    pub security_text: String,          // includes hidden text, comments, alt/aria, metadata
    pub display: StructuredDocument,    // visible/readable structure
    pub links: Vec<Url>,
    pub raw_bytes: Option<Vec<u8>>,     // only when debug.retainRaw = true
}

pub struct ScannedDocument { doc: UntrustedDocument, findings: SecurityFindings }   // sealed

pub struct AcceptedDocument {           // sealed; the ONLY type CorpusStore accepts
    doc_id: DocumentId,
    final_url: Url,
    requested_url: Url,
    title: Option<String>,              // already normalized/scanned
    markdown: String,                   // from display, never from security_text
    links: Vec<Url>,
    security: SecuritySummary,          // decision Safe|Warn, ids only
    provenance: Provenance,
}

pub struct BlockedDocument {            // no body, no matched text
    pub doc_id: DocumentId,
    pub requested_url: Url,
    pub final_url: Option<Url>,
    pub reason: BlockReason,
    pub max_severity: Option<Severity>,
    pub finding_ids: Vec<String>,
    pub scanner_version: Option<String>,
}
```

`BlockedDocument` must not implement any accessor that returns document text. Enforce with a test
that the type has no `String` field other than ids.

## Core enums (contract — see `docs/contracts/mcp-contract.md`)

```rust
#[serde(rename_all = "SCREAMING_SNAKE_CASE")] pub enum SecurityDecision { Safe, Warn, Block }
#[serde(rename_all = "SCREAMING_SNAKE_CASE")] pub enum Severity { Low, Medium, High, Critical }
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlockReason {
    PromptInjection, Ssrf, UnsupportedScheme, UnsupportedContentType,
    ContentTooLarge, ScannerFailure, RedirectViolation, PolicyViolation,
}
```

## Internal traits (`secure-web-core::ports`)

```rust
#[async_trait] pub trait Fetcher        { async fn fetch(&self, req: FetchRequest) -> Result<FetchedResponse, FetchError>; }
pub trait Extractor                     { fn extract(&self, input: &ExtractInput<'_>) -> Result<ExtractedDocument, ExtractError>; }  // sync, CPU-bound; lives in secure-web-extract (ADR-013)
pub trait SecurityScanner               { fn scan<'a>(&'a self, security_text: &'a str) -> ScanFuture<'a>; }  // secure-web-security::injection, boxed future (like Fetcher)
pub trait SecurityPolicy                { fn decide(&self, findings: &SecurityFindings) -> PolicyOutcome; fn policy_version(&self) -> &str; }  // secure-web-security::policy
// scan errors never reach a SecurityPolicy: policy::decide_error(&ScanError) is a free fn -> Block(ScannerFailure)
// decision::scan_and_accept(doc, scanner, policy, ctx) -> Result<AcceptedDocument, BlockedDocument>  (ADR-014)
// decision::scan_and_decide(doc, scanner, policy, ctx) -> Decision { outcome, findings, scan_duration, raw }  (ADR-016; used by PageProcessor)
pub trait CorpusStore                   { fn store<'a>(&'a self, doc: AcceptedDocument, ctx: &'a StoreContext) -> StoreFuture<'a, StoredDocument>;
                                          fn record_blocked<'a>(&'a self, b: &'a BlockedDocument, ctx: &'a StoreContext) -> StoreFuture<'a, ()>; }
// secure-web-store::corpus, boxed future; implemented per run by RunWriter (FsCorpusStore::begin_run),
// which also issues document ids (next_doc_id), records failures and checkpoints/finishes the manifest
#[async_trait] pub trait SearchProvider { async fn search(&self, q: SearchQuery) -> Result<Vec<SearchResult>, SearchError>; }
```

Traits are for testability (stub scanner, in-memory store), not for plug-in architecture. One
implementation each in v0.1.

## PageProcessor (`secure-web-crawl::processor` — used by both open and crawl)

```rust
pub struct PageProcessor { guard: UrlGuard, fetcher: Arc<dyn Fetcher>, extractor: Arc<dyn Extractor>,
                           scanner: Arc<dyn SecurityScanner>, policy: Arc<dyn SecurityPolicy>,
                           store: FsCorpusStore, limits: FetchLimits, retain_raw: bool, .. }
// built by PageProcessor::from_config / with_guard; the fetcher uses the same UrlGuard that
// validates the first URL (so extraBlocked* apply to every redirect hop too)

pub struct PageContext { pub run: Arc<RunWriter>, pub depth: u32, pub budget: Arc<CrawlBudget>,
                         pub max_fetch_bytes: Option<u64> }   // crawl byte-budget reservation

pub enum PageOutcome {
    Stored { doc: StoredDocument, page: ExposedPage, links: Vec<DiscoveredLink> },  // links only from accepted docs
    Blocked(BlockedDocument),                          // links == none, by construction
    Failed { code: ErrorCode, retryable: bool },
}

impl PageProcessor {
    pub async fn process(&self, url: Url, ctx: PageContext) -> PageOutcome;
    pub async fn process_link(&self, link: &DiscoveredLink, ctx: PageContext) -> PageOutcome; // guard on the href as written (ADR-018)
    pub async fn open_cancellable(&self, url: &str, cancel: &CancellationToken)
        -> Result<OpenedRun, OpenError>;   // one-page open_<id> run (web_open, CLI open); CANCELLED on cancel
}

// secure-web-crawl::crawler — imports nothing from fetch/extract/security
pub struct Crawler { processor: Arc<PageProcessor> }
impl Crawler {
    pub async fn crawl(&self, root: &str, options: CrawlOptions, cancel: CancellationToken)
        -> Result<CrawlReport, CrawlError>;   // one crawl_<id> run (web_crawl, CLI crawl)
}
```

`ExposedPage` is sealed: built only from an `AcceptedDocument`, it hands out the requested/final
URL, title and Markdown — the only page strings `secure-web-mcp` can expose. Extraction runs in
`spawn_blocking`. Guard rejections and network failures are `Failed`; fetch/extract policy
violations (redirect, size, content type) and scan/policy blocks are `Blocked` (ADR-016).

`secure-web-mcp::App` wraps `Arc<PageProcessor>` plus a call semaphore
(`min(crawl.concurrency, 16)`); both the MCP server and the CLI `open` command use it.

Invariant test: `PageOutcome::Blocked` and `Failed` carry no `links` field at all.

## Per-page state machine

```text
DISCOVERED -> VALIDATING -> FETCHING -> EXTRACTING -> SCANNING
                                                        ├─ SAFE  -> STORED
                                                        ├─ WARN  -> STORED (flagged) | QUARANTINED (policy)
                                                        ├─ BLOCK -> BLOCKED
                                                        └─ ERROR -> FAILED
```

Crawl: `CREATED -> RUNNING -> COMPLETE | LIMIT_REACHED | CANCELLED | FAILED`.
`LIMIT_REACHED` and `CANCELLED` are successful terminal states that still write a manifest.

## Concurrency model (crawler)

- Bounded BFS `VecDeque<(DiscoveredLink, depth)>` (`frontier.rs`) with a hard cap on frontier
  length (`maxFrontier`, default 10 000); a link arriving at a full frontier is dropped (counted as
  discovered). Dedupe on the canonical URL (`canonical.rs`); scope in `scope.rs` (ADR-004).
- Global concurrency: at most `crawl.concurrency` (default 8, max 32) page tasks in a `JoinSet`,
  spawned only from the frontier — never one task per discovered URL. Per-host concurrency
  (`fetch.perHostConcurrency`, default 4) and delay are enforced by the fetcher's host throttle.
- Budgets checked before every fetch: `maxPages` counts attempts; every attempt reserves
  `min(maxPageBytes, maxTotalBytes - fetched - reserved)` and is capped at it, so `totalBytes`
  never exceeds `maxTotalBytes` (a page that does not fit is failed `CRAWL_LIMIT_REACHED`).
  Exceeding a budget → stop scheduling, drain in-flight, finish with `LIMIT_REACHED`;
  `maxDuration` → abort in-flight, `LIMIT_REACHED`.
- `CancellationToken` from the MCP request (rmcp request context) or the CLI's Ctrl-C; on cancel →
  stop scheduling, abort in-flight, write partial manifest, status `CANCELLED`. `web_open` takes
  the same token and finishes its `open_<id>` run `CANCELLED`.

## Storage layout (contract — see `docs/contracts/manifest-schema.md`)

```text
<workspace>/runs/<crawlId>/
  manifest.json
  pages/000001-<slug>.md
  metadata/000001.json
  security/summary.json
  security/findings.json          # ids + severities only
  quarantine/000004-<slug>.md     # WARN pages when security.warnHandling = quarantine
<workspace>/private-audit/         # NEVER mounted into an agent sandbox; raw bodies only if debug.retainRaw
```

`web_open` uses the same layout with a `open_<id>` run directory containing exactly one page.

## Version stamps

Every manifest and metadata file records `secureWebVersion`, `scannerVersion`, `policyVersion`.
`policyVersion` is a hash of the effective `security:` config block.

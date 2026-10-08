//! [`PageProcessor`]: the single processing path for model-facing Internet content
//! (`docs/architecture.md` "PageProcessor", ADR-009, invariant 1).
//!
//! ```text
//! UrlGuard -> HttpFetcher -> Extractor (spawn_blocking) -> scan_and_decide -> RunWriter
//! ```
//!
//! `web_open` and the crawler (PR-08) both call [`PageProcessor::process`]; nothing else
//! sequences these steps.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use secure_web_core::config::{Config, ConfigError};
use secure_web_core::error::ErrorCode;
use secure_web_core::model::{
    BlockReason, BlockedDocument, ContentType as ModelContentType, DiscoveredLink, StoredDocument,
    UntrustedDocument,
};
use secure_web_extract::{
    ContentExtractor, ExtractInput, ExtractLimits, ExtractedDocument, Extractor, SourceKind,
};
use secure_web_fetch::{
    ContentType, FetchError, FetchLimits, FetchRequest, FetchedResponse, Fetcher, HttpFetcher,
};
use secure_web_security::decision::{scan_and_decide, AcceptContext, AcceptedDocument};
use secure_web_security::injection::{SecurityScanner, SubprocessScanner};
use secure_web_security::policy::{PolicyEngine, PolicyError, SecurityPolicy};
use secure_web_security::ssrf::{GuardConfigError, GuardError, UrlGuard};
use secure_web_store::{
    DocumentSizes, FsCorpusStore, RunWriter, StoreContext, StoreError, StoreOptions, Versions,
};
use url::Url;

/// `versions.scanner` of a run whose scanner failed its `--version` check at startup. Every
/// page of such a run is blocked (`SCANNER_FAILURE`, ADR-003), so no document is ever decided
/// under this "version".
pub const SCANNER_UNAVAILABLE: &str = "unavailable";

/// The processor could not be built from the configuration.
#[derive(Debug, thiserror::Error)]
pub enum ProcessorError {
    /// `security.network` is invalid.
    #[error(transparent)]
    Guard(#[from] GuardConfigError),
    /// The `security` block would weaken the policy.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// The workspace cannot be opened.
    #[error("workspace: {0}")]
    Store(#[from] StoreError),
    /// The config cannot be hashed into a policy version.
    #[error(transparent)]
    Config(#[from] ConfigError),
}

/// Counters a crawl (or a single `web_open`) shares across its pages. The processor adds every
/// fetched body; the crawler (PR-08) checks the limits before scheduling.
#[derive(Debug, Default)]
pub struct CrawlBudget {
    pages_fetched: AtomicU64,
    total_bytes: AtomicU64,
}

impl CrawlBudget {
    /// A fresh budget.
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one fetched response of `bytes` decompressed bytes.
    pub fn record_fetch(&self, bytes: u64) {
        self.pages_fetched.fetch_add(1, Ordering::SeqCst);
        self.total_bytes.fetch_add(bytes, Ordering::SeqCst);
    }

    /// Responses fetched so far.
    pub fn pages_fetched(&self) -> u64 {
        self.pages_fetched.load(Ordering::SeqCst)
    }

    /// Decompressed bytes fetched so far.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes.load(Ordering::SeqCst)
    }
}

/// Where one page belongs.
#[derive(Debug, Clone)]
pub struct PageContext {
    /// The run the page is recorded in; it issues the document id.
    pub run: Arc<RunWriter>,
    /// Crawl depth (0 for `web_open`).
    pub depth: u32,
    /// Shared counters of the run.
    pub budget: Arc<CrawlBudget>,
    /// The crawl's remaining byte budget reserved for this page, when it is below
    /// `fetch.maxPageBytes` / `maxJsonBytes`: the fetch is capped at it, and a body that would
    /// exceed it is recorded as failed `CRAWL_LIMIT_REACHED` (not a blocked page), so
    /// `crawl.maxTotalBytes` is never exceeded. `None` for `web_open`.
    pub max_fetch_bytes: Option<u64>,
}

/// The model-facing strings of an accepted page. Sealed: only built by the processor from a
/// sealed `AcceptedDocument`, whose `accept()` step proved that the title, the Markdown and the
/// final URL are part of the scanned `security_text` (invariant 8, ADR-013/014/016). Callers
/// (the MCP layer) can only expose what this type hands out.
#[derive(Clone, PartialEq, Eq)]
pub struct ExposedPage {
    requested_url: Url,
    final_url: Url,
    title: Option<String>,
    markdown: String,
}

impl ExposedPage {
    fn from_accepted(doc: &AcceptedDocument) -> Self {
        Self {
            requested_url: doc.requested_url().clone(),
            final_url: doc.final_url().clone(),
            title: doc.title().map(str::to_owned),
            markdown: doc.markdown().to_owned(),
        }
    }

    /// URL as requested.
    pub fn requested_url(&self) -> &Url {
        &self.requested_url
    }

    /// URL after redirects (scanned).
    pub fn final_url(&self) -> &Url {
        &self.final_url
    }

    /// Normalized, scanned title.
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Clean Markdown rendered from the page's display structure (scanned).
    pub fn markdown(&self) -> &str {
        &self.markdown
    }
}

impl fmt::Debug for ExposedPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExposedPage")
            .field("markdown_bytes", &self.markdown.len())
            .field("has_title", &self.title.is_some())
            .finish_non_exhaustive()
    }
}

/// What happened to one URL. Only `Stored` carries links: a blocked or failed page contributes
/// no child URLs, by construction (invariant 6).
#[derive(Debug, Clone)]
pub enum PageOutcome {
    /// Accepted (`SAFE`/`WARN`) and written to the corpus.
    Stored {
        /// The stored document.
        doc: StoredDocument,
        /// Its model-facing strings.
        page: ExposedPage,
        /// Links found on the page (each a whole line of its scanned `security_text`).
        links: Vec<DiscoveredLink>,
    },
    /// Blocked by policy: ids, URLs and enums only.
    Blocked(BlockedDocument),
    /// Nothing was fetched or decided (guard rejection, network failure, internal error).
    Failed {
        /// Contract error code.
        code: ErrorCode,
        /// Whether retrying may succeed.
        retryable: bool,
    },
}

/// The one pipeline. Cheap to share behind an `Arc`.
pub struct PageProcessor {
    guard: UrlGuard,
    fetcher: Arc<dyn Fetcher>,
    extractor: Arc<dyn Extractor>,
    scanner: Arc<dyn SecurityScanner>,
    policy: Arc<dyn SecurityPolicy>,
    limits: FetchLimits,
    retain_raw: bool,
    store: FsCorpusStore,
    versions: Versions,
    config: Config,
}

impl fmt::Debug for PageProcessor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageProcessor")
            .field("versions", &self.versions)
            .field("retain_raw", &self.retain_raw)
            .finish_non_exhaustive()
    }
}

impl PageProcessor {
    /// Build the pipeline from `config` with a guard on the system resolver.
    pub async fn from_config(config: &Config) -> Result<Self, ProcessorError> {
        let guard = UrlGuard::with_system_resolver(&config.security.network)?;
        Self::with_guard(config, guard).await
    }

    /// Build the pipeline from `config` around `guard`. The same guard validates the first URL
    /// and (inside the fetcher) every redirect hop, so `extraBlocked*` apply to both. Its DNS
    /// lookups are bounded by `fetch.connectTimeout`.
    pub async fn with_guard(config: &Config, guard: UrlGuard) -> Result<Self, ProcessorError> {
        let guard = guard.with_dns_timeout(config.fetch.connect_timeout);
        let fetcher = HttpFetcher::new(&config.fetch, guard.clone());
        let extract_limits = ExtractLimits::from(&config.extract);
        let scanner = SubprocessScanner::new(
            &config.security.scanner,
            extract_limits.max_security_text_bytes,
        )
        .await;
        let policy = PolicyEngine::new(&config.security)?;
        let scanner_version = scanner
            .version()
            .map_or_else(|_| SCANNER_UNAVAILABLE.to_owned(), str::to_owned);
        let versions = Versions::current(scanner_version, policy.policy_version());
        // The store quarantines from the same config the policy was built from.
        let store = FsCorpusStore::new(StoreOptions::from_config(config))?;
        Ok(Self {
            guard,
            fetcher: Arc::new(fetcher),
            extractor: Arc::new(ContentExtractor::new(extract_limits)),
            scanner: Arc::new(scanner),
            policy: Arc::new(policy),
            limits: FetchLimits::from(&config.fetch),
            retain_raw: config.debug.retain_raw,
            store,
            versions,
            config: config.clone(),
        })
    }

    /// Scanner and policy versions every document of this processor is decided under.
    pub fn versions(&self) -> &Versions {
        &self.versions
    }

    /// The corpus store runs are created in.
    pub fn store(&self) -> &FsCorpusStore {
        &self.store
    }

    /// The effective configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Process one URL and record the outcome in `ctx.run`.
    ///
    /// INVARIANT (deep-dive §76, ADR-009): **No Internet-derived model-facing content may bypass
    /// `PageProcessor`.** This function is the only place that sequences
    /// guard → fetch → extract → scan → policy → store. `web_open`, the crawler and any future
    /// content source call it; none re-implements a step.
    pub async fn process(&self, url: Url, ctx: PageContext) -> PageOutcome {
        let as_written = url.as_str().to_owned();
        self.process_as_written(&as_written, url, ctx).await
    }

    /// [`process`](PageProcessor::process) for a link found on an accepted page (the crawler).
    /// The guard validates the href as written ([`DiscoveredLink::as_written`]), so its
    /// raw-text rules apply to crawled links exactly as to a `web_open` argument. A link whose
    /// written text does not parse to exactly `link.url` is refused (`INVALID_URL`) without
    /// any network access: the page is recorded under `link.url`, so nothing else may be
    /// fetched in its name.
    pub async fn process_link(&self, link: &DiscoveredLink, ctx: PageContext) -> PageOutcome {
        match self.process_link_or_defer(link, ctx, false).await {
            Ok(outcome) => outcome,
            // Unreachable with `defer_retry = false`; recorded as failed all the same.
            Err(later) => PageOutcome::Failed {
                code: later.code,
                retryable: true,
            },
        }
    }

    /// [`process_link`](PageProcessor::process_link) for the crawler's first attempt at a
    /// link. With `defer_retry`, a `429`/`503` that carried `Retry-After` is **not recorded**:
    /// it comes back as [`RetryLater`] so the crawler can retry it once within its budgets, or
    /// record it with [`RetryLater::record`]. Every other outcome is recorded as usual.
    pub async fn process_link_or_defer(
        &self,
        link: &DiscoveredLink,
        ctx: PageContext,
        defer_retry: bool,
    ) -> Result<PageOutcome, RetryLater> {
        let consistent = Url::parse(&link.as_written).is_ok_and(|mut parsed| {
            parsed.set_fragment(None);
            parsed == link.url
        });
        if !consistent {
            tracing::debug!("link text does not match its resolved URL; refused");
            if let Err(err) = ctx
                .run
                .record_failed(&link.url, ctx.depth, ErrorCode::InvalidUrl, false)
                .await
            {
                return Ok(store_failure(&err));
            }
            return Ok(PageOutcome::Failed {
                code: ErrorCode::InvalidUrl,
                retryable: false,
            });
        }
        self.process_steps(&link.as_written, link.url.clone(), ctx, defer_retry)
            .await
    }

    /// [`process`](PageProcessor::process) for a URL whose original text is still known (a
    /// `web_open` argument). The guard validates `as_written`, not the parsed `url`: parsing
    /// rewrites a non-canonical IPv4 spelling and drops an empty userinfo `@`, so the guard's
    /// raw-text rules (`docs/security-policy.md` §1, `CheckedUrl`) only work on the original.
    /// `url` must be `Url::parse(as_written)`; it names the page in the run records.
    pub(crate) async fn process_as_written(
        &self,
        as_written: &str,
        url: Url,
        ctx: PageContext,
    ) -> PageOutcome {
        match self.process_steps(as_written, url, ctx, false).await {
            Ok(outcome) => outcome,
            // Unreachable with `defer_retry = false`.
            Err(later) => PageOutcome::Failed {
                code: later.code,
                retryable: true,
            },
        }
    }

    async fn process_steps(
        &self,
        as_written: &str,
        url: Url,
        ctx: PageContext,
        defer_retry: bool,
    ) -> Result<PageOutcome, RetryLater> {
        let outcome = self.run_steps(as_written, url.clone(), &ctx).await;
        Ok(match outcome {
            Step::Stored { doc, page, links } => PageOutcome::Stored { doc, page, links },
            Step::Blocked(mut blocked, mut store_ctx) => {
                withhold_server_chosen_urls(&mut blocked, &mut store_ctx);
                match ctx.run.record_blocked(&blocked, &store_ctx).await {
                    Ok(()) => PageOutcome::Blocked(blocked),
                    Err(err) => store_failure(&err),
                }
            }
            Step::Failed {
                code,
                retryable,
                retry_after: Some(delay),
            } if defer_retry && retryable => {
                return Err(RetryLater {
                    url,
                    depth: ctx.depth,
                    code,
                    delay,
                });
            }
            Step::Failed {
                code, retryable, ..
            } => record_failure(&ctx.run, &url, ctx.depth, code, retryable).await,
        })
    }

    async fn run_steps(&self, as_written: &str, url: Url, ctx: &PageContext) -> Step {
        // 1. Guard: parse, scheme, literal rules, DNS, every resolved address (invariant 2).
        // The raw-text rules need the URL as written, never a re-serialized parse.
        let target = match self.guard.validate(as_written).await {
            Ok(target) => target,
            Err(err) => {
                tracing::debug!(error = %err.code(), "URL rejected by the guard");
                return Step::Failed {
                    code: err.code(),
                    retryable: matches!(err, GuardError::DnsFailed),
                    retry_after: None,
                };
            }
        };

        // 2. Fetch: pinned connection, every redirect hop re-validated by the same guard.
        let mut limits = self.limits;
        if let Some(cap) = ctx.max_fetch_bytes {
            limits.max_page_bytes = limits.max_page_bytes.min(cap);
            limits.max_json_bytes = limits.max_json_bytes.min(cap);
        }
        let request = FetchRequest { target, limits };
        let mut response = match self.fetcher.fetch(request).await {
            Ok(response) => response,
            Err(err) => return self.fetch_failed(url, &err, ctx),
        };
        ctx.budget.record_fetch(response.decompressed_bytes);
        keep_scanned_hops(&mut response);

        // 3. Extract, off the reactor (a 5 MiB hostile page is CPU work).
        let extracted = match self.extract(&response).await {
            Ok(extracted) => extracted,
            Err(Extraction::Blocked(reason)) => {
                let doc_id = match ctx.run.next_doc_id() {
                    Ok(id) => id,
                    Err(err) => return Step::store_error(&err),
                };
                let blocked = BlockedDocument {
                    doc_id,
                    requested_url: response.requested_url.clone(),
                    final_url: Some(response.final_url.clone()),
                    reason,
                    max_severity: None,
                    finding_ids: Vec::new(),
                    scanner_version: None,
                };
                let store_ctx = StoreContext {
                    sizes: DocumentSizes {
                        raw_bytes: response.decompressed_bytes,
                        ..DocumentSizes::default()
                    },
                    ..response_context(&response, ctx.depth)
                };
                return Step::Blocked(blocked, store_ctx);
            }
            Err(Extraction::Internal) => {
                return Step::Failed {
                    code: ErrorCode::Internal,
                    retryable: false,
                    retry_after: None,
                }
            }
        };

        // 4. Scan + policy: the one scan → accept path (ADR-014), under an id this run issued.
        let doc_id = match ctx.run.next_doc_id() {
            Ok(id) => id,
            Err(err) => return Step::store_error(&err),
        };
        let sizes = DocumentSizes {
            raw_bytes: response.decompressed_bytes,
            extracted_bytes: 0,
            security_text_bytes: extracted.security_text.len() as u64,
            links_found: extracted.links.len() as u64,
            links_truncated: extracted.links_truncated,
        };
        let mut store_ctx = response_context(&response, ctx.depth);
        let doc = untrusted(response, extracted, self.retain_raw);
        let accept_ctx = AcceptContext {
            doc_id,
            depth: ctx.depth,
            retain_raw: self.retain_raw,
        };
        let decision = scan_and_decide(
            doc,
            self.scanner.as_ref(),
            self.policy.as_ref(),
            &accept_ctx,
        )
        .await;
        store_ctx.findings = decision.findings;
        store_ctx.scan_duration_ms = decision
            .scan_duration
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        store_ctx.raw = decision.raw;

        // 5. Store: accepted documents only; a blocked one is recorded without content.
        match decision.outcome {
            Ok(accepted) => {
                store_ctx.sizes = DocumentSizes {
                    extracted_bytes: accepted.markdown().len() as u64,
                    ..sizes
                };
                let page = ExposedPage::from_accepted(&accepted);
                let links = accepted.links().to_vec();
                match ctx.run.store(accepted, &store_ctx).await {
                    Ok(doc) => Step::Stored { doc, page, links },
                    Err(err) => Step::store_error(&err),
                }
            }
            Err(blocked) => {
                store_ctx.sizes = sizes;
                Step::Blocked(blocked, store_ctx)
            }
        }
    }

    /// A fetch error is a `BlockedDocument` when it is a policy violation (redirect, size,
    /// content type), an ordinary failure otherwise.
    fn fetch_failed(&self, url: Url, err: &FetchError, ctx: &PageContext) -> Step {
        tracing::debug!(error = %err, "fetch failed");
        if let (FetchError::ContentTooLarge { limit, .. }, Some(cap)) = (err, ctx.max_fetch_bytes) {
            let budget_capped = *limit == cap
                && (cap < self.limits.max_page_bytes || cap < self.limits.max_json_bytes);
            if budget_capped {
                // The page did not fit the crawl's remaining byte budget: a limit, not a
                // property of the page.
                return Step::Failed {
                    code: ErrorCode::CrawlLimitReached,
                    retryable: false,
                    retry_after: None,
                };
            }
        }
        let Some(reason) = err.block_reason() else {
            return Step::Failed {
                code: err.code(),
                retryable: err.retryable(),
                retry_after: err.retry_after(),
            };
        };
        let doc_id = match ctx.run.next_doc_id() {
            Ok(id) => id,
            Err(err) => return Step::store_error(&err),
        };
        Step::Blocked(
            BlockedDocument {
                doc_id,
                requested_url: url,
                final_url: None,
                reason,
                max_severity: None,
                finding_ids: Vec::new(),
                scanner_version: None,
            },
            StoreContext {
                depth: ctx.depth,
                ..StoreContext::default()
            },
        )
    }

    async fn extract(&self, response: &FetchedResponse) -> Result<ExtractedDocument, Extraction> {
        let kind = match &response.content_type {
            ContentType::Html => SourceKind::Html,
            ContentType::PlainText => SourceKind::PlainText,
            ContentType::Markdown => SourceKind::Markdown,
            ContentType::Json => SourceKind::Json,
            // The fetcher never returns an unsupported type; refuse it anyway.
            ContentType::Unsupported(_) => {
                return Err(Extraction::Blocked(BlockReason::UnsupportedContentType))
            }
        };
        let extractor = Arc::clone(&self.extractor);
        let final_url = response.final_url.clone();
        let charset = response.charset.clone();
        let body = response.body.clone();
        // The blocking thread keeps the caller's subscriber and span, so its logs land where
        // the caller's go.
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let span = tracing::Span::current();
        let task = tokio::task::spawn_blocking(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                span.in_scope(|| {
                    extractor.extract(&ExtractInput {
                        final_url: &final_url,
                        kind,
                        charset: charset.as_deref(),
                        body: &body,
                    })
                })
            })
        });
        match task.await {
            Ok(Ok(extracted)) => Ok(extracted),
            Ok(Err(err)) => {
                tracing::debug!(error = %err, "extraction refused the page");
                Err(Extraction::Blocked(err.block_reason()))
            }
            Err(_) => Err(Extraction::Internal),
        }
    }
}

enum Extraction {
    Blocked(BlockReason),
    Internal,
}

enum Step {
    Stored {
        doc: StoredDocument,
        page: ExposedPage,
        links: Vec<DiscoveredLink>,
    },
    Blocked(BlockedDocument, StoreContext),
    Failed {
        code: ErrorCode,
        retryable: bool,
        /// `Retry-After` delay of a `429`/`503` (never set for any other failure).
        retry_after: Option<Duration>,
    },
}

impl Step {
    fn store_error(err: &StoreError) -> Self {
        tracing::error!(error = %err, "corpus store failed");
        Step::Failed {
            code: ErrorCode::Internal,
            retryable: false,
            retry_after: None,
        }
    }
}

/// A blocked page's redirect targets are chosen by the server, and were either part of the
/// security text that was blocked or never scanned at all. None of them is recorded or
/// returned (invariant 4): `finalUrl` is dropped when it differs from the requested URL, and the
/// redirect chain is dropped. The requested URL came from the caller and is kept.
fn withhold_server_chosen_urls(blocked: &mut BlockedDocument, store_ctx: &mut StoreContext) {
    if blocked.final_url.as_ref() != Some(&blocked.requested_url) {
        blocked.final_url = None;
    }
    store_ctx.redirect_chain.clear();
}

/// Intermediate redirect hops are server-chosen URLs the scanner never reads; only the final
/// hop (the final URL, a whole line of the scanned `security_text`) is kept, so nothing
/// unscanned reaches `metadata/*.json` `redirectChain` (ADR-018). Whether the page was
/// redirected stays visible: the chain is `[finalUrl]` rather than empty.
fn keep_scanned_hops(response: &mut FetchedResponse) {
    let final_url = response.final_url.clone();
    response.redirect_chain.retain(|hop| *hop == final_url);
    response.redirect_chain.dedup();
}

/// A `429`/`503` with `Retry-After` whose failure was not recorded yet
/// ([`PageProcessor::process_link_or_defer`]). Carries no response content: only the page's
/// URL (the link it was fetched under), its depth, the error code and the delay.
#[derive(Debug, Clone)]
pub struct RetryLater {
    url: Url,
    depth: u32,
    code: ErrorCode,
    delay: Duration,
}

impl RetryLater {
    /// The server's `Retry-After` delay (clamped by the fetcher).
    pub fn delay(&self) -> Duration {
        self.delay
    }

    /// Record the page as failed (retryable) in `run` — when no retry fits the budgets.
    pub async fn record(&self, run: &RunWriter) -> PageOutcome {
        record_failure(run, &self.url, self.depth, self.code, true).await
    }
}

async fn record_failure(
    run: &RunWriter,
    url: &Url,
    depth: u32,
    code: ErrorCode,
    retryable: bool,
) -> PageOutcome {
    if let Err(err) = run.record_failed(url, depth, code, retryable).await {
        return store_failure(&err);
    }
    PageOutcome::Failed { code, retryable }
}

fn store_failure(err: &StoreError) -> PageOutcome {
    tracing::error!(error = %err, "corpus store failed");
    PageOutcome::Failed {
        code: ErrorCode::Internal,
        retryable: false,
    }
}

/// Response facts recorded for a blocked document.
fn response_context(response: &FetchedResponse, depth: u32) -> StoreContext {
    StoreContext {
        depth,
        http_status: Some(response.status),
        content_type: Some(response.content_type.essence().to_owned()),
        retrieved_at: Some(response.retrieved_at),
        redirect_chain: response.redirect_chain.clone(),
        ..StoreContext::default()
    }
}

/// `FetchedResponse` + extraction → the untrusted document the scanner reads.
fn untrusted(
    response: FetchedResponse,
    extracted: ExtractedDocument,
    retain_raw: bool,
) -> UntrustedDocument {
    UntrustedDocument {
        requested_url: response.requested_url,
        final_url: response.final_url,
        redirect_chain: response.redirect_chain,
        http_status: response.status,
        content_type: ModelContentType {
            essence: response.content_type.essence().to_owned(),
            charset: response.charset,
        },
        retrieved_at: response.retrieved_at,
        security_text: extracted.security_text,
        display: extracted.display,
        links: extracted.links,
        raw_bytes: retain_raw.then_some(response.body),
    }
}

//! The bounded BFS crawler (SW-010, deep-dive §13, §43–45, §82): one `crawl_<id>` run.
//!
//! The crawler contains no fetch, extraction, scan or policy code: every URL goes through
//! [`PageProcessor::process_link`] (invariant 1, ADR-009), and links are only ever taken from
//! [`PageOutcome::Stored`] — a blocked or failed page contributes none, by type (invariant 6).
//!
//! Budgets (invariant 5), all hard:
//!
//! - **depth**: the root is depth 0; a link found at depth `d` is queued only if
//!   `d + 1 <= maxDepth`.
//! - **pages**: `maxPages` counts fetch attempts (stored, blocked and failed); no attempt starts
//!   once it is reached.
//! - **bytes**: every attempt reserves `min(maxPageBytes, maxTotalBytes - fetched - reserved)`
//!   bytes and is capped at that reservation, so the bytes fetched never exceed
//!   `maxTotalBytes`; a page that does not fit its reservation is recorded as failed
//!   `CRAWL_LIMIT_REACHED` and the crawl stops scheduling.
//! - **duration**: at `maxDuration` in-flight pages are aborted and the run ends
//!   `LIMIT_REACHED`.
//! - **frontier**: at most `maxFrontier` queued links ([`Frontier`]); at most `concurrency`
//!   pages in flight (a bounded `JoinSet`, never one task per discovered URL). Per-host
//!   concurrency and politeness are enforced by the fetcher (`fetch.perHostConcurrency`).
//!
//! `Retry-After`: a `429`/`503` carrying it is retried once after the delay when the retry fits
//! the page, byte and duration budgets (it is an attempt); otherwise it is recorded failed.
//!
//! Cancellation (`CancellationToken`): stop scheduling, abort in-flight pages, finish the run
//! `CANCELLED`. The manifest is checkpointed by the store every 25 recorded entries and written
//! in full when the run finishes, so a cancelled or limited crawl leaves a valid partial
//! manifest.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use secure_web_core::config::{Config, CrawlScope, MAX_CRAWL_DEPTH, MAX_CRAWL_PAGES};
use secure_web_core::error::ErrorCode;
use secure_web_core::ids::{CrawlId, IdError, RunId};
use secure_web_core::model::DiscoveredLink;
use secure_web_store::{
    Manifest, ManifestPolicy, RunSpec, RunStats, RunStatus, StoreError, Versions,
};
use tokio::task::{self, JoinSet};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::canonical::canonicalize;
use crate::frontier::{Frontier, Push};
use crate::processor::{CrawlBudget, PageContext, PageOutcome, PageProcessor, RetryLater};
use crate::scope::{Scope, ScopeError};

/// Most pages in flight per crawl, whatever `crawl.concurrency` says.
pub const MAX_CRAWL_CONCURRENCY: u32 = 32;

/// Log a progress line (counts only) every this many finished pages.
const PROGRESS_EVERY: u64 = 10;

/// Budgets and scope of one crawl. Built from the config and narrowed by the caller
/// ([`CrawlOptions::from_config`]); [`Crawler::crawl`] clamps depth, pages and concurrency to
/// their hard maxima again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlOptions {
    /// Deepest link depth fetched (root = 0), at most [`MAX_CRAWL_DEPTH`].
    pub max_depth: u32,
    /// Most fetch attempts, at most [`MAX_CRAWL_PAGES`].
    pub max_pages: u32,
    /// Most decompressed body bytes fetched over the whole crawl.
    pub max_total_bytes: u64,
    /// Wall-clock limit.
    pub max_duration: Duration,
    /// Pages in flight, at most [`MAX_CRAWL_CONCURRENCY`].
    pub concurrency: u32,
    /// Most queued links.
    pub max_frontier: u32,
    /// Scope kind.
    pub scope: CrawlScope,
    /// Hosts for `ALLOWLIST`.
    pub allowed_hosts: Vec<String>,
    /// Path regexes a followed link must match (any).
    pub include_patterns: Vec<String>,
    /// Path regexes a followed link must not match.
    pub exclude_patterns: Vec<String>,
    /// Query parameters removed by canonicalization.
    pub strip_query_params: Vec<String>,
}

impl CrawlOptions {
    /// The `crawl:` section of `config`.
    pub fn from_config(config: &Config) -> Self {
        let crawl = &config.crawl;
        Self {
            max_depth: crawl.max_depth,
            max_pages: crawl.max_pages,
            max_total_bytes: crawl.max_total_bytes,
            max_duration: crawl.max_duration,
            concurrency: crawl.concurrency,
            max_frontier: crawl.max_frontier,
            scope: crawl.scope,
            allowed_hosts: crawl.allowed_hosts.clone(),
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            strip_query_params: crawl.strip_query_params.clone(),
        }
    }

    fn clamped(mut self) -> Self {
        self.max_depth = self.max_depth.min(MAX_CRAWL_DEPTH);
        self.max_pages = self.max_pages.clamp(1, MAX_CRAWL_PAGES);
        self.concurrency = self.concurrency.clamp(1, MAX_CRAWL_CONCURRENCY);
        self
    }
}

/// The crawl could not be started or finished (never a statement about a page).
#[derive(Debug, thiserror::Error)]
pub enum CrawlError {
    /// The root is not an absolute URL (no run was created).
    #[error("the URL is not an absolute URL")]
    InvalidUrl,
    /// The scope arguments are invalid (no run was created).
    #[error(transparent)]
    Scope(#[from] ScopeError),
    /// No run id could be generated.
    #[error("run id: {0}")]
    Id(#[from] IdError),
    /// The run directory or manifest could not be written.
    #[error("corpus store: {0}")]
    Store(#[from] StoreError),
}

/// A finished `crawl_<id>` run.
#[derive(Debug, Clone)]
pub struct CrawlReport {
    /// The run id (`crawl_<12 hex>`).
    pub run_id: RunId,
    /// Canonical `<workspace>/runs/<runId>`.
    pub run_dir: PathBuf,
    /// Canonical `<workspace>/runs/<runId>/manifest.json`.
    pub manifest_path: PathBuf,
    /// The manifest as written when the run finished.
    pub manifest: Manifest,
    /// Versions every page was decided under.
    pub versions: Versions,
    /// Wall-clock duration.
    pub duration: Duration,
    /// The root's failure, when the run is `FAILED`.
    pub root_failure: Option<(ErrorCode, bool)>,
    /// Links dropped because the frontier was full.
    pub frontier_dropped: u64,
    /// Largest frontier length reached.
    pub frontier_peak: usize,
}

/// Runs crawls over one shared [`PageProcessor`].
#[derive(Debug, Clone)]
pub struct Crawler {
    processor: Arc<PageProcessor>,
}

/// What one page task returns.
struct Finished {
    depth: u32,
    reserved: u64,
    /// The link, kept for a `Retry-After` retry.
    link: DiscoveredLink,
    /// `Err` only for a first attempt deferred by `Retry-After` (not recorded yet).
    result: Result<PageOutcome, RetryLater>,
}

/// Spawn one page attempt into the bounded `JoinSet`. A first attempt (`retry_after: None`)
/// defers a `Retry-After` failure to the crawler; a retry waits out the delay first and records
/// whatever happens. Returns the task's id.
fn spawn_page(
    tasks: &mut JoinSet<Finished>,
    processor: &Arc<PageProcessor>,
    ctx: PageContext,
    link: DiscoveredLink,
    reserved: u64,
    retry_after: Option<Duration>,
) -> task::Id {
    let processor = Arc::clone(processor);
    let depth = ctx.depth;
    tasks
        .spawn(async move {
            if let Some(delay) = retry_after {
                tokio::time::sleep(delay).await;
            }
            let result = processor
                .process_link_or_defer(&link, ctx, retry_after.is_none())
                .await;
            Finished {
                depth,
                reserved,
                link,
                result,
            }
        })
        .id()
}

impl Crawler {
    /// A crawler over `processor`.
    pub fn new(processor: Arc<PageProcessor>) -> Self {
        Self { processor }
    }

    /// Crawl from `root` (the URL as the caller wrote it: the guard's raw-text rules apply to
    /// it) within `options`, until the frontier is empty, a budget is reached or `cancel` fires.
    pub async fn crawl(
        &self,
        root: &str,
        options: CrawlOptions,
        cancel: CancellationToken,
    ) -> Result<CrawlReport, CrawlError> {
        let options = options.clamped();
        let root_url = Url::parse(root).map_err(|_| CrawlError::InvalidUrl)?;
        let scope = Scope::new(
            &root_url,
            options.scope,
            &options.allowed_hosts,
            &options.include_patterns,
            &options.exclude_patterns,
        )?;
        let crawl_id = CrawlId::generate()?;
        let run_id = RunId::parse(crawl_id.as_str())?;
        let processor = &self.processor;
        let config = processor.config();
        let max_page_bytes = config.fetch.max_page_bytes.max(config.fetch.max_json_bytes);
        let writer = processor
            .store()
            .begin_run(RunSpec {
                run_id: run_id.clone(),
                root_url: root_url.clone(),
                started_at: Utc::now(),
                versions: processor.versions().clone(),
                policy: ManifestPolicy {
                    max_depth: options.max_depth,
                    max_pages: options.max_pages,
                    max_total_bytes: options.max_total_bytes,
                    max_page_bytes: config.fetch.max_page_bytes,
                    max_duration_ms: u64::try_from(options.max_duration.as_millis())
                        .unwrap_or(u64::MAX),
                    scope: options.scope,
                    allowed_hosts: options.allowed_hosts.clone(),
                },
            })
            .await?;
        let run_dir = writer.run_dir().to_path_buf();
        let manifest_path = run_dir.join("manifest.json");
        let run = Arc::new(writer);
        let budget = Arc::new(CrawlBudget::new());
        tracing::info!(run_id = %run_id, "crawl started");

        let started = Instant::now();
        let deadline = started + options.max_duration;
        let max_frontier = usize::try_from(options.max_frontier).unwrap_or(usize::MAX);
        let concurrency = usize::try_from(options.concurrency).unwrap_or(1);
        let mut frontier = Frontier::new(max_frontier.max(1));
        let root_link = DiscoveredLink {
            url: root_url.clone(),
            as_written: root.to_owned(),
        };
        let root_key = canonicalize(&root_url, &options.strip_query_params);
        frontier.push(root_link, root_key, 0);
        let mut discovered: u64 = 1;

        let mut tasks: JoinSet<Finished> = JoinSet::new();
        let mut attempts: u32 = 0;
        let mut reserved: u64 = 0;
        let mut limit_reached = false;
        let mut interrupted: Option<RunStatus> = None;
        let mut root_failure = None;
        // Retry tasks by id, with the first attempt's failure: recorded if the retry never
        // finishes (a cancel or the deadline aborts it), so the completed attempt is not lost.
        let mut awaiting_retry: HashMap<task::Id, RetryLater> = HashMap::new();
        let mut progress = Progress::default();

        loop {
            // Schedule while there is room, work and budget.
            while !limit_reached && tasks.len() < concurrency && !frontier.is_empty() {
                // Cancellation and the deadline are checked before every fetch, not only while
                // waiting: an already-cancelled or already-expired crawl starts no work.
                if cancel.is_cancelled() {
                    interrupted = Some(RunStatus::Cancelled);
                    break;
                }
                if Instant::now() >= deadline {
                    interrupted = Some(RunStatus::LimitReached);
                    break;
                }
                if attempts >= options.max_pages {
                    limit_reached = true;
                    break;
                }
                let used = budget.total_bytes().saturating_add(reserved);
                let remaining = options.max_total_bytes.saturating_sub(used);
                if remaining == 0 {
                    // In-flight pages may release part of their reservation; with none in
                    // flight the byte budget is spent.
                    limit_reached = tasks.is_empty();
                    break;
                }
                let Some(entry) = frontier.pop() else {
                    break;
                };
                let allowance = remaining.min(max_page_bytes);
                attempts += 1;
                reserved += allowance;
                let ctx = PageContext {
                    run: Arc::clone(&run),
                    depth: entry.depth,
                    budget: Arc::clone(&budget),
                    max_fetch_bytes: Some(allowance),
                };
                spawn_page(&mut tasks, processor, ctx, entry.link, allowance, None);
            }
            if interrupted.is_some() || tasks.is_empty() {
                break;
            }
            let joined = tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    interrupted = Some(RunStatus::Cancelled);
                    break;
                }
                () = tokio::time::sleep_until(deadline) => {
                    interrupted = Some(RunStatus::LimitReached);
                    break;
                }
                joined = tasks.join_next_with_id() => joined,
            };
            let Some(joined) = joined else {
                continue;
            };
            let finished = match joined {
                Ok((id, finished)) => {
                    awaiting_retry.remove(&id);
                    finished
                }
                Err(err) => {
                    // A panicked page task: its reservation stays held (conservative).
                    tracing::error!(error = %err, "crawl page task failed");
                    if let Some(later) = awaiting_retry.remove(&err.id()) {
                        later.record(&run).await;
                    }
                    continue;
                }
            };
            reserved = reserved.saturating_sub(finished.reserved);
            let outcome = match finished.result {
                Ok(outcome) => outcome,
                Err(later) => {
                    // `Retry-After` (a 429/503, not recorded yet): one retry after the delay,
                    // only if it fits every budget — it is a fetch attempt like any other, and
                    // it must start before the deadline. Otherwise the page is recorded failed.
                    let used = budget.total_bytes().saturating_add(reserved);
                    let remaining = options.max_total_bytes.saturating_sub(used);
                    let fits = !limit_reached
                        && !cancel.is_cancelled()
                        && attempts < options.max_pages
                        && remaining > 0
                        && Instant::now()
                            .checked_add(later.delay())
                            .is_some_and(|start| start < deadline);
                    if fits {
                        let allowance = remaining.min(max_page_bytes);
                        attempts += 1;
                        reserved += allowance;
                        let ctx = PageContext {
                            run: Arc::clone(&run),
                            depth: finished.depth,
                            budget: Arc::clone(&budget),
                            max_fetch_bytes: Some(allowance),
                        };
                        let delay = later.delay();
                        let id = spawn_page(
                            &mut tasks,
                            processor,
                            ctx,
                            finished.link,
                            allowance,
                            Some(delay),
                        );
                        awaiting_retry.insert(id, later);
                        continue;
                    }
                    later.record(&run).await
                }
            };
            progress.record(&outcome);
            if progress.done % PROGRESS_EVERY == 0 {
                progress.log(&run_id);
            }
            match outcome {
                PageOutcome::Stored { links, .. } => {
                    if finished.depth < options.max_depth {
                        for link in links {
                            if !scope.allows(&link.url) {
                                continue;
                            }
                            let key = canonicalize(&link.url, &options.strip_query_params);
                            match frontier.push(link, key, finished.depth + 1) {
                                Push::Admitted | Push::Full => discovered += 1,
                                Push::Seen => {}
                            }
                        }
                    }
                }
                // No links, by type (invariant 6).
                PageOutcome::Blocked(_) => {}
                PageOutcome::Failed { code, retryable } => {
                    if code == ErrorCode::CrawlLimitReached {
                        limit_reached = true;
                    }
                    // Only the root has depth 0; a failed root means nothing was fetched.
                    if finished.depth == 0 {
                        root_failure = Some((code, retryable));
                    }
                }
            }
        }

        // Cancelled or out of time: abort what is in flight and wait for it to go. A first
        // attempt deferred by `Retry-After` is recorded failed once (ADR-019) if its retry was
        // aborted, or if it finished but was never joined.
        tasks.abort_all();
        while let Some(joined) = tasks.join_next_with_id().await {
            match joined {
                Ok((id, finished)) => {
                    awaiting_retry.remove(&id);
                    if let Err(later) = finished.result {
                        later.record(&run).await;
                    }
                }
                Err(err) => {
                    if let Some(later) = awaiting_retry.remove(&err.id()) {
                        later.record(&run).await;
                    }
                }
            }
        }
        let status = match interrupted {
            Some(status) => status,
            None if limit_reached => RunStatus::LimitReached,
            None if root_failure.is_some() => RunStatus::Failed,
            None => RunStatus::Complete,
        };
        let stats = RunStats {
            discovered,
            total_bytes: budget.total_bytes(),
            ..RunStats::default()
        };
        // Every page task was dropped above; this is the last reference.
        let writer = Arc::try_unwrap(run).map_err(|_| StoreError::Task)?;
        let manifest = writer.finish(status, stats).await?;
        let duration = started.elapsed();
        tracing::info!(
            run_id = %run_id,
            status = ?manifest.status,
            fetched = manifest.stats.fetched,
            blocked = manifest.stats.blocked,
            failed = manifest.stats.failed,
            frontier_dropped = frontier.dropped(),
            "crawl finished"
        );
        Ok(CrawlReport {
            run_id,
            run_dir,
            manifest_path,
            root_failure: (status == RunStatus::Failed)
                .then_some(root_failure)
                .flatten(),
            manifest,
            versions: processor.versions().clone(),
            duration,
            frontier_dropped: frontier.dropped(),
            frontier_peak: frontier.peak(),
        })
    }
}

/// Running counts for the progress log (counts only, never URLs or text).
#[derive(Debug, Default)]
struct Progress {
    done: u64,
    stored: u64,
    blocked: u64,
    failed: u64,
}

impl Progress {
    fn record(&mut self, outcome: &PageOutcome) {
        self.done += 1;
        match outcome {
            PageOutcome::Stored { .. } => self.stored += 1,
            PageOutcome::Blocked(_) => self.blocked += 1,
            PageOutcome::Failed { .. } => self.failed += 1,
        }
    }

    fn log(&self, run_id: &RunId) {
        tracing::info!(
            run_id = %run_id,
            pages = self.done,
            stored = self.stored,
            blocked = self.blocked,
            failed = self.failed,
            "crawl progress"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SW-010 acceptance: the crawler imports nothing from fetch/extract/security; every page
    /// goes through `PageProcessor` (invariant 1).
    #[test]
    fn crawler_modules_import_no_pipeline_crates() {
        for (name, source) in [
            ("crawler.rs", include_str!("crawler.rs")),
            ("frontier.rs", include_str!("frontier.rs")),
            ("scope.rs", include_str!("scope.rs")),
            ("canonical.rs", include_str!("canonical.rs")),
        ] {
            for forbidden in [
                concat!("secure_web_", "fetch"),
                concat!("secure_web_", "extract"),
                concat!("secure_web_", "security"),
            ] {
                assert!(!source.contains(forbidden), "{name} names {forbidden}");
            }
        }
    }

    #[test]
    fn options_are_clamped_to_the_hard_maxima() {
        let options = CrawlOptions {
            max_depth: 99,
            max_pages: 1_000_000,
            concurrency: 0,
            ..CrawlOptions::from_config(&Config::default())
        }
        .clamped();
        assert_eq!(options.max_depth, MAX_CRAWL_DEPTH);
        assert_eq!(options.max_pages, MAX_CRAWL_PAGES);
        assert_eq!(options.concurrency, 1);
        let options = CrawlOptions {
            concurrency: 10_000,
            ..CrawlOptions::from_config(&Config::default())
        }
        .clamped();
        assert_eq!(options.concurrency, MAX_CRAWL_CONCURRENCY);
    }
}

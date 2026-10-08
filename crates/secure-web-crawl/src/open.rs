//! One `open_<id>` run around one [`PageProcessor::process`] call (`web_open`, `secure-web
//! open`).

use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use secure_web_core::ids::{IdError, RunId};
use secure_web_store::{ManifestPolicy, RunSpec, RunStats, RunStatus, StoreError, Versions};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::processor::{CrawlBudget, PageContext, PageOutcome, PageProcessor};

/// A finished `open_<id>` run.
#[derive(Debug, Clone)]
pub struct OpenedRun {
    /// The run id (`open_<12 hex>`).
    pub run_id: RunId,
    /// Canonical `<workspace>/runs/<runId>/manifest.json`.
    pub manifest_path: PathBuf,
    /// Versions the page was decided under.
    pub versions: Versions,
    /// What happened to the URL.
    pub outcome: PageOutcome,
}

/// The run could not be created or finished (never a statement about the page).
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// No run id could be generated.
    #[error("run id: {0}")]
    Id(#[from] IdError),
    /// The URL is not an absolute URL (no run was created).
    #[error("the URL is not an absolute URL")]
    InvalidUrl,
    /// The run directory or manifest could not be written.
    #[error("corpus store: {0}")]
    Store(#[from] StoreError),
    /// The call was cancelled; the run was finished `CANCELLED` (no page entry).
    #[error("the call was cancelled")]
    Cancelled {
        /// The cancelled run.
        run_id: RunId,
        /// Its manifest.
        manifest_path: PathBuf,
    },
}

impl PageProcessor {
    /// Open `url` in a new `open_<id>` run: create the run, process the page at depth 0 with a
    /// single-page budget, and finish the run (`COMPLETE`, or `FAILED` when nothing was
    /// decided). The manifest is terminal before this returns; a `RUNNING` manifest only
    /// remains if the process dies mid-call.
    ///
    /// `raw_url` is the URL exactly as the caller wrote it: the guard's raw-text rules
    /// (non-canonical IPv4 spelling, empty userinfo) are checked on it, not on the parse.
    pub async fn open(&self, raw_url: &str) -> Result<OpenedRun, OpenError> {
        self.open_cancellable(raw_url, &CancellationToken::new())
            .await
    }

    /// [`open`](PageProcessor::open) that stops when `cancel` fires: the page is abandoned
    /// wherever it is, and the run is finished `CANCELLED` with no entry
    /// ([`OpenError::Cancelled`]), so a cancelled call never leaves a `RUNNING` manifest.
    pub async fn open_cancellable(
        &self,
        raw_url: &str,
        cancel: &CancellationToken,
    ) -> Result<OpenedRun, OpenError> {
        let url = Url::parse(raw_url).map_err(|_| OpenError::InvalidUrl)?;
        let run_id = RunId::generate_open()?;
        let mut policy = ManifestPolicy::from_config(self.config());
        policy.max_depth = 0;
        policy.max_pages = 1;
        let writer = self
            .store()
            .begin_run(RunSpec {
                run_id: run_id.clone(),
                root_url: url.clone(),
                started_at: Utc::now(),
                versions: self.versions().clone(),
                policy,
            })
            .await?;
        let manifest_path = writer.run_dir().join("manifest.json");
        let run = Arc::new(writer);
        let budget = Arc::new(CrawlBudget::new());
        let ctx = PageContext {
            run: Arc::clone(&run),
            depth: 0,
            budget: Arc::clone(&budget),
            max_fetch_bytes: None,
        };
        let outcome = tokio::select! {
            biased;
            () = cancel.cancelled() => None,
            outcome = self.process_as_written(raw_url, url, ctx) => Some(outcome),
        };
        let status = match &outcome {
            Some(PageOutcome::Stored { .. } | PageOutcome::Blocked(_)) => RunStatus::Complete,
            Some(PageOutcome::Failed { .. }) => RunStatus::Failed,
            None => RunStatus::Cancelled,
        };
        let stats = RunStats {
            discovered: 1,
            fetched: budget.pages_fetched(),
            total_bytes: budget.total_bytes(),
            ..RunStats::default()
        };
        // `process` dropped its context; this is the last reference.
        let writer = Arc::try_unwrap(run).map_err(|_| StoreError::Task)?;
        writer.finish(status, stats).await?;
        let Some(outcome) = outcome else {
            return Err(OpenError::Cancelled {
                run_id,
                manifest_path,
            });
        };
        Ok(OpenedRun {
            run_id,
            manifest_path,
            versions: self.versions().clone(),
            outcome,
        })
    }
}

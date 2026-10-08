//! `FsCorpusStore`: writes one run's corpus under `<workspace>/runs/<runId>/`
//! (`docs/contracts/manifest-schema.md`, `docs/security-policy.md` §6–8, ADR-015).
//!
//! ```text
//! FsCorpusStore::begin_run(spec)      -> RunWriter      (creates runs/<runId>/, fails if it exists)
//! RunWriter::next_doc_id()            -> doc_NNNNNN     (fetch-completion order)
//! RunWriter::store(AcceptedDocument)  -> StoredDocument (page file + metadata)
//! RunWriter::record_blocked(..)       -> ()             (metadata + manifest entry, no content)
//! RunWriter::record_failed(..)        -> ()             (manifest entry only)
//! RunWriter::finish(status, stats)    -> Manifest
//! ```
//!
//! Only an [`AcceptedDocument`] produces a page file. Blocked and failed documents produce ids,
//! URLs and enums only (invariant 4). Every name the store creates is generated (`NNNNNN`, a
//! `[a-z0-9-]` slug, fixed directory names); page-derived strings never choose a path. Writes are
//! atomic (temp file + fsync + rename) and never follow a symbolic link. The manifest is
//! checkpointed when the run starts and after every 25 recorded entries, so a killed run always
//! leaves a valid manifest whose `path`s exist.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{DateTime, SecondsFormat, Utc};
use secure_web_core::config::{Config, WarnHandling};
use secure_web_core::error::ErrorCode;
use secure_web_core::ids::{DocumentId, RunId, MAX_DOCUMENT_SEQ};
use secure_web_core::model::{
    Block, BlockReason, BlockedDocument, Finding, SecurityDecision, Severity, StoredDocument,
    StructuredDocument,
};
use secure_web_extract::markdown::render;
use secure_web_extract::title::{normalize_title, slug};
pub use secure_web_security::decision::{AcceptedDocument, RawContent};
use serde::Serialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::error::StoreError;
use crate::fsx::{
    self, Dir, MODE_PRIVATE_DIR, MODE_PRIVATE_FILE, MODE_PUBLIC_DIR, MODE_PUBLIC_FILE,
};
use crate::manifest::{
    is_page_file_name, BlockedEntry, DocumentEntry, FailedEntry, Manifest, ManifestPolicy, RunKind,
    RunStats, RunStatus, Versions, MANIFEST_VERSION, PAGES_DIR, QUARANTINE_DIR,
};
use crate::workspace::{expand_home, home_dir};

/// The manifest is rewritten after this many recorded entries (`docs/contracts/manifest-schema.md`).
pub const CHECKPOINT_EVERY: u32 = 25;

const RUNS_DIR: &str = "runs";
const AUDIT_DIR: &str = "private-audit";
const METADATA_DIR: &str = "metadata";
const SECURITY_DIR: &str = "security";
const MANIFEST_FILE: &str = "manifest.json";
const SUMMARY_FILE: &str = "summary.json";
const FINDINGS_FILE: &str = "findings.json";

/// How to build an [`FsCorpusStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreOptions {
    /// Workspace root; a leading `~` is expanded. `runs/` and `private-audit/` live below it.
    pub workspace: PathBuf,
    /// Private-audit root; default `<workspace>/private-audit`. Must be a directory named
    /// `private-audit` that is neither equal to, inside, nor an ancestor of `runs/`.
    pub audit_root: Option<PathBuf>,
    /// `debug.retainRaw`: keep raw bodies and security text under the private-audit root.
    pub retain_raw: bool,
    /// `security.warnHandling`: `quarantine` keeps `WARN` pages out of `pages/`.
    pub warn_handling: WarnHandling,
}

impl StoreOptions {
    /// Options from the effective config (`server.workspace`, `debug.retainRaw`,
    /// `security.warnHandling`).
    pub fn from_config(config: &Config) -> Self {
        Self {
            workspace: config.server.workspace.clone(),
            audit_root: None,
            retain_raw: config.debug.retain_raw,
            warn_handling: config.security.warn_handling,
        }
    }
}

/// Everything a new run's manifest records up front.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSpec {
    /// Run id; also the run directory name. `open_…` runs hold exactly one entry.
    pub run_id: RunId,
    /// Crawl root or opened URL.
    pub root_url: Url,
    /// When the run started.
    pub started_at: DateTime<Utc>,
    /// Version stamps; every recorded document must carry the same scanner and policy version.
    pub versions: Versions,
    /// Budgets and scope.
    pub policy: ManifestPolicy,
}

/// Sizes the page processor measured for one document (`metadata/NNNNNN.json`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DocumentSizes {
    /// Decompressed response body bytes.
    pub raw_bytes: u64,
    /// Rendered display (Markdown) bytes.
    pub extracted_bytes: u64,
    /// `security_text` bytes.
    pub security_text_bytes: u64,
    /// Links found on the page.
    pub links_found: u64,
    /// Whether the link list was truncated at `extract.maxLinksPerPage`.
    pub links_truncated: bool,
}

/// Per-document facts the documents themselves do not carry.
///
/// For [`RunWriter::store`] the depth, status, content type, time and redirect chain come from
/// the document's `provenance`; the fields here are used for blocked documents only.
#[derive(Debug, Clone, Default)]
pub struct StoreContext {
    /// Crawl depth (blocked documents).
    pub depth: u32,
    /// Final HTTP status, if a response was received (blocked documents).
    pub http_status: Option<u16>,
    /// Content type essence, if a response was received (blocked documents). Dropped unless it
    /// is a plain `type/subtype` token.
    pub content_type: Option<String>,
    /// When the response was received (blocked documents).
    pub retrieved_at: Option<DateTime<Utc>>,
    /// Redirect hops, in order (blocked documents).
    pub redirect_chain: Vec<Url>,
    /// Measured sizes.
    pub sizes: DocumentSizes,
    /// The scanner findings behind the document's `findingIds`, for `security/findings.json`.
    /// Their ids must be exactly the document's finding ids.
    pub findings: Vec<Finding>,
    /// Scan wall time, if the scanner ran.
    pub scan_duration_ms: Option<u64>,
    /// Raw content for the private audit (ignored unless `retainRaw`). Sealed: only
    /// `secure_web_security::decision::scan_and_decide` builds one, from the document it scanned.
    pub raw: Option<RawContent>,
}

/// A boxed store future (the store is used behind `dyn`, like the fetcher and scanner).
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + Send + 'a>>;

/// Where a run's documents go (`docs/architecture.md`, "Internal traits"). One implementation
/// in v0.1 ([`RunWriter`]); the trait exists for test doubles.
pub trait CorpusStore: Send + Sync {
    /// Store an accepted document.
    fn store<'a>(
        &'a self,
        doc: AcceptedDocument,
        ctx: &'a StoreContext,
    ) -> StoreFuture<'a, StoredDocument>;

    /// Record a blocked document (ids, URLs and enums only).
    fn record_blocked<'a>(
        &'a self,
        blocked: &'a BlockedDocument,
        ctx: &'a StoreContext,
    ) -> StoreFuture<'a, ()>;
}

/// The filesystem corpus store.
#[derive(Debug, Clone)]
pub struct FsCorpusStore {
    /// `<workspace>/runs`, held open: runs are created relative to it (ADR-015).
    runs: Arc<Dir>,
    /// The private-audit root, held open.
    audit_root: Arc<Dir>,
    retain_raw: bool,
    warn_handling: WarnHandling,
}

impl FsCorpusStore {
    /// Open (creating as needed) the workspace, using the process's home directory for `~`.
    pub fn new(options: StoreOptions) -> Result<Self, StoreError> {
        Self::with_home(options, home_dir().as_deref())
    }

    /// [`FsCorpusStore::new`] with an explicit home directory for `~` expansion.
    pub fn with_home(options: StoreOptions, home: Option<&Path>) -> Result<Self, StoreError> {
        let workspace = expand_home(&options.workspace, home)?;
        if workspace.as_os_str().is_empty() {
            return Err(StoreError::Workspace("empty workspace path"));
        }
        std::fs::create_dir_all(&workspace)
            .map_err(|err| StoreError::io("create workspace", &err))?;
        let root = std::fs::canonicalize(&workspace)
            .map_err(|err| StoreError::io("canonicalize workspace", &err))?;
        let root = Dir::open(&root)?;
        let runs = root.create_dir(RUNS_DIR, MODE_PUBLIC_DIR, true)?;
        let audit_root = match options.audit_root {
            None => root.create_dir(AUDIT_DIR, MODE_PRIVATE_DIR, true)?,
            Some(path) => {
                let path = expand_home(&path, home)?;
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                std::os::unix::fs::DirBuilderExt::mode(&mut builder, MODE_PRIVATE_DIR);
                builder
                    .create(&path)
                    .map_err(|err| StoreError::io("create audit root", &err))?;
                fsx::ensure_real_dir(&path)?;
                let canonical = std::fs::canonicalize(&path)
                    .map_err(|err| StoreError::io("canonicalize audit root", &err))?;
                Dir::open(&canonical)?
            }
        };
        let (runs_path, audit_path) = (runs.path(), audit_root.path());
        // Both canonical: symlinked spellings of either side compare by their real location.
        // An audit root equal to, inside, or containing `runs/` would put retained payloads
        // where an agent can read them (or `runs/` inside the audit tree).
        if audit_path.starts_with(runs_path) || runs_path.starts_with(audit_path) {
            return Err(StoreError::AuditInsideRuns);
        }
        // Retained payloads always sit under a `private-audit/` component, whatever the root is
        // called in the configuration.
        if audit_path.file_name() != Some(AUDIT_DIR.as_ref()) {
            return Err(StoreError::Workspace(
                "private-audit root must be a directory named private-audit",
            ));
        }
        Ok(Self {
            runs: Arc::new(runs),
            audit_root: Arc::new(audit_root),
            retain_raw: options.retain_raw,
            warn_handling: options.warn_handling,
        })
    }

    /// Canonical `<workspace>/runs`.
    pub fn runs_dir(&self) -> &Path {
        self.runs.path()
    }

    /// Canonical private-audit root.
    pub fn audit_root(&self) -> &Path {
        self.audit_root.path()
    }

    /// Start a run: create `runs/<runId>/` (refusing an existing entry of any kind) and its
    /// subdirectories, and write the initial `RUNNING` manifest.
    pub async fn begin_run(&self, spec: RunSpec) -> Result<RunWriter, StoreError> {
        let store = self.clone();
        blocking(move || store.begin_run_sync(spec)).await
    }

    fn begin_run_sync(&self, spec: RunSpec) -> Result<RunWriter, StoreError> {
        let run_name = spec.run_id.as_str().to_owned();
        let run_dir = self.runs.create_dir(&run_name, MODE_PUBLIC_DIR, false)?;
        let sub = |name: &str| run_dir.create_dir(name, MODE_PUBLIC_DIR, false);
        let pages = sub(PAGES_DIR)?;
        let metadata = sub(METADATA_DIR)?;
        let security = sub(SECURITY_DIR)?;
        let quarantine = match self.warn_handling {
            WarnHandling::Quarantine => Some(sub(QUARANTINE_DIR)?),
            WarnHandling::Store => None,
        };
        // The new entries (the run directory in `runs/`, its subdirectories) are durable before
        // the first manifest names the run.
        run_dir.sync()?;
        self.runs.sync()?;
        let audit_dir = if self.retain_raw {
            Some(
                self.audit_root
                    .create_dir(&run_name, MODE_PRIVATE_DIR, false)?,
            )
        } else {
            None
        };

        let kind = RunKind::of(&spec.run_id);
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            run_id: spec.run_id.clone(),
            kind,
            root_url: spec.root_url,
            status: RunStatus::Running,
            started_at: spec.started_at,
            finished_at: None,
            versions: spec.versions,
            policy: spec.policy,
            stats: RunStats::default(),
            documents: Vec::new(),
            blocked: Vec::new(),
            failed: Vec::new(),
        };
        let inner = RunInner {
            run_id: spec.run_id,
            kind,
            run_dir,
            pages,
            metadata,
            security,
            quarantine,
            audit_dir,
            next_seq: AtomicU32::new(0),
            issued: Mutex::new(HashSet::new()),
            state: Mutex::new(RunState {
                manifest,
                findings: Vec::new(),
                index: HashMap::new(),
                since_checkpoint: 0,
                quarantined: 0,
                duplicates: 0,
                total_bytes: 0,
                finished: false,
            }),
        };
        {
            let state = inner.lock_state()?;
            inner.write_run_files(&state)?;
        }
        Ok(RunWriter {
            inner: Arc::new(inner),
        })
    }
}

/// Where an accepted page file goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Area {
    Pages,
    Quarantine,
}

/// One row of `security/findings.json`: ids, severity and detector only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingRecord {
    document_id: DocumentId,
    finding_id: String,
    severity: Severity,
    detector: String,
}

/// `security/summary.json`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Summary<'a> {
    version: u32,
    run_id: &'a RunId,
    status: RunStatus,
    versions: &'a Versions,
    counts: SummaryCounts,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SummaryCounts {
    safe: u64,
    warned: u64,
    quarantined: u64,
    blocked: u64,
    failed: u64,
    duplicates: u64,
    findings: u64,
}

/// `metadata/NNNNNN.json` (provenance). Blocked documents have no title and no hash.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MetadataFile<'a> {
    id: &'a DocumentId,
    seq: u32,
    requested_url: &'a Url,
    final_url: Option<&'a Url>,
    redirect_chain: &'a [Url],
    http_status: Option<u16>,
    content_type: Option<&'a str>,
    retrieved_at: Option<DateTime<Utc>>,
    raw_bytes: u64,
    extracted_bytes: u64,
    security_text_bytes: u64,
    links_found: u64,
    links_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<&'a str>,
    depth: u32,
    security: MetadataSecurity<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duplicate_of: Option<&'a DocumentId>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    quarantined: bool,
    secure_web_version: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MetadataSecurity<'a> {
    decision: SecurityDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<BlockReason>,
    max_severity: Option<Severity>,
    finding_ids: &'a [String],
    scanner_version: Option<&'a str>,
    policy_version: &'a str,
    scan_duration_ms: Option<u64>,
}

struct RunState {
    manifest: Manifest,
    findings: Vec<FindingRecord>,
    /// `(area, contentHash)` → first document with that content and its relative path.
    index: HashMap<(Area, String), (DocumentId, String)>,
    since_checkpoint: u32,
    quarantined: u64,
    duplicates: u64,
    total_bytes: u64,
    finished: bool,
}

impl RunState {
    fn entries(&self) -> usize {
        self.manifest.documents.len() + self.manifest.blocked.len() + self.manifest.failed.len()
    }

    /// Stats computed from the recorded entries; `caller` can only raise `discovered`,
    /// `fetched` and `totalBytes` (the store cannot see the frontier).
    fn stats(&self, caller: Option<RunStats>) -> RunStats {
        let docs = &self.manifest.documents;
        let count = |decision| docs.iter().filter(|d| d.decision == decision).count() as u64;
        let blocked = self.manifest.blocked.len() as u64;
        let failed = self.manifest.failed.len() as u64;
        let fetched = docs.len() as u64 + blocked;
        let caller = caller.unwrap_or_default();
        RunStats {
            discovered: caller.discovered.max(fetched + failed),
            fetched: caller.fetched.max(fetched),
            safe: count(SecurityDecision::Safe),
            warned: count(SecurityDecision::Warn),
            blocked,
            failed,
            total_bytes: caller.total_bytes.max(self.total_bytes),
        }
    }
}

struct RunInner {
    run_id: RunId,
    kind: RunKind,
    /// The run directory and its subdirectories, held open: every write is relative to one of
    /// them, so no pathname is resolved again after `begin_run` (ADR-015).
    run_dir: Dir,
    pages: Dir,
    metadata: Dir,
    security: Dir,
    quarantine: Option<Dir>,
    /// `<audit root>/<runId>` when `retainRaw`.
    audit_dir: Option<Dir>,
    /// Last issued sequence number.
    next_seq: AtomicU32,
    /// Issued ids not yet recorded.
    issued: Mutex<HashSet<u32>>,
    state: Mutex<RunState>,
}

/// Writes one run. Cheap to share by reference; all writes are serialized internally and run
/// on the blocking pool.
///
/// Dropping a writer without [`RunWriter::finish`] leaves the last checkpoint: a valid
/// `RUNNING` manifest whose paths exist (entries recorded after it are not listed).
pub struct RunWriter {
    inner: Arc<RunInner>,
}

impl fmt::Debug for RunWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunWriter")
            .field("run_id", &self.inner.run_id)
            .finish()
    }
}

async fn blocking<T, F>(task: F) -> Result<T, StoreError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, StoreError> + Send + 'static,
{
    // The blocking pool thread gets the caller's subscriber and span, so audit events land
    // where the caller's logs go.
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&dispatch, || span.in_scope(task))
    })
    .await
    .map_err(|_| StoreError::Task)?
}

impl RunWriter {
    /// The run id.
    pub fn run_id(&self) -> &RunId {
        &self.inner.run_id
    }

    /// Canonical run directory.
    pub fn run_dir(&self) -> &Path {
        self.inner.run_dir.path()
    }

    /// Issue the next document id (fetch-completion order). Only issued ids can be recorded,
    /// each exactly once.
    pub fn next_doc_id(&self) -> Result<DocumentId, StoreError> {
        // A compare-exchange loop rather than `fetch_update` (deprecated on current stable) or
        // `try_update` (not yet stable on older toolchains), so it builds on both.
        let next_seq = &self.inner.next_seq;
        let mut last = next_seq.load(Ordering::SeqCst);
        let seq = loop {
            if last >= MAX_DOCUMENT_SEQ {
                return Err(StoreError::SequenceExhausted);
            }
            match next_seq.compare_exchange_weak(last, last + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break last + 1,
                Err(actual) => last = actual,
            }
        };
        let id = DocumentId::from_seq(seq).map_err(|_| StoreError::SequenceExhausted)?;
        self.inner
            .issued
            .lock()
            .map_err(|_| StoreError::Task)?
            .insert(seq);
        Ok(id)
    }

    /// Store an accepted document: page file (or a reference to an identical earlier one),
    /// metadata and manifest entry.
    pub async fn store(
        &self,
        doc: AcceptedDocument,
        ctx: &StoreContext,
    ) -> Result<StoredDocument, StoreError> {
        let inner = Arc::clone(&self.inner);
        let ctx = ctx.clone();
        blocking(move || inner.store_sync(doc, &ctx)).await
    }

    /// Record a blocked document: metadata (no title, no hash) and a manifest entry.
    pub async fn record_blocked(
        &self,
        blocked: &BlockedDocument,
        ctx: &StoreContext,
    ) -> Result<(), StoreError> {
        let inner = Arc::clone(&self.inner);
        let blocked = blocked.clone();
        let ctx = ctx.clone();
        blocking(move || inner.record_blocked_sync(&blocked, &ctx)).await
    }

    /// Record a URL that failed before a document existed.
    pub async fn record_failed(
        &self,
        url: &Url,
        depth: u32,
        code: ErrorCode,
        retryable: bool,
    ) -> Result<(), StoreError> {
        let inner = Arc::clone(&self.inner);
        let entry = FailedEntry {
            url: url.clone(),
            depth,
            code,
            retryable,
        };
        blocking(move || inner.record_failed_sync(entry)).await
    }

    /// Rewrite the manifest (`RUNNING`), summary and findings now.
    pub async fn checkpoint(&self) -> Result<(), StoreError> {
        let inner = Arc::clone(&self.inner);
        blocking(move || {
            let mut state = inner.lock_state()?;
            inner.ensure_open(&state)?;
            inner.checkpoint_locked(&mut state)
        })
        .await
    }

    /// Finish the run with a terminal `status`. Counts in `stats` are recomputed from the
    /// recorded entries (the manifest must agree with its own arrays); `discovered`, `fetched`
    /// and `totalBytes` are taken from `stats` when larger than what the store saw.
    pub async fn finish(self, status: RunStatus, stats: RunStats) -> Result<Manifest, StoreError> {
        if !status.is_terminal() {
            return Err(StoreError::InvalidStatus);
        }
        let inner = Arc::clone(&self.inner);
        blocking(move || {
            let mut state = inner.lock_state()?;
            inner.ensure_open(&state)?;
            state.manifest.status = status;
            // Never before `startedAt` (a clock step back would make the manifest invalid).
            state.manifest.finished_at = Some(Utc::now().max(state.manifest.started_at));
            state.manifest.stats = state.stats(Some(stats));
            inner.write_run_files(&state)?;
            state.finished = true;
            Ok(state.manifest.clone())
        })
        .await
    }
}

impl CorpusStore for RunWriter {
    fn store<'a>(
        &'a self,
        doc: AcceptedDocument,
        ctx: &'a StoreContext,
    ) -> StoreFuture<'a, StoredDocument> {
        Box::pin(RunWriter::store(self, doc, ctx))
    }

    fn record_blocked<'a>(
        &'a self,
        blocked: &'a BlockedDocument,
        ctx: &'a StoreContext,
    ) -> StoreFuture<'a, ()> {
        Box::pin(RunWriter::record_blocked(self, blocked, ctx))
    }
}

impl RunInner {
    fn lock_state(&self) -> Result<MutexGuard<'_, RunState>, StoreError> {
        self.state.lock().map_err(|_| StoreError::Task)
    }

    fn ensure_open(&self, state: &RunState) -> Result<(), StoreError> {
        if state.finished {
            return Err(StoreError::Finished);
        }
        Ok(())
    }

    /// Checks shared by every record call, before anything is written.
    fn ensure_room(&self, state: &RunState) -> Result<(), StoreError> {
        self.ensure_open(state)?;
        if self.kind == RunKind::Open && state.entries() >= 1 {
            return Err(StoreError::OpenRunFull);
        }
        Ok(())
    }

    /// Consume an issued, unrecorded id.
    fn claim(&self, id: &DocumentId) -> Result<(), StoreError> {
        let mut issued = self.issued.lock().map_err(|_| StoreError::Task)?;
        if issued.remove(&id.seq()) {
            Ok(())
        } else {
            Err(StoreError::UnknownDocumentId(id.clone()))
        }
    }

    fn store_sync(
        &self,
        doc: AcceptedDocument,
        ctx: &StoreContext,
    ) -> Result<StoredDocument, StoreError> {
        let mut state = self.lock_state()?;
        self.ensure_room(&state)?;
        let versions = state.manifest.versions.clone();
        validate_accepted(&doc, ctx, &versions)?;
        self.claim(doc.doc_id())?;

        let seq = doc.doc_id().seq();
        let area = match (doc.security().decision, &self.quarantine) {
            (SecurityDecision::Warn, Some(_)) => Area::Quarantine,
            _ => Area::Pages,
        };
        let body = page_body(doc.title(), doc.markdown());
        let content_hash = format!("sha256:{}", hex::encode(Sha256::digest(body.as_bytes())));
        let content_bytes = body.len() as u64;

        let (path, duplicate_of) = match state.index.get(&(area, content_hash.clone())) {
            Some((first, path)) => (path.clone(), Some(first.clone())),
            None => {
                let name = page_file_name(seq, doc.title(), doc.final_url())?;
                let (dir, dir_name) = match (area, &self.quarantine) {
                    (Area::Quarantine, Some(dir)) => (dir, QUARANTINE_DIR),
                    _ => (&self.pages, PAGES_DIR),
                };
                let file = format!("{}{body}", frontmatter(&doc));
                dir.write_atomic(&name, file.as_bytes(), MODE_PUBLIC_FILE)?;
                let path = format!("{dir_name}/{name}");
                state.index.insert(
                    (area, content_hash.clone()),
                    (doc.doc_id().clone(), path.clone()),
                );
                (path, None)
            }
        };

        let provenance = &doc.provenance();
        let metadata = MetadataFile {
            id: doc.doc_id(),
            seq,
            requested_url: doc.requested_url(),
            final_url: Some(doc.final_url()),
            redirect_chain: &provenance.redirect_chain,
            http_status: Some(provenance.http_status),
            content_type: Some(&provenance.content_type),
            retrieved_at: Some(provenance.retrieved_at),
            raw_bytes: ctx.sizes.raw_bytes,
            extracted_bytes: ctx.sizes.extracted_bytes,
            security_text_bytes: ctx.sizes.security_text_bytes,
            links_found: ctx.sizes.links_found,
            links_truncated: ctx.sizes.links_truncated,
            title: doc.title(),
            depth: provenance.depth,
            security: MetadataSecurity {
                decision: doc.security().decision,
                reason: None,
                max_severity: doc.security().max_severity,
                finding_ids: &doc.security().finding_ids,
                scanner_version: Some(&doc.security().scanner_version),
                policy_version: &doc.security().policy_version,
                scan_duration_ms: ctx.scan_duration_ms,
            },
            content_hash: Some(&content_hash),
            duplicate_of: duplicate_of.as_ref(),
            quarantined: area == Area::Quarantine,
            secure_web_version: &provenance.secure_web_version,
        };
        self.write_metadata(seq, &metadata)?;
        self.retain_raw(doc.doc_id(), ctx)?;

        audit_event(
            &self.run_id,
            doc.doc_id(),
            doc.requested_url(),
            doc.security().decision,
            None,
            doc.security().max_severity,
            &doc.security().finding_ids,
            Some(&doc.security().scanner_version),
        );

        push_findings(&mut state.findings, doc.doc_id(), &ctx.findings);
        if area == Area::Quarantine {
            state.quarantined += 1;
        }
        if duplicate_of.is_some() {
            state.duplicates += 1;
        }
        state.total_bytes = state.total_bytes.saturating_add(ctx.sizes.raw_bytes);
        state.manifest.documents.push(DocumentEntry {
            id: doc.doc_id().clone(),
            seq,
            url: doc.requested_url().clone(),
            final_url: doc.final_url().clone(),
            path: path.clone(),
            title: doc.title().map(str::to_owned),
            depth: provenance.depth,
            decision: doc.security().decision,
            max_severity: doc.security().max_severity,
            finding_ids: doc.security().finding_ids.clone(),
            content_hash,
            content_bytes,
            http_status: provenance.http_status,
            content_type: provenance.content_type.clone(),
            retrieved_at: provenance.retrieved_at,
            duplicate_of,
        });
        self.after_record(&mut state)?;

        Ok(StoredDocument {
            doc_id: doc.doc_id().clone(),
            content_path: self.run_dir.path().join(path),
            content_bytes,
            security: doc.security().clone(),
        })
    }

    fn record_blocked_sync(
        &self,
        blocked: &BlockedDocument,
        ctx: &StoreContext,
    ) -> Result<(), StoreError> {
        let mut state = self.lock_state()?;
        self.ensure_room(&state)?;
        let versions = state.manifest.versions.clone();
        validate_ids(&blocked.finding_ids, ctx)?;
        if let Some(scanner) = &blocked.scanner_version {
            if *scanner != versions.scanner {
                return Err(StoreError::InvalidDocument(
                    "scanner version differs from the run",
                ));
            }
        }
        self.claim(&blocked.doc_id)?;

        let seq = blocked.doc_id.seq();
        let content_type = ctx.content_type.as_deref().filter(|ct| is_mime_essence(ct));
        let metadata = MetadataFile {
            id: &blocked.doc_id,
            seq,
            requested_url: &blocked.requested_url,
            final_url: blocked.final_url.as_ref(),
            redirect_chain: &ctx.redirect_chain,
            http_status: ctx.http_status,
            content_type,
            retrieved_at: ctx.retrieved_at,
            raw_bytes: ctx.sizes.raw_bytes,
            extracted_bytes: ctx.sizes.extracted_bytes,
            security_text_bytes: ctx.sizes.security_text_bytes,
            links_found: ctx.sizes.links_found,
            links_truncated: ctx.sizes.links_truncated,
            title: None,
            depth: ctx.depth,
            security: MetadataSecurity {
                decision: SecurityDecision::Block,
                reason: Some(blocked.reason),
                max_severity: blocked.max_severity,
                finding_ids: &blocked.finding_ids,
                scanner_version: blocked.scanner_version.as_deref(),
                policy_version: &versions.policy,
                scan_duration_ms: ctx.scan_duration_ms,
            },
            content_hash: None,
            duplicate_of: None,
            quarantined: false,
            secure_web_version: &versions.secure_web,
        };
        self.write_metadata(seq, &metadata)?;
        self.retain_raw(&blocked.doc_id, ctx)?;

        audit_event(
            &self.run_id,
            &blocked.doc_id,
            &blocked.requested_url,
            SecurityDecision::Block,
            Some(blocked.reason),
            blocked.max_severity,
            &blocked.finding_ids,
            blocked.scanner_version.as_deref(),
        );

        push_findings(&mut state.findings, &blocked.doc_id, &ctx.findings);
        state.total_bytes = state.total_bytes.saturating_add(ctx.sizes.raw_bytes);
        state.manifest.blocked.push(BlockedEntry {
            id: blocked.doc_id.clone(),
            url: blocked.requested_url.clone(),
            final_url: blocked.final_url.clone(),
            depth: ctx.depth,
            reason: blocked.reason,
            max_severity: blocked.max_severity,
            finding_ids: blocked.finding_ids.clone(),
            http_status: ctx.http_status,
            content_type: content_type.map(str::to_owned),
            retrieved_at: ctx.retrieved_at,
        });
        self.after_record(&mut state)
    }

    fn record_failed_sync(&self, entry: FailedEntry) -> Result<(), StoreError> {
        let mut state = self.lock_state()?;
        self.ensure_room(&state)?;
        state.manifest.failed.push(entry);
        self.after_record(&mut state)
    }

    fn after_record(&self, state: &mut RunState) -> Result<(), StoreError> {
        state.since_checkpoint += 1;
        if state.since_checkpoint >= CHECKPOINT_EVERY {
            self.checkpoint_locked(state)?;
        }
        Ok(())
    }

    fn checkpoint_locked(&self, state: &mut RunState) -> Result<(), StoreError> {
        state.manifest.stats = state.stats(None);
        self.write_run_files(state)?;
        state.since_checkpoint = 0;
        Ok(())
    }

    fn write_metadata(&self, seq: u32, metadata: &MetadataFile<'_>) -> Result<(), StoreError> {
        let json = to_json(metadata)?;
        self.metadata
            .write_atomic(&format!("{seq:06}.json"), json.as_bytes(), MODE_PUBLIC_FILE)?;
        Ok(())
    }

    /// `security/findings.json`, `security/summary.json`, then `manifest.json` (last, so a
    /// manifest never describes more than the other files).
    ///
    /// Durability order: each file is fsynced before its rename (`write_atomic`); every
    /// directory the manifest can reference (`pages/`, `metadata/`, `quarantine/`, then
    /// `security/`) is fsynced after its renames and before the manifest rename; the run
    /// directory is fsynced after it. A crash can lose the newest checkpoint, never leave a
    /// durable manifest listing a page whose directory entry was lost.
    fn write_run_files(&self, state: &RunState) -> Result<(), StoreError> {
        self.pages.sync()?;
        self.metadata.sync()?;
        if let Some(quarantine) = &self.quarantine {
            quarantine.sync()?;
        }
        let manifest = &state.manifest;
        let findings = to_json(&state.findings)?;
        self.security
            .write_atomic(FINDINGS_FILE, findings.as_bytes(), MODE_PUBLIC_FILE)?;
        let stats = &manifest.stats;
        let summary = Summary {
            version: MANIFEST_VERSION,
            run_id: &manifest.run_id,
            status: manifest.status,
            versions: &manifest.versions,
            counts: SummaryCounts {
                safe: stats.safe,
                warned: stats.warned,
                quarantined: state.quarantined,
                blocked: stats.blocked,
                failed: stats.failed,
                duplicates: state.duplicates,
                findings: state.findings.len() as u64,
            },
        };
        self.security.write_atomic(
            SUMMARY_FILE,
            to_json(&summary)?.as_bytes(),
            MODE_PUBLIC_FILE,
        )?;
        self.security.sync()?;
        self.run_dir.write_atomic(
            MANIFEST_FILE,
            to_json(manifest)?.as_bytes(),
            MODE_PUBLIC_FILE,
        )?;
        self.run_dir.sync()
    }

    /// With `retainRaw`, write the raw body and security text to
    /// `<audit root>/<runId>/<docId>.raw|.sectext` (0600). Never under `runs/`.
    fn retain_raw(&self, id: &DocumentId, ctx: &StoreContext) -> Result<(), StoreError> {
        let (Some(dir), Some(raw)) = (&self.audit_dir, &ctx.raw) else {
            return Ok(());
        };
        if let Some(bytes) = raw.raw_bytes() {
            dir.write_atomic(&format!("{id}.raw"), bytes, MODE_PRIVATE_FILE)?;
        }
        dir.write_atomic(
            &format!("{id}.sectext"),
            raw.security_text().as_bytes(),
            MODE_PRIVATE_FILE,
        )?;
        Ok(())
    }
}

fn to_json<T: Serialize + ?Sized>(value: &T) -> Result<String, StoreError> {
    let mut json = serde_json::to_string_pretty(value).map_err(|_| StoreError::Serialize)?;
    json.push('\n');
    Ok(json)
}

fn push_findings(out: &mut Vec<FindingRecord>, id: &DocumentId, findings: &[Finding]) {
    out.extend(findings.iter().map(|finding| FindingRecord {
        document_id: id.clone(),
        finding_id: finding.id.clone(),
        severity: finding.severity,
        detector: finding.detector.clone(),
    }));
}

/// The page body: the title as the first H1 (escaped by the extractor's Markdown renderer, so
/// it is never raw HTML or extra structure) followed by the rendered Markdown.
fn page_body(title: Option<&str>, markdown: &str) -> String {
    let heading = title
        .map(|title| {
            render(&StructuredDocument {
                title: None,
                blocks: vec![Block::Heading {
                    level: 1,
                    text: title.to_owned(),
                }],
            })
        })
        .unwrap_or_default();
    match (heading.is_empty(), markdown.is_empty()) {
        (true, _) => markdown.to_owned(),
        (false, true) => heading,
        (false, false) => format!("{heading}\n{markdown}"),
    }
}

/// Frontmatter with Secure Web-generated fields only. URLs are `url`-crate serialized (no
/// whitespace or control characters), ids and enums are generated.
fn frontmatter(doc: &AcceptedDocument) -> String {
    let decision = match doc.security().decision {
        SecurityDecision::Safe => "SAFE",
        SecurityDecision::Warn => "WARN",
        SecurityDecision::Block => "BLOCK",
    };
    format!(
        "---\nsecureWeb: 1\ndocumentId: {}\nurl: {}\nfinalUrl: {}\nretrievedAt: {}\ndecision: {decision}\n---\n",
        doc.doc_id(),
        doc.requested_url(),
        doc.final_url(),
        doc.provenance()
            .retrieved_at
            .to_rfc3339_opts(SecondsFormat::AutoSi, true),
    )
}

/// `NNNNNN-<slug>.md`, the slug from the normalized title, else the URL path, else none
/// (`NNNNNN.md`). Re-checked against the page-name pattern before use.
fn page_file_name(seq: u32, title: Option<&str>, url: &Url) -> Result<String, StoreError> {
    let from_title = title.map(slug).unwrap_or_default();
    let slug = if from_title.is_empty() {
        slug(url.path())
    } else {
        from_title
    };
    let name = if slug.is_empty() {
        format!("{seq:06}.md")
    } else {
        format!("{seq:06}-{slug}.md")
    };
    if is_page_file_name(&name) && fsx::is_safe_name(&name) {
        Ok(name)
    } else {
        Err(StoreError::UnsafePath)
    }
}

/// Preconditions on an accepted document (defense in depth: `scan_and_accept` already
/// guarantees them). Nothing is written when one fails.
fn validate_accepted(
    doc: &AcceptedDocument,
    ctx: &StoreContext,
    versions: &Versions,
) -> Result<(), StoreError> {
    if !matches!(
        doc.security().decision,
        SecurityDecision::Safe | SecurityDecision::Warn
    ) {
        return Err(StoreError::InvalidDocument("decision is not SAFE or WARN"));
    }
    if let Some(title) = doc.title() {
        // The title must already be the extractor's normalized form (NFC, no control or
        // invisible characters, ≤ 200 chars): the scanner saw exactly that string.
        if normalize_title(title).as_deref() != Some(title) {
            return Err(StoreError::InvalidDocument("title is not normalized"));
        }
    }
    if doc.security().scanner_version != versions.scanner
        || doc.provenance().scanner_version != versions.scanner
    {
        return Err(StoreError::InvalidDocument(
            "scanner version differs from the run",
        ));
    }
    if doc.security().policy_version != versions.policy
        || doc.provenance().policy_version != versions.policy
    {
        return Err(StoreError::InvalidDocument(
            "policy version differs from the run",
        ));
    }
    if doc.provenance().final_url != *doc.final_url()
        || doc.provenance().requested_url != *doc.requested_url()
    {
        return Err(StoreError::InvalidDocument("provenance URLs differ"));
    }
    if !is_mime_essence(&doc.provenance().content_type) {
        return Err(StoreError::InvalidDocument("content type"));
    }
    if !is_short_token(&doc.provenance().secure_web_version) {
        return Err(StoreError::InvalidDocument("secure web version"));
    }
    validate_ids(&doc.security().finding_ids, ctx)
}

/// Finding ids must be scanner pattern ids, and `ctx.findings` must describe exactly them.
fn validate_ids(finding_ids: &[String], ctx: &StoreContext) -> Result<(), StoreError> {
    if !finding_ids.iter().all(|id| is_pattern_id(id)) {
        return Err(StoreError::InvalidDocument("finding id"));
    }
    if !ctx
        .findings
        .iter()
        .all(|f| is_pattern_id(&f.id) && is_detector(&f.detector))
    {
        return Err(StoreError::InvalidDocument("finding record"));
    }
    let declared: HashSet<&str> = finding_ids.iter().map(String::as_str).collect();
    let described: HashSet<&str> = ctx.findings.iter().map(|f| f.id.as_str()).collect();
    if declared != described {
        return Err(StoreError::InvalidDocument(
            "findings do not match the document's finding ids",
        ));
    }
    Ok(())
}

/// `[A-Z]{1,8}[0-9]{1,6}` (the adapter's pattern id rule, ADR-014).
fn is_pattern_id(id: &str) -> bool {
    let letters = id.bytes().take_while(u8::is_ascii_uppercase).count();
    let digits = &id[letters..];
    (1..=8).contains(&letters)
        && (1..=6).contains(&digits.len())
        && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Lowercase `[a-z0-9]` words joined by single hyphens, at most 64 bytes.
fn is_detector(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.split('-').all(|word| {
            !word.is_empty()
                && word
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// Printable ASCII, 1..=64 bytes.
fn is_short_token(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// A lowercase MIME essence `type/subtype` of RFC 7230 token characters, at most 127 bytes.
fn is_mime_essence(s: &str) -> bool {
    let token = |t: &str| {
        !t.is_empty()
            && t.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$&^_.+-".contains(&b))
    };
    s.len() <= 127 && s.split_once('/').is_some_and(|(a, b)| token(a) && token(b))
}

/// sha256 of the requested URL, for the audit event (the URL itself stays in the manifest).
fn url_hash(url: &Url) -> String {
    hex::encode(Sha256::digest(url.as_str().as_bytes()))
}

/// Emit the `document_security_decision` audit event: ids and enums only, never body text
/// (`docs/security-policy.md` §8).
#[allow(clippy::too_many_arguments)]
fn audit_event(
    run_id: &RunId,
    id: &DocumentId,
    url: &Url,
    decision: SecurityDecision,
    reason: Option<BlockReason>,
    severity: Option<Severity>,
    finding_ids: &[String],
    scanner_version: Option<&str>,
) {
    tracing::info!(
        event = "document_security_decision",
        run_id = %run_id,
        document_id = %id,
        url_hash = %url_hash(url),
        decision = ?decision,
        reason = ?reason,
        severity = ?severity,
        finding_ids = %finding_ids.join(","),
        scanner_version = scanner_version.unwrap_or(""),
        "document security decision"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_ids_and_detectors() {
        for good in ["PI001", "A1", "ABCDEFGH123456"] {
            assert!(is_pattern_id(good), "{good}");
        }
        for bad in [
            "",
            "PI",
            "001",
            "pi001",
            "PI0012345",
            "ABCDEFGHI1",
            "PI-1",
            "PI1a",
        ] {
            assert!(!is_pattern_id(bad), "{bad}");
        }
        assert!(is_detector("ignore-previous-instructions"));
        for bad in ["", "-a", "a-", "a--b", "A", "a b", &"a".repeat(65)] {
            assert!(!is_detector(bad), "{bad}");
        }
    }

    #[test]
    fn mime_and_tokens() {
        assert!(is_mime_essence("text/html"));
        assert!(is_mime_essence("application/vnd.api+json"));
        for bad in [
            "text",
            "text/",
            "/html",
            "Text/html",
            "text/html; x",
            "text/h\ntml",
        ] {
            assert!(!is_mime_essence(bad), "{bad:?}");
        }
        assert!(is_short_token("injection-scanner 0.1.0"));
        assert!(!is_short_token("a\nb"));
        assert!(!is_short_token(""));
    }

    #[test]
    fn body_puts_the_escaped_title_first() {
        assert_eq!(page_body(None, "text\n"), "text\n");
        assert_eq!(page_body(Some("Home"), ""), "# Home\n");
        assert_eq!(page_body(Some("Home"), "text\n"), "# Home\n\ntext\n");
        let body = page_body(Some("<script>x</script> *y*"), "");
        assert!(!body.contains("<script>"), "{body}");
    }

    #[test]
    fn file_names_fall_back_to_the_path() {
        let url = Url::parse("https://example.test/Docs/Getting_Started").unwrap();
        assert_eq!(
            page_file_name(1, Some("Home"), &url).unwrap(),
            "000001-home.md"
        );
        assert_eq!(
            page_file_name(2, Some("日本語"), &url).unwrap(),
            "000002-docs-getting-started.md"
        );
        let root = Url::parse("https://example.test/").unwrap();
        assert_eq!(page_file_name(3, None, &root).unwrap(), "000003.md");
    }

    /// A document that went through the real `scan_and_decide` (the only way to an
    /// `AcceptedDocument`), with a fixed scanner report: `Medium` findings make it `WARN`.
    fn accepted(seq: u32, decision: SecurityDecision) -> (AcceptedDocument, Vec<Finding>) {
        use secure_web_core::config::SecurityConfig;
        use secure_web_core::model::{ContentType, SecurityFindings, UntrustedDocument};
        use secure_web_extract::{ContentExtractor, ExtractInput, Extractor, SourceKind};
        use secure_web_security::decision::{scan_and_decide, AcceptContext};
        use secure_web_security::injection::{ScanFuture, SecurityScanner};
        use secure_web_security::policy::PolicyEngine;

        struct Fixed(Vec<Finding>);
        impl SecurityScanner for Fixed {
            fn scan<'a>(&'a self, _text: &'a str) -> ScanFuture<'a> {
                let findings = SecurityFindings::new(
                    SCANNER.into(),
                    self.0.clone(),
                    0,
                    std::time::Duration::ZERO,
                );
                Box::pin(async move { Ok(findings) })
            }
        }

        let url = Url::parse(&format!("https://example.test/p/{seq}")).unwrap();
        let html = format!("<title>Page {seq}</title><p>Body {seq} {decision:?}</p>");
        let extracted = ContentExtractor::default()
            .extract(&ExtractInput {
                final_url: &url,
                kind: SourceKind::Html,
                charset: None,
                body: html.as_bytes(),
            })
            .unwrap();
        let doc = UntrustedDocument {
            requested_url: url.clone(),
            final_url: url,
            redirect_chain: vec![],
            http_status: 200,
            content_type: ContentType {
                essence: "text/html".into(),
                charset: None,
            },
            retrieved_at: Utc::now(),
            security_text: extracted.security_text,
            display: extracted.display,
            links: extracted.links,
            raw_bytes: None,
        };
        let findings = match decision {
            SecurityDecision::Warn => vec![Finding {
                id: "PI500".into(),
                severity: Severity::Medium,
                detector: "stub-medium".into(),
                line: 1,
                confidence: 1.0,
            }],
            _ => vec![],
        };
        let policy = PolicyEngine::new(&SecurityConfig::default()).unwrap();
        let ctx = AcceptContext::new(DocumentId::from_seq(seq).unwrap(), 0);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let decision = runtime.block_on(scan_and_decide(doc, &Fixed(findings), &policy, &ctx));
        (decision.outcome.unwrap(), decision.findings)
    }

    const SCANNER: &str = "injection-scanner 0.1.0";

    fn versions() -> Versions {
        let policy = secure_web_security::policy::PolicyEngine::new(
            &secure_web_core::config::SecurityConfig::default(),
        )
        .unwrap();
        Versions::current(
            SCANNER,
            secure_web_security::policy::SecurityPolicy::policy_version(&policy),
        )
    }

    /// Crash durability: every rename a manifest lists is made durable (file fsync inside
    /// `write_atomic`, then an fsync of its directory) before the manifest is renamed into
    /// place, and the run directory is fsynced after it.
    #[test]
    fn checkpoints_sync_every_listed_directory_before_the_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsCorpusStore::new(StoreOptions {
            workspace: tmp.path().to_path_buf(),
            audit_root: None,
            retain_raw: false,
            warn_handling: WarnHandling::Quarantine,
        })
        .unwrap();
        let versions = versions();
        // Documents are decided (on their own runtime) before the sync log starts recording.
        let docs: Vec<_> = (1..=CHECKPOINT_EVERY + 2)
            .map(|seq| {
                let decision = if seq % 3 == 0 {
                    SecurityDecision::Warn
                } else {
                    SecurityDecision::Safe
                };
                accepted(seq, decision)
            })
            .collect();
        fsx::sync_log::start();
        let writer = store
            .begin_run_sync(RunSpec {
                run_id: RunId::parse("crawl_00000000abcd").unwrap(),
                root_url: Url::parse("https://example.test/").unwrap(),
                started_at: Utc::now(),
                versions: versions.clone(),
                policy: ManifestPolicy::from_config(&Config::default()),
            })
            .unwrap();
        let inner = &writer.inner;
        let ctx = StoreContext::default();
        for (doc, findings) in docs {
            assert_eq!(writer.next_doc_id().unwrap(), *doc.doc_id());
            let ctx = StoreContext {
                findings,
                ..StoreContext::default()
            };
            inner.store_sync(doc, &ctx).unwrap();
        }
        let id = writer.next_doc_id().unwrap();
        let blocked = BlockedDocument {
            doc_id: id,
            requested_url: Url::parse("https://example.test/evil").unwrap(),
            final_url: None,
            reason: BlockReason::PromptInjection,
            max_severity: None,
            finding_ids: vec![],
            scanner_version: None,
        };
        inner.record_blocked_sync(&blocked, &ctx).unwrap();
        {
            let mut state = inner.lock_state().unwrap();
            inner.checkpoint_locked(&mut state).unwrap();
        }
        let events = fsx::sync_log::take();
        let run = store.runs_dir().join("crawl_00000000abcd");
        let manifest_rename =
            PathBuf::from(format!("rename:{}", run.join(MANIFEST_FILE).display()));
        let run_sync = PathBuf::from(format!("sync:{}", run.display()));

        // Creating the run makes its directory entries durable.
        let first_manifest = events.iter().position(|e| *e == manifest_rename).unwrap();
        let runs_sync = PathBuf::from(format!("sync:{}", store.runs_dir().display()));
        assert!(events[..first_manifest].contains(&runs_sync), "{events:#?}");

        let manifests: Vec<usize> = events
            .iter()
            .enumerate()
            .filter(|(_, e)| **e == manifest_rename)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            manifests.len(),
            3,
            "start + automatic + explicit checkpoint"
        );
        for &m in &manifests {
            assert_eq!(events.get(m + 1), Some(&run_sync), "{events:#?}");
            // Every rename before this manifest has its directory synced between the two.
            for (i, event) in events[..m].iter().enumerate() {
                let Some(target) = event.to_str().and_then(|e| e.strip_prefix("rename:")) else {
                    continue;
                };
                let dir = Path::new(target).parent().unwrap();
                let sync = PathBuf::from(format!("sync:{}", dir.display()));
                assert!(
                    events[i + 1..m].contains(&sync),
                    "{target} is not synced before the manifest at {m}: {events:#?}"
                );
            }
        }
        for dir in ["pages", "metadata", "quarantine", "security"] {
            let sync = PathBuf::from(format!("sync:{}", run.join(dir).display()));
            assert!(events.contains(&sync), "{dir}");
        }
    }

    #[test]
    fn document_ids_stop_at_the_last_sequence_number() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsCorpusStore::new(StoreOptions {
            workspace: tmp.path().to_path_buf(),
            audit_root: None,
            retain_raw: false,
            warn_handling: WarnHandling::Quarantine,
        })
        .unwrap();
        let writer = store
            .begin_run_sync(RunSpec {
                run_id: RunId::parse("crawl_00000000abcd").unwrap(),
                root_url: Url::parse("https://example.test/").unwrap(),
                started_at: Utc::now(),
                versions: versions(),
                policy: ManifestPolicy::from_config(&Config::default()),
            })
            .unwrap();
        assert_eq!(
            writer.next_doc_id().unwrap(),
            DocumentId::from_seq(1).unwrap()
        );

        writer
            .inner
            .next_seq
            .store(MAX_DOCUMENT_SEQ - 1, Ordering::SeqCst);
        assert_eq!(
            writer.next_doc_id().unwrap(),
            DocumentId::from_seq(MAX_DOCUMENT_SEQ).unwrap()
        );
        for _ in 0..2 {
            assert!(matches!(
                writer.next_doc_id(),
                Err(StoreError::SequenceExhausted)
            ));
        }
        assert_eq!(
            writer.inner.next_seq.load(Ordering::SeqCst),
            MAX_DOCUMENT_SEQ,
            "a refused id must not advance the counter"
        );
    }
}

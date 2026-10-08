//! Manifest v1 (`docs/contracts/manifest-schema.md`): the agent's entry point into a run.
//!
//! Types serialize to exactly the contract shape (`camelCase` objects, `SCREAMING_SNAKE_CASE`
//! enums) and deserialize with `deny_unknown_fields`, so [`Manifest::load`] accepts only what
//! the store writes. Blocked and failed entries have no field for a title, path, hash or text.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

use chrono::{DateTime, Utc};
use secure_web_core::config::{Config, CrawlScope};
use secure_web_core::error::ErrorCode;
use secure_web_core::ids::{DocumentId, RunId};
use secure_web_core::model::{BlockReason, SecurityDecision, Severity};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::StoreError;

/// Manifest format version.
pub const MANIFEST_VERSION: u32 = 1;

/// Directory (relative to the run) of agent-visible pages.
pub const PAGES_DIR: &str = "pages";
/// Directory (relative to the run) of quarantined `WARN` pages (`warnHandling: quarantine`).
pub const QUARANTINE_DIR: &str = "quarantine";

/// Largest `manifest.json` [`Manifest::load`] reads.
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

/// What produced the run (contract enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunKind {
    /// `web_crawl`.
    Crawl,
    /// `web_open` (exactly one entry).
    Open,
}

impl RunKind {
    /// The kind implied by a run id (`open_…` → `OPEN`, `crawl_…` → `CRAWL`).
    pub fn of(run_id: &RunId) -> Self {
        if run_id.is_open() {
            RunKind::Open
        } else {
            RunKind::Crawl
        }
    }
}

/// Run status (contract enum). `RUNNING` only appears in checkpoints of a run that has not
/// finished (or was killed); every other value is terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunStatus {
    /// Checkpoint of an unfinished run; `finishedAt` is `null`.
    Running,
    /// The run completed.
    Complete,
    /// A budget was exhausted.
    LimitReached,
    /// The run was cancelled.
    Cancelled,
    /// The run failed.
    Failed,
}

impl RunStatus {
    /// Whether this status ends a run.
    pub fn is_terminal(self) -> bool {
        !matches!(self, RunStatus::Running)
    }
}

/// Version stamps (threat T17: "safe" is only meaningful under a known scanner and policy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Versions {
    /// Secure Web version.
    pub secure_web: String,
    /// Verbatim `injection-scanner --version` output.
    pub scanner: String,
    /// Policy version (`Config::policy_version`).
    pub policy: String,
}

impl Versions {
    /// Stamps for this build of Secure Web with the given scanner `--version` line and policy
    /// version.
    pub fn current(scanner: impl Into<String>, policy: impl Into<String>) -> Self {
        Self {
            secure_web: secure_web_core::SECURE_WEB_VERSION.to_owned(),
            scanner: scanner.into(),
            policy: policy.into(),
        }
    }
}

/// The crawl budgets and scope in force (`manifest.policy`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestPolicy {
    /// `crawl.maxDepth`.
    pub max_depth: u32,
    /// `crawl.maxPages`.
    pub max_pages: u32,
    /// `crawl.maxTotalBytes`.
    pub max_total_bytes: u64,
    /// `fetch.maxPageBytes`.
    pub max_page_bytes: u64,
    /// `crawl.maxDuration` in milliseconds.
    pub max_duration_ms: u64,
    /// `crawl.scope`.
    pub scope: CrawlScope,
    /// `crawl.allowedHosts`.
    pub allowed_hosts: Vec<String>,
}

impl ManifestPolicy {
    /// The policy block for `config`.
    pub fn from_config(config: &Config) -> Self {
        Self {
            max_depth: config.crawl.max_depth,
            max_pages: config.crawl.max_pages,
            max_total_bytes: config.crawl.max_total_bytes,
            max_page_bytes: config.fetch.max_page_bytes,
            max_duration_ms: u64::try_from(config.crawl.max_duration.as_millis())
                .unwrap_or(u64::MAX),
            scope: config.crawl.scope,
            allowed_hosts: config.crawl.allowed_hosts.clone(),
        }
    }
}

/// Run counters (`manifest.stats`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunStats {
    /// URLs discovered (frontier admissions), including the root.
    pub discovered: u64,
    /// Documents fetched (stored, duplicate, quarantined or blocked).
    pub fetched: u64,
    /// `SAFE` documents.
    pub safe: u64,
    /// `WARN` documents (stored or quarantined).
    pub warned: u64,
    /// Blocked documents.
    pub blocked: u64,
    /// Failed fetches.
    pub failed: u64,
    /// Bytes fetched (decompressed response bodies).
    pub total_bytes: u64,
}

/// One accepted (`SAFE` / `WARN`) document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentEntry {
    /// Document id.
    pub id: DocumentId,
    /// Sequence number (the id's number).
    pub seq: u32,
    /// URL as requested.
    pub url: Url,
    /// URL after redirects.
    pub final_url: Url,
    /// Page file, relative to the run directory: `pages/…` or, when quarantined,
    /// `quarantine/…`. For a duplicate, the first document's file.
    pub path: String,
    /// Normalized, scanned title.
    pub title: Option<String>,
    /// Crawl depth.
    pub depth: u32,
    /// `SAFE` or `WARN`.
    pub decision: SecurityDecision,
    /// Highest finding severity.
    pub max_severity: Option<Severity>,
    /// Finding ids.
    pub finding_ids: Vec<String>,
    /// `sha256:<hex>` of the page body (title heading + Markdown, no frontmatter).
    pub content_hash: String,
    /// Size of the page body in bytes.
    pub content_bytes: u64,
    /// Final HTTP status.
    pub http_status: u16,
    /// Content type essence.
    pub content_type: String,
    /// When the response was received.
    pub retrieved_at: DateTime<Utc>,
    /// The first document with the same `contentHash`, when deduplicated.
    pub duplicate_of: Option<DocumentId>,
}

impl DocumentEntry {
    /// Whether the page file is in `quarantine/` (never part of the agent corpus).
    pub fn is_quarantined(&self) -> bool {
        self.path.starts_with("quarantine/")
    }
}

/// One blocked document: ids, URLs and enums only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlockedEntry {
    /// Document id.
    pub id: DocumentId,
    /// URL as requested.
    pub url: Url,
    /// URL after redirects, if the fetch got that far.
    pub final_url: Option<Url>,
    /// Crawl depth.
    pub depth: u32,
    /// Why the page was blocked.
    pub reason: BlockReason,
    /// Highest finding severity, if the scanner ran.
    pub max_severity: Option<Severity>,
    /// Finding ids.
    pub finding_ids: Vec<String>,
    /// Final HTTP status, if a response was received.
    pub http_status: Option<u16>,
    /// Content type essence, if a response was received.
    pub content_type: Option<String>,
    /// When the response was received.
    pub retrieved_at: Option<DateTime<Utc>>,
}

/// One URL that could not be fetched or processed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailedEntry {
    /// URL as requested.
    pub url: Url,
    /// Crawl depth.
    pub depth: u32,
    /// Contract error code.
    pub code: ErrorCode,
    /// Whether a retry may succeed.
    pub retryable: bool,
}

/// `manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    /// Always [`MANIFEST_VERSION`].
    pub version: u32,
    /// Run id (the run directory name).
    pub run_id: RunId,
    /// `CRAWL` or `OPEN`.
    pub kind: RunKind,
    /// Root URL of the crawl, or the opened URL.
    pub root_url: Url,
    /// Run status.
    pub status: RunStatus,
    /// When the run started.
    pub started_at: DateTime<Utc>,
    /// When the run finished; `null` while `RUNNING`.
    pub finished_at: Option<DateTime<Utc>>,
    /// Version stamps.
    pub versions: Versions,
    /// Budgets and scope.
    pub policy: ManifestPolicy,
    /// Counters.
    pub stats: RunStats,
    /// Accepted documents, in recording order.
    pub documents: Vec<DocumentEntry>,
    /// Blocked documents, in recording order.
    pub blocked: Vec<BlockedEntry>,
    /// Failed URLs, in recording order.
    pub failed: Vec<FailedEntry>,
}

impl Manifest {
    /// Read and validate `manifest.json` at `path` (at most [`MAX_MANIFEST_BYTES`]).
    ///
    /// Beyond the schema, every document `path` must be a page file name the store generates
    /// (`pages/` or `quarantine/`, `NNNNNN[-slug].md`), so a tampered manifest cannot point a
    /// reader outside the run directory.
    pub fn load(path: &Path) -> Result<Self, StoreError> {
        let file =
            std::fs::File::open(path).map_err(|err| StoreError::io("open manifest", &err))?;
        let mut bytes = Vec::new();
        file.take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|err| StoreError::io("read manifest", &err))?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(StoreError::InvalidManifest("too large"));
        }
        Self::from_json(&bytes)
    }

    /// Parse and validate a manifest from JSON bytes (see [`Manifest::load`]).
    pub fn from_json(bytes: &[u8]) -> Result<Self, StoreError> {
        // serde messages can quote input; they are dropped.
        let manifest: Manifest = serde_json::from_slice(bytes)
            .map_err(|_| StoreError::InvalidManifest("not a manifest v1 document"))?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.version != MANIFEST_VERSION {
            return Err(StoreError::InvalidManifest("unsupported version"));
        }
        if self.kind != RunKind::of(&self.run_id) {
            return Err(StoreError::InvalidManifest("kind does not match runId"));
        }
        // `RUNNING` ⇔ `finishedAt: null`; a terminal run finished no earlier than it started.
        match (self.status, self.finished_at) {
            (RunStatus::Running, None) => {}
            (RunStatus::Running, Some(_)) => {
                return Err(StoreError::InvalidManifest(
                    "RUNNING manifest has finishedAt",
                ));
            }
            (_, None) => {
                return Err(StoreError::InvalidManifest(
                    "finished manifest has no finishedAt",
                ));
            }
            (_, Some(finished)) if finished < self.started_at => {
                return Err(StoreError::InvalidManifest("finishedAt precedes startedAt"));
            }
            (_, Some(_)) => {}
        }
        let mut ids = HashSet::new();
        for (index, doc) in self.documents.iter().enumerate() {
            validate_document(doc, &self.documents[..index])?;
            if !ids.insert(&doc.id) {
                return Err(StoreError::InvalidManifest("duplicate document id"));
            }
        }
        for blocked in &self.blocked {
            if !ids.insert(&blocked.id) {
                return Err(StoreError::InvalidManifest("duplicate document id"));
            }
        }
        Ok(())
    }

    /// Documents in the agent corpus: `SAFE` / `WARN` entries whose page is under `pages/`
    /// (never quarantined, never any other decision or location — re-checked here even for a
    /// manifest that was built in memory rather than loaded). Duplicates are included (they
    /// point at the first document's file).
    pub fn accepted_documents(&self) -> impl Iterator<Item = &DocumentEntry> {
        self.documents.iter().filter(|doc| {
            is_stored_decision(doc.decision)
                && doc
                    .path
                    .strip_prefix("pages/")
                    .is_some_and(is_page_file_name)
        })
    }
}

/// Whether a document with `decision` may have a page file (`SAFE` or `WARN`).
fn is_stored_decision(decision: SecurityDecision) -> bool {
    matches!(decision, SecurityDecision::Safe | SecurityDecision::Warn)
}

/// One `documents[]` entry against the contract and the entries before it (`earlier`).
fn validate_document(doc: &DocumentEntry, earlier: &[DocumentEntry]) -> Result<(), StoreError> {
    if !is_stored_decision(doc.decision) {
        return Err(StoreError::InvalidManifest("document decision"));
    }
    if !is_page_path(&doc.path) {
        return Err(StoreError::InvalidManifest("document path"));
    }
    // `SAFE` pages are always under `pages/`; only `WARN` pages are ever quarantined.
    if doc.is_quarantined() && doc.decision != SecurityDecision::Warn {
        return Err(StoreError::InvalidManifest(
            "quarantined document is not WARN",
        ));
    }
    if doc.seq != doc.id.seq() {
        return Err(StoreError::InvalidManifest("document seq"));
    }
    match &doc.duplicate_of {
        // A first copy's file is named after its own sequence number.
        None => {
            let own = doc
                .path
                .split_once('/')
                .is_some_and(|(_, name)| name.starts_with(&format!("{:06}", doc.seq)));
            if !own {
                return Err(StoreError::InvalidManifest(
                    "document path does not match seq",
                ));
            }
        }
        // A duplicate shares the file and hash of an earlier first copy in the same area.
        Some(first) => {
            let ok = earlier.iter().any(|e| {
                e.id == *first
                    && e.duplicate_of.is_none()
                    && e.path == doc.path
                    && e.content_hash == doc.content_hash
            });
            if !ok {
                return Err(StoreError::InvalidManifest("duplicateOf"));
            }
        }
    }
    Ok(())
}

/// Whether `path` is `pages/` or `quarantine/` followed by a generated page file name.
pub fn is_page_path(path: &str) -> bool {
    let Some((dir, name)) = path.split_once('/') else {
        return false;
    };
    (dir == PAGES_DIR || dir == QUARANTINE_DIR) && is_page_file_name(name)
}

/// Whether `name` is `NNNNNN.md` or `NNNNNN-<slug>.md` with a slug of 1..=48 characters
/// `[a-z0-9]` in `-`-separated runs (`docs/security-policy.md` §7).
pub fn is_page_file_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".md") else {
        return false;
    };
    let (digits, slug) = match stem.split_once('-') {
        Some((digits, slug)) => (digits, Some(slug)),
        None => (stem, None),
    };
    let digits_ok = digits.len() == 6 && digits.bytes().all(|b| b.is_ascii_digit());
    let slug_ok = slug.is_none_or(|slug| {
        !slug.is_empty()
            && slug.len() <= secure_web_extract::title::MAX_SLUG_LEN
            && !slug.starts_with('-')
            && !slug.ends_with('-')
            && !slug.contains("--")
            && slug
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    digits_ok && slug_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_names() {
        for good in ["000001.md", "000001-home.md", "999999-a-b-c.md"] {
            assert!(is_page_file_name(good), "{good}");
        }
        for bad in [
            "1-home.md",
            "000001-.md",
            "000001--x.md",
            "000001-x-.md",
            "000001-Home.md",
            "000001-../x.md",
            "000001-x.txt",
            "0000001.md",
        ] {
            assert!(!is_page_file_name(bad), "{bad}");
        }
        assert!(is_page_path("pages/000001-home.md"));
        assert!(is_page_path("quarantine/000001.md"));
        for bad in [
            "metadata/000001.json",
            "pages/../manifest.json",
            "/pages/000001.md",
            "pages/sub/000001.md",
            "pages/000001.md/",
        ] {
            assert!(!is_page_path(bad), "{bad}");
        }
    }

    #[test]
    fn statuses() {
        assert!(!RunStatus::Running.is_terminal());
        assert!(RunStatus::Complete.is_terminal());
        assert_eq!(
            serde_json::to_string(&RunStatus::LimitReached).unwrap(),
            "\"LIMIT_REACHED\""
        );
    }

    #[test]
    fn policy_from_config() {
        let policy = ManifestPolicy::from_config(&Config::default());
        assert_eq!(policy.max_depth, 2);
        assert_eq!(policy.max_duration_ms, 120_000);
        assert_eq!(policy.scope, CrawlScope::SameOrigin);
    }

    #[test]
    fn from_json_rejects_garbage_quietly() {
        let err = Manifest::from_json(b"{\"secret-page-text\": 1}").unwrap_err();
        assert!(!err.to_string().contains("secret"));
    }
}

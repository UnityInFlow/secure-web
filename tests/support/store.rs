//! Corpus store test harness (PR-06): runs pages through extract → stub scan → `accept()` the
//! way the page processor will (PR-07) and records the outcome in a `RunWriter`.
#![allow(dead_code)]

#[path = "scanner.rs"]
pub mod scanner;

use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeZone, Utc};
use secure_web_core::config::WarnHandling;
use secure_web_core::ids::{DocumentId, RunId};
use secure_web_core::model::{BlockedDocument, ContentType, Finding, UntrustedDocument};
use secure_web_extract::markdown::render;
use secure_web_extract::{ExtractLimits, SourceKind};
use secure_web_security::decision::{scan_and_decide, AcceptContext, AcceptedDocument};
use secure_web_security::injection::SubprocessScanner;
use secure_web_security::policy::SecurityPolicy;
use secure_web_store::{
    DocumentSizes, FsCorpusStore, ManifestPolicy, RawContent, RunSpec, RunWriter, StoreContext,
    StoreOptions, Versions,
};
use url::Url;

#[allow(unused_imports)]
pub use scanner::{canaries, policy, stub_scanner, Harness};

/// Fixed response time so manifests are deterministic.
pub fn retrieved_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 24, 18, 0, 1).unwrap()
}

/// Fixed run start.
pub fn started_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 24, 18, 0, 0).unwrap()
}

/// One page after the security pipeline.
pub struct Page {
    pub doc: UntrustedDocument,
    pub findings: Vec<Finding>,
    pub outcome: Result<AcceptedDocument, BlockedDocument>,
    /// Raw content as the decision returned it (always requested here; the store ignores it
    /// unless `retainRaw`).
    pub raw: Option<RawContent>,
}

/// A store over `workspace` (no retained raw content, `WARN` pages stored).
pub fn store_at(workspace: &Path) -> FsCorpusStore {
    store_with(workspace, false, WarnHandling::Store)
}

pub fn store_with(
    workspace: &Path,
    retain_raw: bool,
    warn_handling: WarnHandling,
) -> FsCorpusStore {
    FsCorpusStore::new(StoreOptions {
        workspace: workspace.to_path_buf(),
        audit_root: None,
        retain_raw,
        warn_handling,
    })
    .unwrap()
}

/// Version stamps for `scanner` and the default policy.
pub fn versions(scanner: &SubprocessScanner) -> Versions {
    Versions::current(scanner.version().unwrap(), policy().policy_version())
}

/// A run spec with fixed times and the default config's policy block.
pub fn spec(run_id: &str, root: &str, scanner: &SubprocessScanner) -> RunSpec {
    RunSpec {
        run_id: RunId::parse(run_id).unwrap(),
        root_url: Url::parse(root).unwrap(),
        started_at: started_at(),
        versions: versions(scanner),
        policy: ManifestPolicy::from_config(&Default::default()),
    }
}

/// The page processor's `UntrustedDocument` for an in-memory HTML body at `url`.
pub fn untrusted_html(url: &str, html: &str) -> UntrustedDocument {
    let extracted =
        scanner::extract::extract_str(html, SourceKind::Html, url, ExtractLimits::default())
            .unwrap();
    let url = Url::parse(url).unwrap();
    UntrustedDocument {
        requested_url: url.clone(),
        final_url: url,
        redirect_chain: vec![],
        http_status: 200,
        content_type: ContentType {
            essence: "text/html".into(),
            charset: Some("utf-8".into()),
        },
        retrieved_at: retrieved_at(),
        security_text: extracted.security_text,
        display: extracted.display,
        links: extracted.links,
        raw_bytes: Some(html.as_bytes().to_vec()),
    }
}

/// Scan and decide `doc` as document `id`.
pub async fn scan(
    scanner: &SubprocessScanner,
    doc: UntrustedDocument,
    id: DocumentId,
    depth: u32,
) -> Page {
    let ctx = AcceptContext {
        doc_id: id,
        depth,
        retain_raw: true,
    };
    let decision = scan_and_decide(doc.clone(), scanner, &policy(), &ctx).await;
    Page {
        doc,
        findings: decision.findings,
        outcome: decision.outcome,
        raw: decision.raw,
    }
}

/// The `StoreContext` the page processor builds for `page`.
pub fn context(page: &Page, depth: u32) -> StoreContext {
    let doc = &page.doc;
    StoreContext {
        depth,
        http_status: Some(doc.http_status),
        content_type: Some(doc.content_type.essence.clone()),
        retrieved_at: Some(doc.retrieved_at),
        redirect_chain: doc.redirect_chain.clone(),
        sizes: DocumentSizes {
            raw_bytes: doc.raw_bytes.as_ref().map_or(0, |b| b.len() as u64),
            extracted_bytes: render(&doc.display).len() as u64,
            security_text_bytes: doc.security_text.len() as u64,
            links_found: doc.links.len() as u64,
            links_truncated: false,
        },
        findings: page.findings.clone(),
        scan_duration_ms: None,
        raw: page.raw.clone(),
    }
}

/// Record `page` (stored or blocked) in `writer`.
pub async fn record(writer: &RunWriter, page: &Page, depth: u32) {
    let ctx = context(page, depth);
    match &page.outcome {
        Ok(accepted) => {
            writer.store(accepted.clone(), &ctx).await.unwrap();
        }
        Err(blocked) => writer.record_blocked(blocked, &ctx).await.unwrap(),
    }
}

/// Run an HTML page through the pipeline as the writer's next document and record it.
pub async fn add_html(
    writer: &RunWriter,
    scanner: &SubprocessScanner,
    url: &str,
    html: &str,
    depth: u32,
) -> Page {
    let id = writer.next_doc_id().unwrap();
    let page = scan(scanner, untrusted_html(url, html), id, depth).await;
    record(writer, &page, depth).await;
    page
}

/// Every regular file below `dir`, sorted.
pub fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next).unwrap() {
            let path = entry.unwrap().path();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

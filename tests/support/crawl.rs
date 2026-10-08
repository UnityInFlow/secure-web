//! Crawler test harness (PR-08): the MCP harness (fixture site + stub DNS + stub scanner + the
//! real `PageProcessor`) plus helpers to run a crawl directly and inspect what it did.
#![allow(dead_code)]

#[path = "mcp.rs"]
pub mod mcp;

use secure_web_core::config::Config;
use secure_web_crawl::{CancellationToken, CrawlOptions, CrawlReport};
use secure_web_store::Manifest;

pub use mcp::{files_under, Harness, Options};

/// A harness whose config `configure` adjusts (crawl budgets, fetch limits, …).
pub async fn harness(configure: fn(&mut Config)) -> Harness {
    Harness::with(Options {
        configure,
        ..Options::default()
    })
    .await
}

/// Crawl the fixture `path` with the harness config narrowed by `adjust`.
pub async fn crawl(
    harness: &Harness,
    path: &str,
    adjust: impl FnOnce(&mut CrawlOptions),
) -> CrawlReport {
    crawl_with(harness, path, adjust, CancellationToken::new()).await
}

/// [`crawl`] with a caller-held cancellation token.
pub async fn crawl_with(
    harness: &Harness,
    path: &str,
    adjust: impl FnOnce(&mut CrawlOptions),
    cancel: CancellationToken,
) -> CrawlReport {
    let mut options = CrawlOptions::from_config(harness.app.config());
    adjust(&mut options);
    harness
        .app
        .crawler()
        .crawl(&harness.url(path), options, cancel)
        .await
        .unwrap()
}

/// The manifest on disk, loaded (and so validated) by `Manifest::load`.
pub fn load_manifest(report: &CrawlReport) -> Manifest {
    let manifest = Manifest::load(&report.manifest_path).unwrap();
    assert_eq!(manifest, report.manifest, "manifest on disk = report");
    manifest
}

/// Requests the fixture server received for exactly `path` (queries are not recorded).
pub fn requests_for(harness: &Harness, path: &str) -> usize {
    harness
        .fixture
        .requests()
        .iter()
        .filter(|p| p.as_str() == path)
        .count()
}

/// Every request path the fixture server received, sorted.
pub fn requests(harness: &Harness) -> Vec<String> {
    let mut requests = harness.fixture.requests();
    requests.sort();
    requests
}

/// Assert no canary appears in any file under the workspace `runs/`.
pub fn assert_runs_canary_free(harness: &Harness) {
    for file in files_under(&harness.runs_dir()) {
        let bytes = std::fs::read(&file).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        for canary in mcp::canaries::ALL {
            assert!(!text.contains(canary), "{canary} in {}", file.display());
        }
    }
}

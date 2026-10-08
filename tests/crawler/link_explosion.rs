//! T8 — link explosion: a bounded frontier, canonical dedupe and bounded concurrency
//! (`docs/tasks/PR-08-crawler.md`).
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

#[path = "../support/crawl.rs"]
mod crawl;

use crawl::{crawl, harness, load_manifest, requests, requests_for};
use secure_web_core::config::ExtractConfig;
use secure_web_store::RunStatus;

#[tokio::test]
async fn the_frontier_never_exceeds_max_frontier() {
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/links/huge", |o| {
        o.max_depth = 1;
        o.max_pages = 1000;
        o.max_frontier = 50;
    })
    .await;
    let manifest = load_manifest(&report);
    // 50 000 anchors, capped at maxLinksPerPage by the extractor; 50 queued, the rest dropped.
    let links = u64::from(ExtractConfig::default().max_links_per_page);
    assert_eq!(report.frontier_peak, 50);
    assert_eq!(report.frontier_dropped, links - 50);
    assert_eq!(h.fixture.requests().len(), 51);
    assert_eq!(manifest.documents.len(), 51);
    assert_eq!(manifest.status, RunStatus::Complete);
    // Admitted and dropped links both count as discovered.
    assert_eq!(manifest.stats.discovered, 1 + links);
}

#[tokio::test]
async fn fragments_tracking_params_and_param_order_are_fetched_once() {
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/links/dupes", |o| o.max_depth = 1).await;
    let manifest = load_manifest(&report);
    assert_eq!(requests_for(&h, "/clean/a"), 1);
    assert_eq!(requests_for(&h, "/clean/guide"), 1);
    assert_eq!(h.fixture.requests().len(), 3);
    assert_eq!(manifest.documents.len(), 3);
    assert_eq!(manifest.stats.discovered, 3);
    assert_eq!(manifest.status, RunStatus::Complete);
}

#[tokio::test]
async fn a_link_cycle_terminates() {
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/cycle/a", |o| o.max_depth = 5).await;
    let manifest = load_manifest(&report);
    assert_eq!(requests(&h), ["/cycle/a", "/cycle/b"]);
    assert_eq!(manifest.status, RunStatus::Complete);
    assert_eq!(manifest.documents.len(), 2);
}

#[tokio::test]
async fn concurrency_one_fetches_in_bfs_order() {
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/link/a", |o| {
        o.max_depth = 2;
        o.concurrency = 1;
    })
    .await;
    let manifest = load_manifest(&report);
    assert_eq!(h.fixture.requests(), ["/link/a", "/link/b", "/link/c"]);
    let depths: Vec<u32> = manifest.documents.iter().map(|d| d.depth).collect();
    assert_eq!(depths, [0, 1, 1]);
}

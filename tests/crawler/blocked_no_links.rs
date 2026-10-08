//! T14 — a blocked page seeds nothing: `PageOutcome::Blocked` carries no links by type, so the
//! crawler cannot follow a blocked page's links (invariant 6).
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

#[path = "../support/crawl.rs"]
mod crawl;

use crawl::{assert_runs_canary_free, crawl, harness, load_manifest, requests};
use secure_web_core::model::BlockReason;
use secure_web_store::RunStatus;

#[tokio::test]
async fn a_blocked_page_contributes_no_child_urls() {
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/blocked-with-links", |o| o.max_depth = 5).await;
    let manifest = load_manifest(&report);
    assert_eq!(requests(&h), ["/blocked-with-links"]);
    assert_eq!(manifest.stats.fetched, 1);
    assert_eq!(manifest.stats.blocked, 1);
    assert_eq!(manifest.stats.discovered, 1);
    assert!(manifest.documents.is_empty());
    assert_eq!(manifest.blocked[0].reason, BlockReason::PromptInjection);
    assert_eq!(manifest.status, RunStatus::Complete);
    assert_runs_canary_free(&h);
}

#[tokio::test]
async fn a_blocked_child_is_recorded_under_its_scanned_url_and_seeds_nothing() {
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/links/blocked-child", |o| o.max_depth = 1).await;
    let manifest = load_manifest(&report);
    assert_eq!(
        requests(&h),
        ["/clean/a", "/injection/direct", "/links/blocked-child"]
    );
    assert_eq!(manifest.documents.len(), 2);
    assert_eq!(manifest.blocked.len(), 1);
    let blocked = &manifest.blocked[0];
    assert_eq!(blocked.url.as_str(), h.url("/injection/direct"));
    assert_eq!(blocked.depth, 1);
    assert_eq!(blocked.reason, BlockReason::PromptInjection);
    assert_runs_canary_free(&h);
}

//! T7 — runaway crawl: depth, pages, total bytes and duration are hard limits, checked before
//! every fetch (`docs/tasks/PR-08-crawler.md`). Every limit is asserted with equality.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

#[path = "../support/crawl.rs"]
mod crawl;

use std::time::{Duration, Instant};

use crawl::{crawl, harness, load_manifest, requests, requests_for};
use secure_web_core::error::ErrorCode;
use secure_web_store::RunStatus;

#[tokio::test]
async fn depth_chain_with_max_depth_3_fetches_exactly_4_pages() {
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/depth/0", |o| o.max_depth = 3).await;
    let manifest = load_manifest(&report);
    assert_eq!(
        requests(&h),
        ["/depth/0", "/depth/1", "/depth/2", "/depth/3"]
    );
    assert_eq!(manifest.status, RunStatus::Complete);
    assert_eq!(manifest.documents.len(), 4);
    let depths: Vec<u32> = manifest.documents.iter().map(|d| d.depth).collect();
    assert_eq!(depths, [0, 1, 2, 3]);
    assert_eq!(manifest.stats.fetched, 4);
    // /depth/4 is never admitted (depth 4 > maxDepth), so it is not discovered either.
    assert_eq!(manifest.stats.discovered, 4);
    assert_eq!(manifest.policy.max_depth, 3);
}

#[tokio::test]
async fn huge_link_page_with_max_pages_10_makes_exactly_10_attempts() {
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/links/huge", |o| o.max_pages = 10).await;
    let manifest = load_manifest(&report);
    assert_eq!(h.fixture.requests().len(), 10);
    assert_eq!(requests_for(&h, "/links/huge"), 1);
    assert_eq!(manifest.status, RunStatus::LimitReached);
    let attempts = manifest.documents.len() + manifest.blocked.len() + manifest.failed.len();
    assert_eq!(attempts, 10);
    assert_eq!(manifest.stats.fetched, 10);
    assert_eq!(manifest.policy.max_pages, 10);
}

/// Size of one `/depth/<n>` page (n < 6, all the same length), from an unconstrained crawl.
async fn depth_page_bytes() -> u64 {
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/depth/0", |o| o.max_depth = 4).await;
    let manifest = load_manifest(&report);
    assert_eq!(manifest.documents.len(), 5);
    assert_eq!(manifest.stats.total_bytes % 5, 0);
    manifest.stats.total_bytes / 5
}

#[tokio::test]
async fn max_total_bytes_is_never_exceeded() {
    let page = depth_page_bytes().await;

    // Exactly three pages fit: the fourth has no budget left, so it never starts.
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/depth/0", |o| {
        o.max_depth = 5;
        o.max_total_bytes = 3 * page;
    })
    .await;
    let manifest = load_manifest(&report);
    assert_eq!(manifest.status, RunStatus::LimitReached);
    assert_eq!(requests(&h), ["/depth/0", "/depth/1", "/depth/2"]);
    assert_eq!(manifest.documents.len(), 3);
    assert_eq!(manifest.stats.total_bytes, 3 * page);
    assert!(manifest.failed.is_empty());

    // Three and a half pages: the fourth is fetched under a half-page cap, does not fit, and
    // is recorded as a limit (not a blocked page); nothing past it is fetched.
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/depth/0", |o| {
        o.max_depth = 5;
        o.max_total_bytes = 3 * page + page / 2;
    })
    .await;
    let manifest = load_manifest(&report);
    assert_eq!(manifest.status, RunStatus::LimitReached);
    assert_eq!(
        requests(&h),
        ["/depth/0", "/depth/1", "/depth/2", "/depth/3"]
    );
    assert_eq!(manifest.documents.len(), 3);
    assert_eq!(manifest.stats.total_bytes, 3 * page);
    assert!(manifest.stats.total_bytes <= 3 * page + page / 2);
    assert!(manifest.blocked.is_empty());
    assert_eq!(manifest.failed.len(), 1);
    assert_eq!(manifest.failed[0].code, ErrorCode::CrawlLimitReached);
    assert_eq!(manifest.failed[0].url.as_str(), h.url("/depth/3"));
}

#[tokio::test]
async fn max_duration_ends_the_crawl_with_a_partial_manifest() {
    let h = harness(|_| {}).await;
    let started = Instant::now();
    let report = crawl(&h, "/slowchain/0", |o| {
        o.max_depth = 5;
        o.max_duration = Duration::from_secs(1);
    })
    .await;
    let elapsed = started.elapsed();
    let manifest = load_manifest(&report);
    assert_eq!(manifest.status, RunStatus::LimitReached);
    assert!(manifest.finished_at.is_some());
    // Each page takes 300 ms to answer: some are stored, the chain is not finished.
    assert!(!manifest.documents.is_empty());
    assert!(manifest.documents.len() < 6, "{}", manifest.documents.len());
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    assert_eq!(manifest.policy.max_duration_ms, 1000);
    // Every listed page file exists (a valid partial corpus).
    for doc in &manifest.documents {
        assert!(report.run_dir.join(&doc.path).is_file(), "{}", doc.path);
    }
}

/// An already-spent budget starts no work: a zero `maxDuration` (reachable through the library
/// API) or a token cancelled before the crawl began never lets a fetch reach the site.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_spent_duration_or_a_prior_cancel_starts_no_fetch() {
    let h = harness(|_| {}).await;
    for _ in 0..25 {
        let report = crawl(&h, "/clean/a", |o| o.max_duration = Duration::ZERO).await;
        let manifest = load_manifest(&report);
        assert_eq!(manifest.status, RunStatus::LimitReached);
        assert_eq!(manifest.stats.fetched + manifest.stats.failed, 0);

        let cancel = secure_web_crawl::CancellationToken::new();
        cancel.cancel();
        let report = crawl::crawl_with(&h, "/clean/a", |_| {}, cancel).await;
        let manifest = load_manifest(&report);
        assert_eq!(manifest.status, RunStatus::Cancelled);
        assert_eq!(manifest.stats.fetched + manifest.stats.failed, 0);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(requests(&h), Vec::<String>::new());
}

/// `Retry-After` (brief design note): a `503` with `Retry-After: 7` is retried once after the
/// delay when the duration budget allows it, and the retry counts as a page attempt.
#[tokio::test]
async fn retry_after_is_honoured_once_within_budget() {
    let h = harness(|_| {}).await;
    let started = Instant::now();
    let report = crawl(&h, "/status/503", |o| o.max_pages = 5).await;
    let manifest = load_manifest(&report);
    assert_eq!(requests_for(&h, "/status/503"), 2, "{:?}", requests(&h));
    assert!(started.elapsed() >= Duration::from_secs(7));
    assert_eq!(manifest.failed.len(), 1);
    // The root failed twice: the run failed (not COMPLETE).
    assert_eq!(manifest.status, RunStatus::Failed);
}

/// The `Retry-After` retry never gets around a budget: not `maxPages` (it is an attempt), not
/// `maxDuration` (a delay past the deadline is not waited for), and not a cancel during the
/// delay. In each case the page is fetched exactly once.
#[tokio::test]
async fn retry_after_never_exceeds_a_budget() {
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/status/503", |o| o.max_pages = 1).await;
    let manifest = load_manifest(&report);
    assert_eq!(requests_for(&h, "/status/503"), 1);
    assert_eq!(manifest.failed.len(), 1);
    assert_eq!(manifest.status, RunStatus::Failed);

    let h = harness(|_| {}).await;
    let started = Instant::now();
    let report = crawl(&h, "/status/429", |o| {
        o.max_duration = Duration::from_secs(3);
    })
    .await;
    let manifest = load_manifest(&report);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(requests_for(&h, "/status/429"), 1);
    assert_eq!(manifest.failed.len(), 1);

    let h = harness(|_| {}).await;
    let cancel = secure_web_crawl::CancellationToken::new();
    let trigger = cancel.clone();
    let started = Instant::now();
    let crawl = crawl::crawl_with(&h, "/status/503", |_| {}, cancel);
    let fire = async {
        while h.fixture.requests().is_empty() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        trigger.cancel();
    };
    let (report, ()) = tokio::join!(crawl, fire);
    let manifest = load_manifest(&report);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(manifest.status, RunStatus::Cancelled);
    assert_eq!(requests_for(&h, "/status/503"), 1);
    // The completed first attempt is still recorded, once (ADR-019).
    assert_eq!(manifest.failed.len(), 1);
}

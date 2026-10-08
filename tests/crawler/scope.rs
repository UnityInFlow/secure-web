//! Crawl scope (ADR-004): `SAME_ORIGIN` by default, `ALLOWLIST` with explicit hosts, path
//! include/exclude patterns — and the guard's raw-text rules on every crawled link (ADR-018).
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

#[path = "../support/crawl.rs"]
mod crawl;

use crawl::mcp::scanner::extract::fetch::fixture_server::{FIXTURE_HOST, SECOND_HOST};
use crawl::{crawl, harness, load_manifest, requests, requests_for};
use secure_web_core::config::CrawlScope;
use secure_web_core::error::ErrorCode;
use secure_web_crawl::{CancellationToken, CrawlError, CrawlOptions, ScopeError};
use secure_web_store::RunStatus;

#[tokio::test]
async fn same_origin_does_not_follow_cross_origin_private_or_mailto_links() {
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/link/a", |o| o.max_depth = 3).await;
    let manifest = load_manifest(&report);
    // /link/c links to https://example.com/external, http://127.0.0.1:<port>/clean/a,
    // mailto: and #section: none is followed, so none is even attempted.
    assert_eq!(requests(&h), ["/link/a", "/link/b", "/link/c"]);
    assert!(manifest.failed.is_empty(), "{:?}", manifest.failed);
    assert!(manifest.blocked.is_empty());
    assert_eq!(manifest.stats.discovered, 3);
    assert_eq!(manifest.status, RunStatus::Complete);
}

#[tokio::test]
async fn same_origin_ignores_a_second_host() {
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/scope/multi", |o| o.max_depth = 1).await;
    let manifest = load_manifest(&report);
    assert_eq!(
        requests(&h),
        ["/clean/guide", "/clean/post", "/other/x", "/scope/multi"]
    );
    assert!(manifest
        .failed
        .iter()
        .all(|f| f.url.host_str() == Some(FIXTURE_HOST)));
}

#[tokio::test]
async fn allowlist_follows_only_the_listed_hosts() {
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/scope/multi", |o| {
        o.max_depth = 1;
        o.scope = CrawlScope::Allowlist;
        o.allowed_hosts = vec![FIXTURE_HOST.to_owned(), SECOND_HOST.to_owned()];
    })
    .await;
    let manifest = load_manifest(&report);
    // The second host is followed: the guard then refuses it (the test allowance covers only
    // the fixture name, ADR-011), before any request is made.
    let second: Vec<_> = manifest
        .failed
        .iter()
        .filter(|f| f.url.host_str() == Some(SECOND_HOST))
        .collect();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].code, ErrorCode::SsrfBlocked);
    assert_eq!(requests_for(&h, "/clean/a"), 0);
    assert_eq!(requests_for(&h, "/clean/post"), 1);

    // Only the fixture host listed: the second host is not followed at all.
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/scope/multi", |o| {
        o.max_depth = 1;
        o.scope = CrawlScope::Allowlist;
        o.allowed_hosts = vec![FIXTURE_HOST.to_owned()];
    })
    .await;
    let second_manifest = load_manifest(&report);
    assert!(second_manifest
        .failed
        .iter()
        .all(|f| f.url.host_str() == Some(FIXTURE_HOST)));
    assert_eq!(requests_for(&h, "/clean/post"), 1);
}

#[tokio::test]
async fn allowlist_without_hosts_is_refused_before_any_run() {
    let h = harness(|_| {}).await;
    let mut options = CrawlOptions::from_config(h.app.config());
    options.scope = CrawlScope::Allowlist;
    options.allowed_hosts.clear();
    let err = h
        .app
        .crawler()
        .crawl(&h.url("/scope/multi"), options, CancellationToken::new())
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CrawlError::Scope(ScopeError::AllowlistWithoutHosts)
    ));
    assert!(h.fixture.requests().is_empty());
    assert!(!h.runs_dir().exists() || std::fs::read_dir(h.runs_dir()).unwrap().count() == 0);
}

#[tokio::test]
async fn include_and_exclude_patterns_narrow_the_scope() {
    let h = harness(|_| {}).await;
    crawl(&h, "/scope/multi", |o| {
        o.max_depth = 1;
        o.include_patterns = vec!["^/clean/".to_owned()];
        o.exclude_patterns = vec!["guide$".to_owned()];
    })
    .await;
    assert_eq!(requests(&h), ["/clean/post", "/scope/multi"]);
}

/// Carried over from PR-07 (`docs/backlog.md`, ADR-018): a crawled link is validated as
/// written, so the guard's raw-text rules apply to it — here an empty userinfo `@` that the
/// parse would silently drop.
#[tokio::test]
async fn raw_text_guard_rules_apply_to_crawled_links() {
    let h = harness(|_| {}).await;
    let report = crawl(&h, "/links/raw", |o| o.max_depth = 1).await;
    let manifest = load_manifest(&report);
    assert_eq!(requests_for(&h, "/clean/b"), 0);
    assert_eq!(requests_for(&h, "/clean/a"), 1);
    assert_eq!(manifest.failed.len(), 1);
    assert_eq!(manifest.failed[0].url.as_str(), h.url("/clean/b"));
    assert_eq!(manifest.failed[0].code, ErrorCode::InvalidUrl);
}

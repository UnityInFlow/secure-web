//! Cancellation (deep-dive §82): a cancelled crawl stops scheduling, aborts in-flight pages and
//! still writes a valid partial manifest (`CANCELLED`); a cancelled `web_open` never leaves a
//! `RUNNING` manifest (carried over from PR-07).
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

#[path = "../support/crawl.rs"]
mod crawl;

use std::time::{Duration, Instant};

use crawl::{crawl_with, harness, load_manifest};
use secure_web_crawl::{CancellationToken, OpenError};
use secure_web_mcp::SecureWebServer;
use secure_web_store::{Manifest, RunStatus};
use serde_json::json;

#[tokio::test]
async fn cancel_after_three_pages_writes_a_partial_manifest() {
    let h = harness(|_| {}).await;
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    let crawl = crawl_with(
        &h,
        "/links/huge",
        |o| {
            o.max_depth = 1;
            o.max_pages = 1000;
            o.concurrency = 1;
        },
        cancel,
    );
    let watch = async {
        while h.fixture.requests().len() < 3 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        trigger.cancel();
    };
    let (report, ()) = tokio::join!(crawl, watch);
    let manifest = load_manifest(&report);
    assert_eq!(manifest.status, RunStatus::Cancelled);
    assert!(manifest.finished_at.is_some());
    assert!(!manifest.documents.is_empty());
    assert!(manifest.documents.len() < 1000);
    for doc in &manifest.documents {
        assert!(report.run_dir.join(&doc.path).is_file(), "{}", doc.path);
    }
    // Nothing is scheduled after the cancel.
    let after = h.fixture.requests().len();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(h.fixture.requests().len(), after);
}

#[tokio::test]
async fn a_cancelled_open_finishes_its_run_cancelled() {
    let h = harness(|_| {}).await;
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    let started = Instant::now();
    let url = h.url("/slow");
    let open = h.app.processor().open_cancellable(&url, &cancel);
    let fire = async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        trigger.cancel();
    };
    let (result, ()) = tokio::join!(open, fire);
    assert!(started.elapsed() < Duration::from_secs(5));
    let Err(OpenError::Cancelled { manifest_path, .. }) = result else {
        panic!("expected Cancelled, got {result:?}");
    };
    let manifest = Manifest::load(&manifest_path).unwrap();
    assert_eq!(manifest.status, RunStatus::Cancelled);
    assert!(manifest.finished_at.is_some());
    assert!(manifest.documents.is_empty() && manifest.blocked.is_empty());
    assert!(manifest.failed.is_empty());
}

#[tokio::test]
async fn a_cancelled_web_open_call_ends_crawl_cancelled_with_a_terminal_run() {
    let h = harness(|_| {}).await;
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    let started = Instant::now();
    let server = SecureWebServer::new(h.app.clone());
    let call = server.call_cancellable(
        "web_open",
        json!({ "url": h.url("/slow") }).as_object().cloned(),
        cancel,
    );
    let fire = async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        trigger.cancel();
    };
    let (response, ()) = tokio::join!(call, fire);
    let response = response.unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(response.is_error);
    assert_eq!(response.exit_code, 7);
    let error = &response.body["error"];
    assert_eq!(error["code"], "CRAWL_CANCELLED");
    assert_eq!(error["retryable"], true);
    let path = error["details"]["manifestPath"].as_str().unwrap();
    let manifest = Manifest::load(std::path::Path::new(path)).unwrap();
    assert_eq!(manifest.status, RunStatus::Cancelled);
}

#[tokio::test]
async fn a_cancelled_web_crawl_call_returns_a_cancelled_result() {
    let h = harness(|_| {}).await;
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    let server = SecureWebServer::new(h.app.clone());
    let call = server.call_cancellable(
        "web_crawl",
        json!({ "url": h.url("/slowchain/0"), "maxDepth": 5 })
            .as_object()
            .cloned(),
        cancel,
    );
    let fire = async {
        tokio::time::sleep(Duration::from_millis(700)).await;
        trigger.cancel();
    };
    let (response, ()) = tokio::join!(call, fire);
    let response = response.unwrap();
    assert!(!response.is_error, "{}", response.body);
    assert_eq!(response.exit_code, 7);
    assert_eq!(response.body["status"], "CANCELLED");
    assert!(response.body["summary"]
        .as_str()
        .unwrap()
        .contains("The crawl was cancelled."));
    let path = response.body["manifestPath"].as_str().unwrap();
    let manifest = Manifest::load(std::path::Path::new(path)).unwrap();
    assert_eq!(manifest.status, RunStatus::Cancelled);
    assert!(!manifest.documents.is_empty());
}

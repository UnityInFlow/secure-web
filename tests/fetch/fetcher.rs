//! `HttpFetcher` behaviour against the fixture server: content types, statuses, timeouts,
//! encodings (`docs/tasks/PR-03-fetcher.md`).
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../support/fetch.rs"]
mod fetch;

use std::time::{Duration, Instant};

use secure_web_core::config::FetchConfig;
use secure_web_core::error::ErrorCode;
use secure_web_core::model::BlockReason;
use secure_web_fetch::{ContentType, FetchError};

use fetch::fixture_server::MIME_STALL;
use fetch::Harness;

#[tokio::test]
async fn clean_html_is_fetched_with_metadata() {
    let h = Harness::start().await;
    let before = chrono::Utc::now();
    let response = h.fetch("/clean/a").await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, ContentType::Html);
    assert_eq!(response.charset.as_deref(), Some("utf-8"));
    assert_eq!(response.requested_url, response.final_url);
    assert!(response.redirect_chain.is_empty());
    assert_eq!(response.decompressed_bytes, response.body.len() as u64);
    assert!(response.retrieved_at >= before);
    assert!(String::from_utf8_lossy(&response.body).contains("Getting started"));
}

#[tokio::test]
async fn markdown_text_and_json_are_classified() {
    let h = Harness::start().await;
    let cases = [
        ("/clean/guide", ContentType::Markdown),
        ("/clean/notes", ContentType::PlainText),
        ("/clean/data", ContentType::Json),
    ];
    for (path, expected) in cases {
        assert_eq!(
            h.fetch(path).await.unwrap().content_type,
            expected,
            "{path}"
        );
    }
}

#[tokio::test]
async fn debug_output_does_not_contain_the_body_or_path() {
    let h = Harness::start().await;
    let response = h.fetch("/injection/direct").await.unwrap();
    let debug = format!("{response:?}");
    for canary in fetch::fixture_server::canaries::ALL {
        assert!(!debug.contains(canary));
    }
    assert!(!debug.contains("/injection/direct"));
}

#[tokio::test]
async fn slow_server_times_out() {
    let cfg = FetchConfig {
        request_timeout: Duration::from_millis(300),
        ..FetchConfig::default()
    };
    let h = Harness::with_config(cfg).await;
    let started = Instant::now();
    let err = h.fetch("/slow").await.unwrap_err();
    assert_eq!(err, FetchError::Timeout);
    assert_eq!(err.code(), ErrorCode::FetchTimeout);
    assert!(err.retryable());
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn unsupported_types_are_refused_without_downloading_the_body() {
    let h = Harness::start().await;
    for (path, essence) in [
        ("/mime/pdf", "application/pdf"),
        ("/mime/zip", "application/zip"),
    ] {
        let started = Instant::now();
        let err = h.fetch(path).await.unwrap_err();
        assert_eq!(
            err,
            FetchError::UnsupportedContentType {
                essence: essence.to_owned()
            }
        );
        assert_eq!(err.code(), ErrorCode::UnsupportedContentType);
        assert_eq!(
            err.block_reason(),
            Some(BlockReason::UnsupportedContentType)
        );
        // The server stalls before sending any body byte; returning early proves the fetcher
        // decided on the headers alone.
        assert!(
            started.elapsed() < MIME_STALL / 2,
            "{path} waited for the body"
        );
    }
    assert_eq!(h.server.stalled_body_bytes(), 0);
}

#[tokio::test]
async fn server_errors_are_retryable_and_client_errors_are_not() {
    let h = Harness::start().await;
    let server_error = h.fetch("/status/500").await.unwrap_err();
    assert_eq!(
        server_error,
        FetchError::Status {
            status: 500,
            retry_after: None
        }
    );
    assert_eq!(server_error.code(), ErrorCode::FetchFailed);
    assert!(server_error.retryable());
    assert_eq!(server_error.block_reason(), None);

    let not_found = h.fetch("/status/404").await.unwrap_err();
    assert_eq!(not_found.code(), ErrorCode::FetchFailed);
    assert!(!not_found.retryable());
}

#[tokio::test]
async fn retry_after_is_reported_on_429_and_503() {
    let h = Harness::start().await;
    for path in ["/status/429", "/status/503"] {
        let err = h.fetch(path).await.unwrap_err();
        assert!(err.retryable(), "{path}");
        assert_eq!(err.retry_after(), Some(Duration::from_secs(7)), "{path}");
    }
    // An HTTP-date in the past means "now".
    let err = h.fetch("/retry-after/date").await.unwrap_err();
    assert_eq!(err.retry_after(), Some(Duration::ZERO));
}

#[tokio::test]
async fn retry_after_is_ignored_when_disabled() {
    let cfg = FetchConfig {
        respect_retry_after: false,
        ..FetchConfig::default()
    };
    let h = Harness::with_config(cfg).await;
    let err = h.fetch("/status/503").await.unwrap_err();
    assert!(err.retryable());
    assert_eq!(err.retry_after(), None);
}

#[tokio::test]
async fn missing_content_type_is_sniffed() {
    let h = Harness::start().await;
    assert_eq!(
        h.fetch("/no-content-type/html").await.unwrap().content_type,
        ContentType::Html
    );
    assert_eq!(
        h.fetch("/no-content-type/text").await.unwrap().content_type,
        ContentType::PlainText
    );
    let err = h.fetch("/no-content-type/binary").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::UnsupportedContentType);
}

#[tokio::test]
async fn gzip_and_deflate_bodies_are_decoded() {
    let h = Harness::start().await;
    let gzip = h.fetch("/encoding/gzip").await.unwrap();
    assert_eq!(gzip.body, b"gzip body");
    assert_eq!(gzip.decompressed_bytes, 9);
    let deflate = h.fetch("/encoding/deflate").await.unwrap();
    assert!(String::from_utf8_lossy(&deflate.body).contains("deflate body"));
}

#[tokio::test]
async fn a_closed_port_is_a_retryable_network_failure() {
    let h = Harness::start().await;
    let target = h.target("/clean/a").await;
    drop(h.server);
    // Give the aborted accept loop a moment to release the listener.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let result = secure_web_fetch::Fetcher::fetch(
        &h.fetcher,
        secure_web_fetch::FetchRequest {
            target,
            limits: h.limits,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::FetchFailed, "{err:?}");
    assert!(err.retryable());
}

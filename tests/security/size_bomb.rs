//! T9 — decompression / size bombs (`docs/threat-model.md`, `docs/security-policy.md` §2).
//!
//! The byte counter runs on decompressed bytes, the stream is aborted the moment it passes the
//! limit, and `Content-Length` is a hint used only to refuse early, never to accept.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../support/fetch.rs"]
mod fetch;

use secure_web_core::config::FetchConfig;
use secure_web_core::error::ErrorCode;
use secure_web_core::model::BlockReason;
use secure_web_fetch::FetchError;

use fetch::{Harness, CHUNK_SLACK};

fn too_large(err: FetchError) -> (u64, u64) {
    assert_eq!(err.code(), ErrorCode::ContentTooLarge, "{err:?}");
    assert_eq!(err.block_reason(), Some(BlockReason::ContentTooLarge));
    assert!(!err.retryable());
    match err {
        FetchError::ContentTooLarge {
            limit,
            peak_buffered_bytes,
        } => (limit, peak_buffered_bytes),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn huge_body_is_aborted_at_the_page_limit() {
    let h = Harness::start().await;
    let (limit, peak) = too_large(h.fetch("/huge").await.unwrap_err());
    assert_eq!(limit, FetchConfig::default().max_page_bytes);
    assert!(
        peak <= limit + CHUNK_SLACK,
        "peak {peak} > limit {limit} + one chunk"
    );
}

#[tokio::test]
async fn gzip_bomb_is_aborted_on_decompressed_bytes() {
    let h = Harness::start().await;
    let (limit, peak) = too_large(h.fetch("/gzip-bomb").await.unwrap_err());
    assert_eq!(limit, FetchConfig::default().max_page_bytes);
    assert!(
        peak <= limit + CHUNK_SLACK,
        "peak {peak} > limit {limit} + one chunk"
    );
}

#[tokio::test]
async fn a_small_configured_limit_is_exact() {
    let cfg = FetchConfig {
        max_page_bytes: 1000,
        ..FetchConfig::default()
    };
    let h = Harness::with_config(cfg).await;
    let (limit, peak) = too_large(h.fetch("/gzip-bomb").await.unwrap_err());
    assert_eq!(limit, 1000);
    assert!(peak <= limit + CHUNK_SLACK);
    let (_, peak) = too_large(h.fetch("/huge").await.unwrap_err());
    assert!(peak <= 1000 + CHUNK_SLACK);
    // A page under the limit is still fetched.
    let small = h.fetch("/clean/guide").await.unwrap();
    assert!(small.decompressed_bytes <= 1000);
}

#[tokio::test]
async fn json_uses_the_json_limit() {
    let h = Harness::start().await;
    let (limit, _) = too_large(h.fetch("/json/big").await.unwrap_err());
    assert_eq!(limit, FetchConfig::default().max_json_bytes);
}

#[tokio::test]
async fn a_short_content_length_never_lets_more_bytes_through() {
    // The server declares 64 bytes and then streams 8 MiB. Only the declared bytes are read;
    // the rest is never buffered.
    let h = Harness::start().await;
    match h.fetch("/lying-length/short").await {
        Ok(response) => assert_eq!(response.body.len(), 64),
        Err(err) => {
            let (limit, peak) = too_large(err);
            assert!(peak <= limit + CHUNK_SLACK);
        }
    }
}

#[tokio::test]
async fn a_lying_short_length_on_a_huge_stream_is_still_capped_by_the_counter() {
    let cfg = FetchConfig {
        max_page_bytes: 32,
        ..FetchConfig::default()
    };
    let h = Harness::with_config(cfg).await;
    let (limit, peak) = too_large(h.fetch("/lying-length/short").await.unwrap_err());
    assert_eq!(limit, 32);
    assert!(peak <= 32 + CHUNK_SLACK);
}

#[tokio::test]
async fn an_oversized_content_length_is_refused_before_reading() {
    let h = Harness::start().await;
    let (_, peak) = too_large(h.fetch("/lying-length/long").await.unwrap_err());
    assert_eq!(peak, 0, "refused on the header, nothing buffered");
}

#[tokio::test]
async fn stacked_and_unknown_content_encodings_are_refused() {
    let h = Harness::start().await;
    for path in ["/encoding/gzip-gzip", "/encoding/br"] {
        let err = h.fetch(path).await.unwrap_err();
        assert_eq!(err, FetchError::UnsupportedContentEncoding, "{path}");
        assert_eq!(err.code(), ErrorCode::UnsupportedContentType);
    }
}

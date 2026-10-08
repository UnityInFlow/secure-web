//! Bounded extraction work on hostile input (`docs/security-policy.md` §3, ADR-013): size caps
//! map to `CONTENT_TOO_LARGE`, and pathological HTML (deep nesting, huge attribute lists, many
//! nodes), Markdown and JSON finish quickly without recursion-driven stack overflows.
//!
//! Every input here is at most the fetcher's 5 MiB page cap.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../support/extract.rs"]
mod extract;

use std::time::{Duration, Instant};

use extract::{extract_str, fetch_extract_with, Harness};
use secure_web_core::error::ErrorCode;
use secure_web_core::model::BlockReason;
use secure_web_extract::markdown::render;
use secure_web_extract::{ExtractError, ExtractLimits, ExtractedDocument, SourceKind};

/// The fetcher's default `maxPageBytes`.
const PAGE_CAP: usize = 5 * 1024 * 1024;

/// Generous wall-clock bound for one extraction of a capped page in an unoptimized test build.
/// Quadratic behaviour on these inputs takes minutes (the html5ever bake-off in ADR-013).
const BOUND: Duration = Duration::from_secs(10);

const C: &str = "ZQX-CANARY-0000-BOUNDS";

fn timed(
    body: &str,
    kind: SourceKind,
    limits: ExtractLimits,
) -> (Result<ExtractedDocument, ExtractError>, Duration) {
    assert!(body.len() <= PAGE_CAP, "fixture exceeds the page cap");
    let start = Instant::now();
    let result = extract_str(body, kind, "http://fixture.test/page", limits);
    (result, start.elapsed())
}

/// Success, or the node cap (`CONTENT_TOO_LARGE`) — both are bounded, fail-closed outcomes.
fn bounded_outcome(result: &Result<ExtractedDocument, ExtractError>) -> bool {
    matches!(result, Ok(_) | Err(ExtractError::TooManyNodes { .. }))
}

fn roomy() -> ExtractLimits {
    ExtractLimits {
        max_security_text_bytes: 16 * 1024 * 1024,
        max_links_per_page: 2000,
        max_display_bytes: 16 * 1024 * 1024,
    }
}

#[test]
fn deeply_nested_blocks_are_linear_and_hidden_text_stays_hidden() {
    let depth = 500_000;
    let mut body = String::from("<p>top</p>");
    body.push_str(&"<div>".repeat(depth));
    body.push_str(&format!("<div style=\"display:none\">{C}</div>deep"));
    let (result, elapsed) = timed(&body, SourceKind::Html, roomy());
    let doc = result.unwrap();
    assert!(elapsed < BOUND, "{elapsed:?}");
    assert!(doc.security_text.contains(C));
    let markdown = render(&doc.display);
    assert!(!markdown.contains(C));
    assert!(markdown.contains("deep"));
}

// `deeply_nested_inline_and_table_elements_are_bounded` lives in `secure-web-extract`
// (`src/html.rs` tests): it bounds the extraction *work* with the crate's test-only counters,
// which an integration test cannot reach, instead of a wall-clock time that machine load skews.

#[test]
fn deeply_nested_lists_and_quotes_render_without_recursion_blowup() {
    let depth = 100_000;
    for (open, close) in [
        ("<ul><li>", "</li></ul>"),
        ("<blockquote>", "</blockquote>"),
    ] {
        let body = format!("{}{C}-visible{}", open.repeat(depth), close.repeat(depth));
        let (result, elapsed) = timed(&body, SourceKind::Html, roomy());
        let doc = result.unwrap();
        assert!(elapsed < BOUND, "{open}: {elapsed:?}");
        assert!(render(&doc.display).contains(&format!("{C}-visible")));
    }
}

#[test]
fn a_huge_attribute_list_is_linear() {
    // html5ever's tokenizer checks duplicate attributes with a linear scan per attribute
    // (quadratic); html5gum's map-based check is not.
    let mut body = String::from("<div");
    let mut i = 0;
    while body.len() < PAGE_CAP - 64 {
        body.push_str(&format!(" a{i}=\"v\""));
        i += 1;
    }
    body.push_str(&format!(" title=\"{C}\">x</div>"));
    let (result, elapsed) = timed(&body, SourceKind::Html, roomy());
    let doc = result.unwrap();
    assert!(elapsed < BOUND, "{elapsed:?}");
    assert!(doc.security_text.contains(C));
}

#[test]
fn too_many_nodes_is_content_too_large() {
    let body = "<i>".repeat(PAGE_CAP / 3);
    let (result, elapsed) = timed(&body, SourceKind::Html, roomy());
    let err = result.unwrap_err();
    assert!(matches!(err, ExtractError::TooManyNodes { .. }), "{err:?}");
    assert_eq!(err.error_code(), ErrorCode::ContentTooLarge);
    assert!(elapsed < BOUND, "{elapsed:?}");
}

#[test]
fn max_security_text_bytes_is_enforced() {
    let limits = ExtractLimits {
        max_security_text_bytes: 1024,
        ..ExtractLimits::default()
    };
    // Hidden text counts: a page that looks tiny can still be too large to scan.
    let body = format!("<p>small</p><!-- {} -->", "x".repeat(2000));
    let err = extract_str(&body, SourceKind::Html, "http://fixture.test/", limits).unwrap_err();
    assert_eq!(err, ExtractError::SecurityTextTooLarge { limit: 1024 });
    assert_eq!(err.error_code(), ErrorCode::ContentTooLarge);
    assert_eq!(err.block_reason(), BlockReason::ContentTooLarge);
    // Attributes count too.
    let body = format!("<p data-x=\"{}\">small</p>", "y".repeat(2000));
    assert!(extract_str(&body, SourceKind::Html, "http://fixture.test/", limits).is_err());
    for kind in [
        SourceKind::PlainText,
        SourceKind::Markdown,
        SourceKind::Json,
    ] {
        let body = format!("\"{}\"", "z".repeat(2000));
        let err = extract_str(&body, kind, "http://fixture.test/", limits).unwrap_err();
        assert_eq!(err.error_code(), ErrorCode::ContentTooLarge, "{kind:?}");
    }
    // Under the limit is fine.
    assert!(extract_str(
        "<p>small</p>",
        SourceKind::Html,
        "http://fixture.test/",
        limits
    )
    .is_ok());
}

#[tokio::test]
async fn max_security_text_bytes_applies_to_fetched_pages() {
    let harness = Harness::start().await;
    let limits = ExtractLimits {
        max_security_text_bytes: 64,
        ..ExtractLimits::default()
    };
    let err = fetch_extract_with(&harness, "/injection/hidden-css", limits)
        .await
        .unwrap_err();
    assert_eq!(err.error_code(), ErrorCode::ContentTooLarge);
}

#[test]
fn max_display_bytes_is_enforced() {
    let limits = ExtractLimits {
        max_display_bytes: 100,
        ..ExtractLimits::default()
    };
    let body = format!("<p>{}</p>", "word ".repeat(100));
    let err = extract_str(&body, SourceKind::Html, "http://fixture.test/", limits).unwrap_err();
    assert_eq!(err, ExtractError::DisplayTooLarge { limit: 100 });
    assert_eq!(err.error_code(), ErrorCode::ContentTooLarge);
}

#[test]
fn pathological_markdown_is_bounded() {
    for body in [
        ">".repeat(PAGE_CAP / 2),
        "- ".repeat(PAGE_CAP / 4),
        "[".repeat(PAGE_CAP / 2),
        "*a".repeat(PAGE_CAP / 4),
        "<div>".repeat(PAGE_CAP / 10),
    ] {
        let (result, elapsed) = timed(&body, SourceKind::Markdown, roomy());
        assert!(bounded_outcome(&result), "{result:?}");
        assert!(elapsed < BOUND, "{elapsed:?}");
    }
}

#[test]
fn deeply_nested_json_falls_back_to_text() {
    let body = format!("{}{}", "[".repeat(200_000), "]".repeat(200_000));
    let (result, elapsed) = timed(&body, SourceKind::Json, roomy());
    let doc = result.unwrap();
    assert!(elapsed < BOUND, "{elapsed:?}");
    assert_eq!(doc.display.blocks.len(), 1);
}

#[test]
fn leaving_rendered_lines_to_the_visible_section_is_linear() {
    // Each in-place line is looked up in the rendered Markdown; lines display escapes are never
    // found (every lookup misses), lines behind long link URLs are found far away. Both stay
    // linear, and a line that is not found verbatim stays in place.
    let lines = PAGE_CAP / 4;
    let long = "u".repeat(4000);
    let cases = [
        (
            format!("<p>{}</p>", "a_\n".repeat(lines)),
            SourceKind::Html,
            "a_",
        ),
        ("a_\n".repeat(lines), SourceKind::PlainText, "a_"),
        (
            format!("<p>{}</p>", "ab\n".repeat(lines)),
            SourceKind::Html,
            "ab",
        ),
        (
            format!(
                "<p>{}</p>",
                format!("<a href=\"/{long}\">x</a>\n").repeat(1200)
            ),
            SourceKind::Html,
            "x",
        ),
    ];
    for (body, kind, line) in cases {
        let (result, elapsed) = timed(&body, kind, roomy());
        let doc = result.unwrap();
        assert!(elapsed < BOUND, "{kind:?} {line}: {elapsed:?}");
        assert!(doc.security_text.contains(line));
        assert!(doc.security_text.contains(&render(&doc.display)));
    }
}

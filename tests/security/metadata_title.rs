//! T4 (title injection) and the T13 title/slug rules (`docs/threat-model.md`,
//! `docs/security-policy.md` §7): titles are normalized and always scanned; slugs are ASCII
//! `[a-z0-9-]{0,48}` whatever the title.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../support/scanner.rs"]
mod scanner;

use scanner::extract;

use extract::extract_html;
use proptest::prelude::*;
use secure_web_extract::title::{normalize_title, slug, MAX_SLUG_LEN, MAX_TITLE_CHARS};

fn title_of(raw_title: &str) -> Option<String> {
    extract_html(&format!(
        "<html><head><title>{raw_title}</title></head><body><p>x</p></body></html>"
    ))
    .title
}

#[test]
fn control_and_bidi_characters_are_stripped() {
    assert_eq!(
        title_of("Re\u{0007}lease\u{001B}[31m \u{202E}sgnirts\u{202C} notes").as_deref(),
        Some("Release[31m sgnirts notes")
    );
    assert_eq!(
        title_of("  many \n\t spaces  ").as_deref(),
        Some("many spaces")
    );
}

#[test]
fn title_is_nfc_normalized() {
    assert_eq!(title_of("Cafe\u{0301}").as_deref(), Some("Caf\u{00E9}"));
}

#[test]
fn a_10000_char_title_is_capped() {
    let title = title_of(&"A".repeat(10_000)).unwrap();
    assert_eq!(title.chars().count(), MAX_TITLE_CHARS);
    // The whole raw <title> is still scanned.
    let doc = extract_html(&format!("<title>{}</title>", "A".repeat(10_000)));
    assert!(doc.security_text.contains(&"A".repeat(10_000)));
}

#[test]
fn path_traversal_title_is_plain_text_and_slugs_safely() {
    let title = title_of("../../etc/passwd").unwrap();
    assert_eq!(title, "../../etc/passwd");
    assert_eq!(slug(&title), "etc-passwd");
    assert_eq!(slug("..\\..\\windows\\system32"), "windows-system32");
}

#[test]
fn title_falls_back_to_og_title_then_first_visible_h1() {
    let og = extract_html(
        "<head><meta property=\"og:title\" content=\" OG  title \"></head><h1>Heading</h1>",
    );
    assert_eq!(og.title.as_deref(), Some("OG title"));
    let h1 = extract_html("<div hidden><h1>Hidden</h1></div><h1>Visible <b>one</b></h1>");
    assert_eq!(h1.title.as_deref(), Some("Visible one"));
    assert_eq!(extract_html("<p>no title</p>").title, None);
    assert_eq!(title_of(" \u{200B} "), None);
}

#[test]
fn every_title_source_is_scanned() {
    for (html, title) in [
        ("<title>From title</title>", "From title"),
        (
            "<meta name=\"og:title\" content=\"From og\"><p>x</p>",
            "From og",
        ),
        ("<h1>From h1</h1>", "From h1"),
    ] {
        let doc = extract_html(html);
        assert_eq!(doc.title.as_deref(), Some(title));
        assert!(
            doc.security_text
                .ends_with(&format!("[hidden:title]\n{title}\n")),
            "{html}: {:?}",
            doc.security_text
        );
        assert_eq!(doc.display.title.as_deref(), Some(title));
    }
}

#[test]
fn slug_examples() {
    assert_eq!(slug("Getting started"), "getting-started");
    assert_eq!(slug("Crème brûlée — 2026!"), "creme-brulee-2026");
    assert_eq!(slug("---"), "");
    assert_eq!(slug(""), "");
    assert_eq!(slug("日本語のページ"), "");
}

proptest! {
    #[test]
    fn slug_matches_the_filename_whitelist(input in any::<String>()) {
        let out = slug(&input);
        prop_assert!(out.len() <= MAX_SLUG_LEN);
        prop_assert!(out.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
        prop_assert!(!out.starts_with('-') && !out.ends_with('-') && !out.contains("--"));
    }

    #[test]
    fn slug_of_normalized_titles_matches_the_whitelist(input in "\\PC{0,300}") {
        if let Some(title) = normalize_title(&input) {
            let out = slug(&title);
            prop_assert!(out.len() <= MAX_SLUG_LEN);
            prop_assert!(out.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
        }
    }

    #[test]
    fn normalized_titles_are_bounded_and_clean(input in any::<String>()) {
        if let Some(title) = normalize_title(&input) {
            prop_assert!(title.chars().count() <= MAX_TITLE_CHARS);
            prop_assert!(!title.chars().any(|c| c.is_control() || secure_web_extract::textclean::is_stripped(c)));
            prop_assert_eq!(title.trim(), title.as_str());
            prop_assert!(!title.contains("  "));
            // Idempotent.
            prop_assert_eq!(normalize_title(&title), Some(title.clone()));
        }
    }
}

/// An injection in `<title>` alone is scanned and blocks the page; the blocked document has no
/// title field at all, so the title cannot leak (T4, `docs/security-policy.md` §6–7).
#[cfg(unix)]
#[tokio::test]
async fn title_injection_is_blocked_and_the_title_is_not_emitted() {
    use scanner::canaries::CANARY_TITLE;
    use secure_web_core::model::BlockReason;

    let harness = scanner::Harness::start().await;
    let (doc, outcome) = scanner::process(&harness, "/injection/title").await;
    assert!(doc.display.title.as_deref().unwrap().contains(CANARY_TITLE));
    let blocked = outcome.unwrap_err();
    assert_eq!(blocked.reason, BlockReason::PromptInjection);
    assert_eq!(blocked.finding_ids, ["PI001"]);
    let json = serde_json::to_string(&blocked).unwrap();
    assert!(!json.contains(CANARY_TITLE));
    assert!(!json.contains("Ignore all previous instructions"));
    assert!(!format!("{blocked:?}").contains(CANARY_TITLE));
}

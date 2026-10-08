//! T1 — direct prompt injection (`docs/threat-model.md`, `docs/security-policy.md` §4–5).
//!
//! Fixture pages go through fetch → extract → stub scanner (`canary` mode) → `accept()`. An
//! injected page is blocked with ids only; clean pages are accepted; LOW findings are recorded
//! but accepted `SAFE`; MEDIUM findings are accepted as `WARN`.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

#[path = "../support/scanner.rs"]
mod scanner;

use scanner::{process, process_html, stub_scanner, Harness};
use secure_web_core::model::{BlockReason, SecurityDecision, Severity};

#[tokio::test]
async fn direct_injection_is_blocked_with_ids_only() {
    let harness = Harness::start().await;
    for path in [
        "/injection/direct",
        "/injection/json",
        "/blocked-with-links",
    ] {
        let (_, outcome) = process(&harness, path).await;
        let blocked = outcome.expect_err(path);
        assert_eq!(blocked.reason, BlockReason::PromptInjection, "{path}");
        assert_eq!(blocked.finding_ids, ["PI001"], "{path}");
        assert_eq!(blocked.max_severity, Some(Severity::Critical), "{path}");
        assert_eq!(
            blocked.scanner_version.as_deref(),
            Some("injection-scanner 0.1.0-stub")
        );
        assert_eq!(blocked.final_url.as_ref().unwrap().path(), path);
    }
}

#[tokio::test]
async fn clean_fixtures_are_accepted_safe() {
    let harness = Harness::start().await;
    for name in ["a", "post", "layout", "guide", "notes", "data"] {
        let path = format!("/clean/{name}");
        let (doc, outcome) = process(&harness, &path).await;
        let accepted = outcome.unwrap_or_else(|b| panic!("{path} blocked: {:?}", b.reason));
        assert_eq!(
            accepted.security().decision,
            SecurityDecision::Safe,
            "{path}"
        );
        assert!(accepted.security().finding_ids.is_empty(), "{path}");
        assert_eq!(accepted.security().max_severity, None);
        // Markdown comes from display and was part of the scanned text.
        assert!(!accepted.markdown().is_empty(), "{path}");
        assert!(doc.security_text.contains(accepted.markdown()), "{path}");
        assert_eq!(accepted.links(), doc.links);
        assert_eq!(accepted.provenance().http_status, 200);
    }
}

#[tokio::test]
async fn low_finding_is_recorded_but_safe() {
    let scanner = stub_scanner("canary").await;
    let (_, outcome) = process_html("<p>A MILD remark about deadlines.</p>", &scanner).await;
    let accepted = outcome.unwrap();
    assert_eq!(accepted.security().decision, SecurityDecision::Safe);
    assert_eq!(accepted.security().max_severity, Some(Severity::Low));
    assert_eq!(accepted.security().finding_ids, ["PI900"]);
}

#[tokio::test]
async fn medium_finding_is_accepted_as_warn() {
    let scanner = stub_scanner("canary").await;
    let (_, outcome) = process_html("<p>Please STUB-MEDIUM consider this.</p>", &scanner).await;
    let accepted = outcome.unwrap();
    assert_eq!(accepted.security().decision, SecurityDecision::Warn);
    assert_eq!(accepted.security().max_severity, Some(Severity::Medium));
    assert_eq!(accepted.security().finding_ids, ["PI500"]);
}

#[tokio::test]
async fn strictest_finding_wins() {
    let scanner = stub_scanner("canary").await;
    let (_, outcome) = process_html(
        "<p>MILD</p><p>STUB-MEDIUM</p><p>ZQX-CANARY-strict</p>",
        &scanner,
    )
    .await;
    let blocked = outcome.unwrap_err();
    assert_eq!(blocked.reason, BlockReason::PromptInjection);
    assert_eq!(blocked.max_severity, Some(Severity::Critical));
    assert_eq!(blocked.finding_ids, ["PI900", "PI500", "PI001"]);
}

#[tokio::test]
async fn low_confidence_matches_never_decide() {
    let scanner = stub_scanner("canary").await;
    let findings = secure_web_security::injection::SecurityScanner::scan(&scanner, "STUB-LOWCONF")
        .await
        .unwrap();
    assert_eq!(findings.low_confidence_count, 1);
    assert!(findings.findings.is_empty());
    let (_, outcome) = process_html("<p>STUB-LOWCONF</p>", &scanner).await;
    assert_eq!(outcome.unwrap().security().decision, SecurityDecision::Safe);
}

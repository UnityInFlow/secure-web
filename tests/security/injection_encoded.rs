//! T2 — encoded injection (`docs/threat-model.md`). The base64 payload reaches the scanner
//! intact (inside `security_text`), and a finding on it blocks the page like any other.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

#[path = "../support/scanner.rs"]
mod scanner;

use scanner::canaries::CANARY_B64;
use scanner::{process, Harness};
use secure_web_core::model::{BlockReason, Severity};

#[tokio::test]
async fn base64_injection_is_blocked() {
    let harness = Harness::start().await;
    let (doc, outcome) = process(&harness, "/injection/base64").await;
    // The canary is only present encoded: the scanner decodes, Secure Web never does.
    assert!(!doc.security_text.contains(CANARY_B64));
    let blocked = outcome.unwrap_err();
    assert_eq!(blocked.reason, BlockReason::PromptInjection);
    assert_eq!(blocked.finding_ids, ["PI001"]);
    assert_eq!(blocked.max_severity, Some(Severity::Critical));
}

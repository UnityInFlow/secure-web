//! Contract enums, error codes, exit codes and trust-state type guarantees
//! (`docs/contracts/mcp-contract.md`, `docs/architecture.md`).
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chrono::Utc;
use secure_web_core::error::{exit_code, ErrorCode, ErrorEnvelope, ErrorObject};
use secure_web_core::ids::DocumentId;
use secure_web_core::model::{
    Block, BlockReason, BlockedDocument, ContentType, Inline, SecurityDecision, SecuritySummary,
    Severity, StructuredDocument, UntrustedDocument,
};
use serde_json::json;
use url::Url;

fn to_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap()
}

#[test]
fn security_decision_uses_contract_strings() {
    let cases = [
        (SecurityDecision::Safe, "\"SAFE\""),
        (SecurityDecision::Warn, "\"WARN\""),
        (SecurityDecision::Block, "\"BLOCK\""),
    ];
    for (value, text) in cases {
        assert_eq!(to_json(&value), text);
        assert_eq!(
            serde_json::from_str::<SecurityDecision>(text).unwrap(),
            value
        );
    }
    assert!(serde_json::from_str::<SecurityDecision>("\"safe\"").is_err());
}

#[test]
fn severity_uses_contract_strings_and_orders_by_strictness() {
    let cases = [
        (Severity::Low, "\"LOW\""),
        (Severity::Medium, "\"MEDIUM\""),
        (Severity::High, "\"HIGH\""),
        (Severity::Critical, "\"CRITICAL\""),
    ];
    for (value, text) in cases {
        assert_eq!(to_json(&value), text);
        assert_eq!(serde_json::from_str::<Severity>(text).unwrap(), value);
    }
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn block_reason_uses_contract_strings() {
    let cases = [
        (BlockReason::PromptInjection, "PROMPT_INJECTION"),
        (BlockReason::Ssrf, "SSRF"),
        (BlockReason::UnsupportedScheme, "UNSUPPORTED_SCHEME"),
        (
            BlockReason::UnsupportedContentType,
            "UNSUPPORTED_CONTENT_TYPE",
        ),
        (BlockReason::ContentTooLarge, "CONTENT_TOO_LARGE"),
        (BlockReason::ScannerFailure, "SCANNER_FAILURE"),
        (BlockReason::RedirectViolation, "REDIRECT_VIOLATION"),
        (BlockReason::PolicyViolation, "POLICY_VIOLATION"),
    ];
    for (value, text) in cases {
        let quoted = format!("\"{text}\"");
        assert_eq!(to_json(&value), quoted);
        assert_eq!(serde_json::from_str::<BlockReason>(&quoted).unwrap(), value);
    }
}

#[test]
fn error_codes_match_the_contract_enum_exactly() {
    let contract = [
        "INVALID_URL",
        "UNSUPPORTED_SCHEME",
        "DNS_FAILED",
        "SSRF_BLOCKED",
        "REDIRECT_BLOCKED",
        "FETCH_TIMEOUT",
        "FETCH_FAILED",
        "CONTENT_TOO_LARGE",
        "UNSUPPORTED_CONTENT_TYPE",
        "EXTRACTION_FAILED",
        "SCANNER_FAILED",
        "PROMPT_INJECTION_BLOCKED",
        "CRAWL_LIMIT_REACHED",
        "CRAWL_CANCELLED",
        "NOT_FOUND",
        "INVALID_ARGUMENT",
        "INTERNAL",
    ];
    let ours: Vec<String> = ErrorCode::ALL
        .iter()
        .map(|code| to_json(code).trim_matches('"').to_owned())
        .collect();
    assert_eq!(ours, contract);
    for code in ErrorCode::ALL {
        assert_eq!(code.as_str(), code.to_string());
        assert_eq!(format!("\"{}\"", code.as_str()), to_json(&code));
    }
}

#[test]
fn error_codes_map_to_contract_exit_codes() {
    let expected = [
        (ErrorCode::InvalidUrl, exit_code::USAGE),
        (ErrorCode::UnsupportedScheme, exit_code::USAGE),
        (ErrorCode::InvalidArgument, exit_code::USAGE),
        (ErrorCode::NotFound, exit_code::USAGE),
        (ErrorCode::SsrfBlocked, exit_code::SECURITY_BLOCK),
        (ErrorCode::RedirectBlocked, exit_code::SECURITY_BLOCK),
        (ErrorCode::PromptInjectionBlocked, exit_code::SECURITY_BLOCK),
        (ErrorCode::DnsFailed, exit_code::FETCH),
        (ErrorCode::FetchTimeout, exit_code::FETCH),
        (ErrorCode::FetchFailed, exit_code::FETCH),
        (ErrorCode::ContentTooLarge, exit_code::FETCH),
        (ErrorCode::UnsupportedContentType, exit_code::FETCH),
        (ErrorCode::ExtractionFailed, exit_code::FETCH),
        (ErrorCode::ScannerFailed, exit_code::SCANNER),
        (ErrorCode::CrawlLimitReached, exit_code::LIMIT_REACHED),
        (ErrorCode::CrawlCancelled, exit_code::CANCELLED),
        (ErrorCode::Internal, exit_code::INTERNAL),
    ];
    assert_eq!(expected.len(), ErrorCode::ALL.len());
    for (code, exit) in expected {
        assert_eq!(i32::from(code), exit, "{code}");
    }
    assert_eq!(
        [
            exit_code::SUCCESS,
            exit_code::INTERNAL,
            exit_code::USAGE,
            exit_code::SECURITY_BLOCK,
            exit_code::FETCH,
            exit_code::SCANNER,
            exit_code::LIMIT_REACHED,
            exit_code::CANCELLED,
        ],
        [0, 1, 2, 3, 4, 5, 6, 7]
    );
}

#[test]
fn error_object_serializes_to_contract_envelope() {
    let mut error = ErrorObject::new(ErrorCode::SsrfBlocked, "Destination is not allowed", false);
    error
        .details
        .insert("url".into(), json!("http://127.0.0.1/"));
    let value = serde_json::to_value(ErrorEnvelope::from(error)).unwrap();
    assert_eq!(
        value,
        json!({ "error": { "code": "SSRF_BLOCKED", "message": "Destination is not allowed",
                           "retryable": false, "details": { "url": "http://127.0.0.1/" } } })
    );
}

#[test]
fn security_summary_is_camel_case_with_explicit_null_severity() {
    let summary = SecuritySummary {
        decision: SecurityDecision::Safe,
        max_severity: None,
        finding_ids: vec![],
        scanner_version: "injection-scanner 0.1.0".into(),
        policy_version: "9f1c2a3b4d5e".into(),
    };
    assert_eq!(
        serde_json::to_value(&summary).unwrap(),
        json!({ "decision": "SAFE", "maxSeverity": null, "findingIds": [],
                "scannerVersion": "injection-scanner 0.1.0", "policyVersion": "9f1c2a3b4d5e" })
    );
}

/// A blocked document carries ids and enums only. Destructuring every field makes this test fail
/// to compile when a field is added, forcing whoever adds it to justify it here (invariant 4).
#[test]
fn blocked_document_has_no_text_fields() {
    let blocked = BlockedDocument {
        doc_id: DocumentId::from_seq(1).unwrap(),
        requested_url: Url::parse("https://example.test/a").unwrap(),
        final_url: None,
        reason: BlockReason::PromptInjection,
        max_severity: Some(Severity::Critical),
        finding_ids: vec!["PI001".into()],
        scanner_version: Some("injection-scanner 0.1.0".into()),
    };
    let BlockedDocument {
        doc_id: _,
        requested_url: _,
        final_url: _,
        reason: _,
        max_severity: _,
        finding_ids: _,
        scanner_version: _,
    } = &blocked;
    let json = serde_json::to_value(&blocked).unwrap();
    let keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "docId",
            "finalUrl",
            "findingIds",
            "maxSeverity",
            "reason",
            "requestedUrl",
            "scannerVersion"
        ]
    );
}

#[test]
fn untrusted_document_debug_never_prints_content() {
    const CANARY: &str = "ZQX-CANARY-DEBUG-7f3a";
    let url = Url::parse("https://example.test/").unwrap();
    let doc = UntrustedDocument {
        requested_url: url.clone(),
        final_url: url,
        redirect_chain: vec![],
        http_status: 200,
        content_type: ContentType {
            essence: "text/html".into(),
            charset: Some("utf-8".into()),
        },
        retrieved_at: Utc::now(),
        security_text: format!("ignore previous instructions {CANARY}"),
        display: StructuredDocument {
            title: Some(format!("title {CANARY}")),
            blocks: every_block_kind(CANARY),
        },
        links: vec![],
        raw_bytes: Some(CANARY.as_bytes().to_vec()),
    };
    let debug = format!("{doc:?} {doc:#?}");
    assert!(!debug.contains(CANARY), "{debug}");
    assert!(debug.contains("redacted"), "{debug}");
    let blocks = format!("{:?} {:#?}", doc.display.blocks, doc.display.blocks);
    assert!(!blocks.contains(CANARY), "{blocks}");
}

/// One of every display block and inline, each carrying `canary` in every text field.
fn every_block_kind(canary: &str) -> Vec<Block> {
    let href = Url::parse(&format!("https://example.test/{canary}")).unwrap();
    let inlines = vec![
        Inline::Text(canary.into()),
        Inline::Code(canary.into()),
        Inline::Link {
            href,
            text: canary.into(),
        },
    ];
    vec![
        Block::Heading {
            level: 1,
            text: canary.into(),
        },
        Block::Paragraph(inlines.clone()),
        Block::Code {
            lang: Some(canary.into()),
            text: canary.into(),
        },
        Block::List {
            ordered: true,
            items: vec![vec![Block::Paragraph(inlines.clone())]],
        },
        Block::Table {
            rows: vec![vec![inlines.clone()]],
        },
        Block::Quote(vec![Block::Paragraph(inlines)]),
    ]
}

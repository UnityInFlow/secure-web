//! Parser contract for `injection-scanner 0.1.0` (`docs/security-policy.md` §4), driven by the
//! verbatim output pinned in `tests/contracts/scanner_output.json`. Runs unconditionally: it
//! needs no scanner binary.
//!
//! Proves that `matched_text`, `context`, `message`, `remediation` and the per-match `file` are
//! dropped at parse time, and that the known PI018 false positive (our own tool-description
//! boilerplate) is blocked at the policy layer, not silently swallowed (§10).
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use secure_web_core::config::SecurityConfig;
use secure_web_core::model::{BlockReason, Finding, SecurityFindings, Severity};
use secure_web_security::injection::{parse_output, parse_version, RawFinding};
use secure_web_security::policy::{PolicyEngine, PolicyOutcome, SecurityPolicy};
use serde_json::Value;

/// Match fields that carry page or scanner text and must never survive parsing.
const TEXT_FIELDS: [&str; 5] = ["matched_text", "context", "message", "remediation", "file"];

fn fixture() -> Value {
    let raw = include_str!("scanner_output.json");
    serde_json::from_str(raw).unwrap()
}

fn cases() -> Vec<Value> {
    fixture()["cases"].as_array().unwrap().clone()
}

fn case(name: &str) -> Value {
    cases()
        .into_iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("no fixture case {name}"))
}

fn findings_of(case: &Value) -> SecurityFindings {
    let stdout = serde_json::to_vec(&case["stdout"]).unwrap();
    let exit = i32::try_from(case["exitCode"].as_i64().unwrap()).unwrap();
    let version = fixture()["version"].as_str().unwrap().to_owned();
    parse_output(&stdout, exit)
        .unwrap_or_else(|err| panic!("case {}: {err}", case["name"]))
        .into_findings(version, Duration::from_millis(1))
}

/// Every string value of the text-bearing fields of every match in the fixture (the per-match
/// `file` is `<stdin>`, which appears nowhere in a Secure Web value either).
fn text_values(case: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for report in case["stdout"].as_array().unwrap() {
        for list in ["matches", "low_confidence", "suppressed", "baselined"] {
            for finding in report[list].as_array().unwrap() {
                for field in TEXT_FIELDS {
                    if let Some(text) = finding[field].as_str() {
                        out.push(text.to_owned());
                    }
                }
            }
        }
    }
    out
}

#[test]
fn every_pinned_case_parses() {
    type Expected<'a> = (&'a str, &'a str, Severity);
    let expected: [(&str, &[Expected]); 4] = [
        (
            "injected",
            &[
                ("PI001", "ignore-previous-instructions", Severity::Critical),
                ("PI021", "post-system-prompt", Severity::Critical),
            ],
        ),
        ("clean", &[]),
        ("empty", &[]),
        (
            "pi018-false-positive",
            &[("PI018", "priority-escalation", Severity::High)],
        ),
    ];
    assert_eq!(cases().len(), expected.len(), "fixture cases changed");
    for (name, want) in expected {
        let findings = findings_of(&case(name));
        let got: Vec<(&str, &str, Severity)> = findings
            .findings
            .iter()
            .map(|f| (f.id.as_str(), f.detector.as_str(), f.severity))
            .collect();
        assert_eq!(got, want, "case {name}");
        assert_eq!(
            findings.max_severity,
            want.iter().map(|w| w.2).max(),
            "case {name}"
        );
        assert_eq!(findings.low_confidence_count, 0);
        assert_eq!(findings.scanner_version, "injection-scanner 0.1.0");
        assert!(findings.findings.iter().all(|f| f.line == 1));
    }
    let injected = findings_of(&case("injected"));
    assert_eq!(injected.findings[0].confidence, 1.0);
    assert!((findings_of(&case("pi018-false-positive")).findings[0].confidence - 0.9).abs() < 1e-6);
}

/// `RawFinding` and `Finding` have exactly these fields. Exhaustive destructuring stops compiling
/// if a field is added, so nobody can quietly add a slot for `matched_text` (invariant 4).
#[test]
fn parsed_types_have_no_text_bearing_fields() {
    let stdout = serde_json::to_vec(&case("injected")["stdout"]).unwrap();
    let output = parse_output(&stdout, 1).unwrap();
    let RawFinding {
        pattern_id,
        pattern_name,
        severity: _,
        line: _,
        confidence: _,
    } = &output.matches[0];
    assert_eq!(
        (pattern_id.as_str(), pattern_name.as_str()),
        ("PI001", "ignore-previous-instructions")
    );

    let findings = output.into_findings("injection-scanner 0.1.0".into(), Duration::ZERO);
    let Finding {
        id: _,
        severity: _,
        detector: _,
        line: _,
        confidence: _,
    } = &findings.findings[0];
    let SecurityFindings {
        scanner_version: _,
        findings: _,
        low_confidence_count: _,
        max_severity: _,
        scan_duration: _,
    } = &findings;

    let json = serde_json::to_value(&findings).unwrap();
    for finding in json["findings"].as_array().unwrap() {
        let mut keys: Vec<&str> = finding
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["confidence", "detector", "id", "line", "severity"]);
    }
}

#[test]
fn matched_text_never_survives_parsing() {
    for case in cases() {
        let findings = findings_of(&case);
        let json = serde_json::to_string(&findings).unwrap();
        let debug = format!("{findings:?}");
        let stdout = serde_json::to_vec(&case["stdout"]).unwrap();
        let exit = i32::try_from(case["exitCode"].as_i64().unwrap()).unwrap();
        let output_debug = format!("{:?}", parse_output(&stdout, exit).unwrap());
        for text in text_values(&case) {
            assert!(!json.contains(&text), "{}: {text:?} in JSON", case["name"]);
            assert!(
                !debug.contains(&text),
                "{}: {text:?} in Debug",
                case["name"]
            );
            if text != "<stdin>" {
                assert!(
                    !output_debug.contains(&text),
                    "{}: {text:?} in ScannerOutput Debug",
                    case["name"]
                );
            }
        }
        // The scanned input itself never appears either.
        let stdin = case["stdin"].as_str().unwrap();
        if !stdin.is_empty() {
            assert!(!json.contains(stdin));
        }
    }
    // The fixture really does carry the text we check for.
    assert!(text_values(&case("injected")).contains(&"Ignore all previous instructions".to_owned()));
}

#[test]
fn pinned_decisions() {
    let policy = PolicyEngine::new(&SecurityConfig::default()).unwrap();
    let block = PolicyOutcome::Block(BlockReason::PromptInjection);
    assert_eq!(policy.decide(&findings_of(&case("injected"))), block);
    assert_eq!(
        policy.decide(&findings_of(&case("clean"))),
        PolicyOutcome::Safe
    );
    assert_eq!(
        policy.decide(&findings_of(&case("empty"))),
        PolicyOutcome::Safe
    );
    // Known false positive (docs/security-policy.md §10): our own boilerplate trips PI018 HIGH.
    // It is blocked, documented and pinned here — never silently accepted or dropped.
    assert_eq!(
        policy.decide(&findings_of(&case("pi018-false-positive"))),
        block
    );
}

#[test]
fn pinned_version_line_is_accepted() {
    let version = fixture()["version"].as_str().unwrap().to_owned();
    assert_eq!(
        parse_version(format!("{version}\n").as_bytes()).unwrap(),
        version
    );
}

#[test]
fn pinned_command_matches_the_adapter() {
    // The fixture was recorded without the hardening flags; the adapter always adds them.
    let command = fixture()["command"].as_str().unwrap().to_owned();
    let args = secure_web_security::injection::SCANNER_ARGS.join(" ");
    assert!(args.starts_with(command.trim_start_matches("injection-scanner ")));
    assert!(args.ends_with("--no-suppress --strict"));
}

//! Invariant 4 / ADR-005 — blocked payload text never leaves the security pipeline.
//!
//! Every injection fixture is fetched, extracted, scanned by the stub (whose output echoes the
//! offending line in `matched_text`, `context`, `message` and `remediation`) and blocked. Then
//! the JSON and `Debug` forms of everything the pipeline hands onward — `BlockedDocument`,
//! `SecuritySummary`, `PolicyOutcome`, `SecurityFindings` — plus every log line emitted at any
//! level, must contain no canary and no line of the page's `security_text`.
//!
//! PR-06 (threat T11): the same pages recorded in a corpus run leave no canary and no
//! security-text line anywhere under `runs/`; with `debug.retainRaw` the raw content exists
//! only under `private-audit/`, owner-only.
//!
//! PR-07: the same pages opened through the real MCP server (`web_open` over streamable HTTP)
//! and through the CLI's tool path leave no canary and no security-text line in any raw MCP
//! response body, any file under `runs/`, or any log line at any level.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

#[path = "../support/mcp.rs"]
mod mcp;

use mcp::store;

use store::scanner;

use std::io::Write;
use std::sync::{Arc, Mutex};

use scanner::canaries::ALL as CANARIES;
use scanner::{ctx, policy, process_with, stub_scanner, Harness};
use secure_web_core::model::{BlockedDocument, SecurityDecision, SecuritySummary};
use secure_web_security::decision::scan_and_accept;
use secure_web_security::injection::SecurityScanner;
use secure_web_security::policy::SecurityPolicy;
use url::Url;

const ROUTES: [&str; 8] = [
    "/injection/direct",
    "/injection/base64",
    "/injection/hidden-css",
    "/injection/comment",
    "/injection/title",
    "/injection/alt",
    "/injection/json",
    "/blocked-with-links",
];

/// The exact JSON keys a `BlockedDocument` may have (`docs/security-policy.md` §6).
const BLOCKED_KEYS: [&str; 7] = [
    "docId",
    "finalUrl",
    "findingIds",
    "maxSeverity",
    "reason",
    "requestedUrl",
    "scannerVersion",
];

/// Log output captured from a `tracing` subscriber at `TRACE`.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Logs {
    fn capture(&self) -> tracing::subscriber::DefaultGuard {
        let logs = self.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || logs.clone())
            .finish();
        tracing::subscriber::set_default(subscriber)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// Fail if `output` contains a canary, or any non-URL line (≥ 8 bytes) of `security_text`.
fn assert_no_leak(what: &str, output: &str, security_text: &str) {
    for canary in CANARIES {
        assert!(
            !output.contains(canary),
            "{what}: canary {canary} leaked:\n{output}"
        );
    }
    assert!(
        !output.contains("Ignore all previous instructions"),
        "{what}:\n{output}"
    );
    for line in security_text.lines().map(str::trim) {
        if line.len() < 8 || Url::parse(line).is_ok() {
            continue;
        }
        assert!(
            !output.contains(line),
            "{what}: security_text line {line:?} leaked:\n{output}"
        );
    }
}

fn summary_of(blocked: &BlockedDocument, policy_version: &str) -> SecuritySummary {
    SecuritySummary {
        decision: SecurityDecision::Block,
        max_severity: blocked.max_severity,
        finding_ids: blocked.finding_ids.clone(),
        scanner_version: blocked.scanner_version.clone().unwrap_or_default(),
        policy_version: policy_version.to_owned(),
    }
}

#[tokio::test]
async fn blocked_fixtures_leak_nothing() {
    let logs = Logs::default();
    let _guard = logs.capture();
    let harness = Harness::start().await;
    let scanner = stub_scanner("canary").await;
    let policy = policy();

    for path in ROUTES {
        let (doc, outcome) = process_with(&harness, path, &scanner).await;
        let blocked = outcome.expect_err(path);

        // What the scanner said, and the policy's view of it.
        let findings = scanner.scan(&doc.security_text).await.unwrap();
        let decision = policy.decide(&findings);
        let summary = summary_of(&blocked, policy.policy_version());

        let outputs = [
            (
                "BlockedDocument JSON",
                serde_json::to_string(&blocked).unwrap(),
            ),
            ("BlockedDocument Debug", format!("{blocked:?} {blocked:#?}")),
            (
                "SecuritySummary JSON",
                serde_json::to_string(&summary).unwrap(),
            ),
            ("SecuritySummary Debug", format!("{summary:?}")),
            (
                "PolicyOutcome JSON",
                serde_json::to_string(&decision).unwrap(),
            ),
            ("PolicyOutcome Debug", format!("{decision:?}")),
            (
                "SecurityFindings JSON",
                serde_json::to_string(&findings).unwrap(),
            ),
            ("SecurityFindings Debug", format!("{findings:?}")),
            ("UntrustedDocument Debug", format!("{doc:?}")),
        ];
        for (what, output) in &outputs {
            assert_no_leak(&format!("{path} {what}"), output, &doc.security_text);
        }

        let json = serde_json::to_value(&blocked).unwrap();
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, BLOCKED_KEYS, "{path}");
    }

    // Also the failure path: a crashing scanner and one whose --version echoes page-like text.
    for mode in ["crash", "bad-version", "garbage", "huge"] {
        let failing = stub_scanner(mode).await;
        let (doc, outcome) = process_with(&harness, "/injection/direct", &failing).await;
        let blocked = outcome.unwrap_err();
        let output = format!("{} {blocked:?}", serde_json::to_string(&blocked).unwrap());
        assert_no_leak(mode, &output, &doc.security_text);
        assert!(!output.contains("ZQX-CANARY-VERSION"), "{mode}");
    }

    let log_text = logs.text();
    assert!(
        log_text.contains("injection scan failed"),
        "log capture is not working:\n{log_text}"
    );
    assert!(!log_text.contains("ZQX-CANARY-VERSION"));
    for canary in CANARIES {
        assert!(
            !log_text.contains(canary),
            "canary {canary} in logs:\n{log_text}"
        );
    }
    assert!(!log_text.contains("Ignore all previous instructions"));
}

/// A document the stub flags only on a hidden line is blocked; accepting pages leak nothing of
/// the hidden text through the accepted Markdown either.
#[tokio::test]
async fn accepted_pages_expose_only_scanned_display_text() {
    let scanner = stub_scanner("canary").await;
    let (doc, outcome) = scanner::process_html(
        "<p>Visible paragraph.</p><!-- private MILD note -->",
        &scanner,
    )
    .await;
    let accepted = outcome.unwrap();
    assert_eq!(accepted.security().decision, SecurityDecision::Safe);
    assert!(!accepted.markdown().contains("private"));
    assert!(doc.security_text.contains("private MILD note"));
    assert!(doc.security_text.contains(accepted.markdown()));
    let summary = serde_json::to_string(&accepted.security()).unwrap();
    assert!(!summary.contains("private"));
}

/// `scan_and_accept` never needs the text again once blocked: the `BlockedDocument` it returns
/// is the same whatever the page said.
#[tokio::test]
async fn blocked_documents_do_not_depend_on_page_text() {
    let harness = Harness::start().await;
    let scanner = stub_scanner("canary").await;
    let (doc_a, a) = process_with(&harness, "/injection/hidden-css", &scanner).await;
    let (_, b) = process_with(&harness, "/injection/comment", &scanner).await;
    let (mut a, mut b) = (a.unwrap_err(), b.unwrap_err());
    a.requested_url = b.requested_url.clone();
    a.final_url = b.final_url.clone();
    assert_eq!(a, b);
    // And the same document blocks identically on a second pass.
    b = scan_and_accept(doc_a, &scanner, &policy(), &ctx(1))
        .await
        .unwrap_err();
    assert_eq!(b.finding_ids, ["PI001"]);
}

/// Record every injection fixture (plus one clean page) in a corpus run, with and without
/// `retainRaw`, and grep the whole workspace.
#[tokio::test]
async fn corpus_runs_leak_nothing_outside_private_audit() {
    use std::os::unix::fs::PermissionsExt;

    use secure_web_core::config::WarnHandling;
    use secure_web_store::{RunStats, RunStatus};

    let logs = Logs::default();
    let _guard = logs.capture();
    let harness = Harness::start().await;
    let scanner = stub_scanner("canary").await;

    for retain_raw in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let store = store::store_with(tmp.path(), retain_raw, WarnHandling::Store);
        let writer = store
            .begin_run(store::spec(
                "crawl_0000000c0a11",
                &harness.url("/"),
                &scanner,
            ))
            .await
            .unwrap();
        let mut blocked_texts = Vec::new();
        for path in ROUTES.iter().chain(["/dup/a"].iter()) {
            let resp = harness.fetch(path).await.unwrap();
            let extracted = secure_web_extract::Extractor::extract(
                &secure_web_extract::ContentExtractor::new(Default::default()),
                &scanner::extract::input(&resp),
            )
            .unwrap();
            let mut doc = scanner::untrusted(&resp, extracted);
            doc.raw_bytes = Some(resp.body.clone());
            let id = writer.next_doc_id().unwrap();
            let page = store::scan(&scanner, doc, id, 1).await;
            if page.outcome.is_err() {
                blocked_texts.push(page.doc.security_text.clone());
            } else {
                assert_eq!(*path, "/dup/a");
            }
            store::record(&writer, &page, 1).await;
        }
        assert_eq!(blocked_texts.len(), ROUTES.len());
        let manifest = writer
            .finish(RunStatus::Complete, RunStats::default())
            .await
            .unwrap();
        assert_eq!(manifest.blocked.len(), ROUTES.len());
        assert_eq!(manifest.documents.len(), 1);

        let runs = store.runs_dir().to_path_buf();
        for file in store::files_under(&runs) {
            let text = String::from_utf8_lossy(&std::fs::read(&file).unwrap()).into_owned();
            for security_text in &blocked_texts {
                assert_no_leak(&file.display().to_string(), &text, security_text);
            }
        }

        let audit_files = store::files_under(store.audit_root());
        if retain_raw {
            // 9 security texts + 9 raw bodies, all owner-only, and the canaries are there.
            assert_eq!(audit_files.len(), 2 * (ROUTES.len() + 1));
            let mut seen = 0;
            for file in &audit_files {
                let mode = std::fs::metadata(file).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode & 0o077, 0, "{} is {mode:o}", file.display());
                let text = String::from_utf8_lossy(&std::fs::read(file).unwrap()).into_owned();
                seen += usize::from(CANARIES.iter().any(|c| text.contains(c)));
            }
            assert!(
                seen >= ROUTES.len(),
                "canaries retained in {seen} audit files"
            );
            let dir = audit_files[0].parent().unwrap();
            let dir_mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode & 0o077, 0, "{dir_mode:o}");
            assert!(!store.audit_root().starts_with(&runs));
        } else {
            assert!(audit_files.is_empty());
        }
    }

    let log_text = logs.text();
    assert!(
        log_text.contains("document_security_decision"),
        "audit events missing:\n{log_text}"
    );
    for canary in CANARIES {
        assert!(!log_text.contains(canary), "canary {canary} in logs");
    }
    assert!(!log_text.contains("Ignore all previous instructions"));
}

/// PR-07: every injection fixture through `web_open` — MCP over streamable HTTP (with and
/// without `inline`) and the CLI's direct tool path — is a `BLOCK` result, and nothing an agent
/// or an operator's default log can see carries its text. The retained security texts under
/// `private-audit/` are the reference for "its text".
#[tokio::test]
async fn mcp_responses_runs_and_logs_leak_nothing() {
    let logs = Logs::default();
    let _guard = logs.capture();
    let harness = mcp::Harness::start().await;
    let (mut client, _) = mcp::Client::connect(&harness.mcp_url).await;

    let mut cli_bodies = String::new();
    for route in ROUTES {
        for inline in [false, true] {
            let (result, is_error) = client
                .call(
                    "web_open",
                    serde_json::json!({ "url": harness.url(route), "inline": inline }),
                )
                .await;
            assert!(!is_error, "{route}: {result}");
            assert_eq!(result["status"], "BLOCK", "{route}");
            assert_eq!(result["block"]["reason"], "PROMPT_INJECTION", "{route}");
            for field in ["title", "content", "contentPath", "truncated"] {
                assert!(result.get(field).is_none(), "{route}: {field}");
            }
        }
        let response = harness
            .call_direct("web_open", serde_json::json!({ "url": harness.url(route) }))
            .await;
        assert_eq!(response.exit_code, 3, "{route}");
        cli_bodies.push_str(&response.body.to_string());
    }

    // The reference texts: what the scanner read for each blocked page.
    let audit = mcp::files_under(&harness.audit_dir());
    let sectexts: Vec<String> = audit
        .iter()
        .filter(|f| f.extension().is_some_and(|e| e == "sectext"))
        .map(|f| std::fs::read_to_string(f).unwrap())
        .collect();
    assert_eq!(sectexts.len(), 3 * ROUTES.len());
    // Every fixture but the base64 one carries a literal canary.
    let with_canary = sectexts
        .iter()
        .filter(|text| CANARIES.iter().any(|c| text.contains(c)))
        .count();
    assert!(with_canary >= 3 * (ROUTES.len() - 1), "{with_canary}");

    let transcript = client.transcript_text();
    let log_text = logs.text();
    let run_files: Vec<(String, String)> = mcp::files_under(&harness.runs_dir())
        .into_iter()
        .map(|f| {
            (
                f.display().to_string(),
                String::from_utf8_lossy(&std::fs::read(&f).unwrap()).into_owned(),
            )
        })
        .collect();
    assert!(!run_files.is_empty());
    for security_text in &sectexts {
        assert_no_leak("MCP responses", &transcript, security_text);
        assert_no_leak("CLI tool results", &cli_bodies, security_text);
        assert_no_leak("logs", &log_text, security_text);
        for (name, text) in &run_files {
            assert_no_leak(name, text, security_text);
        }
    }
    assert!(
        log_text.contains("web_open finished") && log_text.contains("document_security_decision"),
        "logs were not captured:\n{log_text}"
    );
}

/// A redirect target is chosen by the server, so its text is untrusted Internet content. When
/// that text is what the scanner blocked, it must not come back as the block's `finalUrl` in
/// the MCP result, the CLI result, the manifest or the metadata file (invariant 4). The
/// agent's own requested URL may still be echoed: the agent wrote it.
#[tokio::test]
async fn a_blocked_redirect_target_is_not_echoed() {
    let harness = mcp::Harness::start().await;
    let (mut client, _) = mcp::Client::connect(&harness.mcp_url).await;
    let requested = harness.url("/redirect/canary");
    let (result, is_error) = client
        .call("web_open", serde_json::json!({ "url": requested }))
        .await;
    assert!(!is_error, "{result}");
    assert_eq!(result["status"], "BLOCK", "{result}");
    assert_eq!(result["block"]["reason"], "PROMPT_INJECTION", "{result}");
    assert_eq!(result["url"], requested.as_str());
    assert!(result["finalUrl"].is_null(), "{result}");
    assert!(result["block"]["finalUrl"].is_null(), "{result}");

    let cli = harness
        .call_direct("web_open", serde_json::json!({ "url": requested }))
        .await;
    assert_eq!(cli.exit_code, 3);

    let transcript = client.transcript_text();
    let cli_body = cli.body.to_string();
    let run_files = mcp::files_under(&harness.runs_dir());
    assert!(!run_files.is_empty());
    for canary in CANARIES {
        assert!(
            !transcript.contains(canary),
            "MCP transcript leaks {canary}"
        );
        assert!(!cli_body.contains(canary), "CLI result leaks {canary}");
        for file in &run_files {
            let text = String::from_utf8_lossy(&std::fs::read(file).unwrap()).into_owned();
            assert!(!text.contains(canary), "{} leaks {canary}", file.display());
        }
    }
}

/// A redirect target (and, for crawled pages, the requested link) is server-chosen text that
/// has not been scanned yet: `UntrustedDocument`'s `Debug` must not print it (ADR-005). Nor may
/// `BlockedDocument`'s, whose `final_url` still holds it until `PageProcessor` withholds it —
/// whether the scanner blocked the page or crashed on it.
#[tokio::test]
async fn untrusted_document_debug_redacts_urls() {
    let harness = Harness::start().await;
    for mode in ["crash", "canary"] {
        let (_, outcome) =
            process_with(&harness, "/redirect/canary", &stub_scanner(mode).await).await;
        let blocked = outcome.expect_err("the canary page is blocked");
        assert!(
            blocked
                .final_url
                .as_ref()
                .is_some_and(|u| u.as_str().contains("ZQX-CANARY")),
            "{mode}: the blocked result no longer carries the canary final URL"
        );
        let blocked_debug = format!("{blocked:?} {blocked:#?} {:?}", Err::<(), _>(&blocked));
        for canary in CANARIES {
            assert!(
                !blocked_debug.contains(canary),
                "{mode}: BlockedDocument Debug leaks {canary}:\n{blocked_debug}"
            );
        }
    }
    let (doc, _) = process_with(&harness, "/redirect/canary", &stub_scanner("canary").await).await;
    assert!(
        doc.final_url.as_str().contains("ZQX-CANARY"),
        "fixture no longer redirects to a canary URL: {}",
        doc.final_url
    );
    let output = format!("{doc:?} {doc:#?}");
    for canary in CANARIES {
        assert!(!output.contains(canary), "Debug leaks {canary}:\n{output}");
    }
    assert!(
        !output.contains("?q="),
        "Debug prints the URL query:\n{output}"
    );
}

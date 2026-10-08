//! Scanner test harness (`docs/testing.md`, "Stub scanner"): builds `tools/stub-scanner`, gives
//! each `STUB_SCANNER_MODE` its own wrapper executable, and runs a fixture page through
//! fetch → extract → scan → `accept()` the way the page processor will (PR-07).
#![allow(dead_code)]

#[path = "extract.rs"]
pub mod extract;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use secure_web_core::config::{ExtractConfig, ScannerConfig, SecurityConfig};
use secure_web_core::ids::DocumentId;
use secure_web_core::model::{BlockedDocument, ContentType, UntrustedDocument};
use secure_web_extract::ExtractedDocument;
use secure_web_fetch::FetchedResponse;
use secure_web_security::decision::{scan_and_accept, AcceptContext, AcceptedDocument};
use secure_web_security::injection::SubprocessScanner;
use secure_web_security::policy::PolicyEngine;

#[allow(unused_imports)]
pub use extract::{canaries, fetch_extract, Harness};

/// Every stub mode (see `tools/stub-scanner/src/main.rs`), plus `timeout-pid`: `timeout` with
/// `STUB_SCANNER_PID_DIR` set to [`pid_dir`].
pub const MODES: [&str; 21] = [
    "canary",
    "crash",
    "timeout",
    "timeout-pid",
    "garbage",
    "partial",
    "huge",
    "unexpected-exit",
    "exit1-clean",
    "no-read",
    "partial-read",
    "wrong-line",
    "stderr-flood",
    "stderr-at-cap",
    "stderr-over-cap",
    "signal",
    "bad-version",
    "no-version",
    "structural",
    "raw-crash",
    "raw-past-end",
];

struct Stub {
    wrappers: PathBuf,
}

/// `target/<...>/stub-scanner`, next to the directory holding this test binary.
fn stub_root() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    // target/<profile>/deps/<test> -> target
    let target = exe
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .unwrap();
    target.join("stub-scanner")
}

fn stub() -> &'static Stub {
    static STUB: OnceLock<Stub> = OnceLock::new();
    STUB.get_or_init(|| {
        let root = stub_root();
        let build = root.join("build");
        // A separate target dir: the outer `cargo test` may still hold its own build lock.
        // Coverage/flag overrides are dropped so the stub builds plainly.
        let status = Command::new(env!("CARGO"))
            .args([
                "build",
                "--quiet",
                "--locked",
                "--offline",
                "-p",
                "stub-scanner",
                "--bin",
                "stub-injection-scanner",
                "--target-dir",
            ])
            .arg(&build)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("CARGO_BUILD_RUSTFLAGS")
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env_remove("LLVM_PROFILE_FILE")
            .status()
            .expect("cannot run cargo to build the stub scanner");
        assert!(status.success(), "building stub-injection-scanner failed");
        let bin = build.join("debug").join("stub-injection-scanner");
        assert!(bin.is_file(), "stub binary missing at {}", bin.display());

        // One wrapper script per mode, written before any test spawns a scanner (so no
        // executable is open for writing while another thread forks: ETXTBSY).
        let wrappers = root.join(format!("wrappers-{}", std::process::id()));
        std::fs::create_dir_all(&wrappers).unwrap();
        std::fs::create_dir_all(pid_dir_in(&root)).unwrap();
        for mode in MODES {
            let (stub_mode, extra) = match mode {
                "timeout-pid" => (
                    "timeout",
                    format!(
                        "export STUB_SCANNER_PID_DIR='{}'\n",
                        pid_dir_in(&root).display()
                    ),
                ),
                other => (other, String::new()),
            };
            let script = format!(
                "#!/bin/sh\nexport STUB_SCANNER_MODE={stub_mode}\n{extra}exec '{}' \"$@\"\n",
                bin.display()
            );
            let path = wrappers.join(mode);
            std::fs::write(&path, script).unwrap();
            make_executable(&path);
        }
        Stub { wrappers }
    })
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// The wrapper scripts need a POSIX shell; the scanner suites are `cfg(unix)`.
#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

fn pid_dir_in(root: &Path) -> PathBuf {
    root.join(format!("pids-{}", std::process::id()))
}

/// Where `timeout-pid` records the pid of each stub process it starts.
pub fn pid_dir() -> PathBuf {
    stub();
    pid_dir_in(&stub_root())
}

/// The executable for `mode` (one of [`MODES`]).
pub fn stub_executable(mode: &str) -> PathBuf {
    assert!(MODES.contains(&mode), "unknown stub mode {mode}");
    stub().wrappers.join(mode)
}

/// The scanner config pointing at the stub in `mode`.
pub fn stub_config(mode: &str, timeout: Duration) -> ScannerConfig {
    ScannerConfig {
        executable: stub_executable(mode).display().to_string(),
        timeout,
        ..ScannerConfig::default()
    }
}

/// Default `extract.maxSecurityTextBytes`, the scanner's input cap.
pub fn max_input_bytes() -> usize {
    usize::try_from(ExtractConfig::default().max_security_text_bytes).unwrap()
}

/// A subprocess scanner running the stub in `mode` with a 2 s timeout.
pub async fn stub_scanner(mode: &str) -> SubprocessScanner {
    SubprocessScanner::new(
        &stub_config(mode, Duration::from_secs(2)),
        max_input_bytes(),
    )
    .await
}

/// The default policy.
pub fn policy() -> PolicyEngine {
    PolicyEngine::new(&SecurityConfig::default()).unwrap()
}

/// Context for document `seq` at depth 0.
pub fn ctx(seq: u32) -> AcceptContext {
    AcceptContext::new(DocumentId::from_seq(seq).unwrap(), 0)
}

/// The `UntrustedDocument` the page processor builds from a fetch + extraction.
pub fn untrusted(resp: &FetchedResponse, extracted: ExtractedDocument) -> UntrustedDocument {
    UntrustedDocument {
        requested_url: resp.requested_url.clone(),
        final_url: resp.final_url.clone(),
        redirect_chain: resp.redirect_chain.clone(),
        http_status: resp.status,
        content_type: ContentType {
            essence: resp.content_type.essence().to_owned(),
            charset: resp.charset.clone(),
        },
        retrieved_at: resp.retrieved_at,
        security_text: extracted.security_text,
        display: extracted.display,
        links: extracted.links,
        raw_bytes: None,
    }
}

/// Fetch `path`, extract it, and run it through `scanner` + the default policy.
pub async fn process_with(
    harness: &Harness,
    path: &str,
    scanner: &SubprocessScanner,
) -> (UntrustedDocument, Result<AcceptedDocument, BlockedDocument>) {
    let resp = harness.fetch(path).await.unwrap();
    let extracted = secure_web_extract::Extractor::extract(
        &secure_web_extract::ContentExtractor::new(Default::default()),
        &extract::input(&resp),
    )
    .unwrap();
    let doc = untrusted(&resp, extracted);
    let outcome = scan_and_accept(doc.clone(), scanner, &policy(), &ctx(1)).await;
    (doc, outcome)
}

/// [`process_with`] using the stub in `canary` mode.
pub async fn process(
    harness: &Harness,
    path: &str,
) -> (UntrustedDocument, Result<AcceptedDocument, BlockedDocument>) {
    let scanner = stub_scanner("canary").await;
    process_with(harness, path, &scanner).await
}

/// Run an in-memory HTML page (served at `http://fixture.test/page`) through the pipeline.
pub async fn process_html(
    html: &str,
    scanner: &SubprocessScanner,
) -> (UntrustedDocument, Result<AcceptedDocument, BlockedDocument>) {
    let extracted = extract::extract_html(html);
    let url = url::Url::parse("http://fixture.test/page").unwrap();
    let doc = UntrustedDocument {
        requested_url: url.clone(),
        final_url: url,
        redirect_chain: vec![],
        http_status: 200,
        content_type: ContentType {
            essence: "text/html".into(),
            charset: Some("utf-8".into()),
        },
        retrieved_at: chrono::Utc::now(),
        security_text: extracted.security_text,
        display: extracted.display,
        links: extracted.links,
        raw_bytes: None,
    };
    let outcome = scan_and_accept(doc.clone(), scanner, &policy(), &ctx(1)).await;
    (doc, outcome)
}

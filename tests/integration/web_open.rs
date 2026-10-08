//! `web_open` end to end (PR-07, SW-009): fixture site + stub scanner + the real
//! `PageProcessor` behind the real MCP server on an ephemeral loopback port, driven over
//! streamable HTTP with raw JSON-RPC (`docs/tasks/PR-07-web-open.md`).
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

#[path = "../support/mcp.rs"]
mod mcp;

use std::collections::BTreeSet;
use std::time::Duration;

use mcp::{files_under, redact, Client, Harness, Options};
use serde_json::{json, Value};

fn keys(value: &Value) -> BTreeSet<String> {
    value.as_object().unwrap().keys().cloned().collect()
}

fn read_json(path: &str) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// The corpus snapshot of `/clean/a` (`tests/corpus/snapshots/docs/a.html.snap`): title and
/// Markdown as the extractor renders them at `http://fixture.test/clean/a`.
fn clean_a_snapshot() -> (String, String) {
    let snap = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/corpus/snapshots/docs/a.html.snap"
    ))
    .unwrap();
    let body = snap.splitn(3, "---\n").nth(2).unwrap();
    let (title, markdown) = body.split_once("\n---\n").unwrap();
    (
        title.strip_prefix("title: ").unwrap().to_owned(),
        markdown.to_owned(),
    )
}

#[tokio::test]
async fn safe_page_is_stored_and_returned_inline() {
    let harness = Harness::start().await;
    let (mut client, _) = Client::connect(&harness.mcp_url).await;
    let (result, is_error) = client
        .call(
            "web_open",
            json!({ "url": harness.url("/clean/a"), "inline": true }),
        )
        .await;
    assert!(!is_error, "{result}");
    assert_eq!(result["status"], "SAFE");
    assert_eq!(result["security"]["decision"], "SAFE");
    assert_eq!(result["security"]["findingIds"], json!([]));
    assert_eq!(result["truncated"], false);

    // The Markdown matches the extraction snapshot (at the fixture's real port).
    let (title, markdown) = clean_a_snapshot();
    let port = harness.base.port().unwrap();
    let markdown = markdown.replace("fixture.test/", &format!("fixture.test:{port}/"));
    assert_eq!(result["title"], title.as_str());
    assert_eq!(result["content"].as_str().unwrap(), markdown);

    // The page file, its metadata and a terminal OPEN manifest exist in the run directory.
    let run_id = result["runId"].as_str().unwrap();
    let run_dir = harness.runs_dir().join(run_id);
    let content_path = result["contentPath"].as_str().unwrap();
    assert!(content_path.starts_with(run_dir.join("pages").to_str().unwrap()));
    let page = std::fs::read_to_string(content_path).unwrap();
    assert!(page.contains(&markdown), "{page}");
    assert_eq!(
        result["contentBytes"],
        page.len() as u64 - frontmatter_len(&page)
    );
    let manifest = read_json(result["manifestPath"].as_str().unwrap());
    assert_eq!(manifest["kind"], "OPEN");
    assert_eq!(manifest["status"], "COMPLETE");
    assert_eq!(manifest["documents"][0]["id"], result["documentId"]);
    assert_eq!(manifest["stats"]["fetched"], 1);

    // Invariant 8 at the MCP boundary: every model-facing string of the result was part of
    // the security_text the scanner read (retained under private-audit/ in this test).
    let sectext = std::fs::read_to_string(harness.audit_dir().join(run_id).join(format!(
        "{}.sectext",
        result["documentId"].as_str().unwrap()
    )))
    .unwrap();
    let lines: BTreeSet<&str> = sectext.lines().collect();
    assert!(sectext.contains(result["content"].as_str().unwrap()));
    assert!(lines.contains(result["title"].as_str().unwrap()));
    assert!(lines.contains(result["finalUrl"].as_str().unwrap()));

    insta::assert_snapshot!(
        "web_open_safe",
        serde_json::to_string_pretty(&redact(&result, &harness)).unwrap()
    );
}

fn frontmatter_len(page: &str) -> u64 {
    let end = page[4..].find("---\n").unwrap() + 4 + 4;
    end as u64
}

#[tokio::test]
async fn without_inline_there_is_no_content() {
    let harness = Harness::start().await;
    let (mut client, _) = Client::connect(&harness.mcp_url).await;
    let (result, is_error) = client
        .call("web_open", json!({ "url": harness.url("/clean/post") }))
        .await;
    assert!(!is_error, "{result}");
    assert_eq!(
        keys(&result),
        [
            "contentBytes",
            "contentPath",
            "documentId",
            "finalUrl",
            "manifestPath",
            "runId",
            "security",
            "status",
            "title",
            "url"
        ]
        .map(String::from)
        .into()
    );
}

#[tokio::test]
async fn injected_page_is_blocked_without_content_fields() {
    let harness = Harness::start().await;
    let (mut client, _) = Client::connect(&harness.mcp_url).await;
    let (result, is_error) = client
        .call(
            "web_open",
            json!({ "url": harness.url("/injection/direct"), "inline": true }),
        )
        .await;
    assert!(!is_error, "a security block is a normal result: {result}");
    assert_eq!(result["status"], "BLOCK");
    assert_eq!(
        keys(&result),
        [
            "block",
            "documentId",
            "finalUrl",
            "runId",
            "security",
            "status",
            "url"
        ]
        .map(String::from)
        .into()
    );
    assert_eq!(result["block"]["reason"], "PROMPT_INJECTION");
    assert_eq!(result["block"]["maxSeverity"], "CRITICAL");
    assert_eq!(result["block"]["findingIds"], json!(["PI001"]));
    assert_eq!(result["security"]["decision"], "BLOCK");
    let run_dir = harness.runs_dir().join(result["runId"].as_str().unwrap());
    assert!(files_under(&run_dir.join("pages")).is_empty());
    let manifest = read_json(run_dir.join("manifest.json").to_str().unwrap());
    assert_eq!(manifest["blocked"][0]["reason"], "PROMPT_INJECTION");
    assert_eq!(manifest["documents"], json!([]));
    insta::assert_snapshot!(
        "web_open_blocked",
        serde_json::to_string_pretty(&redact(&result, &harness)).unwrap()
    );
}

#[tokio::test]
async fn redirect_to_a_private_address_is_redirect_blocked() {
    let harness = Harness::start().await;
    let (mut client, _) = Client::connect(&harness.mcp_url).await;
    for path in [
        "/redirect/private",
        "/redirect/metadata",
        "/redirect/localhost",
    ] {
        let (result, is_error) = client
            .call("web_open", json!({ "url": harness.url(path) }))
            .await;
        assert!(is_error, "{path}: {result}");
        assert_eq!(result["error"]["code"], "REDIRECT_BLOCKED", "{path}");
        assert_eq!(result["error"]["retryable"], false);
        assert_eq!(result["error"]["details"]["reason"], "REDIRECT_VIOLATION");
        let manifest = read_json(result["error"]["details"]["manifestPath"].as_str().unwrap());
        assert_eq!(manifest["blocked"][0]["reason"], "REDIRECT_VIOLATION");
        assert_eq!(
            manifest["blocked"][0]["id"],
            result["error"]["details"]["documentId"]
        );
    }
    // The private target itself was never requested.
    assert!(!harness.fixture.requests().iter().any(|p| p == "/clean/a"));
    let (result, _) = client
        .call(
            "web_open",
            json!({ "url": harness.url("/redirect/private") }),
        )
        .await;
    insta::assert_snapshot!(
        "web_open_redirect_blocked",
        serde_json::to_string_pretty(&redact(&result, &harness)).unwrap()
    );
}

#[tokio::test]
async fn private_destinations_are_ssrf_blocked_before_any_request() {
    let harness = Harness::start().await;
    let (mut client, _) = Client::connect(&harness.mcp_url).await;
    let port = harness.fixture.addr().port();
    for url in [
        "http://127.0.0.1:1/".to_owned(),
        format!("http://127.0.0.1:{port}/clean/a"),
        "http://localhost/".to_owned(),
        "http://[::1]/".to_owned(),
        "http://169.254.169.254/latest/meta-data/".to_owned(),
        "http://2130706433/".to_owned(),
        format!("http://rebind.test:{port}/clean/a"),
    ] {
        let (result, is_error) = client.call("web_open", json!({ "url": url })).await;
        assert!(is_error, "{url}: {result}");
        assert_eq!(result["error"]["code"], "SSRF_BLOCKED", "{url}");
        let manifest = read_json(result["error"]["details"]["manifestPath"].as_str().unwrap());
        assert_eq!(manifest["status"], "FAILED");
        assert_eq!(manifest["failed"][0]["code"], "SSRF_BLOCKED");
    }
    assert!(harness.fixture.requests().is_empty());
}

/// The guard's raw-text rules (non-canonical IPv4 spelling, an empty userinfo `@`) must see
/// the URL exactly as the agent wrote it: `Url::parse` rewrites `3221225985` to `192.0.2.1`
/// and drops an empty `@`, so validating the parsed URL would silently skip them
/// (`docs/security-policy.md` §1). All of these name a public TEST-NET address, so only the
/// raw-text rules can refuse them.
#[tokio::test]
async fn raw_text_url_rules_apply_to_web_open() {
    let harness = Harness::start().await;
    let (mut client, _) = Client::connect(&harness.mcp_url).await;
    for (url, code) in [
        ("http://3221225985/", "SSRF_BLOCKED"),
        ("http://0xC0000201/", "SSRF_BLOCKED"),
        ("http://0300.0.2.1/", "SSRF_BLOCKED"),
        ("http://192.0.2.1./", "SSRF_BLOCKED"),
        ("http://192.0.2.1%2e/", "SSRF_BLOCKED"),
        ("http://@192.0.2.1/", "INVALID_URL"),
        ("http://:@192.0.2.1/", "INVALID_URL"),
        ("http://@example.test/", "INVALID_URL"),
    ] {
        let (result, is_error) = client.call("web_open", json!({ "url": url })).await;
        assert!(is_error, "{url}: {result}");
        assert_eq!(result["error"]["code"], code, "{url}: {result}");
        let manifest = read_json(result["error"]["details"]["manifestPath"].as_str().unwrap());
        assert_eq!(manifest["status"], "FAILED", "{url}");
        assert_eq!(manifest["failed"][0]["code"], code, "{url}");
    }
    assert!(harness.fixture.requests().is_empty());
}

#[tokio::test]
async fn oversized_pages_are_content_too_large() {
    let harness = Harness::start().await;
    let (mut client, _) = Client::connect(&harness.mcp_url).await;
    for path in ["/huge", "/gzip-bomb", "/json/big"] {
        let (result, is_error) = client
            .call("web_open", json!({ "url": harness.url(path) }))
            .await;
        assert!(is_error, "{path}: {result}");
        assert_eq!(result["error"]["code"], "CONTENT_TOO_LARGE", "{path}");
        assert_eq!(result["error"]["details"]["reason"], "CONTENT_TOO_LARGE");
    }
    let (result, is_error) = client
        .call("web_open", json!({ "url": harness.url("/mime/pdf") }))
        .await;
    assert!(is_error);
    assert_eq!(result["error"]["code"], "UNSUPPORTED_CONTENT_TYPE");
}

#[tokio::test]
async fn fetch_failures_are_errors() {
    let harness = Harness::start().await;
    let (mut client, _) = Client::connect(&harness.mcp_url).await;
    let (result, is_error) = client
        .call("web_open", json!({ "url": harness.url("/status/503") }))
        .await;
    assert!(is_error);
    assert_eq!(result["error"]["code"], "FETCH_FAILED");
    assert_eq!(result["error"]["retryable"], true);
    let (result, _) = client
        .call("web_open", json!({ "url": "https://nxdomain.invalid/" }))
        .await;
    assert_eq!(result["error"]["code"], "DNS_FAILED");
    assert_eq!(result["error"]["retryable"], true);
}

#[tokio::test]
async fn scanner_timeout_blocks_as_scanner_failure() {
    let harness = Harness::with(Options {
        scanner_mode: "timeout",
        scanner_timeout: Duration::from_millis(300),
        ..Options::default()
    })
    .await;
    let (mut client, _) = Client::connect(&harness.mcp_url).await;
    let (result, is_error) = client
        .call(
            "web_open",
            json!({ "url": harness.url("/clean/a"), "inline": true }),
        )
        .await;
    assert!(!is_error, "{result}");
    assert_eq!(result["status"], "BLOCK");
    assert_eq!(result["block"]["reason"], "SCANNER_FAILURE");
    assert_eq!(result["block"]["findingIds"], json!([]));
    assert!(result.get("content").is_none() && result.get("title").is_none());
    assert_eq!(
        result["security"]["scannerVersion"],
        "injection-scanner 0.1.0-stub"
    );
    // The CLI maps a scanner-failure block to exit 5, any other block to 3.
    let response = harness
        .call_direct("web_open", json!({ "url": harness.url("/clean/a") }))
        .await;
    assert_eq!(response.exit_code, 5);
}

#[tokio::test]
async fn missing_scanner_blocks_every_page() {
    let harness = Harness::with(Options {
        scanner_mode: "no-version",
        ..Options::default()
    })
    .await;
    let response = harness
        .call_direct("web_open", json!({ "url": harness.url("/clean/a") }))
        .await;
    assert!(!response.is_error);
    assert_eq!(response.body["block"]["reason"], "SCANNER_FAILURE");
    assert_eq!(response.body["security"]["scannerVersion"], "unavailable");
    assert_eq!(response.exit_code, 5);
}

#[tokio::test]
async fn inline_content_is_truncated_and_clamped() {
    let harness = Harness::start().await;
    let (mut client, _) = Client::connect(&harness.mcp_url).await;
    let (full, _) = client
        .call(
            "web_open",
            json!({ "url": harness.url("/clean/layout"), "inline": true }),
        )
        .await;
    let full = full["content"].as_str().unwrap().to_owned();
    assert!(full.len() > 64);

    let (result, is_error) = client
        .call(
            "web_open",
            json!({ "url": harness.url("/clean/layout"), "inline": true, "maxInlineBytes": 64 }),
        )
        .await;
    assert!(!is_error);
    let content = result["content"].as_str().unwrap();
    assert!(content.len() <= 64);
    assert!(full.starts_with(content));
    assert_eq!(result["truncated"], true);
    // The stored page is never truncated.
    let page = std::fs::read_to_string(result["contentPath"].as_str().unwrap()).unwrap();
    assert!(page.contains(&full));

    // Above the hard maximum: clamped to 262144 bytes, never an error.
    let (result, is_error) = client
        .call(
            "web_open",
            json!({ "url": harness.url("/clean/layout"), "inline": true, "maxInlineBytes": 10_000_000u64 }),
        )
        .await;
    assert!(!is_error);
    assert_eq!(result["content"].as_str().unwrap(), full);
    assert_eq!(result["truncated"], false);
    assert_eq!(
        secure_web_mcp::tools::open::HARD_MAX_INLINE_BYTES,
        262_144,
        "contract hard max"
    );
}

#[tokio::test]
async fn invalid_arguments_are_rejected() {
    let harness = Harness::start().await;
    let (mut client, _) = Client::connect(&harness.mcp_url).await;
    for args in [
        json!({}),
        json!({ "url": 7 }),
        json!({ "url": "" }),
        json!({ "url": "not a url" }),
        json!({ "url": "/relative" }),
        json!({ "url": "a".repeat(9000) }),
        json!({ "url": harness.url("/clean/a"), "maxInlineBytes": -1 }),
        json!({ "url": harness.url("/clean/a"), "unknown": true }),
    ] {
        let (result, is_error) = client.call("web_open", args.clone()).await;
        assert!(is_error, "{args}: {result}");
        assert_eq!(result["error"]["code"], "INVALID_ARGUMENT", "{args}");
    }
    for (url, code) in [
        ("file:///etc/passwd", "UNSUPPORTED_SCHEME"),
        ("ftp://example.test/", "UNSUPPORTED_SCHEME"),
        ("http://user:pw@example.test/", "INVALID_URL"),
    ] {
        let (result, is_error) = client.call("web_open", json!({ "url": url })).await;
        assert!(is_error);
        assert_eq!(result["error"]["code"], code, "{url}");
    }
    // Nothing was fetched and no run exists for an invalid argument.
    assert!(harness.fixture.requests().is_empty());

    // An unknown tool is a protocol error.
    let response = client
        .request(
            "tools/call",
            json!({ "name": "web_search", "arguments": {} }),
        )
        .await;
    assert!(response["error"].is_object(), "{response}");
}

#[tokio::test]
async fn concurrent_calls_are_all_answered() {
    let harness = Harness::start().await;
    let mut tasks = Vec::new();
    for i in 0..24 {
        let path = if i % 2 == 0 {
            "/clean/a"
        } else {
            "/injection/direct"
        };
        let server = secure_web_mcp::SecureWebServer::new(harness.app.clone());
        let args = json!({ "url": harness.url(path) });
        tasks.push(tokio::spawn(async move {
            server
                .call("web_open", args.as_object().cloned())
                .await
                .unwrap()
        }));
    }
    for (i, task) in tasks.into_iter().enumerate() {
        let response = task.await.unwrap();
        let expected = if i % 2 == 0 { "SAFE" } else { "BLOCK" };
        assert_eq!(response.body["status"], expected, "{}", response.body);
    }
    // One run per call.
    assert_eq!(std::fs::read_dir(harness.runs_dir()).unwrap().count(), 24);
}

#[tokio::test]
async fn the_http_transport_refuses_browsers_foreign_hosts_and_other_paths() {
    let mut harness = Harness::start().await;
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": mcp::PROTOCOL_VERSION, "capabilities": {},
                    "clientInfo": { "name": "t", "version": "0" } }
    });
    let post = |url: &str| {
        http.post(url)
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&init).unwrap())
    };
    // Any Origin header (a browser page, even a local one) is refused.
    let response = post(&harness.mcp_url)
        .header("origin", "http://localhost:8787")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    // A foreign Host (DNS rebinding) is refused.
    let response = post(&harness.mcp_url)
        .header("host", "attacker.example")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    // Only /mcp is served.
    let other = harness.mcp_url.replace("/mcp", "/other");
    assert_eq!(post(&other).send().await.unwrap().status(), 404);
    // A plain client gets in.
    assert!(post(&harness.mcp_url)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());

    // Graceful shutdown ends sessions and returns.
    harness.stop().await;
    assert!(post(&harness.mcp_url).send().await.is_err());
}

#[tokio::test]
async fn non_loopback_listen_is_refused_without_allow_remote() {
    for addr in ["192.0.2.1:0", "[2001:db8::1]:0"] {
        let err = secure_web_mcp::bind(addr.parse().unwrap(), false)
            .await
            .unwrap_err();
        assert!(
            matches!(err, secure_web_mcp::ServeError::NotLoopback(_)),
            "{err}"
        );
    }
    secure_web_mcp::bind("127.0.0.1:0".parse().unwrap(), false)
        .await
        .unwrap();
}

/// With `allowRemote` the only extra accepted `Host` is the listen IP, so a wildcard bind would
/// answer every remote client 403: it is refused at bind, loudly, instead.
#[tokio::test]
async fn a_wildcard_listen_is_refused_even_with_allow_remote() {
    for addr in ["0.0.0.0:0", "[::]:0", "[::ffff:0.0.0.0]:0"] {
        let err = secure_web_mcp::bind(addr.parse().unwrap(), true)
            .await
            .unwrap_err();
        assert!(
            matches!(err, secure_web_mcp::ServeError::Unspecified(_)),
            "{err}"
        );
    }
}

/// Invariant 6 at the processor: only a stored page yields links; a blocked one has no links
/// field at all. Metadata records the measured sizes and the scanner findings.
#[tokio::test]
async fn only_stored_pages_yield_links() {
    use secure_web_crawl::PageOutcome;

    let harness = Harness::start().await;
    let processor = harness.app.processor();
    let url = |path: &str| url::Url::parse(&harness.url(path)).unwrap();

    let opened = processor.open(url("/link/a").as_str()).await.unwrap();
    let PageOutcome::Stored { doc, links, page } = &opened.outcome else {
        panic!("{:?}", opened.outcome);
    };
    assert!(!links.is_empty());
    assert!(links.iter().all(|l| l.url.scheme().starts_with("http")));
    assert!(page.markdown().len() as u64 <= doc.content_bytes);
    let run_dir = opened.manifest_path.parent().unwrap();
    let meta = read_json(run_dir.join("metadata/000001.json").to_str().unwrap());
    assert!(meta["rawBytes"].as_u64().unwrap() > 0);
    assert!(meta["securityTextBytes"].as_u64().unwrap() > meta["extractedBytes"].as_u64().unwrap());
    assert_eq!(meta["linksFound"], links.len() as u64);

    let opened = processor
        .open(url("/blocked-with-links").as_str())
        .await
        .unwrap();
    let PageOutcome::Blocked(blocked) = &opened.outcome else {
        panic!("{:?}", opened.outcome);
    };
    assert_eq!(blocked.finding_ids, ["PI001"]);
    let run_dir = opened.manifest_path.parent().unwrap();
    let findings = read_json(run_dir.join("security/findings.json").to_str().unwrap());
    assert_eq!(findings[0]["findingId"], "PI001");
    assert_eq!(findings[0]["documentId"], "doc_000001");
    let meta = read_json(run_dir.join("metadata/000001.json").to_str().unwrap());
    assert_eq!(meta["security"]["reason"], "PROMPT_INJECTION");
    assert!(meta.get("title").is_none());
    // No linked page was requested.
    assert!(!harness
        .fixture
        .requests()
        .iter()
        .any(|p| p.starts_with("/clean/page-")));
}

/// `security.network.extraBlockedHosts` reaches the processor's guard.
#[tokio::test]
async fn extra_blocked_hosts_apply_to_web_open() {
    use secure_web_core::config::Config;

    let harness = Harness::start().await;
    let mut config = Config::default();
    config.server.workspace = harness.workspace.path().to_path_buf();
    config.security.network.extra_blocked_hosts = vec!["fixture.test".into()];
    let resolver = mcp::scanner::extract::fetch::resolver::StubResolver::new(&[(
        "fixture.test",
        &["127.0.0.1"],
    )]);
    let guard =
        secure_web_security::ssrf::UrlGuard::new(&config.security.network.clone(), resolver)
            .unwrap()
            .with_test_fixture("fixture.test", harness.fixture.addr())
            .unwrap();
    let processor = secure_web_crawl::PageProcessor::with_guard(&config, guard)
        .await
        .unwrap();
    let opened = processor.open(&harness.url("/clean/a")).await.unwrap();
    assert!(
        matches!(
            opened.outcome,
            secure_web_crawl::PageOutcome::Failed {
                code: secure_web_core::error::ErrorCode::SsrfBlocked,
                ..
            }
        ),
        "{:?}",
        opened.outcome
    );
    assert!(harness.fixture.requests().is_empty());
}

/// Send one raw HTTP/1.1 request to the MCP listener and return the status line.
async fn raw_status(mcp_url: &str, request: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = mcp_url
        .trim_start_matches("http://")
        .trim_end_matches("/mcp");
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 256];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8_lossy(&buf[..read])
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// DNS-rebinding defence must not depend on which of several `Host` headers the check reads,
/// nor on an absolute-form request target naming another authority: both are refused (400,
/// RFC 9112 §3.2 / §3.2.2).
#[tokio::test]
async fn the_http_transport_refuses_duplicate_hosts_and_absolute_form_targets() {
    let harness = Harness::start().await;
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": mcp::PROTOCOL_VERSION, "capabilities": {},
                    "clientInfo": { "name": "t", "version": "0" } }
    })
    .to_string();
    let request = |target: &str, hosts: &[&str]| {
        let hosts: String = hosts.iter().map(|h| format!("Host: {h}\r\n")).collect();
        format!(
            "POST {target} HTTP/1.1\r\n{hosts}Accept: application/json, text/event-stream\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    let ok = raw_status(&harness.mcp_url, &request("/mcp", &["localhost"])).await;
    assert!(ok.contains(" 200 "), "{ok}");
    for (target, hosts) in [
        ("/mcp", &["localhost", "evil.example"][..]),
        ("/mcp", &["evil.example", "localhost"][..]),
        ("/mcp", &["localhost", "localhost"][..]),
        ("http://evil.example/mcp", &["localhost"][..]),
        ("http://localhost/mcp", &["localhost"][..]),
    ] {
        let status = raw_status(&harness.mcp_url, &request(target, hosts)).await;
        assert!(status.contains(" 400 "), "{target} {hosts:?}: {status}");
    }
}

/// A client that never finishes its request headers is disconnected (slowloris).
#[tokio::test]
async fn the_http_transport_drops_connections_that_never_finish_their_headers() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let harness = Harness::start().await;
    let addr = harness
        .mcp_url
        .trim_start_matches("http://")
        .trim_end_matches("/mcp")
        .to_owned();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 256];
    let started = std::time::Instant::now();
    let read = tokio::time::timeout(
        secure_web_mcp::HEADER_READ_TIMEOUT + Duration::from_secs(5),
        stream.read(&mut buf),
    )
    .await;
    assert!(read.is_ok(), "still open after {:?}", started.elapsed());
}

/// A client that sends its headers and then stalls on the body is answered 408 and the
/// connection closed, rather than held open indefinitely (slow-body slowloris).
#[tokio::test]
async fn the_http_transport_drops_connections_that_never_finish_their_body() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let harness = Harness::start().await;
    let addr = harness
        .mcp_url
        .trim_start_matches("http://")
        .trim_end_matches("/mcp")
        .to_owned();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
              Accept: application/json, text/event-stream\r\nContent-Length: 1000\r\n\r\n{",
        )
        .await
        .unwrap();
    let mut buf = vec![0u8; 256];
    let started = std::time::Instant::now();
    let read = tokio::time::timeout(
        secure_web_mcp::BODY_READ_TIMEOUT + Duration::from_secs(5),
        stream.read(&mut buf),
    )
    .await
    .unwrap_or_else(|_| panic!("still open after {:?}", started.elapsed()))
    .unwrap();
    let head = String::from_utf8_lossy(&buf[..read]);
    assert!(head.starts_with("HTTP/1.1 408 "), "{head}");
}

/// The head timeout also covers the wait for the next request on a keep-alive connection: an
/// idle connection is closed after `HEADER_READ_TIMEOUT` (contract: idle keep-alive).
#[tokio::test]
async fn the_http_transport_closes_idle_keep_alive_connections() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let harness = Harness::start().await;
    let addr = harness
        .mcp_url
        .trim_start_matches("http://")
        .trim_end_matches("/mcp")
        .to_owned();
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": mcp::PROTOCOL_VERSION, "capabilities": {},
                    "clientInfo": { "name": "t", "version": "0" } }
    })
    .to_string();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAccept: application/json, text/event-stream\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 8192];
    let first = stream.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..first]).starts_with("HTTP/1.1 200 "));
    // Drain the rest of the response, then stay idle.
    while let Ok(Ok(read)) =
        tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await
    {
        assert!(read > 0, "closed before the idle timeout");
    }
    let read = tokio::time::timeout(
        secure_web_mcp::HEADER_READ_TIMEOUT + Duration::from_secs(5),
        stream.read(&mut buf),
    )
    .await
    .expect("idle keep-alive connection still open");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
}

/// Carried over from PR-07 (`docs/backlog.md`, ADR-018): intermediate redirect hops of an
/// accepted page are server-chosen text the scanner never read; they are not recorded. Only the
/// final hop (the scanned `finalUrl`) remains in `redirectChain`.
#[tokio::test]
async fn unscanned_redirect_hops_of_an_accepted_page_are_not_recorded() {
    let harness = Harness::start().await;
    let response = harness
        .call_direct(
            "web_open",
            json!({ "url": harness.url("/redirect/canary-hop") }),
        )
        .await;
    assert!(!response.is_error, "{}", response.body);
    assert_eq!(response.body["status"], "SAFE");
    assert_eq!(response.body["finalUrl"], harness.url("/clean/a"));
    let run_dir = harness
        .runs_dir()
        .join(response.body["runId"].as_str().unwrap());
    let metadata = read_json(run_dir.join("metadata/000001.json").to_str().unwrap());
    assert_eq!(metadata["redirectChain"], json!([harness.url("/clean/a")]));
    for file in files_under(&harness.runs_dir()) {
        let bytes = std::fs::read(&file).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        for canary in mcp::canaries::ALL {
            assert!(!text.contains(canary), "{canary} in {}", file.display());
        }
    }
}

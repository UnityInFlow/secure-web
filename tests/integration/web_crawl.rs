//! `web_crawl` end to end (PR-08, SW-011): the hostile docs site crawled through the real MCP
//! server over streamable HTTP, argument clamping, the blocked-list and result-size caps, and
//! the no-leak rules for crawled URLs (`docs/tasks/PR-08-crawler.md`, ADR-018).
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

#[path = "../support/mcp.rs"]
mod mcp;

use std::collections::BTreeSet;

use mcp::canaries;
use mcp::scanner::extract::fetch::fixture_server::{LONG_INJECTIONS, MANY_INJECTIONS};
use mcp::{files_under, redact, Client, Harness};
use serde_json::{json, Value};

fn read_json(path: &str) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn keys(value: &Value) -> BTreeSet<String> {
    value.as_object().unwrap().keys().cloned().collect()
}

/// No canary in `text`.
fn assert_canary_free(text: &str, what: &str) {
    for canary in canaries::ALL {
        assert!(!text.contains(canary), "{canary} in {what}");
    }
}

/// No canary in any file under `runs/`.
fn assert_runs_canary_free(harness: &Harness) {
    for file in files_under(&harness.runs_dir()) {
        let bytes = std::fs::read(&file).unwrap();
        assert_canary_free(
            &String::from_utf8_lossy(&bytes),
            &file.display().to_string(),
        );
    }
}

#[tokio::test]
async fn hostile_docs_site_is_crawled_and_the_injected_page_is_withheld() {
    let harness = Harness::start().await;
    let (mut client, _) = Client::connect(&harness.mcp_url).await;
    let (result, is_error) = client
        .call(
            "web_crawl",
            json!({ "url": harness.url("/clean/docs/index"), "maxDepth": 2 }),
        )
        .await;
    assert!(!is_error, "{result}");
    assert_eq!(result["status"], "COMPLETE");
    assert_eq!(
        keys(&result),
        [
            "blocked",
            "corpusPath",
            "crawlId",
            "manifestPath",
            "rootUrl",
            "stats",
            "status",
            "summary"
        ]
        .map(str::to_owned)
        .into_iter()
        .collect()
    );
    let stats = &result["stats"];
    assert_eq!(stats["discovered"], 5);
    assert_eq!(stats["fetched"], 5);
    assert_eq!(stats["safe"], 4);
    assert_eq!(stats["warned"], 0);
    assert_eq!(stats["blocked"], 1);
    assert_eq!(stats["failed"], 0);
    assert_eq!(
        result["summary"],
        "Secure Web crawled 5 pages; 1 blocked (prompt injection). Blocked content was not exposed."
    );

    // The injected page is listed as blocked (ids, URL, enums) ...
    let blocked = result["blocked"].as_array().unwrap();
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0]["url"], harness.url("/injection/hidden-css"));
    assert_eq!(blocked[0]["reason"], "PROMPT_INJECTION");
    assert_eq!(blocked[0]["findingIds"], json!(["PI001"]));
    let blocked_id = blocked[0]["documentId"].as_str().unwrap().to_owned();

    // ... in the manifest, and absent from pages/.
    let manifest = read_json(result["manifestPath"].as_str().unwrap());
    assert_eq!(manifest["kind"], "CRAWL");
    assert_eq!(manifest["status"], "COMPLETE");
    assert_eq!(manifest["blocked"][0]["id"], blocked_id.as_str());
    assert_eq!(manifest["documents"].as_array().unwrap().len(), 4);
    let corpus = std::path::PathBuf::from(result["corpusPath"].as_str().unwrap());
    let pages: Vec<_> = std::fs::read_dir(corpus.join("pages")).unwrap().collect();
    assert_eq!(pages.len(), 4);
    let blocked_seq = &blocked_id["doc_".len()..];
    for page in std::fs::read_dir(corpus.join("pages")).unwrap() {
        let name = page.unwrap().file_name().to_string_lossy().into_owned();
        assert!(!name.starts_with(blocked_seq), "{name}");
    }

    // No canary anywhere an agent can read: MCP responses and the run directory.
    assert_canary_free(&client.transcript_text(), "the MCP transcript");
    assert_runs_canary_free(&harness);
}

#[tokio::test]
async fn web_crawl_output_matches_the_contract_snapshot() {
    let harness = Harness::start().await;
    let response = harness
        .call_direct(
            "web_crawl",
            json!({ "url": harness.url("/clean/docs/index"), "maxDepth": 2 }),
        )
        .await;
    assert!(!response.is_error, "{}", response.body);
    assert_eq!(response.exit_code, 0);
    let mut body = redact(&response.body, &harness);
    // Timing, the port's digit count (inside page bodies) and the completion order (which
    // assigns document ids) vary between runs.
    body["stats"]["durationMs"] = json!("<durationMs>");
    body["stats"]["totalBytes"] = json!("<totalBytes>");
    body["blocked"][0]["documentId"] = json!("<documentId>");
    insta::assert_snapshot!(
        "web_crawl_result",
        serde_json::to_string_pretty(&body).unwrap()
    );
}

#[tokio::test]
async fn limit_reached_and_exit_codes() {
    let harness = Harness::start().await;
    let response = harness
        .call_direct(
            "web_crawl",
            json!({ "url": harness.url("/links/huge"), "maxPages": 2 }),
        )
        .await;
    assert!(!response.is_error, "{}", response.body);
    assert_eq!(response.body["status"], "LIMIT_REACHED");
    assert_eq!(response.exit_code, 6);
    assert_eq!(response.body["stats"]["fetched"], 2);
    assert!(response.body["summary"]
        .as_str()
        .unwrap()
        .contains("The crawl stopped at a budget limit."));
}

#[tokio::test]
async fn a_canary_in_a_child_href_never_reaches_mcp_output_or_runs() {
    let harness = Harness::start().await;
    let (mut client, _) = Client::connect(&harness.mcp_url).await;
    let (result, is_error) = client
        .call(
            "web_crawl",
            json!({ "url": harness.url("/links/canary-href"), "maxDepth": 2 }),
        )
        .await;
    assert!(!is_error, "{result}");
    // The scanner read the link line, so the parent is blocked and nothing is followed.
    assert_eq!(result["stats"]["fetched"], 1);
    assert_eq!(result["stats"]["blocked"], 1);
    assert_eq!(harness.fixture.requests(), ["/links/canary-href"]);
    assert_canary_free(&client.transcript_text(), "the MCP transcript");
    assert_runs_canary_free(&harness);
}

#[tokio::test]
async fn blocked_list_is_capped_at_50_and_the_result_at_64_kib() {
    let harness = Harness::start().await;
    let response = harness
        .call_direct(
            "web_crawl",
            json!({ "url": harness.url("/links/many-injections"), "maxDepth": 1 }),
        )
        .await;
    assert!(!response.is_error, "{}", response.body);
    let blocked = MANY_INJECTIONS as u64;
    assert_eq!(response.body["stats"]["blocked"], blocked);
    assert_eq!(response.body["blocked"].as_array().unwrap().len(), 50);
    let manifest = read_json(response.body["manifestPath"].as_str().unwrap());
    assert_eq!(
        manifest["blocked"].as_array().unwrap().len(),
        MANY_INJECTIONS
    );
    assert!(serde_json::to_string(&response.body).unwrap().len() <= 64 * 1024);

    // ~6 KiB per blocked entry (url + finalUrl): the inline list is cut to fit 64 KiB.
    let harness = Harness::start().await;
    let response = harness
        .call_direct(
            "web_crawl",
            json!({ "url": harness.url("/links/long-injections"), "maxDepth": 1 }),
        )
        .await;
    assert!(!response.is_error, "{}", response.body);
    let text = serde_json::to_string(&response.body).unwrap();
    assert!(text.len() <= 64 * 1024, "{}", text.len());
    let inline = response.body["blocked"].as_array().unwrap().len();
    assert!(inline > 0 && inline < LONG_INJECTIONS, "{inline}");
    assert_eq!(response.body["stats"]["blocked"], LONG_INJECTIONS as u64);
}

#[tokio::test]
async fn arguments_are_clamped_or_rejected() {
    let harness = Harness::start().await;
    let response = harness
        .call_direct(
            "web_crawl",
            json!({ "url": harness.url("/depth/0"), "maxDepth": 99, "maxPages": 100000 }),
        )
        .await;
    assert!(!response.is_error, "{}", response.body);
    let manifest = read_json(response.body["manifestPath"].as_str().unwrap());
    assert_eq!(manifest["policy"]["maxDepth"], 5);
    assert_eq!(manifest["policy"]["maxPages"], 1000);
    assert_eq!(response.body["stats"]["fetched"], 6);

    let runs_before = std::fs::read_dir(harness.runs_dir()).unwrap().count();
    for args in [
        json!({ "url": harness.url("/depth/0"), "scope": "ALLOWLIST" }),
        json!({ "url": harness.url("/depth/0"), "scope": "ALLOWLIST", "allowedHosts": [] }),
        json!({ "url": harness.url("/depth/0"), "includePatterns": ["("] }),
        json!({ "url": harness.url("/depth/0"), "excludePatterns": ["a".repeat(600)] }),
        json!({ "url": harness.url("/depth/0"), "maxDuration": 5 }),
        json!({ "url": "not a url" }),
        json!({ "url": "" }),
        json!({ "url": 7 }),
    ] {
        let response = harness.call_direct("web_crawl", args.clone()).await;
        assert!(response.is_error, "{args}");
        assert_eq!(response.body["error"]["code"], "INVALID_ARGUMENT", "{args}");
        assert_eq!(response.exit_code, 2);
        assert!(!response.body.to_string().contains("not a url"));
    }
    // No run was created for a rejected call.
    assert_eq!(
        std::fs::read_dir(harness.runs_dir()).unwrap().count(),
        runs_before
    );
}

#[tokio::test]
async fn a_refused_root_is_an_error_with_a_failed_run() {
    let harness = Harness::start().await;
    let port = harness.fixture.addr().port();
    let response = harness
        .call_direct(
            "web_crawl",
            json!({ "url": format!("http://127.0.0.1:{port}/clean/a") }),
        )
        .await;
    assert!(response.is_error);
    assert_eq!(response.exit_code, 3);
    let error = &response.body["error"];
    assert_eq!(error["code"], "SSRF_BLOCKED");
    assert!(error["details"]["crawlId"]
        .as_str()
        .unwrap()
        .starts_with("crawl_"));
    let manifest = read_json(error["details"]["manifestPath"].as_str().unwrap());
    assert_eq!(manifest["status"], "FAILED");
    assert!(harness.fixture.requests().is_empty());
}

#[tokio::test]
async fn allowlist_over_mcp_follows_the_listed_hosts() {
    let harness = Harness::start().await;
    let response = harness
        .call_direct(
            "web_crawl",
            json!({
                "url": harness.url("/scope/multi"),
                "maxDepth": 1,
                "scope": "ALLOWLIST",
                "allowedHosts": ["fixture.test"],
                "excludePatterns": ["^/other/"]
            }),
        )
        .await;
    assert!(!response.is_error, "{}", response.body);
    let manifest = read_json(response.body["manifestPath"].as_str().unwrap());
    assert_eq!(manifest["policy"]["scope"], "ALLOWLIST");
    assert_eq!(manifest["policy"]["allowedHosts"], json!(["fixture.test"]));
    let mut requests = harness.fixture.requests();
    requests.sort();
    assert_eq!(requests, ["/clean/guide", "/clean/post", "/scope/multi"]);
}

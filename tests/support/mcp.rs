//! MCP test harness (PR-07): fixture server + stub DNS + stub scanner + the real
//! `PageProcessor` behind the real MCP server on `127.0.0.1:<ephemeral>`, driven by a small raw
//! JSON-RPC-over-HTTP client (`docs/testing.md`). Every raw HTTP response body the client reads
//! is kept, so leak tests can grep exactly what an agent received.
#![allow(dead_code)]

#[path = "store.rs"]
pub mod store;

pub use store::scanner;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use secure_web_core::config::{Config, NetworkConfig};
use secure_web_crawl::PageProcessor;
use secure_web_mcp::{App, SecureWebServer, ToolResponse};
use secure_web_security::ssrf::UrlGuard;
use serde_json::{json, Value};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use url::Url;

use scanner::extract::fetch::fixture_server::{
    FixtureServer, FIXTURE_HOST, REBIND_HOST, SECOND_HOST,
};
use scanner::extract::fetch::resolver::StubResolver;

#[allow(unused_imports)]
pub use scanner::canaries;

/// Protocol version the client asks for (a session-based streamable-HTTP version).
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// How the pipeline under test is configured.
#[derive(Debug, Clone)]
pub struct Options {
    /// Stub scanner mode (`tests/support/scanner.rs` `MODES`).
    pub scanner_mode: &'static str,
    /// Scanner timeout.
    pub scanner_timeout: Duration,
    /// `debug.retainRaw`.
    pub retain_raw: bool,
    /// Last-minute config changes (crawl budgets, fetch limits, …).
    pub configure: fn(&mut Config),
}

impl Default for Options {
    fn default() -> Self {
        Self {
            scanner_mode: "canary",
            scanner_timeout: Duration::from_secs(2),
            retain_raw: true,
            configure: |_| {},
        }
    }
}

/// Fixture site + pipeline + (optionally) a running MCP HTTP server.
pub struct Harness {
    pub base: Url,
    pub fixture: FixtureServer,
    pub workspace: tempfile::TempDir,
    pub app: App,
    pub mcp_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<Result<(), secure_web_mcp::ServeError>>>,
}

impl Harness {
    /// Start everything with default options.
    pub async fn start() -> Self {
        Self::with(Options::default()).await
    }

    /// Start everything with `options`.
    pub async fn with(options: Options) -> Self {
        let (base, fixture) = FixtureServer::start().await;
        let workspace = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.server.workspace = workspace.path().to_path_buf();
        config.debug.retain_raw = options.retain_raw;
        config.security.scanner =
            scanner::stub_config(options.scanner_mode, options.scanner_timeout);
        (options.configure)(&mut config);
        let resolver = StubResolver::new(&[
            (FIXTURE_HOST, &["127.0.0.1"]),
            (REBIND_HOST, &["10.0.0.1"]),
            (SECOND_HOST, &["127.0.0.1"]),
        ]);
        let guard = UrlGuard::new(&NetworkConfig::default(), resolver)
            .unwrap()
            .with_test_fixture(FIXTURE_HOST, fixture.addr())
            .unwrap();
        let processor = PageProcessor::with_guard(&config, guard).await.unwrap();
        let app = App::with_processor(Arc::new(processor));

        let listener = secure_web_mcp::bind("127.0.0.1:0".parse().unwrap(), false)
            .await
            .unwrap();
        let mcp_url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let (tx, rx) = oneshot::channel::<()>();
        let server = tokio::spawn(secure_web_mcp::serve_http(
            app.clone(),
            listener,
            false,
            async {
                let _ = rx.await;
            },
        ));
        Self {
            base,
            fixture,
            workspace,
            app,
            mcp_url,
            shutdown: Some(tx),
            server: Some(server),
        }
    }

    /// Fixture URL for `path`.
    pub fn url(&self, path: &str) -> String {
        self.base.join(path).unwrap().to_string()
    }

    /// `<workspace>/runs`.
    pub fn runs_dir(&self) -> PathBuf {
        std::fs::canonicalize(self.workspace.path())
            .unwrap()
            .join("runs")
    }

    /// `<workspace>/private-audit`.
    pub fn audit_dir(&self) -> PathBuf {
        std::fs::canonicalize(self.workspace.path())
            .unwrap()
            .join("private-audit")
    }

    /// Call a tool without a transport (the CLI's path).
    pub async fn call_direct(&self, name: &str, args: Value) -> ToolResponse {
        SecureWebServer::new(self.app.clone())
            .call(name, args.as_object().cloned())
            .await
            .unwrap()
    }

    /// Stop the MCP server gracefully and wait for it.
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(server) = self.server.take() {
            tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .expect("server did not shut down")
                .unwrap()
                .unwrap();
        }
    }
}

/// A raw JSON-RPC client for the streamable-HTTP transport.
pub struct Client {
    http: reqwest::Client,
    url: String,
    session: Option<String>,
    next_id: u64,
    /// Every raw response body received, in order.
    pub transcript: Arc<Mutex<Vec<String>>>,
}

impl Client {
    /// Connect and complete the `initialize` handshake.
    pub async fn connect(url: &str) -> (Self, Value) {
        let mut client = Self {
            http: reqwest::Client::builder().no_proxy().build().unwrap(),
            url: url.to_owned(),
            session: None,
            next_id: 1,
            transcript: Arc::default(),
        };
        let init = client
            .request(
                "initialize",
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": { "name": "secure-web-tests", "version": "0" }
                }),
            )
            .await;
        client.notify("notifications/initialized", json!({})).await;
        (client, init)
    }

    fn post(&self, body: &Value) -> reqwest::RequestBuilder {
        let mut req = self
            .http
            .post(&self.url)
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .body(serde_json::to_vec(body).unwrap());
        if let Some(session) = &self.session {
            req = req
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", PROTOCOL_VERSION);
        }
        req
    }

    /// Send a request and return the JSON-RPC response object (`result` or `error`).
    pub async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let response = self.post(&body).send().await.unwrap();
        assert!(
            response.status().is_success(),
            "{method}: HTTP {}",
            response.status()
        );
        if let Some(session) = response.headers().get("mcp-session-id") {
            self.session = Some(session.to_str().unwrap().to_owned());
        }
        let text = response.text().await.unwrap();
        self.transcript.lock().unwrap().push(text.clone());
        find_response(&text, id).unwrap_or_else(|| panic!("{method}: no response in {text}"))
    }

    /// Send a notification.
    pub async fn notify(&mut self, method: &str, params: Value) {
        let body = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        let response = self.post(&body).send().await.unwrap();
        assert!(
            response.status().is_success(),
            "{method}: HTTP {}",
            response.status()
        );
        let text = response.text().await.unwrap();
        self.transcript.lock().unwrap().push(text);
    }

    /// `tools/list` result.
    pub async fn tools_list(&mut self) -> Value {
        let response = self.request("tools/list", json!({})).await;
        response["result"].clone()
    }

    /// `tools/call` → (parsed JSON of the single text content, isError).
    pub async fn call(&mut self, name: &str, arguments: Value) -> (Value, bool) {
        let response = self
            .request(
                "tools/call",
                json!({ "name": name, "arguments": arguments }),
            )
            .await;
        let result = &response["result"];
        assert!(result.is_object(), "tools/call {name}: {response}");
        let content = result["content"].as_array().unwrap();
        assert_eq!(content.len(), 1, "{result}");
        assert_eq!(content[0]["type"], "text");
        let text = content[0]["text"].as_str().unwrap();
        (
            serde_json::from_str(text).unwrap(),
            result["isError"].as_bool().unwrap_or(false),
        )
    }

    /// Everything received so far, concatenated.
    pub fn transcript_text(&self) -> String {
        self.transcript.lock().unwrap().join("\n")
    }
}

/// The JSON-RPC message with `id` in a plain JSON or `text/event-stream` body.
fn find_response(text: &str, id: u64) -> Option<Value> {
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        if value["id"] == id {
            return Some(value);
        }
    }
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
        .find(|value| value["id"] == id)
}

/// Every regular file below `dir` (empty when it does not exist).
pub fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if std::fs::symlink_metadata(&path).unwrap().is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Replace run ids, document ids, ports and the workspace path so results snapshot stably.
pub fn redact(value: &Value, harness: &Harness) -> Value {
    let text = serde_json::to_string(value).unwrap();
    let workspace = std::fs::canonicalize(harness.workspace.path())
        .unwrap()
        .display()
        .to_string();
    let port = harness.base.port().unwrap();
    let text = text
        .replace(&workspace, "<workspace>")
        .replace(&format!(":{port}"), ":<port>")
        // The policy version hashes the security block, which names the stub's path.
        .replace(
            &format!("\"{}\"", harness.app.processor().versions().policy),
            "\"<policyVersion>\"",
        );
    // open_<12 hex> -> open_<id>, crawl_<12 hex> -> crawl_<id>
    let text = redact_ids(&text, "open_");
    let text = redact_ids(&text, "crawl_");
    serde_json::from_str(&text).unwrap()
}

fn redact_ids(text: &str, prefix: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = rest.find(prefix) {
        out.push_str(&rest[..i]);
        let after = &rest[i + prefix.len()..];
        let hex = after
            .bytes()
            .take(12)
            .take_while(u8::is_ascii_hexdigit)
            .count();
        out.push_str(prefix);
        if hex == 12 {
            out.push_str("<id>");
            rest = &after[12..];
        } else {
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

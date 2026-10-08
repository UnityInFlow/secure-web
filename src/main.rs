//! `secure-web` — security gateway for agentic Internet access.
//!
//! Every subcommand loads and validates the config first (exit 2 on any config error). `config`,
//! `open`, `crawl` and `serve` are implemented; `find` and `inspect` exit 1 with
//! `NOT_IMPLEMENTED` until their PR lands (PR-09/10).
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context as _;
use clap::{Parser, Subcommand, ValueEnum};
use secure_web_core::config::{Config, LoadedConfig, LogLevel};
use secure_web_core::error::exit_code;
use secure_web_crawl::ProcessorError;
use secure_web_mcp::{App, CancellationToken, SecureWebServer, ToolResponse};
use tracing_subscriber::EnvFilter;

/// Security gateway for agentic Internet access, exposed over MCP.
///
/// Every page passes URL guard -> bounded fetch -> extraction -> injection-scanner -> policy
/// before anything reaches an agent.
#[derive(Debug, Parser)]
#[command(name = "secure-web", version, about, long_about = None)]
struct Cli {
    /// Config file (default search: ./secure-web.yaml, ~/.secure-web/config.yaml, built-in defaults).
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Workspace directory for runs/ (overrides server.workspace).
    #[arg(long, global = true, value_name = "DIR")]
    workspace: Option<PathBuf>,

    /// Log level (overrides debug.logLevel). Logs go to stderr.
    #[arg(long, global = true, value_enum, value_name = "LEVEL")]
    log_level: Option<LogLevelArg>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the MCP server (streamable HTTP at /mcp, or stdio).
    Serve {
        /// Listen address (overrides server.listen; non-loopback needs server.allowRemote).
        #[arg(long, value_name = "ADDR")]
        listen: Option<SocketAddr>,
        /// Serve MCP over stdio instead of HTTP.
        #[arg(long)]
        stdio: bool,
    },
    /// Retrieve, inspect and store one URL (the `web_open` tool).
    Open {
        /// URL to open.
        url: String,
        /// Include the clean Markdown in the result.
        #[arg(long)]
        inline: bool,
        /// Largest inline content in bytes (default 32768, clamped to 262144).
        #[arg(long, value_name = "BYTES")]
        max_inline_bytes: Option<u64>,
        /// Print the `web_open` JSON result instead of a summary.
        #[arg(long)]
        json: bool,
    },
    /// Crawl from a root URL within hard budgets (the `web_crawl` tool). Ctrl-C cancels and
    /// keeps a partial manifest.
    Crawl {
        /// Root URL.
        url: String,
        /// Maximum link depth (hard max 5).
        #[arg(long)]
        depth: Option<u32>,
        /// Maximum pages (hard max 1000).
        #[arg(long)]
        max_pages: Option<u32>,
        /// Which links to follow.
        #[arg(long, value_enum, value_name = "SCOPE")]
        scope: Option<ScopeArg>,
        /// A host whose links are followed with `--scope allowlist` (repeatable).
        #[arg(long = "allow-host", value_name = "HOST")]
        allow_hosts: Vec<String>,
        /// Path regex a followed link must match (repeatable; any).
        #[arg(long = "include", value_name = "REGEX")]
        include: Vec<String>,
        /// Path regex a followed link must not match (repeatable).
        #[arg(long = "exclude", value_name = "REGEX")]
        exclude: Vec<String>,
        /// Print the `web_crawl` JSON result instead of a summary.
        #[arg(long)]
        json: bool,
    },
    /// Search the accepted documents of a crawl.
    Find {
        /// Crawl id (crawl_<12 hex>).
        crawl_id: String,
        /// Query text.
        query: String,
        /// Maximum matches (max 50).
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Summarize a run from its manifest.
    Inspect {
        /// Run id (crawl_<12 hex> or open_<12 hex>).
        run_id: String,
    },
    /// Validate the configuration, or print the effective configuration.
    Config {
        /// Print the effective configuration as YAML.
        #[arg(long)]
        effective: bool,
    },
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Command::Serve { .. } => "serve",
            Command::Open { .. } => "open",
            Command::Crawl { .. } => "crawl",
            Command::Find { .. } => "find",
            Command::Inspect { .. } => "inspect",
            Command::Config { .. } => "config",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ScopeArg {
    /// Links on the root URL's scheme, host and port only (default).
    SameOrigin,
    /// Links to `--allow-host` hosts only.
    Allowlist,
}

impl ScopeArg {
    fn contract_name(self) -> &'static str {
        match self {
            ScopeArg::SameOrigin => "SAME_ORIGIN",
            ScopeArg::Allowlist => "ALLOWLIST",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogLevelArg {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<LogLevelArg> for LogLevel {
    fn from(value: LogLevelArg) -> Self {
        match value {
            LogLevelArg::Trace => LogLevel::Trace,
            LogLevelArg::Debug => LogLevel::Debug,
            LogLevelArg::Info => LogLevel::Info,
            LogLevelArg::Warn => LogLevel::Warn,
            LogLevelArg::Error => LogLevel::Error,
        }
    }
}

fn main() -> ExitCode {
    // clap exits 2 on usage errors, matching the exit-code contract.
    let cli = Cli::parse();

    let mut loaded = match Config::load(cli.config.as_deref()) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("error: {err}");
            return exit(exit_code::USAGE);
        }
    };
    if let Some(workspace) = &cli.workspace {
        loaded.config.server.workspace.clone_from(workspace);
    }
    // A `serve --listen` override is validated like the file (a non-loopback address without
    // server.allowRemote exits 2).
    if let Command::Serve {
        listen: Some(listen),
        ..
    } = &cli.command
    {
        loaded.config.server.listen = *listen;
        if let Err(err) = loaded.config.validate() {
            eprintln!("error: {err}");
            return exit(exit_code::USAGE);
        }
    }

    let level = cli
        .log_level
        .map(LogLevel::from)
        .unwrap_or(loaded.config.debug.log_level);
    loaded.config.debug.log_level = level;
    init_tracing(level);
    for warning in &loaded.warnings {
        tracing::warn!("{warning}");
    }
    tracing::debug!(source = %loaded.source, "configuration loaded");

    match run(&cli.command, &loaded) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            exit(exit_code::INTERNAL)
        }
    }
}

fn run(command: &Command, loaded: &LoadedConfig) -> anyhow::Result<ExitCode> {
    match command {
        Command::Config { effective } => {
            let policy_version = loaded
                .config
                .policy_version()
                .context("computing policyVersion")?;
            if *effective {
                let yaml = loaded
                    .config
                    .to_effective_yaml()
                    .context("rendering the effective config")?;
                println!("# source: {}", loaded.source);
                println!("# policyVersion: {policy_version}");
                print!("{yaml}");
            } else {
                println!("config OK");
                println!("source: {}", loaded.source);
                println!("policyVersion: {policy_version}");
            }
            Ok(exit(exit_code::SUCCESS))
        }
        Command::Open {
            url,
            inline,
            max_inline_bytes,
            json,
        } => {
            let runtime = runtime()?;
            runtime.block_on(async {
                let app = match App::from_config(&loaded.config).await {
                    Ok(app) => app,
                    Err(err) => return Ok(startup_failure(&err)),
                };
                let mut arguments = serde_json::Map::new();
                arguments.insert("url".into(), url.clone().into());
                arguments.insert("inline".into(), (*inline).into());
                if let Some(bytes) = max_inline_bytes {
                    arguments.insert("maxInlineBytes".into(), (*bytes).into());
                }
                let response = SecureWebServer::new(app)
                    .call("web_open", Some(arguments))
                    .await
                    .context("web_open is not registered")?;
                print_open(&response, *json)?;
                Ok(exit(response.exit_code))
            })
        }
        Command::Serve { stdio, .. } => {
            let runtime = runtime()?;
            runtime.block_on(async {
                let app = match App::from_config(&loaded.config).await {
                    Ok(app) => app,
                    Err(err) => return Ok(startup_failure(&err)),
                };
                if *stdio {
                    secure_web_mcp::serve_stdio(app).await?;
                    return Ok(exit(exit_code::SUCCESS));
                }
                let server = &loaded.config.server;
                let listener = match secure_web_mcp::bind(server.listen, server.allow_remote).await
                {
                    Ok(listener) => listener,
                    Err(secure_web_mcp::ServeError::NotLoopback(addr)) => {
                        eprintln!(
                            "error: {addr} is not a loopback address; set server.allowRemote: true"
                        );
                        return Ok(exit(exit_code::USAGE));
                    }
                    Err(err @ secure_web_mcp::ServeError::Unspecified(_)) => {
                        eprintln!("error: {err}");
                        return Ok(exit(exit_code::USAGE));
                    }
                    Err(err) => return Err(err.into()),
                };
                eprintln!(
                    "secure-web MCP server on http://{}/mcp (Ctrl-C to stop)",
                    listener.local_addr()?
                );
                secure_web_mcp::serve_http(
                    app,
                    listener,
                    server.allow_remote,
                    secure_web_mcp::shutdown_signal(),
                )
                .await?;
                Ok(exit(exit_code::SUCCESS))
            })
        }
        Command::Crawl {
            url,
            depth,
            max_pages,
            scope,
            allow_hosts,
            include,
            exclude,
            json,
        } => {
            let runtime = runtime()?;
            runtime.block_on(async {
                let app = match App::from_config(&loaded.config).await {
                    Ok(app) => app,
                    Err(err) => return Ok(startup_failure(&err)),
                };
                let mut arguments = serde_json::Map::new();
                arguments.insert("url".into(), url.clone().into());
                if let Some(depth) = depth {
                    arguments.insert("maxDepth".into(), (*depth).into());
                }
                if let Some(pages) = max_pages {
                    arguments.insert("maxPages".into(), (*pages).into());
                }
                if let Some(scope) = scope {
                    arguments.insert("scope".into(), scope.contract_name().into());
                }
                for (key, values) in [
                    ("allowedHosts", allow_hosts),
                    ("includePatterns", include),
                    ("excludePatterns", exclude),
                ] {
                    if !values.is_empty() {
                        arguments.insert(key.into(), values.clone().into());
                    }
                }
                // Ctrl-C / SIGTERM cancel the crawl; it still finishes its manifest.
                let cancel = CancellationToken::new();
                let on_signal = cancel.clone();
                let signal = tokio::spawn(async move {
                    secure_web_mcp::shutdown_signal().await;
                    on_signal.cancel();
                });
                let response = SecureWebServer::new(app)
                    .call_cancellable("web_crawl", Some(arguments), cancel)
                    .await
                    .context("web_crawl is not registered")?;
                signal.abort();
                print_crawl(&response, *json)?;
                Ok(exit(response.exit_code))
            })
        }
        Command::Find { .. } | Command::Inspect { .. } => {
            eprintln!(
                "NOT_IMPLEMENTED: `secure-web {}` is not implemented yet",
                command.name()
            );
            Ok(exit(exit_code::INTERNAL))
        }
    }
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")
}

/// The pipeline could not be built: a config problem exits 2, a workspace problem 1.
fn startup_failure(err: &ProcessorError) -> ExitCode {
    eprintln!("error: {err}");
    match err {
        ProcessorError::Guard(_) | ProcessorError::Policy(_) | ProcessorError::Config(_) => {
            exit(exit_code::USAGE)
        }
        ProcessorError::Store(_) => exit(exit_code::INTERNAL),
    }
}

/// `--json`: the `web_open` JSON on stdout (errors too, as `{ "error": … }`). Otherwise a short
/// summary built from the same JSON, with errors on stderr.
fn print_open(response: &ToolResponse, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&response.body)?);
        return Ok(());
    }
    let body = &response.body;
    let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().to_owned();
    if response.is_error {
        let error = &body["error"];
        eprintln!(
            "error: {} {}",
            text(&error["code"]),
            text(&error["message"])
        );
        if let Some(manifest) = error["details"]["manifestPath"].as_str() {
            eprintln!("manifest: {manifest}");
        }
        return Ok(());
    }
    let status = text(&body["status"]);
    println!(
        "{status} {} ({})",
        text(&body["documentId"]),
        text(&body["runId"])
    );
    if status == "BLOCK" {
        let block = &body["block"];
        let ids: Vec<String> = block["findingIds"]
            .as_array()
            .map(|ids| ids.iter().map(text).collect())
            .unwrap_or_default();
        println!("reason: {}", text(&block["reason"]));
        println!("findings: {}", ids.join(","));
    } else {
        println!("content: {}", text(&body["contentPath"]));
    }
    println!("manifest: {}", text(&body["manifestPath"]));
    if let Some(content) = body["content"].as_str() {
        println!();
        print!("{content}");
        if body["truncated"].as_bool() == Some(true) {
            println!("\n[truncated]");
        }
    }
    Ok(())
}

/// `--json`: the `web_crawl` JSON on stdout (errors too). Otherwise the summary, status and
/// paths, blocked URLs with reasons, and errors on stderr — never page content.
fn print_crawl(response: &ToolResponse, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&response.body)?);
        return Ok(());
    }
    let body = &response.body;
    let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().to_owned();
    if response.is_error {
        let error = &body["error"];
        eprintln!(
            "error: {} {}",
            text(&error["code"]),
            text(&error["message"])
        );
        if let Some(manifest) = error["details"]["manifestPath"].as_str() {
            eprintln!("manifest: {manifest}");
        }
        return Ok(());
    }
    println!("{} {}", text(&body["status"]), text(&body["crawlId"]));
    println!("{}", text(&body["summary"]));
    println!("corpus: {}", text(&body["corpusPath"]));
    println!("manifest: {}", text(&body["manifestPath"]));
    if let Some(blocked) = body["blocked"].as_array() {
        for entry in blocked {
            println!(
                "blocked: {} {}",
                text(&entry["reason"]),
                text(&entry["url"])
            );
        }
    }
    Ok(())
}

fn init_tracing(level: LogLevel) {
    // A second initialisation can only fail if a subscriber is already set; keep that one.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(level.as_str()))
        .with_writer(std::io::stderr)
        .try_init();
}

fn exit(code: i32) -> ExitCode {
    u8::try_from(code).map_or(ExitCode::FAILURE, ExitCode::from)
}

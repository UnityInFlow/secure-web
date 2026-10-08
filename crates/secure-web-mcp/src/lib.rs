//! MCP server for Secure Web (`docs/contracts/mcp-contract.md`).
//!
//! - [`app`]: config → the shared `PageProcessor` plus the call semaphore; used by the MCP
//!   server and the CLI alike.
//! - [`tools`]: tool implementations (`web_open`, `web_crawl`; `web_find` in PR-09).
//! - [`server`]: the `rmcp` handler, the streamable-HTTP transport at `/mcp` (loopback unless
//!   `server.allowRemote`) and stdio.
#![forbid(unsafe_code)]

pub mod app;
pub mod server;
pub mod tools;

pub use app::App;
pub use secure_web_crawl::CancellationToken;
pub use server::{
    bind, serve_http, serve_stdio, shutdown_signal, SecureWebServer, ServeError, BODY_READ_TIMEOUT,
    HEADER_READ_TIMEOUT, MAX_REQUEST_BODY_BYTES,
};
pub use tools::crawl::WebCrawlInput;
pub use tools::open::{ToolResponse, WebOpenInput};

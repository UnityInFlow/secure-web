//! Contract error codes, the MCP error object, and CLI exit codes
//! (`docs/contracts/mcp-contract.md`).

use std::fmt;

use serde::{Deserialize, Serialize};

/// CLI exit codes (contract).
pub mod exit_code {
    /// Success, including `SAFE` and `WARN` results.
    pub const SUCCESS: i32 = 0;
    /// Internal error (also used for not-yet-implemented subcommands).
    pub const INTERNAL: i32 = 1;
    /// Usage or configuration error.
    pub const USAGE: i32 = 2;
    /// Security block (`BLOCK`).
    pub const SECURITY_BLOCK: i32 = 3;
    /// Fetch or network error.
    pub const FETCH: i32 = 4;
    /// Scanner failure.
    pub const SCANNER: i32 = 5;
    /// Crawl limit reached.
    pub const LIMIT_REACHED: i32 = 6;
    /// Cancelled.
    pub const CANCELLED: i32 = 7;
}

/// Error codes returned in the MCP error object (contract enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// The URL could not be parsed.
    InvalidUrl,
    /// The URL scheme is not `http` or `https`.
    UnsupportedScheme,
    /// DNS resolution failed.
    DnsFailed,
    /// The destination resolved to a blocked address.
    SsrfBlocked,
    /// A redirect hop was rejected.
    RedirectBlocked,
    /// The request timed out.
    FetchTimeout,
    /// The request failed for another network reason.
    FetchFailed,
    /// The response exceeded a size limit.
    ContentTooLarge,
    /// The response content type is not supported.
    UnsupportedContentType,
    /// Extraction failed.
    ExtractionFailed,
    /// The injection scanner failed (the page is blocked, never accepted).
    ScannerFailed,
    /// The page was blocked for prompt injection.
    PromptInjectionBlocked,
    /// A crawl budget was exhausted.
    CrawlLimitReached,
    /// The crawl was cancelled.
    CrawlCancelled,
    /// The requested run or document does not exist.
    NotFound,
    /// A tool argument was invalid.
    InvalidArgument,
    /// Internal error.
    Internal,
}

impl ErrorCode {
    /// Every code, in contract order.
    pub const ALL: [ErrorCode; 17] = [
        ErrorCode::InvalidUrl,
        ErrorCode::UnsupportedScheme,
        ErrorCode::DnsFailed,
        ErrorCode::SsrfBlocked,
        ErrorCode::RedirectBlocked,
        ErrorCode::FetchTimeout,
        ErrorCode::FetchFailed,
        ErrorCode::ContentTooLarge,
        ErrorCode::UnsupportedContentType,
        ErrorCode::ExtractionFailed,
        ErrorCode::ScannerFailed,
        ErrorCode::PromptInjectionBlocked,
        ErrorCode::CrawlLimitReached,
        ErrorCode::CrawlCancelled,
        ErrorCode::NotFound,
        ErrorCode::InvalidArgument,
        ErrorCode::Internal,
    ];

    /// The contract string, e.g. `SSRF_BLOCKED`.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidUrl => "INVALID_URL",
            ErrorCode::UnsupportedScheme => "UNSUPPORTED_SCHEME",
            ErrorCode::DnsFailed => "DNS_FAILED",
            ErrorCode::SsrfBlocked => "SSRF_BLOCKED",
            ErrorCode::RedirectBlocked => "REDIRECT_BLOCKED",
            ErrorCode::FetchTimeout => "FETCH_TIMEOUT",
            ErrorCode::FetchFailed => "FETCH_FAILED",
            ErrorCode::ContentTooLarge => "CONTENT_TOO_LARGE",
            ErrorCode::UnsupportedContentType => "UNSUPPORTED_CONTENT_TYPE",
            ErrorCode::ExtractionFailed => "EXTRACTION_FAILED",
            ErrorCode::ScannerFailed => "SCANNER_FAILED",
            ErrorCode::PromptInjectionBlocked => "PROMPT_INJECTION_BLOCKED",
            ErrorCode::CrawlLimitReached => "CRAWL_LIMIT_REACHED",
            ErrorCode::CrawlCancelled => "CRAWL_CANCELLED",
            ErrorCode::NotFound => "NOT_FOUND",
            ErrorCode::InvalidArgument => "INVALID_ARGUMENT",
            ErrorCode::Internal => "INTERNAL",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// CLI exit code for an error code (mapping documented in `docs/contracts/mcp-contract.md`).
impl From<ErrorCode> for i32 {
    fn from(code: ErrorCode) -> Self {
        match code {
            ErrorCode::InvalidUrl
            | ErrorCode::UnsupportedScheme
            | ErrorCode::InvalidArgument
            | ErrorCode::NotFound => exit_code::USAGE,
            ErrorCode::SsrfBlocked
            | ErrorCode::RedirectBlocked
            | ErrorCode::PromptInjectionBlocked => exit_code::SECURITY_BLOCK,
            ErrorCode::DnsFailed
            | ErrorCode::FetchTimeout
            | ErrorCode::FetchFailed
            | ErrorCode::ContentTooLarge
            | ErrorCode::UnsupportedContentType
            | ErrorCode::ExtractionFailed => exit_code::FETCH,
            ErrorCode::ScannerFailed => exit_code::SCANNER,
            ErrorCode::CrawlLimitReached => exit_code::LIMIT_REACHED,
            ErrorCode::CrawlCancelled => exit_code::CANCELLED,
            ErrorCode::Internal => exit_code::INTERNAL,
        }
    }
}

/// The MCP error object. `message` and `details` must never contain fetched content text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorObject {
    /// Contract error code.
    pub code: ErrorCode,
    /// Human-readable message generated by Secure Web (never page content).
    pub message: String,
    /// Whether retrying the same call may succeed.
    pub retryable: bool,
    /// Structured details (e.g. the requested `url`).
    #[serde(default)]
    pub details: serde_json::Map<String, serde_json::Value>,
}

impl ErrorObject {
    /// Build an error object with empty details.
    pub fn new(code: ErrorCode, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code,
            message: message.into(),
            retryable,
            details: serde_json::Map::new(),
        }
    }
}

/// The `{ "error": ErrorObject }` wrapper returned as MCP tool error content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorEnvelope {
    /// The error.
    pub error: ErrorObject,
}

impl From<ErrorObject> for ErrorEnvelope {
    fn from(error: ErrorObject) -> Self {
        Self { error }
    }
}

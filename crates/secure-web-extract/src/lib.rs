//! Extraction of `security_text` (everything) and `display` (readable structure) from one parse
//! (`docs/security-policy.md` §3, threats T3/T4/T13, ADR-013).
//!
//! - [`ExtractedDocument::security_text`] is the scanner input. It holds **every** textual signal
//!   of the page: visible text, `<title>`, `<meta>` content, every attribute value (`alt`,
//!   `title`, `aria-*`, `data-*`, `href`, `src`, …), comments, `<script>`/`<style>` bodies,
//!   `<noscript>`/`<template>` content and CSS/attribute-hidden nodes. Hidden segments are
//!   introduced by a `[hidden:<kind>]` marker line ([`HiddenKind`]).
//! - [`ExtractedDocument::display`] is the only source of model-facing text: visible, readable
//!   blocks with navigation chrome and hidden nodes removed. [`markdown::render`] turns it into
//!   byte-deterministic Markdown with no raw HTML.
//! - [`ExtractedDocument::links`] are resolved, `http(s)`-only, fragment-free, deduplicated and
//!   capped at `extract.maxLinksPerPage`.
//!
//! Every character filtered out of display text is filtered out of `security_text` the same
//! way, and `security_text` ends with the model-facing strings verbatim: the rendered display
//! Markdown after a [`VISIBLE_MARKER`] line, every exposed link URL after [`LINKS_MARKER`], the
//! page URL after [`URL_MARKER`] and the normalized title after `[hidden:title]`. So every
//! string the model will read is a contiguous substring of what the scanner reads (invariant
//! 8, ADR-013 rules 3 and 5). A rendered line already verbatim in the `[visible]` section is
//! not repeated in place.
//!
//! All work is bounded on hostile input: tokenizing is linear and non-recursive (an in-crate
//! tokenizer, ADR-013), tree construction does bounded stack scans, and every traversal is
//! iterative (no recursion on document depth).
#![forbid(unsafe_code)]

mod charset;
mod dom;
mod html;
pub mod markdown;
mod style;
mod text;
pub mod textclean;
pub mod title;
mod tokenizer;
#[cfg(test)]
mod work;

use std::fmt;

use secure_web_core::config::ExtractConfig;
use secure_web_core::error::ErrorCode;
use secure_web_core::model::{BlockReason, StructuredDocument};
use url::Url;

pub use crate::html::{HiddenKind, LINKS_MARKER, URL_MARKER, VISIBLE_MARKER};

/// What kind of body is being extracted (the fetcher's classified content type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// `text/html` / `application/xhtml+xml`.
    Html,
    /// `text/plain`.
    PlainText,
    /// `text/markdown`.
    Markdown,
    /// `application/json`.
    Json,
}

/// One body to extract. Everything in it is untrusted.
#[derive(Clone, Copy)]
pub struct ExtractInput<'a> {
    /// URL of the final response; relative links resolve against it.
    pub final_url: &'a Url,
    /// Classified content type.
    pub kind: SourceKind,
    /// Normalized `charset` parameter, if any.
    pub charset: Option<&'a str>,
    /// Decompressed body (already capped by the fetcher).
    pub body: &'a [u8],
}

impl fmt::Debug for ExtractInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtractInput")
            .field("kind", &self.kind)
            .field("charset", &self.charset)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Extraction limits (`extract:` config section).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractLimits {
    /// Largest `security_text`, in bytes; more is [`ExtractError::SecurityTextTooLarge`].
    pub max_security_text_bytes: usize,
    /// Most links kept per page; the rest set [`ExtractedDocument::links_truncated`].
    pub max_links_per_page: usize,
    /// Largest rendered display Markdown, in bytes; more is [`ExtractError::DisplayTooLarge`].
    pub max_display_bytes: usize,
}

impl From<&ExtractConfig> for ExtractLimits {
    fn from(cfg: &ExtractConfig) -> Self {
        Self {
            max_security_text_bytes: usize::try_from(cfg.max_security_text_bytes)
                .unwrap_or(usize::MAX),
            max_links_per_page: usize::try_from(cfg.max_links_per_page).unwrap_or(usize::MAX),
            max_display_bytes: usize::try_from(cfg.max_display_bytes).unwrap_or(usize::MAX),
        }
    }
}

impl Default for ExtractLimits {
    fn default() -> Self {
        Self::from(&ExtractConfig::default())
    }
}

/// The two outputs of one parse, plus links and title. Untrusted; `Debug` redacts all text.
#[derive(Clone, PartialEq, Eq)]
pub struct ExtractedDocument {
    /// Scanner input: everything textual, hidden segments marked (`docs/security-policy.md` §3).
    pub security_text: String,
    /// Visible, readable structure; the only source of model-facing text.
    pub display: StructuredDocument,
    /// Resolved `http(s)` links, fragment-free, deduplicated, in document order, capped.
    pub links: Vec<secure_web_core::model::DiscoveredLink>,
    /// Whether more distinct links existed than `max_links_per_page`.
    pub links_truncated: bool,
    /// Normalized title (`<title>` → `og:title` → first `<h1>`); also in `security_text`.
    pub title: Option<String>,
}

impl fmt::Debug for ExtractedDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtractedDocument")
            .field("security_text_bytes", &self.security_text.len())
            .field("display", &self.display)
            .field("links", &self.links.len())
            .field("links_truncated", &self.links_truncated)
            .field("title", &self.title.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Why extraction failed. Carries sizes only, never page text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExtractError {
    /// `security_text` would exceed `extract.maxSecurityTextBytes`.
    #[error("security text exceeds {limit} bytes")]
    SecurityTextTooLarge {
        /// The configured limit.
        limit: usize,
    },
    /// The rendered display would exceed `extract.maxDisplayBytes`.
    #[error("display text exceeds {limit} bytes")]
    DisplayTooLarge {
        /// The configured limit.
        limit: usize,
    },
    /// The document has more nodes than the extractor builds.
    #[error("document exceeds {limit} nodes")]
    TooManyNodes {
        /// The node limit.
        limit: usize,
    },
}

impl ExtractError {
    /// The contract error code (`CONTENT_TOO_LARGE` for every size bound).
    pub fn error_code(&self) -> ErrorCode {
        match self {
            ExtractError::SecurityTextTooLarge { .. }
            | ExtractError::DisplayTooLarge { .. }
            | ExtractError::TooManyNodes { .. } => ErrorCode::ContentTooLarge,
        }
    }

    /// The block reason recorded for a page that fails extraction.
    pub fn block_reason(&self) -> BlockReason {
        match self {
            ExtractError::SecurityTextTooLarge { .. }
            | ExtractError::DisplayTooLarge { .. }
            | ExtractError::TooManyNodes { .. } => BlockReason::ContentTooLarge,
        }
    }
}

/// Turns a fetched body into an [`ExtractedDocument`]. Extraction is CPU-bound and synchronous;
/// the trait exists so the page processor can be tested with a stub.
pub trait Extractor: Send + Sync {
    /// Extract `input`.
    fn extract(&self, input: &ExtractInput<'_>) -> Result<ExtractedDocument, ExtractError>;
}

/// HTML extractor: one parse, both outputs.
#[derive(Debug, Clone, Default)]
pub struct HtmlExtractor {
    limits: ExtractLimits,
}

impl HtmlExtractor {
    /// An HTML extractor with `limits`.
    pub fn new(limits: ExtractLimits) -> Self {
        Self { limits }
    }
}

impl Extractor for HtmlExtractor {
    fn extract(&self, input: &ExtractInput<'_>) -> Result<ExtractedDocument, ExtractError> {
        let source = charset::decode(input.body, input.charset);
        html::extract_html(&source, input.final_url, &self.limits)
    }
}

/// `text/plain` extractor: paragraphs split on blank lines.
#[derive(Debug, Clone, Default)]
pub struct PlainTextExtractor {
    limits: ExtractLimits,
}

impl PlainTextExtractor {
    /// A plain-text extractor with `limits`.
    pub fn new(limits: ExtractLimits) -> Self {
        Self { limits }
    }
}

impl Extractor for PlainTextExtractor {
    fn extract(&self, input: &ExtractInput<'_>) -> Result<ExtractedDocument, ExtractError> {
        let source = charset::decode(input.body, input.charset);
        text::extract_plain(&source, input.final_url, &self.limits)
    }
}

/// `text/markdown` extractor: raw HTML stripped, structure kept (via the HTML display path).
#[derive(Debug, Clone, Default)]
pub struct MarkdownExtractor {
    limits: ExtractLimits,
}

impl MarkdownExtractor {
    /// A Markdown extractor with `limits`.
    pub fn new(limits: ExtractLimits) -> Self {
        Self { limits }
    }
}

impl Extractor for MarkdownExtractor {
    fn extract(&self, input: &ExtractInput<'_>) -> Result<ExtractedDocument, ExtractError> {
        let source = charset::decode(input.body, input.charset);
        text::extract_markdown(&source, input.final_url, &self.limits)
    }
}

/// `application/json` extractor: pretty-printed inside one fenced block.
#[derive(Debug, Clone, Default)]
pub struct JsonExtractor {
    limits: ExtractLimits,
}

impl JsonExtractor {
    /// A JSON extractor with `limits`.
    pub fn new(limits: ExtractLimits) -> Self {
        Self { limits }
    }
}

impl Extractor for JsonExtractor {
    fn extract(&self, input: &ExtractInput<'_>) -> Result<ExtractedDocument, ExtractError> {
        let source = charset::decode(input.body, input.charset);
        text::extract_json(&source, input.final_url, &self.limits)
    }
}

/// Dispatches on [`ExtractInput::kind`]; the extractor the page processor uses.
#[derive(Debug, Clone, Default)]
pub struct ContentExtractor {
    limits: ExtractLimits,
}

impl ContentExtractor {
    /// A dispatching extractor with `limits`.
    pub fn new(limits: ExtractLimits) -> Self {
        Self { limits }
    }
}

impl Extractor for ContentExtractor {
    fn extract(&self, input: &ExtractInput<'_>) -> Result<ExtractedDocument, ExtractError> {
        match input.kind {
            SourceKind::Html => HtmlExtractor::new(self.limits).extract(input),
            SourceKind::PlainText => PlainTextExtractor::new(self.limits).extract(input),
            SourceKind::Markdown => MarkdownExtractor::new(self.limits).extract(input),
            SourceKind::Json => JsonExtractor::new(self.limits).extract(input),
        }
    }
}

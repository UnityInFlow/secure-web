//! Shared model enums (contract) and the trust-state types.
//!
//! ```text
//! fetch()                     -> UntrustedDocument
//! scan(UntrustedDocument)     -> ScannedDocument
//! accept(ScannedDocument)     -> Result<AcceptedDocument, BlockedDocument>
//! store(AcceptedDocument)     -> StoredDocument
//! ```
//!
//! Only an `AcceptedDocument` may reach the corpus or an MCP result. `ScannedDocument` and
//! `AcceptedDocument` are **sealed** in `secure_web_security::decision` (private fields, built
//! only by `scan_document` / `accept`, ADR-016); this crate holds the unsealed shapes around
//! them. [`UntrustedDocument`] deliberately does not implement `Serialize`, and its `Debug`
//! output redacts all content. [`BlockedDocument`] carries ids and enums only.
//!
//! PR-01 defines the shapes from `docs/architecture.md`; placeholder fields are marked and are
//! filled in by the PR that introduces the producing stage.

use std::fmt;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::ids::DocumentId;

/// Outcome of the security policy for one page (contract enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityDecision {
    /// No finding at or above the warn threshold.
    Safe,
    /// Stored but flagged (or quarantined, per `security.warnHandling`).
    Warn,
    /// Not stored; no content exposed.
    Block,
}

/// Scanner finding severity (contract enum), ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// Critical.
    Critical,
}

/// Why a page was blocked (contract enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlockReason {
    /// The scanner reported a blocking prompt-injection finding.
    PromptInjection,
    /// The destination resolved to a blocked address.
    Ssrf,
    /// The URL scheme is not supported.
    UnsupportedScheme,
    /// The content type is not supported.
    UnsupportedContentType,
    /// A size limit was exceeded.
    ContentTooLarge,
    /// The scanner failed; the page fails closed.
    ScannerFailure,
    /// A redirect hop violated policy.
    RedirectViolation,
    /// Another policy rule rejected the page.
    PolicyViolation,
}

/// Security metadata attached to every stored or blocked document. Ids only, never matched text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecuritySummary {
    /// Policy decision.
    pub decision: SecurityDecision,
    /// Highest finding severity, `null` when there were no findings.
    pub max_severity: Option<Severity>,
    /// Scanner finding ids (e.g. `PI001`).
    pub finding_ids: Vec<String>,
    /// Verbatim `injection-scanner --version` output.
    pub scanner_version: String,
    /// See [`crate::config::Config::policy_version`].
    pub policy_version: String,
}

/// Where a stored document came from (`metadata/NNNNNN.json`, `docs/contracts/manifest-schema.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Provenance {
    /// URL as requested.
    pub requested_url: Url,
    /// URL after redirects.
    pub final_url: Url,
    /// Every redirect hop, in order.
    pub redirect_chain: Vec<Url>,
    /// Final HTTP status.
    pub http_status: u16,
    /// Response `Content-Type`, as normalized by the fetcher.
    pub content_type: String,
    /// When the response was received.
    pub retrieved_at: DateTime<Utc>,
    /// Crawl depth (0 for `web_open`).
    pub depth: u32,
    /// Secure Web version that produced the document.
    pub secure_web_version: String,
    /// Verbatim `injection-scanner --version` output.
    pub scanner_version: String,
    /// Policy version in force.
    pub policy_version: String,
}

/// Parsed `Content-Type`. Placeholder until the fetcher (PR-03) owns MIME handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentType {
    /// MIME essence, e.g. `text/html`.
    pub essence: String,
    /// `charset` parameter, if any.
    pub charset: Option<String>,
}

/// Readable structure extracted from a page (the `display` output of the extractor,
/// `docs/security-policy.md` §3). Untrusted until accepted.
///
/// It only ever holds visible, readable text: hidden nodes, comments, scripts, attributes and
/// navigation chrome never reach it. It is serialized to Markdown by
/// `secure_web_extract::markdown::render`. `Debug` redacts all content.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct StructuredDocument {
    /// Normalized page title (untrusted; NFC, no control characters, at most 200 chars).
    pub title: Option<String>,
    /// Readable blocks, in document order.
    pub blocks: Vec<Block>,
}

impl fmt::Debug for StructuredDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StructuredDocument")
            .field("title", &self.title.as_ref().map(|_| Redacted))
            .field("blocks", &self.blocks.len())
            .finish()
    }
}

/// One block of readable structure. All text is untrusted page content; `Debug` redacts it.
#[derive(Clone, PartialEq, Eq)]
pub enum Block {
    /// A heading, level 1–6.
    Heading {
        /// Heading level (1–6).
        level: u8,
        /// Heading text (single line, whitespace collapsed).
        text: String,
    },
    /// A paragraph of inline content.
    Paragraph(Vec<Inline>),
    /// Preformatted code, verbatim.
    Code {
        /// Language hint (`[a-z0-9+#._-]`, at most 32 chars), if any.
        lang: Option<String>,
        /// Code text, `\n` line endings.
        text: String,
    },
    /// A list; each item is a sequence of blocks.
    List {
        /// Numbered (`<ol>`) or bulleted.
        ordered: bool,
        /// Items, in order.
        items: Vec<Vec<Block>>,
    },
    /// A table; the first row is the header row. Each cell is inline content.
    Table {
        /// Rows of cells.
        rows: Vec<Vec<Vec<Inline>>>,
    },
    /// A block quote.
    Quote(Vec<Block>),
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Block::Heading { level, text } => f
                .debug_struct("Heading")
                .field("level", level)
                .field("text_bytes", &text.len())
                .finish(),
            Block::Paragraph(inlines) => f.debug_tuple("Paragraph").field(inlines).finish(),
            Block::Code { lang, text } => f
                .debug_struct("Code")
                .field("lang", &lang.as_ref().map(|_| Redacted))
                .field("text_bytes", &text.len())
                .finish(),
            Block::List { ordered, items } => f
                .debug_struct("List")
                .field("ordered", ordered)
                .field("items", items)
                .finish(),
            Block::Table { rows } => f.debug_struct("Table").field("rows", &rows.len()).finish(),
            Block::Quote(blocks) => f.debug_tuple("Quote").field(blocks).finish(),
        }
    }
}

/// Inline content inside a paragraph or table cell. Untrusted; `Debug` redacts it.
#[derive(Clone, PartialEq, Eq)]
pub enum Inline {
    /// Plain text.
    Text(String),
    /// Inline code.
    Code(String),
    /// A hyperlink to an absolute, fragment-free `http(s)` URL.
    Link {
        /// Link target.
        href: Url,
        /// Link text.
        text: String,
    },
}

impl fmt::Debug for Inline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Inline::Text(text) => f.debug_tuple("Text").field(&text.len()).finish(),
            Inline::Code(text) => f.debug_tuple("Code").field(&text.len()).finish(),
            Inline::Link { text, .. } => f
                .debug_struct("Link")
                .field("href", &Redacted)
                .field("text_bytes", &text.len())
                .finish(),
        }
    }
}

/// One scanner finding, reduced to ids and numbers (`docs/security-policy.md` §4).
///
/// It deliberately has no field for the scanner's `matched_text`, `context`, `message`,
/// `remediation` or `file`: those are dropped at parse time, so no page text can ride along.
/// `id` and `detector` come from the scanner, never from the page, and the adapter rejects
/// output whose ids are not short identifiers.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Scanner pattern id, e.g. `PI001`.
    pub id: String,
    /// Finding severity.
    pub severity: Severity,
    /// Scanner pattern name, e.g. `ignore-previous-instructions`.
    pub detector: String,
    /// 1-based line in `security_text`.
    pub line: u32,
    /// Scanner confidence in `0.0..=1.0`. Telemetry only; the policy decides on severity.
    pub confidence: f32,
}

/// Scanner output for one document: ids, severities and counts only, never page text.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityFindings {
    /// Verbatim `injection-scanner --version` output (`injection-scanner X.Y.Z`).
    pub scanner_version: String,
    /// Findings from the scanner's `matches` array, in scanner order.
    pub findings: Vec<Finding>,
    /// Number of `low_confidence` entries. Observability only; never changes the decision.
    pub low_confidence_count: usize,
    /// Highest severity among `findings`, recomputed from them (the scanner's counters are not
    /// trusted).
    pub max_severity: Option<Severity>,
    /// Wall time of the scan, including process spawn.
    pub scan_duration: std::time::Duration,
}

impl SecurityFindings {
    /// Build findings, computing `max_severity` from `findings`.
    pub fn new(
        scanner_version: String,
        findings: Vec<Finding>,
        low_confidence_count: usize,
        scan_duration: std::time::Duration,
    ) -> Self {
        let max_severity = findings.iter().map(|finding| finding.severity).max();
        Self {
            scanner_version,
            findings,
            low_confidence_count,
            max_severity,
            scan_duration,
        }
    }

    /// Finding ids in scanner order, deduplicated (first occurrence wins).
    pub fn finding_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = Vec::with_capacity(self.findings.len());
        for finding in &self.findings {
            if !ids.contains(&finding.id) {
                ids.push(finding.id.clone());
            }
        }
        ids
    }
}

/// A link found on a page.
///
/// `url` is the resolved, fragment-free link: the string the page exposes (a whole line of the
/// scanned `security_text` once the page is accepted), recorded in run files and used for
/// scope and dedupe. `as_written` is the href text the URL guard validates: parsing rewrites a
/// non-canonical IPv4 spelling (`http://1572395042/`) and drops an empty userinfo `@`, so the
/// guard's raw-text rules (`docs/security-policy.md` §1) only work on the original. It is the
/// href itself (fragment cut) when it names its own authority, `<base scheme>:` + the href for a
/// scheme-relative one, and `url` for a path-relative one (the authority is the base's, already
/// validated). It is never recorded, logged or returned. `Debug` prints the host only.
#[derive(Clone, PartialEq, Eq)]
pub struct DiscoveredLink {
    /// Resolved link URL (exposed form).
    pub url: Url,
    /// The href text the guard validates.
    pub as_written: String,
}

impl DiscoveredLink {
    /// A link whose written form is its own serialization (no raw text to preserve).
    pub fn from_url(url: Url) -> Self {
        let as_written = url.as_str().to_owned();
        Self { url, as_written }
    }
}

impl fmt::Debug for DiscoveredLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscoveredLink")
            .field("scheme", &self.url.scheme())
            .field("host", &self.url.host_str())
            .finish_non_exhaustive()
    }
}

/// A fetched and extracted page that has **not** been scanned. Never serialized, never stored,
/// never returned; `Debug` redacts all content, including the URLs.
#[derive(Clone)]
pub struct UntrustedDocument {
    /// URL as requested.
    pub requested_url: Url,
    /// URL after redirects.
    pub final_url: Url,
    /// Every redirect hop, in order.
    pub redirect_chain: Vec<Url>,
    /// Final HTTP status.
    pub http_status: u16,
    /// Response content type.
    pub content_type: ContentType,
    /// When the response was received.
    pub retrieved_at: DateTime<Utc>,
    /// Everything textual, including hidden text, comments and metadata — scanner input only.
    pub security_text: String,
    /// Visible, readable structure.
    pub display: StructuredDocument,
    /// Links found on the page.
    pub links: Vec<DiscoveredLink>,
    /// Raw body, only when `debug.retainRaw = true`.
    pub raw_bytes: Option<Vec<u8>>,
}

/// Marker printed instead of untrusted content in `Debug` output.
struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Debug for UntrustedDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UntrustedDocument")
            // Both URLs may be server-chosen (a redirect target, a crawled link) and are not
            // scanned yet: print their size only.
            .field("requested_url", &Redacted)
            .field("requested_url_bytes", &self.requested_url.as_str().len())
            .field("final_url", &Redacted)
            .field("final_url_bytes", &self.final_url.as_str().len())
            .field("redirect_hops", &self.redirect_chain.len())
            .field("http_status", &self.http_status)
            .field("content_type", &self.content_type.essence)
            .field("retrieved_at", &self.retrieved_at)
            .field("security_text", &Redacted)
            .field("security_text_bytes", &self.security_text.len())
            .field("display", &Redacted)
            .field("links", &self.links.len())
            .field("raw_bytes", &self.raw_bytes.as_ref().map(|_| Redacted))
            .finish()
    }
}

/// A document the policy blocked. Ids, URLs and enums only — no body, title or matched text.
///
/// `Debug` prints neither URL: until `PageProcessor` withholds it, `final_url` may be a
/// server-chosen redirect target that was part of the blocked text (invariant 4).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlockedDocument {
    /// Document id within its run.
    pub doc_id: DocumentId,
    /// URL as requested.
    pub requested_url: Url,
    /// URL after redirects, if the fetch got that far.
    pub final_url: Option<Url>,
    /// Why the page was blocked.
    pub reason: BlockReason,
    /// Highest finding severity, if the scanner ran.
    pub max_severity: Option<Severity>,
    /// Scanner finding ids.
    pub finding_ids: Vec<String>,
    /// Verbatim `injection-scanner --version` output, if the scanner ran.
    pub scanner_version: Option<String>,
}

impl fmt::Debug for BlockedDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockedDocument")
            .field("doc_id", &self.doc_id)
            .field("requested_url", &Redacted)
            .field("requested_url_bytes", &self.requested_url.as_str().len())
            .field("final_url", &self.final_url.as_ref().map(|_| Redacted))
            .field(
                "final_url_bytes",
                &self.final_url.as_ref().map(|u| u.as_str().len()),
            )
            .field("reason", &self.reason)
            .field("max_severity", &self.max_severity)
            .field("finding_ids", &self.finding_ids)
            .field("scanner_version", &self.scanner_version)
            .finish()
    }
}

/// An accepted document after it was written to the corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDocument {
    /// Document id within its run.
    pub doc_id: DocumentId,
    /// Absolute path of the stored Markdown file.
    pub content_path: PathBuf,
    /// Size of the stored Markdown in bytes.
    pub content_bytes: u64,
    /// Security summary.
    pub security: SecuritySummary,
}

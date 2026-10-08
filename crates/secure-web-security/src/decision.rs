//! The trust-state step (`docs/architecture.md`, CLAUDE.md "Trust-state types"):
//!
//! ```text
//! scan(UntrustedDocument)     -> ScannedDocument        (scan_document)
//! accept(ScannedDocument)     -> Result<AcceptedDocument, BlockedDocument>
//! ```
//!
//! [`scan_and_decide`] (and its shorthand [`scan_and_accept`]) is the one entry point the page
//! processor uses: it feeds the document's **entire** `security_text` to the scanner, blocks on
//! any scan error, and otherwise applies the policy.
//!
//! # Sealed trust states (ADR-016)
//!
//! [`ScannedDocument`], [`AcceptedDocument`] and [`RawContent`] live in this module and have only
//! private fields, so Rust privacy makes this module the only code that can construct or modify
//! them. An [`AcceptedDocument`] is only ever built by [`accept`], from strings that were part of
//! the scanned `security_text` (ADR-013 "scanner sees what the model sees", ADR-014); a
//! [`RawContent`] is only ever the body and `security_text` of a document this module scanned.
//! Every other crate can read them, clone them and hand them on, never forge or edit them.
//!
//! A struct literal outside this module does not compile:
//!
//! ```compile_fail
//! use secure_web_security::decision::AcceptedDocument;
//! fn forge(doc: AcceptedDocument) -> AcceptedDocument {
//!     AcceptedDocument { markdown: "unscanned".into(), ..doc }
//! }
//! ```
//!
//! ```compile_fail
//! use secure_web_security::decision::ScannedDocument;
//! use secure_web_core::model::{SecurityFindings, UntrustedDocument};
//! fn forge(doc: UntrustedDocument, findings: SecurityFindings) -> ScannedDocument {
//!     ScannedDocument { doc, findings }
//! }
//! ```
//!
//! ```compile_fail
//! use secure_web_security::decision::RawContent;
//! fn forge() -> RawContent {
//!     RawContent { raw_bytes: None, security_text: "anything".into() }
//! }
//! ```
//!
//! and neither does editing an accepted document in place:
//!
//! ```compile_fail
//! use secure_web_security::decision::AcceptedDocument;
//! fn edit(mut doc: AcceptedDocument) {
//!     doc.markdown = "unscanned".into();
//! }
//! ```
//!
//! while reading one does:
//!
//! ```
//! use secure_web_security::decision::AcceptedDocument;
//! fn read(doc: &AcceptedDocument) -> usize {
//!     doc.markdown().len() + doc.title().map_or(0, str::len)
//! }
//! ```

use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

use secure_web_core::ids::DocumentId;
use secure_web_core::model::{
    BlockReason, BlockedDocument, DiscoveredLink, Finding, Provenance, SecurityFindings,
    SecuritySummary, UntrustedDocument,
};
use secure_web_core::SECURE_WEB_VERSION;
use secure_web_extract::markdown::render;
use url::Url;

use crate::injection::{ScanError, SecurityScanner};
use crate::policy::{decide_error, PolicyOutcome, SecurityPolicy};

/// An untrusted document plus its scanner findings, awaiting a policy decision. Sealed: only
/// [`scan_document`] builds one, so [`accept`] never sees findings that do not belong to the
/// document. `Debug` redacts all content.
#[derive(Debug, Clone)]
pub struct ScannedDocument {
    doc: UntrustedDocument,
    findings: SecurityFindings,
}

impl ScannedDocument {
    /// The scanned document (untrusted).
    pub fn document(&self) -> &UntrustedDocument {
        &self.doc
    }

    /// The scanner findings for [`ScannedDocument::document`].
    pub fn findings(&self) -> &SecurityFindings {
        &self.findings
    }
}

/// A document the policy accepted (`SAFE` or `WARN`): the only type the corpus store accepts and
/// the only source of model-facing text. Sealed (see the module docs): built only by [`accept`],
/// read-only everywhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedDocument {
    doc_id: DocumentId,
    final_url: Url,
    requested_url: Url,
    title: Option<String>,
    markdown: String,
    links: Vec<DiscoveredLink>,
    security: SecuritySummary,
    provenance: Provenance,
}

impl AcceptedDocument {
    /// Document id within its run.
    pub fn doc_id(&self) -> &DocumentId {
        &self.doc_id
    }

    /// URL after redirects (a whole line of the scanned `security_text`).
    pub fn final_url(&self) -> &Url {
        &self.final_url
    }

    /// URL as requested.
    pub fn requested_url(&self) -> &Url {
        &self.requested_url
    }

    /// Normalized, scanned title (a whole line of the scanned `security_text`).
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Markdown rendered from `display`, never from `security_text`; a contiguous substring of
    /// the scanned `security_text`.
    pub fn markdown(&self) -> &str {
        &self.markdown
    }

    /// Links found on the page (only accepted pages contribute links); each a whole line of the
    /// scanned `security_text`.
    pub fn links(&self) -> &[DiscoveredLink] {
        &self.links
    }

    /// Security summary; decision is `SAFE` or `WARN`.
    pub fn security(&self) -> &SecuritySummary {
        &self.security
    }

    /// Provenance.
    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }
}

/// Raw content kept for operators when `debug.retainRaw = true`: the decompressed body and the
/// exact `security_text` the scanner read. Written only under the private-audit root, never
/// under `runs/`. Sealed: only [`scan_and_decide`] builds one, from the document it scanned, so
/// no caller can put arbitrary bytes into the private audit. `Debug` redacts it.
#[derive(Clone)]
pub struct RawContent {
    raw_bytes: Option<Vec<u8>>,
    security_text: String,
}

impl RawContent {
    /// Decompressed response body, if the fetcher kept it.
    pub fn raw_bytes(&self) -> Option<&[u8]> {
        self.raw_bytes.as_deref()
    }

    /// The `security_text` the scanner read.
    pub fn security_text(&self) -> &str {
        &self.security_text
    }
}

impl fmt::Debug for RawContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawContent")
            .field("raw_bytes", &self.raw_bytes.as_ref().map(Vec::len))
            .field("security_text_bytes", &self.security_text.len())
            .finish()
    }
}

/// Per-document context the decision needs but the document does not carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptContext {
    /// Id the document gets within its run (accepted or blocked).
    pub doc_id: DocumentId,
    /// Crawl depth (0 for `web_open`).
    pub depth: u32,
    /// `debug.retainRaw`: return the document's body and `security_text` as [`RawContent`] for
    /// the private audit.
    pub retain_raw: bool,
}

impl AcceptContext {
    /// Context for `doc_id` at `depth`, without raw retention.
    pub fn new(doc_id: DocumentId, depth: u32) -> Self {
        Self {
            doc_id,
            depth,
            retain_raw: false,
        }
    }
}

/// Everything one scan-and-decide produced.
#[derive(Debug, Clone)]
pub struct Decision {
    /// The accepted or blocked document.
    pub outcome: Result<AcceptedDocument, BlockedDocument>,
    /// The scanner findings behind the outcome's finding ids (empty when the scan failed): what
    /// the store records in `security/findings.json`.
    pub findings: Vec<Finding>,
    /// Scan wall time, if the scanner produced a report.
    pub scan_duration: Option<Duration>,
    /// Raw content for the private audit, only when [`AcceptContext::retain_raw`] is set.
    pub raw: Option<RawContent>,
}

/// Scan the document's full `security_text`.
#[allow(clippy::result_large_err)]
pub async fn scan_document(
    doc: UntrustedDocument,
    scanner: &dyn SecurityScanner,
) -> Result<ScannedDocument, (UntrustedDocument, ScanError)> {
    match scanner.scan(&doc.security_text).await {
        Ok(findings) => Ok(ScannedDocument { doc, findings }),
        Err(err) => Err((doc, err)),
    }
}

/// Scan `doc` and decide: the single scan → policy path for all model-facing content.
///
/// A scan error of any kind yields `BlockedDocument { reason: SCANNER_FAILURE }` via
/// [`decide_error`] (ADR-003); it is never treated as "no findings". The findings are returned
/// alongside the outcome so the store can describe every finding id it records.
pub async fn scan_and_decide(
    doc: UntrustedDocument,
    scanner: &dyn SecurityScanner,
    policy: &dyn SecurityPolicy,
    ctx: &AcceptContext,
) -> Decision {
    let raw = ctx.retain_raw.then(|| RawContent {
        raw_bytes: doc.raw_bytes.clone(),
        security_text: doc.security_text.clone(),
    });
    match scan_document(doc, scanner).await {
        Ok(scanned) => {
            let findings = scanned.findings.findings.clone();
            let scan_duration = Some(scanned.findings.scan_duration);
            Decision {
                outcome: accept(scanned, policy, ctx),
                findings,
                scan_duration,
                raw,
            }
        }
        Err((doc, err)) => {
            // ADR-003: fail closed. The error's Display carries no scanner output or page text.
            tracing::warn!(doc_id = %ctx.doc_id, error = %err, "injection scan failed; page blocked");
            let reason = match decide_error(&err) {
                PolicyOutcome::Block(reason) => reason,
                PolicyOutcome::Safe | PolicyOutcome::Warn => BlockReason::ScannerFailure,
            };
            Decision {
                outcome: Err(BlockedDocument {
                    doc_id: ctx.doc_id.clone(),
                    requested_url: doc.requested_url,
                    final_url: Some(doc.final_url),
                    reason,
                    max_severity: None,
                    finding_ids: Vec::new(),
                    scanner_version: None,
                }),
                findings: Vec::new(),
                scan_duration: None,
                raw,
            }
        }
    }
}

/// [`scan_and_decide`], keeping only the outcome.
#[allow(clippy::result_large_err)]
pub async fn scan_and_accept(
    doc: UntrustedDocument,
    scanner: &dyn SecurityScanner,
    policy: &dyn SecurityPolicy,
    ctx: &AcceptContext,
) -> Result<AcceptedDocument, BlockedDocument> {
    scan_and_decide(doc, scanner, policy, ctx).await.outcome
}

/// Apply the policy to a scanned document.
///
/// ADR-005 (blocked payload is never agent-visible): a blocked document keeps ids, URLs and
/// enums only — no title, Markdown, security text or matched text. An accepted document's
/// `markdown` is rendered from `display` only, never from `security_text`, and every
/// model-facing string it exposes (Markdown, title, links, final URL) must occur in the scanned
/// `security_text`; if one does not, the page is blocked as `POLICY_VIOLATION` rather than
/// exposing text the scanner never saw (ADR-013, ADR-014).
// The trust-state signature is fixed by `docs/architecture.md`; both documents are moved, not copied.
#[allow(clippy::result_large_err)]
pub fn accept(
    scanned: ScannedDocument,
    policy: &dyn SecurityPolicy,
    ctx: &AcceptContext,
) -> Result<AcceptedDocument, BlockedDocument> {
    let ScannedDocument { doc, findings } = scanned;
    let blocked = |doc: UntrustedDocument, reason: BlockReason| BlockedDocument {
        doc_id: ctx.doc_id.clone(),
        requested_url: doc.requested_url,
        final_url: Some(doc.final_url),
        reason,
        max_severity: findings.max_severity,
        finding_ids: findings.finding_ids(),
        scanner_version: Some(findings.scanner_version.clone()),
    };

    let outcome = policy.decide(&findings);
    if let PolicyOutcome::Block(reason) = outcome {
        return Err(blocked(doc, reason));
    }

    let markdown = render(&doc.display);
    if !exposed_strings_were_scanned(&doc, &markdown) {
        tracing::warn!(
            doc_id = %ctx.doc_id,
            "model-facing text missing from the scanned security_text; page blocked"
        );
        return Err(blocked(doc, BlockReason::PolicyViolation));
    }

    let security = SecuritySummary {
        decision: outcome.decision(),
        max_severity: findings.max_severity,
        finding_ids: findings.finding_ids(),
        scanner_version: findings.scanner_version.clone(),
        policy_version: policy.policy_version().to_owned(),
    };
    let provenance = Provenance {
        requested_url: doc.requested_url.clone(),
        final_url: doc.final_url.clone(),
        redirect_chain: doc.redirect_chain,
        http_status: doc.http_status,
        content_type: doc.content_type.essence,
        retrieved_at: doc.retrieved_at,
        depth: ctx.depth,
        secure_web_version: SECURE_WEB_VERSION.to_owned(),
        scanner_version: findings.scanner_version,
        policy_version: policy.policy_version().to_owned(),
    };
    Ok(AcceptedDocument {
        doc_id: ctx.doc_id.clone(),
        final_url: doc.final_url,
        requested_url: doc.requested_url,
        title: doc.display.title,
        markdown,
        links: doc.links,
        security,
        provenance,
    })
}

/// Whether every string an [`AcceptedDocument`] would expose is part of the scanned
/// `security_text`: the rendered Markdown as a contiguous substring, and the title, each link
/// and the final URL as whole lines (the extractor's `[visible]`, `[hidden:title]`, `[links]`
/// and `[url]` sections, ADR-013).
fn exposed_strings_were_scanned(doc: &UntrustedDocument, markdown: &str) -> bool {
    let text = &doc.security_text;
    if !markdown.is_empty() && !text.contains(markdown) {
        return false;
    }
    let lines: HashSet<&str> = text.split('\n').collect();
    let title_ok = doc
        .display
        .title
        .as_deref()
        .is_none_or(|title| lines.contains(title));
    title_ok
        && lines.contains(doc.final_url.as_str())
        && doc
            .links
            .iter()
            .all(|link| lines.contains(link.url.as_str()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use chrono::Utc;
    use secure_web_core::config::SecurityConfig;
    use secure_web_core::model::{
        Block, ContentType, Inline, SecurityDecision, Severity, StructuredDocument,
    };

    use super::*;
    use crate::injection::ScanFuture;
    use crate::policy::PolicyEngine;

    const PAGE: &str = "https://example.test/page";
    const LINK: &str = "https://example.test/other";

    fn display() -> StructuredDocument {
        StructuredDocument {
            title: Some("Release notes".into()),
            blocks: vec![Block::Paragraph(vec![Inline::Text("Hello world.".into())])],
        }
    }

    /// A document whose security_text holds every exposed string, as the extractor builds it.
    fn doc() -> UntrustedDocument {
        let display = display();
        let markdown = render(&display);
        UntrustedDocument {
            requested_url: Url::parse(PAGE).unwrap(),
            final_url: Url::parse(PAGE).unwrap(),
            redirect_chain: vec![],
            http_status: 200,
            content_type: ContentType {
                essence: "text/html".into(),
                charset: Some("utf-8".into()),
            },
            retrieved_at: Utc::now(),
            security_text: format!(
                "[hidden:comment]\nsecret\n[visible]\n{markdown}\n[links]\n{LINK}\n[url]\n{PAGE}\n\
                 [hidden:title]\nRelease notes\n"
            ),
            display,
            links: vec![DiscoveredLink::from_url(Url::parse(LINK).unwrap())],
            raw_bytes: None,
        }
    }

    fn findings(severities: &[Severity]) -> SecurityFindings {
        SecurityFindings::new(
            "injection-scanner 0.1.0".into(),
            severities
                .iter()
                .map(|&severity| Finding {
                    id: "PI001".into(),
                    severity,
                    detector: "ignore-previous-instructions".into(),
                    line: 1,
                    confidence: 1.0,
                })
                .collect(),
            0,
            Duration::ZERO,
        )
    }

    fn ctx() -> AcceptContext {
        AcceptContext::new(DocumentId::from_seq(7).unwrap(), 2)
    }

    fn policy() -> PolicyEngine {
        PolicyEngine::new(&SecurityConfig::default()).unwrap()
    }

    fn scanned(doc: UntrustedDocument, severities: &[Severity]) -> ScannedDocument {
        ScannedDocument {
            doc,
            findings: findings(severities),
        }
    }

    #[test]
    fn safe_document_is_accepted_with_markdown_from_display() {
        let accepted = accept(scanned(doc(), &[Severity::Low]), &policy(), &ctx()).unwrap();
        assert_eq!(accepted.markdown, render(&display()));
        assert!(!accepted.markdown.contains("secret"));
        assert_eq!(accepted.title(), Some("Release notes"));
        assert_eq!(
            accepted.links(),
            vec![DiscoveredLink::from_url(Url::parse(LINK).unwrap())]
        );
        assert_eq!(accepted.security().decision, SecurityDecision::Safe);
        assert_eq!(accepted.security().max_severity, Some(Severity::Low));
        assert_eq!(accepted.security().finding_ids, ["PI001"]);
        assert_eq!(
            accepted.security().policy_version,
            policy().policy_version()
        );
        assert_eq!(accepted.provenance().depth, 2);
        assert_eq!(accepted.provenance().content_type, "text/html");
        assert_eq!(accepted.provenance().secure_web_version, SECURE_WEB_VERSION);
        assert_eq!(
            accepted.provenance().scanner_version,
            "injection-scanner 0.1.0"
        );
        assert_eq!(accepted.doc_id(), &ctx().doc_id);
    }

    #[test]
    fn medium_is_accepted_as_warn() {
        let accepted = accept(scanned(doc(), &[Severity::Medium]), &policy(), &ctx()).unwrap();
        assert_eq!(accepted.security().decision, SecurityDecision::Warn);
    }

    #[test]
    fn critical_is_blocked_with_ids_only() {
        let blocked = accept(scanned(doc(), &[Severity::Critical]), &policy(), &ctx()).unwrap_err();
        assert_eq!(blocked.reason, BlockReason::PromptInjection);
        assert_eq!(blocked.max_severity, Some(Severity::Critical));
        assert_eq!(blocked.finding_ids, ["PI001"]);
        assert_eq!(blocked.final_url, Some(Url::parse(PAGE).unwrap()));
        assert_eq!(
            blocked.scanner_version.as_deref(),
            Some("injection-scanner 0.1.0")
        );
    }

    #[test]
    fn exposed_text_missing_from_security_text_is_blocked() {
        let cases: [fn(&mut UntrustedDocument); 5] = [
            |d| d.security_text = d.security_text.replace("Hello world.", "Hello"),
            |d| d.display.title = Some("Other title".into()),
            |d| {
                d.links.push(DiscoveredLink::from_url(
                    Url::parse("https://example.test/unscanned").unwrap(),
                ))
            },
            |d| d.final_url = Url::parse("https://example.test/elsewhere").unwrap(),
            // A title that only occurs inside a longer line does not count.
            |d| d.display.title = Some("Release".into()),
        ];
        for mutate in cases {
            let mut doc = doc();
            mutate(&mut doc);
            let blocked = accept(scanned(doc, &[]), &policy(), &ctx()).unwrap_err();
            assert_eq!(blocked.reason, BlockReason::PolicyViolation);
        }
    }

    #[test]
    fn empty_display_without_title_is_accepted() {
        let mut doc = doc();
        doc.display = StructuredDocument::default();
        doc.links.clear();
        let accepted = accept(scanned(doc, &[]), &policy(), &ctx()).unwrap();
        assert_eq!(accepted.markdown, "");
        assert_eq!(accepted.title, None);
    }

    struct Fixed(Result<SecurityFindings, ScanError>);

    impl SecurityScanner for Fixed {
        fn scan<'a>(&'a self, _security_text: &'a str) -> ScanFuture<'a> {
            let result = self.0.clone();
            Box::pin(async move { result })
        }
    }

    /// Records what it was asked to scan.
    struct Recording(std::sync::Mutex<String>);

    impl SecurityScanner for Recording {
        fn scan<'a>(&'a self, security_text: &'a str) -> ScanFuture<'a> {
            if let Ok(mut seen) = self.0.lock() {
                *seen = security_text.to_owned();
            }
            Box::pin(async { Ok(findings(&[])) })
        }
    }

    #[tokio::test]
    async fn scan_errors_block_as_scanner_failure() {
        let scanner = Fixed(Err(ScanError::Timeout(Duration::from_secs(2))));
        let blocked = scan_and_accept(doc(), &scanner, &policy(), &ctx())
            .await
            .unwrap_err();
        assert_eq!(blocked.reason, BlockReason::ScannerFailure);
        assert_eq!(blocked.max_severity, None);
        assert!(blocked.finding_ids.is_empty());
        assert_eq!(blocked.scanner_version, None);
    }

    #[tokio::test]
    async fn scanner_receives_the_entire_security_text() {
        let scanner = Recording(std::sync::Mutex::new(String::new()));
        let doc = doc();
        let expected = doc.security_text.clone();
        scan_and_accept(doc, &scanner, &policy(), &ctx())
            .await
            .unwrap();
        assert_eq!(*scanner.0.lock().unwrap(), expected);
    }

    #[tokio::test]
    async fn successful_scan_goes_through_the_policy() {
        let scanner = Fixed(Ok(findings(&[Severity::High])));
        let blocked = scan_and_accept(doc(), &scanner, &policy(), &ctx())
            .await
            .unwrap_err();
        assert_eq!(blocked.reason, BlockReason::PromptInjection);
    }

    #[tokio::test]
    async fn decision_carries_the_findings_and_raw_content_only_on_request() {
        let scanner = Fixed(Ok(findings(&[Severity::Medium])));
        let mut doc = doc();
        doc.raw_bytes = Some(b"<p>Hello world.</p>".to_vec());
        let expected_text = doc.security_text.clone();

        let decision = scan_and_decide(doc.clone(), &scanner, &policy(), &ctx()).await;
        assert!(decision.outcome.is_ok());
        assert_eq!(decision.findings.len(), 1);
        assert_eq!(decision.findings[0].id, "PI001");
        assert_eq!(decision.scan_duration, Some(Duration::ZERO));
        assert!(decision.raw.is_none());

        let retain = AcceptContext {
            retain_raw: true,
            ..ctx()
        };
        let decision = scan_and_decide(doc, &scanner, &policy(), &retain).await;
        let raw = decision.raw.unwrap();
        assert_eq!(raw.security_text(), expected_text);
        assert_eq!(raw.raw_bytes(), Some(&b"<p>Hello world.</p>"[..]));
        let debug = format!("{raw:?}");
        assert!(!debug.contains("Hello"), "{debug}");
    }

    #[tokio::test]
    async fn failed_scans_return_no_findings_but_keep_raw_content() {
        let scanner = Fixed(Err(ScanError::NotFound));
        let retain = AcceptContext {
            retain_raw: true,
            ..ctx()
        };
        let decision = scan_and_decide(doc(), &scanner, &policy(), &retain).await;
        assert!(decision.outcome.is_err());
        assert!(decision.findings.is_empty());
        assert_eq!(decision.scan_duration, None);
        assert!(decision.raw.is_some());
    }

    #[test]
    fn sealed_types_are_readable() {
        let scanned = scanned(doc(), &[Severity::Low]);
        assert_eq!(scanned.findings().findings.len(), 1);
        assert_eq!(scanned.document().final_url.as_str(), PAGE);
        let accepted = accept(scanned, &policy(), &ctx()).unwrap();
        assert_eq!(accepted.requested_url().as_str(), PAGE);
        assert_eq!(accepted.final_url().as_str(), PAGE);
        assert_eq!(accepted.doc_id(), &ctx().doc_id);
        assert_eq!(accepted.provenance().http_status, 200);
    }
}

//! HTML extraction: one parse, two outputs (`docs/security-policy.md` §3, ADR-013).
//!
//! 1. [`dom::parse`] builds a bounded arena tree with the in-crate tokenizer.
//! 2. A **survey** walk over the whole document collects the links (outside hidden subtrees),
//!    the title sources and the display root.
//! 3. The **display walk** visits only the readable root (`<main>`, else `<body>`), skipping
//!    hidden nodes and chrome, builds [`Block`]s and records which text nodes it rendered.
//! 4. The **security walk** visits every node of the document and writes `security_text`:
//!    visible text in place (a rendered line found verbatim in the rendered Markdown is left to
//!    the `[visible]` section), hidden subtrees behind a `[hidden:<kind>]` marker line,
//!    comments, doctype and `<meta>` content as their own marked segments, and every other
//!    attribute value (deduplicated) in a trailing `[hidden:attr]` segment.
//! 5. The model-facing sections follow verbatim: `[visible]` (rendered Markdown), `[links]`
//!    (every exposed link URL), `[url]` (the page URL) and `[hidden:title]` (normalized title).

use std::collections::HashSet;

use secure_web_core::model::{Block, DiscoveredLink, Inline, StructuredDocument};
use url::Url;

use crate::dom::{self, Dom, Element, Event, NodeData, NodeId, Walk, ROOT};
use crate::style::{hidden_by_style, StyleHidden};
use crate::textclean::{self, collapse, collapse_for_scan};
use crate::title::normalize_title;
use crate::{markdown, ExtractError, ExtractLimits, ExtractedDocument};

/// Longest `href` considered for a link; longer ones are dropped.
const MAX_HREF_BYTES: usize = 4096;

/// Deepest nesting of lists and quotes in `display`; deeper ones are flattened.
const MAX_BLOCK_NESTING: usize = 8;

/// Most columns kept per table row.
const MAX_TABLE_COLUMNS: usize = 64;

/// The kind of a hidden `security_text` segment, shown as `[hidden:<kind>]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HiddenKind {
    /// Inline style `display:none`, `visibility:hidden`, `opacity:0`, `color:transparent`.
    Css,
    /// Zero-size box: `font-size:0`, zero `width`/`height` with `overflow:hidden`, a zero clip,
    /// or `width="0"` / `height="0"` attributes.
    ZeroSize,
    /// Positioned far off screen (`left:-9999px`, `text-indent:-9999px`, …).
    Offscreen,
    /// The `hidden` attribute.
    HiddenAttribute,
    /// `aria-hidden="true"`.
    AriaHidden,
    /// A closed `<dialog>`.
    Dialog,
    /// An HTML comment.
    Comment,
    /// A `<script>` body.
    Script,
    /// A `<style>` body.
    Style,
    /// `<noscript>` content.
    Noscript,
    /// `<template>` content.
    Template,
    /// `<iframe>`, `<object>`, `<noframes>`, `<noembed>`, `<frameset>` content.
    Frame,
    /// `<svg>`, `<math>`, `<canvas>` content.
    Embedded,
    /// The `<title>` element, and the normalized title.
    Title,
    /// `<meta>` attribute values (`content`, `name`, `property`, …).
    Meta,
    /// Other attribute values (`alt`, `title`, `aria-*`, `data-*`, `href`, `src`, …).
    Attribute,
    /// The doctype name and identifiers.
    Doctype,
    /// Markup a browser drops: attributes on end tags, a tag cut off by the end of the input.
    Unparsed,
}

impl HiddenKind {
    /// The marker kind, e.g. `css`.
    pub fn as_str(self) -> &'static str {
        match self {
            HiddenKind::Css => "css",
            HiddenKind::ZeroSize => "zero-size",
            HiddenKind::Offscreen => "offscreen",
            HiddenKind::HiddenAttribute => "hidden-attribute",
            HiddenKind::AriaHidden => "aria-hidden",
            HiddenKind::Dialog => "dialog",
            HiddenKind::Comment => "comment",
            HiddenKind::Script => "script",
            HiddenKind::Style => "style",
            HiddenKind::Noscript => "noscript",
            HiddenKind::Template => "template",
            HiddenKind::Frame => "frame",
            HiddenKind::Embedded => "embedded",
            HiddenKind::Title => "title",
            HiddenKind::Meta => "meta",
            HiddenKind::Attribute => "attr",
            HiddenKind::Doctype => "doctype",
            HiddenKind::Unparsed => "unparsed",
        }
    }

    /// The marker line text, e.g. `[hidden:css]`.
    pub fn marker(self) -> String {
        format!("[hidden:{}]", self.as_str())
    }
}

/// Why an element hides its subtree, if it does.
fn hidden_kind(element: &Element) -> Option<HiddenKind> {
    let by_name = match &*element.name {
        "script" => Some(HiddenKind::Script),
        "style" => Some(HiddenKind::Style),
        "noscript" => Some(HiddenKind::Noscript),
        "template" => Some(HiddenKind::Template),
        "iframe" | "object" | "noframes" | "noembed" | "frameset" => Some(HiddenKind::Frame),
        "svg" | "math" | "canvas" => Some(HiddenKind::Embedded),
        "title" => Some(HiddenKind::Title),
        "dialog" if !element.has_attr("open") => Some(HiddenKind::Dialog),
        _ => None,
    };
    if by_name.is_some() {
        return by_name;
    }
    if element.has_attr("hidden") {
        return Some(HiddenKind::HiddenAttribute);
    }
    if element
        .attr("aria-hidden")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"))
    {
        return Some(HiddenKind::AriaHidden);
    }
    if let Some(style) = element.attr("style").and_then(hidden_by_style) {
        return Some(match style {
            StyleHidden::Css => HiddenKind::Css,
            StyleHidden::ZeroSize => HiddenKind::ZeroSize,
            StyleHidden::Offscreen => HiddenKind::Offscreen,
        });
    }
    let zero = |name: &str| {
        element.attr(name).is_some_and(|v| {
            let v = v.trim().trim_end_matches("px").trim();
            !v.is_empty() && v.bytes().all(|b| b == b'0')
        })
    };
    if zero("width") || zero("height") {
        return Some(HiddenKind::ZeroSize);
    }
    None
}

/// Elements that start a new line of text.
fn is_block(name: &str) -> bool {
    matches!(
        name,
        "address"
            | "article"
            | "aside"
            | "blockquote"
            | "body"
            | "br"
            | "caption"
            | "center"
            | "dd"
            | "details"
            | "dialog"
            | "dir"
            | "div"
            | "dl"
            | "dt"
            | "fieldset"
            | "figcaption"
            | "figure"
            | "footer"
            | "form"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "head"
            | "header"
            | "hgroup"
            | "hr"
            | "html"
            | "legend"
            | "li"
            | "main"
            | "menu"
            | "nav"
            | "ol"
            | "option"
            | "p"
            | "pre"
            | "section"
            | "summary"
            | "table"
            | "tbody"
            | "td"
            | "tfoot"
            | "th"
            | "thead"
            | "title"
            | "tr"
            | "ul"
    )
}

fn heading_level(name: &str) -> Option<u8> {
    match name {
        "h1" => Some(1),
        "h2" => Some(2),
        "h3" => Some(3),
        "h4" => Some(4),
        "h5" => Some(5),
        "h6" => Some(6),
        _ => None,
    }
}

/// Resolve an `href` for the link list and display: absolute, `http(s)`, no credentials, no
/// fragment. Fragment-only (`#x`), `mailto:`, `javascript:`, `data:` … are dropped.
pub(crate) fn resolve_link(base: &Url, href: &str) -> Option<Url> {
    #[cfg(test)]
    crate::work::href_resolved();
    let href = href.trim_matches(|c: char| c.is_ascii_whitespace() || c.is_control());
    if href.is_empty() || href.starts_with('#') || href.len() > MAX_HREF_BYTES {
        return None;
    }
    let mut url = base.join(href).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    url.set_fragment(None);
    Some(url)
}

/// [`resolve_link`] plus the text the URL guard validates ([`DiscoveredLink::as_written`]).
pub(crate) fn discover_link(base: &Url, href: &str) -> Option<DiscoveredLink> {
    let url = resolve_link(base, href)?;
    // The same cleaning `Url::parse` applies: trim C0 controls and spaces, drop tab/newline.
    let cleaned: String = href
        .trim_matches(|c: char| c <= '\u{20}')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let text = cleaned.split('#').next().unwrap_or_default();
    let mut chars = text.chars();
    let scheme_relative = matches!(
        (chars.next(), chars.next()),
        (Some('/' | '\\'), Some('/' | '\\'))
    );
    let as_written = if Url::parse(text).is_ok() {
        text.to_owned()
    } else if scheme_relative {
        format!("{}:{text}", base.scheme())
    } else {
        // Path-relative: the authority is the base's, validated when the base was fetched.
        url.as_str().to_owned()
    };
    Some(DiscoveredLink { url, as_written })
}

/// Search slack per candidate line beyond twice its length (escapes at most double a line;
/// the slack covers link syntax and block markers between lines).
const COVER_SLACK: usize = 256;

/// Largest extra window one [`VisibleCover::covers`] search may use.
const MAX_COVER_WINDOW: usize = 64 * 1024;

/// Finds in-place lines that already occur **verbatim** in the rendered Markdown (the
/// `[visible]` section), so the walk can leave them out instead of storing the same text twice.
///
/// Lines are looked up in document order from a cursor that only moves past a match, so the
/// cursor never overtakes text that is still to come. Cost is linear: each search may scan
/// twice the line plus a credit, and the credit (the rendered length up front, then
/// [`COVER_SLACK`] plus the line length per line) is spent by what a search scans beyond twice
/// the line. A miss only means the line is kept, so the heuristic can cost space, never scanning.
pub(crate) struct VisibleCover<'v> {
    visible: &'v str,
    cursor: usize,
    credit: usize,
}

impl<'v> VisibleCover<'v> {
    pub(crate) fn new(visible: &'v str) -> Self {
        Self {
            visible,
            cursor: 0,
            credit: visible.len(),
        }
    }

    /// Whether `needle` (non-empty) occurs in the rendered Markdown at or after the cursor.
    fn covers(&mut self, needle: &str) -> bool {
        self.credit = self
            .credit
            .saturating_add(COVER_SLACK)
            .saturating_add(needle.len());
        let base = needle.len().saturating_mul(2);
        let span = base.saturating_add(self.credit.min(MAX_COVER_WINDOW));
        let mut end = self.cursor.saturating_add(span).min(self.visible.len());
        while end > self.cursor && !self.visible.is_char_boundary(end) {
            end -= 1;
        }
        let window = self.visible.get(self.cursor..end).unwrap_or("");
        let (found, scanned) = match window.find(needle) {
            Some(at) => (true, at.saturating_add(needle.len())),
            None => (false, window.len()),
        };
        #[cfg(test)]
        crate::work::cover_bytes_scanned(scanned);
        self.credit = self.credit.saturating_sub(scanned.saturating_sub(base));
        if found {
            self.cursor = self.cursor.saturating_add(scanned);
        }
        found
    }
}

/// `security_text` under construction, capped.
///
/// Text is written line by line. A line made only of *candidate* text (visible text that
/// display renders) is dropped at its end when [`VisibleCover`] finds it verbatim in the
/// rendered Markdown, which `security_text` carries anyway; every other line is kept.
struct SecurityText<'v> {
    out: String,
    /// Bytes the kept lines may use (the model-facing sections that follow are reserved).
    budget: usize,
    /// `extract.maxSecurityTextBytes`, reported in errors.
    limit: usize,
    cover: VisibleCover<'v>,
    line_start: usize,
    /// Whether the current line holds only candidate text.
    line_candidate: bool,
}

impl<'v> SecurityText<'v> {
    fn new(visible: &'v str, budget: usize, limit: usize) -> Self {
        Self {
            out: String::new(),
            budget,
            limit,
            cover: VisibleCover::new(visible),
            line_start: 0,
            line_candidate: true,
        }
    }

    fn check(&self) -> Result<(), ExtractError> {
        let kept = if self.line_candidate {
            self.line_start
        } else {
            self.out.len()
        };
        if kept > self.budget || self.out.len() - self.line_start > self.limit {
            return Err(ExtractError::SecurityTextTooLarge { limit: self.limit });
        }
        Ok(())
    }

    /// Close the current line: drop it when it is candidate text found verbatim in the
    /// rendered Markdown, else keep it with its `\n`.
    fn end_line(&mut self) {
        let needle = self.out[self.line_start..].trim_matches(' ');
        if self.line_candidate && !needle.is_empty() && self.cover.covers(needle) {
            self.out.truncate(self.line_start);
        } else {
            self.out.push('\n');
        }
        self.line_start = self.out.len();
        self.line_candidate = true;
    }

    /// Append already-cleaned `piece`; `candidate` marks it as rendered visible text.
    fn push(&mut self, piece: &str, candidate: bool) -> Result<(), ExtractError> {
        for part in piece.split_inclusive('\n') {
            let (content, ends_line) = match part.strip_suffix('\n') {
                Some(content) => (content, true),
                None => (part, false),
            };
            if !content.is_empty() {
                self.out.push_str(content);
                self.line_candidate &= candidate;
            }
            if ends_line {
                self.end_line();
            }
            self.check()?;
        }
        Ok(())
    }

    fn newline(&mut self) -> Result<(), ExtractError> {
        if self.out.len() > self.line_start {
            self.push("\n", true)?;
        }
        Ok(())
    }

    fn text(&mut self, text: &str, candidate: bool) -> Result<(), ExtractError> {
        let mut cleaned = String::new();
        collapse_for_scan(&mut cleaned, text);
        self.push(&cleaned, candidate)
    }

    fn marker(&mut self, kind: HiddenKind) -> Result<(), ExtractError> {
        self.push(&format!("\n{}\n", kind.marker()), false)
    }

    /// `\n[hidden:<kind>]\n<text>\n`; nothing when `text` has no visible characters.
    fn segment<'a>(
        &mut self,
        kind: HiddenKind,
        texts: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), ExtractError> {
        let mut body = String::new();
        for text in texts {
            let before = body.len();
            collapse_for_scan(&mut body, text.trim());
            if body.len() > before {
                body.push('\n');
            }
            if body.len() > self.limit {
                return Err(ExtractError::SecurityTextTooLarge { limit: self.limit });
            }
        }
        if body.trim().is_empty() {
            return Ok(());
        }
        self.marker(kind)?;
        self.push(&body, false)
    }

    /// Close the last line and return the text.
    fn finish(mut self) -> Result<String, ExtractError> {
        self.newline()?;
        Ok(self.out)
    }
}

/// `security_text` for a text body (plain text, JSON) whose every line is rendered: `source`
/// line by line, minus lines found verbatim in `rendered`, then the model-facing sections.
pub(crate) fn text_security_text(
    source: &str,
    rendered: &str,
    page_url: &Url,
    limit: usize,
) -> Result<String, ExtractError> {
    let tail = model_facing_tail(rendered, &[], page_url, None, limit)?;
    let mut security = SecurityText::new(rendered, limit.saturating_sub(tail.len()), limit);
    security.text(source, true)?;
    let mut out = security.finish()?;
    out.push_str(&tail);
    Ok(out)
}

/// Marker line that introduces the rendered display Markdown in `security_text`.
pub const VISIBLE_MARKER: &str = "[visible]";

/// Marker line that introduces the exposed link URLs in `security_text`, one per line.
pub const LINKS_MARKER: &str = "[links]";

/// Marker line that introduces the page URL (the base every relative link resolves against).
pub const URL_MARKER: &str = "[url]";

/// Append `\n<marker>\n<body>` to `out` **verbatim** (no cleaning or collapsing). Nothing for
/// an empty body.
fn push_section(out: &mut String, marker: &str, body: &str) {
    if body.is_empty() {
        return;
    }
    out.push('\n');
    out.push_str(marker);
    out.push('\n');
    out.push_str(body);
    if !body.ends_with('\n') {
        out.push('\n');
    }
}

/// The model-facing sections that end `security_text`, each string byte for byte as the model
/// gets it (invariant 8, ADR-013 rule 3):
///
/// - `[visible]` + the rendered display Markdown (`markdown::render`), so every phrase the
///   model reads is contiguous even where display joins text the walk keeps apart;
/// - `[links]` + every exposed link URL as exposed (resolution rewrites hosts and paths, and
///   `nav`/`aside`/image-only links are exposed without being rendered);
/// - `[url]` + the page URL relative links resolve against;
/// - `[hidden:title]` + the normalized title, always last.
///
/// Fails when the sections alone exceed `limit`.
pub(crate) fn model_facing_tail(
    rendered: &str,
    links: &[DiscoveredLink],
    page_url: &Url,
    title: Option<&str>,
    limit: usize,
) -> Result<String, ExtractError> {
    let too_large = ExtractError::SecurityTextTooLarge { limit };
    let links_bytes = links
        .iter()
        .try_fold(0usize, |sum, link| {
            sum.checked_add(link.url.as_str().len() + 1)
        })
        .ok_or(too_large.clone())?;
    let bound = rendered
        .len()
        .saturating_add(links_bytes)
        .saturating_add(page_url.as_str().len())
        .saturating_add(title.map_or(0, str::len))
        .saturating_add(64);
    if bound.saturating_sub(64) > limit {
        return Err(too_large);
    }
    let mut tail = String::with_capacity(bound);
    push_section(&mut tail, VISIBLE_MARKER, rendered);
    let mut list = String::with_capacity(links_bytes);
    for link in links {
        list.push_str(link.url.as_str());
        list.push('\n');
    }
    push_section(&mut tail, LINKS_MARKER, &list);
    push_section(&mut tail, URL_MARKER, page_url.as_str());
    push_section(&mut tail, &HiddenKind::Title.marker(), title.unwrap_or(""));
    if tail.len() > limit {
        return Err(too_large);
    }
    Ok(tail)
}

/// After a marked segment inside a hidden subtree, re-announce the subtree's kind so the text
/// that follows is not read as part of the segment.
fn resume_hidden(
    security: &mut SecurityText,
    hidden_owner: Option<(NodeId, HiddenKind)>,
) -> Result<(), ExtractError> {
    match hidden_owner {
        Some((_, kind)) => security.marker(kind),
        None => Ok(()),
    }
}

/// What the first walk learns about the document: links, title sources and the display root.
struct Survey {
    links: Vec<DiscoveredLink>,
    links_truncated: bool,
    title_element: Option<NodeId>,
    og_title: Option<String>,
    first_main: Option<NodeId>,
    first_body: Option<NodeId>,
}

/// Walk the whole document for links (outside hidden subtrees), the title sources and the
/// display root. No text is written.
fn survey(dom: &Dom, base: &Url, limits: &ExtractLimits) -> Survey {
    let mut links = Vec::new();
    let mut seen_links: HashSet<String> = HashSet::new();
    let mut links_truncated = false;
    let mut hidden_owner: Option<NodeId> = None;
    let mut title_element = None;
    let mut og_title = None;
    let mut first_main = None;
    let mut first_body = None;
    let _ = dom.walk::<()>(ROOT, |event| {
        match event {
            Event::Enter(id) => {
                let Some(element) = dom.element(id) else {
                    return Ok(Walk::Continue);
                };
                if element.is("meta") && og_title.is_none() {
                    let is_og_title = ["property", "name"].iter().any(|key| {
                        element
                            .attr(key)
                            .is_some_and(|v| v.trim().eq_ignore_ascii_case("og:title"))
                    });
                    if is_og_title {
                        og_title = element.attr("content").map(str::to_owned);
                    }
                }
                if element.is("title") && title_element.is_none() {
                    title_element = Some(id);
                }
                let hidden = hidden_kind(element).is_some();
                if hidden_owner.is_none() && !hidden {
                    if element.is("main") && first_main.is_none() {
                        first_main = Some(id);
                    }
                    if element.is("body") && first_body.is_none() {
                        first_body = Some(id);
                    }
                    if element.is("a") || element.is("area") {
                        let link = element.attr("href").and_then(|h| discover_link(base, h));
                        // Once truncated, no further link is looked up or kept.
                        if let (Some(link), false) = (link, links_truncated) {
                            #[cfg(test)]
                            crate::work::link_dedupe_lookup();
                            if !seen_links.contains(link.url.as_str()) {
                                if links.len() < limits.max_links_per_page {
                                    seen_links.insert(link.url.as_str().to_owned());
                                    links.push(link);
                                } else {
                                    links_truncated = true;
                                }
                            }
                        }
                    }
                }
                if hidden_owner.is_none() && hidden {
                    hidden_owner = Some(id);
                }
            }
            Event::Exit(id) => {
                if hidden_owner == Some(id) {
                    hidden_owner = None;
                }
            }
        }
        Ok(Walk::Continue)
    });
    Survey {
        links,
        links_truncated,
        title_element,
        og_title,
        first_main,
        first_body,
    }
}

/// The security walk: every node of the document in document order. Visible text in place
/// (a line that display renders and that occurs verbatim in `rendered` is left to the
/// `[visible]` section), each hidden subtree behind a marker line, comments, doctype, `<meta>`
/// values and unparsed markup as marked segments, then every other attribute value in one
/// `[hidden:attr]` segment. `displayed[id]` says whether display rendered text node `id`.
fn scan(
    dom: &Dom,
    displayed: &[bool],
    rendered: &str,
    budget: usize,
    limit: usize,
) -> Result<String, ExtractError> {
    let mut security = SecurityText::new(rendered, budget, limit);
    let mut attributes: Vec<&str> = Vec::new();
    let mut seen_attributes: HashSet<&str> = HashSet::new();
    let mut hidden_owner: Option<(NodeId, HiddenKind)> = None;

    dom.walk(ROOT, |event| {
        match event {
            Event::Enter(id) => match &dom.node(id).data {
                NodeData::Document => {}
                NodeData::Doctype(text) => {
                    security.segment(HiddenKind::Doctype, [text.as_str()])?;
                    resume_hidden(&mut security, hidden_owner)?;
                }
                NodeData::Comment(text) => {
                    security.segment(HiddenKind::Comment, [text.as_str()])?;
                    resume_hidden(&mut security, hidden_owner)?;
                }
                NodeData::Unparsed(text) => {
                    security.segment(HiddenKind::Unparsed, [text.as_str()])?;
                    resume_hidden(&mut security, hidden_owner)?;
                }
                NodeData::Text(text) => {
                    let candidate = hidden_owner.is_none()
                        && displayed.get(id as usize).copied().unwrap_or(false);
                    security.text(text, candidate)?;
                }
                NodeData::Element(element) => {
                    if is_block(&element.name) {
                        security.newline()?;
                    }
                    if element.is("meta") {
                        security.segment(
                            HiddenKind::Meta,
                            element.attrs.iter().map(|(_, value)| &**value),
                        )?;
                        resume_hidden(&mut security, hidden_owner)?;
                    } else {
                        for (_, value) in &element.attrs {
                            if seen_attributes.insert(&**value) {
                                attributes.push(&**value);
                            }
                        }
                    }
                    if let (None, Some(kind)) = (hidden_owner, hidden_kind(element)) {
                        security.marker(kind)?;
                        hidden_owner = Some((id, kind));
                    }
                }
            },
            Event::Exit(id) => {
                if hidden_owner.is_some_and(|(owner, _)| owner == id) {
                    hidden_owner = None;
                    security.newline()?;
                }
                if dom.element(id).is_some_and(|e| is_block(&e.name)) {
                    security.newline()?;
                }
            }
        }
        Ok::<_, ExtractError>(Walk::Continue)
    })?;
    security.segment(HiddenKind::Attribute, attributes)?;
    security.finish()
}

/// Collects inline content (text, links, inline code) for a paragraph or table cell.
struct InlineCollector<'a> {
    base: &'a Url,
    accepted_links: &'a HashSet<&'a str>,
    raw: Vec<Inline>,
    link: Option<(NodeId, Url, String)>,
    code: Option<(NodeId, String)>,
}

impl<'a> InlineCollector<'a> {
    fn new(base: &'a Url, accepted_links: &'a HashSet<&'a str>) -> Self {
        Self {
            base,
            accepted_links,
            raw: Vec::new(),
            link: None,
            code: None,
        }
    }

    fn text(&mut self, text: &str) {
        if let Some((_, _, link_text)) = &mut self.link {
            link_text.push_str(text);
        } else if let Some((_, code)) = &mut self.code {
            code.push_str(text);
        } else if let Some(Inline::Text(last)) = self.raw.last_mut() {
            last.push_str(text);
        } else {
            self.raw.push(Inline::Text(text.to_owned()));
        }
    }

    fn enter(&mut self, id: NodeId, element: &Element) {
        if self.link.is_some() || self.code.is_some() {
            // A block boundary inside a link separates words, as it does in security_text.
            if is_block(&element.name) {
                self.text(" ");
            }
            return;
        }
        match &*element.name {
            "a" => {
                let url = element
                    .attr("href")
                    .and_then(|h| resolve_link(self.base, h))
                    .filter(|url| self.accepted_links.contains(url.as_str()));
                if let Some(url) = url {
                    self.link = Some((id, url, String::new()));
                }
            }
            "code" | "kbd" | "samp" | "tt" => self.code = Some((id, String::new())),
            "br" => self.text(" "),
            _ => {}
        }
    }

    fn exit(&mut self, id: NodeId) {
        if self.link.as_ref().is_some_and(|(owner, _, _)| *owner == id) {
            if let Some((_, href, text)) = self.link.take() {
                self.raw.push(Inline::Link { href, text });
            }
        } else if self.code.as_ref().is_some_and(|(owner, _)| *owner == id) {
            if let Some((_, text)) = self.code.take() {
                self.raw.push(Inline::Code(text));
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.raw.is_empty() && self.link.is_none() && self.code.is_none()
    }

    /// Normalized inlines: whitespace collapsed across inline boundaries, trimmed, empty
    /// links/code dropped (their text kept as spacing).
    fn finish(&mut self) -> Vec<Inline> {
        if let Some((_, href, text)) = self.link.take() {
            self.raw.push(Inline::Link { href, text });
        }
        if let Some((_, text)) = self.code.take() {
            self.raw.push(Inline::Code(text));
        }
        normalize_inlines(std::mem::take(&mut self.raw))
    }
}

fn push_char(out: &mut Vec<Inline>, c: char) {
    if let Some(Inline::Text(last)) = out.last_mut() {
        last.push(c);
    } else {
        out.push(Inline::Text(c.to_string()));
    }
}

fn normalize_inlines(raw: Vec<Inline>) -> Vec<Inline> {
    let mut out: Vec<Inline> = Vec::new();
    let mut space = false;
    for item in raw {
        let (starts_ws, ends_ws, collapsed) = match &item {
            Inline::Text(text) => {
                for c in text.chars() {
                    if c.is_whitespace() {
                        space = true;
                    } else if !textclean::is_stripped(c) {
                        if space && !out.is_empty() {
                            push_char(&mut out, ' ');
                        }
                        space = false;
                        push_char(&mut out, c);
                    }
                }
                continue;
            }
            Inline::Code(text) | Inline::Link { text, .. } => (
                text.starts_with(char::is_whitespace),
                text.ends_with(char::is_whitespace),
                collapse(text),
            ),
        };
        if starts_ws {
            space = true;
        }
        if collapsed.is_empty() {
            space = space || ends_ws;
            continue;
        }
        if space && !out.is_empty() {
            push_char(&mut out, ' ');
        }
        out.push(match item {
            Inline::Link { href, .. } => Inline::Link {
                href,
                text: collapsed,
            },
            _ => Inline::Code(collapsed),
        });
        space = ends_ws;
    }
    out
}

/// A container being filled by the display walk.
enum Frame {
    Root(Vec<Block>),
    List {
        owner: NodeId,
        ordered: bool,
        items: Vec<Vec<Block>>,
    },
    Item {
        owner: NodeId,
        blocks: Vec<Block>,
    },
    Quote {
        owner: NodeId,
        blocks: Vec<Block>,
    },
}

impl Frame {
    fn owner(&self) -> Option<NodeId> {
        match self {
            Frame::Root(_) => None,
            Frame::List { owner, .. } | Frame::Item { owner, .. } | Frame::Quote { owner, .. } => {
                Some(*owner)
            }
        }
    }
}

/// Whether an element (and its subtree) is left out of `display`. `in_article` is the number
/// of open `<article>`/`<main>` ancestors: a `<header>`/`<footer>` inside one is content.
fn excluded_from_display(element: &Element, in_article: usize) -> bool {
    let chrome = match &*element.name {
        "nav" | "aside" | "head" | "meta" | "link" | "base" | "img" | "picture" | "video"
        | "audio" | "map" | "area" | "input" | "select" | "button" | "textarea" | "frame" => true,
        "header" | "footer" => in_article == 0,
        _ => false,
    };
    let role = element.attr("role").is_some_and(|role| {
        role.split_ascii_whitespace().any(|r| {
            matches!(
                r.to_ascii_lowercase().as_str(),
                "navigation" | "banner" | "contentinfo" | "complementary" | "search"
            )
        })
    });
    chrome || role || hidden_kind(element).is_some()
}

struct DisplayBuilder<'a> {
    dom: &'a Dom,
    base: &'a Url,
    accepted_links: &'a HashSet<&'a str>,
    frames: Vec<Frame>,
    inline: InlineCollector<'a>,
    heading: Option<(NodeId, u8, String)>,
    in_article: usize,
    nesting: usize,
}

impl<'a> DisplayBuilder<'a> {
    fn push_block(&mut self, block: Block) {
        match self.frames.last_mut() {
            Some(Frame::Root(blocks))
            | Some(Frame::Item { blocks, .. })
            | Some(Frame::Quote { blocks, .. }) => blocks.push(block),
            Some(Frame::List { items, .. }) => items.push(vec![block]),
            None => self.frames.push(Frame::Root(vec![block])),
        }
    }

    fn flush(&mut self) {
        if self.inline.is_empty() {
            return;
        }
        let inlines = self.inline.finish();
        if !inlines.is_empty() {
            self.push_block(Block::Paragraph(inlines));
        }
    }

    fn close_frame(&mut self, id: NodeId) {
        if self.frames.last().and_then(Frame::owner) != Some(id) {
            return;
        }
        self.flush();
        let Some(frame) = self.frames.pop() else {
            return;
        };
        match frame {
            Frame::Root(_) => {}
            Frame::List { ordered, items, .. } => {
                self.nesting = self.nesting.saturating_sub(1);
                if !items.is_empty() {
                    self.push_block(Block::List { ordered, items });
                }
            }
            Frame::Item { blocks, .. } => {
                if !blocks.is_empty() {
                    if let Some(Frame::List { items, .. }) = self.frames.last_mut() {
                        items.push(blocks);
                    }
                }
            }
            Frame::Quote { blocks, .. } => {
                self.nesting = self.nesting.saturating_sub(1);
                if !blocks.is_empty() {
                    self.push_block(Block::Quote(blocks));
                }
            }
        }
    }

    fn enter_element(&mut self, id: NodeId, element: &Element, displayed: &mut [bool]) -> Walk {
        if excluded_from_display(element, self.in_article) {
            self.separator();
            return Walk::Skip;
        }
        let name = &*element.name;
        if name == "article" || name == "main" {
            self.in_article += 1;
        }
        if let Some((_, _, text)) = &mut self.heading {
            if is_block(name) {
                text.push(' ');
            }
            return Walk::Continue;
        }
        if self.inline.link.is_some() {
            // Everything inside a link is link text, block elements included.
            self.inline.enter(id, element);
            return Walk::Continue;
        }
        match name {
            "pre" => {
                self.flush();
                if let Some(code) = self.code_block(id, element, displayed) {
                    self.push_block(code);
                }
                return Walk::Skip;
            }
            "table" => {
                self.flush();
                let (caption, table) = self.table(id, displayed);
                if !caption.is_empty() {
                    self.push_block(Block::Paragraph(caption));
                }
                if let Some(table) = table {
                    self.push_block(table);
                }
                return Walk::Skip;
            }
            _ => {}
        }
        if let Some(level) = heading_level(name) {
            self.flush();
            self.heading = Some((id, level, String::new()));
            return Walk::Continue;
        }
        match name {
            "ul" | "ol" | "menu" | "dir" if self.nesting < MAX_BLOCK_NESTING => {
                self.flush();
                self.nesting += 1;
                self.frames.push(Frame::List {
                    owner: id,
                    ordered: name == "ol",
                    items: Vec::new(),
                });
            }
            "li" if matches!(self.frames.last(), Some(Frame::List { .. })) => {
                self.flush();
                self.frames.push(Frame::Item {
                    owner: id,
                    blocks: Vec::new(),
                });
            }
            "blockquote" if self.nesting < MAX_BLOCK_NESTING => {
                self.flush();
                self.nesting += 1;
                self.frames.push(Frame::Quote {
                    owner: id,
                    blocks: Vec::new(),
                });
            }
            _ if is_block(name) && name != "br" => self.flush(),
            _ => self.inline.enter(id, element),
        }
        Walk::Continue
    }

    fn exit_element(&mut self, id: NodeId, element: &Element) {
        if excluded_from_display(element, self.in_article) {
            // Skipped on entry; the walk still reports its exit.
            return;
        }
        let name = &*element.name;
        if name == "article" || name == "main" {
            self.in_article = self.in_article.saturating_sub(1);
        }
        if self
            .heading
            .as_ref()
            .is_some_and(|(owner, _, _)| *owner == id)
        {
            if let Some((_, level, text)) = self.heading.take() {
                let text = collapse(&text);
                if !text.is_empty() {
                    self.push_block(Block::Heading { level, text });
                }
            }
            return;
        }
        if let Some((_, _, text)) = &mut self.heading {
            if is_block(name) {
                text.push(' ');
            }
            return;
        }
        if self.inline.link.is_some() {
            if is_block(name) {
                self.inline.text(" ");
            }
            self.inline.exit(id);
            return;
        }
        self.inline.exit(id);
        if self.frames.last().and_then(Frame::owner) == Some(id) {
            self.close_frame(id);
        } else if is_block(name) && name != "br" {
            self.flush();
        }
    }

    fn text(&mut self, text: &str) {
        if let Some((_, _, heading)) = &mut self.heading {
            heading.push_str(text);
        } else {
            self.inline.text(text);
        }
    }

    /// A node left out of display (hidden element, comment, chrome, image …) separates words:
    /// `ig<span hidden>x</span>nore` must not show the model `ignore` when `security_text`
    /// has `ig` and `nore` on either side of a hidden segment.
    fn separator(&mut self) {
        self.text(" ");
    }

    /// `<pre>`: verbatim text of the visible subtree, with a language hint from a
    /// `language-*` / `lang-*` class on the `<pre>` or a `<code>` inside it.
    fn code_block(&self, id: NodeId, pre: &Element, displayed: &mut [bool]) -> Option<Block> {
        let mut text = String::new();
        let mut lang = code_lang(pre);
        // Skipped nodes separate words (see `separator`).
        let separate = |text: &mut String| {
            if !text.is_empty() && !text.ends_with(char::is_whitespace) {
                text.push(' ');
            }
        };
        // Block boundaries (and <br>) inside <pre> are line breaks, as in security_text.
        let line_break = |text: &mut String| {
            if !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
        };
        let _ = self.dom.walk::<()>(id, |event| {
            match event {
                Event::Enter(child) => match &self.dom.node(child).data {
                    NodeData::Text(t) => {
                        text.push_str(&textclean::clean(t));
                        mark(displayed, child);
                    }
                    NodeData::Comment(_) | NodeData::Doctype(_) | NodeData::Unparsed(_) => {
                        separate(&mut text);
                    }
                    NodeData::Element(e) if child != id => {
                        if excluded_from_display(e, 1) {
                            separate(&mut text);
                            return Ok(Walk::Skip);
                        }
                        if e.is("br") {
                            text.push('\n');
                        } else if is_block(&e.name) {
                            line_break(&mut text);
                        }
                        if lang.is_none() && e.is("code") {
                            lang = code_lang(e);
                        }
                    }
                    _ => {}
                },
                Event::Exit(child) if child != id => {
                    let block = self
                        .dom
                        .element(child)
                        .is_some_and(|e| is_block(&e.name) && !e.is("br"));
                    if block {
                        line_break(&mut text);
                    }
                }
                Event::Exit(_) => {}
            }
            Ok(Walk::Continue)
        });
        let text = text.strip_prefix('\n').unwrap_or(&text);
        let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
        let code = lines.join("\n");
        let code = code.trim_end_matches('\n').trim_start_matches('\n');
        if code.trim().is_empty() {
            return None;
        }
        Some(Block::Code {
            lang,
            text: code.to_owned(),
        })
    }

    /// `<table>`: rows of cells (nested tables are flattened into their cell), plus the
    /// `<caption>` as inline content.
    fn table(&self, id: NodeId, displayed: &mut [bool]) -> (Vec<Inline>, Option<Block>) {
        let mut rows: Vec<Vec<Vec<Inline>>> = Vec::new();
        let mut row: Option<Vec<Vec<Inline>>> = None;
        let mut cell: Option<InlineCollector<'a>> = None;
        let mut caption = InlineCollector::new(self.base, self.accepted_links);
        let mut in_caption: Option<NodeId> = None;
        let mut nested = 0usize;
        let finish_cell = |row: &mut Option<Vec<Vec<Inline>>>,
                           cell: &mut Option<InlineCollector>| {
            if let Some(mut collector) = cell.take() {
                if let Some(row) = row.as_mut() {
                    if row.len() < MAX_TABLE_COLUMNS {
                        row.push(collector.finish());
                    }
                }
            }
        };
        let _ = self.dom.walk::<()>(id, |event| {
            match event {
                Event::Enter(child) => match &self.dom.node(child).data {
                    NodeData::Text(t) => {
                        if in_caption.is_some() {
                            caption.text(t);
                            mark(displayed, child);
                        } else if let Some(collector) = cell.as_mut() {
                            collector.text(t);
                            mark(displayed, child);
                        }
                    }
                    NodeData::Comment(_) | NodeData::Doctype(_) | NodeData::Unparsed(_) => {
                        if in_caption.is_some() {
                            caption.text(" ");
                        } else if let Some(collector) = cell.as_mut() {
                            collector.text(" ");
                        }
                    }
                    NodeData::Element(e) if child != id => {
                        if excluded_from_display(e, 1) {
                            if in_caption.is_some() {
                                caption.text(" ");
                            } else if let Some(collector) = cell.as_mut() {
                                collector.text(" ");
                            }
                            return Ok(Walk::Skip);
                        }
                        let name = &*e.name;
                        if name == "table" {
                            nested += 1;
                        } else if nested == 0 && name == "tr" {
                            finish_cell(&mut row, &mut cell);
                            if let Some(done) = row.take() {
                                rows.push(done);
                            }
                            row = Some(Vec::new());
                            return Ok(Walk::Continue);
                        } else if nested == 0 && (name == "td" || name == "th") {
                            finish_cell(&mut row, &mut cell);
                            if row.is_none() {
                                row = Some(Vec::new());
                            }
                            cell = Some(InlineCollector::new(self.base, self.accepted_links));
                            return Ok(Walk::Continue);
                        } else if nested == 0 && name == "caption" && in_caption.is_none() {
                            in_caption = Some(child);
                            return Ok(Walk::Continue);
                        }
                        let target = if in_caption.is_some() {
                            Some(&mut caption)
                        } else {
                            cell.as_mut()
                        };
                        if let Some(collector) = target {
                            if is_block(name) {
                                collector.text(" ");
                            }
                            collector.enter(child, e);
                        }
                    }
                    _ => {}
                },
                Event::Exit(child) => {
                    let skipped = self
                        .dom
                        .element(child)
                        .is_some_and(|e| excluded_from_display(e, 1));
                    if child == id || skipped {
                        return Ok(Walk::Continue);
                    }
                    if in_caption == Some(child) {
                        in_caption = None;
                    } else {
                        let target = if in_caption.is_some() {
                            Some(&mut caption)
                        } else {
                            cell.as_mut()
                        };
                        if let Some(collector) = target {
                            collector.exit(child);
                            if self.dom.element(child).is_some_and(|e| is_block(&e.name)) {
                                collector.text(" ");
                            }
                        }
                    }
                    if self.dom.element(child).is_some_and(|e| e.is("table")) {
                        nested = nested.saturating_sub(1);
                    }
                }
            }
            Ok(Walk::Continue)
        });
        finish_cell(&mut row, &mut cell);
        if let Some(done) = row.take() {
            rows.push(done);
        }
        rows.retain(|r| r.iter().any(|c| !c.is_empty()));
        let table = (!rows.is_empty()).then_some(Block::Table { rows });
        (caption.finish(), table)
    }
}

fn code_lang(element: &Element) -> Option<String> {
    let class = element.attr("class")?;
    class.split_ascii_whitespace().find_map(|token| {
        let lang = token
            .strip_prefix("language-")
            .or_else(|| token.strip_prefix("lang-"))?
            .to_ascii_lowercase();
        let valid = !lang.is_empty()
            && lang.len() <= 32
            && lang
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+#._-".contains(&b));
        valid.then_some(lang)
    })
}

/// The display blocks, and for every node whether display rendered its text (`displayed`).
fn build_display(
    dom: &Dom,
    root: NodeId,
    base: &Url,
    accepted_links: &HashSet<&str>,
) -> (Vec<Block>, Vec<bool>) {
    let mut displayed = vec![false; dom.nodes.len()];
    let mut builder = DisplayBuilder {
        dom,
        base,
        accepted_links,
        frames: vec![Frame::Root(Vec::new())],
        inline: InlineCollector::new(base, accepted_links),
        heading: None,
        in_article: 0,
        nesting: 0,
    };
    let _ = dom.walk::<()>(root, |event| {
        let walk = match event {
            Event::Enter(id) => match &dom.node(id).data {
                NodeData::Text(text) => {
                    builder.text(text);
                    mark(&mut displayed, id);
                    Walk::Continue
                }
                NodeData::Element(element) => builder.enter_element(id, element, &mut displayed),
                NodeData::Doctype(_) | NodeData::Comment(_) | NodeData::Unparsed(_) => {
                    builder.separator();
                    Walk::Continue
                }
                NodeData::Document => Walk::Continue,
            },
            Event::Exit(id) => {
                if let Some(element) = dom.element(id) {
                    builder.exit_element(id, element);
                }
                Walk::Continue
            }
        };
        Ok(walk)
    });
    builder.flush();
    while builder.frames.len() > 1 {
        match builder.frames.last().and_then(Frame::owner) {
            Some(owner) => builder.close_frame(owner),
            None => break,
        }
    }
    let blocks = match builder.frames.pop() {
        Some(Frame::Root(blocks)) => blocks,
        _ => Vec::new(),
    };
    (blocks, displayed)
}

/// Record that display consumed text node `id`.
fn mark(displayed: &mut [bool], id: NodeId) {
    if let Some(flag) = displayed.get_mut(id as usize) {
        *flag = true;
    }
}

/// Text content of an element's subtree (for `<title>`).
fn text_content(dom: &Dom, id: NodeId) -> String {
    let mut text = String::new();
    let _ = dom.walk::<()>(id, |event| {
        if let Event::Enter(child) = event {
            if let NodeData::Text(t) = &dom.node(child).data {
                text.push_str(t);
            }
        }
        Ok(Walk::Continue)
    });
    text
}

/// Everything [`extract_html`] produces, before the size checks on display.
pub(crate) struct HtmlParts {
    pub(crate) security_text: String,
    pub(crate) blocks: Vec<Block>,
    pub(crate) links: Vec<DiscoveredLink>,
    pub(crate) links_truncated: bool,
    pub(crate) title: Option<String>,
}

pub(crate) fn extract_parts(
    source: &str,
    base: &Url,
    limits: &ExtractLimits,
) -> Result<HtmlParts, ExtractError> {
    let dom = dom::parse(source).map_err(|_| ExtractError::TooManyNodes {
        limit: dom::MAX_NODES,
    })?;
    let Survey {
        links,
        links_truncated,
        title_element,
        og_title,
        first_main,
        first_body,
    } = survey(&dom, base, limits);
    let accepted: HashSet<&str> = links.iter().map(|link| link.url.as_str()).collect();
    let root = first_main.or(first_body).unwrap_or(ROOT);
    let (blocks, displayed) = build_display(&dom, root, base, &accepted);
    let rendered = markdown::render_body(&blocks);
    let first_h1 = blocks.iter().find_map(|block| match block {
        Block::Heading { level: 1, text } => Some(text.clone()),
        _ => None,
    });
    let title = title_element
        .map(|id| text_content(&dom, id))
        .and_then(|t| normalize_title(&t))
        .or_else(|| og_title.and_then(|t| normalize_title(&t)))
        .or_else(|| first_h1.and_then(|t| normalize_title(&t)));
    let limit = limits.max_security_text_bytes;
    let tail = model_facing_tail(&rendered, &links, base, title.as_deref(), limit)?;
    let mut security_text = scan(
        &dom,
        &displayed,
        &rendered,
        limit.saturating_sub(tail.len()),
        limit,
    )?;
    security_text.push_str(&tail);
    if security_text.len() > limit {
        return Err(ExtractError::SecurityTextTooLarge { limit });
    }
    Ok(HtmlParts {
        security_text,
        blocks,
        links,
        links_truncated,
        title,
    })
}

/// Check the rendered display against `max_display_bytes`.
pub(crate) fn check_display(
    display: &StructuredDocument,
    limits: &ExtractLimits,
) -> Result<(), ExtractError> {
    if markdown::render(display).len() > limits.max_display_bytes {
        return Err(ExtractError::DisplayTooLarge {
            limit: limits.max_display_bytes,
        });
    }
    Ok(())
}

pub(crate) fn extract_html(
    source: &str,
    base: &Url,
    limits: &ExtractLimits,
) -> Result<ExtractedDocument, ExtractError> {
    let parts = extract_parts(source, base, limits)?;
    let display = StructuredDocument {
        title: parts.title.clone(),
        blocks: parts.blocks,
    };
    check_display(&display, limits)?;
    Ok(ExtractedDocument {
        security_text: parts.security_text,
        display,
        links: parts.links,
        links_truncated: parts.links_truncated,
        title: parts.title,
    })
}

#[cfg(test)]
mod tests {
    //! Work bounds on hostile input. These count work ([`crate::work`]) instead of timing it, so
    //! machine load cannot change the result; the budget makes a superlinear regression panic
    //! as soon as it passes the linear bound instead of running for hours.

    use super::*;
    use crate::work::{measure, Work};
    use crate::{ContentExtractor, ExtractInput, Extractor, SourceKind};

    /// Total work allowed per source byte. Every walk sees a node twice (enter, exit), three
    /// walks see each node, and an element takes at least three source bytes, so linear
    /// extraction stays near one unit per byte (measured: 0.8–1.4 on the inputs below). A
    /// quadratic regression on these multi-megabyte inputs needs ~10^5 units per byte.
    const WORK_PER_BYTE: u64 = 4;

    /// Extract an HTML `body` served at `url`; panics as soon as the work passes the budget.
    fn extract_counted(
        body: &str,
        url: &str,
        limits: ExtractLimits,
    ) -> (Result<ExtractedDocument, ExtractError>, Work, u64) {
        let url = Url::parse(url).unwrap();
        let budget = WORK_PER_BYTE * u64::try_from(body.len()).unwrap();
        let (result, work) = measure(budget, || {
            ContentExtractor::new(limits).extract(&ExtractInput {
                final_url: &url,
                kind: SourceKind::Html,
                charset: Some("utf-8"),
                body: body.as_bytes(),
            })
        });
        (result, work, budget)
    }

    /// Moved from `tests/security/extract_bounds.rs`, where it asserted a wall-clock bound.
    #[test]
    fn deeply_nested_inline_and_table_elements_are_bounded() {
        let roomy = ExtractLimits {
            max_security_text_bytes: 16 * 1024 * 1024,
            max_links_per_page: 2000,
            max_display_bytes: 16 * 1024 * 1024,
        };
        // `hits_node_cap`: whether the input exceeds `MAX_NODES` (1,000,000). Asserting the exact
        // outcome means removing the node cap fails this test, not only the work budget.
        for (open, n, hits_node_cap) in [
            ("<span>", 700_000, false),
            ("<table><tr><td>", 300_000, false),
            ("<b><i>", 500_000, true),
        ] {
            let body = open.repeat(n) + "x";
            let (result, work, budget) = extract_counted(&body, "http://fixture.test/page", roomy);
            if hits_node_cap {
                assert!(
                    matches!(result, Err(ExtractError::TooManyNodes { .. })),
                    "{open}: {result:?}"
                );
            } else {
                assert!(result.is_ok(), "{open}: {result:?}");
            }
            assert!(work.total() <= budget, "{open}: {work:?}");
        }
    }

    /// The work half of `links_huge_is_capped` (`tests/extract/links.rs`), on the page the
    /// fixture serves at `/links/huge` (`tests/support/fixture_server.rs`).
    #[test]
    fn links_huge_is_capped_with_linear_work() {
        const HUGE_LINK_COUNT: usize = 50_000;
        let anchors: String = (0..HUGE_LINK_COUNT)
            .map(|i| format!("<a href=\"/clean/page-{i}\">link {i}</a>\n"))
            .collect();
        let body = format!(
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
             <title>Many links</title></head>\n<body>{anchors}</body></html>\n"
        );
        let limits = ExtractLimits::default();
        let cap = limits.max_links_per_page;
        assert!(HUGE_LINK_COUNT > cap);
        let (result, work, budget) =
            extract_counted(&body, "http://fixture.test/links/huge", limits);
        let doc = result.unwrap();
        assert_eq!(doc.links.len(), cap);
        assert!(doc.links_truncated);
        assert!(work.total() <= budget, "{work:?}");
        // Link bookkeeping stops at the cap: the kept links plus the one that truncates.
        let max_lookups = u64::try_from(cap + 1).unwrap();
        assert!(work.link_dedupe_lookups <= max_lookups, "{work:?}");
        // Each anchor's href is resolved once by the survey and once by display.
        let max_resolved = 2 * u64::try_from(HUGE_LINK_COUNT).unwrap();
        assert!(work.hrefs_resolved <= max_resolved, "{work:?}");
    }

    /// Every link on the huge page above is distinct, so it cannot show that dedupe works under
    /// load. Here each URL appears five times: the kept links must still be distinct and fill the
    /// cap, with dedupe lookups linear in the anchors seen before truncation.
    #[test]
    fn duplicate_heavy_links_stay_distinct_with_linear_work() {
        const DISTINCT: usize = 10_000;
        const REPEATS: usize = 5;
        let anchors: String = (0..DISTINCT)
            .flat_map(|i| std::iter::repeat(i).take(REPEATS))
            .map(|i| format!("<a href=\"/clean/page-{i}\">link {i}</a>\n"))
            .collect();
        let body = format!("<html><body>{anchors}</body></html>");
        let limits = ExtractLimits::default();
        let cap = limits.max_links_per_page;
        assert!(DISTINCT > cap);
        let (result, work, budget) =
            extract_counted(&body, "http://fixture.test/links/dupes", limits);
        let doc = result.unwrap();
        let distinct: std::collections::HashSet<&str> =
            doc.links.iter().map(|link| link.url.as_str()).collect();
        assert_eq!(doc.links.len(), cap);
        assert_eq!(distinct.len(), cap, "kept links must be distinct");
        assert!(doc.links_truncated);
        assert!(work.total() <= budget, "{work:?}");
        // Anchors seen before truncation: every repeat of the kept URLs, plus the one that truncates.
        let max_lookups = u64::try_from(REPEATS * cap + 1).unwrap();
        assert!(work.link_dedupe_lookups <= max_lookups, "{work:?}");
    }
}

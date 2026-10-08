//! Non-HTML extractors: plain text, Markdown, JSON (PR-04 brief, "Non-HTML").

use pulldown_cmark::{html::push_html, Options, Parser};
use secure_web_core::model::{Block, Inline, StructuredDocument};
use url::Url;

use crate::textclean::{self, collapse, collapse_for_scan};
use crate::{html, markdown};
use crate::{ExtractError, ExtractLimits, ExtractedDocument};

fn security_text(source: &str, limits: &ExtractLimits) -> Result<String, ExtractError> {
    let mut out = String::new();
    collapse_for_scan(&mut out, source);
    if out.len() > limits.max_security_text_bytes {
        return Err(ExtractError::SecurityTextTooLarge {
            limit: limits.max_security_text_bytes,
        });
    }
    Ok(out)
}

fn finish(
    security_text: String,
    blocks: Vec<Block>,
    links: Vec<secure_web_core::model::DiscoveredLink>,
    links_truncated: bool,
    title: Option<String>,
    limits: &ExtractLimits,
) -> Result<ExtractedDocument, ExtractError> {
    let display = StructuredDocument {
        title: title.clone(),
        blocks,
    };
    html::check_display(&display, limits)?;
    Ok(ExtractedDocument {
        security_text,
        display,
        links,
        links_truncated,
        title,
    })
}

/// `text/plain`: one paragraph per blank-line-separated chunk; `security_text` is the text.
pub(crate) fn extract_plain(
    source: &str,
    page_url: &Url,
    limits: &ExtractLimits,
) -> Result<ExtractedDocument, ExtractError> {
    let cleaned = textclean::clean(source);
    let mut blocks = Vec::new();
    let mut paragraph = String::new();
    for line in cleaned.split('\n') {
        if line.trim().is_empty() {
            push_paragraph(&mut blocks, &mut paragraph);
        } else {
            paragraph.push_str(line);
            paragraph.push('\n');
        }
    }
    push_paragraph(&mut blocks, &mut paragraph);
    let security_text = html::text_security_text(
        source,
        &markdown::render_body(&blocks),
        page_url,
        limits.max_security_text_bytes,
    )?;
    finish(security_text, blocks, Vec::new(), false, None, limits)
}

fn push_paragraph(blocks: &mut Vec<Block>, paragraph: &mut String) {
    let text = collapse(paragraph);
    paragraph.clear();
    if !text.is_empty() {
        blocks.push(Block::Paragraph(vec![Inline::Text(text)]));
    }
}

/// `text/markdown`: `display` comes from rendering the Markdown to HTML and running the HTML
/// display path, so raw HTML is parsed and dropped (hidden parts included) instead of passed
/// through. `security_text` is the whole source (raw HTML included) **followed by** the HTML
/// path's `security_text` of the rendered page: Markdown syntax can join text the source keeps
/// apart (`ig*no*re`, `i&#103;nore`, `ig<b>no</b>re` all display as `ignore`), and the scanner must
/// see what the model sees.
pub(crate) fn extract_markdown(
    source: &str,
    base: &Url,
    limits: &ExtractLimits,
) -> Result<ExtractedDocument, ExtractError> {
    let mut security_text = security_text(source, limits)?;
    let mut rendered = String::new();
    push_html(
        &mut rendered,
        Parser::new_ext(
            source,
            Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH,
        ),
    );
    let remaining = ExtractLimits {
        max_security_text_bytes: limits
            .max_security_text_bytes
            .saturating_sub(security_text.len()),
        ..*limits
    };
    let parts = html::extract_parts(&rendered, base, &remaining).map_err(|err| match err {
        ExtractError::SecurityTextTooLarge { .. } => ExtractError::SecurityTextTooLarge {
            limit: limits.max_security_text_bytes,
        },
        other => other,
    })?;
    security_text.push('\n');
    security_text.push_str(&parts.security_text);
    if security_text.len() > limits.max_security_text_bytes {
        return Err(ExtractError::SecurityTextTooLarge {
            limit: limits.max_security_text_bytes,
        });
    }
    finish(
        security_text,
        parts.blocks,
        parts.links,
        parts.links_truncated,
        parts.title,
        limits,
    )
}

/// `application/json`: pretty-printed (keys sorted) in one fenced `json` block; invalid or
/// too-deep JSON (serde_json's recursion limit) is shown as the cleaned source text.
/// `security_text` is the same text.
pub(crate) fn extract_json(
    source: &str,
    page_url: &Url,
    limits: &ExtractLimits,
) -> Result<ExtractedDocument, ExtractError> {
    let pretty = serde_json::from_str::<serde_json::Value>(source)
        .ok()
        .and_then(|value| serde_json::to_string_pretty(&value).ok())
        .unwrap_or_else(|| source.to_owned());
    let cleaned = textclean::clean(&pretty);
    let lines: Vec<&str> = cleaned.lines().map(str::trim_end).collect();
    let text = lines.join("\n");
    let text = text.trim_matches('\n');
    let blocks = if text.trim().is_empty() {
        Vec::new()
    } else {
        vec![Block::Code {
            lang: Some("json".to_owned()),
            text: text.to_owned(),
        }]
    };
    let security_text = html::text_security_text(
        text,
        &markdown::render_body(&blocks),
        page_url,
        limits.max_security_text_bytes,
    )?;
    finish(security_text, blocks, Vec::new(), false, None, limits)
}

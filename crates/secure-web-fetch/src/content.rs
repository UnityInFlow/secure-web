//! `Content-Type` / `Content-Encoding` classification and body sniffing.
//!
//! Parsed by hand rather than with a MIME crate: only the essence and `charset` are needed, and
//! every output is normalized to token characters so header text cannot smuggle anything else.

/// Supported content types (`docs/security-policy.md` §2). `Unsupported` is never returned inside
/// a successful response: the fetcher turns it into `UNSUPPORTED_CONTENT_TYPE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentType {
    /// `text/html` (also `application/xhtml+xml`).
    Html,
    /// `text/plain`.
    PlainText,
    /// `text/markdown` (also `text/x-markdown`).
    Markdown,
    /// `application/json`, capped at `maxJsonBytes`.
    Json,
    /// Anything else, carrying the normalized essence (token characters only, ≤ 64 bytes).
    Unsupported(String),
}

impl ContentType {
    /// The canonical MIME essence, e.g. `text/html`.
    pub fn essence(&self) -> &str {
        match self {
            ContentType::Html => "text/html",
            ContentType::PlainText => "text/plain",
            ContentType::Markdown => "text/markdown",
            ContentType::Json => "application/json",
            ContentType::Unsupported(essence) => essence,
        }
    }
}

/// Longest essence / charset kept from a header; longer values are truncated.
const MAX_TOKEN_LEN: usize = 64;

/// Bytes inspected when the response has no `Content-Type`.
pub const SNIFF_WINDOW: usize = 512;

/// RFC 9110 `tchar`.
fn is_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

fn normalize_token(text: &str) -> Option<String> {
    let lower = text.trim().to_ascii_lowercase();
    if lower.is_empty() || !lower.chars().all(is_tchar) {
        return None;
    }
    Some(lower.chars().take(MAX_TOKEN_LEN).collect())
}

/// Parse a `Content-Type` header value into the content type and `charset` parameter.
pub fn parse_content_type(header: &str) -> (ContentType, Option<String>) {
    let mut parts = header.split(';');
    let essence_text = parts.next().unwrap_or_default().trim();
    let essence = match essence_text.split_once('/') {
        Some((kind, subtype)) => match (normalize_token(kind), normalize_token(subtype)) {
            (Some(kind), Some(subtype)) => Some(format!("{kind}/{subtype}")),
            _ => None,
        },
        None => None,
    };
    let charset = parts.find_map(|param| {
        let (name, value) = param.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("charset") {
            return None;
        }
        normalize_token(value.trim().trim_matches('"'))
    });
    let content_type = match essence.as_deref() {
        Some("text/html" | "application/xhtml+xml") => ContentType::Html,
        Some("text/plain") => ContentType::PlainText,
        Some("text/markdown" | "text/x-markdown") => ContentType::Markdown,
        Some("application/json") => ContentType::Json,
        Some(other) => ContentType::Unsupported(other.chars().take(MAX_TOKEN_LEN).collect()),
        None => ContentType::Unsupported("invalid".to_owned()),
    };
    (content_type, charset)
}

/// Classify a body that arrived without `Content-Type`: HTML if the first
/// [`SNIFF_WINDOW`] bytes open with `<!doctype html` or contain `<html`, binary (unsupported) if
/// they contain a NUL byte, plain text otherwise.
pub fn sniff(body: &[u8]) -> ContentType {
    let window = &body[..body.len().min(SNIFF_WINDOW)];
    if window.contains(&0) {
        return ContentType::Unsupported("application/octet-stream".to_owned());
    }
    let text = String::from_utf8_lossy(window).to_ascii_lowercase();
    let trimmed = text.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n']);
    if trimmed.starts_with("<!doctype html") || trimmed.contains("<html") {
        ContentType::Html
    } else {
        ContentType::PlainText
    }
}

/// Supported `Content-Encoding` values. The fetcher advertises only `gzip, deflate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    Identity,
    Gzip,
    /// HTTP `deflate` is the zlib format (RFC 9110 §8.4.1.2).
    Deflate,
}

/// Parse `Content-Encoding`. Unknown codings and stacked codings (`gzip, gzip` — a
/// multiplying bomb) are refused.
pub(crate) fn parse_content_encoding(header: Option<&str>) -> Option<Encoding> {
    let Some(header) = header else {
        return Some(Encoding::Identity);
    };
    let codings: Vec<String> = header
        .split(',')
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| !c.is_empty() && c != "identity")
        .collect();
    match codings.as_slice() {
        [] => Some(Encoding::Identity),
        [one] if one == "gzip" || one == "x-gzip" => Some(Encoding::Gzip),
        [one] if one == "deflate" => Some(Encoding::Deflate),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_types_are_recognized_case_insensitively() {
        assert_eq!(
            parse_content_type("text/html; charset=UTF-8"),
            (ContentType::Html, Some("utf-8".to_owned()))
        );
        assert_eq!(parse_content_type("TEXT/Plain").0, ContentType::PlainText);
        assert_eq!(parse_content_type("text/markdown").0, ContentType::Markdown);
        assert_eq!(
            parse_content_type("text/x-markdown").0,
            ContentType::Markdown
        );
        assert_eq!(
            parse_content_type("application/json;charset=\"utf-8\""),
            (ContentType::Json, Some("utf-8".to_owned()))
        );
    }

    #[test]
    fn everything_else_is_unsupported_and_normalized() {
        assert_eq!(
            parse_content_type("application/pdf").0,
            ContentType::Unsupported("application/pdf".to_owned())
        );
        assert_eq!(
            parse_content_type("application/zip").0,
            ContentType::Unsupported("application/zip".to_owned())
        );
        assert_eq!(
            parse_content_type("text/html evil").0,
            ContentType::Unsupported("invalid".to_owned())
        );
        assert_eq!(
            parse_content_type("").0,
            ContentType::Unsupported("invalid".to_owned())
        );
        let long = format!("application/{}", "x".repeat(500));
        match parse_content_type(&long).0 {
            ContentType::Unsupported(essence) => assert!(essence.len() <= MAX_TOKEN_LEN),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn invalid_charset_is_dropped() {
        assert_eq!(parse_content_type("text/html; charset=a b").1, None);
        assert_eq!(parse_content_type("text/html; foo=bar").1, None);
    }

    #[test]
    fn sniffing_detects_html_text_and_binary() {
        assert_eq!(sniff(b"  <!DOCTYPE html><p>x"), ContentType::Html);
        assert_eq!(sniff(b"\xef\xbb\xbf<html>"), ContentType::Html);
        assert_eq!(sniff(b"hello world"), ContentType::PlainText);
        assert_eq!(sniff(b""), ContentType::PlainText);
        assert!(matches!(
            sniff(b"%PDF-1.4\0\x01"),
            ContentType::Unsupported(_)
        ));
        let mut late = vec![b'a'; SNIFF_WINDOW];
        late.extend_from_slice(b"<html>");
        assert_eq!(sniff(&late), ContentType::PlainText);
    }

    #[test]
    fn only_single_gzip_or_deflate_encodings_are_accepted() {
        assert_eq!(parse_content_encoding(None), Some(Encoding::Identity));
        assert_eq!(
            parse_content_encoding(Some("identity")),
            Some(Encoding::Identity)
        );
        assert_eq!(parse_content_encoding(Some("GZIP")), Some(Encoding::Gzip));
        assert_eq!(parse_content_encoding(Some("x-gzip")), Some(Encoding::Gzip));
        assert_eq!(
            parse_content_encoding(Some("deflate")),
            Some(Encoding::Deflate)
        );
        assert_eq!(parse_content_encoding(Some("br")), None);
        assert_eq!(parse_content_encoding(Some("zstd")), None);
        assert_eq!(parse_content_encoding(Some("gzip, gzip")), None);
        assert_eq!(parse_content_encoding(Some("gzip, deflate")), None);
    }
}

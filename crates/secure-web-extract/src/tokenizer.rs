//! A small, linear HTML tokenizer (ADR-013).
//!
//! The bake-off found every candidate library unsafe on hostile input within the 5 MiB page
//! cap: html5ever's tokenizer checks duplicate attributes with a linear scan (quadratic in the
//! attribute count of one tag), its tree builder (and `scraper`) scans the open-element stack
//! (quadratic in nesting depth), and html5gum recurses once per quoted attribute (stack
//! overflow, aborting the process). This tokenizer follows the WHATWG tokenization rules that
//! decide *where tags, comments and raw text begin and end*, in one forward pass with no
//! recursion and O(1) work per input byte (attribute de-duplication uses a hash set).
//!
//! Simplifications, all of which only affect `display` precision (every byte of text still
//! reaches `security_text` through some token):
//!
//! - raw-text elements (`script`, `style`, `title`, …) end at the first matching end tag; the
//!   script-data "escaped" states are not modelled;
//! - `<![CDATA[` is a bogus comment (HTML content, not foreign content);
//! - a tag or attribute cut off by the end of the input is emitted as [`Token::Unparsed`]
//!   instead of being dropped, so its text is still scanned.
//!
//! Character references are decoded exactly once, by `htmlize` (full WHATWG named-reference
//! table, attribute-context rules for legacy references).

use std::borrow::Cow;
use std::collections::HashSet;

/// One token. Text and attribute values are decoded; comments and raw text are not.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Token<'a> {
    /// A start tag: lower-case name, attributes (first of duplicates kept, source order),
    /// self-closing flag.
    StartTag {
        name: String,
        attrs: Vec<(String, String)>,
        self_closing: bool,
    },
    /// An end tag. Attribute values on end tags (ignored by browsers) are kept for scanning.
    EndTag { name: String, attrs: Vec<String> },
    /// Character data.
    Text(Cow<'a, str>),
    /// A comment (or bogus comment) body.
    Comment(&'a str),
    /// A doctype body (after `<!doctype`).
    Doctype(&'a str),
    /// Markup cut off by the end of the input.
    Unparsed(&'a str),
}

/// Elements whose content is raw text, and whether character references in it are decoded.
fn raw_text_kind(name: &str) -> Option<RawKind> {
    match name {
        "title" | "textarea" => Some(RawKind::Rcdata),
        "script" | "style" | "xmp" | "iframe" | "noembed" | "noframes" | "noscript" => {
            Some(RawKind::Rawtext)
        }
        "plaintext" => Some(RawKind::Plaintext),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RawKind {
    Rcdata,
    Rawtext,
    Plaintext,
}

fn is_ws(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | b'\x0C' | b'\r' | b' ')
}

fn decode_text(text: &str) -> Cow<'_, str> {
    htmlize::unescape(text)
}

fn decode_attr(text: &str) -> String {
    htmlize::unescape_attribute(text).into_owned()
}

/// Tokenize `input`, calling `emit` for every token in order.
pub(crate) fn tokenize<'a, E>(
    input: &'a str,
    mut emit: impl FnMut(Token<'a>) -> Result<(), E>,
) -> Result<(), E> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        let Some(lt) = bytes[i..].iter().position(|&b| b == b'<').map(|p| p + i) else {
            emit(Token::Text(decode_text(&input[i..])))?;
            break;
        };
        if lt > i {
            emit(Token::Text(decode_text(&input[i..lt])))?;
        }
        i = lt;
        match bytes.get(i + 1) {
            Some(b) if b.is_ascii_alphabetic() => {
                let Some((tag, end)) = tag(input, i + 1) else {
                    emit(Token::Unparsed(&input[i..]))?;
                    break;
                };
                i = end;
                let raw = raw_text_kind(&tag.name);
                let name = tag.name.clone();
                emit(Token::StartTag {
                    name: tag.name,
                    attrs: tag.attrs,
                    self_closing: tag.self_closing,
                })?;
                if let Some(kind) = raw {
                    let content_end = match kind {
                        RawKind::Plaintext => len,
                        RawKind::Rcdata | RawKind::Rawtext => {
                            find_end_tag(bytes, i, name.as_bytes()).unwrap_or(len)
                        }
                    };
                    let content = &input[i..content_end];
                    if !content.is_empty() {
                        emit(Token::Text(match kind {
                            RawKind::Rcdata => decode_text(content),
                            RawKind::Rawtext | RawKind::Plaintext => Cow::Borrowed(content),
                        }))?;
                    }
                    i = content_end;
                }
            }
            Some(b'/') => match bytes.get(i + 2) {
                Some(b) if b.is_ascii_alphabetic() => {
                    let Some((tag, end)) = tag(input, i + 2) else {
                        emit(Token::Unparsed(&input[i..]))?;
                        break;
                    };
                    i = end;
                    emit(Token::EndTag {
                        name: tag.name,
                        attrs: tag.attrs.into_iter().map(|(_, v)| v).collect(),
                    })?;
                }
                // `</>` is ignored.
                Some(b'>') => i += 3,
                // `</` at the end of the input is text.
                None => {
                    emit(Token::Text(Cow::Borrowed(&input[i..])))?;
                    break;
                }
                // `</ …>` is a bogus comment.
                Some(_) => {
                    let (body, end) = bogus_comment(input, i + 2);
                    emit(Token::Comment(body))?;
                    i = end;
                }
            },
            Some(b'!') => {
                let rest = &bytes[i + 2..];
                if rest.starts_with(b"--") {
                    let (body, end) = comment(input, i + 4);
                    emit(Token::Comment(body))?;
                    i = end;
                } else if rest.len() >= 7 && rest[..7].eq_ignore_ascii_case(b"doctype") {
                    let (body, end) = bogus_comment(input, i + 9);
                    emit(Token::Doctype(body.trim()))?;
                    i = end;
                } else {
                    let (body, end) = bogus_comment(input, i + 2);
                    emit(Token::Comment(body))?;
                    i = end;
                }
            }
            Some(b'?') => {
                let (body, end) = bogus_comment(input, i + 1);
                emit(Token::Comment(body))?;
                i = end;
            }
            // A lone `<` is text.
            _ => {
                emit(Token::Text(Cow::Borrowed("<")))?;
                i += 1;
            }
        }
    }
    Ok(())
}

/// A bogus comment starting at `start`: everything up to the next `>`.
fn bogus_comment(input: &str, start: usize) -> (&str, usize) {
    let start = start.min(input.len());
    match input.as_bytes()[start..].iter().position(|&b| b == b'>') {
        Some(p) => (&input[start..start + p], start + p + 1),
        None => (&input[start..], input.len()),
    }
}

/// A comment body starting after `<!--`: ends at `-->` or `--!>` (`<!-->` and `<!--->` are
/// empty comments), or at the end of the input.
fn comment(input: &str, start: usize) -> (&str, usize) {
    let bytes = input.as_bytes();
    let start = start.min(bytes.len());
    if bytes[start..].starts_with(b">") {
        return ("", start + 1);
    }
    if bytes[start..].starts_with(b"->") {
        return ("", start + 2);
    }
    let mut j = start;
    while let Some(p) = bytes[j..].iter().position(|&b| b == b'-') {
        let dash = j + p;
        let after = &bytes[dash..];
        if after.starts_with(b"-->") {
            return (&input[start..dash], dash + 3);
        }
        if after.starts_with(b"--!>") {
            return (&input[start..dash], dash + 4);
        }
        j = dash + 1;
    }
    (&input[start..], bytes.len())
}

/// Position of the `<` of the first `</name` (ASCII case-insensitive) at or after `from` that
/// is followed by whitespace, `/` or `>`.
fn find_end_tag(bytes: &[u8], from: usize, name: &[u8]) -> Option<usize> {
    let mut j = from;
    while let Some(p) = bytes[j..].iter().position(|&b| b == b'<') {
        let lt = j + p;
        let candidate = &bytes[lt..];
        if candidate.len() >= 2 + name.len()
            && candidate[1] == b'/'
            && candidate[2..2 + name.len()].eq_ignore_ascii_case(name)
            && candidate
                .get(2 + name.len())
                .is_some_and(|&b| is_ws(b) || b == b'/' || b == b'>')
        {
            return Some(lt);
        }
        j = lt + 1;
    }
    None
}

struct Tag {
    name: String,
    attrs: Vec<(String, String)>,
    self_closing: bool,
}

/// Parse a tag whose name starts at `start`. Returns the tag and the index after its `>`, or
/// `None` when the input ends inside the tag.
fn tag(input: &str, start: usize) -> Option<(Tag, usize)> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = start;
    while i < len && !is_ws(bytes[i]) && bytes[i] != b'/' && bytes[i] != b'>' {
        i += 1;
    }
    let name = input[start..i].to_ascii_lowercase();
    let mut attrs: Vec<(String, String)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut self_closing = false;
    loop {
        // Before attribute name.
        while i < len && is_ws(bytes[i]) {
            i += 1;
        }
        let &b = bytes.get(i)?;
        match b {
            b'>' => {
                i += 1;
                break;
            }
            b'/' => {
                if bytes.get(i + 1) == Some(&b'>') {
                    self_closing = true;
                    i += 2;
                    break;
                }
                i += 1;
                continue;
            }
            _ => {}
        }
        // Attribute name: the first character is always part of it (even `=`).
        let name_start = i;
        i += 1;
        while i < len && !is_ws(bytes[i]) && !matches!(bytes[i], b'/' | b'>' | b'=') {
            i += 1;
        }
        let attr_name = input[name_start..i].to_ascii_lowercase();
        while i < len && is_ws(bytes[i]) {
            i += 1;
        }
        let mut value = String::new();
        if bytes.get(i) == Some(&b'=') {
            i += 1;
            while i < len && is_ws(bytes[i]) {
                i += 1;
            }
            match *bytes.get(i)? {
                quote @ (b'"' | b'\'') => {
                    let close = bytes[i + 1..].iter().position(|&c| c == quote)? + i + 1;
                    value = decode_attr(&input[i + 1..close]);
                    i = close + 1;
                }
                // Missing value: `<a href=>`.
                b'>' => {}
                _ => {
                    let value_start = i;
                    while i < len && !is_ws(bytes[i]) && bytes[i] != b'>' {
                        i += 1;
                    }
                    value = decode_attr(&input[value_start..i]);
                }
            }
        }
        if seen.insert(attr_name.clone()) {
            attrs.push((attr_name, value));
        }
    }
    Some((
        Tag {
            name,
            attrs,
            self_closing,
        },
        i,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(input: &str) -> Vec<Token<'_>> {
        let mut out = Vec::new();
        tokenize::<()>(input, |t| {
            out.push(t);
            Ok(())
        })
        .unwrap();
        out
    }

    fn start(name: &str, attrs: &[(&str, &str)], self_closing: bool) -> Token<'static> {
        Token::StartTag {
            name: name.into(),
            attrs: attrs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            self_closing,
        }
    }

    fn end(name: &str) -> Token<'static> {
        Token::EndTag {
            name: name.into(),
            attrs: Vec::new(),
        }
    }

    fn text(t: &str) -> Token<'_> {
        Token::Text(Cow::Borrowed(t))
    }

    #[test]
    fn tags_attributes_and_text() {
        assert_eq!(
            tokens("<DIV Class=a id='b' data-x=\"c>d\" hidden title=&amp;x/>hi</Div>"),
            [
                start(
                    "div",
                    &[
                        ("class", "a"),
                        ("id", "b"),
                        ("data-x", "c>d"),
                        ("hidden", ""),
                        ("title", "&x/")
                    ],
                    false
                ),
                text("hi"),
                end("div"),
            ]
        );
        assert_eq!(tokens("<br/>"), [start("br", &[], true)]);
        assert_eq!(
            tokens("<a a=1 a=2 b=\"x\"c=y>"),
            [start("a", &[("a", "1"), ("b", "x"), ("c", "y")], false)]
        );
    }

    #[test]
    fn character_references_are_decoded_once() {
        assert_eq!(
            tokens("&amp;lt; &lt;b&gt; &#x49;&#8220;&copy &zzz; &notit;"),
            // `&not` is a legacy reference, decoded without `;` as browsers do.
            [text("&lt; <b> I\u{201C}\u{A9} &zzz; \u{AC}it;")]
        );
        // Legacy references without `;` are not decoded before `=` / alphanumerics in values.
        assert_eq!(
            tokens("<a href=\"?a=1&copy=2&amp;b\">"),
            [start("a", &[("href", "?a=1&copy=2&b")], false)]
        );
    }

    #[test]
    fn comments_doctype_and_bogus_comments() {
        assert_eq!(
            tokens(
                "<!DOCTYPE html><!-- a -- b --><!--><!--->x<!--y--!><?php z ?></ w><![CDATA[q]]>"
            ),
            [
                Token::Doctype("html"),
                Token::Comment(" a -- b "),
                Token::Comment(""),
                Token::Comment(""),
                text("x"),
                Token::Comment("y"),
                Token::Comment("?php z ?"),
                Token::Comment(" w"),
                Token::Comment("[CDATA[q]]"),
            ]
        );
        assert_eq!(tokens("<!-- open"), [Token::Comment(" open")]);
    }

    #[test]
    fn raw_text_elements() {
        assert_eq!(
            tokens("<script>if (a<b && c>d) { x = '<p>'; }</script ><title>a &amp; <b></TITLE>"),
            [
                start("script", &[], false),
                text("if (a<b && c>d) { x = '<p>'; }"),
                end("script"),
                start("title", &[], false),
                text("a & <b>"),
                end("title"),
            ]
        );
        assert_eq!(
            tokens("<style>a</stylex></style>"),
            [start("style", &[], false), text("a</stylex>"), end("style")]
        );
        assert_eq!(
            tokens("<plaintext><b>x</b>"),
            [start("plaintext", &[], false), text("<b>x</b>")]
        );
        assert_eq!(
            tokens("<script>never closed"),
            [start("script", &[], false), text("never closed")]
        );
    }

    #[test]
    fn stray_angle_brackets_are_text_and_truncated_markup_is_kept() {
        assert_eq!(
            tokens("a < b <3 </> c"),
            [
                text("a "),
                text("<"),
                text(" b "),
                text("<"),
                text("3 "),
                text(" c")
            ]
        );
        assert_eq!(
            tokens("x<div title=\"unterminated"),
            [text("x"), Token::Unparsed("<div title=\"unterminated")]
        );
        assert_eq!(tokens("</"), [text("</")]);
    }

    #[test]
    fn end_tag_attributes_are_kept() {
        assert_eq!(
            tokens("</p title=\"t\">"),
            [Token::EndTag {
                name: "p".into(),
                attrs: vec!["t".into()]
            }]
        );
    }

    #[test]
    fn many_quoted_attributes_do_not_recurse() {
        let mut input = String::from("<div");
        for i in 0..300_000 {
            input.push_str(&format!(" a{i}=\"v\""));
        }
        input.push('>');
        let tokens = tokens(&input);
        assert!(matches!(&tokens[..], [Token::StartTag { attrs, .. }] if attrs.len() == 300_000));
    }
}

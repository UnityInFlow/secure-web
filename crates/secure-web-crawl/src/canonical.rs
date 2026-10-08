//! URL canonicalization for the crawl frontier's `seen` set (deep-dive §13.4).
//!
//! The WHATWG parse (`url` crate) already lowercases the scheme and host, drops a default port
//! and removes dot segments. On top of that the canonical form:
//!
//! - strips the fragment;
//! - uppercases the hex digits of every percent-escape in the path and query (`%2f` → `%2F`);
//! - removes the query parameters named in `crawl.stripQueryParams` (ASCII case-insensitive), and
//!   sorts the rest (by name, then value, as written) — it never drops all query parameters,
//!   because documentation sites use them semantically;
//! - drops an empty query (`?`).
//!
//! The canonical form is a dedupe key only: the crawler fetches the link as written.

use std::fmt;

use url::Url;

/// A canonicalized URL string: equal keys name the same crawl target.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CanonicalUrl(String);

impl CanonicalUrl {
    /// The canonical serialization.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CanonicalUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Paths and queries are page-chosen text; print the length only.
        f.debug_struct("CanonicalUrl")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// Canonicalize `url`, removing the query parameters named in `strip`.
pub fn canonicalize(url: &Url, strip: &[String]) -> CanonicalUrl {
    let mut url = url.clone();
    url.set_fragment(None);
    let path = upper_percent_escapes(url.path());
    url.set_path(&path);
    let query = url.query().map(|query| canonical_query(query, strip));
    match query.as_deref() {
        Some("") | None => url.set_query(None),
        Some(query) => url.set_query(Some(query)),
    }
    CanonicalUrl(url.into())
}

/// `query` without the `strip` parameters, the rest sorted. Parameters are compared by their
/// text as written (no decoding), so `a=%41` and `a=A` stay distinct.
fn canonical_query(query: &str, strip: &[String]) -> String {
    let query = upper_percent_escapes(query);
    let mut params: Vec<(&str, &str)> = query
        .split('&')
        .filter(|param| !param.is_empty())
        .map(|param| param.split_once('=').unwrap_or((param, "")))
        .filter(|(name, _)| !strip.iter().any(|s| s.eq_ignore_ascii_case(name)))
        .collect();
    params.sort_unstable();
    params
        .iter()
        .map(|(name, value)| {
            if value.is_empty() {
                (*name).to_owned()
            } else {
                format!("{name}={value}")
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Uppercase the two hex digits after every `%`.
fn upper_percent_escapes(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        let is_escape = bytes[i] == b'%'
            && bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
            && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit);
        if is_escape {
            out.push('%');
            out.push(char::from(bytes[i + 1].to_ascii_uppercase()));
            out.push(char::from(bytes[i + 2].to_ascii_uppercase()));
            i += 3;
            continue;
        }
        // Copy one whole UTF-8 character (the path and query of a parsed URL are ASCII, but do
        // not rely on it).
        let Some(ch) = text[i..].chars().next() else {
            break;
        };
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(url: &str) -> String {
        let strip = ["utm_source".to_owned(), "utm_medium".to_owned()];
        canonicalize(&Url::parse(url).unwrap(), &strip).0
    }

    #[test]
    fn fragments_default_ports_case_and_dot_segments_collapse() {
        assert_eq!(
            canon("HTTP://Example.COM:80/a/./b/../c#x"),
            "http://example.com/a/c"
        );
        assert_eq!(
            canon("https://example.com:443/docs#a"),
            "https://example.com/docs"
        );
        assert_eq!(
            canon("https://example.com/docs#b"),
            "https://example.com/docs"
        );
        assert_eq!(
            canon("https://example.com:8443/"),
            "https://example.com:8443/"
        );
    }

    #[test]
    fn percent_escapes_are_uppercased_but_not_decoded() {
        assert_eq!(
            canon("http://e.test/a%2fb?q=%7e"),
            "http://e.test/a%2Fb?q=%7E"
        );
        assert_ne!(canon("http://e.test/%41"), canon("http://e.test/A"));
        assert_eq!(canon("http://e.test/100%"), "http://e.test/100%");
    }

    #[test]
    fn tracking_params_are_removed_and_the_rest_sorted() {
        assert_eq!(canon("http://e.test/a?utm_source=x"), "http://e.test/a");
        assert_eq!(
            canon("http://e.test/a?UTM_Medium=y&b=2&a=1&utm_source=x"),
            "http://e.test/a?a=1&b=2"
        );
        assert_eq!(
            canon("http://e.test/a?b=2&a=1"),
            canon("http://e.test/a?a=1&b=2")
        );
        assert_eq!(canon("http://e.test/a?"), "http://e.test/a");
        assert_eq!(canon("http://e.test/a?&&"), "http://e.test/a");
        // Other parameters are kept: documentation sites use them.
        assert_eq!(
            canon("http://e.test/a?version=2"),
            "http://e.test/a?version=2"
        );
    }

    #[test]
    fn debug_hides_the_url() {
        let key = canonicalize(&Url::parse("http://e.test/secret-path").unwrap(), &[]);
        assert!(!format!("{key:?}").contains("secret"));
    }
}

//! Raw-text inspection of a URL's authority.
//!
//! The WHATWG parser (`url` crate) silently normalizes obfuscated IPv4 notations — `2130706433`,
//! `0x7f000001`, `0177.0.0.1`, `127.1`, `%31%32%37.0.0.1` all become `127.0.0.1`. The normalized
//! address is range-checked like any other; this module recovers the host **as written** so a
//! non-canonical spelling can be refused even when the address it encodes is public.

/// Characters the WHATWG parser removes before parsing: leading/trailing C0 controls and spaces
/// are trimmed, and ASCII tab/newline are removed everywhere.
fn clean(input: &str) -> String {
    input
        .trim_matches(|c: char| c <= '\u{20}')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect()
}

/// The authority component (`userinfo@host:port`) of a special-scheme URL as written, or `None`
/// if it cannot be located.
///
/// Mirrors the WHATWG special-scheme rules: any run of `/` or `\` after `scheme:` is skipped,
/// and the authority ends at the first `/`, `\`, `?` or `#`.
pub(crate) fn raw_authority(input: &str) -> Option<String> {
    let cleaned = clean(input);
    let (_, rest) = cleaned.split_once(':')?;
    let rest = rest.trim_start_matches(['/', '\\']);
    let end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
    Some(rest[..end].to_owned())
}

/// The host part of a raw authority: userinfo (up to the last `@`) and `:port` removed.
pub(crate) fn raw_host(authority: &str) -> &str {
    let host_port = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    if host_port.starts_with('[') {
        return match host_port.find(']') {
            Some(close) => &host_port[..=close],
            None => host_port,
        };
    }
    match host_port.rfind(':') {
        Some(colon) => &host_port[..colon],
        None => host_port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_is_found_behind_slash_and_backslash_runs() {
        assert_eq!(raw_authority("http://a.b:80/x").as_deref(), Some("a.b:80"));
        assert_eq!(raw_authority("http:\\\\a.b\\x").as_deref(), Some("a.b"));
        assert_eq!(raw_authority("http:a.b").as_deref(), Some("a.b"));
        assert_eq!(raw_authority(" http://a\t.b?q").as_deref(), Some("a.b"));
        assert_eq!(raw_authority("http://u@a.b#f").as_deref(), Some("u@a.b"));
        assert_eq!(raw_authority("no-colon"), None);
    }

    #[test]
    fn host_drops_userinfo_and_port() {
        assert_eq!(raw_host("u:p@1.2.3.4:80"), "1.2.3.4");
        assert_eq!(raw_host("a@b@0x7f000001"), "0x7f000001");
        assert_eq!(raw_host("[::1]:8080"), "[::1]");
        assert_eq!(raw_host("example.com"), "example.com");
    }
}

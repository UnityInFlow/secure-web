//! Crawl scope (ADR-004): which discovered links the crawler may follow.
//!
//! - `SAME_ORIGIN` (default): scheme, host and port equal to the root URL's.
//! - `ALLOWLIST`: the host is one of `allowedHosts` (any port, `http`/`https`).
//!
//! Include/exclude patterns are regexes over the URL **path**, compiled once with a size limit;
//! a link must match at least one include pattern (when any are given) and no exclude pattern.
//! The scope applies to discovered links only: the root URL is always fetched (the caller named
//! it), subject to the URL guard like every other URL.

use std::fmt;

use regex::{Regex, RegexBuilder};
use secure_web_core::config::CrawlScope;
use url::{Host, Origin, Url};

/// Most include (and, separately, exclude) patterns.
pub const MAX_PATTERNS: usize = 20;
/// Longest pattern, in bytes.
pub const MAX_PATTERN_BYTES: usize = 512;
/// Compiled-program size limit per pattern (`regex` `size_limit` / `dfa_size_limit`).
pub const PATTERN_SIZE_LIMIT: usize = 256 * 1024;
/// Most `allowedHosts` entries.
pub const MAX_ALLOWED_HOSTS: usize = 100;

/// The scope arguments could not be used. Messages never echo the arguments.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeError {
    /// `ALLOWLIST` without any `allowedHosts`.
    #[error("scope ALLOWLIST requires allowedHosts")]
    AllowlistWithoutHosts,
    /// An `allowedHosts` entry is not a host name or IP address, or there are too many.
    #[error("allowedHosts must be 1 to {MAX_ALLOWED_HOSTS} host names")]
    InvalidHost,
    /// Too many patterns, one too long, or one does not compile within the size limit.
    #[error(
        "{0} must be at most {MAX_PATTERNS} valid regexes of at most {MAX_PATTERN_BYTES} bytes"
    )]
    InvalidPattern(&'static str),
}

enum Kind {
    SameOrigin(Origin),
    Allowlist(Vec<String>),
}

/// A compiled crawl scope.
pub struct Scope {
    kind: Kind,
    include: Vec<Regex>,
    exclude: Vec<Regex>,
}

impl fmt::Debug for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match &self.kind {
            Kind::SameOrigin(_) => "SAME_ORIGIN",
            Kind::Allowlist(_) => "ALLOWLIST",
        };
        f.debug_struct("Scope")
            .field("kind", &kind)
            .field("include", &self.include.len())
            .field("exclude", &self.exclude.len())
            .finish()
    }
}

impl Scope {
    /// Compile a scope for a crawl rooted at `root`.
    pub fn new(
        root: &Url,
        scope: CrawlScope,
        allowed_hosts: &[String],
        include: &[String],
        exclude: &[String],
    ) -> Result<Self, ScopeError> {
        let kind = match scope {
            CrawlScope::SameOrigin => Kind::SameOrigin(root.origin()),
            CrawlScope::Allowlist => {
                if allowed_hosts.is_empty() {
                    return Err(ScopeError::AllowlistWithoutHosts);
                }
                if allowed_hosts.len() > MAX_ALLOWED_HOSTS {
                    return Err(ScopeError::InvalidHost);
                }
                let hosts = allowed_hosts
                    .iter()
                    .map(|host| normalize_host(host).ok_or(ScopeError::InvalidHost))
                    .collect::<Result<Vec<_>, _>>()?;
                Kind::Allowlist(hosts)
            }
        };
        Ok(Self {
            kind,
            include: compile(include, "includePatterns")?,
            exclude: compile(exclude, "excludePatterns")?,
        })
    }

    /// Whether the crawler may follow `url`.
    pub fn allows(&self, url: &Url) -> bool {
        if !matches!(url.scheme(), "http" | "https") {
            return false;
        }
        let in_scope = match &self.kind {
            Kind::SameOrigin(origin) => url.origin() == *origin,
            Kind::Allowlist(hosts) => url
                .host()
                .map(|host| host_key(&host))
                .is_some_and(|host| hosts.contains(&host)),
        };
        if !in_scope {
            return false;
        }
        let path = url.path();
        (self.include.is_empty() || self.include.iter().any(|re| re.is_match(path)))
            && !self.exclude.iter().any(|re| re.is_match(path))
    }
}

fn compile(patterns: &[String], field: &'static str) -> Result<Vec<Regex>, ScopeError> {
    if patterns.len() > MAX_PATTERNS {
        return Err(ScopeError::InvalidPattern(field));
    }
    patterns
        .iter()
        .map(|pattern| {
            if pattern.len() > MAX_PATTERN_BYTES {
                return Err(ScopeError::InvalidPattern(field));
            }
            RegexBuilder::new(pattern)
                .size_limit(PATTERN_SIZE_LIMIT)
                .dfa_size_limit(PATTERN_SIZE_LIMIT)
                .build()
                .map_err(|_| ScopeError::InvalidPattern(field))
        })
        .collect()
}

/// An `allowedHosts` entry as a comparison key: parsed like a URL host (lowercased, IDNA,
/// IP literals canonical), a trailing dot removed. `None` for anything that is not a host.
fn normalize_host(host: &str) -> Option<String> {
    let trimmed = host.trim();
    if trimmed.is_empty() || trimmed.len() > 253 || trimmed.contains(['/', '@', ':', '?', '#']) {
        // `:` would be a port (or an unbracketed IPv6 literal); ports are not part of the key.
        if !(trimmed.starts_with('[') && trimmed.ends_with(']')) {
            return None;
        }
    }
    let parsed = Host::parse(trimmed).ok()?;
    Some(host_key(&parsed))
}

fn host_key<S: AsRef<str>>(host: &Host<S>) -> String {
    match host {
        Host::Domain(domain) => domain.as_ref().trim_end_matches('.').to_owned(),
        Host::Ipv4(addr) => addr.to_string(),
        Host::Ipv6(addr) => format!("[{addr}]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn same_origin_compares_scheme_host_and_port() {
        let scope = Scope::new(
            &url("https://docs.example.com/start"),
            CrawlScope::SameOrigin,
            &[],
            &[],
            &[],
        )
        .unwrap();
        assert!(scope.allows(&url("https://docs.example.com/api")));
        assert!(scope.allows(&url("https://DOCS.example.com:443/guides/setup")));
        for other in [
            "https://example.com/",
            "https://api.example.com/",
            "http://docs.example.com/",
            "https://docs.example.com:8443/",
            "https://github.com/",
            "mailto:someone@example.com",
        ] {
            assert!(!scope.allows(&url(other)), "{other}");
        }
    }

    #[test]
    fn allowlist_requires_hosts_and_matches_hosts_only() {
        let root = url("https://docs.example.com/");
        assert_eq!(
            Scope::new(&root, CrawlScope::Allowlist, &[], &[], &[]).unwrap_err(),
            ScopeError::AllowlistWithoutHosts
        );
        for bad in ["", "a/b", "user@host", "host:80", "http://x"] {
            assert_eq!(
                Scope::new(&root, CrawlScope::Allowlist, &strings(&[bad]), &[], &[]).unwrap_err(),
                ScopeError::InvalidHost,
                "{bad:?}"
            );
        }
        let scope = Scope::new(
            &root,
            CrawlScope::Allowlist,
            &strings(&["API.example.com.", "[::1]", "10.0.0.1"]),
            &[],
            &[],
        )
        .unwrap();
        assert!(scope.allows(&url("http://api.example.com:8080/x")));
        assert!(scope.allows(&url("http://[::1]/x")));
        assert!(scope.allows(&url("http://10.0.0.1/x")));
        // The root host is not implicitly allowed for children.
        assert!(!scope.allows(&url("https://docs.example.com/x")));
        assert!(!scope.allows(&url("https://evil-api.example.com/")));
    }

    #[test]
    fn include_and_exclude_patterns_apply_to_the_path() {
        let root = url("https://docs.example.com/");
        let scope = Scope::new(
            &root,
            CrawlScope::SameOrigin,
            &[],
            &strings(&["^/docs/"]),
            &strings(&["\\.(png|jpg)$"]),
        )
        .unwrap();
        assert!(scope.allows(&url("https://docs.example.com/docs/a")));
        assert!(!scope.allows(&url("https://docs.example.com/docs/a.png")));
        assert!(!scope.allows(&url("https://docs.example.com/blog/a")));
        assert!(!scope.allows(&url("https://docs.example.com/blog/?q=/docs/")));
    }

    #[test]
    fn patterns_are_bounded() {
        let root = url("https://docs.example.com/");
        let too_many = vec!["a".to_owned(); MAX_PATTERNS + 1];
        let too_long = vec!["a".repeat(MAX_PATTERN_BYTES + 1)];
        let too_big = vec!["\\w{1000}\\w{1000}\\w{1000}".to_owned()];
        let invalid = vec!["(".to_owned()];
        for patterns in [too_many, too_long, too_big, invalid] {
            assert_eq!(
                Scope::new(&root, CrawlScope::SameOrigin, &[], &patterns, &[]).unwrap_err(),
                ScopeError::InvalidPattern("includePatterns")
            );
            assert_eq!(
                Scope::new(&root, CrawlScope::SameOrigin, &[], &[], &patterns).unwrap_err(),
                ScopeError::InvalidPattern("excludePatterns")
            );
        }
    }
}

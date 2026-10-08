//! URL guard / SSRF protection (`docs/security-policy.md` §1, threat T5).
//!
//! [`UrlGuard`] is the **only** way to obtain a [`ValidatedTarget`], and a `ValidatedTarget` is
//! the only thing the fetcher will connect to. Order of operations:
//!
//! ```text
//! parse -> scheme check -> userinfo / port / host checks -> host literal normalization
//!       -> DNS resolve (all A/AAAA) -> reject if ANY address is blocked -> ValidatedTarget
//! ```
//!
//! The fetcher must connect to one of [`ValidatedTarget::addrs`] (pinned resolution), never
//! re-resolve the host name, and must run every redirect `Location` back through
//! [`UrlGuard::validate`]. [`UrlGuard::resolve_and_check`] only takes a [`CheckedUrl`], which only
//! [`UrlGuard::parse_and_check_static`] produces from the raw text.
//!
//! The `security.network.block*` booleans are not consulted: config validation refuses to start
//! with any of them off, and the guard enforces every range unconditionally.

mod literal;
mod ranges;

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ipnet::IpNet;
use secure_web_core::config::NetworkConfig;
use secure_web_core::error::ErrorCode;
use secure_web_core::network::{
    normalize_blocked_host, normalize_host, parse_blocked_cidr, NetworkRuleError,
};
use url::{Host, Url};

use ranges::ExtraRanges;
pub use ranges::EXTRA_BLOCKED_CIDRS;

/// Rule reported for a public IPv4 address written in a non-canonical notation (decimal, hex,
/// octal, short form, percent-encoded, trailing dot, …).
pub const AMBIGUOUS_IPV4_LITERAL: &str = "ambiguous-ipv4-literal";

/// Upper bound on one DNS lookup made by the guard, unless overridden with
/// [`UrlGuard::with_dns_timeout`]. Matches the `fetch.connectTimeout` default.
pub const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Host names blocked regardless of what they resolve to (in addition to `*.localhost`).
const DENIED_HOSTS: &[&str] = &["localhost", "metadata.google.internal"];

/// Why a URL was refused. Maps onto the contract [`ErrorCode`] via [`GuardError::code`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuardError {
    /// The input is not a valid absolute URL, has no host, or has port 0.
    #[error("invalid URL")]
    InvalidUrl,
    /// The scheme is not `http` or `https`.
    #[error("unsupported URL scheme `{0}`")]
    UnsupportedScheme(String),
    /// The URL carries credentials (`user:pass@host`, including an empty `@host`).
    #[error("URLs with userinfo are not allowed")]
    Userinfo,
    /// DNS resolution failed or returned no addresses.
    #[error("DNS resolution failed")]
    DnsFailed,
    /// A literal or resolved address falls in a blocked range.
    #[error("destination {addr} is blocked ({rule})")]
    Ssrf {
        /// The offending address (as literal or as resolved, before any IPv6 unwrapping).
        addr: IpAddr,
        /// The policy rule that fired: a CIDR from the policy table, [`EXTRA_BLOCKED_CIDRS`] or
        /// [`AMBIGUOUS_IPV4_LITERAL`].
        rule: &'static str,
    },
    /// The host name is on the denylist (`localhost`, `*.localhost`, metadata names, extras).
    #[error("host `{0}` is blocked")]
    HostDenied(String),
}

impl GuardError {
    /// The contract error code for this rejection.
    pub fn code(&self) -> ErrorCode {
        match self {
            GuardError::InvalidUrl | GuardError::Userinfo => ErrorCode::InvalidUrl,
            GuardError::UnsupportedScheme(_) => ErrorCode::UnsupportedScheme,
            GuardError::DnsFailed => ErrorCode::DnsFailed,
            GuardError::Ssrf { .. } | GuardError::HostDenied(_) => ErrorCode::SsrfBlocked,
        }
    }
}

/// `security.network` could not be turned into a guard.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuardConfigError {
    /// An `extraBlockedCidrs` entry is not a CIDR (`addr/prefix`).
    #[error("security.network.extraBlockedCidrs: `{0}` is not a valid CIDR")]
    InvalidCidr(String),
    /// An `extraBlockedHosts` entry is empty.
    #[error("security.network.extraBlockedHosts: empty host name")]
    EmptyHost,
    /// An `extraBlockedHosts` entry is an IP address; IPs belong in `extraBlockedCidrs`.
    #[error(
        "security.network.extraBlockedHosts: `{0}` is an IP address; \
         block it with an extraBlockedCidrs entry (addr/32 or addr/128) instead"
    )]
    IpLiteralHost(String),
    /// An `extraBlockedHosts` entry is not a valid host name (port, path, userinfo, wildcard,
    /// forbidden characters, or an IDNA error).
    #[error("security.network.extraBlockedHosts: `{0}` is not a valid host name")]
    InvalidHost(String),
    /// [`UrlGuard::with_test_fixture`] was given something other than a `*.test` name and a
    /// loopback socket.
    #[cfg(feature = "test-support")]
    #[error("test fixture allowance must be a `*.test` host name and a loopback socket")]
    InvalidFixture,
}

impl From<NetworkRuleError> for GuardConfigError {
    fn from(err: NetworkRuleError) -> Self {
        match err {
            NetworkRuleError::InvalidCidr(entry) => GuardConfigError::InvalidCidr(entry),
            NetworkRuleError::EmptyHost => GuardConfigError::EmptyHost,
            NetworkRuleError::IpLiteralHost(entry) => GuardConfigError::IpLiteralHost(entry),
            NetworkRuleError::InvalidHost(entry) => GuardConfigError::InvalidHost(entry),
        }
    }
}

/// A failed DNS lookup. The message is for debug logs only; callers see [`GuardError::DnsFailed`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ResolveError(String);

impl ResolveError {
    /// A lookup failure with a diagnostic message.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// The future returned by [`Resolver::resolve`].
pub type ResolveFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, ResolveError>> + Send + 'a>>;

/// DNS lookup, injectable so tests never touch real DNS.
pub trait Resolver: Send + Sync {
    /// Every A/AAAA address for `host` (an ASCII domain name, never an IP literal).
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a>;
}

/// Production resolver: the system resolver via [`tokio::net::lookup_host`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host, port))
                .await
                .map_err(|err| ResolveError::new(err.to_string()))?;
            Ok(addrs.map(|addr| addr.ip()).collect())
        })
    }
}

/// A destination that passed every SSRF check. Only [`UrlGuard`] can build one.
///
/// ```compile_fail
/// use secure_web_security::ssrf::ValidatedTarget;
/// let target = ValidatedTarget {
///     url: url::Url::parse("http://127.0.0.1/").unwrap(),
///     addrs: vec!["127.0.0.1".parse().unwrap()],
///     host: "127.0.0.1".to_owned(),
///     port: 80,
/// };
/// ```
///
/// `Debug` is hand-written: the URL's userinfo, path, query and fragment are unscanned,
/// attacker-controlled text and must never reach a log line or an assertion message.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedTarget {
    url: Url,
    addrs: Vec<IpAddr>,
    host: String,
    port: u16,
}

impl fmt::Debug for ValidatedTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedTarget")
            .field("scheme", &self.url.scheme())
            .field("host", &self.host)
            .field("port", &self.port)
            .field("addrs", &self.addrs)
            .finish_non_exhaustive()
    }
}

impl ValidatedTarget {
    /// The validated URL. Its path, query and fragment are untrusted text: never log them.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The validated addresses; connect only to one of these (never re-resolve the host).
    pub fn addrs(&self) -> &[IpAddr] {
        &self.addrs
    }

    /// Host as used for DNS / SNI: ASCII domain, or the IP literal without brackets.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Destination port (explicit, or the scheme default).
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// A URL that passed [`UrlGuard::parse_and_check_static`], the only producer of this type.
///
/// It exists because `Url::parse` erases facts the static check needs from the **raw text**: a
/// non-canonical IPv4 spelling (`http://1572395042/` becomes `http://93.184.216.34/`) and an
/// empty userinfo (`http://@example.com/` becomes `http://example.com/`). No check on a parsed
/// `Url` can recover them, so [`UrlGuard::resolve_and_check`] accepts only this type.
///
/// ```compile_fail,E0423
/// use secure_web_security::ssrf::CheckedUrl;
/// let checked = CheckedUrl(url::Url::parse("http://1572395042/").unwrap());
/// ```
///
/// ```compile_fail,E0308
/// use secure_web_core::config::NetworkConfig;
/// use secure_web_security::ssrf::UrlGuard;
/// let guard = UrlGuard::with_system_resolver(&NetworkConfig::default()).unwrap();
/// let url = url::Url::parse("http://1572395042/").unwrap();
/// let _pending = guard.resolve_and_check(&url);
/// ```
///
/// `Debug` shows only scheme, host and port: the rest of the URL is untrusted text.
#[derive(Clone, PartialEq, Eq)]
pub struct CheckedUrl(Url);

impl CheckedUrl {
    /// The parsed URL. Its path, query and fragment are untrusted text: never log them.
    pub fn as_url(&self) -> &Url {
        &self.0
    }
}

impl fmt::Debug for CheckedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckedUrl")
            .field("scheme", &self.0.scheme())
            .field("host", &self.0.host_str())
            .field("port", &self.0.port_or_known_default())
            .finish_non_exhaustive()
    }
}

/// Validates URLs against the SSRF policy. See the module docs.
#[derive(Clone)]
pub struct UrlGuard {
    extra_ranges: ExtraRanges,
    extra_hosts: Vec<String>,
    resolver: Arc<dyn Resolver>,
    dns_timeout: Duration,
    /// Test-only exemption for the fixture server (ADR-011). Compiled out of production builds.
    #[cfg(feature = "test-support")]
    fixture_allowance: Option<FixtureAllowance>,
}

impl fmt::Debug for UrlGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UrlGuard")
            .field("extra_ranges", &self.extra_ranges)
            .field("extra_hosts", &self.extra_hosts)
            .finish_non_exhaustive()
    }
}

impl UrlGuard {
    /// A guard for `cfg`, resolving host names through `resolver`.
    pub fn new(cfg: &NetworkConfig, resolver: Arc<dyn Resolver>) -> Result<Self, GuardConfigError> {
        let mut extra_ranges = ExtraRanges::default();
        for text in &cfg.extra_blocked_cidrs {
            match parse_blocked_cidr(text)? {
                IpNet::V4(v4) => extra_ranges.v4.push(v4),
                IpNet::V6(v6) => extra_ranges.v6.push(v6),
            }
        }
        let mut extra_hosts = Vec::with_capacity(cfg.extra_blocked_hosts.len());
        for entry in &cfg.extra_blocked_hosts {
            extra_hosts.push(normalize_blocked_host(entry)?);
        }
        Ok(Self {
            extra_ranges,
            extra_hosts,
            resolver,
            dns_timeout: DEFAULT_DNS_TIMEOUT,
            #[cfg(feature = "test-support")]
            fixture_allowance: None,
        })
    }

    /// Bound every DNS lookup to `timeout`; a lookup that takes longer is
    /// [`GuardError::DnsFailed`]. A zero timeout is replaced by [`DEFAULT_DNS_TIMEOUT`].
    #[must_use]
    pub fn with_dns_timeout(mut self, timeout: Duration) -> Self {
        self.dns_timeout = if timeout.is_zero() {
            DEFAULT_DNS_TIMEOUT
        } else {
            timeout
        };
        self
    }

    /// The DNS lookup bound in force.
    pub fn dns_timeout(&self) -> Duration {
        self.dns_timeout
    }

    /// A guard for `cfg` using the system resolver.
    pub fn with_system_resolver(cfg: &NetworkConfig) -> Result<Self, GuardConfigError> {
        Self::new(cfg, Arc::new(SystemResolver))
    }

    /// Every check that needs no DNS: parse, scheme, userinfo, port, host denylist, and IP
    /// literals (range rules plus the non-canonical-notation rule). The raw-text checks
    /// (userinfo `@`, non-canonical IPv4 spelling) happen only here; see [`CheckedUrl`].
    pub fn parse_and_check_static(&self, raw: &str) -> Result<CheckedUrl, GuardError> {
        let url = Url::parse(raw).map_err(|_| GuardError::InvalidUrl)?;
        self.check_url(&url)?;
        let authority = literal::raw_authority(raw);
        if authority.as_deref().is_some_and(|a| a.contains('@')) {
            return Err(GuardError::Userinfo);
        }
        if let Some(Host::Ipv4(addr)) = url.host() {
            // Already range-checked in `check_url`; now refuse a public address unless it was
            // written exactly in canonical dotted-decimal.
            let canonical = addr.to_string();
            let as_written = authority.as_deref().map(literal::raw_host);
            if as_written != Some(canonical.as_str()) {
                return Err(GuardError::Ssrf {
                    addr: IpAddr::V4(addr),
                    rule: AMBIGUOUS_IPV4_LITERAL,
                });
            }
        }
        Ok(CheckedUrl(url))
    }

    /// Resolve the host of a [`CheckedUrl`] and validate every address.
    ///
    /// Takes a `CheckedUrl`, not a `Url`, because the raw-text checks cannot be recovered from a
    /// parsed `Url`. The checks that survive parsing (scheme, userinfo, port, host denylist, IP
    /// ranges) are re-run anyway as defence in depth.
    pub async fn resolve_and_check(
        &self,
        checked: &CheckedUrl,
    ) -> Result<ValidatedTarget, GuardError> {
        let url = checked.as_url();
        let (host, port) = self.check_url(url)?;
        let addrs = match host {
            Target::Ip(addr) => vec![addr],
            Target::Domain(ref domain) => {
                let resolved =
                    tokio::time::timeout(self.dns_timeout, self.resolver.resolve(domain, port))
                        .await
                        .map_err(|_| GuardError::DnsFailed)?
                        .map_err(|_| GuardError::DnsFailed)?;
                let mut unique: Vec<IpAddr> = Vec::with_capacity(resolved.len());
                for addr in resolved {
                    if !unique.contains(&addr) {
                        unique.push(addr);
                    }
                }
                if unique.is_empty() {
                    return Err(GuardError::DnsFailed);
                }
                for addr in &unique {
                    #[cfg(feature = "test-support")]
                    if self.is_fixture_socket(domain, port, *addr) {
                        continue;
                    }
                    self.check_addr(*addr)?;
                }
                unique
            }
        };
        Ok(ValidatedTarget {
            url: url.clone(),
            addrs,
            host: host.to_string(),
            port,
        })
    }

    /// [`parse_and_check_static`](UrlGuard::parse_and_check_static) then
    /// [`resolve_and_check`](UrlGuard::resolve_and_check).
    pub async fn validate(&self, raw: &str) -> Result<ValidatedTarget, GuardError> {
        let url = self.parse_and_check_static(raw)?;
        self.resolve_and_check(&url).await
    }

    /// Check one address against the blocked ranges (policy table plus `extraBlockedCidrs`).
    /// IPv4-mapped, NAT64 and IPv4-compatible IPv6 addresses are checked by their embedded IPv4.
    pub fn check_addr(&self, addr: IpAddr) -> Result<(), GuardError> {
        match ranges::classify(addr, &self.extra_ranges) {
            Some(rule) => Err(GuardError::Ssrf { addr, rule }),
            None => Ok(()),
        }
    }

    /// Checks on a parsed URL that need neither DNS nor the raw input text.
    fn check_url(&self, url: &Url) -> Result<(Target, u16), GuardError> {
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(GuardError::UnsupportedScheme(scheme.to_owned()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(GuardError::Userinfo);
        }
        let port = url.port_or_known_default().ok_or(GuardError::InvalidUrl)?;
        if port == 0 {
            return Err(GuardError::InvalidUrl);
        }
        let target = match url.host().ok_or(GuardError::InvalidUrl)? {
            Host::Ipv4(addr) => Target::Ip(IpAddr::V4(addr)),
            Host::Ipv6(addr) => Target::Ip(IpAddr::V6(addr)),
            Host::Domain(domain) => {
                let normalized = normalize_host(domain);
                if normalized.is_empty() {
                    return Err(GuardError::InvalidUrl);
                }
                if self.is_denied_host(&normalized) {
                    return Err(GuardError::HostDenied(normalized));
                }
                Target::Domain(domain.to_owned())
            }
        };
        if let Target::Ip(addr) = target {
            self.check_addr(addr)?;
        }
        Ok((target, port))
    }

    fn is_denied_host(&self, host: &str) -> bool {
        if host == "localhost" || host.ends_with(".localhost") {
            return true;
        }
        DENIED_HOSTS
            .iter()
            .copied()
            .chain(self.extra_hosts.iter().map(String::as_str))
            .any(|denied| is_same_or_subdomain(host, denied))
    }
}

/// Marker bytes that exist only when the `test-support` code is compiled. CI's release-build
/// job scans the release artifacts for them and fails if they are found (ADR-011); the value is
/// deliberately not an identifier, because rustc records the *names* of cfg-stripped items in
/// crate metadata even when the code is compiled out.
#[cfg(feature = "test-support")]
#[used]
static TEST_SUPPORT_MARKER: [u8; 36] = *b"secure-web:test-support:compiled-in!";

/// The one socket a test guard lets through (ADR-011): only when the URL names `host` (a
/// reserved `*.test` name, resolved by a test resolver), on exactly `socket`'s port, and the name
/// resolved to exactly `socket`'s loopback address. IP-literal URLs are never exempt, so
/// `http://127.0.0.1:<port>/` stays blocked even for the fixture's own socket.
#[cfg(feature = "test-support")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct FixtureAllowance {
    host: String,
    socket: std::net::SocketAddr,
}

#[cfg(feature = "test-support")]
impl UrlGuard {
    /// **Test support only** (cargo feature `test-support`, never enabled by the shipped
    /// binary; ADR-011). Let `host` resolve to the loopback `socket` of an in-process fixture
    /// server. `host` must be a `*.test` name (RFC 6761) and `socket` a loopback address.
    pub fn with_test_fixture(
        mut self,
        host: &str,
        socket: std::net::SocketAddr,
    ) -> Result<Self, GuardConfigError> {
        let normalized = normalize_host(host);
        let valid_name = normalized.len() > ".test".len()
            && normalized.ends_with(".test")
            && !normalized.split('.').any(str::is_empty)
            && matches!(Host::parse(&normalized), Ok(Host::Domain(_)));
        if !valid_name || !socket.ip().is_loopback() || socket.port() == 0 {
            return Err(GuardConfigError::InvalidFixture);
        }
        self.fixture_allowance = Some(FixtureAllowance {
            host: normalized,
            socket,
        });
        Ok(self)
    }

    fn is_fixture_socket(&self, domain: &str, port: u16, addr: IpAddr) -> bool {
        self.fixture_allowance.as_ref().is_some_and(|allowed| {
            normalize_host(domain) == allowed.host
                && port == allowed.socket.port()
                && addr == allowed.socket.ip()
        })
    }
}

/// Resolution target: an IP literal (never resolved) or a domain name.
enum Target {
    Ip(IpAddr),
    Domain(String),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Ip(addr) => addr.fmt(f),
            Target::Domain(domain) => f.write_str(domain),
        }
    }
}

/// `host` equals `denied` or is a subdomain of it (both already normalized).
fn is_same_or_subdomain(host: &str, denied: &str) -> bool {
    host == denied
        || host
            .strip_suffix(denied)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subdomain_matching_requires_a_label_boundary() {
        assert!(is_same_or_subdomain("a.example", "a.example"));
        assert!(is_same_or_subdomain("x.a.example", "a.example"));
        assert!(!is_same_or_subdomain("xa.example", "a.example"));
        assert!(!is_same_or_subdomain("example", "a.example"));
    }

    #[test]
    fn metadata_host_subdomains_are_denied() {
        let guard = UrlGuard::new(&NetworkConfig::default(), Arc::new(SystemResolver)).unwrap();
        assert!(guard.is_denied_host("metadata.google.internal"));
        assert!(guard.is_denied_host("x.metadata.google.internal"));
        assert!(!guard.is_denied_host("google.internal"));
    }
}

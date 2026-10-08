//! Parsing of the operator-supplied network denylist (`security.network.extraBlockedCidrs` and
//! `extraBlockedHosts`, `docs/security-policy.md` §1, ADR-010).
//!
//! It lives here so that [`crate::config::Config::validate`] reports a bad entry together with
//! every other config error (exit 2) and the URL guard (`secure_web_security::ssrf::UrlGuard`)
//! parses the very same entries with the very same code.

use std::net::IpAddr;

use ipnet::IpNet;
use url::Host;

/// A denylist entry that cannot be used. Carries the offending entry (operator config, never
/// fetched content).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetworkRuleError {
    /// An `extraBlockedCidrs` entry is not a CIDR (`addr/prefix`).
    #[error("`{0}` is not a valid CIDR (addr/prefix)")]
    InvalidCidr(String),
    /// An `extraBlockedHosts` entry is empty.
    #[error("empty host name")]
    EmptyHost,
    /// An `extraBlockedHosts` entry is an IP address; IPs belong in `extraBlockedCidrs`.
    #[error(
        "`{0}` is an IP address; block it with an extraBlockedCidrs entry (addr/32 or addr/128) \
         instead"
    )]
    IpLiteralHost(String),
    /// An `extraBlockedHosts` entry is not a valid host name (port, path, userinfo, wildcard,
    /// forbidden characters, a leading dot, an empty label, or an IDNA error).
    #[error("`{0}` is not a valid host name")]
    InvalidHost(String),
}

/// Parse an `extraBlockedCidrs` entry (`addr/prefix`, v4 or v6), truncated to its network.
pub fn parse_blocked_cidr(text: &str) -> Result<IpNet, NetworkRuleError> {
    text.trim()
        .parse::<IpNet>()
        .map(|net| net.trunc())
        .map_err(|_| NetworkRuleError::InvalidCidr(text.to_owned()))
}

/// Lowercase, surrounding whitespace and trailing dots removed.
pub fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// An `extraBlockedHosts` entry normalized exactly like a URL host (WHATWG host parsing:
/// percent-decoding, IDNA/UTS #46 to ASCII, lower case), then trailing dots removed. IP
/// literals in any notation are refused: the denylist is only consulted for domain hosts, so an
/// IP entry would silently block nothing.
pub fn normalize_blocked_host(entry: &str) -> Result<String, NetworkRuleError> {
    let trimmed = entry.trim();
    let bare = trimmed.trim_end_matches('.');
    if bare.is_empty() {
        return Err(NetworkRuleError::EmptyHost);
    }
    let unbracketed = bare
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(bare);
    if unbracketed.parse::<IpAddr>().is_ok() {
        return Err(NetworkRuleError::IpLiteralHost(entry.to_owned()));
    }
    if trimmed.contains('*') {
        return Err(NetworkRuleError::InvalidHost(entry.to_owned()));
    }
    let domain = match Host::parse(trimmed) {
        Ok(Host::Domain(domain)) => domain,
        Ok(Host::Ipv4(_) | Host::Ipv6(_)) => {
            return Err(NetworkRuleError::IpLiteralHost(entry.to_owned()))
        }
        Err(_) => return Err(NetworkRuleError::InvalidHost(entry.to_owned())),
    };
    // The WHATWG ends-in-a-number check drops only one empty last label, so `127.1..` parses as a
    // domain while the URL host `127.1` is an IPv4 literal. Strip every trailing dot (including
    // ones that only appear after percent-decoding or full-width mapping) and classify again.
    let stripped = domain.trim_end_matches('.');
    if stripped.is_empty() {
        return Err(NetworkRuleError::EmptyHost);
    }
    match Host::parse(stripped) {
        Ok(Host::Domain(domain)) => {
            let normalized = normalize_host(&domain);
            if normalized.is_empty() {
                return Err(NetworkRuleError::EmptyHost);
            }
            // A leading dot or an empty label would compare against nothing and block nothing.
            if normalized.split('.').any(str::is_empty) {
                return Err(NetworkRuleError::InvalidHost(entry.to_owned()));
            }
            Ok(normalized)
        }
        Ok(Host::Ipv4(_) | Host::Ipv6(_)) => Err(NetworkRuleError::IpLiteralHost(entry.to_owned())),
        Err(_) => Err(NetworkRuleError::InvalidHost(entry.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidrs_need_a_prefix() {
        assert!(parse_blocked_cidr("203.0.113.0/24").is_ok());
        assert!(parse_blocked_cidr(" 2001:db8::/32 ").is_ok());
        assert_eq!(
            parse_blocked_cidr("203.0.113.7/24").unwrap().to_string(),
            "203.0.113.0/24"
        );
        for bad in ["203.0.113.0", "203.0.113.0/33", "", "example.com/8"] {
            assert!(parse_blocked_cidr(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn hosts_are_normalized_like_url_hosts() {
        assert_eq!(
            normalize_blocked_host("Example.COM.").unwrap(),
            "example.com"
        );
        assert_eq!(
            normalize_blocked_host("bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
        assert_eq!(normalize_blocked_host(""), Err(NetworkRuleError::EmptyHost));
        assert_eq!(
            normalize_blocked_host("..."),
            Err(NetworkRuleError::EmptyHost)
        );
        for ip in ["10.0.0.1", "[::1]", "0x7f000001", "127.1.."] {
            assert!(
                matches!(
                    normalize_blocked_host(ip),
                    Err(NetworkRuleError::IpLiteralHost(_))
                ),
                "{ip}"
            );
        }
        for bad in [
            "*.example.com",
            ".example.com",
            "a..b",
            "example.com:80",
            "a/b",
        ] {
            assert!(
                matches!(
                    normalize_blocked_host(bad),
                    Err(NetworkRuleError::InvalidHost(_))
                ),
                "{bad}"
            );
        }
    }
}

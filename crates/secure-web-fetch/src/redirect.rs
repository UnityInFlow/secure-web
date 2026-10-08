//! Manual redirect handling (threat T6). The HTTP client never follows a redirect; every
//! `Location` goes back through [`UrlGuard`] from its **raw text** (ADR-010 §7, ADR-011).
//!
//! A redirect is resolved the way a client would resolve it (`base.join(location)`, WHATWG), and
//! the destination is validated as follows:
//!
//! - **same authority as the current URL** (path-relative `Location`, or an absolute one naming
//!   the same scheme/host/port): the authority is the one already validated from raw text, so
//!   the joined URL's canonical serialization is validated (DNS re-resolved, every address
//!   re-checked).
//! - **new authority**: the authority can only have come from the `Location` text itself, so
//!   that raw text (or `scheme:` + it, for a scheme-relative `//host/...`) goes through
//!   [`UrlGuard::parse_and_check_static`], and the result must be exactly the joined URL.
//!   Any disagreement between the raw-text reading and the joined reading fails closed.

use secure_web_security::ssrf::{GuardError, UrlGuard, ValidatedTarget};
use url::Url;

use crate::error::RedirectViolation;

/// HTTP statuses treated as redirects (all others, including `300`/`304`, are final).
pub(crate) fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// `https` → `http`.
pub(crate) fn is_downgrade(from: &Url, to: &Url) -> bool {
    from.scheme() == "https" && to.scheme() == "http"
}

fn same_authority(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host() == b.host()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Validate the `Location` of a redirect from `base`.
pub(crate) async fn next_target(
    guard: &UrlGuard,
    base: &Url,
    raw_location: &str,
    allow_downgrade: bool,
) -> Result<ValidatedTarget, RedirectViolation> {
    let joined = base
        .join(raw_location)
        .map_err(|_| RedirectViolation::InvalidLocation)?;
    if is_downgrade(base, &joined) && !allow_downgrade {
        return Err(RedirectViolation::Downgrade);
    }
    if same_authority(base, &joined) {
        return guard
            .validate(joined.as_str())
            .await
            .map_err(RedirectViolation::Guard);
    }
    let checked = match guard.parse_and_check_static(raw_location) {
        Ok(checked) => checked,
        // Relative text (e.g. scheme-relative `//host/x`): read it against the base scheme,
        // still from the raw authority text.
        Err(GuardError::InvalidUrl) if Url::parse(raw_location).is_err() => guard
            .parse_and_check_static(&format!("{}:{raw_location}", base.scheme()))
            .map_err(RedirectViolation::Guard)?,
        Err(err) => return Err(RedirectViolation::Guard(err)),
    };
    if checked.as_url() != &joined {
        return Err(RedirectViolation::InconsistentLocation);
    }
    guard
        .resolve_and_check(&checked)
        .await
        .map_err(RedirectViolation::Guard)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;

    use secure_web_core::config::NetworkConfig;
    use secure_web_security::ssrf::{ResolveError, ResolveFuture, Resolver};

    use super::*;

    /// `*.example` resolves to a public address; nothing else resolves.
    struct PublicResolver;

    impl Resolver for PublicResolver {
        fn resolve<'a>(&'a self, host: &'a str, _port: u16) -> ResolveFuture<'a> {
            let answer = if host.ends_with(".example") {
                Ok(vec![IpAddr::from([93, 184, 216, 34])])
            } else {
                Err(ResolveError::new("no such host"))
            };
            Box::pin(async move { answer })
        }
    }

    fn guard() -> UrlGuard {
        UrlGuard::new(&NetworkConfig::default(), Arc::new(PublicResolver)).unwrap()
    }

    async fn follow(
        base: &str,
        location: &str,
        allow_downgrade: bool,
    ) -> Result<Url, RedirectViolation> {
        let base = Url::parse(base).unwrap();
        next_target(&guard(), &base, location, allow_downgrade)
            .await
            .map(|target| target.url().clone())
    }

    #[tokio::test]
    async fn https_to_http_is_refused_unless_allowed() {
        assert_eq!(
            follow("https://a.example/", "http://a.example/x", false).await,
            Err(RedirectViolation::Downgrade)
        );
        assert_eq!(
            follow("https://a.example/", "http://b.example/x", false).await,
            Err(RedirectViolation::Downgrade)
        );
        assert_eq!(
            follow("https://a.example/", "http://a.example/x", true)
                .await
                .unwrap()
                .as_str(),
            "http://a.example/x"
        );
        assert!(follow("http://a.example/", "https://a.example/", false)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn relative_locations_keep_the_validated_authority() {
        let next = follow("http://a.example/dir/page", "../other?q=1", false)
            .await
            .unwrap();
        assert_eq!(next.as_str(), "http://a.example/other?q=1");
        let next = follow("http://a.example/", "//b.example/x", false)
            .await
            .unwrap();
        assert_eq!(next.as_str(), "http://b.example/x");
    }

    #[tokio::test]
    async fn new_authorities_are_checked_from_the_raw_text() {
        // Non-canonical spellings of a public address are refused even though `Url::parse`
        // would normalize them to the canonical form.
        for location in [
            "http://1572395042/",
            "//1572395042/",
            "/\\1572395042/",
            "http://0x5d.0xb8.0xd8.0x22/",
        ] {
            assert!(
                matches!(
                    follow("http://a.example/", location, false).await,
                    Err(RedirectViolation::Guard(GuardError::Ssrf { .. }))
                ),
                "{location}"
            );
        }
        assert_eq!(
            follow("http://a.example/", "http://@b.example/", false).await,
            Err(RedirectViolation::Guard(GuardError::Userinfo))
        );
        assert_eq!(
            follow("http://a.example/", "//@b.example/", false).await,
            Err(RedirectViolation::Guard(GuardError::Userinfo))
        );
    }

    #[tokio::test]
    async fn private_and_invalid_locations_are_refused() {
        assert!(matches!(
            follow("http://a.example/", "http://10.0.0.1/", false).await,
            Err(RedirectViolation::Guard(GuardError::Ssrf { .. }))
        ));
        assert!(matches!(
            follow("http://a.example/", "file:///etc/passwd", false).await,
            Err(RedirectViolation::Guard(GuardError::UnsupportedScheme(_)))
        ));
        assert!(matches!(
            follow("http://a.example/", "http://[::1/", false).await,
            Err(RedirectViolation::InvalidLocation | RedirectViolation::Guard(_))
        ));
        assert_eq!(
            follow("http://a.example/", "http://nowhere.invalid/", false).await,
            Err(RedirectViolation::Guard(GuardError::DnsFailed))
        );
    }

    #[test]
    fn only_real_redirect_statuses_are_followed() {
        for status in [301, 302, 303, 307, 308] {
            assert!(is_redirect_status(status));
        }
        for status in [200, 300, 304, 305, 306, 404] {
            assert!(!is_redirect_status(status));
        }
    }

    #[test]
    fn downgrade_is_https_to_http_only() {
        let https = Url::parse("https://a.example/").unwrap();
        let http = Url::parse("http://a.example/").unwrap();
        assert!(is_downgrade(&https, &http));
        assert!(!is_downgrade(&http, &https));
        assert!(!is_downgrade(&https, &https));
        assert!(!is_downgrade(&http, &http));
    }
}

//! T5 — hostname denylist and DNS-resolved address validation.
//!
//! DNS goes through the injectable stub in `tests/support/resolver.rs`; nothing here touches the
//! network.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../support/resolver.rs"]
mod resolver;

use std::net::IpAddr;

use secure_web_core::config::NetworkConfig;
use secure_web_core::error::ErrorCode;
use secure_web_security::ssrf::{GuardConfigError, GuardError, UrlGuard};
use url::Url;

use resolver::{corpus_urls, guard, guard_with, StubResolver};

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[tokio::test]
async fn every_localhost_corpus_url_is_rejected_without_a_dns_lookup() {
    let resolver = StubResolver::new(&[("localhost", &["127.0.0.1"])]);
    let guard = guard(&resolver);
    for url in corpus_urls("localhost/urls.txt") {
        let err = guard.validate(&url).await.unwrap_err();
        assert!(
            matches!(err, GuardError::Ssrf { .. } | GuardError::HostDenied(_)),
            "{url}: {err:?}"
        );
        assert_eq!(err.code(), ErrorCode::SsrfBlocked, "{url}");
    }
    assert_eq!(resolver.lookups(), 0);
}

#[tokio::test]
async fn localhost_names_are_denied_by_name() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    for (url, host) in [
        ("http://localhost/", "localhost"),
        ("http://LocalHost:8080/", "localhost"),
        ("http://localhost./", "localhost"),
        ("http://foo.localhost/", "foo.localhost"),
        ("http://a.b.localhost./x", "a.b.localhost"),
    ] {
        assert_eq!(
            guard.validate(url).await,
            Err(GuardError::HostDenied(host.to_owned())),
            "{url}"
        );
    }
    // Not a subdomain of localhost: resolved normally (and here, unknown).
    assert_eq!(
        guard.validate("http://notlocalhost/").await,
        Err(GuardError::DnsFailed)
    );
}

#[tokio::test]
async fn metadata_hostnames_are_denied_even_if_they_resolve_publicly() {
    let resolver = StubResolver::new(&[("metadata.google.internal", &["93.184.216.34"])]);
    let guard = guard(&resolver);
    for url in [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://METADATA.GOOGLE.INTERNAL./",
        "https://metadata.google.internal:443/",
    ] {
        assert_eq!(
            guard.validate(url).await,
            Err(GuardError::HostDenied(
                "metadata.google.internal".to_owned()
            )),
            "{url}"
        );
    }
    assert_eq!(resolver.lookups(), 0);
}

#[tokio::test]
async fn extra_blocked_hosts_block_the_host_and_its_subdomains() {
    let resolver = StubResolver::new(&[
        ("internal.example", &["93.184.216.34"]),
        ("api.internal.example", &["93.184.216.34"]),
        ("notinternal.example", &["93.184.216.34"]),
    ]);
    let cfg = NetworkConfig {
        extra_blocked_hosts: vec!["Internal.Example.".to_owned()],
        ..NetworkConfig::default()
    };
    let guard = guard_with(cfg, &resolver);
    assert_eq!(
        guard.validate("http://internal.example/").await,
        Err(GuardError::HostDenied("internal.example".to_owned()))
    );
    assert_eq!(
        guard.validate("https://API.internal.example/v1").await,
        Err(GuardError::HostDenied("api.internal.example".to_owned()))
    );
    assert!(guard.validate("http://notinternal.example/").await.is_ok());
}

fn guard_blocking(entries: &[&str], resolver: &std::sync::Arc<StubResolver>) -> UrlGuard {
    let cfg = NetworkConfig {
        extra_blocked_hosts: entries.iter().map(|e| (*e).to_owned()).collect(),
        ..NetworkConfig::default()
    };
    UrlGuard::new(&cfg, resolver.clone()).unwrap()
}

#[tokio::test]
async fn extra_blocked_hosts_are_idna_normalized_like_url_hosts() {
    let resolver = StubResolver::new(&[
        ("xn--bcher-kva.example", &["93.184.216.34"]),
        ("api.xn--bcher-kva.example", &["93.184.216.34"]),
    ]);
    // Unicode, upper case + trailing dot, full-width letters and dot, percent-encoded, punycode.
    for entry in [
        "bücher.example",
        "BÜCHER.Example.",
        "\u{ff42}ücher\u{ff0e}example",
        "b%C3%BCcher.example",
        "xn--bcher-kva.example",
    ] {
        let guard = guard_blocking(&[entry], &resolver);
        for url in [
            "http://bücher.example/",
            "http://BÜCHER.example./",
            "http://xn--bcher-kva.example/",
            "https://api.bücher.example/v1",
        ] {
            assert!(
                matches!(guard.validate(url).await, Err(GuardError::HostDenied(_))),
                "entry {entry:?} must block {url}"
            );
        }
    }
    assert_eq!(resolver.lookups(), 0);
}

#[test]
fn ip_literals_in_extra_blocked_hosts_are_a_config_error() {
    let resolver = StubResolver::new(&[]);
    for entry in [
        "93.184.216.34",
        "0x5db8d822",
        "1572395042",
        "93.184.216.34.",
        "::1",
        "[::1]",
        "::ffff:93.184.216.34",
        "[fd00:ec2::254]",
        // Several trailing dots: the WHATWG ends-in-a-number check drops only one empty last
        // label, so these parse as domains unless every trailing dot is stripped first.
        "1572395042..",
        "0x5db8d822..",
        "0X5DB8D822...",
        "0135.0270.0330.042..",
        "93.11010082..",
        "127.1..",
        "0x7f.1..",
        // Trailing dots that only appear after full-width mapping or percent-decoding.
        "\u{ff11}\u{ff12}\u{ff17}\u{ff0e}\u{ff11}\u{ff0e}\u{ff0e}",
        "127%2E0%2E0%2E1%2E%2E",
        "127.0.0.1\u{3002}\u{3002}",
        "[::1]..",
    ] {
        let cfg = NetworkConfig {
            extra_blocked_hosts: vec![entry.to_owned()],
            ..NetworkConfig::default()
        };
        let err = UrlGuard::new(&cfg, resolver.clone()).unwrap_err();
        assert!(
            matches!(err, GuardConfigError::IpLiteralHost(_)),
            "{entry}: {err:?}"
        );
        assert!(
            err.to_string().contains("extraBlockedCidrs"),
            "{entry}: {err}"
        );
    }
}

#[test]
fn malformed_extra_blocked_hosts_are_a_config_error() {
    let resolver = StubResolver::new(&[]);
    // A leading dot or an empty label would compare against nothing and block nothing.
    for entry in [
        ".example.com",
        "example..com",
        "exa mple.com",
        "example.com:8080",
        "*.example.com",
        "a/b",
        "user@example.com",
    ] {
        let cfg = NetworkConfig {
            extra_blocked_hosts: vec![entry.to_owned()],
            ..NetworkConfig::default()
        };
        let err = UrlGuard::new(&cfg, resolver.clone()).unwrap_err();
        assert!(
            matches!(err, GuardConfigError::InvalidHost(_)),
            "{entry}: {err:?}"
        );
    }
    for entry in ["", "  ", "."] {
        let cfg = NetworkConfig {
            extra_blocked_hosts: vec![entry.to_owned()],
            ..NetworkConfig::default()
        };
        assert_eq!(
            UrlGuard::new(&cfg, resolver.clone()).unwrap_err(),
            GuardConfigError::EmptyHost,
            "{entry:?}"
        );
    }
}

#[tokio::test]
async fn a_host_resolving_to_a_private_address_is_rejected() {
    let resolver = StubResolver::new(&[
        ("intranet.test", &["192.168.1.10"]),
        ("loop.test", &["127.0.0.1"]),
        ("meta.test", &["169.254.169.254"]),
        ("ula.test", &["fd00::1"]),
        ("mapped.test", &["::ffff:127.0.0.1"]),
        ("nat64.test", &["64:ff9b::a9fe:a9fe"]),
    ]);
    let guard = guard(&resolver);
    for (url, addr, rule) in [
        ("http://intranet.test/", "192.168.1.10", "192.168.0.0/16"),
        ("http://loop.test/", "127.0.0.1", "127.0.0.0/8"),
        (
            "http://meta.test/latest/",
            "169.254.169.254",
            "169.254.0.0/16",
        ),
        ("http://ula.test/", "fd00::1", "fc00::/7"),
        ("http://mapped.test/", "::ffff:127.0.0.1", "127.0.0.0/8"),
        ("http://nat64.test/", "64:ff9b::a9fe:a9fe", "169.254.0.0/16"),
    ] {
        assert_eq!(
            guard.validate(url).await,
            Err(GuardError::Ssrf {
                addr: ip(addr),
                rule
            }),
            "{url}"
        );
    }
}

#[tokio::test]
async fn mixed_public_and_private_resolution_is_rejected() {
    let resolver = StubResolver::new(&[
        ("rebind-a.test", &["93.184.216.34", "10.0.0.5"]),
        ("rebind-b.test", &["10.0.0.5", "93.184.216.34"]),
        ("rebind-v6.test", &["2606:2800:220:1::1", "::1"]),
        (
            "rebind-mixed-family.test",
            &["2606:2800:220:1::1", "93.184.216.34", "169.254.169.254"],
        ),
    ]);
    let guard = guard(&resolver);
    for (url, addr) in [
        ("http://rebind-a.test/", "10.0.0.5"),
        ("http://rebind-b.test/", "10.0.0.5"),
        ("http://rebind-v6.test/", "::1"),
        ("http://rebind-mixed-family.test/", "169.254.169.254"),
    ] {
        match guard.validate(url).await {
            Err(GuardError::Ssrf { addr: got, .. }) => assert_eq!(got, ip(addr), "{url}"),
            other => panic!("{url}: expected Ssrf, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn dns_failure_and_empty_answers_are_dns_failed() {
    let resolver = StubResolver::new(&[("empty.test", &[])]);
    let guard = guard(&resolver);
    let unknown = guard.validate("https://nxdomain.test/").await;
    assert_eq!(unknown, Err(GuardError::DnsFailed));
    assert_eq!(GuardError::DnsFailed.code(), ErrorCode::DnsFailed);
    assert_eq!(
        guard.validate("https://empty.test/").await,
        Err(GuardError::DnsFailed)
    );
}

#[tokio::test]
async fn a_public_host_yields_a_validated_target() {
    let resolver = StubResolver::new(&[("example.com", &["93.184.216.34"])]);
    let guard = guard(&resolver);
    let target = guard.validate("https://example.com").await.unwrap();
    assert_eq!(target.url().as_str(), "https://example.com/");
    assert_eq!(target.host(), "example.com");
    assert_eq!(target.port(), 443);
    assert_eq!(target.addrs(), &[ip("93.184.216.34")]);
    assert_eq!(resolver.lookups(), 1);
}

#[tokio::test]
async fn a_public_ipv6_host_yields_a_validated_target() {
    let resolver = StubResolver::new(&[("v6.example", &["2606:2800:220:1:248:1893:25c8:1946"])]);
    let guard = guard(&resolver);
    let target = guard.validate("http://v6.example/page?q=1").await.unwrap();
    assert_eq!(target.port(), 80);
    assert_eq!(target.addrs(), &[ip("2606:2800:220:1:248:1893:25c8:1946")]);
}

#[tokio::test]
async fn a_non_default_port_is_kept() {
    let resolver = StubResolver::new(&[("example.com", &["93.184.216.34", "93.184.216.34"])]);
    let guard = guard(&resolver);
    let target = guard.validate("https://example.com:8443/x").await.unwrap();
    assert_eq!(target.port(), 8443);
    // Duplicate answers are collapsed.
    assert_eq!(target.addrs(), &[ip("93.184.216.34")]);
}

#[tokio::test]
async fn public_ip_literals_are_accepted_without_a_dns_lookup() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    let v4 = guard.validate("http://93.184.216.34:8080/").await.unwrap();
    assert_eq!(v4.host(), "93.184.216.34");
    assert_eq!(v4.addrs(), &[ip("93.184.216.34")]);
    let v6 = guard
        .validate("https://[2606:4700:4700::1111]/dns-query")
        .await
        .unwrap();
    assert_eq!(v6.host(), "2606:4700:4700::1111");
    assert_eq!(v6.port(), 443);
    assert_eq!(v6.addrs(), &[ip("2606:4700:4700::1111")]);
    assert_eq!(resolver.lookups(), 0);
}

#[tokio::test]
async fn inputs_normalized_away_by_the_parser_never_reach_resolve_and_check() {
    // `Url::parse` erases these (`http://93.184.216.34/`, `http://example.com/`), so no check on
    // a parsed `Url` can see them. `resolve_and_check` therefore only accepts a `CheckedUrl`,
    // which only `parse_and_check_static` produces (compile-fail doc test on `CheckedUrl`).
    let resolver = StubResolver::new(&[("example.com", &["93.184.216.34"])]);
    let guard = guard(&resolver);
    for (raw, expected) in [
        (
            "http://1572395042/",
            GuardError::Ssrf {
                addr: ip("93.184.216.34"),
                rule: "ambiguous-ipv4-literal",
            },
        ),
        ("http://@example.com/", GuardError::Userinfo),
        ("http://:@example.com/", GuardError::Userinfo),
    ] {
        assert_eq!(Url::parse(raw).unwrap().username(), "", "{raw}");
        assert_eq!(
            guard.parse_and_check_static(raw),
            Err(expected.clone()),
            "{raw}"
        );
        assert_eq!(guard.validate(raw).await, Err(expected), "{raw}");
    }
    assert_eq!(resolver.lookups(), 0);
}

#[tokio::test]
async fn resolve_and_check_accepts_a_checked_url_and_resolves_it() {
    let resolver = StubResolver::new(&[("example.com", &["93.184.216.34"])]);
    let guard = guard(&resolver);
    let checked = guard
        .parse_and_check_static("https://example.com/a")
        .unwrap();
    let target = guard.resolve_and_check(&checked).await.unwrap();
    assert_eq!(target.url(), checked.as_url());
    assert_eq!(target.addrs(), &[ip("93.184.216.34")]);
    let rendered = format!("{checked:?} {checked:#?}");
    assert!(!rendered.contains("/a"), "CheckedUrl Debug leaks the path");
}

/// Canary placed in URL-controlled text; it must never appear in a guard type's `Debug`.
/// (`tests/support/canaries.rs` does not exist yet; PR-05 introduces the shared canaries.)
const URL_CANARY: &str = "SWCANARYurl7f3a";

#[tokio::test]
async fn validated_target_debug_omits_userinfo_path_query_and_fragment() {
    let resolver = StubResolver::new(&[("example.com", &["93.184.216.34"])]);
    let guard = guard(&resolver);
    let raw = format!("https://example.com/{URL_CANARY}/p?q={URL_CANARY}#{URL_CANARY}");
    let target = guard.validate(&raw).await.unwrap();
    for rendered in [format!("{target:?}"), format!("{target:#?}")] {
        assert!(!rendered.contains(URL_CANARY), "Debug leaks URL text");
        assert!(rendered.contains("example.com"), "host missing");
        assert!(rendered.contains("443"), "port missing");
        assert!(rendered.contains("93.184.216.34"), "addrs missing");
    }
}

#[tokio::test]
async fn guard_errors_never_carry_path_query_or_fragment() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    for raw in [
        format!("http://127.0.0.1/{URL_CANARY}?{URL_CANARY}#{URL_CANARY}"),
        format!("http://localhost/{URL_CANARY}?{URL_CANARY}#{URL_CANARY}"),
        format!("http://{URL_CANARY}:{URL_CANARY}@example.com/"),
        format!("ftp://example.com/{URL_CANARY}?{URL_CANARY}"),
        format!("http://unknown.test/{URL_CANARY}"),
        format!("http://1572395042/{URL_CANARY}"),
    ] {
        let err = guard.validate(&raw).await.unwrap_err();
        for rendered in [format!("{err:?}"), format!("{err:#?}"), err.to_string()] {
            assert!(!rendered.contains(URL_CANARY), "error leaks URL text");
        }
    }
}

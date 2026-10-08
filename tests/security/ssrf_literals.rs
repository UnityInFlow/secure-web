//! T5 — URL parsing, schemes, userinfo and IP-literal normalization.
//!
//! Obfuscated IPv4 notations (decimal, hex, octal, short forms, percent-encoding) are parsed as
//! IPs and range-checked; if one still turns out to be public it is rejected anyway as an
//! ambiguous literal — no legitimate caller needs `http://1572395042/`.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../support/resolver.rs"]
mod resolver;

use std::net::IpAddr;

use secure_web_core::error::ErrorCode;
use secure_web_security::ssrf::{GuardError, AMBIGUOUS_IPV4_LITERAL};

use resolver::{corpus_urls, guard, StubResolver};

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[tokio::test]
async fn every_network_corpus_url_is_rejected_statically() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    let mut urls = corpus_urls("private-ip/urls.txt");
    urls.extend(corpus_urls("localhost/urls.txt"));
    for url in urls {
        let err = guard.parse_and_check_static(&url).unwrap_err();
        assert_eq!(err.code(), ErrorCode::SsrfBlocked, "{url}: {err:?}");
        assert!(guard.validate(&url).await.is_err(), "{url}");
    }
    assert_eq!(resolver.lookups(), 0);
}

#[test]
fn obfuscated_loopback_literals_are_parsed_and_range_checked() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    for url in [
        "http://127.0.0.1/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0X7F000001/",
        "http://017700000001/",
        "http://0177.0.0.1/",
        "http://0x7f.0.0.1/",
        "http://127.1/",
        "http://127.0.1/",
        "http://127.0.0.1./",
        "http://%31%32%37.0.0.1/",
        "http://\u{ff11}\u{ff12}\u{ff17}.\u{ff10}.\u{ff10}.\u{ff11}/",
    ] {
        assert_eq!(
            guard.parse_and_check_static(url),
            Err(GuardError::Ssrf {
                addr: ip("127.0.0.1"),
                rule: "127.0.0.0/8"
            }),
            "{url}"
        );
    }
}

#[test]
fn ipv6_literals_embedding_ipv4_are_unwrapped() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    for (url, addr, rule) in [
        (
            "http://[::ffff:127.0.0.1]/",
            "::ffff:127.0.0.1",
            "127.0.0.0/8",
        ),
        ("http://[::ffff:7f00:1]/", "::ffff:127.0.0.1", "127.0.0.0/8"),
        (
            "http://[0:0:0:0:0:ffff:a9fe:a9fe]/",
            "::ffff:169.254.169.254",
            "169.254.0.0/16",
        ),
        ("http://[::127.0.0.1]/", "::127.0.0.1", "127.0.0.0/8"),
        (
            "http://[64:ff9b::7f00:1]/",
            "64:ff9b::7f00:1",
            "127.0.0.0/8",
        ),
        (
            "http://[64:ff9b::10.0.0.1]/",
            "64:ff9b::a00:1",
            "10.0.0.0/8",
        ),
        ("http://[::1]/", "::1", "::1/128"),
        ("http://[::]/", "::", "::/128"),
        ("http://[fd00:ec2::254]/", "fd00:ec2::254", "fc00::/7"),
    ] {
        assert_eq!(
            guard.parse_and_check_static(url),
            Err(GuardError::Ssrf {
                addr: ip(addr),
                rule
            }),
            "{url}"
        );
    }
}

#[test]
fn obfuscated_public_ipv4_literals_are_rejected_as_ambiguous() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    for url in [
        "http://1572395042/",
        "http://0x5db8d822/",
        "http://0135.0270.0330.042/",
        "http://0x5d.0xb8.0xd8.0x22/",
        "http://93.12113954/",
        "http://93.184.216.34./",
        "http://%39%33.184.216.34/",
    ] {
        assert_eq!(
            guard.parse_and_check_static(url),
            Err(GuardError::Ssrf {
                addr: ip("93.184.216.34"),
                rule: AMBIGUOUS_IPV4_LITERAL
            }),
            "{url}"
        );
    }
    // The canonical spelling of the same address is fine.
    assert!(guard
        .parse_and_check_static("http://93.184.216.34/")
        .is_ok());
    assert!(guard
        .parse_and_check_static("http://93.184.216.34:8080/a")
        .is_ok());
}

#[test]
fn leading_zero_octets_are_rejected() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    // `093` is not valid octal: the URL does not parse at all.
    assert_eq!(
        guard.parse_and_check_static("http://093.184.216.34/"),
        Err(GuardError::InvalidUrl)
    );
    // `010.0.0.1` is octal 8.0.0.1 — public, but ambiguous.
    assert_eq!(
        guard.parse_and_check_static("http://010.0.0.1/"),
        Err(GuardError::Ssrf {
            addr: ip("8.0.0.1"),
            rule: AMBIGUOUS_IPV4_LITERAL
        })
    );
}

#[test]
fn userinfo_is_rejected() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    for url in [
        "http://user:pass@example.com/",
        "http://user@example.com/",
        "http://:pass@example.com/",
        "http://@example.com/",
        "http://:@example.com/",
        "https://example.com@127.0.0.1/",
        "http://example.com%40evil.test@93.184.216.34/",
    ] {
        let err = guard.parse_and_check_static(url).unwrap_err();
        assert_eq!(err, GuardError::Userinfo, "{url}");
        assert_eq!(err.code(), ErrorCode::InvalidUrl);
    }
}

#[test]
fn unsupported_schemes_are_rejected() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    for (url, scheme) in [
        ("file:///etc/passwd", "file"),
        ("FILE:///etc/passwd", "file"),
        ("file://localhost/etc/passwd", "file"),
        ("data:text/html,<script>alert(1)</script>", "data"),
        ("DATA:text/plain;base64,SGVsbG8=", "data"),
        ("javascript:alert(1)", "javascript"),
        ("JavaScript:alert(document.cookie)", "javascript"),
        ("ftp://example.com/file", "ftp"),
        ("gopher://127.0.0.1:6379/_INFO", "gopher"),
        ("ws://example.com/socket", "ws"),
        ("wss://example.com/socket", "wss"),
        ("unix:/var/run/docker.sock", "unix"),
        ("dict://127.0.0.1:11211/stat", "dict"),
        ("blob:https://example.com/uuid", "blob"),
    ] {
        let err = guard.parse_and_check_static(url).unwrap_err();
        assert_eq!(
            err,
            GuardError::UnsupportedScheme(scheme.to_owned()),
            "{url}"
        );
        assert_eq!(err.code(), ErrorCode::UnsupportedScheme);
    }
}

#[tokio::test]
async fn uppercase_http_schemes_are_accepted() {
    let resolver = StubResolver::new(&[("example.com", &["93.184.216.34"])]);
    let guard = guard(&resolver);
    for url in ["HTTP://EXAMPLE.COM/", "HtTpS://Example.Com/path"] {
        let target = guard.validate(url).await.unwrap();
        assert_eq!(target.host(), "example.com", "{url}");
    }
}

#[test]
fn malformed_urls_are_invalid() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    for url in [
        "",
        "   ",
        "not a url",
        "example.com",
        "//example.com/",
        "http://",
        "https://",
        "http://exa mple.com/",
        "http://[::1/",
        "http://1.2.3.4.5/",
        "http://256.0.0.1/",
        "http://example.com:0/",
        "https://example.com:0",
        "http://example.com:65536/",
    ] {
        let err = guard.parse_and_check_static(url).unwrap_err();
        assert_eq!(err, GuardError::InvalidUrl, "{url:?}");
        assert_eq!(err.code(), ErrorCode::InvalidUrl);
    }
}

#[test]
fn whitespace_and_slash_tricks_do_not_hide_a_loopback_literal() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    for url in [
        " http://127.0.0.1/",
        "http://127.0.0.1/ ",
        "\u{0}http://127.0.0.1/",
        "http://127.0.0.1\t/",
        "http://127.0.\n0.1/",
        "ht\ttp://127.0.0.1/",
        "http:\\\\127.0.0.1\\",
        "http:/127.0.0.1/",
        "http:127.0.0.1/",
        "http:///127.0.0.1/",
        "http://127.0.0.1#@example.com/",
        "http://127.0.0.1?@example.com/",
        "http://127.0.0.1:80/",
    ] {
        let err = guard.parse_and_check_static(url).unwrap_err();
        assert_eq!(err.code(), ErrorCode::SsrfBlocked, "{url:?}: {err:?}");
    }
}

#[test]
fn a_clean_public_url_passes_the_static_check() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    let url = guard
        .parse_and_check_static("https://example.com/docs?page=1#intro")
        .unwrap();
    assert_eq!(
        url.as_url().as_str(),
        "https://example.com/docs?page=1#intro"
    );
    assert_eq!(resolver.lookups(), 0);
}

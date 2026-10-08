//! T5 — every blocked range in `docs/security-policy.md` §1, tested at its boundaries.
//!
//! For each CIDR: the first and last address are blocked **by that rule**, and the address one
//! before / one after is not (it is either allowed or caught by a different, named rule). The
//! expected table is written out by hand here on purpose — it must not be derived from the
//! implementation's own table.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../support/resolver.rs"]
mod resolver;

use std::net::IpAddr;

use secure_web_core::config::NetworkConfig;
use secure_web_security::ssrf::{GuardError, UrlGuard};

use resolver::{guard, guard_with, StubResolver};

/// What the guard must say about an address just outside a range.
#[derive(Debug, Clone, Copy)]
enum Outside {
    /// No range applies: the address is allowed.
    Allowed,
    /// Blocked, but by this other rule.
    Rule(&'static str),
    /// Anything except "blocked by the rule under test".
    NotThisRule,
}

struct Range {
    cidr: &'static str,
    first: &'static str,
    last: &'static str,
    before: Option<(&'static str, Outside)>,
    after: Option<(&'static str, Outside)>,
}

const V4: &[Range] = &[
    Range {
        cidr: "0.0.0.0/8",
        first: "0.0.0.0",
        last: "0.255.255.255",
        before: None,
        after: Some(("1.0.0.0", Outside::Allowed)),
    },
    Range {
        cidr: "10.0.0.0/8",
        first: "10.0.0.0",
        last: "10.255.255.255",
        before: Some(("9.255.255.255", Outside::Allowed)),
        after: Some(("11.0.0.0", Outside::Allowed)),
    },
    Range {
        cidr: "100.64.0.0/10",
        first: "100.64.0.0",
        last: "100.127.255.255",
        before: Some(("100.63.255.255", Outside::Allowed)),
        after: Some(("100.128.0.0", Outside::Allowed)),
    },
    Range {
        cidr: "127.0.0.0/8",
        first: "127.0.0.0",
        last: "127.255.255.255",
        before: Some(("126.255.255.255", Outside::Allowed)),
        after: Some(("128.0.0.0", Outside::Allowed)),
    },
    Range {
        cidr: "169.254.0.0/16",
        first: "169.254.0.0",
        last: "169.254.255.255",
        before: Some(("169.253.255.255", Outside::Allowed)),
        after: Some(("169.255.0.0", Outside::Allowed)),
    },
    Range {
        cidr: "172.16.0.0/12",
        first: "172.16.0.0",
        last: "172.31.255.255",
        before: Some(("172.15.255.255", Outside::Allowed)),
        after: Some(("172.32.0.0", Outside::Allowed)),
    },
    Range {
        cidr: "192.0.0.0/24",
        first: "192.0.0.0",
        last: "192.0.0.255",
        before: Some(("191.255.255.255", Outside::Allowed)),
        after: Some(("192.0.1.0", Outside::Allowed)),
    },
    Range {
        cidr: "192.168.0.0/16",
        first: "192.168.0.0",
        last: "192.168.255.255",
        before: Some(("192.167.255.255", Outside::Allowed)),
        after: Some(("192.169.0.0", Outside::Allowed)),
    },
    Range {
        cidr: "198.18.0.0/15",
        first: "198.18.0.0",
        last: "198.19.255.255",
        before: Some(("198.17.255.255", Outside::Allowed)),
        after: Some(("198.20.0.0", Outside::Allowed)),
    },
    Range {
        cidr: "224.0.0.0/4",
        first: "224.0.0.0",
        last: "239.255.255.255",
        before: Some(("223.255.255.255", Outside::Allowed)),
        after: Some(("240.0.0.0", Outside::Rule("240.0.0.0/4"))),
    },
    Range {
        cidr: "240.0.0.0/4",
        first: "240.0.0.0",
        // 255.255.255.255 is reported under its own, more specific /32 rule.
        last: "255.255.255.254",
        before: Some(("239.255.255.255", Outside::Rule("224.0.0.0/4"))),
        after: Some(("255.255.255.255", Outside::Rule("255.255.255.255/32"))),
    },
    Range {
        cidr: "255.255.255.255/32",
        first: "255.255.255.255",
        last: "255.255.255.255",
        before: Some(("255.255.255.254", Outside::Rule("240.0.0.0/4"))),
        after: None,
    },
];

const V6: &[Range] = &[
    Range {
        cidr: "::/128",
        first: "::",
        last: "::",
        before: None,
        after: Some(("::1", Outside::Rule("::1/128"))),
    },
    Range {
        cidr: "::1/128",
        first: "::1",
        last: "::1",
        before: Some(("::", Outside::Rule("::/128"))),
        // ::2 is IPv4-compatible (::0.0.0.2) and is unwrapped into 0.0.0.0/8.
        after: Some(("::2", Outside::Rule("0.0.0.0/8"))),
    },
    Range {
        cidr: "fc00::/7",
        first: "fc00::",
        last: "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        before: Some((
            "fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Outside::NotThisRule,
        )),
        after: Some(("fe00::", Outside::NotThisRule)),
    },
    Range {
        cidr: "fe80::/10",
        first: "fe80::",
        last: "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        before: Some(("fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Outside::Allowed)),
        after: Some(("fec0::", Outside::Rule("fec0::/10"))),
    },
    // Deprecated site-local (RFC 3879); still routed on some internal networks.
    Range {
        cidr: "fec0::/10",
        first: "fec0::",
        last: "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        before: Some((
            "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Outside::Rule("fe80::/10"),
        )),
        after: Some(("ff00::", Outside::Rule("ff00::/8"))),
    },
    // NAT64 local-use prefix (RFC 8215): blocked whole, never a public destination.
    Range {
        cidr: "64:ff9b:1::/48",
        first: "64:ff9b:1::",
        last: "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
        before: Some(("64:ff9b:0:ffff:ffff:ffff:ffff:ffff", Outside::Allowed)),
        after: Some(("64:ff9b:2::", Outside::Allowed)),
    },
    Range {
        cidr: "ff00::/8",
        first: "ff00::",
        last: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        before: Some((
            "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Outside::Rule("fec0::/10"),
        )),
        after: None,
    },
];

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn assert_blocked_by(guard: &UrlGuard, addr: &str, rule: &str) {
    match guard.check_addr(ip(addr)) {
        Err(GuardError::Ssrf {
            addr: got,
            rule: got_rule,
        }) => {
            assert_eq!(got, ip(addr), "{addr}: reported address");
            assert_eq!(got_rule, rule, "{addr}: reported rule");
        }
        other => panic!("{addr}: expected Ssrf by {rule}, got {other:?}"),
    }
}

fn assert_outside(guard: &UrlGuard, addr: &str, cidr: &str, expected: Outside) {
    let result = guard.check_addr(ip(addr));
    match expected {
        Outside::Allowed => assert_eq!(result, Ok(()), "{addr} (next to {cidr}) must be allowed"),
        Outside::Rule(rule) => assert_blocked_by(guard, addr, rule),
        Outside::NotThisRule => {
            if let Err(GuardError::Ssrf { rule, .. }) = &result {
                assert_ne!(*rule, cidr, "{addr} must not be blocked by {cidr}");
            }
        }
    }
}

fn check_table(table: &[Range]) {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    for range in table {
        assert_blocked_by(&guard, range.first, range.cidr);
        assert_blocked_by(&guard, range.last, range.cidr);
        if let Some((addr, expected)) = range.before {
            assert_outside(&guard, addr, range.cidr, expected);
        }
        if let Some((addr, expected)) = range.after {
            assert_outside(&guard, addr, range.cidr, expected);
        }
    }
    assert_eq!(resolver.lookups(), 0, "check_addr never resolves");
}

#[test]
fn every_ipv4_range_is_blocked_at_its_boundaries() {
    check_table(V4);
}

#[test]
fn every_ipv6_range_is_blocked_at_its_boundaries() {
    check_table(V6);
}

#[test]
fn ipv4_mapped_addresses_are_unwrapped_and_checked_against_ipv4_rules() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    // ::ffff:0:0/96 — first and last embedded addresses hit the v4 rules.
    assert_blocked_by(&guard, "::ffff:0.0.0.0", "0.0.0.0/8");
    assert_blocked_by(&guard, "::ffff:255.255.255.255", "255.255.255.255/32");
    for (mapped, rule) in [
        ("::ffff:127.0.0.1", "127.0.0.0/8"),
        ("::ffff:10.0.0.1", "10.0.0.0/8"),
        ("::ffff:169.254.169.254", "169.254.0.0/16"),
        ("::ffff:192.168.1.1", "192.168.0.0/16"),
        ("::ffff:100.100.100.200", "100.64.0.0/10"),
    ] {
        assert_blocked_by(&guard, mapped, rule);
    }
    assert_eq!(guard.check_addr(ip("::ffff:93.184.216.34")), Ok(()));
    // Just outside ::ffff:0:0/96 the address is not unwrapped as mapped.
    assert_outside(
        &guard,
        "::fffe:ffff:ffff",
        "::ffff:0:0/96",
        Outside::NotThisRule,
    );
    assert_outside(&guard, "::1:0:0:0", "::ffff:0:0/96", Outside::NotThisRule);
}

#[test]
fn ipv4_compatible_addresses_are_unwrapped_and_checked_against_ipv4_rules() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    assert_blocked_by(&guard, "::127.0.0.1", "127.0.0.0/8");
    assert_blocked_by(&guard, "::10.0.0.1", "10.0.0.0/8");
    assert_blocked_by(&guard, "::169.254.169.254", "169.254.0.0/16");
}

#[test]
fn nat64_addresses_are_unwrapped_and_checked_against_ipv4_rules() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    // 64:ff9b::/96 — first and last embedded addresses hit the v4 rules.
    assert_blocked_by(&guard, "64:ff9b::", "0.0.0.0/8");
    assert_blocked_by(&guard, "64:ff9b::ffff:ffff", "255.255.255.255/32");
    assert_blocked_by(&guard, "64:ff9b::7f00:1", "127.0.0.0/8");
    assert_blocked_by(&guard, "64:ff9b::a9fe:a9fe", "169.254.0.0/16");
    assert_blocked_by(&guard, "64:ff9b::c0a8:101", "192.168.0.0/16");
    // A public embedded address is a legitimate NAT64 destination.
    assert_eq!(guard.check_addr(ip("64:ff9b::5db8:d822")), Ok(()));
    // One before / one after the /96: not unwrapped as NAT64.
    assert_outside(
        &guard,
        "64:ff9a:ffff:ffff:ffff:ffff:ffff:ffff",
        "64:ff9b::/96",
        Outside::Allowed,
    );
    assert_outside(
        &guard,
        "64:ff9b::1:7f00:1",
        "64:ff9b::/96",
        Outside::Allowed,
    );
}

/// IPv4-translated (SIIT), 6to4 and Teredo addresses carry an IPv4 address that a translator or
/// relay on the path may deliver to; it is checked against the IPv4 rules (ADR-017).
#[test]
fn translated_6to4_and_teredo_addresses_are_unwrapped_and_checked() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    // ::ffff:0:0:0/96 (IPv4-translated): the last 32 bits.
    assert_blocked_by(&guard, "::ffff:0:127.0.0.1", "127.0.0.0/8");
    assert_blocked_by(&guard, "::ffff:0:a9fe:a9fe", "169.254.0.0/16");
    // 2002::/16 (6to4): bits 16..48.
    assert_blocked_by(&guard, "2002:7f00:1::", "127.0.0.0/8");
    assert_blocked_by(&guard, "2002:a9fe:a9fe::1", "169.254.0.0/16");
    assert_blocked_by(&guard, "2002:c0a8:101:ffff::", "192.168.0.0/16");
    // 2001::/32 (Teredo): server in bits 32..64, client in the last 32 bits, inverted.
    assert_blocked_by(&guard, "2001:0:7f00:1::", "127.0.0.0/8");
    assert_blocked_by(
        &guard,
        "2001:0:4136:e378:8000:63bf:80ff:fffe",
        "127.0.0.0/8",
    );
    assert_blocked_by(&guard, "2001:0:4136:e378::5601:5ebf", "169.254.0.0/16");
    // Public embedded addresses stay allowed.
    for addr in [
        "::ffff:0:5db8:d822",
        "2002:5db8:d822::1",
        "2001:0:4136:e378:8000:63bf:a247:27dd",
        "2001:db8::1",
        "2001:4860:4860::8888",
    ] {
        assert_eq!(guard.check_addr(ip(addr)), Ok(()), "{addr}");
    }
}

/// ISATAP interface identifiers (`::0:5efe:a.b.c.d` / `::200:5efe:a.b.c.d`, RFC 5214) under any
/// prefix carry an IPv4 address an ISATAP router delivers to; it is checked against the IPv4
/// rules (ADR-017, PR-08 addendum).
#[test]
fn isatap_interface_ids_are_unwrapped_and_checked() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    assert_blocked_by(&guard, "2606:4700::5efe:7f00:1", "127.0.0.0/8");
    assert_blocked_by(&guard, "2606:4700::200:5efe:a9fe:a9fe", "169.254.0.0/16");
    assert_blocked_by(&guard, "2001:db8:1:2:0:5efe:c0a8:101", "192.168.0.0/16");
    // A public embedded address stays allowed, and 5efe elsewhere is not ISATAP.
    for addr in [
        "2606:4700::5efe:5db8:d822",
        "2606:4700::5efe:0:7f00:1",
        "2606:4700::100:5efe:7f00:1",
    ] {
        assert_eq!(guard.check_addr(ip(addr)), Ok(()), "{addr}");
    }
}

#[test]
fn metadata_addresses_from_the_policy_are_blocked() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    assert_blocked_by(&guard, "169.254.169.254", "169.254.0.0/16");
    assert_blocked_by(&guard, "100.100.100.200", "100.64.0.0/10");
    assert_blocked_by(&guard, "fd00:ec2::254", "fc00::/7");
}

#[test]
fn public_addresses_are_allowed() {
    let resolver = StubResolver::new(&[]);
    let guard = guard(&resolver);
    for addr in [
        "93.184.216.34",
        "1.1.1.1",
        "8.8.8.8",
        "2606:2800:220:1:248:1893:25c8:1946",
        "2606:4700:4700::1111",
    ] {
        assert_eq!(guard.check_addr(ip(addr)), Ok(()), "{addr}");
    }
}

#[test]
fn extra_blocked_cidrs_are_enforced_at_their_boundaries() {
    let resolver = StubResolver::new(&[]);
    let cfg = NetworkConfig {
        extra_blocked_cidrs: vec!["93.184.216.0/24".to_owned(), "2001:db8::/32".to_owned()],
        ..NetworkConfig::default()
    };
    let guard = guard_with(cfg, &resolver);
    assert_blocked_by(&guard, "93.184.216.0", "extraBlockedCidrs");
    assert_blocked_by(&guard, "93.184.216.255", "extraBlockedCidrs");
    assert_eq!(guard.check_addr(ip("93.184.215.255")), Ok(()));
    assert_eq!(guard.check_addr(ip("93.184.217.0")), Ok(()));
    assert_blocked_by(&guard, "2001:db8::", "extraBlockedCidrs");
    assert_blocked_by(
        &guard,
        "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
        "extraBlockedCidrs",
    );
    assert_eq!(
        guard.check_addr(ip("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff")),
        Ok(())
    );
    assert_eq!(guard.check_addr(ip("2001:db9::")), Ok(()));
    // Extra v4 ranges also apply to v4 addresses embedded in v6.
    assert_blocked_by(&guard, "::ffff:93.184.216.34", "extraBlockedCidrs");
    assert_blocked_by(&guard, "64:ff9b::5db8:d822", "extraBlockedCidrs");
}

#[test]
fn an_invalid_extra_cidr_is_a_construction_error() {
    let resolver = StubResolver::new(&[]);
    for bad in ["10.0.0.0/33", "not-a-cidr", "10.0.0.0", "", "::/129"] {
        let cfg = NetworkConfig {
            extra_blocked_cidrs: vec![bad.to_owned()],
            ..NetworkConfig::default()
        };
        assert!(
            UrlGuard::new(&cfg, resolver.clone()).is_err(),
            "{bad:?} must be rejected"
        );
    }
}

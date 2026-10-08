//! URL guard additions for PR-03: bounded DNS lookups, and the test-only fixture allowance
//! (ADR-011) — which must exempt exactly one name + socket and nothing else.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../support/resolver.rs"]
mod resolver;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use secure_web_core::config::NetworkConfig;
use secure_web_security::ssrf::{
    GuardConfigError, GuardError, ResolveFuture, Resolver, UrlGuard, DEFAULT_DNS_TIMEOUT,
};

use resolver::StubResolver;

/// A resolver that never answers.
struct HangingResolver;

impl Resolver for HangingResolver {
    fn resolve<'a>(&'a self, _host: &'a str, _port: u16) -> ResolveFuture<'a> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn a_hanging_dns_lookup_fails_closed_within_the_timeout() {
    let guard = UrlGuard::new(&NetworkConfig::default(), Arc::new(HangingResolver))
        .unwrap()
        .with_dns_timeout(Duration::from_millis(100));
    let started = Instant::now();
    let err = guard.validate("http://example.com/").await.unwrap_err();
    assert_eq!(err, GuardError::DnsFailed);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn dns_timeout_defaults_and_zero_falls_back_to_the_default() {
    let resolver = StubResolver::new(&[]);
    let guard = UrlGuard::new(&NetworkConfig::default(), resolver).unwrap();
    assert_eq!(guard.dns_timeout(), DEFAULT_DNS_TIMEOUT);
    assert_eq!(
        guard.with_dns_timeout(Duration::ZERO).dns_timeout(),
        DEFAULT_DNS_TIMEOUT
    );
}

fn fixture_guard(resolver: &Arc<StubResolver>, socket: SocketAddr) -> UrlGuard {
    UrlGuard::new(&NetworkConfig::default(), resolver.clone())
        .unwrap()
        .with_test_fixture("fixture.test", socket)
        .unwrap()
}

#[tokio::test]
async fn the_allowance_admits_only_the_named_host_on_the_exact_socket() {
    let socket: SocketAddr = "127.0.0.1:4321".parse().unwrap();
    let resolver = StubResolver::new(&[
        ("fixture.test", &["127.0.0.1"]),
        ("other.test", &["127.0.0.1"]),
        ("wrong-ip.test", &["127.0.0.2"]),
    ]);
    let guard = fixture_guard(&resolver, socket);

    let ok = guard.validate("http://fixture.test:4321/x").await.unwrap();
    assert_eq!(
        ok.addrs(),
        &["127.0.0.1".parse::<std::net::IpAddr>().unwrap()]
    );
    assert!(guard.validate("http://FIXTURE.test:4321/x").await.is_ok());

    // Another port on the same host.
    assert!(matches!(
        guard.validate("http://fixture.test:4322/").await,
        Err(GuardError::Ssrf { .. })
    ));
    assert!(matches!(
        guard.validate("http://fixture.test/").await,
        Err(GuardError::Ssrf { .. })
    ));
    // Another name resolving to the same socket.
    assert!(matches!(
        guard.validate("http://other.test:4321/").await,
        Err(GuardError::Ssrf { .. })
    ));
    // The IP literal of the fixture socket itself.
    assert!(matches!(
        guard.validate("http://127.0.0.1:4321/").await,
        Err(GuardError::Ssrf { .. })
    ));
    // A subdomain is not the allowed name.
    assert!(guard.validate("http://a.fixture.test:4321/").await.is_err());
}

#[tokio::test]
async fn the_allowance_does_not_admit_a_private_address_mixed_into_the_answer() {
    let socket: SocketAddr = "127.0.0.1:4321".parse().unwrap();
    let resolver = StubResolver::new(&[("fixture.test", &["127.0.0.1", "10.0.0.1"])]);
    let guard = fixture_guard(&resolver, socket);
    assert!(matches!(
        guard.validate("http://fixture.test:4321/").await,
        Err(GuardError::Ssrf { .. })
    ));
}

#[test]
fn the_allowance_requires_a_test_name_and_a_loopback_socket() {
    let base = || UrlGuard::new(&NetworkConfig::default(), StubResolver::new(&[])).unwrap();
    let loopback: SocketAddr = "127.0.0.1:4321".parse().unwrap();
    for host in ["example.com", "test", ".test", "a..test", "localhost", ""] {
        assert_eq!(
            base().with_test_fixture(host, loopback).unwrap_err(),
            GuardConfigError::InvalidFixture,
            "{host}"
        );
    }
    for socket in ["10.0.0.1:80", "93.184.216.34:80", "127.0.0.1:0"] {
        assert_eq!(
            base()
                .with_test_fixture("fixture.test", socket.parse().unwrap())
                .unwrap_err(),
            GuardConfigError::InvalidFixture,
            "{socket}"
        );
    }
}

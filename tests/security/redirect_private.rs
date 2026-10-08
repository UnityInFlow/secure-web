//! T6 — redirect to a private host / DNS rebinding (`docs/threat-model.md`).
//!
//! Redirects are followed by the fetcher, never the HTTP client, and every `Location` is
//! re-validated by the URL guard from its raw text. Connections go only to the addresses the
//! guard validated. Everything runs against the in-process fixture server.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../support/fetch.rs"]
mod fetch;

use secure_web_core::config::FetchConfig;
use secure_web_core::error::ErrorCode;
use secure_web_core::model::BlockReason;
use secure_web_fetch::{FetchError, Fetcher, RedirectViolation};
use secure_web_security::ssrf::{GuardError, AMBIGUOUS_IPV4_LITERAL};

use fetch::Harness;

fn guard_violation(err: FetchError) -> GuardError {
    assert_eq!(err.code(), ErrorCode::RedirectBlocked, "{err:?}");
    assert_eq!(err.block_reason(), Some(BlockReason::RedirectViolation));
    assert!(!err.retryable());
    match err {
        FetchError::RedirectBlocked(RedirectViolation::Guard(guard)) => guard,
        other => panic!("expected a guard rejection, got {other:?}"),
    }
}

fn ssrf_rule(err: FetchError) -> &'static str {
    match guard_violation(err) {
        GuardError::Ssrf { rule, .. } => rule,
        other => panic!("expected an SSRF rule, got {other:?}"),
    }
}

#[tokio::test]
async fn redirect_to_the_fixtures_own_loopback_address_is_blocked() {
    let h = Harness::start().await;
    let err = h.fetch("/redirect/private").await.unwrap_err();
    assert_eq!(ssrf_rule(err), "127.0.0.0/8");
    assert!(
        !h.served("/clean/a"),
        "the private target must never be requested"
    );
}

#[tokio::test]
async fn redirect_to_cloud_metadata_is_blocked() {
    let h = Harness::start().await;
    let err = h.fetch("/redirect/metadata").await.unwrap_err();
    assert_eq!(ssrf_rule(err), "169.254.0.0/16");
}

#[tokio::test]
async fn scheme_relative_and_backslash_redirects_to_loopback_are_blocked() {
    let h = Harness::start().await;
    for path in [
        "/redirect/scheme-relative-private",
        "/redirect/backslash-private",
    ] {
        let err = h.fetch(path).await.unwrap_err();
        assert_eq!(ssrf_rule(err), "127.0.0.0/8", "{path}");
    }
    assert!(!h.served("/clean/a"));
}

#[tokio::test]
async fn redirect_to_an_obfuscated_ipv4_literal_is_blocked_from_the_raw_location() {
    let h = Harness::start().await;
    let err = h.fetch("/redirect/obfuscated").await.unwrap_err();
    assert_eq!(ssrf_rule(err), AMBIGUOUS_IPV4_LITERAL);
}

#[tokio::test]
async fn redirect_to_localhost_is_denied_by_name() {
    let h = Harness::start().await;
    let err = h.fetch("/redirect/localhost").await.unwrap_err();
    assert!(matches!(guard_violation(err), GuardError::HostDenied(_)));
}

#[tokio::test]
async fn redirect_to_a_name_resolving_to_a_private_address_is_blocked() {
    let h = Harness::start().await;
    let err = h.fetch("/redirect/rebind").await.unwrap_err();
    assert_eq!(ssrf_rule(err), "10.0.0.0/8");
}

#[tokio::test]
async fn redirect_carrying_userinfo_is_blocked() {
    let h = Harness::start().await;
    let err = h.fetch("/redirect/userinfo").await.unwrap_err();
    assert_eq!(guard_violation(err), GuardError::Userinfo);
    assert!(!h.served("/clean/a"));
}

#[tokio::test]
async fn redirect_loop_is_blocked() {
    let h = Harness::start().await;
    for path in ["/redirect/loop", "/redirect/fragment-loop"] {
        let err = h.fetch(path).await.unwrap_err();
        assert_eq!(
            err,
            FetchError::RedirectBlocked(RedirectViolation::Loop),
            "{path}"
        );
        assert_eq!(err.code(), ErrorCode::RedirectBlocked);
    }
}

#[tokio::test]
async fn five_redirects_are_followed_and_six_are_blocked() {
    let h = Harness::start().await;
    let ok = h.fetch("/redirect/chain/5").await.unwrap();
    assert_eq!(ok.redirect_chain.len(), 5);
    assert_eq!(ok.final_url.path(), "/clean/a");
    assert_eq!(ok.requested_url.path(), "/redirect/chain/5");
    assert_eq!(ok.redirect_chain.last(), Some(&ok.final_url));

    let h = Harness::start().await;
    let err = h.fetch("/redirect/chain/6").await.unwrap_err();
    assert_eq!(
        err,
        FetchError::RedirectBlocked(RedirectViolation::TooManyHops { max: 5 })
    );
    assert!(h.served("/redirect/chain/1"), "five hops are followed");
    assert!(!h.served("/clean/a"), "the sixth hop is never requested");
}

#[tokio::test]
async fn the_hop_cap_follows_config() {
    let cfg = FetchConfig {
        max_redirects: 1,
        ..FetchConfig::default()
    };
    let h = Harness::with_config(cfg).await;
    assert!(h.fetch("/redirect/chain/1").await.is_ok());
    let err = h.fetch("/redirect/chain/2").await.unwrap_err();
    assert_eq!(
        err,
        FetchError::RedirectBlocked(RedirectViolation::TooManyHops { max: 1 })
    );
}

#[tokio::test]
async fn redirect_without_location_is_a_failed_fetch() {
    let h = Harness::start().await;
    let err = h.fetch("/redirect/no-location").await.unwrap_err();
    assert_eq!(
        err,
        FetchError::Status {
            status: 302,
            retry_after: None
        }
    );
    assert_eq!(err.code(), ErrorCode::FetchFailed);
}

#[tokio::test]
async fn every_hop_is_resolved_again_and_connections_use_only_the_pinned_addresses() {
    let h = Harness::start().await;
    // `fixture.test` exists only in the stub resolver, so these fetches can only succeed by
    // connecting to the address the guard validated; the client never does its own lookup.
    let direct = h.fetch("/clean/a").await.unwrap();
    assert_eq!(direct.status, 200);
    assert_eq!(h.resolver.lookups(), 1, "only the guard resolves");

    let redirected = h.fetch("/redirect/absolute").await.unwrap();
    assert_eq!(redirected.final_url.path(), "/clean/a");
    assert_eq!(
        h.resolver.lookups(),
        3,
        "the redirect target is resolved and validated again by the guard"
    );
}

#[tokio::test]
async fn a_target_is_not_re_resolved_at_connect_time() {
    let h = Harness::start().await;
    let target = h.target("/clean/a").await;
    let before = h.resolver.lookups();
    let response = h
        .fetcher
        .fetch(secure_web_fetch::FetchRequest {
            target,
            limits: h.limits,
        })
        .await;
    assert!(response.is_ok());
    assert_eq!(
        h.resolver.lookups(),
        before,
        "no second lookup (rebinding window)"
    );
}

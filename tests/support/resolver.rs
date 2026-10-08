//! Offline DNS for SSRF tests: a fixed host -> addresses map that also counts lookups.
//!
//! Tests never touch real DNS (`docs/testing.md`); every `UrlGuard` in a test is built with this.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use secure_web_core::config::NetworkConfig;
use secure_web_security::ssrf::{ResolveError, ResolveFuture, Resolver, UrlGuard};

/// Resolves only the hosts it was given; everything else fails like `NXDOMAIN`.
#[derive(Debug, Default)]
pub struct StubResolver {
    hosts: HashMap<String, Vec<IpAddr>>,
    lookups: AtomicUsize,
}

impl StubResolver {
    pub fn new(entries: &[(&str, &[&str])]) -> Arc<Self> {
        let hosts = entries
            .iter()
            .map(|(host, addrs)| {
                let parsed = addrs.iter().map(|a| a.parse().unwrap()).collect();
                ((*host).to_owned(), parsed)
            })
            .collect();
        Arc::new(Self {
            hosts,
            lookups: AtomicUsize::new(0),
        })
    }

    /// Number of lookups performed so far.
    pub fn lookups(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
}

impl Resolver for StubResolver {
    fn resolve<'a>(&'a self, host: &'a str, _port: u16) -> ResolveFuture<'a> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        let result = self
            .hosts
            .get(host)
            .cloned()
            .ok_or_else(|| ResolveError::new(format!("stub: no such host {host}")));
        Box::pin(async move { result })
    }
}

/// A guard over the default network config and the given stub.
pub fn guard(resolver: &Arc<StubResolver>) -> UrlGuard {
    guard_with(NetworkConfig::default(), resolver)
}

/// A guard over a custom network config and the given stub.
pub fn guard_with(cfg: NetworkConfig, resolver: &Arc<StubResolver>) -> UrlGuard {
    UrlGuard::new(&cfg, resolver.clone()).unwrap()
}

/// Non-comment, non-empty lines of a `tests/corpus/network/` URL list.
pub fn corpus_urls(relative: &str) -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus/network")
        .join(relative);
    let text = std::fs::read_to_string(&path).unwrap();
    let urls: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect();
    assert!(!urls.is_empty(), "{} is empty", path.display());
    urls
}

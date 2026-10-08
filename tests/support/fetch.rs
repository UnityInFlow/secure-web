//! Fetcher test harness: fixture server + stub DNS + a guard that lets exactly the fixture's
//! `fixture.test:<port>` through (ADR-011).
#![allow(dead_code)]

#[path = "fixture_server.rs"]
pub mod fixture_server;
#[path = "resolver.rs"]
pub mod resolver;

use std::sync::Arc;

use secure_web_core::config::{FetchConfig, NetworkConfig};
use secure_web_fetch::{
    FetchError, FetchLimits, FetchRequest, FetchedResponse, Fetcher, HttpFetcher,
};
use secure_web_security::ssrf::{UrlGuard, ValidatedTarget};
use url::Url;

use fixture_server::{FixtureServer, FIXTURE_HOST, REBIND_HOST};
use resolver::StubResolver;

/// Largest network chunk hyper hands out (its maximum read buffer is 8 KiB + 400 KiB), rounded
/// up. "Peak buffered ≤ limit + one chunk" is asserted with this slack.
pub const CHUNK_SLACK: u64 = 512 * 1024;

pub struct Harness {
    pub base: Url,
    pub server: FixtureServer,
    pub resolver: Arc<StubResolver>,
    pub guard: UrlGuard,
    pub fetcher: HttpFetcher,
    pub limits: FetchLimits,
}

impl Harness {
    pub async fn start() -> Self {
        Self::with_config(FetchConfig::default()).await
    }

    pub async fn with_config(cfg: FetchConfig) -> Self {
        let (base, server) = FixtureServer::start().await;
        let resolver = StubResolver::new(&[
            (FIXTURE_HOST, &["127.0.0.1"]),
            // A public-looking name whose DNS answer is private: the guard must refuse it.
            (REBIND_HOST, &["10.0.0.1"]),
        ]);
        let guard = UrlGuard::new(&NetworkConfig::default(), resolver.clone())
            .unwrap()
            .with_test_fixture(FIXTURE_HOST, server.addr())
            .unwrap();
        let fetcher = HttpFetcher::new(&cfg, guard.clone());
        Self {
            base,
            server,
            resolver,
            guard,
            fetcher,
            limits: FetchLimits::from(&cfg),
        }
    }

    pub fn url(&self, path: &str) -> String {
        self.base.join(path).unwrap().to_string()
    }

    pub async fn target(&self, path: &str) -> ValidatedTarget {
        self.guard.validate(&self.url(path)).await.unwrap()
    }

    pub async fn fetch(&self, path: &str) -> Result<FetchedResponse, FetchError> {
        self.fetch_with(path, self.limits).await
    }

    pub async fn fetch_with(
        &self,
        path: &str,
        limits: FetchLimits,
    ) -> Result<FetchedResponse, FetchError> {
        let target = self.target(path).await;
        self.fetcher.fetch(FetchRequest { target, limits }).await
    }

    /// Whether the fixture served `path` at all.
    pub fn served(&self, path: &str) -> bool {
        self.server.requests().iter().any(|served| served == path)
    }
}

//! Hard limits for one fetch (`docs/security-policy.md` §2).

use std::time::Duration;

use secure_web_core::config::FetchConfig;

/// Per-fetch limits. Every one is enforced in code; none is advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchLimits {
    /// TCP (and TLS) connect timeout for each hop → `FETCH_TIMEOUT`.
    pub connect_timeout: Duration,
    /// Deadline for the **whole** fetch, every redirect hop and the full body included →
    /// `FETCH_TIMEOUT`. DNS lookups for redirect hops are also bounded by `connect_timeout`.
    pub request_timeout: Duration,
    /// Maximum redirect hops followed; one more is `REDIRECT_BLOCKED`.
    pub max_redirects: u32,
    /// Permit an `https` → `http` redirect.
    pub allow_redirect_downgrade: bool,
    /// Maximum decompressed body size in bytes for non-JSON content → `CONTENT_TOO_LARGE`.
    pub max_page_bytes: u64,
    /// Maximum decompressed body size in bytes for `application/json` → `CONTENT_TOO_LARGE`.
    pub max_json_bytes: u64,
}

impl From<&FetchConfig> for FetchLimits {
    fn from(cfg: &FetchConfig) -> Self {
        Self {
            connect_timeout: cfg.connect_timeout,
            request_timeout: cfg.request_timeout,
            max_redirects: cfg.max_redirects,
            allow_redirect_downgrade: cfg.allow_redirect_downgrade,
            max_page_bytes: cfg.max_page_bytes,
            max_json_bytes: cfg.max_json_bytes,
        }
    }
}

impl Default for FetchLimits {
    fn default() -> Self {
        Self::from(&FetchConfig::default())
    }
}

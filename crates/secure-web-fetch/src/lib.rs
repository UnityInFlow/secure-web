//! Bounded HTTP fetcher. Only fetches targets validated by the SSRF guard.
//!
//! [`HttpFetcher`] takes a [`FetchRequest`] holding a [`ValidatedTarget`] — never a raw URL —
//! and:
//!
//! - connects only to the addresses the guard validated (pinned resolution, no proxy);
//! - follows redirects itself, re-validating every `Location` from its raw text through the
//!   guard, with a hop cap, loop detection and the `https` → `http` downgrade rule
//!   (`REDIRECT_BLOCKED`);
//! - classifies the `Content-Type` before reading the body (`UNSUPPORTED_CONTENT_TYPE`);
//! - streams the body, decompressing `gzip`/`deflate` itself, and aborts the moment the
//!   **decompressed** size passes `maxPageBytes` / `maxJsonBytes` (`CONTENT_TOO_LARGE`);
//!   `Content-Length` is only used to refuse early, never to accept;
//! - bounds the whole fetch by `requestTimeout` and each connect by `connectTimeout`
//!   (`FETCH_TIMEOUT`); redirect-hop DNS is bounded by `connectTimeout` too;
//! - reports `FETCH_FAILED` for non-2xx finals, retryable for `5xx`/`429` with `Retry-After`.
//!
//! See `docs/security-policy.md` §1–2, threats T5/T6/T9, ADR-010 and ADR-011.
#![forbid(unsafe_code)]

mod body;
mod client;
pub mod content;
pub mod error;
pub mod limits;
mod redirect;
mod throttle;

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::header::{self, HeaderMap};
use secure_web_core::config::FetchConfig;
use secure_web_security::ssrf::{UrlGuard, ValidatedTarget};
use url::Url;

use crate::body::{BodyError, BoundedBody};
pub use crate::content::ContentType;
use crate::content::{parse_content_encoding, parse_content_type, sniff};
pub use crate::error::{FetchError, RedirectViolation};
pub use crate::limits::FetchLimits;
use crate::throttle::HostThrottle;

/// `Accept` header: the supported types first, anything else tolerated (and then refused).
const ACCEPT: &str =
    "text/html,application/xhtml+xml,text/markdown,text/plain,application/json;q=0.9,*/*;q=0.1";

/// `Accept-Encoding`: only codings the fetcher decodes itself under the byte cap.
const ACCEPT_ENCODING: &str = "gzip, deflate";

/// Longest `Retry-After` honoured; longer values are clamped.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(3600);

/// One fetch: a validated target and the limits to apply.
#[derive(Debug, Clone)]
pub struct FetchRequest {
    /// The destination, as validated by the URL guard.
    pub target: ValidatedTarget,
    /// Limits for this fetch.
    pub limits: FetchLimits,
}

/// A successful (`2xx`, supported type, within limits) response. All of it is untrusted.
///
/// `Debug` prints only scheme/host of the URLs and the body length: paths, queries and the body
/// are attacker-controlled text.
#[derive(Clone)]
pub struct FetchedResponse {
    /// URL as requested.
    pub requested_url: Url,
    /// URL of the final response (the last redirect target, or `requested_url`).
    pub final_url: Url,
    /// Every redirect target followed, in order (empty without redirects).
    pub redirect_chain: Vec<Url>,
    /// Final HTTP status (always `2xx`).
    pub status: u16,
    /// Classified content type (never [`ContentType::Unsupported`]).
    pub content_type: ContentType,
    /// Normalized `charset` parameter, if any.
    pub charset: Option<String>,
    /// Decompressed body, at most the applicable byte limit.
    pub body: Vec<u8>,
    /// Decompressed body size in bytes (`body.len()`).
    pub decompressed_bytes: u64,
    /// When the final response headers arrived.
    pub retrieved_at: DateTime<Utc>,
    /// `Retry-After` on the final response, if present and honoured.
    pub retry_after: Option<Duration>,
}

/// `scheme://host:port` of a URL, for `Debug` output.
struct Origin<'a>(&'a Url);

impl fmt::Debug for Origin<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}://{}:{}",
            self.0.scheme(),
            self.0.host_str().unwrap_or_default(),
            self.0.port_or_known_default().unwrap_or_default()
        )
    }
}

impl fmt::Debug for FetchedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchedResponse")
            .field("requested_origin", &Origin(&self.requested_url))
            .field("final_origin", &Origin(&self.final_url))
            .field("redirect_hops", &self.redirect_chain.len())
            .field("status", &self.status)
            .field("content_type", &self.content_type.essence())
            .field("charset", &self.charset)
            .field("body_bytes", &self.body.len())
            .field("retrieved_at", &self.retrieved_at)
            .field("retry_after", &self.retry_after)
            .finish_non_exhaustive()
    }
}

/// The future returned by [`Fetcher::fetch`].
pub type FetchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<FetchedResponse, FetchError>> + Send + 'a>>;

/// Fetches a validated target. One implementation ([`HttpFetcher`]); the trait exists so the
/// page processor can be tested with a stub.
pub trait Fetcher: Send + Sync {
    /// Fetch `req.target` under `req.limits`.
    fn fetch(&self, req: FetchRequest) -> FetchFuture<'_>;
}

/// The production fetcher. See the crate docs.
pub struct HttpFetcher {
    guard: UrlGuard,
    user_agent: String,
    respect_retry_after: bool,
    throttle: HostThrottle,
}

impl fmt::Debug for HttpFetcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpFetcher")
            .field("user_agent", &self.user_agent)
            .field("respect_retry_after", &self.respect_retry_after)
            .finish_non_exhaustive()
    }
}

impl HttpFetcher {
    /// A fetcher using `cfg` for the user agent, per-host politeness and `Retry-After`, and
    /// `guard` to re-validate redirect targets. The guard's DNS lookups are bounded by
    /// `cfg.connect_timeout`.
    pub fn new(cfg: &FetchConfig, guard: UrlGuard) -> Self {
        Self {
            guard: guard.with_dns_timeout(cfg.connect_timeout),
            user_agent: cfg.user_agent.clone(),
            respect_retry_after: cfg.respect_retry_after,
            throttle: HostThrottle::new(cfg.per_host_concurrency, cfg.min_delay_per_host),
        }
    }

    async fn fetch_within_deadline(
        &self,
        req: FetchRequest,
    ) -> Result<FetchedResponse, FetchError> {
        let FetchRequest { target, limits } = req;
        let requested_url = target.url().clone();
        let mut chain: Vec<Url> = Vec::new();
        let mut visited = vec![without_fragment(&requested_url)];
        let mut current = target;
        loop {
            let throttle_key = format!("{}:{}", current.host(), current.port());
            let _permit = self.throttle.acquire(&throttle_key).await;
            let client = client::client_for(&current, &limits, &self.user_agent)?;
            let response = client
                .get(current.url().clone())
                .header(header::ACCEPT, ACCEPT)
                .header(header::ACCEPT_ENCODING, ACCEPT_ENCODING)
                .send()
                .await
                .map_err(map_reqwest_error)?;
            let status = response.status().as_u16();
            if !redirect::is_redirect_status(status) {
                return self
                    .finish(
                        response,
                        requested_url,
                        current.url().clone(),
                        chain,
                        &limits,
                    )
                    .await;
            }
            let Some(location) = response.headers().get(header::LOCATION) else {
                // A redirect status without a target is a final, failed response.
                return Err(FetchError::Status {
                    status,
                    retry_after: None,
                });
            };
            if chain.len() >= usize::try_from(limits.max_redirects).unwrap_or(usize::MAX) {
                return Err(FetchError::RedirectBlocked(
                    RedirectViolation::TooManyHops {
                        max: limits.max_redirects,
                    },
                ));
            }
            let raw_location = location
                .to_str()
                .map_err(|_| FetchError::RedirectBlocked(RedirectViolation::InvalidLocation))?
                .to_owned();
            drop(response);
            let next = redirect::next_target(
                &self.guard,
                current.url(),
                &raw_location,
                limits.allow_redirect_downgrade,
            )
            .await
            .map_err(FetchError::RedirectBlocked)?;
            let key = without_fragment(next.url());
            if visited.contains(&key) {
                return Err(FetchError::RedirectBlocked(RedirectViolation::Loop));
            }
            tracing::debug!(
                hop = chain.len() + 1,
                host = next.host(),
                port = next.port(),
                "following validated redirect"
            );
            visited.push(key);
            chain.push(next.url().clone());
            current = next;
        }
    }

    async fn finish(
        &self,
        mut response: reqwest::Response,
        requested_url: Url,
        final_url: Url,
        redirect_chain: Vec<Url>,
        limits: &FetchLimits,
    ) -> Result<FetchedResponse, FetchError> {
        let retrieved_at = Utc::now();
        let status = response.status().as_u16();
        let retry_after = if self.respect_retry_after {
            parse_retry_after(response.headers(), retrieved_at)
        } else {
            None
        };
        if !(200..=299).contains(&status) {
            let retry_after = if status == 429 || status == 503 {
                retry_after
            } else {
                None
            };
            return Err(FetchError::Status {
                status,
                retry_after,
            });
        }
        let declared = header_str(response.headers(), header::CONTENT_TYPE).map(parse_content_type);
        if let Some((ContentType::Unsupported(essence), _)) = declared {
            return Err(FetchError::UnsupportedContentType { essence });
        }
        let encoding =
            parse_content_encoding(header_str(response.headers(), header::CONTENT_ENCODING))
                .ok_or(FetchError::UnsupportedContentEncoding)?;
        let limit = match declared {
            Some((ContentType::Json, _)) => limits.max_json_bytes,
            _ => limits.max_page_bytes,
        };
        // `Content-Length` may refuse early, never accept: the stream counter is authoritative.
        if encoding == content::Encoding::Identity
            && response.content_length().is_some_and(|len| len > limit)
        {
            return Err(FetchError::ContentTooLarge {
                limit,
                peak_buffered_bytes: 0,
            });
        }
        let mut body = BoundedBody::new(encoding, limit);
        loop {
            let chunk = response.chunk().await.map_err(map_reqwest_error)?;
            let Some(chunk) = chunk else { break };
            body.push(&chunk)
                .map_err(|err| body_error(err, limit, body.peak_buffered()))?;
        }
        let peak = body.peak_buffered();
        let body = body.finish().map_err(|err| body_error(err, limit, peak))?;
        let (content_type, charset) = match declared {
            Some(declared) => declared,
            None => match sniff(&body) {
                ContentType::Unsupported(essence) => {
                    return Err(FetchError::UnsupportedContentType { essence })
                }
                sniffed => (sniffed, None),
            },
        };
        Ok(FetchedResponse {
            requested_url,
            final_url,
            redirect_chain,
            status,
            content_type,
            charset,
            decompressed_bytes: body.len() as u64,
            body,
            retrieved_at,
            retry_after,
        })
    }
}

impl Fetcher for HttpFetcher {
    fn fetch(&self, req: FetchRequest) -> FetchFuture<'_> {
        Box::pin(async move {
            let deadline = req.limits.request_timeout;
            tokio::time::timeout(deadline, self.fetch_within_deadline(req))
                .await
                .map_err(|_| FetchError::Timeout)?
        })
    }
}

fn body_error(err: BodyError, limit: u64, peak_buffered_bytes: u64) -> FetchError {
    match err {
        BodyError::TooLarge => FetchError::ContentTooLarge {
            limit,
            peak_buffered_bytes,
        },
        BodyError::Corrupt => FetchError::Network { retryable: false },
    }
}

fn map_reqwest_error(err: reqwest::Error) -> FetchError {
    if err.is_timeout() {
        FetchError::Timeout
    } else if err.is_builder() {
        FetchError::Client
    } else {
        FetchError::Network { retryable: true }
    }
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    // A header that is not visible ASCII is treated as present-but-invalid text.
    headers
        .get(name)
        .map(|value| value.to_str().unwrap_or("\u{0}"))
}

fn without_fragment(url: &Url) -> Url {
    let mut url = url.clone();
    url.set_fragment(None);
    url
}

/// `Retry-After` as delay-seconds or an HTTP-date, clamped to [`MAX_RETRY_AFTER`].
fn parse_retry_after(headers: &HeaderMap, now: DateTime<Utc>) -> Option<Duration> {
    let text = headers.get(header::RETRY_AFTER)?.to_str().ok()?.trim();
    let delay = if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
        Duration::from_secs(text.parse::<u64>().unwrap_or(u64::MAX))
    } else {
        let at = DateTime::parse_from_rfc2822(text).ok()?.with_timezone(&Utc);
        (at - now).to_std().unwrap_or(Duration::ZERO)
    };
    Some(delay.min(MAX_RETRY_AFTER))
}

#[cfg(test)]
mod tests {
    use reqwest::header::HeaderValue;

    use super::*;

    fn retry_after(value: &str) -> Option<Duration> {
        let mut headers = HeaderMap::new();
        headers.insert(header::RETRY_AFTER, HeaderValue::from_str(value).unwrap());
        let now = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        parse_retry_after(&headers, now)
    }

    #[test]
    fn retry_after_seconds_and_dates_are_parsed_and_clamped() {
        assert_eq!(retry_after("7"), Some(Duration::from_secs(7)));
        assert_eq!(
            retry_after("Thu, 01 Jan 2026 00:00:30 GMT"),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            retry_after("Wed, 31 Dec 2025 23:00:00 GMT"),
            Some(Duration::ZERO)
        );
        assert_eq!(retry_after("99999999999999999999"), Some(MAX_RETRY_AFTER));
        assert_eq!(retry_after("soon"), None);
        assert_eq!(retry_after("-5"), None);
    }

    #[test]
    fn fragment_is_ignored_for_loop_detection() {
        let a = Url::parse("http://a.example/x#one").unwrap();
        let b = Url::parse("http://a.example/x#two").unwrap();
        assert_eq!(without_fragment(&a), without_fragment(&b));
    }
}

//! Hostile servers the HTTP fixture routes cannot express (threats T5, T6, T9).
//!
//! Each test runs a tiny raw-TCP server on `127.0.0.1:<ephemeral>` and reaches it as
//! `http://fixture.test:<port>/` through the test-only guard allowance (ADR-011), so the
//! fetcher under test is the production `HttpFetcher` with nothing stubbed but DNS. Every abuse
//! must end in a typed error within `requestTimeout` plus a small margin, with bounded memory.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::future::Future;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use flate2::write::GzEncoder;
use flate2::Compression;
use secure_web_core::config::{FetchConfig, NetworkConfig};
use secure_web_core::error::ErrorCode;
use secure_web_fetch::{
    FetchError, FetchLimits, FetchRequest, FetchedResponse, Fetcher, HttpFetcher, RedirectViolation,
};
use secure_web_security::ssrf::{GuardError, ResolveError, ResolveFuture, Resolver, UrlGuard};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const FIXTURE_HOST: &str = "fixture.test";
const REQUEST_TIMEOUT: Duration = Duration::from_millis(1000);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(400);
/// Scheduling slack on top of `requestTimeout`.
const MARGIN: Duration = Duration::from_millis(500);
const PAGE_LIMIT: u64 = 64 * 1024;
/// hyper's maximum read buffer (8 KiB + 400 KiB) rounded up: the most a response head or one
/// network chunk may occupy.
const HYPER_BUF: u64 = 512 * 1024;
/// hyper's cap on chunk-extension bytes (16 KiB) with room for the chunk-size digits.
const HYPER_CHUNK_EXT: u64 = 20 * 1024;

// ---------------------------------------------------------------------------------------------
// DNS: fixed answers, an empty answer, a lookup that never finishes, a mixed answer.

struct TestResolver;

impl Resolver for TestResolver {
    fn resolve<'a>(&'a self, host: &'a str, _port: u16) -> ResolveFuture<'a> {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        match host {
            FIXTURE_HOST => Box::pin(async move { Ok(vec![ip("127.0.0.1")]) }),
            "empty.test" => Box::pin(async { Ok(Vec::new()) }),
            "hang.test" => Box::pin(std::future::pending()),
            "mixed.test" => Box::pin(async move { Ok(vec![ip("93.184.216.34"), ip("10.0.0.1")]) }),
            "mapped.test" => Box::pin(async move { Ok(vec![ip("::ffff:127.0.0.1")]) }),
            other => {
                let err = ResolveError::new(format!("test: no such host {other}"));
                Box::pin(async move { Err(err) })
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Raw TCP server.

#[derive(Clone, Default)]
struct Stats {
    /// Bytes the server managed to hand to the kernel (all connections).
    written: Arc<AtomicU64>,
    /// Request heads received, in order.
    requests: Arc<Mutex<Vec<String>>>,
}

impl Stats {
    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

/// One accepted connection, after its request head was read.
struct Conn {
    stream: TcpStream,
    stats: Stats,
    /// Request target (path) of the request line.
    path: String,
    port: u16,
}

impl Conn {
    /// Write `bytes`; `false` once the client has gone away.
    async fn send(&mut self, bytes: &[u8]) -> bool {
        if self.stream.write_all(bytes).await.is_err() {
            return false;
        }
        self.stats
            .written
            .fetch_add(bytes.len() as u64, Ordering::SeqCst);
        true
    }

    /// Write `bytes` forever (until the client disconnects).
    async fn send_forever(&mut self, bytes: &[u8]) {
        while self.send(bytes).await {}
    }

    /// Write `bytes` one byte at a time, `every` apart, forever.
    async fn trickle_forever(&mut self, bytes: &[u8], every: Duration) {
        for byte in bytes.iter().cycle() {
            if !self.send(&[*byte]).await {
                return;
            }
            tokio::time::sleep(every).await;
        }
    }

    /// Write `bytes` repeatedly until exactly `budget` bytes were sent, then keep the connection
    /// open without sending anything more. A client that has not rejected the response by the
    /// time `budget` bytes arrived would wait for the deadline, so a fast, non-timeout error
    /// proves the client stopped buffering at most `budget` bytes on its own.
    async fn send_then_stall(&mut self, bytes: &[u8], budget: u64) {
        let mut left = budget;
        while left > 0 {
            let take = usize::try_from(left).unwrap().min(bytes.len());
            if !self.send(&bytes[..take]).await {
                return;
            }
            left -= take as u64;
        }
        self.stall().await;
    }

    /// Keep the connection open without sending anything.
    async fn stall(&mut self) {
        let mut sink = [0u8; 64];
        // Returns when the client closes its side.
        while matches!(self.stream.read(&mut sink).await, Ok(n) if n > 0) {}
    }
}

async fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 64 * 1024 {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => head.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

async fn serve<F, Fut>(handler: F) -> (SocketAddr, Stats)
where
    F: Fn(Conn) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Stats::default();
    let handler = Arc::new(handler);
    let server_stats = stats.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let handler = handler.clone();
            let stats = server_stats.clone();
            tokio::spawn(async move {
                let head = read_head(&mut stream).await;
                let path = head.split(' ').nth(1).unwrap_or_default().to_owned();
                stats.requests.lock().unwrap().push(head);
                handler(Conn {
                    stream,
                    stats,
                    path,
                    port: addr.port(),
                })
                .await;
            });
        }
    });
    (addr, stats)
}

// ---------------------------------------------------------------------------------------------
// Client side: the production fetcher, short limits.

struct Client {
    guard: UrlGuard,
    fetcher: HttpFetcher,
    limits: FetchLimits,
    port: u16,
}

fn config() -> FetchConfig {
    FetchConfig {
        connect_timeout: CONNECT_TIMEOUT,
        request_timeout: REQUEST_TIMEOUT,
        max_page_bytes: PAGE_LIMIT,
        max_json_bytes: PAGE_LIMIT,
        ..FetchConfig::default()
    }
}

fn client(addr: SocketAddr) -> Client {
    client_with(addr, config())
}

fn client_with(addr: SocketAddr, cfg: FetchConfig) -> Client {
    let guard = UrlGuard::new(&NetworkConfig::default(), Arc::new(TestResolver))
        .unwrap()
        .with_test_fixture(FIXTURE_HOST, addr)
        .unwrap();
    Client {
        fetcher: HttpFetcher::new(&cfg, guard.clone()),
        guard,
        limits: FetchLimits::from(&cfg),
        port: addr.port(),
    }
}

impl Client {
    /// Fetch `path` on the raw server; returns the result and how long it took.
    async fn fetch(&self, path: &str) -> (Result<FetchedResponse, FetchError>, Duration) {
        let url = format!("http://{FIXTURE_HOST}:{}{path}", self.port);
        let target = self.guard.validate(&url).await.unwrap();
        let started = Instant::now();
        let result = self
            .fetcher
            .fetch(FetchRequest {
                target,
                limits: self.limits,
            })
            .await;
        (result, started.elapsed())
    }
}

/// Serve `handler` and fetch `/` once; asserts the fetch ended within the deadline.
async fn attack<F, Fut>(handler: F) -> (Result<FetchedResponse, FetchError>, Stats)
where
    F: Fn(Conn) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (result, stats, _) = attack_with(config(), handler).await;
    (result, stats)
}

/// [`attack`] with a custom fetch configuration; also returns how long the fetch took.
async fn attack_with<F, Fut>(
    cfg: FetchConfig,
    handler: F,
) -> (Result<FetchedResponse, FetchError>, Stats, Duration)
where
    F: Fn(Conn) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let deadline = cfg.request_timeout;
    let (addr, stats) = serve(handler).await;
    let (result, elapsed) = client_with(addr, cfg).fetch("/").await;
    assert!(
        elapsed <= deadline + MARGIN,
        "fetch took {elapsed:?} ({result:?})"
    );
    (result, stats, elapsed)
}

/// The client rejected the response itself (a protocol error), not by running out of time.
fn assert_rejected_by_client(result: &Result<FetchedResponse, FetchError>) {
    assert!(
        matches!(result, Err(FetchError::Network { .. })),
        "expected the client to reject the response on its own, got {result:?}"
    );
}

fn assert_code(result: &Result<FetchedResponse, FetchError>, codes: &[ErrorCode]) {
    match result {
        Ok(response) => panic!("hostile response accepted: {response:?}"),
        Err(err) => assert!(codes.contains(&err.code()), "{err:?}"),
    }
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn head(extra: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n{extra}\r\n").into_bytes()
}

// ---------------------------------------------------------------------------------------------
// (a) header floods.

// A response head is buffered by hyper up to its own read-buffer cap (~408 KiB, `HYPER_BUF`
// rounded up; reqwest 0.12 exposes no smaller setting) and at most 100 header lines. The server
// sends at most `HYPER_BUF` bytes and then goes silent: only a client that rejects on its own,
// having buffered no more than that, can end the fetch before the deadline.

#[tokio::test]
async fn endless_header_lines_are_refused() {
    let (result, _) = attack(|mut conn| async move {
        if conn.send(b"HTTP/1.1 200 OK\r\n").await {
            conn.send_then_stall(b"X-Flood: aaaaaaaaaaaaaaaa\r\n", HYPER_BUF)
                .await;
        }
    })
    .await;
    assert_rejected_by_client(&result);
}

#[tokio::test]
async fn one_endless_header_value_is_refused() {
    let (result, _) = attack(|mut conn| async move {
        if conn.send(b"HTTP/1.1 200 OK\r\nX-Big: ").await {
            conn.send_then_stall(&[b'a'; 4096], HYPER_BUF).await;
        }
    })
    .await;
    assert_rejected_by_client(&result);
}

#[tokio::test]
async fn endless_interim_1xx_responses_time_out() {
    let (result, _) = attack(|mut conn| async move {
        conn.send_forever(b"HTTP/1.1 100 Continue\r\n\r\n").await;
    })
    .await;
    assert_code(&result, &[ErrorCode::FetchFailed, ErrorCode::FetchTimeout]);
}

// ---------------------------------------------------------------------------------------------
// (b) slowloris.

#[tokio::test]
async fn slowloris_response_head_times_out() {
    let (result, _) = attack(|mut conn| async move {
        if conn.send(b"HTTP/1.1 200 OK\r\n").await {
            conn.trickle_forever(b"X-Slow: a\r\n", Duration::from_millis(200))
                .await;
        }
    })
    .await;
    assert_eq!(result.unwrap_err(), FetchError::Timeout);
}

#[tokio::test]
async fn slowloris_body_times_out() {
    let (result, _) = attack(|mut conn| async move {
        if conn.send(&head("Content-Length: 1000\r\n")).await {
            conn.trickle_forever(b"a", Duration::from_millis(200)).await;
        }
    })
    .await;
    assert_eq!(result.unwrap_err(), FetchError::Timeout);
}

// ---------------------------------------------------------------------------------------------
// (c) chunked abuse.

#[tokio::test]
async fn endless_tiny_chunks_hit_the_byte_cap() {
    // Only the byte cap can end this fetch: the deadline is far away and the server never stops
    // sending 1-byte chunks. The cap is small so the (per-chunk) work stays fast.
    const TINY_LIMIT: u64 = 4 * 1024;
    let cfg = FetchConfig {
        request_timeout: Duration::from_secs(10),
        max_page_bytes: TINY_LIMIT,
        ..config()
    };
    let (result, _, elapsed) = attack_with(cfg, |mut conn| async move {
        if conn.send(&head("Transfer-Encoding: chunked\r\n")).await {
            conn.send_forever(&b"1\r\na\r\n".repeat(512)).await;
        }
    })
    .await;
    match result {
        Err(FetchError::ContentTooLarge {
            limit,
            peak_buffered_bytes,
        }) => {
            assert_eq!(limit, TINY_LIMIT);
            // Everything accepted so far plus the one 1-byte chunk that crossed the cap.
            assert!(
                (TINY_LIMIT..=TINY_LIMIT + 1).contains(&peak_buffered_bytes),
                "{peak_buffered_bytes}"
            );
        }
        other => panic!("expected CONTENT_TOO_LARGE from the byte cap, got {other:?}"),
    }
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
}

#[tokio::test]
async fn endless_chunk_size_line_is_refused() {
    // hyper refuses a chunk size that overflows 64 bits; 4 KiB of hex digits is far past that.
    let (result, _) = attack(|mut conn| async move {
        if conn.send(&head("Transfer-Encoding: chunked\r\n")).await {
            conn.send_then_stall(&[b'f'; 4096], 4096).await;
        }
    })
    .await;
    assert_rejected_by_client(&result);
}

#[tokio::test]
async fn endless_chunk_extension_is_refused() {
    // hyper caps chunk extensions at 16 KiB, well under the page limit.
    let (result, _) = attack(|mut conn| async move {
        if conn.send(&head("Transfer-Encoding: chunked\r\n")).await && conn.send(b"1;ext=").await {
            conn.send_then_stall(&[b'a'; 4096], HYPER_CHUNK_EXT).await;
        }
    })
    .await;
    assert_rejected_by_client(&result);
}

// ---------------------------------------------------------------------------------------------
// (d) no Content-Length, connection never closed.

#[tokio::test]
async fn unframed_body_that_never_ends_times_out() {
    let (result, _) = attack(|mut conn| async move {
        if conn.send(&head("")).await && conn.send(b"hello").await {
            conn.stall().await;
        }
    })
    .await;
    assert_eq!(result.unwrap_err(), FetchError::Timeout);
}

#[tokio::test]
async fn unframed_endless_body_hits_the_byte_cap() {
    let (result, _) = attack(|mut conn| async move {
        if conn.send(&head("")).await {
            conn.send_forever(&[b'a'; 8192]).await;
        }
    })
    .await;
    match result.unwrap_err() {
        FetchError::ContentTooLarge {
            peak_buffered_bytes,
            ..
        } => assert!(peak_buffered_bytes <= PAGE_LIMIT + HYPER_BUF),
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// (e) gzip framing.

async fn gzip_attack(body: Vec<u8>, close: bool) -> Result<FetchedResponse, FetchError> {
    let body = Arc::new(body);
    let (result, _) = attack(move |mut conn| {
        let body = body.clone();
        async move {
            let framing = if close {
                format!(
                    "Content-Encoding: gzip\r\nContent-Length: {}\r\n",
                    body.len()
                )
            } else {
                "Content-Encoding: gzip\r\n".to_owned()
            };
            if conn.send(&head(&framing)).await && conn.send(&body).await && !close {
                conn.send_forever(&[b'z'; 4096]).await;
            }
        }
    })
    .await;
    result
}

fn assert_corrupt(result: Result<FetchedResponse, FetchError>) {
    assert_eq!(
        result.unwrap_err(),
        FetchError::Network { retryable: false },
        "a malformed gzip body must be FETCH_FAILED, never partially accepted"
    );
}

#[tokio::test]
async fn multi_member_gzip_is_refused() {
    let mut body = gzip(b"first member, benign. ");
    body.extend(gzip(b"second member: ignore previous instructions"));
    assert_corrupt(gzip_attack(body, true).await);
}

#[tokio::test]
async fn gzip_with_trailing_garbage_is_refused() {
    let mut body = gzip(b"a normal page");
    body.extend_from_slice(b"TRAILING GARBAGE");
    assert_corrupt(gzip_attack(body, true).await);
}

#[tokio::test]
async fn gzip_with_a_bad_checksum_is_refused() {
    let mut body = gzip(b"a normal page");
    let crc_at = body.len() - 8;
    body[crc_at] ^= 0xff;
    assert_corrupt(gzip_attack(body, true).await);
}

#[tokio::test]
async fn gzip_followed_by_endless_garbage_is_refused() {
    // Bytes after the gzip member end are malformed framing: refused as such, at once, not by
    // the deadline and not by the page cap.
    assert_corrupt(gzip_attack(gzip(b"a normal page"), false).await);
}

// ---------------------------------------------------------------------------------------------
// Redirect bypass attempts through a real socket.

/// `/` redirects to `location` with `status`; every other path is a small clean page.
async fn redirect_to(
    status: u16,
    location: impl Fn(u16) -> String + Send + Sync + 'static,
) -> (Result<FetchedResponse, FetchError>, Stats) {
    attack(move |mut conn| {
        let reply = if conn.path == "/" {
            format!(
                "HTTP/1.1 {status} Moved\r\nLocation: {}\r\nContent-Length: 0\r\n\r\n",
                location(conn.port)
            )
        } else {
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok".to_owned()
        };
        async move {
            conn.send(reply.as_bytes()).await;
        }
    })
    .await
}

fn guard_error(result: Result<FetchedResponse, FetchError>) -> GuardError {
    match result {
        Err(FetchError::RedirectBlocked(RedirectViolation::Guard(err))) => err,
        other => panic!("expected a guard rejection, got {other:?}"),
    }
}

fn only_root_served(stats: &Stats) {
    let requests = stats.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
}

#[tokio::test]
async fn redirect_to_ipv4_mapped_and_nat64_loopback_is_blocked() {
    for location in [
        "http://[::ffff:127.0.0.1]:{port}/x",
        "http://[::ffff:7f00:1]:{port}/x",
        "http://[::ffff:10.0.0.1]/x",
        "http://[64:ff9b::a9fe:a9fe]/x",
        "http://[::127.0.0.1]:{port}/x",
        "http://[::1]:{port}/x",
    ] {
        let (result, stats) = redirect_to(302, move |port| {
            location.replace("{port}", &port.to_string())
        })
        .await;
        assert!(
            matches!(guard_error(result), GuardError::Ssrf { .. }),
            "{location}"
        );
        only_root_served(&stats);
    }
}

#[tokio::test]
async fn redirect_to_a_name_resolving_to_mapped_loopback_is_blocked() {
    let (result, stats) = redirect_to(302, |port| format!("http://mapped.test:{port}/x")).await;
    assert!(matches!(guard_error(result), GuardError::Ssrf { .. }));
    only_root_served(&stats);
}

#[tokio::test]
async fn location_with_tab_or_bare_cr_cannot_reach_loopback() {
    for location in [
        "http://127.0.\t0.1:{port}/x",
        "http://1\t27.0.0.1:{port}/x",
        "http://fixture.test\t@127.0.0.1:{port}/x",
        "http://127.0.0.1:{port}\r/x",
    ] {
        let (result, stats) = redirect_to(302, move |port| {
            location.replace("{port}", &port.to_string())
        })
        .await;
        assert!(
            matches!(
                result,
                Err(FetchError::RedirectBlocked(_)) | Err(FetchError::Network { .. })
            ),
            "{location:?}: {result:?}"
        );
        only_root_served(&stats);
    }
}

#[tokio::test]
async fn redirect_307_and_308_are_followed_as_bodiless_get() {
    for status in [307, 308] {
        let (result, stats) =
            redirect_to(status, |port| format!("http://{FIXTURE_HOST}:{port}/next")).await;
        let response = result.unwrap();
        assert_eq!(response.body, b"ok");
        let requests = stats.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].starts_with("GET /next "), "{:?}", requests[1]);
        assert!(!requests[1].to_ascii_lowercase().contains("content-length"));
    }
}

#[tokio::test]
async fn redirect_307_to_loopback_literal_is_blocked() {
    let (result, stats) = redirect_to(307, |port| format!("http://127.0.0.1:{port}/x")).await;
    assert!(matches!(guard_error(result), GuardError::Ssrf { .. }));
    only_root_served(&stats);
}

#[tokio::test]
async fn trailing_dot_fixture_host_gets_no_extra_allowance() {
    // `fixture.test.` names the same host; it must not widen the test allowance to another
    // port, and on the fixture's own port it may only reach the fixture itself.
    let (result, stats) = redirect_to(302, |port| {
        format!("http://{FIXTURE_HOST}.:{}/x", port.wrapping_add(1))
    })
    .await;
    assert!(result.is_err(), "{result:?}");
    only_root_served(&stats);
}

#[tokio::test]
async fn fixture_name_on_another_port_is_blocked() {
    let (result, stats) = redirect_to(302, |port| {
        format!("http://{FIXTURE_HOST}:{}/x", port.wrapping_add(1))
    })
    .await;
    assert!(
        matches!(guard_error(result), GuardError::Ssrf { .. }),
        "the allowance is for one socket only"
    );
    only_root_served(&stats);
}

#[tokio::test]
async fn redirect_to_an_empty_dns_answer_is_blocked() {
    let (result, _) = redirect_to(302, |_| "http://empty.test/x".to_owned()).await;
    assert_eq!(guard_error(result), GuardError::DnsFailed);
}

#[tokio::test]
async fn redirect_to_a_hanging_resolver_is_bounded_by_connect_timeout() {
    let (addr, _) = serve(|mut conn| async move {
        conn.send(
            b"HTTP/1.1 302 Found\r\nLocation: http://hang.test/x\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
    })
    .await;
    let (result, elapsed) = client(addr).fetch("/").await;
    assert_eq!(guard_error(result), GuardError::DnsFailed);
    // The hanging lookup ends at connectTimeout (plus scheduling slack), far before the deadline.
    assert!(
        elapsed >= CONNECT_TIMEOUT && elapsed < CONNECT_TIMEOUT + Duration::from_millis(250),
        "DNS must be bounded by connectTimeout ({CONNECT_TIMEOUT:?}): {elapsed:?}"
    );
}

#[tokio::test]
async fn redirect_to_a_mixed_public_private_answer_is_blocked() {
    let (result, _) = redirect_to(302, |_| "http://mixed.test/x".to_owned()).await;
    assert!(matches!(guard_error(result), GuardError::Ssrf { .. }));
}

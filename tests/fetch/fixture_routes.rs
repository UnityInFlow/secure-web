//! The fixture server serves every route in `docs/testing.md`. Checked with a raw TCP client,
//! not the fetcher, so routes the fetcher refuses (private redirects, bombs) are still verified.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../support/fixture_server.rs"]
mod fixture_server;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use fixture_server::canaries;
use fixture_server::{documented_routes, FixtureServer, BLOCKED_LINK_COUNT, HUGE_LINK_COUNT};

/// Response head (status line + headers) and up to `body_limit` body bytes.
struct Raw {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Raw {
    fn header(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

async fn get(server: &FixtureServer, path: &str, body_limit: usize) -> Raw {
    let mut socket = TcpStream::connect(server.addr()).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n");
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let head_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let n = socket.read(&mut chunk).await.unwrap();
        assert!(n > 0, "{path}: connection closed before the response head");
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < body_limit {
        let n = socket.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(body_limit);
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap();
    Raw { status, head, body }
}

#[tokio::test]
async fn every_documented_route_answers() {
    let (_, server) = FixtureServer::start().await;
    for path in documented_routes() {
        if path == "/slow" {
            continue; // covered below: it deliberately does not answer in time
        }
        let raw = get(&server, path, 0).await;
        assert_ne!(raw.status, 404, "{path} is not served");
    }
}

#[tokio::test]
async fn redirect_routes_point_where_the_docs_say() {
    let (_, server) = FixtureServer::start().await;
    let port = server.addr().port();
    let location = |raw: Raw| {
        assert_eq!(raw.status, 302);
        raw.header("Location").unwrap()
    };
    assert_eq!(
        location(get(&server, "/redirect/private", 0).await),
        format!("http://127.0.0.1:{port}/clean/a")
    );
    assert_eq!(
        location(get(&server, "/redirect/metadata", 0).await),
        "http://169.254.169.254/latest/meta-data/"
    );
    assert_eq!(
        location(get(&server, "/redirect/loop", 0).await),
        "/redirect/loop"
    );
    assert_eq!(
        location(get(&server, "/redirect/chain/2", 0).await),
        "/redirect/chain/1"
    );
    assert_eq!(
        location(get(&server, "/redirect/chain/1", 0).await),
        "/clean/a"
    );
    assert_eq!(get(&server, "/redirect/chain/0", 0).await.status, 200);
    assert!(location(get(&server, "/redirect/downgrade", 0).await).starts_with("http://"));
}

#[tokio::test]
async fn content_routes_have_the_documented_shape() {
    let (_, server) = FixtureServer::start().await;

    let injection = [
        ("/injection/direct", canaries::CANARY_DIRECT),
        ("/injection/hidden-css", canaries::CANARY_HIDDEN),
        ("/injection/comment", canaries::CANARY_COMMENT),
        ("/injection/title", canaries::CANARY_TITLE),
        ("/injection/alt", canaries::CANARY_ALT),
        ("/injection/json", canaries::CANARY_JSON),
    ];
    for (path, canary) in injection {
        assert!(
            get(&server, path, 1 << 20).await.text().contains(canary),
            "{path}"
        );
    }
    // The base64 route carries its canary only in encoded form.
    let b64 = get(&server, "/injection/base64", 1 << 20).await.text();
    assert!(!b64.contains(canaries::CANARY_B64));
    assert!(get(&server, "/injection/json", 0)
        .await
        .header("Content-Type")
        .unwrap()
        .starts_with("application/json"));

    let dup_a = get(&server, "/dup/a", 1 << 20).await.body;
    assert_eq!(dup_a, get(&server, "/dup/b", 1 << 20).await.body);

    let huge_links = get(&server, "/links/huge", 16 << 20).await.text();
    assert_eq!(huge_links.matches("<a href=").count(), HUGE_LINK_COUNT);

    let blocked = get(&server, "/blocked-with-links", 1 << 20).await.text();
    assert!(blocked.contains(canaries::CANARY_DIRECT));
    assert_eq!(
        blocked.matches("<a href=\"/clean/").count(),
        BLOCKED_LINK_COUNT
    );

    let depth = get(&server, "/depth/3", 1 << 20).await.text();
    assert!(depth.contains("/depth/4"));
    let link_c = get(&server, "/link/c", 1 << 20).await.text();
    assert!(link_c.contains("mailto:") && link_c.contains("127.0.0.1") && link_c.contains("#"));

    let teapot = get(&server, "/status/418", 0).await;
    assert_eq!(teapot.status, 418);
    assert_eq!(
        get(&server, "/mime/pdf", 0)
            .await
            .header("Content-Type")
            .unwrap(),
        "application/pdf"
    );
    assert_eq!(
        get(&server, "/mime/zip", 0)
            .await
            .header("Content-Type")
            .unwrap(),
        "application/zip"
    );
}

#[tokio::test]
async fn bomb_routes_are_large_and_the_slow_route_is_slow() {
    let (_, server) = FixtureServer::start().await;
    let huge = get(&server, "/huge", 8 << 20).await;
    assert_eq!(huge.body.len(), 8 << 20, "/huge streams well past 5 MB");
    assert_eq!(huge.header("Content-Length"), None);

    let bomb = get(&server, "/gzip-bomb", 1 << 20).await;
    assert_eq!(bomb.header("Content-Encoding").as_deref(), Some("gzip"));
    assert!(bomb.body.len() < 64 * 1024, "the compressed bomb is small");

    let slow = tokio::time::timeout(Duration::from_millis(300), get(&server, "/slow", 0)).await;
    assert!(slow.is_err(), "/slow must not answer quickly");
}

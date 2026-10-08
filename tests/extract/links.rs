//! Link extraction (PR-04 brief): resolved against the final URL, `http(s)` only, fragment-free,
//! deduplicated in document order, capped at `extract.maxLinksPerPage`.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../support/extract.rs"]
mod extract;

use extract::fetch::fixture_server::HUGE_LINK_COUNT;
use extract::{extract_html, fetch_extract, input, Harness};
use secure_web_core::config::ExtractConfig;
use secure_web_core::model::DiscoveredLink;
use secure_web_extract::markdown::render;
use secure_web_extract::{ContentExtractor, ExtractLimits, Extractor};

fn strings(links: &[DiscoveredLink]) -> Vec<String> {
    links.iter().map(|l| l.url.to_string()).collect()
}

#[tokio::test]
async fn link_c_keeps_only_absolute_http_links() {
    let harness = Harness::start().await;
    let doc = fetch_extract(&harness, "/link/c").await;
    let port = harness.server.addr().port();
    // mailto: and the fragment-only link are dropped; the private-address link is kept here
    // (the URL guard refuses it at fetch time, not the extractor).
    assert_eq!(
        strings(&doc.links),
        [
            "https://example.com/external".to_owned(),
            format!("http://127.0.0.1:{port}/clean/a"),
        ]
    );
    assert!(!doc.links_truncated);
}

#[tokio::test]
async fn link_a_resolves_relative_links_against_the_final_url() {
    let harness = Harness::start().await;
    let doc = fetch_extract(&harness, "/link/a").await;
    assert_eq!(
        strings(&doc.links),
        [harness.url("/link/b"), harness.url("/link/c")]
    );
    let markdown = render(&doc.display);
    assert!(markdown.contains(&format!("[link 0]({})", harness.url("/link/b"))));
}

/// The extraction work on this page (link bookkeeping stops at the cap, every walk is linear)
/// is bounded by counting it, not timing it: `links_huge_is_capped_with_linear_work` in
/// `secure-web-extract` (`src/html.rs` tests) runs the same page with the crate's test-only
/// work counters, which an integration test cannot reach.
#[tokio::test]
async fn links_huge_is_capped() {
    let harness = Harness::start().await;
    let resp = harness.fetch("/links/huge").await.unwrap();
    // Default config (brief PR-04): the link cap applies, and the page still fits every other
    // default limit, `extract.maxSecurityTextBytes` included.
    let limits = ExtractLimits::default();
    let doc = ContentExtractor::new(limits)
        .extract(&input(&resp))
        .unwrap();
    assert!(doc.security_text.len() <= limits.max_security_text_bytes);
    let cap = ExtractConfig::default().max_links_per_page as usize;
    assert!(HUGE_LINK_COUNT > cap);
    assert_eq!(doc.links.len(), cap);
    assert!(doc.links_truncated);
    assert_eq!(doc.links[0].url.as_str(), harness.url("/clean/page-0"));
    assert_eq!(
        doc.links[cap - 1].url.as_str(),
        harness.url(&format!("/clean/page-{}", cap - 1))
    );
    // Display links only to kept URLs; the rest of the anchors stay as plain text.
    let markdown = render(&doc.display);
    assert_eq!(markdown.matches("](http").count(), cap);
    assert!(markdown.contains(&format!("link {}", HUGE_LINK_COUNT - 1)));
}

#[test]
fn links_are_normalized_deduplicated_and_filtered() {
    let doc = extract_html(
        "<a href=\"/a#x\">1</a><a href=\"/a#y\">2</a><a href=\" /b \">3</a>\
         <a href=\"#top\">4</a><a href=\"javascript:alert(1)\">5</a><a href=\"mailto:x@y.z\">6</a>\
         <a href=\"data:text/html,x\">7</a><a href=\"ftp://example.com/f\">8</a>\
         <a href=\"https://user:pw@example.com/\">9</a><a href=\"//cdn.example.com/c\">10</a>\
         <a>no href</a><area href=\"/map\"><a href=\"HTTPS://EXAMPLE.COM/Up\">11</a>\
         <div style=\"display:none\"><a href=\"/trap\">trap</a></div>\
         <template><a href=\"/tpl\">t</a></template>",
    );
    assert_eq!(
        strings(&doc.links),
        [
            "http://fixture.test/a",
            "http://fixture.test/b",
            "http://cdn.example.com/c",
            "http://fixture.test/map",
            "https://example.com/Up",
        ]
    );
}

#[test]
fn navigation_links_are_crawlable_even_though_nav_is_not_displayed() {
    let doc = extract_html(
        "<nav><a href=\"/docs\">Docs</a></nav><main><p><a href=\"/guide\">Guide</a></p></main>",
    );
    assert_eq!(
        strings(&doc.links),
        ["http://fixture.test/docs", "http://fixture.test/guide"]
    );
    assert_eq!(render(&doc.display), "[Guide](http://fixture.test/guide)\n");
}

#[test]
fn the_cap_counts_distinct_links() {
    let limits = ExtractLimits {
        max_links_per_page: 2,
        ..ExtractLimits::default()
    };
    let body = "<a href=\"/a\">a</a><a href=\"/a\">a</a><a href=\"/b\">b</a>";
    let doc = extract::extract_str(
        body,
        secure_web_extract::SourceKind::Html,
        "http://fixture.test/",
        limits,
    )
    .unwrap();
    assert_eq!(doc.links.len(), 2);
    assert!(!doc.links_truncated);
    let body = format!("{body}<a href=\"/c\">c</a>");
    let doc = extract::extract_str(
        &body,
        secure_web_extract::SourceKind::Html,
        "http://fixture.test/",
        limits,
    )
    .unwrap();
    assert_eq!(doc.links.len(), 2);
    assert!(doc.links_truncated);
    assert_eq!(
        render(&doc.display),
        "[a](http://fixture.test/a)[a](http://fixture.test/a)[b](http://fixture.test/b)c\n"
    );
}

#[test]
fn many_links_with_large_visible_text_fit_or_fail_closed() {
    // /links/huge plus a paragraph of visible text: under the default cap the page either fits
    // with every model-facing string scanned, or fails as CONTENT_TOO_LARGE.
    let anchors: String = (0..HUGE_LINK_COUNT)
        .map(|i| format!("<a href=\"/clean/page-{i}\">link {i}</a>\n"))
        .collect();
    for (words, fits) in [(30_000, true), (200_000, false)] {
        let body = format!(
            "<html><head><title>Many links</title></head><body>{anchors}<p>{}</p></body></html>",
            "visible words ".repeat(words / 2)
        );
        let result = extract::extract_str(
            &body,
            secure_web_extract::SourceKind::Html,
            "http://fixture.test/links/huge",
            ExtractLimits::default(),
        );
        match result {
            Ok(doc) => {
                assert!(fits, "{words} words fit");
                assert!(
                    doc.security_text.len() <= ExtractLimits::default().max_security_text_bytes
                );
                assert!(doc.security_text.contains(&render(&doc.display)));
                // Every link is a whole line (so a substring) of security_text.
                let lines: std::collections::HashSet<&str> = doc.security_text.lines().collect();
                assert!(doc.links.iter().all(|l| lines.contains(l.url.as_str())));
                assert!(doc.security_text.contains("Many links"));
            }
            Err(err) => {
                assert!(!fits, "{words} words: {err:?}");
                assert!(matches!(
                    err,
                    secure_web_extract::ExtractError::SecurityTextTooLarge { .. }
                ));
            }
        }
    }
}

/// Carried over from PR-07 (`docs/backlog.md`): a link keeps the text the guard must validate.
/// Parsing rewrites a non-canonical IPv4 spelling and drops an empty userinfo `@`, so the
/// guard's raw-text rules only work on the href **as written** (resolved against the base when
/// it names no authority of its own; fragment cut).
#[test]
fn links_keep_their_href_as_written_for_the_guard() {
    let doc = extract_html(
        "<a href=\"http://1572395042/a#f\">1</a>\
         <a href=\"//@example.com/x\">2</a>\
         <a href=\"\\\\0x7f.1/y\">3</a>\
         <a href=\" http://@fixture.test/b \">4</a>\
         <a href=\"/rel?q=1#frag\">5</a>\
         <a href=\"HTTPS://Example.COM/Up\">6</a>",
    );
    let pairs: Vec<(String, String)> = doc
        .links
        .iter()
        .map(|l| (l.url.to_string(), l.as_written.clone()))
        .collect();
    assert_eq!(
        pairs,
        [
            (
                "http://93.184.216.34/a".to_owned(),
                "http://1572395042/a".to_owned()
            ),
            (
                "http://example.com/x".to_owned(),
                "http://@example.com/x".to_owned()
            ),
            (
                "http://127.0.0.1/y".to_owned(),
                "http:\\\\0x7f.1/y".to_owned()
            ),
            (
                "http://fixture.test/b".to_owned(),
                "http://@fixture.test/b".to_owned()
            ),
            (
                "http://fixture.test/rel?q=1".to_owned(),
                "http://fixture.test/rel?q=1".to_owned()
            ),
            (
                "https://example.com/Up".to_owned(),
                "HTTPS://Example.COM/Up".to_owned()
            ),
        ]
    );
    // `Debug` never prints a path, query or the text as written.
    let debug = format!("{:?}", doc.links);
    assert!(!debug.contains("1572395042"), "{debug}");
    assert!(!debug.contains("/rel"), "{debug}");
}

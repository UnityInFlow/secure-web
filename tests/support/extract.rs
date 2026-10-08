//! Extraction test harness: fetch a fixture route through the real fetcher (fixture server +
//! stub DNS, `support/fetch.rs`) and extract it, or extract a corpus file directly.
#![allow(dead_code)]

#[path = "fetch.rs"]
pub mod fetch;

use std::path::Path;

use secure_web_extract::{
    ContentExtractor, ExtractError, ExtractInput, ExtractLimits, ExtractedDocument, Extractor,
    SourceKind,
};
use secure_web_fetch::{ContentType, FetchedResponse};
use url::Url;

#[allow(unused_imports)]
pub use fetch::fixture_server::canaries;
pub use fetch::Harness;

/// The extractor input for a fetched response.
pub fn input(resp: &FetchedResponse) -> ExtractInput<'_> {
    let kind = match &resp.content_type {
        ContentType::Html => SourceKind::Html,
        ContentType::PlainText => SourceKind::PlainText,
        ContentType::Markdown => SourceKind::Markdown,
        ContentType::Json => SourceKind::Json,
        ContentType::Unsupported(essence) => panic!("unsupported content type {essence}"),
    };
    ExtractInput {
        final_url: &resp.final_url,
        kind,
        charset: resp.charset.as_deref(),
        body: &resp.body,
    }
}

/// Fetch `path` from the fixture server and extract it with `limits`.
pub async fn fetch_extract_with(
    harness: &Harness,
    path: &str,
    limits: ExtractLimits,
) -> Result<ExtractedDocument, ExtractError> {
    let resp = harness.fetch(path).await.unwrap();
    ContentExtractor::new(limits).extract(&input(&resp))
}

/// Fetch `path` and extract it with the default limits.
pub async fn fetch_extract(harness: &Harness, path: &str) -> ExtractedDocument {
    fetch_extract_with(harness, path, ExtractLimits::default())
        .await
        .unwrap()
}

/// Source kind of a corpus file, from its extension.
pub fn kind_for(path: &Path) -> SourceKind {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => SourceKind::Html,
        Some("md") => SourceKind::Markdown,
        Some("txt") => SourceKind::PlainText,
        Some("json") => SourceKind::Json,
        other => panic!("no source kind for extension {other:?}"),
    }
}

/// Extract an in-memory body as if served at `url`.
pub fn extract_str(
    body: &str,
    kind: SourceKind,
    url: &str,
    limits: ExtractLimits,
) -> Result<ExtractedDocument, ExtractError> {
    let url = Url::parse(url).unwrap();
    ContentExtractor::new(limits).extract(&ExtractInput {
        final_url: &url,
        kind,
        charset: Some("utf-8"),
        body: body.as_bytes(),
    })
}

/// Extract an HTML string served at `http://fixture.test/page` with default limits.
pub fn extract_html(body: &str) -> ExtractedDocument {
    extract_str(
        body,
        SourceKind::Html,
        "http://fixture.test/page",
        ExtractLimits::default(),
    )
    .unwrap()
}

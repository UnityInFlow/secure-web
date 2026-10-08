//! Content-hash dedupe (deep-dive §45): `/dup/a` and `/dup/b` serve byte-identical content
//! under different URLs → one page file, two manifest entries, the second `duplicateOf` the
//! first and pointing at its file.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

#[path = "../support/store.rs"]
mod store;

use secure_web_store::{RunStats, RunStatus};
use store::scanner::extract::input;
use store::scanner::untrusted;
use store::{files_under, record, scan, spec, store_at, stub_scanner, Harness};

#[tokio::test]
async fn identical_content_is_stored_once() {
    let harness = Harness::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let scanner = stub_scanner("canary").await;
    let store = store_at(tmp.path());
    let writer = store
        .begin_run(spec("crawl_00000000d0d0", &harness.url("/"), &scanner))
        .await
        .unwrap();

    for path in ["/dup/a", "/dup/b"] {
        let resp = harness.fetch(path).await.unwrap();
        let extracted = secure_web_extract::Extractor::extract(
            &secure_web_extract::ContentExtractor::new(Default::default()),
            &input(&resp),
        )
        .unwrap();
        let id = writer.next_doc_id().unwrap();
        let page = scan(&scanner, untrusted(&resp, extracted), id, 1).await;
        assert!(page.outcome.is_ok(), "{path}");
        record(&writer, &page, 1).await;
    }
    let manifest = writer
        .finish(RunStatus::Complete, RunStats::default())
        .await
        .unwrap();

    let run_dir = tmp.path().join("runs/crawl_00000000d0d0");
    assert_eq!(files_under(&run_dir.join("pages")).len(), 1);
    assert_eq!(files_under(&run_dir.join("metadata")).len(), 2);
    let [a, b] = manifest.documents.as_slice() else {
        panic!("expected two entries");
    };
    assert!(a.url.path().ends_with("/dup/a"));
    assert!(b.url.path().ends_with("/dup/b"));
    assert_eq!(a.duplicate_of, None);
    assert_eq!(b.duplicate_of.as_ref(), Some(&a.id));
    assert_eq!(b.path, a.path);
    assert_eq!(b.content_hash, a.content_hash);
    assert_eq!(manifest.stats.safe, 2);
}

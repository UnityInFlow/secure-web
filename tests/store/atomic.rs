//! Atomic writes and checkpoints (`docs/contracts/manifest-schema.md`): a run that is dropped
//! (killed, cancelled without `finish`) still leaves a valid manifest — the last checkpoint —
//! whose paths all exist, and no temp files.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

#[path = "../support/store.rs"]
mod store;

use std::path::Path;

use secure_web_store::{Manifest, RunStats, RunStatus, StoreError, CHECKPOINT_EVERY};
use store::{add_html, files_under, spec, store_at, stub_scanner};

const RUN: &str = "crawl_0000000a70c1";

fn load(run_dir: &Path) -> Manifest {
    let text = std::fs::read_to_string(run_dir.join("manifest.json")).unwrap();
    serde_json::from_str::<serde_json::Value>(&text).expect("manifest is valid JSON");
    Manifest::load(&run_dir.join("manifest.json")).unwrap()
}

fn assert_consistent(run_dir: &Path, manifest: &Manifest) {
    for doc in &manifest.documents {
        assert!(run_dir.join(&doc.path).is_file(), "{}", doc.path);
        let meta = run_dir.join(format!("metadata/{:06}.json", doc.seq));
        assert!(meta.is_file(), "{}", meta.display());
    }
    for file in files_under(run_dir) {
        let name = file.file_name().unwrap().to_string_lossy();
        assert!(!name.ends_with(".tmp") && !name.starts_with('.'), "{name}");
    }
}

#[tokio::test]
async fn dropped_writer_leaves_the_last_checkpoint() {
    let tmp = tempfile::tempdir().unwrap();
    let scanner = stub_scanner("canary").await;
    let store = store_at(tmp.path());
    let writer = store
        .begin_run(spec(RUN, "http://fixture.test/", &scanner))
        .await
        .unwrap();
    let run_dir = writer.run_dir().to_path_buf();

    // The run starts with a valid, empty RUNNING manifest.
    let initial = load(&run_dir);
    assert_eq!(initial.status, RunStatus::Running);
    assert!(initial.finished_at.is_none());
    assert!(initial.documents.is_empty());

    let total = CHECKPOINT_EVERY + 5;
    for i in 1..=total {
        add_html(
            &writer,
            &scanner,
            &format!("http://fixture.test/page/{i}"),
            &format!("<title>Page {i}</title><p>Content {i}.</p>"),
            1,
        )
        .await;
        if i == CHECKPOINT_EVERY - 1 {
            assert!(
                load(&run_dir).documents.is_empty(),
                "no checkpoint before 25"
            );
        }
    }

    // Kill the run: drop the writer without finishing.
    drop(writer);
    let manifest = load(&run_dir);
    assert_eq!(manifest.status, RunStatus::Running);
    assert!(manifest.finished_at.is_none());
    assert_eq!(manifest.documents.len(), CHECKPOINT_EVERY as usize);
    assert_eq!(manifest.stats.safe, u64::from(CHECKPOINT_EVERY));
    assert_consistent(&run_dir, &manifest);
    // Pages written after the checkpoint exist on disk but are not listed.
    assert_eq!(files_under(&run_dir.join("pages")).len(), total as usize);
    let summary: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(run_dir.join("security/summary.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(summary["status"], "RUNNING");
}

#[tokio::test]
async fn explicit_checkpoint_and_finish() {
    let tmp = tempfile::tempdir().unwrap();
    let scanner = stub_scanner("canary").await;
    let store = store_at(tmp.path());
    let writer = store
        .begin_run(spec(RUN, "http://fixture.test/", &scanner))
        .await
        .unwrap();
    let run_dir = writer.run_dir().to_path_buf();
    add_html(&writer, &scanner, "http://fixture.test/", "<p>One.</p>", 0).await;
    writer.checkpoint().await.unwrap();
    assert_eq!(load(&run_dir).documents.len(), 1);

    let stats = RunStats {
        discovered: 40,
        fetched: 1,
        total_bytes: 1,
        safe: 99, // recomputed by the store
        ..RunStats::default()
    };
    let manifest = writer.finish(RunStatus::LimitReached, stats).await.unwrap();
    assert_eq!(manifest.status, RunStatus::LimitReached);
    assert_eq!(manifest.stats.discovered, 40);
    assert_eq!(manifest.stats.safe, 1);
    assert!(manifest.stats.total_bytes > 1);
    assert_eq!(load(&run_dir), manifest);
    assert_consistent(&run_dir, &manifest);
}

#[tokio::test]
async fn concurrent_records_are_serialized() {
    let tmp = tempfile::tempdir().unwrap();
    let scanner = stub_scanner("canary").await;
    let store = store_at(tmp.path());
    let writer = store
        .begin_run(spec(RUN, "http://fixture.test/", &scanner))
        .await
        .unwrap();
    let run_dir = writer.run_dir().to_path_buf();
    let writer = std::sync::Arc::new(writer);
    let scanner = std::sync::Arc::new(scanner);
    let handles: Vec<_> = (1..=8)
        .map(|i| {
            let (writer, scanner) = (writer.clone(), scanner.clone());
            tokio::spawn(async move {
                add_html(
                    &writer,
                    &scanner,
                    &format!("http://fixture.test/c/{i}"),
                    &format!("<p>Concurrent {i}.</p>"),
                    1,
                )
                .await;
            })
        })
        .collect();
    for handle in handles {
        handle.await.unwrap();
    }
    let writer = std::sync::Arc::try_unwrap(writer).unwrap();
    let manifest = writer
        .finish(RunStatus::Complete, RunStats::default())
        .await
        .unwrap();
    assert_eq!(manifest.documents.len(), 8);
    assert_consistent(&run_dir, &manifest);
    let err = store
        .begin_run(spec(RUN, "http://fixture.test/", &scanner))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::RunExists));
}

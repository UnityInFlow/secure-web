//! Extraction determinism (`docs/contracts/manifest-schema.md`, "Page file format"): every file
//! under `tests/corpus/clean/**` renders to its committed snapshot in
//! `tests/corpus/snapshots/<dir>/<file>.snap`, and rendering is byte-identical run to run.
//!
//! New or changed snapshots: `INSTA_UPDATE=always cargo test --test corpus_snapshots`, then
//! review the `.snap` diff. CI never writes snapshots (a missing one fails).
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../support/extract.rs"]
mod extract;

use std::path::{Path, PathBuf};

use extract::{extract_str, kind_for};
use pulldown_cmark::{Event, Parser};
use secure_web_extract::markdown::render;
use secure_web_extract::ExtractLimits;

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/clean")
}

/// Every clean fixture, sorted, as (directory name, file path).
fn clean_fixtures() -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for dir in std::fs::read_dir(corpus_root()).unwrap() {
        let dir = dir.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        let dir_name = dir.file_name().unwrap().to_string_lossy().into_owned();
        for file in std::fs::read_dir(&dir).unwrap() {
            let file = file.unwrap().path();
            if file.is_file() {
                out.push((dir_name.clone(), file));
            }
        }
    }
    out.sort();
    assert!(out.len() >= 4, "clean corpus is missing");
    out
}

/// The page as the fixture server would serve it (`/clean/<stem>`), at a fixed origin so the
/// absolute links in the snapshot do not depend on the ephemeral port.
fn render_fixture(path: &Path) -> String {
    let body = std::fs::read_to_string(path).unwrap();
    let stem = path.file_stem().unwrap().to_string_lossy();
    let url = format!("http://fixture.test/clean/{stem}");
    let doc = extract_str(&body, kind_for(path), &url, ExtractLimits::default()).unwrap();
    let title = doc.title.as_deref().unwrap_or("(none)");
    format!("title: {title}\n---\n{}", render(&doc.display))
}

#[test]
fn clean_corpus_matches_snapshots() {
    for (dir, path) in clean_fixtures() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let mut settings = insta::Settings::clone_current();
        settings.set_snapshot_path(format!("../corpus/snapshots/{dir}"));
        settings.set_prepend_module_to_snapshot(false);
        settings.set_omit_expression(true);
        settings.set_input_file(&path);
        settings.bind(|| insta::assert_snapshot!(name.clone(), render_fixture(&path)));
    }
}

#[test]
fn rendering_is_byte_deterministic() {
    for (_, path) in clean_fixtures() {
        let first = render_fixture(&path);
        for _ in 0..3 {
            assert_eq!(render_fixture(&path), first, "{}", path.display());
        }
    }
}

#[test]
fn rendered_corpus_has_no_raw_html_and_clean_whitespace() {
    for (_, path) in clean_fixtures() {
        let rendered = render_fixture(&path);
        let markdown = rendered.split_once("---\n").unwrap().1;
        for event in Parser::new(markdown) {
            assert!(
                !matches!(event, Event::Html(_) | Event::InlineHtml(_)),
                "{}: raw HTML {event:?}",
                path.display()
            );
        }
        assert!(!markdown.contains('\r'));
        assert!(markdown.is_empty() || markdown.ends_with('\n'));
        assert!(!markdown.ends_with("\n\n"));
        for line in markdown.lines() {
            assert_eq!(
                line,
                line.trim_end(),
                "{}: trailing whitespace",
                path.display()
            );
        }
    }
}

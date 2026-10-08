//! Threat T13 (`docs/security-policy.md` §7, ADR-015): page-derived strings never choose a
//! path. Hostile titles and URL paths (`../`, NUL, RTL overrides, 5 000 characters, empty) end
//! up as `pages/NNNNNN[-slug].md` inside the run directory; the store never writes through a
//! symbolic link, never reopens a run, and keeps the private-audit root out of `runs/`.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

#[path = "../support/store.rs"]
mod store;

use std::path::{Path, PathBuf};

use secure_web_core::config::WarnHandling;
use secure_web_store::{FsCorpusStore, Manifest, RunStats, RunStatus, StoreError, StoreOptions};
use store::{add_html, files_under, spec, store_at, stub_scanner};

const RUN: &str = "crawl_00000000beef";

/// `pages/` + six digits + an optional `[a-z0-9]` slug in single-hyphen runs of ≤ 48 chars.
fn is_contract_page_path(path: &str) -> bool {
    let Some(name) = path.strip_prefix("pages/") else {
        return false;
    };
    let Some(stem) = name.strip_suffix(".md") else {
        return false;
    };
    let (digits, slug) = stem.split_at(6.min(stem.len()));
    digits.len() == 6
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (slug.is_empty()
            || slug.strip_prefix('-').is_some_and(|slug| {
                slug.len() <= 48
                    && slug.split('-').all(|w| {
                        !w.is_empty()
                            && w.bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                    })
            }))
}

#[tokio::test]
async fn hostile_titles_and_urls_stay_inside_the_run() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(tmp.path()).unwrap();
    let scanner = stub_scanner("canary").await;
    let store = store_at(&workspace);
    let writer = store
        .begin_run(spec(RUN, "http://fixture.test/", &scanner))
        .await
        .unwrap();

    let long = "A".repeat(5_000);
    let cases: Vec<(String, String)> = vec![
        (
            "http://fixture.test/a".into(),
            "../../../../etc/passwd".into(),
        ),
        (
            "http://fixture.test/b".into(),
            "..\\..\\windows\\system32".into(),
        ),
        (
            "http://fixture.test/c".into(),
            "nul\u{0}byte\u{0}title".into(),
        ),
        (
            "http://fixture.test/d".into(),
            "\u{202E}gnp.exe\u{202C} rtl".into(),
        ),
        ("http://fixture.test/e".into(), long.clone()),
        ("http://fixture.test/f".into(), String::new()),
        ("http://fixture.test/g".into(), "   \u{200B}  ".into()),
        ("http://fixture.test/h".into(), "....".into()),
        ("http://fixture.test/i".into(), "/absolute/path".into()),
        (
            "http://fixture.test/..%2F..%2Fetc%2Fpasswd".into(),
            String::new(),
        ),
        ("http://fixture.test/%00%E2%80%AE/x".into(), "日本語".into()),
        (
            format!("http://fixture.test/{}", "p/".repeat(2_000)),
            String::new(),
        ),
    ];
    for (i, (url, title)) in cases.iter().enumerate() {
        let title_html = html_escape(title);
        let html = format!("<title>{title_html}</title><p>Body number {i}.</p>");
        let page = add_html(&writer, &scanner, url, &html, 1).await;
        let accepted = page.outcome.as_ref().unwrap();
        // The stored title is the scanned, normalized one (≤ 200 chars, no controls).
        if let Some(stored) = accepted.title() {
            assert!(stored.chars().count() <= 200);
            assert!(!stored.chars().any(|c| c.is_control() || c == '\u{202E}'));
        }
    }
    let manifest = writer
        .finish(RunStatus::Complete, RunStats::default())
        .await
        .unwrap();
    assert_eq!(manifest.documents.len(), cases.len());

    let run_dir = workspace.join("runs").join(RUN);
    for doc in &manifest.documents {
        assert!(is_contract_page_path(&doc.path), "{}", doc.path);
        let file = std::fs::canonicalize(run_dir.join(&doc.path)).unwrap();
        assert!(
            file.starts_with(run_dir.join("pages")),
            "{}",
            file.display()
        );
    }
    // Long title: capped, and so is the file name.
    let long_doc = &manifest.documents[4];
    assert_eq!(long_doc.title.as_ref().unwrap().chars().count(), 200);
    assert!(long_doc.path.len() <= "pages/000005-".len() + 48 + ".md".len());
    // Empty and invisible-only titles fall back to the URL path.
    assert_eq!(manifest.documents[5].path, "pages/000006-f.md");
    assert_eq!(manifest.documents[6].path, "pages/000007-g.md");
    assert_eq!(manifest.documents[0].path, "pages/000001-etc-passwd.md");

    // Nothing was created anywhere but the run directory and the (empty) audit root.
    let mut top: Vec<String> = std::fs::read_dir(&workspace)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    top.sort();
    assert_eq!(top, ["private-audit", "runs"]);
    assert!(files_under(&workspace.join("private-audit")).is_empty());
    for file in files_under(&workspace) {
        assert!(file.starts_with(&run_dir), "{}", file.display());
        let name = file.file_name().unwrap().to_str().unwrap();
        assert!(name.is_ascii() && !name.starts_with('.'), "{name}");
    }
    Manifest::load(&run_dir.join("manifest.json")).unwrap();
}

/// A title that did not come through the extractor's normalization is refused, not "fixed":
/// the scanner saw the normalized string, so anything else was not scanned.
/// A title can no longer be swapped into an accepted document after the scan (the type is
/// sealed, ADR-016; see the `compile_fail` doc tests in `secure_web_security::decision`): an
/// unnormalized title in the page itself reaches the store only in its normalized form.
#[tokio::test]
async fn unnormalized_titles_are_stored_normalized() {
    let tmp = tempfile::tempdir().unwrap();
    let scanner = stub_scanner("canary").await;
    let store = store_at(tmp.path());
    let writer = store
        .begin_run(spec(RUN, "http://fixture.test/", &scanner))
        .await
        .unwrap();
    for raw in [
        "../x\u{0}",
        "\u{202E}evil",
        &"x".repeat(201),
        " padded ",
        "a\nb",
    ] {
        let html = format!("<title>{raw}</title><p>Body.</p>");
        let page = add_html(&writer, &scanner, "http://fixture.test/", &html, 0).await;
        let accepted = page.outcome.as_ref().unwrap();
        let title = accepted.title().unwrap();
        assert!(title.chars().count() <= 200, "{title:?}");
        assert!(
            !title
                .chars()
                .any(|c| c.is_control() || c == '\u{202E}' || c == '\n'),
            "{title:?}"
        );
        assert_eq!(title, title.trim());
    }
    let pages = files_under(&tmp.path().join("runs").join(RUN).join("pages"));
    assert!(!pages.is_empty());
    for page in pages {
        let name = page.file_name().unwrap().to_str().unwrap();
        assert!(
            name.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'),
            "{name}"
        );
    }
}

#[tokio::test]
async fn symlinked_run_locations_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(tmp.path()).unwrap();
    let outside = workspace.join("outside");
    std::fs::create_dir(&outside).unwrap();
    let scanner = stub_scanner("canary").await;

    // A symlink planted where the run directory goes.
    let store = store_at(&workspace.join("ws"));
    std::os::unix::fs::symlink(&outside, workspace.join("ws/runs").join(RUN)).unwrap();
    let err = store
        .begin_run(spec(RUN, "http://fixture.test/", &scanner))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::RunExists), "{err}");

    // `runs` itself a symlink.
    let ws2 = workspace.join("ws2");
    std::fs::create_dir(&ws2).unwrap();
    std::os::unix::fs::symlink(&outside, ws2.join("runs")).unwrap();
    let err = FsCorpusStore::new(StoreOptions {
        workspace: ws2,
        audit_root: None,
        retain_raw: false,
        warn_handling: WarnHandling::Store,
    })
    .unwrap_err();
    assert!(matches!(err, StoreError::SymlinkRefused), "{err}");

    assert!(files_under(&outside).is_empty());
}

fn audit_store(workspace: &Path, audit: PathBuf) -> Result<FsCorpusStore, StoreError> {
    FsCorpusStore::new(StoreOptions {
        workspace: workspace.to_path_buf(),
        audit_root: Some(audit),
        retain_raw: true,
        warn_handling: WarnHandling::Store,
    })
}

#[test]
fn audit_root_must_be_outside_runs() {
    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let ws = base.join("ws");
    std::fs::create_dir(&ws).unwrap();
    // An alias of the workspace through a symbolic link.
    std::os::unix::fs::symlink(&ws, base.join("alias")).unwrap();
    for audit in [
        // equal to / inside runs/
        ws.join("runs"),
        ws.join("runs/private-audit"),
        base.join("alias/runs"),
        base.join("alias/runs/x/private-audit"),
        // ancestors of runs/ (the workspace itself, its parent, `/`)
        ws.clone(),
        base.clone(),
        PathBuf::from("/"),
        base.join("alias").join("."),
    ] {
        let err = audit_store(&ws, audit.clone()).unwrap_err();
        assert!(
            matches!(err, StoreError::AuditInsideRuns),
            "{}: {err}",
            audit.display()
        );
    }
}

#[tokio::test]
async fn retained_files_land_under_private_audit() {
    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let ws = base.join("ws");
    std::fs::create_dir(&ws).unwrap();
    // A custom root must itself be a `private-audit` directory.
    let err = audit_store(&ws, base.join("audit")).unwrap_err();
    assert!(matches!(err, StoreError::Workspace(_)), "{err}");

    let scanner = stub_scanner("canary").await;
    for (i, audit) in [
        base.join("elsewhere/private-audit"),
        ws.join("private-audit"),
    ]
    .into_iter()
    .enumerate()
    {
        let store = audit_store(&ws, audit.clone()).unwrap();
        let run = format!("crawl_00000000bee{i}");
        let writer = store
            .begin_run(spec(&run, "http://fixture.test/", &scanner))
            .await
            .unwrap();
        add_html(
            &writer,
            &scanner,
            "http://fixture.test/",
            "<p>Kept raw.</p>",
            0,
        )
        .await;
        drop(writer);
        let kept = files_under(&audit);
        assert_eq!(kept.len(), 2, "{kept:?}");
        for file in kept {
            assert!(
                file.parent().and_then(Path::parent) == Some(audit.as_path())
                    && audit.file_name() == Some("private-audit".as_ref()),
                "{}",
                file.display()
            );
        }
        std::fs::remove_dir_all(ws.join("runs").join(&run)).unwrap();
    }
}

#[test]
fn tilde_workspace_expands_to_home() {
    let home = tempfile::tempdir().unwrap();
    let store = FsCorpusStore::with_home(
        StoreOptions {
            workspace: Path::new("~/.secure-web").to_path_buf(),
            audit_root: None,
            retain_raw: false,
            warn_handling: WarnHandling::Store,
        },
        Some(home.path()),
    )
    .unwrap();
    let expected = std::fs::canonicalize(home.path())
        .unwrap()
        .join(".secure-web");
    assert_eq!(store.runs_dir(), expected.join("runs"));
    assert_eq!(store.audit_root(), expected.join("private-audit"));
    assert!(!Path::new("~").exists());
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Swap `dir` for a symbolic link to `outside` (the real directory moves to `<dir>-real`).
fn swap_for_link(dir: &Path, outside: &Path) {
    let real = dir.with_file_name(format!(
        "{}-real",
        dir.file_name().unwrap().to_string_lossy()
    ));
    std::fs::rename(dir, &real).unwrap();
    std::os::unix::fs::symlink(outside, dir).unwrap();
}

#[tokio::test]
async fn swapped_run_directories_do_not_redirect_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let outside = base.join("outside");
    std::fs::create_dir(&outside).unwrap();
    let scanner = stub_scanner("canary").await;
    let store = store_at(&base.join("ws"));
    let writer = store
        .begin_run(spec(RUN, "http://fixture.test/", &scanner))
        .await
        .unwrap();
    let run_dir = writer.run_dir().to_path_buf();
    for sub in ["pages", "metadata", "security"] {
        swap_for_link(&run_dir.join(sub), &outside);
    }
    add_html(&writer, &scanner, "http://fixture.test/", "<p>One.</p>", 0).await;
    // The run directory itself (an ancestor of every write) too.
    swap_for_link(&run_dir, &outside);
    add_html(&writer, &scanner, "http://fixture.test/2", "<p>Two.</p>", 0).await;
    writer
        .finish(RunStatus::Complete, RunStats::default())
        .await
        .unwrap();

    assert!(
        files_under(&outside).is_empty(),
        "{:?}",
        files_under(&outside)
    );
    let real = base.join("ws/runs").join(format!("{RUN}-real"));
    let manifest = Manifest::load(&real.join("manifest.json")).unwrap();
    assert_eq!(manifest.documents.len(), 2);
    for doc in &manifest.documents {
        let moved = doc.path.replacen("pages/", "pages-real/", 1);
        assert!(real.join(&moved).is_file(), "{moved}");
    }
}

/// A thread keeps swapping the run's subdirectories for symbolic links to an outside directory
/// while documents are stored: every write still succeeds and nothing lands outside.
#[tokio::test]
async fn concurrent_symlink_swaps_never_escape_the_run() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let outside = base.join("outside");
    std::fs::create_dir(&outside).unwrap();
    let scanner = stub_scanner("canary").await;
    let store = store_at(&base.join("ws"));
    let writer = store
        .begin_run(spec(RUN, "http://fixture.test/", &scanner))
        .await
        .unwrap();
    let run_dir = writer.run_dir().to_path_buf();

    let stop = Arc::new(AtomicBool::new(false));
    let swapper = {
        let (stop, outside, run_dir) = (stop.clone(), outside.clone(), run_dir.clone());
        std::thread::spawn(move || {
            let mut swaps = 0u64;
            while !stop.load(Ordering::Relaxed) {
                for sub in ["pages", "metadata", "security"] {
                    let (dir, real) = (run_dir.join(sub), run_dir.join(format!("{sub}-real")));
                    let _ = std::fs::rename(&dir, &real);
                    let _ = std::os::unix::fs::symlink(&outside, &dir);
                    let _ = std::fs::remove_file(&dir);
                    let _ = std::fs::rename(&real, &dir);
                }
                swaps += 1;
            }
            swaps
        })
    };
    let total = 6 * secure_web_store::CHECKPOINT_EVERY as usize;
    for i in 0..total {
        add_html(
            &writer,
            &scanner,
            &format!("http://fixture.test/p/{i}"),
            &format!("<title>Page {i}</title><p>Body {i}.</p>"),
            1,
        )
        .await;
    }
    stop.store(true, Ordering::Relaxed);
    let swaps = swapper.join().unwrap();
    assert!(swaps > 0);
    writer
        .finish(RunStatus::Complete, RunStats::default())
        .await
        .unwrap();

    assert!(
        files_under(&outside).is_empty(),
        "{:?}",
        files_under(&outside)
    );
    // Every page is inside the run directory (under `pages/` or its swapped-out name).
    let pages: Vec<_> = files_under(&run_dir)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "md"))
        .collect();
    assert_eq!(pages.len(), total);
}

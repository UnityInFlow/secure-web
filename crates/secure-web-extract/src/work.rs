//! Test-only work counters (compiled under `#[cfg(test)]` only).
//!
//! Extraction tests on hostile input bound the **work** done — walk steps, tree-builder stack
//! scans, `href` resolutions, link-dedupe lookups and bytes searched for verbatim lines — instead
//! of wall-clock time, which machine load skews. The counts are deterministic for a given input.
//!
//! [`measure`] also takes a budget: once the total work passes it, the next count panics, so a
//! superlinear regression fails at once instead of running for hours before any assertion.
//! Counters are per thread; every test runs on its own thread.

use std::cell::Cell;

/// Work done by one [`measure`]d extraction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Work {
    /// `Dom::walk` events (one per `Enter` and one per `Exit`), over every walk.
    pub(crate) walk_steps: u64,
    /// Open elements examined by the tree builder's end-tag and implied-end searches.
    pub(crate) stack_scan_steps: u64,
    /// `href`s resolved against the base URL (`resolve_link`).
    pub(crate) hrefs_resolved: u64,
    /// Lookups in the survey's set of links already kept (link dedupe).
    pub(crate) link_dedupe_lookups: u64,
    /// Bytes of rendered Markdown searched for in-place lines (`VisibleCover::covers`).
    pub(crate) cover_bytes_scanned: u64,
}

impl Work {
    /// Every counter added up (mixed units; only used against the budget).
    pub(crate) fn total(&self) -> u64 {
        self.walk_steps
            .saturating_add(self.stack_scan_steps)
            .saturating_add(self.hrefs_resolved)
            .saturating_add(self.link_dedupe_lookups)
            .saturating_add(self.cover_bytes_scanned)
    }
}

thread_local! {
    static WORK: Cell<Work> = Cell::new(Work::default());
    static BUDGET: Cell<u64> = const { Cell::new(u64::MAX) };
}

fn add(update: impl FnOnce(&mut Work)) {
    let work = WORK.with(|cell| {
        let mut work = cell.get();
        update(&mut work);
        cell.set(work);
        work
    });
    let budget = BUDGET.with(Cell::get);
    assert!(
        work.total() <= budget,
        "extraction work exceeded its budget of {budget}: {work:?}"
    );
}

pub(crate) fn walk_step() {
    add(|w| w.walk_steps += 1);
}

pub(crate) fn stack_scan_step() {
    add(|w| w.stack_scan_steps += 1);
}

pub(crate) fn href_resolved() {
    add(|w| w.hrefs_resolved += 1);
}

pub(crate) fn link_dedupe_lookup() {
    add(|w| w.link_dedupe_lookups += 1);
}

pub(crate) fn cover_bytes_scanned(bytes: usize) {
    add(|w| {
        w.cover_bytes_scanned = w
            .cover_bytes_scanned
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
    });
}

/// Run `f` with fresh counters and a total-work `budget`; returns its result and the work done.
pub(crate) fn measure<R>(budget: u64, f: impl FnOnce() -> R) -> (R, Work) {
    WORK.with(|cell| cell.set(Work::default()));
    BUDGET.with(|cell| cell.set(budget));
    let result = f();
    BUDGET.with(|cell| cell.set(u64::MAX));
    (result, WORK.with(Cell::get))
}

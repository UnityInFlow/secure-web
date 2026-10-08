//! `PageProcessor` (the single processing path) and the bounded BFS crawler.
//!
//! - [`processor`]: [`PageProcessor::process`] sequences guard → fetch → extract → scan →
//!   policy → store for one URL (ADR-009, invariant 1).
//! - [`open`]: one `open_<id>` run around one page (`web_open`, `secure-web open`).
//! - [`crawler`]: one `crawl_<id>` run (`web_crawl`, `secure-web crawl`) over [`frontier`],
//!   [`scope`] and [`canonical`]; it only calls [`PageProcessor::process_link`].
#![forbid(unsafe_code)]

pub mod canonical;
pub mod crawler;
pub mod frontier;
pub mod open;
pub mod processor;
pub mod scope;

pub use crawler::{CrawlError, CrawlOptions, CrawlReport, Crawler, MAX_CRAWL_CONCURRENCY};
pub use open::{OpenError, OpenedRun};
pub use processor::{
    CrawlBudget, ExposedPage, PageContext, PageOutcome, PageProcessor, ProcessorError, RetryLater,
    SCANNER_UNAVAILABLE,
};
pub use scope::ScopeError;
pub use tokio_util::sync::CancellationToken;

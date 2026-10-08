//! [`App`]: config → `PageProcessor`, shared by the MCP server and the CLI.

use std::sync::Arc;

use secure_web_core::config::Config;
use secure_web_crawl::{Crawler, PageProcessor, ProcessorError};
use tokio::sync::Semaphore;

/// Most tool calls processed at once, whatever `crawl.concurrency` says (each call may hold a
/// scanner process and up to `maxPageBytes` of body).
pub const MAX_CONCURRENT_CALLS: usize = 16;

/// Everything a tool call needs. Cheap to clone.
#[derive(Debug, Clone)]
pub struct App {
    processor: Arc<PageProcessor>,
    permits: Arc<Semaphore>,
}

impl App {
    /// Build the pipeline from `config` (system DNS resolver).
    pub async fn from_config(config: &Config) -> Result<Self, ProcessorError> {
        Ok(Self::with_processor(Arc::new(
            PageProcessor::from_config(config).await?,
        )))
    }

    /// Wrap an existing processor. Concurrent tool calls are bounded by
    /// `min(crawl.concurrency, MAX_CONCURRENT_CALLS)` (at least 1); further calls wait.
    pub fn with_processor(processor: Arc<PageProcessor>) -> Self {
        let configured = usize::try_from(processor.config().crawl.concurrency).unwrap_or(1);
        let permits = configured.clamp(1, MAX_CONCURRENT_CALLS);
        Self {
            processor,
            permits: Arc::new(Semaphore::new(permits)),
        }
    }

    /// The shared page processor.
    pub fn processor(&self) -> &PageProcessor {
        &self.processor
    }

    /// A crawler over the shared page processor.
    pub fn crawler(&self) -> Crawler {
        Crawler::new(Arc::clone(&self.processor))
    }

    /// The effective configuration.
    pub fn config(&self) -> &Config {
        self.processor.config()
    }

    /// The call semaphore.
    pub(crate) fn permits(&self) -> &Semaphore {
        &self.permits
    }
}

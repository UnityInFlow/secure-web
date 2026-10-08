//! The bounded BFS frontier (T8, `docs/architecture.md` "Concurrency model").
//!
//! A FIFO queue of `(link, depth)` capped at `crawl.maxFrontier` entries, plus the set of
//! canonical URLs already admitted. A link is admitted at most once per crawl; a link that
//! arrives while the queue is full is dropped (counted, never queued, not remembered — so the
//! `seen` set only ever holds admitted URLs and stays bounded by admissions).

use std::collections::{HashSet, VecDeque};

use secure_web_core::model::DiscoveredLink;

use crate::canonical::CanonicalUrl;

/// One queued crawl target.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The link as discovered (fetched as written).
    pub link: DiscoveredLink,
    /// Its crawl depth (root = 0).
    pub depth: u32,
}

/// What [`Frontier::push`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push {
    /// Queued.
    Admitted,
    /// Already admitted earlier in this crawl.
    Seen,
    /// The queue was full; the link was dropped.
    Full,
}

/// Bounded BFS queue with canonical-URL dedupe.
#[derive(Debug)]
pub struct Frontier {
    queue: VecDeque<Entry>,
    seen: HashSet<CanonicalUrl>,
    max_len: usize,
    dropped: u64,
    peak: usize,
}

impl Frontier {
    /// An empty frontier holding at most `max_len` queued entries.
    pub fn new(max_len: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            seen: HashSet::new(),
            max_len,
            dropped: 0,
            peak: 0,
        }
    }

    /// Queue `link` at `depth` unless its canonical form was admitted before or the queue is
    /// full.
    pub fn push(&mut self, link: DiscoveredLink, canonical: CanonicalUrl, depth: u32) -> Push {
        if self.seen.contains(&canonical) {
            return Push::Seen;
        }
        if self.queue.len() >= self.max_len {
            self.dropped += 1;
            return Push::Full;
        }
        self.seen.insert(canonical);
        self.queue.push_back(Entry { link, depth });
        self.peak = self.peak.max(self.queue.len());
        Push::Admitted
    }

    /// The oldest queued entry.
    pub fn pop(&mut self) -> Option<Entry> {
        self.queue.pop_front()
    }

    /// Queued entries.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Links dropped because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Largest queue length reached.
    pub fn peak(&self) -> usize {
        self.peak
    }

    /// Canonical URLs admitted so far.
    pub fn admitted(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;
    use crate::canonical::canonicalize;

    fn push(frontier: &mut Frontier, url: &str, depth: u32) -> Push {
        let url = Url::parse(url).unwrap();
        let canonical = canonicalize(&url, &["utm_source".to_owned()]);
        frontier.push(DiscoveredLink::from_url(url), canonical, depth)
    }

    #[test]
    fn fifo_dedupe_and_hard_cap() {
        let mut frontier = Frontier::new(2);
        assert_eq!(push(&mut frontier, "http://e.test/a", 0), Push::Admitted);
        assert_eq!(push(&mut frontier, "http://e.test/a#x", 1), Push::Seen);
        assert_eq!(
            push(&mut frontier, "http://e.test/a?utm_source=1", 1),
            Push::Seen
        );
        assert_eq!(push(&mut frontier, "http://e.test/b", 1), Push::Admitted);
        assert_eq!(push(&mut frontier, "http://e.test/c", 1), Push::Full);
        assert_eq!(push(&mut frontier, "http://e.test/c", 1), Push::Full);
        assert_eq!(frontier.len(), 2);
        assert_eq!(frontier.dropped(), 2);
        assert_eq!(frontier.peak(), 2);
        let first = frontier.pop().unwrap();
        assert_eq!(first.link.url.as_str(), "http://e.test/a");
        assert_eq!(first.depth, 0);
        // Room again; a dropped link was not remembered, an admitted one still is.
        assert_eq!(push(&mut frontier, "http://e.test/c", 2), Push::Admitted);
        assert_eq!(push(&mut frontier, "http://e.test/a", 2), Push::Seen);
        assert_eq!(frontier.pop().unwrap().link.url.as_str(), "http://e.test/b");
        assert_eq!(frontier.pop().unwrap().link.url.as_str(), "http://e.test/c");
        assert!(frontier.pop().is_none());
        assert_eq!(frontier.admitted(), 3);
    }
}

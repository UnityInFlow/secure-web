//! Per-host politeness (deep-dive §83): bounded concurrency plus an optional minimum delay
//! between request starts to the same host.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

struct HostSlot {
    permits: Arc<Semaphore>,
    next_start: AsyncMutex<Option<Instant>>,
}

/// Per-host semaphores keyed by `host:port`.
pub(crate) struct HostThrottle {
    per_host: usize,
    min_delay: Duration,
    hosts: Mutex<HashMap<String, Arc<HostSlot>>>,
}

impl HostThrottle {
    pub(crate) fn new(per_host: u32, min_delay: Duration) -> Self {
        Self {
            per_host: usize::try_from(per_host).unwrap_or(1).max(1),
            min_delay,
            hosts: Mutex::new(HashMap::new()),
        }
    }

    fn slot(&self, key: &str) -> Arc<HostSlot> {
        let mut hosts = self
            .hosts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        hosts
            .entry(key.to_owned())
            .or_insert_with(|| {
                Arc::new(HostSlot {
                    permits: Arc::new(Semaphore::new(self.per_host)),
                    next_start: AsyncMutex::new(None),
                })
            })
            .clone()
    }

    /// Wait for a slot on `key`; the returned permit frees it on drop.
    pub(crate) async fn acquire(&self, key: &str) -> Option<OwnedSemaphorePermit> {
        let slot = self.slot(key);
        let permit = slot.permits.clone().acquire_owned().await.ok()?;
        if !self.min_delay.is_zero() {
            let mut next_start = slot.next_start.lock().await;
            if let Some(at) = *next_start {
                tokio::time::sleep_until(at).await;
            }
            *next_start = Some(Instant::now() + self.min_delay);
        }
        Some(permit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn concurrency_per_host_is_bounded() {
        let throttle = HostThrottle::new(2, Duration::ZERO);
        let first = throttle.acquire("a:80").await.unwrap();
        let _second = throttle.acquire("a:80").await.unwrap();
        let third = tokio::time::timeout(Duration::from_millis(50), throttle.acquire("a:80")).await;
        assert!(third.is_err(), "third permit must wait");
        let other_host = throttle.acquire("b:80").await;
        assert!(other_host.is_some());
        drop(first);
        assert!(throttle.acquire("a:80").await.is_some());
    }

    #[tokio::test]
    async fn min_delay_spaces_request_starts() {
        let throttle = HostThrottle::new(4, Duration::from_millis(60));
        let started = Instant::now();
        drop(throttle.acquire("a:80").await);
        drop(throttle.acquire("a:80").await);
        assert!(started.elapsed() >= Duration::from_millis(60));
    }

    #[test]
    fn zero_concurrency_means_one() {
        assert_eq!(HostThrottle::new(0, Duration::ZERO).per_host, 1);
    }
}

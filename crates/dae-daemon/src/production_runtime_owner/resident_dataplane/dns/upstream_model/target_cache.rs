use super::*;
use std::time::Duration;

use crate::production_runtime_owner::resident_dataplane::resident_dns_upstream_refresh_interval;

const DNS_UPSTREAM_STALE_RETRY_DIVISOR: u32 = 10;
const DNS_UPSTREAM_STALE_RETRY_MIN: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsResolvedTargetCache
{
    state: AsyncMutex<Option<ResidentDnsResolvedTargetEntry>>,
    refresh_interval: Duration,
}

#[derive(Clone, Debug)]
struct ResidentDnsResolvedTargetEntry {
    addrs: Vec<SocketAddr>,
    refresh_at: time::Instant,
}

impl ResidentDnsResolvedTargetCache {
    pub(super) fn new(refresh_interval: Duration) -> Self {
        Self {
            state: AsyncMutex::new(None),
            refresh_interval,
        }
    }

    pub(super) async fn resolve<F, Fut>(&self, resolver: F) -> Result<Vec<SocketAddr>, String>
    where
        F: FnOnce(Duration) -> Fut,
        Fut: std::future::Future<Output = Result<ResolvedHostAddrs, String>>,
    {
        let mut state = self.state.lock().await;
        let now = time::Instant::now();
        if let Some(entry) = state.as_ref()
            && now < entry.refresh_at
        {
            return Ok(entry.addrs.clone());
        }
        match resolver(self.refresh_interval).await {
            Ok(resolved) => {
                let addrs = resolved.addrs;
                *state = Some(ResidentDnsResolvedTargetEntry {
                    addrs: addrs.clone(),
                    refresh_at: time::Instant::now() + resolved.valid_for,
                });
                Ok(addrs)
            }
            Err(err) => {
                let Some(entry) = state.as_mut() else {
                    return Err(err);
                };
                let retry = self
                    .refresh_interval
                    .checked_div(DNS_UPSTREAM_STALE_RETRY_DIVISOR)
                    .unwrap_or(Duration::ZERO)
                    .max(DNS_UPSTREAM_STALE_RETRY_MIN);
                entry.refresh_at = time::Instant::now() + retry.min(self.refresh_interval);
                Ok(entry.addrs.clone())
            }
        }
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane::dns) async fn seed(
        &self,
        addrs: Vec<SocketAddr>,
        valid_for: Duration,
    ) {
        *self.state.lock().await = Some(ResidentDnsResolvedTargetEntry {
            addrs,
            refresh_at: time::Instant::now() + valid_for,
        });
    }

    #[cfg(test)]
    pub(super) fn seeded(addrs: Vec<SocketAddr>, valid_for: Duration) -> Self {
        Self {
            state: AsyncMutex::new(Some(ResidentDnsResolvedTargetEntry {
                addrs,
                refresh_at: time::Instant::now() + valid_for,
            })),
            refresh_interval: resident_dns_upstream_refresh_interval(),
        }
    }
}

impl Default for ResidentDnsResolvedTargetCache {
    fn default() -> Self {
        Self::new(resident_dns_upstream_refresh_interval())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn resolved(addr: &str, valid_for: Duration) -> ResolvedHostAddrs {
        ResolvedHostAddrs {
            addrs: vec![addr.parse().unwrap()],
            valid_for,
        }
    }

    #[tokio::test]
    async fn expired_target_cache_refreshes_and_replaces_addresses() {
        let cache = ResidentDnsResolvedTargetCache::default();
        let calls = AtomicUsize::new(0);
        let first = cache
            .resolve(|_| async {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(resolved("192.0.2.1:53", Duration::ZERO))
            })
            .await
            .unwrap();
        let second = cache
            .resolve(|_| async {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(resolved("192.0.2.2:53", Duration::from_secs(60)))
            })
            .await
            .unwrap();

        assert_eq!(first[0], "192.0.2.1:53".parse().unwrap());
        assert_eq!(second[0], "192.0.2.2:53".parse().unwrap());
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn refresh_failure_temporarily_reuses_stale_addresses() {
        let cache = ResidentDnsResolvedTargetCache::seeded(
            vec!["192.0.2.3:53".parse().unwrap()],
            Duration::ZERO,
        );
        let addrs = cache
            .resolve(|_| async { Err("injected resolver failure".to_owned()) })
            .await
            .unwrap();
        assert_eq!(addrs[0], "192.0.2.3:53".parse().unwrap());
    }

    #[tokio::test]
    async fn initial_refresh_failure_is_reported_without_stale_addresses() {
        let cache = ResidentDnsResolvedTargetCache::new(Duration::from_secs(60));
        let err = cache
            .resolve(|_| async { Err("injected initial resolver failure".to_owned()) })
            .await
            .unwrap_err();
        assert_eq!(err, "injected initial resolver failure");
    }

    #[tokio::test]
    async fn concurrent_refreshes_share_one_resolution() {
        let cache = Arc::new(ResidentDnsResolvedTargetCache::new(Duration::from_secs(60)));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let cache = Arc::clone(&cache);
            let calls = Arc::clone(&calls);
            tasks.push(tokio::spawn(async move {
                cache
                    .resolve(move |_| async move {
                        calls.fetch_add(1, Ordering::Relaxed);
                        time::sleep(Duration::from_millis(10)).await;
                        Ok(resolved("192.0.2.4:53", Duration::from_secs(60)))
                    })
                    .await
                    .unwrap()
            }));
        }

        for task in tasks {
            assert_eq!(task.await.unwrap()[0], "192.0.2.4:53".parse().unwrap());
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}

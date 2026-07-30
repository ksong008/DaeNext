use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;
use tokio::sync::Notify;

use crate::production_runtime_owner::resident_dataplane::resident_dns_upstream_refresh_interval;

use super::target_refresh::ResidentDnsTargetRefreshHandle;

const DNS_UPSTREAM_STALE_RETRY_DIVISOR: u32 = 10;
const DNS_UPSTREAM_STALE_RETRY_MIN: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsResolvedTargetCache
{
    state: RwLock<Option<ResidentDnsResolvedTargetEntry>>,
    initial_refresh: AsyncMutex<()>,
    refresh_handle: OnceLock<ResidentDnsTargetRefreshHandle>,
    refreshing: AtomicBool,
    refresh_changed: Notify,
    next_epoch: AtomicU64,
    refresh_interval: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsResolvedTargetSnapshot
{
    addrs: Arc<[SocketAddr]>,
    epoch: u64,
    stale: bool,
}

impl ResidentDnsResolvedTargetSnapshot {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn literal(
        addr: SocketAddr,
    ) -> Self {
        Self {
            addrs: Arc::from([addr]),
            epoch: 0,
            stale: false,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn to_vec(
        &self,
    ) -> Vec<SocketAddr> {
        self.addrs.to_vec()
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn as_slice(
        &self,
    ) -> &[SocketAddr] {
        &self.addrs
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) const fn is_stale(
        &self,
    ) -> bool {
        self.stale
    }
}

#[derive(Clone, Debug)]
struct ResidentDnsResolvedTargetEntry {
    addrs: Arc<[SocketAddr]>,
    refresh_at: time::Instant,
    epoch: u64,
    invalidated: bool,
    invalidated_refresh_attempted: bool,
}

impl ResidentDnsResolvedTargetCache {
    pub(super) fn new(refresh_interval: Duration) -> Self {
        Self {
            state: RwLock::new(None),
            initial_refresh: AsyncMutex::new(()),
            refresh_handle: OnceLock::new(),
            refreshing: AtomicBool::new(false),
            refresh_changed: Notify::new(),
            next_epoch: AtomicU64::new(1),
            refresh_interval,
        }
    }

    pub(super) fn install_refresh_handle(&self, handle: ResidentDnsTargetRefreshHandle) {
        let _ = self.refresh_handle.set(handle);
    }

    pub(super) async fn resolve<F, Fut>(
        self: &Arc<Self>,
        resolver: F,
    ) -> Result<ResidentDnsResolvedTargetSnapshot, String>
    where
        F: FnOnce(Duration) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<ResolvedHostAddrs, String>> + Send + 'static,
    {
        let now = time::Instant::now();
        if let Some(entry) = self.cached_entry()
            && !entry.invalidated
            && now < entry.refresh_at
        {
            return Ok(Self::snapshot(entry, false));
        }
        if let Some(stale) = self.cached_entry()
            && !stale.invalidated
            && let Some(handle) = self.refresh_handle.get()
        {
            if self.begin_background_refresh() {
                handle.try_schedule(self, resolver);
            }
            return Ok(Self::snapshot(stale, true));
        }
        self.resolve_while_waiting(resolver).await
    }

    async fn resolve_while_waiting<F, Fut>(
        &self,
        resolver: F,
    ) -> Result<ResidentDnsResolvedTargetSnapshot, String>
    where
        F: FnOnce(Duration) -> Fut,
        Fut: std::future::Future<Output = Result<ResolvedHostAddrs, String>>,
    {
        if self.cached_entry().is_some_and(|entry| entry.invalidated) {
            self.wait_for_background_refresh().await;
        }
        let _refresh = self.initial_refresh.lock().await;
        let now = time::Instant::now();
        if let Some(entry) = self.cached_entry()
            && !entry.invalidated
            && now < entry.refresh_at
        {
            return Ok(Self::snapshot(entry, false));
        }
        if self.cached_entry().is_some_and(|entry| entry.invalidated)
            && !self.prepare_invalidated_refresh(now, None)
        {
            return Err(
                "DNS upstream target refresh is deferred after a failed stale-address refresh"
                    .to_owned(),
            );
        }
        let stale = self.cached_entry();
        match resolver(self.refresh_interval).await {
            Ok(resolved) => Ok(self.store_resolved(resolved)),
            Err(error) => match stale.filter(|entry| !entry.invalidated) {
                Some(stale) => {
                    self.defer_stale_retry();
                    Ok(Self::snapshot(stale, true))
                }
                None => Err(error),
            },
        }
    }

    fn snapshot(
        entry: ResidentDnsResolvedTargetEntry,
        stale: bool,
    ) -> ResidentDnsResolvedTargetSnapshot {
        ResidentDnsResolvedTargetSnapshot {
            addrs: entry.addrs,
            epoch: entry.epoch,
            stale,
        }
    }

    fn cached_entry(&self) -> Option<ResidentDnsResolvedTargetEntry> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn store_resolved(&self, resolved: ResolvedHostAddrs) -> ResidentDnsResolvedTargetSnapshot {
        let addrs = Arc::<[SocketAddr]>::from(resolved.addrs);
        let epoch = self.next_epoch.fetch_add(1, Ordering::AcqRel);
        *self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(ResidentDnsResolvedTargetEntry {
                addrs: Arc::clone(&addrs),
                refresh_at: time::Instant::now() + resolved.valid_for,
                epoch,
                invalidated: false,
                invalidated_refresh_attempted: false,
            });
        ResidentDnsResolvedTargetSnapshot {
            addrs,
            epoch,
            stale: false,
        }
    }

    fn defer_stale_retry(&self) {
        let retry = self
            .refresh_interval
            .checked_div(DNS_UPSTREAM_STALE_RETRY_DIVISOR)
            .unwrap_or(Duration::ZERO)
            .max(DNS_UPSTREAM_STALE_RETRY_MIN)
            .min(self.refresh_interval);
        if let Some(entry) = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_mut()
        {
            entry.refresh_at = time::Instant::now() + retry;
        }
    }

    fn begin_background_refresh(&self) -> bool {
        self.refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn prepare_invalidated_refresh(&self, now: time::Instant, expected_epoch: Option<u64>) -> bool {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = state.as_mut() else {
            return true;
        };
        if expected_epoch.is_some_and(|epoch| epoch != entry.epoch) || !entry.invalidated {
            return false;
        }
        if entry.invalidated_refresh_attempted && now < entry.refresh_at {
            return false;
        }
        entry.invalidated_refresh_attempted = true;
        true
    }

    pub(super) async fn refresh_after_stale_failure<F, Fut>(
        &self,
        snapshot: &ResidentDnsResolvedTargetSnapshot,
        resolver: F,
    ) -> Result<(), String>
    where
        F: FnOnce(Duration) -> Fut,
        Fut: std::future::Future<Output = Result<ResolvedHostAddrs, String>>,
    {
        if !snapshot.stale {
            return Ok(());
        }
        {
            let mut state = self
                .state
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(entry) = state.as_mut() else {
                return Ok(());
            };
            if entry.epoch != snapshot.epoch {
                return Ok(());
            }
            if !entry.invalidated {
                entry.invalidated = true;
                entry.invalidated_refresh_attempted = false;
            }
        }

        self.wait_for_background_refresh().await;
        let _refresh = self.initial_refresh.lock().await;
        if !self.prepare_invalidated_refresh(time::Instant::now(), Some(snapshot.epoch)) {
            return Ok(());
        }
        match resolver(self.refresh_interval).await {
            Ok(resolved) => {
                self.store_resolved(resolved);
                Ok(())
            }
            Err(error) => {
                self.defer_stale_retry();
                Err(error)
            }
        }
    }

    async fn wait_for_background_refresh(&self) {
        loop {
            let changed = self.refresh_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !self.refreshing.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }

    pub(super) fn complete_background_refresh(&self, result: Result<ResolvedHostAddrs, String>) {
        match result {
            Ok(resolved) => {
                self.store_resolved(resolved);
            }
            Err(_) => self.defer_stale_retry(),
        }
        self.cancel_background_refresh();
    }

    pub(super) fn cancel_background_refresh(&self) {
        self.refreshing.store(false, Ordering::Release);
        self.refresh_changed.notify_waiters();
    }

    pub(super) const fn refresh_interval(&self) -> Duration {
        self.refresh_interval
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane::dns) async fn seed(
        &self,
        addrs: Vec<SocketAddr>,
        valid_for: Duration,
    ) {
        let epoch = self.next_epoch.fetch_add(1, Ordering::AcqRel);
        *self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(ResidentDnsResolvedTargetEntry {
                addrs: Arc::from(addrs),
                refresh_at: time::Instant::now() + valid_for,
                epoch,
                invalidated: false,
                invalidated_refresh_attempted: false,
            });
    }

    #[cfg(test)]
    pub(super) fn seeded(addrs: Vec<SocketAddr>, valid_for: Duration) -> Self {
        Self {
            state: RwLock::new(Some(ResidentDnsResolvedTargetEntry {
                addrs: Arc::from(addrs),
                refresh_at: time::Instant::now() + valid_for,
                epoch: 1,
                invalidated: false,
                invalidated_refresh_attempted: false,
            })),
            initial_refresh: AsyncMutex::new(()),
            refresh_handle: OnceLock::new(),
            refreshing: AtomicBool::new(false),
            refresh_changed: Notify::new(),
            next_epoch: AtomicU64::new(2),
            refresh_interval: resident_dns_upstream_refresh_interval(),
        }
    }

    #[cfg(test)]
    pub(super) fn cached_addrs_for_test(&self) -> Option<Arc<[SocketAddr]>> {
        self.cached_entry().map(|entry| entry.addrs)
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn resolved(addr: &str, valid_for: Duration) -> ResolvedHostAddrs {
        ResolvedHostAddrs {
            addrs: vec![addr.parse().unwrap()],
            valid_for,
        }
    }

    #[tokio::test]
    async fn expired_target_cache_refreshes_and_replaces_addresses_without_an_owner() {
        let cache = Arc::new(ResidentDnsResolvedTargetCache::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let first = cache
            .resolve({
                let calls = Arc::clone(&calls);
                move |_| async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    Ok(resolved("192.0.2.1:53", Duration::ZERO))
                }
            })
            .await
            .unwrap();
        let second = cache
            .resolve({
                let calls = Arc::clone(&calls);
                move |_| async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    Ok(resolved("192.0.2.2:53", Duration::from_secs(60)))
                }
            })
            .await
            .unwrap();

        assert_eq!(first.as_slice()[0], "192.0.2.1:53".parse().unwrap());
        assert_eq!(second.as_slice()[0], "192.0.2.2:53".parse().unwrap());
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn refresh_failure_temporarily_reuses_stale_addresses() {
        let cache = Arc::new(ResidentDnsResolvedTargetCache::seeded(
            vec!["192.0.2.3:53".parse().unwrap()],
            Duration::ZERO,
        ));
        let addrs = cache
            .resolve(|_| async { Err("injected resolver failure".to_owned()) })
            .await
            .unwrap();
        assert_eq!(addrs.as_slice()[0], "192.0.2.3:53".parse().unwrap());
    }

    #[tokio::test]
    async fn initial_refresh_failure_is_reported_without_stale_addresses() {
        let cache = Arc::new(ResidentDnsResolvedTargetCache::new(Duration::from_secs(60)));
        let err = cache
            .resolve(|_| async { Err("injected initial resolver failure".to_owned()) })
            .await
            .unwrap_err();
        assert_eq!(err, "injected initial resolver failure");
    }

    #[tokio::test]
    async fn concurrent_initial_refreshes_share_one_resolution() {
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
            assert_eq!(
                task.await.unwrap().as_slice()[0],
                "192.0.2.4:53".parse().unwrap()
            );
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn stale_failure_cannot_invalidate_a_newer_published_epoch() {
        let cache = Arc::new(ResidentDnsResolvedTargetCache::seeded(
            vec!["192.0.2.5:53".parse().unwrap()],
            Duration::ZERO,
        ));
        let stale = ResidentDnsResolvedTargetCache::snapshot(
            cache.cached_entry().expect("seeded cache entry"),
            true,
        );
        cache.complete_background_refresh(Ok(resolved("192.0.2.6:53", Duration::from_secs(60))));
        let calls = Arc::new(AtomicUsize::new(0));

        cache
            .refresh_after_stale_failure(&stale, {
                let calls = Arc::clone(&calls);
                move |_| async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    Ok(resolved("192.0.2.7:53", Duration::from_secs(60)))
                }
            })
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            cache.cached_addrs_for_test().unwrap()[0],
            "192.0.2.6:53".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn concurrent_stale_failures_share_one_forced_refresh() {
        let cache = Arc::new(ResidentDnsResolvedTargetCache::seeded(
            vec!["192.0.2.8:53".parse().unwrap()],
            Duration::ZERO,
        ));
        let stale = ResidentDnsResolvedTargetCache::snapshot(
            cache.cached_entry().expect("seeded cache entry"),
            true,
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let cache = Arc::clone(&cache);
            let stale = stale.clone();
            let calls = Arc::clone(&calls);
            tasks.push(tokio::spawn(async move {
                cache
                    .refresh_after_stale_failure(&stale, move |_| async move {
                        calls.fetch_add(1, Ordering::Relaxed);
                        time::sleep(Duration::from_millis(10)).await;
                        Ok(resolved("192.0.2.9:53", Duration::from_secs(60)))
                    })
                    .await
            }));
        }

        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            cache.cached_addrs_for_test().unwrap()[0],
            "192.0.2.9:53".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn failed_forced_refresh_retains_evidence_without_reusing_dead_stale_addresses() {
        let cache = Arc::new(ResidentDnsResolvedTargetCache::seeded(
            vec!["192.0.2.10:53".parse().unwrap()],
            Duration::ZERO,
        ));
        let stale = ResidentDnsResolvedTargetCache::snapshot(
            cache.cached_entry().expect("seeded cache entry"),
            true,
        );
        let error = cache
            .refresh_after_stale_failure(&stale, |_| async {
                Err("injected forced refresh failure".to_owned())
            })
            .await
            .unwrap_err();
        assert_eq!(error, "injected forced refresh failure");
        assert_eq!(
            cache.cached_addrs_for_test().unwrap()[0],
            "192.0.2.10:53".parse().unwrap()
        );

        let calls = Arc::new(AtomicUsize::new(0));
        let retry = cache
            .resolve({
                let calls = Arc::clone(&calls);
                move |_| async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    Ok(resolved("192.0.2.11:53", Duration::from_secs(60)))
                }
            })
            .await;
        assert!(retry.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn fresh_snapshot_failure_feedback_does_not_run_the_resolver() {
        let cache = Arc::new(ResidentDnsResolvedTargetCache::seeded(
            vec!["192.0.2.12:53".parse().unwrap()],
            Duration::from_secs(60),
        ));
        let fresh = cache
            .resolve(|_| async { Err("fresh resolver must not run".to_owned()) })
            .await
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        cache
            .refresh_after_stale_failure(&fresh, {
                let calls = Arc::clone(&calls);
                move |_| async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    Ok(resolved("192.0.2.13:53", Duration::from_secs(60)))
                }
            })
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
}

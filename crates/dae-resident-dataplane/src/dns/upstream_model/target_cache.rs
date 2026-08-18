use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;
use tokio::sync::Notify;

use crate::resident_dns_upstream_refresh_interval;

use super::target_refresh::ResidentDnsTargetRefreshHandle;

const DNS_UPSTREAM_STALE_RETRY_DIVISOR: u32 = 10;
const DNS_UPSTREAM_STALE_RETRY_MIN: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::dns) enum ResidentDnsTargetRefreshError {
    Deadline,
    Resolver(String),
}

impl std::fmt::Display for ResidentDnsTargetRefreshError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deadline => formatter.write_str("DNS upstream target refresh deadline expired"),
            Self::Resolver(error) => formatter.write_str(error),
        }
    }
}

#[derive(Debug)]
pub(in crate::dns) struct ResidentDnsResolvedTargetCache {
    state: RwLock<Option<ResidentDnsResolvedTargetEntry>>,
    initial_refresh: AsyncMutex<()>,
    refresh_handle: OnceLock<ResidentDnsTargetRefreshHandle>,
    refreshing: AtomicBool,
    refresh_changed: Notify,
    next_epoch: AtomicU64,
    refresh_interval: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::dns) struct ResidentDnsResolvedTargetSnapshot {
    addrs: Arc<[SocketAddr]>,
    epoch: u64,
    stale: bool,
}

impl ResidentDnsResolvedTargetSnapshot {
    pub(in crate::dns) fn literal(addr: SocketAddr) -> Self {
        Self {
            addrs: Arc::from([addr]),
            epoch: 0,
            stale: false,
        }
    }

    #[cfg(test)]
    pub(in crate::dns) fn stale_literal(addr: SocketAddr) -> Self {
        Self {
            addrs: Arc::from([addr]),
            epoch: 1,
            stale: true,
        }
    }

    pub(in crate::dns) fn to_vec(&self) -> Vec<SocketAddr> {
        self.addrs.to_vec()
    }

    #[cfg(test)]
    pub(in crate::dns) fn as_slice(&self) -> &[SocketAddr] {
        &self.addrs
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
        if self.cached_entry().is_some_and(|entry| entry.invalidated) {
            if let Ok(attempt_guard) = self.prepare_invalidated_refresh(now, None) {
                attempt_guard.commit();
            }
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

    fn defer_invalidated_retry(&self, expected_epoch: Option<u64>) {
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
            if expected_epoch.is_some_and(|epoch| epoch != entry.epoch) {
                return;
            }
            entry.invalidated = true;
            entry.invalidated_refresh_attempted = true;
            entry.refresh_at = time::Instant::now() + retry;
        }
    }

    fn begin_background_refresh(&self) -> bool {
        self.refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn prepare_invalidated_refresh(
        &self,
        now: time::Instant,
        expected_epoch: Option<u64>,
    ) -> Result<RefreshAttemptGuard<'_>, ()> {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = state.as_mut() else {
            return Err(());
        };
        if expected_epoch.is_some_and(|epoch| epoch != entry.epoch) || !entry.invalidated {
            return Err(());
        }
        if entry.invalidated_refresh_attempted && now < entry.refresh_at {
            return Err(());
        }
        entry.invalidated_refresh_attempted = true;
        Ok(RefreshAttemptGuard {
            cache: self,
            epoch: entry.epoch,
            armed: true,
        })
    }

    #[cfg(test)]
    pub(super) async fn refresh_after_stale_failure<F, Fut>(
        &self,
        snapshot: &ResidentDnsResolvedTargetSnapshot,
        resolver: F,
    ) -> Result<(), String>
    where
        F: FnOnce(Duration) -> Fut,
        Fut: std::future::Future<Output = Result<ResolvedHostAddrs, String>>,
    {
        let deadline = time::Instant::now() + self.refresh_interval;
        self.refresh_after_stale_failure_and_resolve(snapshot, deadline, resolver)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Invalidate the snapshot that produced a target-specific connect/initial-send
    /// failure, singleflight the forced refresh, and return the newly published
    /// snapshot to the caller.  The snapshot may still be fresh by TTL: an immediate
    /// refusal is sufficient evidence that the currently cached address is unusable.
    /// The epoch check prevents an older failure from evicting a newer publication.
    /// Callers use this method for a single bounded retry of that same request.
    pub(super) async fn refresh_after_stale_failure_and_resolve<F, Fut>(
        &self,
        snapshot: &ResidentDnsResolvedTargetSnapshot,
        deadline: time::Instant,
        resolver: F,
    ) -> Result<Option<ResidentDnsResolvedTargetSnapshot>, ResidentDnsTargetRefreshError>
    where
        F: FnOnce(Duration) -> Fut,
        Fut: std::future::Future<Output = Result<ResolvedHostAddrs, String>>,
    {
        if time::Instant::now() >= deadline {
            self.defer_invalidated_retry(Some(snapshot.epoch));
            return Err(ResidentDnsTargetRefreshError::Deadline);
        }
        {
            let mut state = self
                .state
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(entry) = state.as_mut() else {
                return Ok(None);
            };
            if entry.epoch != snapshot.epoch {
                return Ok(Some(Self::snapshot(entry.clone(), false)));
            }
            if !entry.invalidated {
                entry.invalidated = true;
                entry.invalidated_refresh_attempted = false;
            }
        }

        if tokio::time::timeout_at(deadline, self.wait_for_background_refresh())
            .await
            .is_err()
        {
            self.defer_invalidated_retry(Some(snapshot.epoch));
            return Err(ResidentDnsTargetRefreshError::Deadline);
        }
        let _refresh = match tokio::time::timeout_at(deadline, self.initial_refresh.lock()).await {
            Ok(refresh) => refresh,
            Err(_) => {
                self.defer_invalidated_retry(Some(snapshot.epoch));
                return Err(ResidentDnsTargetRefreshError::Deadline);
            }
        };
        let Ok(attempt_guard) =
            self.prepare_invalidated_refresh(time::Instant::now(), Some(snapshot.epoch))
        else {
            return Ok(self
                .cached_entry()
                .filter(|entry| !entry.invalidated)
                .map(|entry| Self::snapshot(entry, false)));
        };
        if time::Instant::now() >= deadline {
            self.defer_invalidated_retry(Some(snapshot.epoch));
            attempt_guard.commit();
            return Err(ResidentDnsTargetRefreshError::Deadline);
        }
        match tokio::time::timeout_at(deadline, resolver(self.refresh_interval)).await {
            Ok(Ok(resolved)) => {
                attempt_guard.commit();
                Ok(Some(self.store_resolved(resolved)))
            }
            Ok(Err(error)) => {
                self.defer_invalidated_retry(Some(snapshot.epoch));
                attempt_guard.commit();
                Err(ResidentDnsTargetRefreshError::Resolver(error))
            }
            Err(_) => {
                self.defer_invalidated_retry(Some(snapshot.epoch));
                attempt_guard.commit();
                Err(ResidentDnsTargetRefreshError::Deadline)
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
    pub(in crate::dns) async fn seed(&self, addrs: Vec<SocketAddr>, valid_for: Duration) {
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
#[allow(clippy::items_after_test_module)]
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
    async fn forced_refresh_respects_absolute_deadline_and_keeps_old_target_unusable() {
        let cache = Arc::new(ResidentDnsResolvedTargetCache::new(Duration::from_secs(2)));
        cache
            .seed(vec!["192.0.2.17:53".parse().unwrap()], Duration::ZERO)
            .await;
        let stale = cache
            .resolve(|_| async { Err("background refresh not used".to_owned()) })
            .await
            .unwrap();
        let deadline = time::Instant::now() + Duration::from_millis(10);
        let error = cache
            .refresh_after_stale_failure_and_resolve(&stale, deadline, |_| async {
                time::sleep(Duration::from_secs(1)).await;
                Ok(resolved("192.0.2.18:53", Duration::from_secs(60)))
            })
            .await
            .unwrap_err();
        assert_eq!(error, ResidentDnsTargetRefreshError::Deadline);

        let calls = Arc::new(AtomicUsize::new(0));
        let retry = cache
            .resolve({
                let calls = Arc::clone(&calls);
                move |_| async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    Ok(resolved("192.0.2.19:53", Duration::from_secs(60)))
                }
            })
            .await;
        assert!(retry.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn fresh_snapshot_target_failure_forces_one_refresh() {
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
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            cache.cached_addrs_for_test().unwrap()[0],
            "192.0.2.13:53".parse().unwrap()
        );
    }
}

struct RefreshAttemptGuard<'a> {
    cache: &'a ResidentDnsResolvedTargetCache,
    epoch: u64,
    armed: bool,
}

impl RefreshAttemptGuard<'_> {
    fn commit(mut self) {
        self.armed = false;
    }
}

impl Drop for RefreshAttemptGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(entry) = self
            .cache
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_mut()
            && entry.epoch == self.epoch
            && entry.invalidated_refresh_attempted
        {
            entry.invalidated_refresh_attempted = false;
        }
    }
}

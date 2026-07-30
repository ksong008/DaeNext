use super::*;
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, Weak};
use tokio::sync::mpsc;

use crate::production_runtime_owner::resident_dataplane::SharedResidentStopSignal;

use super::target_cache::ResidentDnsResolvedTargetCache;

pub(in crate::production_runtime_owner::resident_dataplane::dns) type ResidentDnsTargetRefreshOwnerTask =
    Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

type ResidentDnsTargetResolver = Box<
    dyn FnOnce(Duration) -> Pin<Box<dyn Future<Output = Result<ResolvedHostAddrs, String>> + Send>>
        + Send,
>;

pub(super) struct ResidentDnsTargetRefreshRequest {
    cache: Weak<ResidentDnsResolvedTargetCache>,
    resolver: Option<ResidentDnsTargetResolver>,
}

impl ResidentDnsTargetRefreshRequest {
    async fn run(mut self) {
        let Some(cache) = self.cache.upgrade() else {
            return;
        };
        let Some(resolver) = self.resolver.take() else {
            return;
        };
        let result = resolver(cache.refresh_interval()).await;
        cache.complete_background_refresh(result);
    }
}

impl Drop for ResidentDnsTargetRefreshRequest {
    fn drop(&mut self) {
        if let Some(cache) = self.cache.upgrade() {
            cache.cancel_background_refresh();
        }
    }
}

#[derive(Clone, Debug)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsTargetRefreshHandle
{
    sender: mpsc::Sender<ResidentDnsTargetRefreshRequest>,
}

impl ResidentDnsTargetRefreshHandle {
    pub(super) fn try_schedule<F, Fut>(
        &self,
        cache: &Arc<ResidentDnsResolvedTargetCache>,
        resolver: F,
    ) where
        F: FnOnce(Duration) -> Fut + Send + 'static,
        Fut: Future<Output = Result<ResolvedHostAddrs, String>> + Send + 'static,
    {
        let request = ResidentDnsTargetRefreshRequest {
            cache: Arc::downgrade(cache),
            resolver: Some(Box::new(move |refresh_interval| {
                Box::pin(resolver(refresh_interval))
            })),
        };
        let _ = self.sender.try_send(request);
    }
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsTargetRefreshOwner
{
    receiver: Mutex<Option<mpsc::Receiver<ResidentDnsTargetRefreshRequest>>>,
    concurrency: usize,
}

impl std::fmt::Debug for ResidentDnsTargetRefreshOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResidentDnsTargetRefreshOwner")
            .field("concurrency", &self.concurrency)
            .finish_non_exhaustive()
    }
}

impl ResidentDnsTargetRefreshOwner {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn new(
        resources: ResidentDnsResourceProfile,
    ) -> (Arc<Self>, ResidentDnsTargetRefreshHandle) {
        Self::with_limits(
            resources.target_refresh_concurrency(),
            resources.target_refresh_queue_depth(),
        )
    }

    fn with_limits(
        concurrency: usize,
        queue_depth: usize,
    ) -> (Arc<Self>, ResidentDnsTargetRefreshHandle) {
        let (sender, receiver) = mpsc::channel(queue_depth.max(1));
        (
            Arc::new(Self {
                receiver: Mutex::new(Some(receiver)),
                concurrency: concurrency.max(1),
            }),
            ResidentDnsTargetRefreshHandle { sender },
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn take_task(
        &self,
        stop: SharedResidentStopSignal,
    ) -> Result<Option<ResidentDnsTargetRefreshOwnerTask>, String> {
        let receiver = self
            .receiver
            .lock()
            .map_err(|_| "resident DNS target refresh owner lock poisoned".to_owned())?
            .take();
        Ok(receiver.map(|receiver| {
            Box::pin(run_resident_dns_target_refresh_owner(
                receiver,
                self.concurrency,
                stop,
            )) as ResidentDnsTargetRefreshOwnerTask
        }))
    }
}

async fn run_resident_dns_target_refresh_owner(
    mut receiver: mpsc::Receiver<ResidentDnsTargetRefreshRequest>,
    concurrency: usize,
    stop: SharedResidentStopSignal,
) {
    let concurrency = concurrency.max(1);
    let mut active = FuturesUnordered::new();
    let mut receiver_closed = false;
    let mut stop_listener = stop.listener();
    loop {
        if receiver_closed && active.is_empty() {
            return;
        }
        tokio::select! {
            _ = stop_listener.cancelled() => {
                receiver.close();
                return;
            }
            _ = active.next(), if !active.is_empty() => {}
            request = receiver.recv(), if !receiver_closed && active.len() < concurrency => {
                match request {
                    Some(request) => active.push(request.run()),
                    None => receiver_closed = true,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_runtime_owner::resident_dataplane::ResidentStopSignal;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn resolved(addr: &str, valid_for: Duration) -> ResolvedHostAddrs {
        ResolvedHostAddrs {
            addrs: vec![addr.parse().unwrap()],
            valid_for,
        }
    }

    #[tokio::test]
    async fn stale_target_returns_before_the_single_background_refresh_completes() {
        let (owner, handle) = ResidentDnsTargetRefreshOwner::with_limits(1, 4);
        let cache = Arc::new(ResidentDnsResolvedTargetCache::new(Duration::from_secs(60)));
        cache.install_refresh_handle(handle);
        cache
            .seed(vec!["192.0.2.1:53".parse().unwrap()], Duration::ZERO)
            .await;
        let stop = ResidentStopSignal::shared();
        let task = tokio::spawn(owner.take_task(Arc::clone(&stop)).unwrap().unwrap());
        let release = Arc::new(tokio::sync::Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));

        let stale = cache
            .resolve({
                let release = Arc::clone(&release);
                let calls = Arc::clone(&calls);
                move |_| async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    release.notified().await;
                    Ok(resolved("192.0.2.2:53", Duration::from_secs(60)))
                }
            })
            .await
            .unwrap();
        assert_eq!(stale.as_slice()[0], "192.0.2.1:53".parse().unwrap());

        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        release.notify_one();
        for _ in 0..20 {
            if cache
                .cached_addrs_for_test()
                .is_some_and(|addrs| addrs[0] == "192.0.2.2:53".parse::<SocketAddr>().unwrap())
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            cache.cached_addrs_for_test().unwrap()[0],
            "192.0.2.2:53".parse().unwrap()
        );
        stop.store(true, Ordering::Release);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn stale_failure_waits_for_the_existing_background_refresh() {
        let (owner, handle) = ResidentDnsTargetRefreshOwner::with_limits(1, 4);
        let cache = Arc::new(ResidentDnsResolvedTargetCache::new(Duration::from_secs(60)));
        cache.install_refresh_handle(handle);
        cache
            .seed(vec!["192.0.2.14:53".parse().unwrap()], Duration::ZERO)
            .await;
        let stop = ResidentStopSignal::shared();
        let owner_task = tokio::spawn(owner.take_task(Arc::clone(&stop)).unwrap().unwrap());
        let background_started = Arc::new(tokio::sync::Notify::new());
        let release_background = Arc::new(tokio::sync::Notify::new());
        let stale = cache
            .resolve({
                let background_started = Arc::clone(&background_started);
                let release_background = Arc::clone(&release_background);
                move |_| async move {
                    background_started.notify_one();
                    release_background.notified().await;
                    Ok(resolved("192.0.2.15:53", Duration::from_secs(60)))
                }
            })
            .await
            .unwrap();
        background_started.notified().await;

        let forced_calls = Arc::new(AtomicUsize::new(0));
        let feedback_task = tokio::spawn({
            let cache = Arc::clone(&cache);
            let forced_calls = Arc::clone(&forced_calls);
            async move {
                cache
                    .refresh_after_stale_failure(&stale, move |_| async move {
                        forced_calls.fetch_add(1, Ordering::Relaxed);
                        Ok(resolved("192.0.2.16:53", Duration::from_secs(60)))
                    })
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert!(!feedback_task.is_finished());
        assert_eq!(forced_calls.load(Ordering::Relaxed), 0);

        release_background.notify_one();
        feedback_task.await.unwrap().unwrap();
        assert_eq!(forced_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            cache.cached_addrs_for_test().unwrap()[0],
            "192.0.2.15:53".parse().unwrap()
        );
        stop.store(true, Ordering::Release);
        owner_task.await.unwrap();
    }

    #[tokio::test]
    async fn stopping_refresh_owner_releases_stale_failure_waiters() {
        let (owner, handle) = ResidentDnsTargetRefreshOwner::with_limits(1, 4);
        let cache = Arc::new(ResidentDnsResolvedTargetCache::new(Duration::from_secs(60)));
        cache.install_refresh_handle(handle);
        cache
            .seed(vec!["192.0.2.17:53".parse().unwrap()], Duration::ZERO)
            .await;
        let stop = ResidentStopSignal::shared();
        let owner_task = tokio::spawn(owner.take_task(Arc::clone(&stop)).unwrap().unwrap());
        let background_started = Arc::new(tokio::sync::Notify::new());
        let stale = cache
            .resolve({
                let background_started = Arc::clone(&background_started);
                move |_| async move {
                    background_started.notify_one();
                    std::future::pending::<Result<ResolvedHostAddrs, String>>().await
                }
            })
            .await
            .unwrap();
        background_started.notified().await;
        let feedback_task = tokio::spawn({
            let cache = Arc::clone(&cache);
            async move {
                cache
                    .refresh_after_stale_failure(&stale, |_| async {
                        Err("refresh owner stopped".to_owned())
                    })
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert!(!feedback_task.is_finished());

        stop.store(true, Ordering::Release);
        owner_task.await.unwrap();
        assert_eq!(
            time::timeout(Duration::from_secs(1), feedback_task)
                .await
                .expect("stale failure waiter remained blocked after owner stop")
                .unwrap()
                .unwrap_err(),
            "refresh owner stopped"
        );
    }
}

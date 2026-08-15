use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::task::{AbortHandle, JoinError, JoinHandle};
use tokio::time;

type UdpSessionReapFuture =
    Pin<Box<dyn Future<Output = (u64, Result<(), JoinError>)> + Send + 'static>>;

pub(super) struct UdpSessionReaper {
    limit: usize,
    next_id: u64,
    pending: FuturesUnordered<UdpSessionReapFuture>,
    aborts: HashMap<u64, AbortHandle>,
}

impl UdpSessionReaper {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            limit: limit.max(1),
            next_id: 0,
            pending: FuturesUnordered::new(),
            aborts: HashMap::new(),
        }
    }

    pub(super) fn has_capacity(&self) -> bool {
        self.pending.len() < self.limit
    }

    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub(super) fn retire(&mut self, handle: JoinHandle<()>) -> Result<(), JoinHandle<()>> {
        if !self.has_capacity() {
            return Err(handle);
        }
        self.track(handle);
        Ok(())
    }

    pub(super) fn retire_for_shutdown(&mut self, handle: JoinHandle<()>) {
        self.track(handle);
    }

    pub(super) async fn join_next(&mut self) -> Option<bool> {
        let (id, result) = self.pending.next().await?;
        self.aborts.remove(&id);
        Some(result.is_err())
    }

    pub(super) async fn join_until_deadline(
        &mut self,
        deadline: time::Instant,
    ) -> (usize, usize, usize) {
        let mut joined = 0_usize;
        let mut failed = 0_usize;
        loop {
            match time::timeout_at(deadline, self.join_next()).await {
                Ok(Some(false)) => joined = joined.saturating_add(1),
                Ok(Some(true)) => failed = failed.saturating_add(1),
                Ok(None) => return (joined, failed, 0),
                Err(_) => {
                    let timed_out = self.pending.len();
                    for abort in self.aborts.values() {
                        abort.abort();
                    }
                    while self.join_next().await.is_some() {}
                    return (joined, failed, timed_out);
                }
            }
        }
    }

    fn track(&mut self, handle: JoinHandle<()>) {
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let id = self.next_id;
        self.aborts.insert(id, handle.abort_handle());
        self.pending
            .push(Box::pin(async move { (id, handle.await) }));
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn runtime_reaper_is_bounded_and_releases_capacity() {
        let mut reaper = UdpSessionReaper::new(1);
        reaper
            .retire(tokio::spawn(async {
                time::sleep(Duration::from_millis(5)).await;
            }))
            .unwrap();
        let rejected = reaper.retire(tokio::spawn(async {})).unwrap_err();
        rejected.abort();
        let _ = rejected.await;

        assert_eq!(reaper.join_next().await, Some(false));
        assert!(reaper.has_capacity());
        assert!(reaper.is_empty());
    }

    #[tokio::test]
    async fn shutdown_reaper_aborts_tasks_at_one_shared_deadline() {
        let mut reaper = UdpSessionReaper::new(1);
        reaper.retire_for_shutdown(tokio::spawn(std::future::pending::<()>()));
        reaper.retire_for_shutdown(tokio::spawn(async {}));

        let (joined, failed, timed_out) = reaper
            .join_until_deadline(time::Instant::now() + Duration::from_millis(10))
            .await;
        assert_eq!(joined, 1);
        assert_eq!(failed, 0);
        assert_eq!(timed_out, 1);
        assert!(reaper.is_empty());
    }
}

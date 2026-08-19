use tokio::sync::mpsc;

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpSessionCleanup<Key> {
    pub key: Key,
    pub actor_id: u64,
}

pub(super) struct UdpSessionCleanupGuard<Key> {
    cleanup: Option<UdpSessionCleanup<Key>>,
    sender: mpsc::Sender<UdpSessionCleanup<Key>>,
    metrics: Arc<ResidentDataplaneMetrics>,
}

impl<Key> UdpSessionCleanupGuard<Key> {
    pub(super) fn new(
        key: Key,
        actor_id: u64,
        sender: mpsc::Sender<UdpSessionCleanup<Key>>,
        metrics: Arc<ResidentDataplaneMetrics>,
    ) -> Self {
        Self {
            cleanup: Some(UdpSessionCleanup { key, actor_id }),
            sender,
            metrics,
        }
    }
}

impl<Key> Drop for UdpSessionCleanupGuard<Key> {
    fn drop(&mut self) {
        let Some(cleanup) = self.cleanup.take() else {
            return;
        };
        if self.sender.try_send(cleanup).is_err() && !self.sender.is_closed() {
            self.metrics.udp_session_cleanup_notification_failed();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cleanup_guard_notifies_owner_during_unwind() {
        let (sender, mut receiver) = mpsc::channel(1);
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = UdpSessionCleanupGuard::new(7_u64, 11, sender, Arc::clone(&metrics));
            panic!("injected UDP actor panic");
        }));
        assert!(result.is_err());
        assert_eq!(
            receiver.recv().await,
            Some(UdpSessionCleanup {
                key: 7,
                actor_id: 11,
            })
        );
        assert_eq!(metrics.snapshot()["udpSessionCleanupNotificationFailed"], 0);
    }
}

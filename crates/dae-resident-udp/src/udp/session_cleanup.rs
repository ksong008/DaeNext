use tokio::sync::{mpsc, watch};

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpSessionCleanup<Key> {
    pub key: Key,
    pub actor_id: u64,
}

#[derive(Clone)]
pub struct UdpSessionCleanupSender<Key> {
    primary: mpsc::Sender<UdpSessionCleanup<Key>>,
    overflow: Option<(mpsc::Sender<UdpSessionCleanup<Key>>, watch::Sender<bool>)>,
}

impl<Key> From<mpsc::Sender<UdpSessionCleanup<Key>>> for UdpSessionCleanupSender<Key> {
    fn from(primary: mpsc::Sender<UdpSessionCleanup<Key>>) -> Self {
        Self {
            primary,
            overflow: None,
        }
    }
}

impl<Key> UdpSessionCleanupSender<Key> {
    pub fn with_overflow(
        primary: mpsc::Sender<UdpSessionCleanup<Key>>,
        overflow: mpsc::Sender<UdpSessionCleanup<Key>>,
        scan_needed: watch::Sender<bool>,
    ) -> Self {
        Self {
            primary,
            overflow: Some((overflow, scan_needed)),
        }
    }

    fn send(&self, cleanup: UdpSessionCleanup<Key>) -> bool {
        let Err(mpsc::error::TrySendError::Full(cleanup)) = self.primary.try_send(cleanup) else {
            return true;
        };
        let Some((overflow, scan_needed)) = self.overflow.as_ref() else {
            return false;
        };
        if matches!(
            overflow.try_send(cleanup),
            Err(mpsc::error::TrySendError::Full(_))
        ) {
            // The worker retries scans for the rest of this shard's lifetime.
            // The task may still be running its destructor when this is set.
            scan_needed.send_if_modified(|needed| !std::mem::replace(needed, true));
            return false;
        }
        true
    }
}

pub(super) struct UdpSessionCleanupGuard<Key> {
    cleanup: Option<UdpSessionCleanup<Key>>,
    sender: UdpSessionCleanupSender<Key>,
    metrics: Arc<ResidentDataplaneMetrics>,
}

impl<Key> UdpSessionCleanupGuard<Key> {
    pub(super) fn new(
        key: Key,
        actor_id: u64,
        sender: UdpSessionCleanupSender<Key>,
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
        if !self.sender.send(cleanup) {
            self.metrics.udp_session_cleanup_notification_failed();
        }
    }
}

#[cfg(test)]
mod tests;

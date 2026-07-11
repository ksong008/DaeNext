use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use super::{XhttpXmuxStateSignal, XhttpXmuxStateWait};

static NEXT_XHTTP_XMUX_MANAGER_GENERATION: AtomicU64 = AtomicU64::new(1);

pub(super) struct XhttpXmuxManagerLifecycle {
    generation: u64,
    closing: AtomicBool,
    opening: AtomicUsize,
    state_signal: XhttpXmuxStateSignal,
}

pub(super) struct XhttpXmuxOpeningLease {
    lifecycle: Arc<XhttpXmuxManagerLifecycle>,
    generation: u64,
}

pub(super) struct XhttpXmuxManagerHandle<M> {
    pub(super) manager: Arc<tokio::sync::Mutex<M>>,
    pub(super) lifecycle: Arc<XhttpXmuxManagerLifecycle>,
}

impl XhttpXmuxManagerLifecycle {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            generation: NEXT_XHTTP_XMUX_MANAGER_GENERATION.fetch_add(1, Ordering::Relaxed),
            closing: AtomicBool::new(false),
            opening: AtomicUsize::new(0),
            state_signal: XhttpXmuxStateSignal::new(),
        })
    }

    pub(super) fn reserve_opening(self: &Arc<Self>) -> Option<XhttpXmuxOpeningLease> {
        if self.is_closing() {
            return None;
        }
        self.opening.fetch_add(1, Ordering::AcqRel);
        if self.is_closing() {
            self.release_opening();
            return None;
        }
        self.state_signal.notify();
        Some(XhttpXmuxOpeningLease {
            lifecycle: Arc::clone(self),
            generation: self.generation,
        })
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) fn opening(&self) -> usize {
        self.opening.load(Ordering::Acquire)
    }

    pub(super) fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }

    pub(super) fn close(&self) {
        self.closing.store(true, Ordering::Release);
        self.state_signal.notify();
    }

    pub(super) fn notify(&self) {
        self.state_signal.notify();
    }

    pub(super) fn waiter(&self, deadline: Option<Instant>) -> XhttpXmuxStateWait {
        self.state_signal.waiter(deadline)
    }

    pub(super) fn signal(&self) -> XhttpXmuxStateSignal {
        self.state_signal.clone()
    }

    fn release_opening(&self) {
        let previous = self.opening.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "xHTTP xmux opening lease underflow");
        self.state_signal.notify();
    }
}

impl XhttpXmuxOpeningLease {
    pub(super) fn is_current(&self) -> bool {
        self.generation == self.lifecycle.generation && !self.lifecycle.is_closing()
    }

    #[cfg(test)]
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }
}

impl Drop for XhttpXmuxOpeningLease {
    fn drop(&mut self) {
        self.lifecycle.release_opening();
    }
}

impl<M> XhttpXmuxManagerHandle<M> {
    pub(super) fn new(build: impl FnOnce(Arc<XhttpXmuxManagerLifecycle>) -> M) -> Self {
        let lifecycle = XhttpXmuxManagerLifecycle::new();
        let manager = Arc::new(tokio::sync::Mutex::new(build(Arc::clone(&lifecycle))));
        Self { manager, lifecycle }
    }
}

impl<M> Clone for XhttpXmuxManagerHandle<M> {
    fn clone(&self) -> Self {
        Self {
            manager: Arc::clone(&self.manager),
            lifecycle: Arc::clone(&self.lifecycle),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(flavor = "current_thread")]
    async fn opening_lease_drop_releases_capacity_and_wakes_waiters() {
        let lifecycle = XhttpXmuxManagerLifecycle::new();
        let lease = lifecycle.reserve_opening().unwrap();
        let generation = lease.generation();
        assert_eq!(generation, lifecycle.generation());
        assert_eq!(lifecycle.opening(), 1);

        let waiter = lifecycle.waiter(None);
        drop(lease);
        tokio::time::timeout(Duration::from_millis(50), waiter.wait())
            .await
            .expect("opening lease drop did not wake xmux waiters");
        assert_eq!(lifecycle.opening(), 0);
    }

    #[test]
    fn closing_lifecycle_rejects_old_generation_and_new_reservations() {
        let lifecycle = XhttpXmuxManagerLifecycle::new();
        let lease = lifecycle.reserve_opening().unwrap();
        assert!(lease.is_current());

        lifecycle.close();
        assert!(lifecycle.is_closing());
        assert!(!lease.is_current());
        assert!(lifecycle.reserve_opening().is_none());

        drop(lease);
        assert_eq!(lifecycle.opening(), 0);
    }
}

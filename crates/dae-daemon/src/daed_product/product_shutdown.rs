use super::*;
use std::sync::Condvar;
use std::sync::atomic::{AtomicBool, AtomicI32};

#[derive(Debug, Default)]
pub(super) struct ProductShutdown {
    requested: AtomicBool,
    ready: AtomicBool,
    signal: AtomicI32,
    wake_lock: Mutex<()>,
    wake: Condvar,
}

impl ProductShutdown {
    pub(super) fn request(&self, signal: i32) -> bool {
        let guard = self
            .wake_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.requested.load(Ordering::Acquire) {
            return false;
        }
        self.signal.store(signal, Ordering::Release);
        self.ready.store(false, Ordering::Release);
        self.requested.store(true, Ordering::Release);
        drop(guard);
        self.wake.notify_all();
        allocator_notify_reclaim_monitor();
        true
    }

    pub(super) fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    pub(super) fn mark_ready(&self) -> bool {
        if self.is_requested() {
            return false;
        }
        self.ready.store(true, Ordering::Release);
        true
    }

    pub(super) fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire) && !self.is_requested()
    }

    pub(super) fn signal(&self) -> Option<i32> {
        self.is_requested()
            .then(|| self.signal.load(Ordering::Acquire))
            .filter(|signal| *signal != 0)
    }

    pub(super) fn wait_timeout(&self, timeout: Duration) -> bool {
        if self.is_requested() {
            return true;
        }
        let guard = self
            .wake_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = self
            .wake
            .wait_timeout_while(guard, timeout, |_| !self.is_requested())
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.is_requested()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_request_is_idempotent_and_wakes_waiters() {
        let shutdown = Arc::new(ProductShutdown::default());
        let waiter = Arc::clone(&shutdown);
        let joined = thread::spawn(move || waiter.wait_timeout(Duration::from_secs(2)));
        thread::sleep(Duration::from_millis(10));
        assert!(shutdown.request(libc::SIGTERM));
        assert!(!shutdown.request(libc::SIGINT));
        assert!(joined.join().unwrap());
        assert_eq!(shutdown.signal(), Some(libc::SIGTERM));
    }
}

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

pub trait ProductShutdownWakeHook: Send + Sync {
    fn wake(&self);
}

#[derive(Default)]
pub struct NoopProductShutdownWakeHook;

impl ProductShutdownWakeHook for NoopProductShutdownWakeHook {
    fn wake(&self) {}
}

pub struct ProductShutdown {
    requested: AtomicBool,
    ready: AtomicBool,
    signal: AtomicI32,
    wake_lock: Mutex<()>,
    wake: Condvar,
    hook: Arc<dyn ProductShutdownWakeHook>,
}

impl std::fmt::Debug for ProductShutdown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductShutdown")
            .field("requested", &self.requested.load(Ordering::Relaxed))
            .field("ready", &self.ready.load(Ordering::Relaxed))
            .field("signal", &self.signal.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Default for ProductShutdown {
    fn default() -> Self {
        Self::with_wake_hook(Arc::new(NoopProductShutdownWakeHook))
    }
}

impl ProductShutdown {
    pub fn with_wake_hook(hook: Arc<dyn ProductShutdownWakeHook>) -> Self {
        Self {
            requested: AtomicBool::new(false),
            ready: AtomicBool::new(false),
            signal: AtomicI32::new(0),
            wake_lock: Mutex::new(()),
            wake: Condvar::new(),
            hook,
        }
    }

    pub fn request(&self, signal: i32) -> bool {
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
        self.hook.wake();
        true
    }

    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    pub fn mark_ready(&self) -> bool {
        if self.is_requested() {
            return false;
        }
        self.ready.store(true, Ordering::Release);
        true
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire) && !self.is_requested()
    }

    pub fn signal(&self) -> Option<i32> {
        self.is_requested()
            .then(|| self.signal.load(Ordering::Acquire))
            .filter(|signal| *signal != 0)
    }

    pub fn wait_timeout(&self, timeout: Duration) -> bool {
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
    use std::sync::atomic::AtomicU64;
    use std::thread;

    struct CountingWakeHook(AtomicU64);

    impl ProductShutdownWakeHook for CountingWakeHook {
        fn wake(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn shutdown_request_is_idempotent_and_wakes_waiters() {
        let hook = Arc::new(CountingWakeHook(AtomicU64::new(0)));
        let shutdown = Arc::new(ProductShutdown::with_wake_hook(hook.clone()));
        let waiter = Arc::clone(&shutdown);
        let joined = thread::spawn(move || waiter.wait_timeout(Duration::from_secs(2)));
        thread::sleep(Duration::from_millis(10));
        assert!(shutdown.request(15));
        assert!(!shutdown.request(2));
        assert!(joined.join().unwrap());
        assert_eq!(shutdown.signal(), Some(15));
        assert_eq!(hook.0.load(Ordering::Relaxed), 1);
    }
}

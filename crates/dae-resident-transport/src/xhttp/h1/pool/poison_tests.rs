use super::*;
use std::sync::atomic::AtomicUsize;

struct TrackedClient(Arc<AtomicUsize>);

impl Drop for TrackedClient {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn poisoned_pool_rejects_reuse_and_still_drops_idle_connections() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let pool = XhttpH1UploadPool::new(1);
    pool.inner.put(TrackedClient(Arc::clone(&dropped)));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = pool.inner.idle.lock().unwrap();
        panic!("injected upload pool poison");
    }));
    assert!(pool.take().await.err().unwrap().contains("poisoned"));
    pool.inner.put(TrackedClient(Arc::clone(&dropped)));
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
    pool.close();
    assert_eq!(dropped.load(Ordering::Relaxed), 2);
    assert!(pool.take().await.is_err());
    drop(pool);
    assert_eq!(dropped.load(Ordering::Relaxed), 2);
}

use super::*;
use std::sync::{Weak, atomic::AtomicUsize};

struct Client {
    drops: Arc<AtomicUsize>,
    pool: Weak<PoolInner<Client>>,
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.upgrade() {
            assert!(
                !matches!(
                    pool.idle.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ),
                "client teardown held the idle lock"
            );
        }
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}

fn client(pool: &XhttpH1UploadPool<Client>, drops: &Arc<AtomicUsize>) -> Client {
    Client {
        drops: Arc::clone(drops),
        pool: Arc::downgrade(&pool.inner),
    }
}

async fn advance_past_ttl() {
    // Let the shared worker establish its first tick before advancing time.
    tokio::task::yield_now().await;
    time::advance(IDLE_TTL + IDLE_TTL / 2).await;
    tokio::task::yield_now().await;
}

#[tokio::test(start_paused = true)]
async fn idle_connection_expires_without_another_take_or_put() {
    let drops = Arc::new(AtomicUsize::new(0));
    let pool = XhttpH1UploadPool::new(1);
    pool.inner.put(client(&pool, &drops));
    advance_past_ttl().await;
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert!(pool.inner.idle.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn borrowed_client_crosses_ttl_and_receives_a_new_idle_deadline_on_return() {
    let drops = Arc::new(AtomicUsize::new(0));
    let pool = XhttpH1UploadPool::new(1);
    pool.inner.put(client(&pool, &drops));
    let (borrowed, inner, permit) = pool.take().await.unwrap();
    advance_past_ttl().await;
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    inner.put(borrowed.unwrap());
    drop(permit);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    advance_past_ttl().await;
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[tokio::test(start_paused = true)]
async fn close_unregisters_and_late_returns_cannot_resurrect_the_pool() {
    let drops = Arc::new(AtomicUsize::new(0));
    let pool = XhttpH1UploadPool::new(2);
    let late = client(&pool, &drops);
    pool.inner.put(client(&pool, &drops));
    let (_, inner, permit) = pool.take().await.unwrap();
    // The first borrowed client was dropped by the destructured result above.
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    pool.close();
    assert!(inner.maintenance.lock().unwrap().is_none());
    inner.put(late);
    drop(permit);
    advance_past_ttl().await;
    assert_eq!(drops.load(Ordering::Relaxed), 2);
    assert!(pool.take().await.is_err());
    assert!(inner.idle.lock().unwrap().is_empty());
}

#[tokio::test]
async fn expiry_close_and_return_race_drop_each_client_once_outside_locks() {
    for _ in 0..16 {
        let drops = Arc::new(AtomicUsize::new(0));
        let pool = Arc::new(XhttpH1UploadPool::new(2));
        pool.inner.put(client(&pool, &drops));
        // Concurrent teardown can legitimately overlap a different sweeper's
        // idle lock. The single-threaded TTL tests check lock-free destruction.
        let mut late = client(&pool, &drops);
        late.pool = Weak::new();
        pool.inner.idle.lock().unwrap()[0].1.pool = Weak::new();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let sweep_pool = Arc::clone(&pool);
        let sweep_barrier = Arc::clone(&barrier);
        let sweep = std::thread::spawn(move || {
            sweep_barrier.wait();
            sweep_pool.inner.prune_idle(time::Instant::now() + IDLE_TTL);
        });
        barrier.wait();
        pool.close();
        pool.inner.put(late);
        sweep.join().unwrap();
        assert_eq!(drops.load(Ordering::Relaxed), 2);
        assert!(pool.inner.idle.lock().unwrap().is_empty());
    }
}

#[test]
fn construction_before_runtime_defers_registration_until_first_take() {
    let pool = XhttpH1UploadPool::<Client>::new(1);
    assert!(pool.inner.maintenance.lock().unwrap().is_none());
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let (_, _, permit) = pool.take().await.unwrap();
            assert!(pool.inner.maintenance.lock().unwrap().is_some());
            drop(permit);
            pool.close();
        });
}

#[test]
fn moved_pool_registers_with_the_new_executor_after_the_old_runtime_stops() {
    let drops = Arc::new(AtomicUsize::new(0));
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let pool = first.block_on(async { XhttpH1UploadPool::<Client>::new(1) });
    drop(first);
    let second = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    second.block_on(async {
        time::pause();
        let (_, inner, permit) = pool.take().await.unwrap();
        inner.put(client(&pool, &drops));
        drop(permit);
        advance_past_ttl().await;
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        pool.close();
    });
}

#[tokio::test]
async fn idle_maintenance_releases_a_real_socket_without_further_pool_access() {
    // Frozen time exercises the actual maintenance task and actual TCP EOF,
    // while keeping the production test suite independent of wall-clock TTL.
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut peer, _) = listener.accept().await.unwrap();
    let pool = XhttpH1UploadPool::new(1);
    pool.inner.put(client);
    time::pause();
    advance_past_ttl().await;
    time::resume();
    assert_eq!(
        time::timeout(Duration::from_secs(1), peer.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

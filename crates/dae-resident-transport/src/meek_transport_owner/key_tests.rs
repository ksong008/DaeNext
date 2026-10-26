use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn owner() -> Arc<MeekTransportGenerationOwner> {
    Arc::new(MeekTransportGenerationOwner {
        generation: OwnerGeneration::new(fastrand::u64(1..)),
        closing: AtomicBool::new(false),
        runtime: tokio::runtime::Handle::current(),
        runtime_worker_threads: 1,
        uses_shared_data_plane_executor: true,
        pools: Mutex::new(HashMap::new()),
        quiescent: Arc::new(Notify::new()),
        builds: Mutex::new(HashMap::new()),
        resources: MeekTransportResourceProfile::selected().with_transport_limits_for_test(
            1,
            2,
            1,
            Duration::from_millis(40),
        ),
        metrics: Arc::new(MeekTransportMetrics::default()),
        changed: Notify::new(),
        next_build_id: AtomicU64::new(1),
    })
}

fn key(owner: &MeekTransportGenerationOwner, n: u8) -> MeekTransportKey {
    MeekTransportKey {
        generation: owner.generation,
        digest: [n; 32],
    }
}

fn deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(2))
}

#[tokio::test]
async fn acquisition_and_detached_build_protect_key_until_actual_exit() {
    let owner = owner();
    let old_key = key(&owner, 1);
    for panic in [false, true] {
        let (old, pin) = meek_transport_pool(&owner, old_key).unwrap();
        let slot = try_reserve_meek_physical(&owner, &old, &pin).ok().unwrap();
        let (_, waiter) = meek_transport_pool(&owner, old_key).unwrap();
        let (ready, entered) = tokio::sync::oneshot::channel();
        let (release, finish) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _slot = slot;
            ready.send(()).unwrap();
            let _ = finish.await;
            assert!(!panic, "injected build failure");
        });
        entered.await.unwrap();
        drop(pin); // The outer acquisition has been cancelled after handoff.
        prune_empty_meek_keys(&mut cleanup_lock(&owner.pools));
        assert!(meek_transport_pool(&owner, key(&owner, 2)).is_err());
        drop(waiter);
        prune_empty_meek_keys(&mut cleanup_lock(&owner.pools));
        assert_eq!(cleanup_lock(&owner.pools).len(), 1);
        if panic {
            release.send(()).unwrap();
        } else {
            task.abort();
        }
        assert!(task.await.is_err());
        assert_eq!(old.physical_count.load(Ordering::Relaxed), 0);
        assert_eq!(owner.metrics.reserved_physical.load(Ordering::Relaxed), 0);
        let (new, new_pin) = meek_transport_pool(&owner, key(&owner, 2)).unwrap();
        assert!(!Arc::ptr_eq(&old, &new));
        // Retaining the old Arc is not a liveness pin or a removal credential.
        prune_empty_meek_keys(&mut cleanup_lock(&owner.pools));
        assert!(Arc::ptr_eq(
            cleanup_lock(&owner.pools).get(&key(&owner, 2)).unwrap(),
            &new
        ));
        drop(new_pin);
        prune_empty_meek_keys(&mut cleanup_lock(&owner.pools));
        assert!(cleanup_lock(&owner.pools).is_empty());
    }
    owner.closing.store(true, Ordering::Release);
    assert!(meek_transport_pool(&owner, old_key).is_err());
}

#[tokio::test]
async fn failed_keys_recover_and_live_tls_lease_survives_pruning() {
    use dae_outbound::shared_transport::test_support::{self_signed_tls_identity, tls13_acceptor};
    let owner = owner();
    register_meek_transport_generation(&owner).unwrap();
    for _ in 0..5 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let binding =
            crate::vless_mux_owner::poison_tests::test_binding_at(owner.generation.get(), address);
        assert!(acquire_meek_transport(binding, deadline()).await.is_err());
        prune_empty_meek_keys(&mut cleanup_lock(&owner.pools));
        assert!(cleanup_lock(&owner.pools).is_empty());
        assert_eq!(owner.metrics.reserved_physical.load(Ordering::Relaxed), 0);
        assert_eq!(owner.metrics.active_builds.load(Ordering::Relaxed), 0);
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let identity = self_signed_tls_identity(&["localhost"]).unwrap();
    let acceptor = tls13_acceptor(&identity, &[b"http/1.1".to_vec()]).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = tokio_boring::accept(&acceptor, stream).await.unwrap();
        let mut buffer = [0; 16];
        loop {
            let n = stream.read(&mut buffer).await.unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buffer[..n]).await.unwrap();
        }
    });
    let binding =
        crate::vless_mux_owner::poison_tests::test_binding_at(owner.generation.get(), address);
    let mut lease = acquire_meek_transport(binding.clone(), deadline())
        .await
        .unwrap();
    prune_expired_meek_idle(&owner);
    assert_eq!(cleanup_lock(&owner.pools).len(), 1);
    assert!(meek_transport_pool(&owner, key(&owner, 7)).is_err());
    lease.client_mut().write_all(b"live").await.unwrap();
    let mut response = [0; 4];
    lease.client_mut().read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"live");
    lease.recycle();
    let pool = cleanup_lock(&owner.pools)
        .get(&MeekTransportKey::for_binding(&binding))
        .unwrap()
        .clone();
    cleanup_lock(&pool.idle).front_mut().unwrap().idle_since =
        Instant::now() - Duration::from_secs(1);
    prune_expired_meek_idle(&owner);
    assert!(cleanup_lock(&owner.pools).is_empty());
    assert_eq!(owner.metrics.reserved_physical.load(Ordering::Relaxed), 0);
    assert_eq!(owner.metrics.active_physical.load(Ordering::Relaxed), 0);
    assert_eq!(pool.physical_count.load(Ordering::Relaxed), 0);
    time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    unregister_meek_transport_generation(&owner);
    cleanup_meek_transport_owner(&owner).await;
}

use super::*;
use std::time::Duration;

fn owner() -> Arc<H2CarrierGenerationOwner> {
    Arc::new(H2CarrierGenerationOwner {
        generation: OwnerGeneration::new(fastrand::u64(1..)),
        closing: AtomicBool::new(false),
        runtime: tokio::runtime::Handle::current(),
        runtime_worker_threads: 1,
        uses_shared_data_plane_executor: true,
        managers: Mutex::new(HashMap::new()),
        quiescent: Arc::new(Notify::new()),
        builds: Mutex::new(HashMap::new()),
        drivers: Mutex::new(HashMap::new()),
        resources: H2CarrierOwnerResourceProfile::selected().with_owner_limit(1),
        metrics: Arc::new(H2CarrierMetrics::default()),
        next_build_id: AtomicU64::new(1),
        next_instance_id: AtomicU64::new(1),
    })
}

fn key(owner: &H2CarrierGenerationOwner, n: u8) -> H2CarrierKey {
    H2CarrierKey {
        generation: owner.generation,
        digest: [n; 32],
    }
}

fn deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(2))
}

fn binding(
    owner: &H2CarrierGenerationOwner,
    address: std::net::SocketAddr,
) -> ResidentProxyBinding {
    use dae_resident_model as plan;
    let fixture =
        crate::vless_mux_owner::poison_tests::test_binding_at(owner.generation.get(), address);
    let mut proxy = fixture.plan().clone();
    proxy.net = "grpc".into();
    proxy.alpn = vec!["h2".into()];
    proxy.handler = plan::ResidentProxyProtocolPlan::VlessVisionTcpTls {
        key: [11; 16],
        encryption: None,
    };
    proxy.materialize_execution();
    plan::ResidentProxyBinding::resident(Arc::new(proxy), owner.generation).unwrap()
}

#[tokio::test]
async fn registry_pin_serializes_prune_with_acquisition_and_handoff() {
    let owner = owner();
    let first_key = key(&owner, 1);
    let (old, pin) = h2_carrier_manager(&owner, first_key).unwrap();
    // A stale snapshot is deliberately retained through replacement. It has no
    // authority to remove anything: pruning inspects the current indexed entry.
    let stale = Arc::clone(&old);
    let (same, waiting) = h2_carrier_manager(&owner, first_key).unwrap();
    assert!(Arc::ptr_eq(&same, &old));
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
    let execution = tokio::spawn(async move {
        let _pin = waiting;
        ready_tx.send(()).unwrap();
        let _ = finish_rx.await;
    });
    ready_rx.await.unwrap();
    drop(pin);
    prune_h2_keys(&mut cleanup_lock(&owner.managers));
    assert!(h2_carrier_manager(&owner, key(&owner, 2)).is_err());
    finish_tx.send(()).unwrap();
    execution.await.unwrap();
    let (new, new_pin) = h2_carrier_manager(&owner, key(&owner, 2)).unwrap();
    assert!(!Arc::ptr_eq(&old, &new));
    assert!(stale.usage.is_quiescent());
    prune_h2_keys(&mut cleanup_lock(&owner.managers));
    assert!(Arc::ptr_eq(
        cleanup_lock(&owner.managers).get(&key(&owner, 2)).unwrap(),
        &new
    ));
    drop(new_pin);
    prune_h2_keys(&mut cleanup_lock(&owner.managers));
    owner.closing.store(true, Ordering::Release);
    assert!(h2_carrier_manager(&owner, first_key).is_err());
    assert!(cleanup_lock(&owner.managers).is_empty());
}

#[tokio::test]
async fn abort_and_panic_release_the_last_execution_pin() {
    let owner = owner();
    for panic in [false, true] {
        let (_, pin) = h2_carrier_manager(&owner, key(&owner, 1)).unwrap();
        let task = tokio::spawn(async move {
            let _pin = pin;
            if panic {
                panic!("injected owner execution failure");
            }
            std::future::pending::<()>().await;
        });
        if !panic {
            task.abort();
        }
        assert!(task.await.is_err());
        prune_h2_keys(&mut cleanup_lock(&owner.managers));
        assert!(cleanup_lock(&owner.managers).is_empty());
    }
}

#[tokio::test]
async fn last_pin_wakes_existing_owner_maintenance_without_new_admission() {
    let owner = owner();
    let stop = dae_resident_core::ResidentStopSignal::shared();
    let worker = {
        let owner = Arc::clone(&owner);
        let stop = Arc::clone(&stop);
        tokio::spawn(async move { maintain_h2_keys(&owner, &stop).await })
    };
    let (_, pin) = h2_carrier_manager(&owner, key(&owner, 1)).unwrap();
    drop(pin);
    time::timeout(Duration::from_secs(1), async {
        while !cleanup_lock(&owner.managers).is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    stop.store(true, Ordering::Release);
    worker.await.unwrap();
}

#[tokio::test]
async fn failed_loopback_keys_restore_capacity_repeatedly() {
    let owner = owner();
    register_h2_carrier_generation(&owner).unwrap();
    for _ in 0..5 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener); // An actual refused connect, with a distinct transport key.
        assert!(
            acquire_h2_carrier(binding(&owner, address), deadline())
                .await
                .is_err()
        );
        prune_h2_keys(&mut cleanup_lock(&owner.managers));
        assert!(cleanup_lock(&owner.managers).is_empty());
        assert_eq!(owner.metrics.active_builds.load(Ordering::Relaxed), 0);
        assert_eq!(owner.metrics.reserved_physical.load(Ordering::Relaxed), 0);
    }
    unregister_h2_carrier_generation(&owner);
    cleanup_h2_carrier_owner(&owner).await;
}

#[tokio::test]
async fn closing_old_driver_cannot_invalidate_rebuilt_stream_after_lease_drop() {
    use dae_outbound::shared_transport::test_support::{self_signed_tls_identity, tls13_acceptor};
    let mut owner = owner();
    Arc::get_mut(&mut owner).unwrap().resources =
        H2CarrierOwnerResourceProfile::selected().with_owner_limit(2);
    register_h2_carrier_generation(&owner).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let identity = self_signed_tls_identity(&["localhost"]).unwrap();
    let acceptor = tls13_acceptor(&identity, &[b"h2".to_vec()]).unwrap();
    let server = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = accepted.unwrap();
                    let acceptor = acceptor.clone();
                    tasks.spawn(async move {
                        let stream = tokio_boring::accept(&acceptor, stream).await.unwrap();
                        let mut connection = h2::server::handshake(stream).await.unwrap();
                        while let Some(Ok((_, mut respond))) = connection.accept().await {
                            let mut body = respond.send_response(http::Response::new(()), false).unwrap();
                            body.send_data(Bytes::from_static(b"still alive"), true).unwrap();
                        }
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    });
    let proxy = binding(&owner, address);
    let old = acquire_h2_carrier(proxy.clone(), deadline()).await.unwrap();
    let old_id = old.physical_instance_id();
    invalidate_h2_carrier(&owner, old.key, old_id).await;
    let new = acquire_h2_carrier(proxy, deadline()).await.unwrap();
    assert_ne!(old_id, new.physical_instance_id());
    // The old callback runs only after the replacement has been installed.
    old.invalidate();
    drop(old);
    let request = http::Request::builder()
        .uri("https://localhost/test")
        .body(())
        .unwrap();
    let (response, send) = new
        .open_request(request, true, deadline(), "key regression")
        .await
        .unwrap();
    drop(new);
    prune_h2_keys(&mut cleanup_lock(&owner.managers));
    assert_eq!(cleanup_lock(&owner.managers).len(), 1);
    let mut body = time::timeout(Duration::from_secs(2), response)
        .await
        .unwrap()
        .unwrap()
        .into_body();
    assert_eq!(body.data().await.unwrap().unwrap(), &b"still alive"[..]);
    drop((send, body));
    unregister_h2_carrier_generation(&owner);
    cleanup_h2_carrier_owner(&owner).await;
    server.abort();
    let _ = server.await;
}

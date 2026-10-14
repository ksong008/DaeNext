use super::*;
use dae_resident_model as plan;

fn poison<T>(lock: &Mutex<T>) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = lock.lock().unwrap();
        panic!("injected inventory poison");
    }));
    assert!(lock.is_poisoned());
}

#[tokio::test]
async fn poisoned_build_registry_rejects_without_spinning_or_leaking_capacity() {
    let stop = dae_resident_core::ResidentStopSignal::shared();
    let (handle, shutdown) = start_vless_mux_generation_owner_on(
        &tokio::runtime::Handle::current(),
        fastrand::u64(..),
        Arc::clone(&stop),
        1,
    )
    .unwrap();
    let owner = &handle.owner;
    let binding = test_binding(owner.generation.get());
    let key = VlessMuxTransportKey::for_binding(&binding);
    let pool = vless_mux_pool(owner, key).unwrap();
    let capacity = try_reserve_vless_mux_physical(owner, &pool).unwrap();
    poison(&owner.builds);
    let error = build_vless_mux_physical(
        owner,
        &pool,
        binding,
        key,
        AbsoluteDeadline::from_now(Instant::now(), std::time::Duration::from_secs(1)),
        capacity,
    )
    .await
    .err()
    .unwrap();
    assert!(error.contains("poisoned"));
    assert_eq!(owner.metrics.reserved_physical.load(Ordering::Relaxed), 0);
    assert_eq!(pool.physical_count.load(Ordering::Relaxed), 0);
    assert_eq!(owner.metrics.active_builds.load(Ordering::Relaxed), 0);
    stop.store(true, Ordering::Release);
    shutdown.await.unwrap();
}

#[tokio::test]
async fn poisoned_mux_inventories_close_existing_physical_and_reap_builds() {
    let stop = dae_resident_core::ResidentStopSignal::shared();
    let (handle, shutdown) = start_vless_mux_generation_owner_on(
        &tokio::runtime::Handle::current(),
        fastrand::u64(..),
        Arc::clone(&stop),
        1,
    )
    .unwrap();
    let owner = &handle.owner;
    let key = VlessMuxTransportKey {
        generation: owner.generation,
        digest: [0; 32],
    };
    let pool = vless_mux_pool(owner, key).unwrap();
    let capacity = try_reserve_vless_mux_physical(owner, &pool).unwrap();
    let physical = super::tests::selection_test_physical(1, 0, true, false);
    // Share the owner's metric inventory rather than the selection fixture's.
    owner.metrics.physical_opened();
    let guard = VlessMuxPhysicalMetricGuard {
        physical: Arc::clone(&physical),
        owner: Arc::clone(owner),
        _capacity: capacity,
    };
    physical.idle.store(false, Ordering::Release);
    let physical_stop = Arc::clone(&physical.stop);
    let actor = tokio::spawn(async move {
        let _guard = guard;
        physical_stop.listener().cancelled().await;
    });
    physical.abort.set(actor.abort_handle()).unwrap();
    pool.physical.lock().unwrap().push(Arc::clone(&physical));
    owner.metrics.active_builds.store(1, Ordering::Relaxed);
    let guard = VlessMuxBuildGuard {
        owner: Arc::clone(owner),
        build_id: 1,
    };
    let build = tokio::spawn(async move {
        let _guard = guard;
        std::future::pending::<()>().await;
    });
    owner.builds.lock().unwrap().insert(1, build.abort_handle());
    poison(&pool.physical);
    poison(&owner.pools);
    poison(&owner.builds);
    assert!(select_vless_mux_physical(owner, &pool).is_err());
    stop.store(true, Ordering::Release);
    time::timeout(std::time::Duration::from_secs(1), shutdown)
        .await
        .unwrap()
        .unwrap();
    actor.await.unwrap();
    assert!(build.await.unwrap_err().is_cancelled());
    assert!(physical.closed.load(Ordering::Acquire));
    assert!(cleanup_lock(&owner.pools).is_empty());
    assert!(cleanup_lock(&owner.builds).is_empty());
    assert_eq!(owner.metrics.active_physical.load(Ordering::Relaxed), 0);
    assert_eq!(owner.metrics.reserved_physical.load(Ordering::Relaxed), 0);
    assert_eq!(owner.metrics.active_builds.load(Ordering::Relaxed), 0);
    assert!(owner.pools.is_poisoned());
    assert!(!owner.metrics.shutdown_timed_out.load(Ordering::Relaxed));
}

fn test_binding(generation: u64) -> plan::ResidentProxyBinding {
    let mut proxy = plan::ResidentProxyPlan {
        graph_id: "resident-graph:poison-test".to_owned(),
        graph_link_hash: "sha256:poison-test".to_owned(),
        redacted_link_source: "vless://<redacted>".to_owned(),
        protocol: "vless",
        group_name: "mux-owner-test".to_owned(),
        group_policy: "fixed".to_owned(),
        node_tag: "mux-owner-node".to_owned(),
        server_host: "127.0.0.1".to_owned(),
        server_port: 1,
        server_name: "localhost".to_owned(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "mux".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        grpc_mode: dae_outbound::shared_transport::GrpcMode::Gun,
        xhttp_download: None,
        xhttp_mode: plan::ResidentXhttpMode::PacketUp,
        xhttp_settings: plan::ResidentXhttpSettingsPlan::default(),
        xhttp_xmux: None,
        tls: "tls".to_owned(),
        allow_insecure: true,
        tls_fragment: None,
        utls_fingerprint: None,
        ech: None,
        reality: None,
        handler: plan::ResidentProxyProtocolPlan::VlessMuxTcpTls {
            key: [11; 16],
            encryption: None,
        },
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    };
    proxy.materialize_execution();
    plan::ResidentProxyBinding::resident(
        Arc::new(proxy),
        dae_runtime_control::OwnerGeneration::new(generation),
    )
    .expect("materialized VLESS mux owner test binding")
}

use super::*;

fn poison<T>(lock: &Mutex<T>) {
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = lock.lock().unwrap();
            panic!("injected inventory poison");
        }))
        .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poisoned_carrier_inventories_still_abort_tasks_and_wake_managers() {
    let stop = dae_resident_core::ResidentStopSignal::shared();
    let (handle, shutdown) = start_h2_carrier_generation_owner_on(
        &tokio::runtime::Handle::current(),
        fastrand::u64(..),
        Arc::clone(&stop),
        1,
    )
    .unwrap();
    let owner = &handle.owner;
    let manager = Arc::new(H2CarrierManager::new());
    manager.state.lock().await.opening_build = Some(1);
    owner.managers.lock().unwrap().insert(
        H2CarrierKey {
            generation: owner.generation,
            digest: [0; 32],
        },
        Arc::clone(&manager),
    );
    owner.metrics.active_builds.store(1, Ordering::Relaxed);
    let build_guard = H2BuildMetricGuard {
        owner: Arc::clone(owner),
        build_id: 1,
    };
    let build = tokio::spawn(async move {
        let _guard = build_guard;
        std::future::pending::<()>().await;
    });
    owner.builds.lock().unwrap().insert(1, build.abort_handle());
    owner.metrics.physical_opened();
    let physical_guard = H2PhysicalMetricGuard {
        metrics: Arc::clone(&owner.metrics),
    };
    let driver_guard = H2DriverInventoryGuard {
        owner: Arc::clone(owner),
        instance_id: 2,
    };
    let driver = tokio::spawn(async move {
        let _physical = physical_guard;
        let _inventory = driver_guard;
        std::future::pending::<()>().await;
    });
    owner
        .drivers
        .lock()
        .unwrap()
        .insert(2, driver.abort_handle());
    poison(&owner.managers);
    poison(&owner.builds);
    poison(&owner.drivers);
    let changed = manager.changed.notified();
    tokio::pin!(changed);
    changed.as_mut().enable();
    stop.store(true, Ordering::Release);
    time::timeout(std::time::Duration::from_secs(1), shutdown)
        .await
        .unwrap()
        .unwrap();
    time::timeout(std::time::Duration::from_secs(1), changed)
        .await
        .unwrap();
    assert!(build.await.unwrap_err().is_cancelled());
    assert!(driver.await.unwrap_err().is_cancelled());
    assert!(manager.state.lock().await.opening_build.is_none());
    assert!(cleanup_lock(&owner.builds).is_empty());
    assert!(cleanup_lock(&owner.drivers).is_empty());
    assert!(owner.builds.is_poisoned());
    assert_eq!(owner.metrics.active_builds.load(Ordering::Relaxed), 0);
    assert_eq!(owner.metrics.active_physical.load(Ordering::Relaxed), 0);
    assert!(!owner.metrics.shutdown_timed_out.load(Ordering::Relaxed));
}

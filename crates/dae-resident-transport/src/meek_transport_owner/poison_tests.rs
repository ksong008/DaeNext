use super::*;

#[tokio::test]
async fn poisoned_meek_build_inventory_is_reaped_before_shutdown_returns() {
    let stop = dae_resident_core::ResidentStopSignal::shared();
    let (handle, shutdown) = start_meek_transport_generation_owner_on(
        &tokio::runtime::Handle::current(),
        fastrand::u64(..),
        Arc::clone(&stop),
        1,
    )
    .unwrap();
    let owner = &handle.owner;
    owner.metrics.active_builds.store(1, Ordering::Relaxed);
    let guard = MeekBuildGuard {
        owner: Arc::clone(owner),
        build_id: 1,
    };
    let build = tokio::spawn(async move {
        let _guard = guard;
        std::future::pending::<()>().await;
    });
    owner.builds.lock().unwrap().insert(1, build.abort_handle());
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = owner.builds.lock().unwrap();
        panic!("injected build inventory poison");
    }));
    stop.store(true, Ordering::Release);
    time::timeout(std::time::Duration::from_secs(1), shutdown)
        .await
        .unwrap()
        .unwrap();
    assert!(build.await.unwrap_err().is_cancelled());
    assert!(cleanup_lock(&owner.builds).is_empty());
    assert!(owner.builds.is_poisoned());
    assert_eq!(owner.metrics.active_builds.load(Ordering::Relaxed), 0);
    assert!(!owner.metrics.shutdown_timed_out.load(Ordering::Relaxed));
}

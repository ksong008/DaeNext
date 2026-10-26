use super::*;
use std::time::Duration;

fn owner() -> Arc<VlessMuxGenerationOwner> {
    Arc::new(VlessMuxGenerationOwner {
        generation: OwnerGeneration::new(fastrand::u64(1..)),
        closing: AtomicBool::new(false),
        runtime: tokio::runtime::Handle::current(),
        runtime_worker_threads: 1,
        uses_shared_data_plane_executor: true,
        pools: Mutex::new(HashMap::new()),
        quiescent: Arc::new(tokio::sync::Notify::new()),
        builds: Mutex::new(HashMap::new()),
        resources: VlessMuxOwnerResourceProfile::selected().with_limits_for_test(
            1,
            2,
            8,
            64,
            Duration::from_secs(30),
        ),
        metrics: Arc::new(VlessMuxOwnerMetrics::default()),
        changed: tokio::sync::Notify::new(),
        next_build_id: AtomicU64::new(1),
        next_physical_id: AtomicU64::new(1),
    })
}

fn key(owner: &VlessMuxGenerationOwner, n: u8) -> VlessMuxTransportKey {
    VlessMuxTransportKey {
        generation: owner.generation,
        digest: [n; 32],
    }
}

fn physical(
    owner: &Arc<VlessMuxGenerationOwner>,
    pool: &Arc<VlessMuxTransportPool>,
    pin: &OwnerKeyPin,
    id: u64,
) -> (Arc<VlessMuxPhysicalHandle>, VlessMuxPhysicalMetricGuard) {
    let capacity = try_reserve_vless_mux_physical(owner, pool, pin).unwrap();
    let physical = super::tests::selection_test_physical(id, 0, true, false);
    physical.idle.store(false, Ordering::Release);
    owner.metrics.physical_opened();
    let guard = VlessMuxPhysicalMetricGuard {
        physical: Arc::clone(&physical),
        owner: Arc::clone(owner),
        _capacity: capacity,
    };
    cleanup_lock(&pool.physical).push(Arc::clone(&physical));
    (physical, guard)
}

#[tokio::test]
async fn closing_old_actor_and_pending_open_do_not_remove_replacement() {
    let owner = owner();
    let first = key(&owner, 1);
    let (pool, root) = vless_mux_pool(&owner, first).unwrap();
    let (old, old_actor) = physical(&owner, &pool, &root, 1);
    old.accepting.store(false, Ordering::Release);
    let (new, new_actor) = physical(&owner, &pool, &root, 2);
    let pending = new.reserve_logical(&owner, &root).unwrap();
    drop(root);
    assert!(vless_mux_pool(&owner, key(&owner, 2)).is_err());
    drop(old_actor); // The old Closing callback arrives after installation.
    prune_vless_mux_owner(&owner);
    assert!(old.closed.load(Ordering::Acquire));
    assert!(!new.closed.load(Ordering::Acquire));
    assert!(Arc::ptr_eq(&cleanup_lock(&pool.physical)[0], &new));
    // Even when the real driver has exited, an in-flight logical operation is
    // still protected until its actual owner drops the permit.
    drop(new_actor);
    prune_vless_mux_owner(&owner);
    assert_eq!(cleanup_lock(&owner.pools).len(), 1);
    drop(pending);
    prune_vless_mux_owner(&owner);
    assert!(cleanup_lock(&owner.pools).is_empty());
    assert_eq!(owner.metrics.active_logical.load(Ordering::Relaxed), 0);
    assert_eq!(owner.metrics.idle_physical.load(Ordering::Relaxed), 0);
    assert_eq!(owner.metrics.active_physical.load(Ordering::Relaxed), 0);
    assert_eq!(owner.metrics.reserved_physical.load(Ordering::Relaxed), 0);
    let (replacement, pin) = vless_mux_pool(&owner, first).unwrap();
    assert!(!Arc::ptr_eq(&pool, &replacement));
    prune_empty_vless_mux_keys(&mut cleanup_lock(&owner.pools));
    assert_eq!(cleanup_lock(&owner.pools).len(), 1);
    drop(pin);
    prune_empty_vless_mux_keys(&mut cleanup_lock(&owner.pools));
    owner.closing.store(true, Ordering::Release);
    assert!(vless_mux_pool(&owner, first).is_err());
}

#[tokio::test]
async fn cancelled_outer_future_cannot_unpin_a_handed_off_build() {
    let owner = owner();
    for panic in [false, true] {
        let (pool, pin) = vless_mux_pool(&owner, key(&owner, 1)).unwrap();
        let capacity = try_reserve_vless_mux_physical(&owner, &pool, &pin).unwrap();
        let (_, waiter) = vless_mux_pool(&owner, key(&owner, 1)).unwrap();
        let (ready, entered) = oneshot::channel();
        let (release, finish) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _capacity = capacity;
            ready.send(()).unwrap();
            let _ = finish.await;
            assert!(!panic, "injected physical task failure");
        });
        entered.await.unwrap();
        drop((pin, waiter));
        prune_empty_vless_mux_keys(&mut cleanup_lock(&owner.pools));
        assert!(vless_mux_pool(&owner, key(&owner, 2)).is_err());
        if panic {
            release.send(()).unwrap();
        } else {
            task.abort();
        }
        assert!(task.await.is_err());
        let (new, new_pin) = vless_mux_pool(&owner, key(&owner, 2)).unwrap();
        assert!(!Arc::ptr_eq(&pool, &new));
        assert_eq!(owner.metrics.reserved_physical.load(Ordering::Relaxed), 0);
        assert_eq!(pool.physical_count.load(Ordering::Relaxed), 0);
        drop(new_pin);
        prune_empty_vless_mux_keys(&mut cleanup_lock(&owner.pools));
        assert!(cleanup_lock(&owner.pools).is_empty());
    }
}

#[tokio::test]
async fn repeated_failed_loopback_builds_restore_key_budget() {
    let owner = owner();
    register_vless_mux_generation(&owner).unwrap();
    for _ in 0..5 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let binding = super::poison_tests::test_binding_at(owner.generation.get(), address);
        let deadline = AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(2));
        assert!(
            acquire_vless_mux_logical_stream(binding, "127.0.0.1:443".into(), deadline)
                .await
                .is_err()
        );
        prune_vless_mux_owner(&owner);
        assert!(cleanup_lock(&owner.pools).is_empty());
        assert_eq!(owner.metrics.active_builds.load(Ordering::Relaxed), 0);
        assert_eq!(owner.metrics.reserved_physical.load(Ordering::Relaxed), 0);
    }
    unregister_vless_mux_generation(&owner);
    cleanup_vless_mux_owner(&owner).await;
}

thread_local! {
    static AFTER_LAST: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn after_last_release() {
    AFTER_LAST.with(|slot| {
        if let Some(callback) = slot.borrow_mut().take() {
            callback();
        }
    });
}

#[tokio::test]
async fn last_release_is_atomic_with_reuse_and_cannot_mark_the_new_flow_idle() {
    let owner = owner();
    let (pool, pin) = vless_mux_pool(&owner, key(&owner, 1)).unwrap();
    let (physical, actor) = physical(&owner, &pool, &pin, 1);
    let old = physical.reserve_logical(&owner, &pin).unwrap();
    let (entered, entering) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let physical_for_hook = Arc::clone(&physical);
    let dropping = std::thread::spawn(move || {
        AFTER_LAST.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                // This precise gap used to allow a new stream to be admitted before
                // the old release published idle=true. The state lock now covers it.
                assert!(matches!(
                    physical_for_hook.idle_since.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ));
                entered.send(()).unwrap();
                released.recv_timeout(Duration::from_secs(2)).unwrap();
            }))
        });
        drop(old);
    });
    entering.recv_timeout(Duration::from_secs(2)).unwrap();
    let acquire_physical = Arc::clone(&physical);
    let acquire_owner = Arc::clone(&owner);
    let acquire_pin = pin.clone();
    let acquiring = std::thread::spawn(move || {
        acquire_physical
            .reserve_logical(&acquire_owner, &acquire_pin)
            .unwrap()
    });
    release.send(()).unwrap();
    dropping.join().unwrap();
    let new = acquiring.join().unwrap();
    assert_eq!(physical.active_logical.load(Ordering::Acquire), 1);
    assert!(!physical.idle.load(Ordering::Acquire));
    // An old idle timestamp must not make the live replacement eligible.
    *cleanup_lock(&physical.idle_since) = Instant::now() - Duration::from_secs(120);
    prune_vless_mux_owner(&owner);
    assert!(physical.accepting.load(Ordering::Acquire));
    assert!(!physical.stop.load(Ordering::Acquire));
    assert_eq!(owner.metrics.idle_physical.load(Ordering::Relaxed), 0);
    drop((new, actor, pin));
    prune_vless_mux_owner(&owner);
    assert!(cleanup_lock(&owner.pools).is_empty());
}

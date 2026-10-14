use super::*;

thread_local! {
    static BEFORE_RECYCLE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn before_recycle_lock() {
    BEFORE_RECYCLE.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recycle_rechecks_closing_after_waiting_for_idle_inventory() {
    let (address, server) = tls_server().await;
    let stop = dae_resident_core::ResidentStopSignal::shared();
    let (handle, shutdown) = start_meek_transport_generation_owner_on(
        &tokio::runtime::Handle::current(),
        fastrand::u64(..),
        Arc::clone(&stop),
        2,
    )
    .unwrap();
    let owner = &handle.owner;
    let binding =
        crate::vless_mux_owner::poison_tests::test_binding_at(owner.generation.get(), address);
    let pool = meek_transport_pool(owner, MeekTransportKey::for_binding(&binding)).unwrap();
    let slot = match try_reserve_meek_physical(owner, &pool) {
        Ok(slot) => slot,
        Err(_) => panic!("reserve physical"),
    };
    let physical = build_meek_transport(
        owner,
        &binding,
        AbsoluteDeadline::from_now(Instant::now(), std::time::Duration::from_secs(2)),
        slot,
    )
    .await
    .unwrap();
    owner.metrics.lease_opened();
    let lease = MeekTransportLease {
        physical: Some(physical),
        pool: Arc::clone(&pool),
        owner: Arc::downgrade(owner),
        metrics: Arc::clone(&owner.metrics),
        lease_counted: true,
    };
    let (entered, entering) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let (held, holding) = std::sync::mpsc::channel();
    let (unlock, unlocked) = std::sync::mpsc::channel();
    let locked_pool = Arc::clone(&pool);
    let holder = std::thread::spawn(move || {
        let _guard = locked_pool.idle.lock().unwrap();
        held.send(()).unwrap();
        unlocked
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
    });
    holding
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    let recycler = std::thread::spawn(move || {
        BEFORE_RECYCLE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                entered.send(()).unwrap();
                released
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap();
            }))
        });
        lease.recycle();
    });
    entering
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    owner.closing.store(true, Ordering::Release);
    release.send(()).unwrap();
    unlock.send(()).unwrap();
    holder.join().unwrap();
    recycler.join().unwrap();
    assert!(cleanup_lock(&pool.idle).is_empty());
    assert_eq!(owner.metrics.idle_physical.load(Ordering::Relaxed), 0);
    assert_eq!(owner.metrics.active_physical.load(Ordering::Relaxed), 0);
    assert_eq!(owner.metrics.active_leases.load(Ordering::Relaxed), 0);
    assert_eq!(owner.metrics.reserved_physical.load(Ordering::Relaxed), 0);
    assert_eq!(pool.physical_count.load(Ordering::Relaxed), 0);
    stop.store(true, Ordering::Release);
    shutdown.await.unwrap();
    time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poisoned_meek_idle_pool_closes_tls_socket_and_releases_every_charge() {
    let (address, server) = tls_server().await;
    let stop = dae_resident_core::ResidentStopSignal::shared();
    let (handle, shutdown) = start_meek_transport_generation_owner_on(
        &tokio::runtime::Handle::current(),
        fastrand::u64(..),
        Arc::clone(&stop),
        2,
    )
    .unwrap();
    let owner = &handle.owner;
    let binding =
        crate::vless_mux_owner::poison_tests::test_binding_at(owner.generation.get(), address);
    let pool = meek_transport_pool(owner, MeekTransportKey::for_binding(&binding)).unwrap();
    let slot = match try_reserve_meek_physical(owner, &pool) {
        Ok(slot) => slot,
        Err(_) => panic!("reserve idle physical"),
    };
    let physical = build_meek_transport(
        owner,
        &binding,
        AbsoluteDeadline::from_now(Instant::now(), std::time::Duration::from_secs(2)),
        slot,
    )
    .await
    .unwrap();
    pool.idle.lock().unwrap().push_back(MeekIdlePhysical {
        physical,
        idle_since: Instant::now(),
    });
    owner.metrics.idle_opened();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = pool.idle.lock().unwrap();
        panic!("injected idle inventory poison");
    }));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = owner.pools.lock().unwrap();
        panic!("injected pool registry poison");
    }));
    stop.store(true, Ordering::Release);
    time::timeout(std::time::Duration::from_secs(2), shutdown)
        .await
        .unwrap()
        .unwrap();
    time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    assert!(pool.idle.is_poisoned());
    assert!(cleanup_lock(&pool.idle).is_empty());
    assert_eq!(pool.physical_count.load(Ordering::Relaxed), 0);
    assert_eq!(owner.metrics.idle_physical.load(Ordering::Relaxed), 0);
    assert_eq!(owner.metrics.active_physical.load(Ordering::Relaxed), 0);
    assert_eq!(owner.metrics.reserved_physical.load(Ordering::Relaxed), 0);
    assert!(!owner.metrics.shutdown_timed_out.load(Ordering::Relaxed));
}

async fn tls_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use boring::ssl::{SslAcceptor, SslMethod};
    use dae_outbound::shared_transport::test_support::self_signed_tls_identity;
    use tokio::io::AsyncReadExt;
    let identity = self_signed_tls_identity(&["localhost"]).unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_certificate(&identity.certificate).unwrap();
    acceptor.set_private_key(&identity.private_key).unwrap();
    let acceptor = acceptor.build();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = tokio_boring::accept(&acceptor, tcp).await.unwrap();
        assert_eq!(tls.get_mut().read(&mut [0; 1]).await.unwrap(), 0);
    });
    (address, server)
}

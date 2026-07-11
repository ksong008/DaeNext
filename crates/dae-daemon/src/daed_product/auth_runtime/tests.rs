use super::*;

fn response(status: u16) -> HttpResponse {
    HttpResponse::json(status, json!({"status": status}))
}

fn update_max(maximum: &AtomicU64, value: u64) {
    let _ = maximum.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.max(value))
    });
}

#[test]
fn auth_runtime_profile_bounds_reserve_an_http_worker() {
    let standard_http = ProductHttpWorkerConfig::from_config_with_profile(
        None,
        ProductHttpProfile::Standard,
        "test",
    );
    let standard = ProductAuthRuntimeConfig::from_http_config(standard_http);
    assert!((1..=PRODUCT_AUTH_STANDARD_WORKER_MAX).contains(&standard.worker_count));
    assert!(standard.waiter_limit < standard_http.worker_count);
    assert!(standard.waiter_limit <= standard.worker_count + standard.queue_capacity);

    let low_http = ProductHttpWorkerConfig::from_config_with_profile(
        None,
        ProductHttpProfile::LowMemory,
        "test",
    );
    let low = ProductAuthRuntimeConfig::from_http_config(low_http);
    assert_eq!(low.worker_count, PRODUCT_AUTH_LOW_MEMORY_WORKERS);
    assert_eq!(low.waiter_limit, PRODUCT_AUTH_LOW_MEMORY_WAITER_MAX);
    assert!(low.waiter_limit < low_http.worker_count);
    assert!(low.tracked_key_capacity < standard.tracked_key_capacity);
}

#[test]
fn auth_runtime_never_exceeds_its_worker_concurrency() {
    let mut config = ProductAuthRuntimeConfig::for_test();
    config.worker_count = 2;
    config.queue_capacity = 4;
    config.waiter_limit = 4;
    config.per_source_limit = 4;
    let runtime = ProductAuthRuntime::start(config).unwrap();
    let active = Arc::new(AtomicU64::new(0));
    let maximum = Arc::new(AtomicU64::new(0));
    let start = Arc::new(std::sync::Barrier::new(5));
    let mut callers = Vec::new();
    for index in 0..4_u8 {
        let runtime = Arc::clone(&runtime);
        let active = Arc::clone(&active);
        let maximum = Arc::clone(&maximum);
        let start = Arc::clone(&start);
        callers.push(thread::spawn(move || {
            start.wait();
            runtime
                .execute(
                    Some(IpAddr::V4(std::net::Ipv4Addr::from(index as u32 + 1))),
                    &format!("user-{index}"),
                    move || {
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        update_max(&maximum, current);
                        thread::sleep(Duration::from_millis(40));
                        active.fetch_sub(1, Ordering::SeqCst);
                        ProductAuthJobOutcome::neutral(response(200))
                    },
                )
                .unwrap()
                .status
        }));
    }
    start.wait();
    for caller in callers {
        assert_eq!(caller.join().unwrap(), 200);
    }
    assert_eq!(maximum.load(Ordering::Relaxed), 2);
    let snapshot = runtime.snapshot();
    assert_eq!(snapshot["queueDepth"], json!(0));
    assert_eq!(snapshot["activeWorkers"], json!(0));
    assert_eq!(snapshot["inFlight"], json!(0));
}

#[test]
fn auth_runtime_real_argon2_pressure_stays_within_the_worker_bound() {
    let mut config = ProductAuthRuntimeConfig::for_test();
    config.worker_count = 2;
    config.queue_capacity = 2;
    config.waiter_limit = 2;
    config.per_source_limit = 2;
    let runtime = ProductAuthRuntime::start(config).unwrap();
    let active = Arc::new(AtomicU64::new(0));
    let maximum = Arc::new(AtomicU64::new(0));
    let start = Arc::new(std::sync::Barrier::new(3));
    let mut callers = Vec::new();
    for index in 0..2_u8 {
        let runtime = Arc::clone(&runtime);
        let active = Arc::clone(&active);
        let maximum = Arc::clone(&maximum);
        let start = Arc::clone(&start);
        callers.push(thread::spawn(move || {
            start.wait();
            runtime.execute(
                Some(IpAddr::V4(std::net::Ipv4Addr::from(index as u32 + 1))),
                &format!("argon-user-{index}"),
                move || {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    update_max(&maximum, current);
                    let hash = hash_password(&[index; 16], &format!("Fixture9-{index}"));
                    active.fetch_sub(1, Ordering::SeqCst);
                    assert!(!password_hash_needs_migration(&hash));
                    ProductAuthJobOutcome::neutral(response(200))
                },
            )
        }));
    }
    start.wait();
    for caller in callers {
        assert_eq!(caller.join().unwrap().unwrap().status, 200);
    }
    assert!((1..=2).contains(&maximum.load(Ordering::Relaxed)));
    assert_eq!(runtime.snapshot()["completedTotal"], json!(2));
}

#[test]
fn auth_runtime_waiter_limit_rejects_without_waiting_for_a_worker() {
    let mut config = ProductAuthRuntimeConfig::for_test();
    config.worker_count = 1;
    config.queue_capacity = 1;
    config.waiter_limit = 1;
    let runtime = ProductAuthRuntime::start(config).unwrap();
    let (started_sender, started_receiver) = std::sync::mpsc::sync_channel(1);
    let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
    let caller_runtime = Arc::clone(&runtime);
    let caller = thread::spawn(move || {
        caller_runtime.execute(None, "first-user", move || {
            started_sender.send(()).unwrap();
            release_receiver.recv().unwrap();
            ProductAuthJobOutcome::neutral(response(200))
        })
    });
    started_receiver
        .recv_timeout(Duration::from_secs(1))
        .unwrap();

    let started_at = Instant::now();
    let rejected = runtime.execute(None, "second-user", || {
        ProductAuthJobOutcome::neutral(response(200))
    });

    assert!(matches!(
        rejected,
        Err(ProductAuthExecutionError::Busy { .. })
    ));
    assert!(started_at.elapsed() < Duration::from_millis(100));
    release_sender.send(()).unwrap();
    assert_eq!(caller.join().unwrap().unwrap().status, 200);
}

#[test]
fn auth_runtime_applies_and_clears_source_and_username_backoff() {
    let mut config = ProductAuthRuntimeConfig::for_test();
    config.backoff_base = Duration::from_millis(20);
    config.backoff_max = Duration::from_millis(20);
    let runtime = ProductAuthRuntime::start(config).unwrap();
    let source = Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    let failed = runtime
        .execute(source, "admin", || {
            ProductAuthJobOutcome::credential_failure(response(401))
        })
        .unwrap();
    assert_eq!(failed.status, 401);
    assert!(matches!(
        runtime.execute(source, "admin", || ProductAuthJobOutcome::success(
            response(200)
        )),
        Err(ProductAuthExecutionError::Busy { .. })
    ));

    thread::sleep(Duration::from_millis(30));
    assert_eq!(
        runtime
            .execute(source, "admin", || ProductAuthJobOutcome::success(
                response(200)
            ))
            .unwrap()
            .status,
        200
    );
    assert_eq!(
        runtime
            .execute(source, "admin", || ProductAuthJobOutcome::success(
                response(200)
            ))
            .unwrap()
            .status,
        200
    );
}

#[test]
fn auth_runtime_bounds_backoff_tracking_cardinality() {
    let mut config = ProductAuthRuntimeConfig::for_test();
    config.tracked_key_capacity = 8;
    config.backoff_base = Duration::ZERO;
    config.backoff_max = Duration::ZERO;
    let runtime = ProductAuthRuntime::start(config).unwrap();
    for index in 1..=32_u32 {
        runtime
            .execute(
                Some(IpAddr::V4(std::net::Ipv4Addr::from(index))),
                &format!("user-{index}"),
                || ProductAuthJobOutcome::credential_failure(response(401)),
            )
            .unwrap();
    }

    let snapshot = runtime.snapshot();
    assert!(snapshot["trackedSourceBackoffs"].as_u64().unwrap() <= 8);
    assert!(snapshot["trackedUsernameBackoffs"].as_u64().unwrap() <= 8);
}

#[test]
fn auth_runtime_survives_a_panicking_job() {
    let runtime = ProductAuthRuntime::start(ProductAuthRuntimeConfig::for_test()).unwrap();
    let failed = runtime
        .execute(None, "panic-user", || panic!("injected auth job panic"))
        .unwrap();
    assert_eq!(failed.status, 500);
    assert_eq!(
        runtime
            .execute(None, "next-user", || ProductAuthJobOutcome::neutral(
                response(200)
            ))
            .unwrap()
            .status,
        200
    );
    assert_eq!(runtime.snapshot()["workerPanicTotal"], json!(1));
}

#[test]
fn auth_runtime_shutdown_detaches_a_stuck_job_after_its_deadline() {
    let mut config = ProductAuthRuntimeConfig::for_test();
    config.job_timeout = Duration::from_millis(10);
    config.shutdown_timeout = Duration::from_millis(20);
    let runtime = ProductAuthRuntime::start(config).unwrap();
    assert!(matches!(
        runtime.execute(None, "slow-user", || {
            thread::sleep(Duration::from_millis(150));
            ProductAuthJobOutcome::neutral(response(200))
        }),
        Err(ProductAuthExecutionError::TimedOut)
    ));

    let started_at = Instant::now();
    drop(runtime);
    assert!(started_at.elapsed() < Duration::from_millis(100));
}

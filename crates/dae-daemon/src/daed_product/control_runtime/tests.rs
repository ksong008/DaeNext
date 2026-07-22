use super::*;

#[test]
fn bounded_control_runtime_executes_and_reports_fixed_resources() {
    let runtime = ProductControlRuntime::start(ProductControlRuntimeConfig::for_test()).unwrap();
    let result = runtime
        .execute(
            ProductControlTaskKind::DirectHttp,
            Duration::from_secs(1),
            |_| async { 7_u64 },
        )
        .unwrap();
    assert_eq!(result, 7);
    let snapshot = runtime.snapshot();
    assert_eq!(snapshot["resources"]["workerThreads"], json!(1));
    assert_eq!(snapshot["submittedTotal"], json!(1));
    assert_eq!(snapshot["completedTotal"], json!(1));
    assert_eq!(snapshot["activeTasks"], json!(0));
    assert_eq!(snapshot["queuedTasks"], json!(0));
    assert_eq!(snapshot["shutdownState"], "running");
    let startup_fields = runtime.startup_fields();
    assert_eq!(
        startup_fields
            .get("controlRuntimeWorkers")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        startup_fields
            .get("controlRuntimeProxyHttpAdmission")
            .map(String::as_str),
        Some("1")
    );
    let shutdown = runtime.shutdown().unwrap();
    assert_eq!(shutdown["status"], "stopped");
    assert_eq!(runtime.snapshot()["shutdownState"], "stopped");
}

#[test]
fn completed_result_releases_admission_before_the_caller_resumes() {
    let runtime = ProductControlRuntime::start(ProductControlRuntimeConfig::for_test()).unwrap();
    for expected in 0_u64..1_000 {
        let result = runtime
            .execute(
                ProductControlTaskKind::DirectHttp,
                Duration::from_secs(1),
                move |_| async move { expected },
            )
            .unwrap();
        assert_eq!(result, expected);
    }
    assert_eq!(runtime.snapshot()["rejectedTotal"], json!(0));
    runtime.shutdown().unwrap();
}

#[test]
fn caller_timeout_requests_cooperative_task_cancellation() {
    let runtime = ProductControlRuntime::start(ProductControlRuntimeConfig::for_test()).unwrap();
    let result = runtime.execute(
        ProductControlTaskKind::Dns,
        Duration::from_millis(20),
        |cancellation| async move {
            cancellation.cancelled().await;
            9_u64
        },
    );
    assert_eq!(result, Err(ProductControlExecutionError::TimedOut));
    let deadline = Instant::now() + Duration::from_secs(1);
    while runtime.snapshot()["activeTasks"].as_u64() != Some(0) && Instant::now() < deadline {
        thread::yield_now();
    }
    let snapshot = runtime.snapshot();
    assert_eq!(snapshot["timedOutTotal"], json!(1));
    assert_eq!(snapshot["activeTasks"], json!(0));
    assert_eq!(snapshot["activeByClass"]["dns"], json!(0));
    runtime.shutdown().unwrap();
}

#[test]
fn operation_admission_rejects_excess_work_without_growing_a_waiter_queue() {
    let runtime = ProductControlRuntime::start(ProductControlRuntimeConfig::for_test()).unwrap();
    let first_runtime = Arc::clone(&runtime);
    let first = thread::spawn(move || {
        first_runtime.execute(
            ProductControlTaskKind::ProxyHttp,
            Duration::from_secs(1),
            |cancellation| async move {
                cancellation.cancelled().await;
            },
        )
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while runtime.snapshot()["activeByClass"]["proxyHttp"].as_u64() != Some(1)
        && Instant::now() < deadline
    {
        thread::yield_now();
    }
    let second = runtime.execute(
        ProductControlTaskKind::ProxyHttp,
        Duration::from_millis(20),
        |_| async {},
    );
    assert_eq!(second, Err(ProductControlExecutionError::Busy));
    runtime.stop.request();
    assert_eq!(first.join().unwrap(), Ok(()));
    runtime.shutdown().unwrap();
}

#[test]
fn explicit_shutdown_rejects_new_control_work() {
    let runtime = ProductControlRuntime::start(ProductControlRuntimeConfig::for_test()).unwrap();
    runtime.shutdown().unwrap();
    let result = runtime.execute(
        ProductControlTaskKind::Dns,
        Duration::from_millis(20),
        |_| async { 1_u64 },
    );
    assert_eq!(result, Err(ProductControlExecutionError::Unavailable));
}

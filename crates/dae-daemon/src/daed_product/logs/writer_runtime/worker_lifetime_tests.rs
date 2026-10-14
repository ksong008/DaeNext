use super::tests::writer_fixture;
use super::*;

fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "worker lifetime fence did not settle"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

fn assert_second_writer_rejected(dir: &Path, state: &Path) {
    assert!(product_log_runtime_for(dir).is_none());
    assert_eq!(
        start_product_log_runtime_for_test(dir, state)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        append_product_log_without_runtime(
            dir,
            state,
            "error".to_owned(),
            "rejected",
            BTreeMap::new(),
            true
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        apply_product_log_limits_without_runtime(dir, 2000, 16 * 1024 * 1024)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn detached_worker_keeps_its_writer_fence_until_drain_and_preserves_sealed_history() {
    let (dir, state) = writer_fixture("detached-worker-identity");
    let mut config = ProductLogRuntimeConfig::for_test();
    config.shutdown_timeout = Duration::from_millis(20);
    let runtime = ProductLogRuntime::start_with_config(&dir, &state, config).unwrap();
    for id in 1..=600 {
        runtime
            .append(
                "error".to_owned(),
                &format!("before-{id}"),
                BTreeMap::new(),
                true,
            )
            .unwrap();
    }
    let sealed: Vec<_> = product_log_segments_shared(&dir)
        .unwrap()
        .iter()
        .map(|segment| (segment.path.clone(), fs::read(&segment.path).unwrap()))
        .collect();
    assert!(!sealed.is_empty());
    let metrics = Arc::clone(&runtime.metrics);
    let store = product_log_store(&dir).unwrap();
    let blocked = store.lock().unwrap();
    runtime
        .append_detached("error".to_owned(), "drained", BTreeMap::new(), true)
        .unwrap();
    wait_until(|| metrics.snapshot()["queueDepth"] == 0);
    drop(runtime);
    assert_eq!(metrics.snapshot()["runtimeDetachedTotal"], 1);
    assert_second_writer_rejected(&dir, &state);
    drop(blocked);
    wait_until(|| ensure_product_log_worker_stopped(&dir).is_ok());
    append_product_log_without_runtime(
        &dir,
        &state,
        "error".to_owned(),
        "after",
        BTreeMap::new(),
        true,
    )
    .unwrap();
    let logs = list_logs_value(&dir, &state, Some("all"), None, 1000).unwrap();
    let items = logs["items"].as_array().unwrap();
    assert_eq!(items.len(), 602);
    assert!(
        items
            .iter()
            .enumerate()
            .all(|(index, item)| item["id"] == index + 1)
    );
    for (path, bytes) in sealed {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn timed_out_startup_keeps_its_writer_fence_until_the_worker_exits() {
    let (dir, state) = writer_fixture("timed-out-worker-identity");
    let store = product_log_store(&dir).unwrap();
    let blocked = store.lock().unwrap();
    let mut config = ProductLogRuntimeConfig::for_test();
    config.completion_timeout = Duration::from_millis(20);
    assert_eq!(
        ProductLogRuntime::start_with_config(&dir, &state, config)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_second_writer_rejected(&dir, &state);
    drop(blocked);
    wait_until(|| ensure_product_log_worker_stopped(&dir).is_ok());
    let runtime = start_product_log_runtime_for_test(&dir, &state).unwrap();
    runtime
        .append("error".to_owned(), "after", BTreeMap::new(), true)
        .unwrap();
    assert_eq!(count_log_file_entries(&dir).unwrap(), 1);
    drop(runtime);
    fs::remove_dir_all(dir).unwrap();
}

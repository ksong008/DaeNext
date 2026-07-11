use super::*;

fn writer_fixture(label: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "daed-product-log-writer-{label}-{}",
        fastrand::u64(..)
    ));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    initialize_log_store(&dir, &state).unwrap();
    set_metadata(&state, "runtime_log_level", "error").unwrap();
    (dir, state)
}

#[test]
fn writer_serializes_concurrent_ids_without_corrupting_lines() {
    const THREADS: u64 = 8;
    const APPENDS_PER_THREAD: u64 = 100;

    let (dir, state) = writer_fixture("concurrent");
    let runtime = start_product_log_runtime_for_test(&dir, &state).unwrap();
    let mut threads = Vec::new();
    for thread_id in 0..THREADS {
        let runtime = Arc::clone(&runtime);
        threads.push(thread::spawn(move || {
            for entry in 0..APPENDS_PER_THREAD {
                runtime
                    .append(
                        "error".to_owned(),
                        &format!("thread-{thread_id}-entry-{entry}"),
                        BTreeMap::new(),
                        true,
                    )
                    .unwrap();
            }
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }

    let logs = list_logs_value(&dir, &state, Some("all"), None, 2_000).unwrap();
    let items = logs["items"].as_array().unwrap();
    assert_eq!(items.len(), (THREADS * APPENDS_PER_THREAD) as usize);
    assert_eq!(items.first().unwrap()["id"], json!(1));
    assert_eq!(
        items.last().unwrap()["id"],
        json!(THREADS * APPENDS_PER_THREAD)
    );
    assert_eq!(runtime.snapshot()["queueDepth"], json!(0));
    assert_eq!(runtime.snapshot()["failedTotal"], json!(0));

    drop(runtime);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_prunes_only_after_the_actual_entry_limit_is_crossed() {
    const MAX_ENTRIES: u64 = MIN_LOG_MAX_ENTRIES as u64;

    let (dir, state) = writer_fixture("prune-threshold");
    let conn = open_state_connection(&state).unwrap();
    conn.execute(
        "UPDATE log_settings SET max_entries = ?1 WHERE id = 1",
        params![MAX_ENTRIES as i64],
    )
    .unwrap();
    drop(conn);
    let runtime = start_product_log_runtime_for_test(&dir, &state).unwrap();

    for id in 1..=MAX_ENTRIES {
        runtime
            .append(
                "error".to_owned(),
                &format!("threshold-{id}"),
                BTreeMap::new(),
                true,
            )
            .unwrap();
    }
    assert_eq!(runtime.snapshot()["pruneTotal"], json!(0));
    runtime
        .append("error".to_owned(), "cross-threshold", BTreeMap::new(), true)
        .unwrap();
    assert_eq!(runtime.snapshot()["pruneTotal"], json!(1));

    let logs = list_logs_value(&dir, &state, Some("all"), None, 2_000).unwrap();
    let items = logs["items"].as_array().unwrap();
    assert_eq!(items.len(), MAX_ENTRIES as usize);
    assert_eq!(items.first().unwrap()["id"], json!(2));
    assert_eq!(items.last().unwrap()["id"], json!(MAX_ENTRIES + 1));

    drop(runtime);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_policy_refresh_filters_without_per_entry_database_reads() {
    let (dir, state) = writer_fixture("policy-refresh");
    let runtime = start_product_log_runtime_for_test(&dir, &state).unwrap();
    runtime
        .append("error".to_owned(), "before-refresh", BTreeMap::new(), true)
        .unwrap();

    set_metadata(&state, "runtime_log_level", "fatal").unwrap();
    refresh_resident_event_log_policy(&dir, &state).unwrap();
    runtime
        .append(
            "error".to_owned(),
            "filtered-after-refresh",
            BTreeMap::new(),
            true,
        )
        .unwrap();
    runtime
        .append(
            "fatal".to_owned(),
            "retained-after-refresh",
            BTreeMap::new(),
            true,
        )
        .unwrap();

    let logs = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
    let items = logs["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["message"], json!("before-refresh"));
    assert_eq!(items[1]["message"], json!("retained-after-refresh"));
    assert_eq!(runtime.snapshot()["filteredTotal"], json!(1));

    drop(runtime);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_reopens_the_path_after_external_replacement() {
    let (dir, state) = writer_fixture("external-replace");
    let runtime = start_product_log_runtime_for_test(&dir, &state).unwrap();
    runtime
        .append(
            "error".to_owned(),
            "before-external-replace",
            BTreeMap::new(),
            true,
        )
        .unwrap();

    let path = product_log_file(&dir);
    fs::write(
        &path,
        "{\"id\":40,\"ts\":\"2026-07-12T00:00:00Z\",\"level\":\"error\",\"message\":\"external\",\"fields\":{}}\n",
    )
    .unwrap();
    runtime
        .append(
            "error".to_owned(),
            "after-external-replace",
            BTreeMap::new(),
            true,
        )
        .unwrap();

    let logs = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
    let items = logs["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["id"], json!(40));
    assert_eq!(items[1]["id"], json!(41));
    assert_eq!(items[1]["message"], json!("after-external-replace"));

    drop(runtime);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_notifies_followers_after_append_and_clear() {
    let (dir, state) = writer_fixture("notifications");
    let runtime = start_product_log_runtime_for_test(&dir, &state).unwrap();
    let mut updates = runtime.subscribe();
    assert!(!updates.has_changed().unwrap());

    runtime
        .append("error".to_owned(), "notify-append", BTreeMap::new(), true)
        .unwrap();
    assert!(updates.has_changed().unwrap());
    updates.borrow_and_update();
    runtime.clear().unwrap();
    assert!(updates.has_changed().unwrap());

    drop(runtime);
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn writer_runtime_uses_one_joined_thread() {
    let (dir, state) = writer_fixture("thread-lifecycle");
    let baseline = named_log_writer_threads();
    let runtime = start_product_log_runtime_for_test(&dir, &state).unwrap();
    wait_until(Duration::from_secs(1), || {
        named_log_writer_threads() == baseline + 1
    });
    drop(runtime);
    wait_until(Duration::from_secs(1), || {
        named_log_writer_threads() == baseline
    });
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(target_os = "linux")]
fn named_log_writer_threads() -> usize {
    fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_to_string(entry.path().join("comm")).ok())
        .filter(|name| name.trim() == "daed-log-writer")
        .count()
}

#[cfg(target_os = "linux")]
fn wait_until(timeout: Duration, predicate: impl Fn() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(predicate(), "condition did not become true before timeout");
}

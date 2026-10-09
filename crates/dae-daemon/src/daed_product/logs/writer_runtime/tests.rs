use super::*;

pub(super) fn writer_fixture(label: &str) -> (PathBuf, PathBuf) {
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
fn writer_segments_keep_exact_recent_entries_and_cursor() {
    const TOTAL: u64 = 1_800;
    const KEEP: u64 = MIN_LOG_MAX_ENTRIES as u64;

    let (dir, state) = writer_fixture("segments-recent");
    let conn = open_state_connection(&state).unwrap();
    conn.execute(
        "UPDATE log_settings SET max_entries = ?1 WHERE id = 1",
        params![KEEP as i64],
    )
    .unwrap();
    drop(conn);
    let runtime = start_product_log_runtime_for_test(&dir, &state).unwrap();
    for id in 1..=TOTAL {
        runtime
            .append(
                "error".to_owned(),
                &format!("segment-{id}-{}", "x".repeat(220)),
                BTreeMap::new(),
                true,
            )
            .unwrap();
    }
    assert!(!product_log_segments(&dir).unwrap().is_empty());
    let items = list_logs_value(&dir, &state, Some("all"), None, 2_000).unwrap();
    let items = items["items"].as_array().unwrap();
    assert_eq!(items.len(), KEEP as usize);
    assert_eq!(items.first().unwrap()["id"], json!(TOTAL - KEEP + 1));
    assert_eq!(items.last().unwrap()["id"], json!(TOTAL));
    assert_eq!(count_log_file_entries(&dir).unwrap(), KEEP as i64);

    let mut cursor = ProductLogScanCursor::start();
    let mut seen = Vec::new();
    loop {
        let batch = read_log_entry_batch_from_cursor(&dir, cursor, 0, 64).unwrap();
        seen.extend(batch.entries.into_iter().map(|entry| entry.id));
        cursor = batch.state.cursor;
        if batch.reached_eof {
            break;
        }
    }
    assert_eq!(seen, ((TOTAL - KEEP + 1)..=TOTAL).collect::<Vec<_>>());
    drop(runtime);
    let _reopened =
        ProductLogWriter::open(dir.clone(), ProductLogPolicy::load(&state).unwrap()).unwrap();
    assert_eq!(count_log_file_entries(&dir).unwrap(), KEEP as i64);
    assert_eq!(read_last_log_id(&product_log_file(&dir)).unwrap(), TOTAL);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_does_not_resurrect_pruned_entries_after_limit_increase_and_reopen() {
    let (dir, state) = writer_fixture("segments-no-resurrection");
    let mut policy = ProductLogPolicy::load(&state).unwrap();
    policy.max_entries = MIN_LOG_MAX_ENTRIES;
    let mut writer = ProductLogWriter::open(dir.clone(), policy.clone()).unwrap();
    for id in 1..=600 {
        writer
            .append(ProductLogAppendRequest {
                level: "error".to_owned(),
                message: format!("entry-{id}"),
                fields: BTreeMap::new(),
                respect_runtime_log_level: true,
            })
            .unwrap();
    }
    drop(writer);

    policy.max_entries = 1_000;
    let writer = ProductLogWriter::open(dir.clone(), policy).unwrap();
    let logs = list_logs_value(&dir, &state, Some("all"), None, 1_000).unwrap();
    let items = logs["items"].as_array().unwrap();
    assert_eq!(items.len(), 500);
    assert_eq!(items.first().unwrap()["id"], json!(101));
    assert_eq!(items.last().unwrap()["id"], json!(600));
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_preserving_clear_does_not_restore_pruned_lifecycle_entries() {
    let (dir, state) = writer_fixture("segments-lifecycle-visibility");
    let mut policy = ProductLogPolicy::load(&state).unwrap();
    policy.max_entries = MIN_LOG_MAX_ENTRIES;
    let mut writer = ProductLogWriter::open(dir.clone(), policy).unwrap();
    for id in 1..=600 {
        writer
            .append(ProductLogAppendRequest {
                level: "error".to_owned(),
                message: if id <= 100 {
                    format!("[Startup] pruned-{id}")
                } else {
                    format!("ordinary-{id}")
                },
                fields: BTreeMap::new(),
                respect_runtime_log_level: true,
            })
            .unwrap();
    }
    assert_eq!(count_log_file_entries(&dir).unwrap(), 500);
    writer.clear_preserving_lifecycle().unwrap();
    let logs = list_logs_value(&dir, &state, Some("all"), None, 1_000).unwrap();
    assert!(logs["items"].as_array().unwrap().is_empty());
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_recovers_interrupted_lifecycle_clear_without_duplicates() {
    let (dir, state) = writer_fixture("clear-interrupted");
    let policy = ProductLogPolicy::load(&state).unwrap();
    let mut writer = ProductLogWriter::open(dir.clone(), policy.clone()).unwrap();
    for id in 1..=600 {
        writer
            .append(ProductLogAppendRequest {
                level: "error".to_owned(),
                message: if id == 1 || id == 600 {
                    format!("[Startup] keep-{id}")
                } else {
                    format!("ordinary-{id}")
                },
                fields: BTreeMap::new(),
                respect_runtime_log_level: true,
            })
            .unwrap();
    }
    assert!(!product_log_segments(&dir).unwrap().is_empty());
    LOG_CLEAR_INTERRUPT_AFTER_RENAME.set(true);
    assert!(writer.clear_preserving_lifecycle().is_err());
    drop(writer);
    let reopened = ProductLogWriter::open(dir.clone(), policy).unwrap();
    let logs = list_logs_value(&dir, &state, Some("all"), None, 2_000).unwrap();
    let ids: Vec<_> = logs["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, vec![1, 600]);
    drop(reopened);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_recovers_interrupted_full_clear_before_next_append() {
    let (dir, state) = writer_fixture("full-clear-interrupted");
    let policy = ProductLogPolicy::load(&state).unwrap();
    let mut writer = ProductLogWriter::open(dir.clone(), policy).unwrap();
    for _ in 0..600 {
        writer
            .append(ProductLogAppendRequest {
                level: "error".to_owned(),
                message: "before-clear".to_owned(),
                fields: BTreeMap::new(),
                respect_runtime_log_level: true,
            })
            .unwrap();
    }
    LOG_CLEAR_INTERRUPT_AFTER_RENAME.set(true);
    assert!(writer.clear().is_err());
    writer
        .append(ProductLogAppendRequest {
            level: "error".to_owned(),
            message: "after-clear".to_owned(),
            fields: BTreeMap::new(),
            respect_runtime_log_level: true,
        })
        .unwrap();
    let logs = list_logs_value(&dir, &state, Some("all"), None, 2_000).unwrap();
    let items = logs["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], json!(1));
    assert_eq!(items[0]["message"], json!("after-clear"));
    assert!(product_log_segments(&dir).unwrap().is_empty());
    assert!(
        !product_log_file(&dir)
            .with_extension("jsonl.clear.ready")
            .exists()
    );
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_recovers_prepared_clear_and_torn_visibility_tail_idempotently() {
    let (dir, state) = writer_fixture("prepared-clear");
    let policy = ProductLogPolicy::load(&state).unwrap();
    let mut writer = ProductLogWriter::open(dir.clone(), policy.clone()).unwrap();
    writer
        .append(ProductLogAppendRequest {
            level: "error".to_owned(),
            message: "old".to_owned(),
            fields: BTreeMap::new(),
            respect_runtime_log_level: true,
        })
        .unwrap();
    drop(writer);
    let ready = product_log_file(&dir).with_extension("jsonl.clear.ready");
    fs::write(
        &ready,
        encode_log_entry_line(8, "error", "[Startup] prepared", BTreeMap::new()).unwrap(),
    )
    .unwrap();
    let writer = ProductLogWriter::open(dir.clone(), policy.clone()).unwrap();
    assert_eq!(read_last_log_id(&product_log_file(&dir)).unwrap(), 8);
    assert_eq!(count_log_file_entries(&dir).unwrap(), 1);
    drop(writer);
    let journal = product_log_visibility_file(&dir);
    fs::OpenOptions::new()
        .append(true)
        .open(&journal)
        .unwrap()
        .write_all(&[7; 9])
        .unwrap();
    let writer = ProductLogWriter::open(dir.clone(), policy).unwrap();
    assert_eq!(count_log_file_entries(&dir).unwrap(), 1);
    assert_eq!(
        fs::metadata(journal).unwrap().len() % PRODUCT_LOG_VISIBILITY_RECORD_BYTES,
        0
    );
    assert!(!ready.exists());
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_segments_obey_physical_byte_budget() {
    let (dir, state) = writer_fixture("segments-bytes");
    let conn = open_state_connection(&state).unwrap();
    conn.execute(
        "UPDATE log_settings SET max_bytes = ?1 WHERE id = 1",
        params![MIN_LOG_MAX_BYTES],
    )
    .unwrap();
    drop(conn);
    let runtime = start_product_log_runtime_for_test(&dir, &state).unwrap();
    let payload = "x".repeat(10_000);
    for id in 1..=800 {
        runtime
            .append(
                "error".to_owned(),
                &format!("{id}-{payload}"),
                BTreeMap::new(),
                true,
            )
            .unwrap();
    }
    let disk_bytes: u64 = product_log_files(&dir)
        .unwrap()
        .iter()
        .map(|path| fs::metadata(path).unwrap().len())
        .sum();
    assert!(disk_bytes <= MIN_LOG_MAX_BYTES as u64, "{disk_bytes}");
    let items = list_logs_value(&dir, &state, Some("all"), None, 2_000).unwrap();
    let items = items["items"].as_array().unwrap();
    assert!(items.len() < 800);
    assert_eq!(items.last().unwrap()["id"], json!(800));
    assert_eq!(
        items.first().unwrap()["id"],
        json!(801 - items.len() as u64)
    );
    drop(runtime);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_segments_keep_visibility_separate_for_each_config() {
    let (first_dir, first_state) = writer_fixture("segments-first-config");
    let (second_dir, second_state) = writer_fixture("segments-second-config");
    for (dir, state) in [(&first_dir, &first_state), (&second_dir, &second_state)] {
        let conn = open_state_connection(state).unwrap();
        conn.execute(
            "UPDATE log_settings SET max_entries = ?1 WHERE id = 1",
            params![MIN_LOG_MAX_ENTRIES],
        )
        .unwrap();
        let runtime = start_product_log_runtime_for_test(dir, state).unwrap();
        for id in 1..=600 {
            runtime
                .append(
                    "error".to_owned(),
                    &format!("entry-{id}"),
                    BTreeMap::new(),
                    true,
                )
                .unwrap();
        }
        drop(runtime);
    }
    for (dir, state) in [(&first_dir, &first_state), (&second_dir, &second_state)] {
        let result = list_logs_value(dir, state, Some("all"), None, 2_000).unwrap();
        let items = result["items"].as_array().unwrap();
        assert_eq!(items.len(), MIN_LOG_MAX_ENTRIES as usize);
        assert_eq!(items.first().unwrap()["id"], json!(101));
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn writer_recovers_from_incomplete_invalid_tail() {
    let (dir, state) = writer_fixture("invalid-tail");
    let runtime = start_product_log_runtime_for_test(&dir, &state).unwrap();
    runtime
        .append("error".to_owned(), "before", BTreeMap::new(), true)
        .unwrap();
    drop(runtime);
    {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(product_log_file(&dir))
            .unwrap();
        file.write_all(b"{\"id\":2,\"message\":\xff").unwrap();
    }
    let mut writer =
        ProductLogWriter::open(dir.clone(), ProductLogPolicy::load(&state).unwrap()).unwrap();
    writer
        .append(ProductLogAppendRequest {
            level: "error".to_owned(),
            message: "after".to_owned(),
            fields: BTreeMap::new(),
            respect_runtime_log_level: true,
        })
        .unwrap();
    let result = list_logs_value(&dir, &state, Some("all"), None, 100).unwrap();
    let items = result["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["id"], json!(1));
    assert_eq!(items[1]["id"], json!(2));
    assert_eq!(items[1]["message"], json!("after"));
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_preserves_sealed_history_after_partial_append_failure() {
    let (dir, state) = writer_fixture("partial-append-failure");
    let mut writer =
        ProductLogWriter::open(dir.clone(), ProductLogPolicy::load(&state).unwrap()).unwrap();
    let request = |message: String| ProductLogAppendRequest {
        level: "error".to_owned(),
        message,
        fields: BTreeMap::new(),
        respect_runtime_log_level: true,
    };
    for id in 1..=600 {
        writer.append(request(format!("before-{id}"))).unwrap();
    }
    assert!(!product_log_segments(&dir).unwrap().is_empty());
    LOG_APPEND_PARTIAL_FAILURE.with(|fail| fail.set(true));
    assert_eq!(
        writer
            .append(request("failed".to_owned()))
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ENOSPC)
    );
    writer.append(request("after".to_owned())).unwrap();
    let logs = list_logs_value(&dir, &state, Some("all"), None, 2000).unwrap();
    let items = logs["items"].as_array().unwrap();
    assert_eq!(
        items.len(),
        601,
        "failed append must not discard sealed history"
    );
    assert_eq!(items[0]["id"], json!(1));
    assert_eq!(items[600]["id"], json!(601));
    assert_eq!(items[600]["message"], json!("after"));
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_recovers_visibility_short_write_before_acknowledging_later_appends() {
    let (dir, state) = writer_fixture("visibility-short-write");
    let mut policy = ProductLogPolicy::load(&state).unwrap();
    policy.max_entries = MIN_LOG_MAX_ENTRIES;
    let mut writer = ProductLogWriter::open(dir.clone(), policy.clone()).unwrap();
    let request = || ProductLogAppendRequest {
        level: "error".to_owned(),
        message: "entry".to_owned(),
        fields: BTreeMap::new(),
        respect_runtime_log_level: true,
    };
    for _ in 0..MIN_LOG_MAX_ENTRIES {
        writer.append(request()).unwrap();
    }
    LOG_VISIBILITY_PARTIAL_FAILURE.set(true);
    assert_eq!(
        writer.append(request()).err().unwrap().raw_os_error(),
        Some(libc::ENOSPC)
    );
    writer.append(request()).unwrap();
    let visible_before = list_logs_value(&dir, &state, Some("all"), None, 2_000).unwrap();
    assert_eq!(
        visible_before["items"].as_array().unwrap().len(),
        MIN_LOG_MAX_ENTRIES as usize
    );
    drop(writer);
    policy.max_entries *= 2;
    let writer = ProductLogWriter::open(dir.clone(), policy).unwrap();
    let visible_after = list_logs_value(&dir, &state, Some("all"), None, 2_000).unwrap();
    assert_eq!(
        visible_after["items"], visible_before["items"],
        "acknowledged appends must not resurrect cropped records after a metadata short write"
    );
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_recovers_repeated_visibility_compaction_failure_with_bounded_journal() {
    let (dir, state) = writer_fixture("visibility-compaction-failure");
    let mut policy = ProductLogPolicy::load(&state).unwrap();
    policy.max_entries = MIN_LOG_MAX_ENTRIES;
    let mut writer = ProductLogWriter::open(dir.clone(), policy.clone()).unwrap();
    let request = || ProductLogAppendRequest {
        level: "error".to_owned(),
        message: "entry".to_owned(),
        fields: BTreeMap::new(),
        respect_runtime_log_level: true,
    };
    for _ in 0..MIN_LOG_MAX_ENTRIES as u64
        + PRODUCT_LOG_VISIBILITY_JOURNAL_MAX_BYTES / PRODUCT_LOG_VISIBILITY_RECORD_BYTES
        - 1
    {
        writer.append(request()).unwrap();
    }
    let journal = product_log_visibility_file(&dir);
    let blocked_compaction = journal.with_extension("bin.tmp");
    fs::create_dir(&blocked_compaction).unwrap();
    for _ in 0..3 {
        assert!(writer.append(request()).is_err());
    }
    drop(writer);
    fs::remove_dir(blocked_compaction).unwrap();
    let mut writer = ProductLogWriter::open(dir.clone(), policy).unwrap();
    writer.append(request()).unwrap();
    assert!(fs::metadata(journal).unwrap().len() <= PRODUCT_LOG_VISIBILITY_JOURNAL_MAX_BYTES);
    assert_eq!(count_log_file_entries(&dir).unwrap(), MIN_LOG_MAX_ENTRIES);
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn log_readers_do_not_skip_the_active_segment_during_rotation() {
    for use_cursor in [false, true] {
        let (dir, state) = writer_fixture("reader-rotation");
        let runtime = start_product_log_runtime_for_test(&dir, &state).unwrap();
        for id in 1..=512 {
            runtime
                .append(
                    "error".to_owned(),
                    &format!("before-{id}"),
                    BTreeMap::new(),
                    true,
                )
                .unwrap();
        }
        let (start, started) = mpsc::channel();
        let (done, completed) = mpsc::channel();
        let worker_runtime = Arc::clone(&runtime);
        let worker = thread::spawn(move || {
            started.recv().unwrap();
            worker_runtime
                .append("error".to_owned(), "after-rotation", BTreeMap::new(), true)
                .unwrap();
            let _ = done.send(());
        });
        LOG_READER_AFTER_ENUMERATION.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                start.send(()).unwrap();
                // A reader may hold the store lock, in which case rotation must
                // finish after this read rather than between enumeration/open.
                let _ = completed.recv_timeout(Duration::from_millis(200));
            }));
        });
        let ids: Vec<u64> = if use_cursor {
            read_log_entry_batch_from_cursor(&dir, ProductLogScanCursor::start(), 0, 2000)
                .unwrap()
                .entries
                .into_iter()
                .map(|entry| entry.id)
                .collect()
        } else {
            list_logs_value(&dir, &state, Some("all"), None, 2000).unwrap()["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["id"].as_u64().unwrap())
                .collect()
        };
        worker.join().unwrap();
        assert!(
            (512..=513).contains(&ids.len()),
            "reader lost the rotated segment: {ids:?}"
        );
        assert!(ids.iter().copied().eq(1..=ids.len() as u64));
        drop(runtime);
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn writer_adopts_legacy_single_file_and_preserves_ids_across_rotation() {
    let (dir, state) = writer_fixture("legacy-migration");
    let mut legacy = fs::File::create(product_log_file(&dir)).unwrap();
    for id in 1..=600 {
        legacy
            .write_all(&encode_log_entry_line(id, "error", "legacy", BTreeMap::new()).unwrap())
            .unwrap();
    }
    drop(legacy);
    let runtime = start_product_log_runtime_for_test(&dir, &state).unwrap();
    runtime
        .append("error".to_owned(), "new-format", BTreeMap::new(), true)
        .unwrap();
    assert!(!product_log_segments(&dir).unwrap().is_empty());
    let logs = list_logs_value(&dir, &state, Some("all"), None, 2000).unwrap();
    let items = logs["items"].as_array().unwrap();
    assert_eq!(items.len(), 601);
    assert!(
        items
            .iter()
            .map(|item| item["id"].as_u64().unwrap())
            .eq(1..=601)
    );
    runtime.apply_limits(500, MIN_LOG_MAX_BYTES).unwrap();
    drop(runtime);
    let writer =
        ProductLogWriter::open(dir.clone(), ProductLogPolicy::load(&state).unwrap()).unwrap();
    assert_eq!(count_log_file_entries(&dir).unwrap(), 500);
    assert_eq!(read_last_log_id(&product_log_file(&dir)).unwrap(), 601);
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_queries_and_clear_remain_coherent_during_concurrent_appends() {
    let (dir, state) = writer_fixture("concurrent-clear-query");
    let runtime = start_product_log_runtime_for_test(&dir, &state).unwrap();
    let worker_runtime = Arc::clone(&runtime);
    let worker = thread::spawn(move || {
        for i in 0..1800 {
            if i == 600 || i == 1200 {
                worker_runtime.clear().unwrap();
            }
            worker_runtime
                .append(
                    "error".to_owned(),
                    &format!("entry-{i}"),
                    BTreeMap::new(),
                    true,
                )
                .unwrap();
        }
    });
    let mut reads = 0;
    while !worker.is_finished() || reads < 10 {
        let logs = list_logs_value(&dir, &state, Some("all"), None, 2000).unwrap();
        let ids: Vec<_> = logs["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["id"].as_u64().unwrap())
            .collect();
        assert!(ids.windows(2).all(|pair| pair[1] == pair[0] + 1));
        reads += 1;
        thread::yield_now();
    }
    worker.join().unwrap();
    assert_eq!(count_log_file_entries(&dir).unwrap(), 600);
    assert_eq!(runtime.snapshot()["failedTotal"], json!(0));
    drop(runtime);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_removes_orphan_compaction_files_on_reopen() {
    let (dir, state) = writer_fixture("orphan-compact");
    let orphan = product_log_dir(&dir)
        .join("segment-00000000000000000001-00000000000000000010.jsonl.compact.tmp");
    fs::write(&orphan, b"incomplete").unwrap();
    let writer =
        ProductLogWriter::open(dir.clone(), ProductLogPolicy::load(&state).unwrap()).unwrap();
    assert!(!orphan.exists());
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_discards_old_segments_after_external_replacement() {
    let (dir, state) = writer_fixture("segments-replacement");
    let runtime = start_product_log_runtime_for_test(&dir, &state).unwrap();
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
    assert!(!product_log_segments(&dir).unwrap().is_empty());
    let path = product_log_file(&dir);
    fs::write(
        &path,
        "{\"id\":900,\"ts\":\"2026-10-08T00:00:00Z\",\"level\":\"error\",\"message\":\"external\"}\n",
    )
    .unwrap();
    runtime
        .append("error".to_owned(), "after", BTreeMap::new(), true)
        .unwrap();
    assert!(product_log_segments(&dir).unwrap().is_empty());
    let items = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
    let items = items["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["id"], json!(900));
    assert_eq!(items[1]["id"], json!(901));
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

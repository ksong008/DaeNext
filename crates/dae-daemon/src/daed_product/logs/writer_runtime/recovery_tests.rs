use super::tests::writer_fixture;
use super::*;

fn request(message: &str) -> ProductLogAppendRequest {
    ProductLogAppendRequest {
        level: "error".to_owned(),
        message: message.to_owned(),
        fields: BTreeMap::new(),
        respect_runtime_log_level: true,
    }
}

#[cfg(unix)]
#[test]
fn first_writer_through_a_symlink_uses_the_canonical_store_lock() {
    let dir = std::env::temp_dir().join(format!("daed-log-store-alias-{}", fastrand::u64(..)));
    fs::create_dir(&dir).unwrap();
    let alias = dir.with_extension("alias");
    std::os::unix::fs::symlink(&dir, &alias).unwrap();
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let mut writer =
        ProductLogWriter::open(alias.clone(), ProductLogPolicy::load(&state).unwrap()).unwrap();
    let store = product_log_store(&dir).unwrap();
    assert!(Arc::ptr_eq(&store, &product_log_store(&alias).unwrap()));
    let guard = store.lock().unwrap();
    let (started, start) = mpsc::channel();
    let (done, completion) = mpsc::channel();
    let worker = thread::spawn(move || {
        started.send(()).unwrap();
        writer.append(request("same store")).unwrap();
        done.send(()).unwrap();
    });
    start.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(matches!(
        completion.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    drop(guard);
    completion.recv_timeout(Duration::from_secs(2)).unwrap();
    worker.join().unwrap();
    fs::remove_file(alias).unwrap();
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn clear_copy_failure_is_recovered_before_the_next_append() {
    let (dir, state) = writer_fixture("copy-clear-failure");
    let mut writer =
        ProductLogWriter::open(dir.clone(), ProductLogPolicy::load(&state).unwrap()).unwrap();
    writer.append(request("old")).unwrap();
    LOG_CLEAR_INTERRUPT_DURING_COPY.set(true);
    assert!(writer.clear().is_err());
    assert!(
        product_log_file(&dir)
            .with_extension("jsonl.clear.ready")
            .exists()
    );
    writer.append(request("new")).unwrap();
    let items = list_logs_value(&dir, &state, None, None, 10).unwrap();
    assert_eq!(items["items"].as_array().unwrap().len(), 1);
    assert_eq!(items["items"][0]["message"], "new");
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn oversized_visibility_is_rejected_without_reading_the_whole_file() {
    let (dir, _) = writer_fixture("visibility-bound");
    let file = fs::File::create(product_log_visibility_file(&dir)).unwrap();
    file.set_len(4 * 1024 * 1024 * 1024).unwrap();
    assert_eq!(
        read_log_visibility(&dir).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn partial_write_with_failed_truncation_survives_later_rotation() {
    let (dir, state) = writer_fixture("partial-no-truncate");
    let mut writer =
        ProductLogWriter::open(dir.clone(), ProductLogPolicy::load(&state).unwrap()).unwrap();
    for _ in 0..600 {
        writer.append(request("before")).unwrap();
    }
    LOG_APPEND_PARTIAL_FAILURE.set(true);
    LOG_APPEND_TRUNCATE_FAILURE.set(true);
    assert!(writer.append(request("failed")).is_err());
    for _ in 0..600 {
        writer.append(request("after")).unwrap();
    }
    let logs = list_logs_value(&dir, &state, None, None, 2000).unwrap();
    let items = logs["items"].as_array().unwrap();
    assert_eq!(items.len(), 1200);
    assert!(
        items
            .iter()
            .enumerate()
            .all(|(i, item)| item["id"] == (i + 1) as u64)
    );
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn interrupted_rotation_reopens_without_conflicting_segment_names() {
    let (dir, state) = writer_fixture("interrupted-rotation");
    let mut writer =
        ProductLogWriter::open(dir.clone(), ProductLogPolicy::load(&state).unwrap()).unwrap();
    for _ in 0..512 {
        writer.append(request("before")).unwrap();
    }
    LOG_ROTATE_AFTER_RENAME_FAILURE.set(true);
    assert!(writer.append(request("interrupted")).is_err());
    for _ in 0..600 {
        writer.append(request("after")).unwrap();
    }
    assert_eq!(count_log_file_entries(&dir).unwrap(), 1112);
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn interrupted_rotation_after_create_keeps_acknowledged_history() {
    let (dir, state) = writer_fixture("rotation-after-create");
    let mut writer =
        ProductLogWriter::open(dir.clone(), ProductLogPolicy::load(&state).unwrap()).unwrap();
    for _ in 0..512 {
        writer.append(request("before")).unwrap();
    }
    LOG_ROTATE_AFTER_CREATE_FAILURE.set(true);
    assert!(writer.append(request("interrupted")).is_err());
    for _ in 0..600 {
        writer.append(request("after")).unwrap();
    }
    let value = list_logs_value(&dir, &state, None, None, 2000).unwrap();
    let items = value["items"].as_array().unwrap();
    assert_eq!(items.len(), 1112);
    assert!(
        items
            .iter()
            .enumerate()
            .all(|(i, item)| item["id"] == (i + 1) as u64)
    );
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn external_replacement_after_failed_append_does_not_reuse_old_segment_names() {
    let (dir, state) = writer_fixture("replace-after-short-write");
    let mut writer =
        ProductLogWriter::open(dir.clone(), ProductLogPolicy::load(&state).unwrap()).unwrap();
    for _ in 0..600 {
        writer.append(request("old")).unwrap();
    }
    LOG_APPEND_PARTIAL_FAILURE.set(true);
    assert!(writer.append(request("failed")).is_err());
    let replacement = product_log_file(&dir).with_extension("external");
    let mut file = fs::File::create(&replacement).unwrap();
    for id in 1..=512 {
        file.write_all(
            &encode_log_entry_line(id, "error", "replacement", BTreeMap::new()).unwrap(),
        )
        .unwrap();
    }
    drop(file);
    fs::rename(replacement, product_log_file(&dir)).unwrap();
    writer.append(request("new")).unwrap();
    let value = list_logs_value(&dir, &state, None, None, 2000).unwrap();
    let items = value["items"].as_array().unwrap();
    assert_eq!(items.len(), 513);
    assert_eq!(items[0]["message"], "replacement");
    assert_eq!(items[512]["message"], "new");
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn snapshot_reader_does_not_hold_the_writer_lock_and_survives_clear() {
    let (dir, state) = writer_fixture("snapshot-clear");
    let runtime = start_product_log_runtime_for_test(&dir, &state).unwrap();
    for _ in 0..600 {
        runtime
            .append("error".to_owned(), "before", BTreeMap::new(), true)
            .unwrap();
    }
    let other = Arc::clone(&runtime);
    let (done, completed) = mpsc::channel();
    LOG_READER_AFTER_ENUMERATION.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            let worker = thread::spawn(move || {
                other.clear().unwrap();
                other
                    .append("error".to_owned(), "after", BTreeMap::new(), true)
                    .unwrap();
                done.send(()).unwrap();
            });
            completed
                .recv_timeout(Duration::from_secs(2))
                .expect("query blocks writer");
            worker.join().unwrap();
        }))
    });
    let snapshot = list_logs_value(&dir, &state, None, None, 2000).unwrap();
    assert_eq!(snapshot["items"].as_array().unwrap().len(), 600);
    assert_eq!(count_log_file_entries(&dir).unwrap(), 1);
    assert_eq!(
        list_logs_value(&dir, &state, None, None, 2000).unwrap()["items"][0]["message"],
        "after"
    );
    drop(runtime);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn fallback_filters_before_open_and_reuses_its_writer() {
    let (dir, state) = writer_fixture("fallback-reuse");
    let _observe = observe_product_log_io(&dir, &state);
    for _ in 0..20 {
        append_product_log_without_runtime(
            &dir,
            &state,
            "trace".to_owned(),
            "filtered",
            BTreeMap::new(),
            true,
        )
        .unwrap();
    }
    assert_eq!(product_log_io_test_snapshot().append_opens, 0);
    for _ in 0..20 {
        append_product_log_without_runtime(
            &dir,
            &state,
            "error".to_owned(),
            "kept",
            BTreeMap::new(),
            true,
        )
        .unwrap();
    }
    assert_eq!(product_log_io_test_snapshot().append_opens, 1);
    assert_eq!(count_log_file_entries(&dir).unwrap(), 20);
    let runtime = start_product_log_runtime_for_test(&dir, &state).unwrap();
    runtime
        .append("error".to_owned(), "handover", BTreeMap::new(), true)
        .unwrap();
    assert_eq!(count_log_file_entries(&dir).unwrap(), 21);
    drop(runtime);
    fs::remove_dir_all(dir).unwrap();
}

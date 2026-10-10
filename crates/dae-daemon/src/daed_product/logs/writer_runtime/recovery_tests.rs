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
    assert_eq!(snapshot["items"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["items"][0]["message"], "after");
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

#[test]
fn snapshot_retries_same_inode_rewrite_and_truncation() {
    for truncate in [false, true] {
        let (dir, state) = writer_fixture("snapshot-inode-change");
        let mut writer =
            ProductLogWriter::open(dir.clone(), ProductLogPolicy::load(&state).unwrap()).unwrap();
        writer.append(request("before")).unwrap();
        let path = product_log_file(&dir);
        let original = fs::read(&path).unwrap();
        let mut replacement = original.clone();
        let start = replacement
            .windows(6)
            .position(|bytes| bytes == b"before")
            .unwrap();
        replacement[start..start + 6].copy_from_slice(b"after!");
        LOG_READER_AFTER_ENUMERATION.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                fs::write(path, if truncate { Vec::new() } else { replacement }).unwrap();
            }));
        });
        let value = list_logs_value(&dir, &state, None, None, 10).unwrap();
        if truncate {
            assert!(value["items"].as_array().unwrap().is_empty());
        } else {
            assert_eq!(value["items"][0]["message"], "after!");
        }
        drop(writer);
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn snapshot_retries_sealed_segment_replacement() {
    let (dir, state) = writer_fixture("snapshot-sealed-replace");
    let mut writer =
        ProductLogWriter::open(dir.clone(), ProductLogPolicy::load(&state).unwrap()).unwrap();
    for _ in 0..513 {
        writer.append(request("before")).unwrap();
    }
    let segment = product_log_segments(&dir).unwrap()[0].path.clone();
    LOG_READER_AFTER_ENUMERATION.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            let replacement = segment.with_extension("replacement");
            fs::write(
                &replacement,
                encode_log_entry_line(512, "error", "replaced", BTreeMap::new()).unwrap(),
            )
            .unwrap();
            fs::rename(replacement, segment).unwrap();
        }));
    });
    let value = list_logs_value(&dir, &state, None, None, 10).unwrap();
    assert_eq!(value["items"].as_array().unwrap().len(), 2);
    assert_eq!(value["items"][0]["message"], "replaced");
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn cursor_retains_partial_active_record_until_newline() {
    let (dir, _) = writer_fixture("cursor-partial");
    let line = encode_log_entry_line(1, "error", "partial", BTreeMap::new()).unwrap();
    let path = product_log_file(&dir);
    fs::write(&path, &line[..line.len() - 1]).unwrap();
    let first =
        read_log_entry_batch_from_cursor(&dir, ProductLogScanCursor::start(), 0, 256).unwrap();
    assert!(first.entries.is_empty());
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    let second = read_log_entry_batch_from_cursor(&dir, first.state.cursor, 0, 256).unwrap();
    assert_eq!(second.entries.len(), 1);
    assert_eq!(second.entries[0].message, "partial");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn append_batches_preserve_ids_rotation_and_partial_write_rollback() {
    let (dir, state) = writer_fixture("append-batch");
    let mut writer =
        ProductLogWriter::open(dir.clone(), ProductLogPolicy::load(&state).unwrap()).unwrap();
    for _ in 0..500 {
        writer.append(request("single")).unwrap();
    }
    assert!(
        writer
            .append_batch((0..32).map(|_| request("batch")).collect())
            .iter()
            .all(Result::is_ok)
    );
    assert_eq!(product_log_segments(&dir).unwrap().len(), 1);
    LOG_APPEND_PARTIAL_FAILURE.set(true);
    assert!(
        writer
            .append_batch(vec![request("failed"), request("failed")])
            .iter()
            .all(Result::is_err)
    );
    writer.append(request("after")).unwrap();
    let value = list_logs_value(&dir, &state, None, None, 2000).unwrap();
    let items = value["items"].as_array().unwrap();
    assert_eq!(items.len(), 533);
    assert!(
        items
            .iter()
            .enumerate()
            .all(|(i, item)| item["id"] == i as u64 + 1)
    );
    assert_eq!(items.last().unwrap()["message"], "after");
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn snapshot_scans_1600_segments_with_64_fd_limit() {
    const CHILD: &str = "DAED_LOG_LOW_FD_TEST";
    if std::env::var_os(CHILD).is_none() {
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "daed_product::logs::writer_runtime::recovery_tests::snapshot_scans_1600_segments_with_64_fd_limit", "--test-threads=1"]).env(CHILD, "1");
        // SAFETY: pre_exec invokes only the async-signal-safe setrlimit syscall.
        unsafe {
            command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: 64,
                    rlim_max: 64,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }
    let (dir, state) = writer_fixture("low-fd");
    for id in 1..=1600 {
        fs::write(
            product_log_segment_path(&dir, id, id),
            encode_log_entry_line(id, "error", "segment", BTreeMap::new()).unwrap(),
        )
        .unwrap();
    }
    let value = list_logs_value(&dir, &state, None, Some("segment"), 2000).unwrap();
    assert_eq!(value["items"].as_array().unwrap().len(), 1600);
    assert!(!fs::read_dir(&dir).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".daed-log-snapshot-")
    }));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn escaped_json_log_strings_roundtrip_and_utf8_trim_keeps_boundaries() {
    let message = "escaped \"quote\"\n tab\t雪";
    let fields = BTreeMap::from([("key\n".to_owned(), "value \"quote\"\t雪".to_owned())]);
    let wire = encode_log_entry_json_line(42, "info", message, &fields).unwrap();
    let entry = parse_log_entry_line(std::str::from_utf8(&wire).unwrap()).unwrap();
    assert_eq!(entry.id, 42);
    assert_eq!(entry.message, message);
    assert_eq!(entry.fields, fields);
    assert_eq!(trim_log_string("雪x", 1), "...");
    assert_eq!(trim_log_string("雪x", 3), "雪...");
}

use super::*;

fn poison<T>(mutex: &Mutex<T>) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = mutex.lock().unwrap();
        panic!("injected log store poison");
    }));
}

#[test]
fn poisoned_read_caches_rebuild_but_mutation_keeps_its_failure_fence() {
    let dir = std::env::temp_dir().join(format!("daed-log-store-poison-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    initialize_log_store(&dir, &state).unwrap();
    let runtime =
        super::super::writer_runtime::start_product_log_runtime_for_test(&dir, &state).unwrap();
    for id in 0..600 {
        runtime
            .append(
                "error".to_owned(),
                &format!("retained-{id}"),
                BTreeMap::new(),
                true,
            )
            .unwrap();
    }
    let store = product_log_store(&dir).unwrap();
    let before = list_logs_value(&dir, &state, Some("all"), None, 1000).unwrap();
    poison(&store.count);
    poison(&store.segment_cache);
    poison(&store.parsed_cache);
    poison(&store.scan);
    let after = list_logs_value(&dir, &state, Some("all"), None, 1000).unwrap();
    assert_eq!(before["items"], after["items"]);
    assert!(!store.segment_cache.is_poisoned());
    assert!(!store.parsed_cache.is_poisoned());
    assert!(store.scan.is_poisoned());
    assert!(Arc::ptr_eq(&product_log_store(&dir).unwrap(), &store));
    poison(&store.mutation);
    assert!(
        list_logs_value(&dir, &state, Some("all"), None, 1000)
            .unwrap_err()
            .to_string()
            .contains("lock poisoned")
    );
    assert!(
        runtime
            .append("error".to_owned(), "rejected", BTreeMap::new(), true)
            .is_err()
    );
    assert!(store.mutation.is_poisoned());
    drop(runtime);
    fs::remove_dir_all(dir).unwrap();
}

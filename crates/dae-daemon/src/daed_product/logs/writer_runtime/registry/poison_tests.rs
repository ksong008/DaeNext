use super::*;

#[test]
fn poisoned_registry_retains_the_runtime_and_segment_history() {
    let (dir, state) = super::super::tests::writer_fixture("poison-registry");
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
    assert!(!product_log_segments_shared(&dir).unwrap().is_empty());
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = PRODUCT_LOG_RUNTIME_REGISTRY
            .get()
            .unwrap()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        panic!("injected runtime registry poison");
    }));
    assert!(Arc::ptr_eq(
        &product_log_runtime_for(&dir).unwrap(),
        &runtime
    ));
    assert!(PRODUCT_LOG_RUNTIME_REGISTRY.get().unwrap().is_poisoned());
    assert_eq!(
        start_product_log_runtime_for_test(&dir, &state)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
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
    assert_eq!(items.len(), 601);
    assert_eq!(items.first().unwrap()["id"], 1);
    assert_eq!(items.last().unwrap()["id"], 601);
    drop(runtime);
    assert!(product_log_runtime_for(&dir).is_none());
    fs::remove_dir_all(dir).unwrap();
}

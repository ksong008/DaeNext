use super::*;

#[test]
fn local_control_reload_busy_gate_rejects_concurrent_work() {
    let busy = AtomicBool::new(false);
    assert!(
        busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    );
    assert!(
        busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    );
    busy.store(false, Ordering::Release);
    assert!(
        busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    );
}

#[test]
fn local_control_reload_uses_live_runtime_state() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
        r#"
        INSERT INTO systems(running, running_config_version, running_dns_version, running_routing_version, running_group_version_sum, running_group_ids)
            VALUES(1, 1, 1, 1, 0, '');
        "#,
    )
    .unwrap();
    drop(conn);
    let app = AppState {
        config_dir: dir.clone(),
        state: state.clone(),
        web_root: dir.clone(),
        api_only: true,
        control_socket: dir.join("control.sock"),
        shutdown: Arc::new(ProductShutdown::default()),
        runtime: Arc::new(ProductRuntimeManager::new()),
        runtime_sampler: None,
        latency_jobs: Arc::new(LatencyJobManager::default()),
        http_metrics: Arc::new(ProductHttpMetrics::default()),
        ui_runtime: product_ui_runtime(),
        auth_runtime: product_test_auth_runtime(),
        geodata_paths: Arc::new(geodata::ProductGeodataPaths::for_directory(dir.clone())),
        geodata_updates: Arc::new(geodata::ProductGeodataUpdateCoordinator::default()),
        geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
        geodata_update_runtime: None,
        control_runtime: product_test_control_runtime(),
    };

    assert!(app.shutdown.mark_ready());
    let fresh_status = handle_local_control_status(&app);
    assert_eq!(fresh_status["ready"], json!(true));
    assert_eq!(fresh_status["productReady"], json!(true));
    assert_eq!(fresh_status["runtimeRequired"], json!(false));
    assert_eq!(fresh_status["runtimeRunning"], json!(false));

    app.runtime.set_runtime_required_for_readiness(true);
    let status = handle_local_control_status(&app);
    assert_eq!(status["ready"], json!(false));
    assert_eq!(status["productReady"], json!(true));
    assert_eq!(status["runtimeRequired"], json!(true));
    assert_eq!(status["runtimeRunning"], json!(false));
    assert_eq!(status["contract"], json!("local-control-readiness-v1"));
    assert!(status.get("runtime").is_none());
    assert!(serde_json::to_vec(&status).unwrap().len() < 1024);

    let response = handle_local_control_reload(&app);
    assert_eq!(response["ok"], json!(false));
    assert_eq!(response["applied"], json!(false));
    assert_eq!(response["skipped"], json!(false));
    assert_eq!(response["runtimeRequired"], json!(true));
    assert_eq!(
        response["error"],
        json!("runtime is required but not running")
    );

    app.runtime.set_runtime_required_for_readiness(false);
    let response = handle_local_control_reload(&app);
    assert_eq!(response["ok"], json!(true));
    assert_eq!(response["applied"], json!(false));
    assert_eq!(response["skipped"], json!(true));
    assert_eq!(response["runtimeRequired"], json!(false));
    assert_eq!(response["reason"], json!("runtime is stopped"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn oversized_local_control_response_fails_as_compact_valid_json() {
    let bytes = bounded_local_control_response_bytes(json!({
        "ok": true,
        "report": "x".repeat(LOCAL_CONTROL_MAX_RESPONSE_BYTES as usize),
    }))
    .unwrap();
    let response: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(response["ok"], json!(false));
    assert_eq!(
        response["error"],
        json!("local control response exceeds the bounded message contract")
    );
    assert!(bytes.len() as u64 <= LOCAL_CONTROL_MAX_RESPONSE_BYTES);
}

use super::*;
#[test]
pub(crate) fn runtime_reload_dry_preview_writes_unified_reload_logs() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
        r#"
            INSERT INTO configs(id, name, global, selected, version)
                VALUES(1, 'global', 'global {}', 1, 1);
            INSERT INTO dns(id, name, dns, selected, version)
                VALUES(1, 'dns', 'dns {}', 1, 1);
            INSERT INTO routings(id, name, routing, selected, version)
                VALUES(1, 'routing', 'routing {}', 1, 1);
        "#,
    )
    .unwrap();
    drop(conn);
    initialize_log_store(&dir, &state).unwrap();
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
        ui_runtime: Arc::new(ProductUiRuntime::default()),
        auth_runtime: product_test_auth_runtime(),
        geodata_updates: Arc::new(geodata::ProductGeodataUpdateCoordinator::default()),
        geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
        geodata_update_runtime: None,
    };
    set_metadata(&state, "runtime_log_level", "info").unwrap();
    let request = HttpRequest {
        method: "POST".to_owned(),
        path: "/api/runtime/reload".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: br#"{"dry":true}"#.to_vec(),
    };

    let response = api_runtime_reload(&app, &request);
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let logs = list_logs_value(&dir, &state, Some("all"), Some("[Reload]"), 500).unwrap();
    let items = logs["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{logs}");
    assert_eq!(items[0]["message"], json!("[Reload] Preview finished"));
    assert_eq!(items[0]["fields"]["source"], json!("api"));
    assert_eq!(items[0]["fields"]["dry"], json!("true"));
    assert_eq!(items[0]["fields"]["applied"], json!("false"));
    assert!(items[0]["fields"]["elapsed"].as_str().is_some());

    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn materialize_runtime_requires_explicit_selected_resources() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
        r#"
            INSERT INTO configs(id, name, global, selected, version)
                VALUES(1, 'global', 'global {}', 0, 1);
            INSERT INTO dns(id, name, dns, selected, version)
                VALUES(1, 'dns', 'dns {}', 0, 1);
            INSERT INTO routings(id, name, routing, selected, version)
                VALUES(1, 'routing', 'routing {}', 0, 1);
        "#,
    )
    .unwrap();
    assert_eq!(selected_id(&conn, SectionKind::Config).unwrap(), None);
    drop(conn);

    let err = materialize_runtime(&state, None, true).unwrap_err();
    assert!(err.to_string().contains("no selected configs resource"));

    let conn = open_state_connection(&state).unwrap();
    conn.execute("UPDATE configs SET selected = 1 WHERE id = 1", [])
        .unwrap();
    drop(conn);
    let err = materialize_runtime(&state, None, true).unwrap_err();
    assert!(err.to_string().contains("no selected dns resource"));

    let conn = open_state_connection(&state).unwrap();
    conn.execute("UPDATE dns SET selected = 1 WHERE id = 1", [])
        .unwrap();
    drop(conn);
    let err = materialize_runtime(&state, None, true).unwrap_err();
    assert!(err.to_string().contains("no selected routings resource"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn product_runtime_start_rejects_missing_lan_before_resident_start() {
    let sections = parse_config(
        r#"
global {
  log_level: info
}
routing {
  fallback: direct
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let err = start_product_runtime_instance(&config, "test", &[]).unwrap_err();

    assert!(err.contains("rejected before current runtime swap"));
    assert!(err.contains("global.lan_interface"));
    assert!(err.contains("must specify"));
}

#[test]
pub(crate) fn resident_dataplane_admission_detail_prefers_structured_error() {
    let state = json!({
        "residentDataplane": {
            "enabled": true,
            "status": "fail",
            "error": "resident dataplane plan is enabled without a default proxy group plan"
        }
    });

    assert_eq!(
        resident_dataplane_admission_detail(&state),
        "resident dataplane plan is enabled without a default proxy group plan"
    );
}

#[test]
pub(crate) fn runtime_stop_clears_reload_traffic_carry() {
    let manager = ProductRuntimeManager::new();
    {
        let mut inner = manager.inner.lock().unwrap();
        inner.traffic_carry = RuntimeTrafficCarry {
            upload_total: 100,
            download_total: 200,
        };
        inner.runtime_started_at = Some("2026-06-15T01:00:00.000Z".to_owned());
    }

    manager.stop().unwrap();

    let inner = manager.inner.lock().unwrap();
    assert_eq!(inner.traffic_carry, RuntimeTrafficCarry::default());
    assert_eq!(inner.runtime_started_at, None);
}

#[test]
pub(crate) fn runtime_stop_records_cleanup_lifecycle_for_fake_runtime() {
    let manager = ProductRuntimeManager::new();
    {
        let mut inner = manager.inner.lock().unwrap();
        inner.runtime = Some(ProductRuntimeInstance::Fake(FakeProductRuntime {
            started_at: "2026-06-23T01:00:00.000Z".to_owned(),
            tproxy_port: 12345,
        }));
        inner.runtime_started_at = Some("2026-06-23T01:00:00.000Z".to_owned());
    }

    let report = manager.stop().unwrap();
    assert_eq!(report["wasRunning"], json!(true));
    assert_eq!(report["cleanupStarted"], json!(true));
    assert_eq!(report["cleanupMode"], json!("background-stop"));
    assert!(report["cleanupReport"].is_null());
    assert!(manager.wait_for_cleanup_idle(std::time::Duration::from_secs(1)));

    let summary = manager.summary();
    assert_eq!(summary["state"], json!("stopped"));
    assert_eq!(summary["cleanup"]["state"], json!("done"));
    assert_eq!(summary["cleanup"]["running"], json!(false));
    assert_eq!(summary["cleanup"]["lastReport"]["status"], json!("pass"));
}

#[test]
pub(crate) fn runtime_signal_stop_waits_for_cleanup_report() {
    let manager = ProductRuntimeManager::new();
    {
        let mut inner = manager.inner.lock().unwrap();
        inner.runtime = Some(ProductRuntimeInstance::Fake(FakeProductRuntime {
            started_at: "2026-06-23T01:00:00.000Z".to_owned(),
            tproxy_port: 12345,
        }));
        inner.runtime_started_at = Some("2026-06-23T01:00:00.000Z".to_owned());
    }

    let report = manager.stop_and_wait_for_cleanup("signal-stop").unwrap();
    assert_eq!(report["wasRunning"], json!(true));
    assert_eq!(report["cleanupStarted"], json!(true));
    assert_eq!(report["cleanupMode"], json!("signal-stop"));
    assert_eq!(report["cleanupReport"]["status"], json!("pass"));
    assert_eq!(
        report["cleanupReport"]["cleanupRuntime"],
        json!("fake-resident-runtime-test-only")
    );
    assert_eq!(
        report["cleanupReport"]["allocatorReclaim"]["reason"],
        json!("stop_runtime")
    );

    let summary = manager.summary();
    assert_eq!(summary["state"], json!("stopped"));
    assert_eq!(summary["cleanup"]["state"], json!("done"));
    assert_eq!(summary["cleanup"]["running"], json!(false));
    assert_eq!(summary["cleanup"]["lastReport"], report["cleanupReport"]);
}

#[test]
pub(crate) fn product_server_blocks_lifecycle_signals_before_spawning_log_workers() {
    let source = include_str!("../cli_commands/server.rs");
    let block_signals = source
        .find("if let Err(err) = block_product_signals()")
        .expect("product server must block lifecycle signals");
    let start_log_runtime = source
        .find("start_product_log_runtime(&options.config_dir, &options.state)")
        .expect("product server must start the product log runtime");

    assert!(
        block_signals < start_log_runtime,
        "all product worker threads must inherit the blocked lifecycle signal mask"
    );
}

#[test]
pub(crate) fn runtime_cleanup_interlock_blocks_failed_cleanup() {
    let manager = ProductRuntimeManager::new();
    {
        let mut inner = manager.inner.lock().unwrap();
        inner.cleanup.begin(7, "background-stop");
        inner.cleanup.finish(Some(json!({
            "status": "fail",
            "loaded_map_cleaned": false,
            "leftovers_after_cleanup": ["iface:dae0"],
            "sys_fs_bpf_dae_mutated": false,
        })));
    }

    let err = manager.ensure_cleanup_allows_start().unwrap_err();
    assert!(err.contains("previous product runtime cleanup failed"));
    assert!(err.contains("iface:dae0"));
}

#[test]
pub(crate) fn stuck_runtime_thread_cleanup_prevents_replacement_publication() {
    let manager = ProductRuntimeManager::new();
    {
        let mut inner = manager.inner.lock().unwrap();
        inner.cleanup.begin(8, "reload-replace");
        inner.cleanup.finish(Some(json!({
            "status": "fail",
            "cleanup_step_failed": true,
            "cleanup_steps": [{
                "name": "stop-resident-dataplane-runtime",
                "status": "fail",
                "task_count_timed_out": 1,
                "task_count_detached": 1
            }],
            "loaded_map_cleaned": true,
            "cleanup_command_timed_out": false,
            "leftovers_after_cleanup": [],
            "sys_fs_bpf_dae_mutated": false,
        })));
    }

    let error = manager.ensure_cleanup_allows_start().unwrap_err();
    assert!(error.contains("previous product runtime cleanup failed"));
    assert!(error.contains("stop-resident-dataplane-runtime"));
    assert!(error.contains("task_count_timed_out"));
    assert!(error.contains("task_count_detached"));
    assert!(!manager.is_running());
}

#[test]
pub(crate) fn owner_cleanup_failure_keeps_bounded_protocol_diagnostics() {
    let manager = ProductRuntimeManager::new();
    let report = json!({
        "status": "fail",
        "cleanup_step_failed": true,
        "cleanup_steps": [{
            "name": "stop-resident-dataplane-runtime",
            "status": "fail",
            "resource_release": {
                "hysteria2Owners": false,
                "tuicOwners": true,
                "juicityOwners": true
            },
            "hysteria2_owners": {
                "registeredKeys": 0,
                "activeOwners": 0,
                "activeLogicalLeases": 0,
                "activeUdpSessions": 0,
                "currentUdpQueuedBytes": 0,
                "activeUdpSessionQuarantine": 0,
                "registryOwnershipReleased": true,
                "endpointDrain": {"requested": 14, "completed": 13, "timedOut": 1},
                "shutdownTimedOut": true,
                "capabilityLedger": {"entries": ["must-not-be-copied"]}
            }
        }],
        "loaded_map_cleaned": true,
        "cleanup_command_timed_out": false,
        "leftovers_after_cleanup": [],
        "sys_fs_bpf_dae_mutated": false,
    });
    {
        let mut inner = manager.inner.lock().unwrap();
        inner.cleanup.begin(10, "reload-replace");
        inner.cleanup.finish(Some(report));
    }

    let error = manager.ensure_cleanup_allows_start().unwrap_err();
    assert!(error.contains("ownerReleaseDetails"));
    assert!(error.contains("registryOwnershipReleased"));
    assert!(error.contains("endpointDrain"));
    assert!(error.contains("\"timedOut\":1"));
    assert!(!error.contains("must-not-be-copied"));
}

#[test]
pub(crate) fn forced_bounded_cleanup_without_residuals_does_not_latch_interlock() {
    let manager = ProductRuntimeManager::new();
    {
        let mut inner = manager.inner.lock().unwrap();
        inner.cleanup.begin(9, "reload-replace");
        inner.cleanup.finish(Some(json!({
            "status": "pass",
            "cleanup_step_failed": false,
            "cleanup_steps": [{
                "name": "stop-resident-dataplane-runtime",
                "status": "pass",
                "safetyStatus": "pass",
                "graceful": false,
                "completionMode": "forced-bounded",
                "task_count_timed_out": 1,
                "task_count_aborted": 1,
                "task_count_pending": 0,
                "active_tcp_connections_at_shutdown": 0,
                "active_udp_sessions_at_shutdown": 0
            }],
            "loaded_map_cleaned": true,
            "cleanup_command_timed_out": false,
            "leftovers_after_cleanup": [],
            "sys_fs_bpf_dae_mutated": false,
        })));
    }

    manager.ensure_cleanup_allows_start().unwrap();
    let summary = manager.summary();
    assert_eq!(summary["cleanup"]["state"], json!("done"));
    assert_eq!(summary["cleanup"]["lastError"], Value::Null);
}

#[test]
pub(crate) fn runtime_interface_recovery_ignores_fake_runtime() {
    let manager = ProductRuntimeManager::new();
    {
        let mut inner = manager.inner.lock().unwrap();
        inner.runtime = Some(ProductRuntimeInstance::Fake(FakeProductRuntime {
            started_at: "2026-06-23T01:00:00.000Z".to_owned(),
            tproxy_port: 12345,
        }));
    }

    assert!(resident_interface_recovery_request(&manager.inner).is_none());
}

#[test]
pub(crate) fn runtime_started_at_survives_reload_but_resets_for_new_start() {
    let initial_started_at = "2026-06-15T01:00:00.000Z".to_owned();
    let reload_transition_at = "2026-06-15T02:00:00.000Z".to_owned();
    let restart_transition_at = "2026-06-15T03:00:00.000Z".to_owned();

    assert_eq!(
        runtime_started_at_after_success(
            true,
            Some(initial_started_at.clone()),
            reload_transition_at
        ),
        initial_started_at
    );
    assert_eq!(
        runtime_started_at_after_success(false, None, restart_transition_at.clone()),
        restart_transition_at
    );
}

#[test]
pub(crate) fn startup_runtime_evidence_logs_report_interfaces_generically() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    initialize_log_store(&dir, &state).unwrap();
    set_metadata(&state, "runtime_log_level", "info").unwrap();
    let program_with_backend = "program_ingress";
    let interface_with_backend = "if_test0";
    let program_without_backend = "program_no_backend";
    let interface_without_backend = "if_missing0";
    let report = json!({
        "residentStartupEvidence": {
            "bpfLoader": {
                "objectSource": "rust-aya-loader",
                "defaultObjectSource": "rust-aya-loader",
                "kernelEbpfProgramRewrite": true
            },
            "loadedEbpf": {
                "programCount": 1,
                "mapCount": 2
            },
            "bindings": [{
                "programName": program_with_backend,
                "interface": interface_with_backend,
                "backend": "tcx",
                "role": "ingress",
                "direction": "ingress",
                "priority": 1,
                "handle": 2
            }, {
                "programName": program_without_backend,
                "interface": interface_without_backend,
                "role": "egress",
                "direction": "egress",
                "priority": 3,
                "handle": 4
            }],
            "routingMatchSets": [{
                "interface": "if_test0",
                "len": 3,
                "maxEntries": 1024,
                "mapId": 4,
                "mapName": "routing_map"
            }]
        }
    });

    append_startup_runtime_evidence_logs_for_config(&dir, &state, &report).unwrap();

    let logs = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
    let items = logs["items"].as_array().unwrap();
    assert_eq!(items.len(), 6, "{logs}");
    assert_eq!(
        items[0]["message"],
        json!(
            "The loading process takes about 120MB free memory, which will be released after loading. Insufficient memory will cause loading failure."
        )
    );
    assert_eq!(items[1]["message"], json!("Rust/Aya BPF loader loaded"));
    assert_eq!(
        items[1]["fields"]["object_source"],
        json!("rust-aya-loader")
    );
    assert_eq!(
        items[1]["fields"]["kernel_ebpf_program_rewrite"],
        json!("true")
    );
    assert_eq!(items[2]["message"], json!("Loaded eBPF programs and maps"));
    assert_eq!(items[2]["fields"]["program_count"], json!("1"));
    assert_eq!(
        items[3]["message"],
        json!(format!(
            "Bind {program_with_backend} via Rust/Aya tcx on {interface_with_backend}"
        ))
    );
    assert_eq!(items[3]["fields"]["role"], json!("ingress"));
    assert_eq!(
        items[4]["message"],
        json!(format!(
            "Bind {program_without_backend} via Rust/Aya on {interface_without_backend}"
        ))
    );
    assert_eq!(items[4]["fields"]["role"], json!("egress"));
    assert_eq!(items[5]["message"], json!("Routing match set len: 3/1024"));
    assert_eq!(items[5]["fields"]["interface"], json!("if_test0"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn runtime_overview_reports_process_metrics_and_stream_retry_delta() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let app = AppState {
        config_dir: dir.clone(),
        state,
        web_root: dir.clone(),
        api_only: true,
        control_socket: dir.join("control.sock"),
        shutdown: Arc::new(ProductShutdown::default()),
        runtime: Arc::new(ProductRuntimeManager::new()),
        runtime_sampler: None,
        latency_jobs: Arc::new(LatencyJobManager::default()),
        http_metrics: Arc::new(ProductHttpMetrics::default()),
        ui_runtime: Arc::new(ProductUiRuntime::default()),
        auth_runtime: product_test_auth_runtime(),
        geodata_updates: Arc::new(geodata::ProductGeodataUpdateCoordinator::default()),
        geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
        geodata_update_runtime: None,
    };
    let request = HttpRequest {
        method: "GET".to_owned(),
        path: "/api/events/runtime".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let overview = runtime_overview_report(&app, &request);
    assert!(
        overview["rssBytes"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 0
    );
    assert!(
        overview["anonymousRssBytes"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 0
    );
    assert_eq!(overview["rssAnonBytes"], overview["anonymousRssBytes"]);
    assert!(overview["fileRssBytes"].as_str().is_some());
    assert_eq!(overview["rssFileBytes"], overview["fileRssBytes"]);
    assert!(overview["vmDataBytes"].as_str().is_some());
    if allocator_stats_snapshot().is_some() {
        assert!(
            overview["heapLiveBytes"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 0
        );
        assert_eq!(overview["heapMetricSource"], json!("allocator-stats"));
        assert_eq!(overview["allocatorStats"]["available"], json!(true));
        assert_eq!(overview["allocatorDerived"]["available"], json!(true));
        assert!(
            overview["allocatorDerived"]["bytes"]["residentMinusActive"]
                .as_str()
                .is_some()
        );
    } else {
        assert_eq!(overview["heapLiveBytes"], Value::Null);
        assert_eq!(overview["heapMetricSource"], json!("unavailable"));
        assert_eq!(overview["allocatorStats"]["available"], json!(false));
        assert_eq!(overview["allocatorDerived"]["available"], json!(false));
    }
    assert!(overview.get("heapAllocBytes").is_none());
    assert!(overview.get("heapAllocBytesSource").is_none());
    assert_eq!(
        overview["heapCompatBytesSource"],
        json!("compat-alias-rss-anon-not-live-heap")
    );
    assert_eq!(overview["allocatorProfile"], json!(allocator_profile()));
    assert!(overview["allocatorReclaim"]["total"].as_u64().is_some());
    assert_eq!(
        overview["allocatorIdleReclaim"]["policy"]["idleDetection"],
        json!("traffic-rate-only")
    );
    assert_eq!(
        overview["allocatorIdleReclaim"]["policy"]["sessionCountGate"],
        json!(false)
    );
    assert!(overview["cgroupMemory"]["available"].as_bool().is_some());
    if overview["cgroupMemory"]["available"] == json!(true) {
        assert!(
            overview["cgroupMemory"]["currentBytes"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 0
        );
    }
    assert_eq!(
        overview["resourcePools"]["udpEndpoint"]["defaultMaxEntries"],
        json!(DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES)
    );
    assert!(overview["goroutines"].as_u64().unwrap() > 0);
    assert!(overview["cpuUsagePercent"].as_f64().unwrap() >= 0.0);

    let delta = runtime_overview_delta_report(&app);
    assert!(delta["uploadRate"].as_str().is_some());
    assert!(delta["rssBytes"].as_str().is_some());
    if allocator_stats_snapshot().is_some() {
        assert!(delta["heapLiveBytes"].as_str().is_some());
    } else {
        assert_eq!(delta["heapLiveBytes"], Value::Null);
    }
    assert!(delta.get("heapAllocBytes").is_none());
    assert!(delta["goroutines"].as_u64().is_some());
    assert!(delta.get("allocatorStats").is_none());
    assert!(delta.get("allocatorDerived").is_none());
    assert!(delta.get("allocatorReclaim").is_none());
    assert!(delta.get("allocatorIdleReclaim").is_none());
    assert!(delta["cgroupMemory"]["available"].as_bool().is_some());
    assert_eq!(delta["samples"].as_array().map(Vec::len), Some(1));
    assert!(delta["sequence"].as_u64().is_some());
    assert!(delta.get("resourcePools").is_none());
    assert!(delta.get("runtime").is_none());

    let response = api_runtime_events(&app, &request);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains("retry: 3000"));
    assert!(body.contains("event: runtime.overview\n"));
    assert!(body.contains("event: runtime.group-selection\n"));
    assert!(body.contains("event: runtime.overview.delta\n"));
    assert!(body.contains("\"heapLiveBytes\""));
    assert!(!body.contains("\"heapAllocBytes\""));
    assert!(body.contains("\"anonymousRssBytes\""));
    assert!(body.contains("\"rssAnonBytes\""));
    assert!(body.contains("\"fileRssBytes\""));
    assert!(body.contains("\"rssFileBytes\""));
    assert!(body.contains("\"heapCompatBytes\""));
    assert!(body.contains("\"heapCompatBytesSource\""));
    assert!(body.contains("\"allocatorProfile\""));
    assert!(body.contains("\"cgroupMemory\""));
    assert!(body.contains("\"resourcePools\""));
    assert!(body.contains("\"goroutines\""));
    assert!(body.contains("\"cpuUsagePercent\""));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn runtime_reclaim_tracks_single_completed_reload_reason() {
    let before = allocator_reclaim_snapshot_json();
    let before_total = before["total"].as_u64().unwrap_or(0);
    let before_reload_completed = before["reasons"]["reload_completed"].as_u64().unwrap_or(0);
    let before_reload_failed = before["reasons"]["reload_failed_after_cleanup"]
        .as_u64()
        .unwrap_or(0);
    let before_geodata_update = before["reasons"]["geodata_update"].as_u64().unwrap_or(0);

    let reclaim = allocator_reclaim(AllocatorReclaimReason::ReloadCompleted);
    let failed_reclaim = allocator_reclaim(AllocatorReclaimReason::ReloadFailedAfterCleanup);
    let geodata_reclaim = allocator_reclaim(AllocatorReclaimReason::GeodataUpdate);
    let after = allocator_reclaim_snapshot_json();

    assert_eq!(reclaim["reason"], json!("reload_completed"));
    assert_eq!(
        failed_reclaim["reason"],
        json!("reload_failed_after_cleanup")
    );
    assert_eq!(geodata_reclaim["reason"], json!("geodata_update"));
    assert_eq!(reclaim["profile"], json!(allocator_profile()));
    #[cfg(feature = "allocator-jemalloc")]
    {
        assert_eq!(reclaim["status"], json!("pass"), "{reclaim}");
        assert_eq!(
            reclaim["detail"]["threadCacheFlush"]["status"],
            json!("pass"),
            "{reclaim}"
        );
        assert_eq!(
            reclaim["detail"]["arenaPurgeScope"],
            json!("all-initialized-arenas"),
            "{reclaim}"
        );
        assert!(
            reclaim["detail"]["arenasAttempted"].as_u64().unwrap_or(0) > 0,
            "{reclaim}"
        );
        assert_eq!(reclaim["detail"]["failures"], json!([]), "{reclaim}");
    }
    assert!(after["total"].as_u64().unwrap_or(0) > before_total);
    assert!(after["reasons"]["reload_completed"].as_u64().unwrap_or(0) > before_reload_completed);
    assert!(
        after["reasons"]["reload_failed_after_cleanup"]
            .as_u64()
            .unwrap_or(0)
            > before_reload_failed
    );
    assert!(after["reasons"]["geodata_update"].as_u64().unwrap_or(0) > before_geodata_update);
}

#[test]
pub(crate) fn runtime_reload_failure_after_cleanup_reclaims_allocator() {
    let manager = ProductRuntimeManager::new();
    {
        let mut inner = manager.inner.lock().unwrap();
        inner.runtime = Some(ProductRuntimeInstance::Fake(FakeProductRuntime {
            started_at: "2026-07-06T01:00:00.000Z".to_owned(),
            tproxy_port: 12345,
        }));
        inner.runtime_started_at = Some("2026-07-06T01:00:00.000Z".to_owned());
    }
    let sections = parse_config(
        r#"
global {
  log_level: info
}
routing {
  fallback: direct
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let before = allocator_reclaim_snapshot_json()["reasons"]["reload_failed_after_cleanup"]
        .as_u64()
        .unwrap_or(0);

    let err = manager
        .reload_with_config_content(config, None, "test", &[])
        .unwrap_err();
    let after = allocator_reclaim_snapshot_json()["reasons"]["reload_failed_after_cleanup"]
        .as_u64()
        .unwrap_or(0);

    assert!(err.contains("global.lan_interface"), "{err}");
    assert!(after > before);
    let summary = manager.summary();
    assert_eq!(summary["state"], json!("error"));
    assert_eq!(summary["cleanup"]["state"], json!("done"));
}

#[test]
pub(crate) fn process_status_metrics_splits_rss_and_keeps_heap_compat_alias() {
    let status = "\
Name:\tdaed\n\
VmRSS:\t  200000 kB\n\
RssAnon:\t  150000 kB\n\
RssFile:\t  50000 kB\n\
VmData:\t  260000 kB\n\
Threads:\t38\n";
    let metrics = process_status_metrics_from_str(status);
    assert_eq!(metrics.rss_bytes, 200000 * 1024);
    assert_eq!(metrics.anonymous_rss_bytes, 150000 * 1024);
    assert_eq!(metrics.file_rss_bytes, 50000 * 1024);
    assert_eq!(metrics.vm_data_bytes, 260000 * 1024);
    assert_eq!(metrics.heap_alloc_bytes_compat(), 150000 * 1024);
    assert_eq!(metrics.thread_count, 38);

    let fallback = process_status_metrics_from_str("VmData:\t42 kB\n");
    assert_eq!(fallback.anonymous_rss_bytes, 42 * 1024);
    assert_eq!(fallback.vm_data_bytes, 42 * 1024);
    assert_eq!(fallback.heap_alloc_bytes_compat(), 42 * 1024);
}

#[test]
pub(crate) fn runtime_process_stop_preserves_persisted_running_state() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute(
            "INSERT INTO systems(running, running_config_version, running_dns_version, running_routing_version, running_group_version_sum, running_group_ids)
             VALUES(1, 0, 0, 0, 0, '')",
            [],
        )
        .unwrap();
    set_metadata(&state, "runtime_running", "true").unwrap();

    mark_runtime_process_stopped(&state).unwrap();

    assert!(should_restore_runtime_on_start(&state).unwrap());
    assert_eq!(
        get_metadata(&state, "runtime_running").unwrap().as_deref(),
        Some("false")
    );
    mark_system_stopped(&state).unwrap();
    assert!(!should_restore_runtime_on_start(&state).unwrap());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn startup_restore_failure_keeps_server_recoverable() {
    let dir = std::env::temp_dir().join(format!(
        "daed-product-startup-restore-failure-{}",
        fastrand::u64(..)
    ));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    initialize_log_store(&dir, &state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute(
        "INSERT INTO systems(running, running_config_version, running_dns_version, running_routing_version, running_group_version_sum, running_group_ids)
         VALUES(1, 0, 0, 0, 0, '')",
        [],
    )
    .unwrap();
    drop(conn);

    record_startup_runtime_restore_failure(&dir, &state, "group proxy has no matched nodes");

    assert!(should_restore_runtime_on_start(&state).unwrap());
    assert_eq!(
        get_metadata(&state, "runtime_running").unwrap().as_deref(),
        Some("false")
    );
    assert_eq!(
        get_metadata(&state, "runtime_transition_phase")
            .unwrap()
            .as_deref(),
        Some("waiting-for-host")
    );
    let logs = list_logs_value(&dir, &state, Some("error"), None, 10).unwrap();
    assert!(logs["items"].as_array().unwrap().iter().any(|entry| {
        entry["message"]
            .as_str()
            .unwrap_or_default()
            .contains("waiting for host readiness")
    }));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn runtime_modified_matches_running_resource_snapshot() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
        r#"
            INSERT INTO configs(id, name, global, selected, version)
                VALUES(1, 'global', 'global {}', 1, 1);
            INSERT INTO dns(id, name, dns, selected, version)
                VALUES(1, 'dns', 'dns {}', 1, 1);
            INSERT INTO routings(id, name, routing, selected, version)
                VALUES(1, 'routing', 'routing { fallback: egress }', 1, 1);
            INSERT INTO groups(id, name, policy, version)
                VALUES(1, 'egress', 'random', 1);
            INSERT INTO systems(
                running,
                running_config_version,
                running_dns_version,
                running_routing_version,
                running_group_version_sum,
                running_group_ids,
                running_config_id,
                running_dns_id,
                running_routing_id
            )
                VALUES(1, 1, 1, 1, 1, '1', 1, 1, 1);
            "#,
    )
    .unwrap();

    assert!(!runtime_modified(&conn, false).unwrap());
    assert!(!runtime_modified(&conn, true).unwrap());

    conn.execute("UPDATE configs SET version = version + 1 WHERE id = 1", [])
        .unwrap();
    assert!(runtime_modified(&conn, true).unwrap());

    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn runtime_modified_tracks_external_input_version_snapshot() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
        r#"
            INSERT INTO configs(id, name, global, selected, version)
                VALUES(1, 'global', 'global {}', 1, 1);
            INSERT INTO dns(id, name, dns, selected, version)
                VALUES(1, 'dns', 'dns {}', 1, 1);
            INSERT INTO routings(id, name, routing, selected, version)
                VALUES(1, 'routing', 'routing { fallback: direct }', 1, 1);
        "#,
    )
    .unwrap();
    insert_config_node(
        &conn,
        1,
        "resource_node",
        "socks://127.0.0.1:1080#resource_node",
        None,
    );
    conn.execute(
        "INSERT INTO group_nodes(group_id, node_id) VALUES(1, 1)",
        [],
    )
    .unwrap();
    drop(conn);

    materialize_runtime(&state, None, false).unwrap();
    let conn = open_state_connection(&state).unwrap();
    assert!(!runtime_modified(&conn, true).unwrap());
    drop(conn);

    bump_runtime_external_input_version(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    assert!(runtime_modified(&conn, true).unwrap());
    drop(conn);

    materialize_runtime(&state, None, false).unwrap();
    let conn = open_state_connection(&state).unwrap();
    assert!(!runtime_modified(&conn, true).unwrap());

    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn runtime_materialization_plan_apply_uses_prepared_snapshot() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
        r#"
            INSERT INTO configs(id, name, global, selected, version)
                VALUES(1, 'global', 'global { log_level: info }', 1, 1);
            INSERT INTO dns(id, name, dns, selected, version)
                VALUES(1, 'dns', 'dns {}', 1, 1);
            INSERT INTO routings(id, name, routing, selected, version)
                VALUES(1, 'routing', 'routing { fallback: direct }', 1, 1);
        "#,
    )
    .unwrap();
    drop(conn);

    let plan = prepare_runtime_materialization_plan(&state).unwrap();
    let prepared_content = plan.content.clone();
    let conn = open_state_connection(&state).unwrap();
    conn.execute(
        "UPDATE configs SET global = 'global { log_level: debug }', version = 2 WHERE id = 1",
        [],
    )
    .unwrap();
    drop(conn);

    let report = apply_runtime_materialization_plan(&state, Some(&dir), &plan).unwrap();
    let generated_path = report["path"].as_str().unwrap();
    assert_eq!(
        fs::read_to_string(generated_path).unwrap(),
        prepared_content
    );
    let conn = open_state_connection(&state).unwrap();
    let running = running_runtime_state(&conn).unwrap().unwrap();
    assert_eq!(running.config_version, 1);
    assert!(runtime_modified(&conn, true).unwrap());

    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn validate_runtime_checks_generated_config_without_applying_it() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
        r#"
            INSERT INTO configs(id, name, global, selected, version)
                VALUES(1, 'global', 'global { log_level: info }', 1, 1);
            INSERT INTO dns(id, name, dns, selected, version)
                VALUES(1, 'dns', 'dns {}', 1, 1);
            INSERT INTO routings(id, name, routing, selected, version)
                VALUES(1, 'routing', 'routing { fallback: direct }', 1, 1);
        "#,
    )
    .unwrap();
    drop(conn);

    let report = validate_product_config_path(&dir, true).unwrap();
    assert_eq!(report["runtimeValidation"]["contentIncluded"], json!(false));
    assert_eq!(
        report["runtimeValidation"]["selected"]["configId"],
        json!(1)
    );
    assert!(!dir.join("runtime").join("generated.dae").exists());
    assert!(
        running_runtime_state(&open_state_connection(&state).unwrap())
            .unwrap()
            .is_none()
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn running_bundle_import_marks_existing_selected_resources_modified() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
        r#"
            INSERT INTO configs(id, name, global, selected, version)
                VALUES(1, 'global', 'global {}', 1, 0);
            INSERT INTO dns(id, name, dns, selected, version)
                VALUES(1, 'dns', 'dns {}', 1, 0);
            INSERT INTO routings(id, name, routing, selected, version)
                VALUES(1, 'routing', 'routing { fallback: egress }', 1, 0);
            INSERT INTO groups(id, name, policy, version)
                VALUES(1, 'egress', 'random', 0);
            INSERT INTO users(id, username, password_hash, jwt_secret, json_storage)
                VALUES(1, 'tester', '', '', '{}');
        "#,
    )
    .unwrap();
    insert_config_node(
        &conn,
        1,
        "resource_node",
        "socks://127.0.0.1:1080#resource_node",
        None,
    );
    conn.execute(
        "INSERT INTO group_nodes(group_id, node_id) VALUES(1, 1)",
        [],
    )
    .unwrap();
    drop(conn);

    materialize_runtime(&state, None, false).unwrap();
    let conn = open_state_connection(&state).unwrap();
    assert!(!runtime_modified(&conn, true).unwrap());
    drop(conn);

    let user = UserRecord {
        id: 1,
        username: "tester".to_owned(),
        password_hash: String::new(),
        jwt_secret: String::new(),
        json_storage: "{}".to_owned(),
        avatar: None,
        name: None,
    };
    let bundle = json!({
        "schemaVersion": 1,
        "mode": "rule",
        "selected": {
            "configId": 1,
            "dnsId": 1,
            "routingId": 1
        },
        "configs": [{
            "id": 1,
            "name": "global",
            "global": "global { log_level: error }"
        }],
        "dnss": [{
            "id": 1,
            "name": "dns",
            "dns": "dns {}"
        }],
        "routings": [{
            "id": 1,
            "name": "routing",
            "routing": "routing { fallback: egress }"
        }],
        "subscriptions": [],
        "nodes": [config_node_value(1, "resource_node", "socks://127.0.0.1:1080#resource_node")],
        "groups": [{
            "id": 1,
            "name": "egress",
            "policy": "random",
            "policyParams": [],
            "nodeIds": [1],
            "subscriptionBindings": []
        }]
    });

    let outcome = import_bundle(&state, &dir, &bundle, &user).unwrap();
    assert!(outcome.imported);
    assert!(outcome.runtime_reload_required);

    let conn = open_state_connection(&state).unwrap();
    assert!(runtime_modified(&conn, true).unwrap());
    let config_version: i64 = conn
        .query_row("SELECT version FROM configs WHERE id = 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    let group_version: i64 = conn
        .query_row("SELECT version FROM groups WHERE id = 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(config_version > 0);
    assert!(group_version > 0);

    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn materializer_tolerates_legacy_orphan_group_node_rows() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    let runtime_dir = dir.join("config");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute_batch(
            r#"
            DROP TABLE group_nodes;
            CREATE TABLE group_nodes (
                group_id INTEGER NOT NULL,
                node_id INTEGER NOT NULL,
                PRIMARY KEY(group_id, node_id),
                FOREIGN KEY(group_id) REFERENCES groups(id),
                FOREIGN KEY(node_id) REFERENCES nodes(id)
            );
            INSERT INTO configs(id, name, global, selected, version)
                VALUES(1, 'global', 'global {}', 1, 1);
            INSERT INTO dns(id, name, dns, selected, version)
                VALUES(1, 'dns', 'dns {}', 1, 1);
            INSERT INTO routings(id, name, routing, selected, version)
                VALUES(1, 'routing', 'routing { fallback: egress }', 1, 1);
            INSERT INTO groups(id, name, policy, version)
                VALUES(1, 'egress', 'random', 1);
            INSERT INTO systems(running, running_config_version, running_dns_version, running_routing_version, running_group_version_sum, running_group_ids)
                VALUES(1, 0, 0, 0, 0, '');
            "#,
        )
        .unwrap();
    insert_config_node(
        &conn,
        1,
        "resource_node",
        "http://127.0.0.1:9/node-under-test#resource-node",
        None,
    );
    conn.execute(
        "INSERT INTO group_nodes(group_id, node_id) VALUES(1, 1)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO group_nodes(group_id, node_id) VALUES(1, 9999)",
        [],
    )
    .unwrap();

    let report = materialize_runtime(&state, Some(&runtime_dir), false).unwrap();
    assert_eq!(report["selected"]["configId"].as_i64(), Some(1));
    assert_eq!(report["contentIncluded"], json!(false));
    assert!(report.get("content").is_none());
    assert!(report["bytes"].as_u64().unwrap() > 0);
    assert!(runtime_dir.join("runtime/generated.dae").is_file());
    fs::remove_dir_all(dir).unwrap();
}

use super::super::super::*;
use super::*;
#[test]
pub(crate) fn runtime_reload_dry_preview_writes_unified_reload_logs() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    initialize_log_store(&dir, &state).unwrap();
    let app = AppState {
        config_dir: dir.clone(),
        state: state.clone(),
        web_root: dir.clone(),
        api_only: true,
        runtime: Arc::new(ProductRuntimeManager::new()),
        http_metrics: Arc::new(ProductHttpMetrics::default()),
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
pub(crate) fn startup_runtime_evidence_logs_report_interfaces_generically() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    initialize_log_store(&dir, &state).unwrap();
    set_metadata(&state, "runtime_log_level", "info").unwrap();
    let report = json!({
        "residentStartupEvidence": {
            "bpfLoader": {
                "objectSource": "rust-aya-skeleton",
                "defaultObjectSource": "rust-aya-skeleton",
                "kernelEbpfProgramRewrite": true
            },
            "loadedEbpf": {
                "programCount": 1,
                "mapCount": 2
            },
            "bindings": [{
                "programName": "program_ingress",
                "interface": "if_test0",
                "backend": "tcx",
                "role": "ingress",
                "direction": "ingress",
                "priority": 1,
                "handle": 2
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
    assert_eq!(items.len(), 5, "{logs}");
    assert_eq!(
        items[0]["message"],
        json!(
            "The loading process takes about 120MB free memory, which will be released after loading. Insufficient memory will cause loading failure."
        )
    );
    assert_eq!(items[1]["message"], json!("Rust/Aya BPF loader loaded"));
    assert_eq!(
        items[1]["fields"]["object_source"],
        json!("rust-aya-skeleton")
    );
    assert_eq!(
        items[1]["fields"]["kernel_ebpf_program_rewrite"],
        json!("true")
    );
    assert_eq!(items[2]["message"], json!("Loaded eBPF programs and maps"));
    assert_eq!(items[2]["fields"]["program_count"], json!("1"));
    assert_eq!(
        items[3]["message"],
        json!("Bind program_ingress via Rust/Aya tcx on if_test0")
    );
    assert_eq!(items[3]["fields"]["role"], json!("ingress"));
    assert_eq!(items[4]["message"], json!("Routing match set len: 3/1024"));
    assert_eq!(items[4]["fields"]["interface"], json!("if_test0"));

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
        runtime: Arc::new(ProductRuntimeManager::new()),
        http_metrics: Arc::new(ProductHttpMetrics::default()),
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
        overview["heapAllocBytes"]
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
    if allocator_live_heap_bytes().is_some() {
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
    } else {
        assert_eq!(overview["heapLiveBytes"], Value::Null);
        assert_eq!(overview["heapMetricSource"], json!("unavailable"));
        assert_eq!(overview["allocatorStats"]["available"], json!(false));
    }
    assert_eq!(overview["heapCompatBytes"], overview["heapAllocBytes"]);
    assert_eq!(
        overview["heapCompatBytesSource"],
        json!("compat-alias-rss-anon-not-live-heap")
    );
    assert_eq!(
        overview["heapAllocBytesSource"],
        json!("compat-alias-rss-anon-not-live-heap")
    );
    assert_eq!(overview["allocatorProfile"], json!(allocator_profile()));
    assert!(overview["allocatorReclaim"]["total"].as_u64().is_some());
    assert_eq!(
        overview["resourcePools"]["udpEndpoint"]["defaultMaxEntries"],
        json!(DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES)
    );
    assert!(overview["goroutines"].as_u64().unwrap() > 0);
    assert!(overview["cpuUsagePercent"].as_f64().unwrap() >= 0.0);

    let delta = runtime_overview_delta_report(&app, &request);
    assert!(delta["uploadRate"].as_str().is_some());
    assert!(delta["rssBytes"].as_str().is_some());
    assert!(delta["heapAllocBytes"].as_str().is_some());
    assert!(delta["goroutines"].as_u64().is_some());
    assert!(delta.get("allocatorStats").is_none());
    assert!(delta.get("allocatorReclaim").is_none());
    assert!(delta.get("resourcePools").is_none());
    assert!(delta.get("runtime").is_none());

    let response = api_runtime_events(&app, &request);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains("retry: 3000"));
    assert!(body.contains("event: runtime.overview\n"));
    assert!(body.contains("event: runtime.overview.delta\n"));
    assert!(body.contains("\"heapAllocBytes\""));
    assert!(body.contains("\"anonymousRssBytes\""));
    assert!(body.contains("\"rssAnonBytes\""));
    assert!(body.contains("\"fileRssBytes\""));
    assert!(body.contains("\"rssFileBytes\""));
    assert!(body.contains("\"heapCompatBytes\""));
    assert!(body.contains("\"heapAllocBytesSource\""));
    assert!(body.contains("\"allocatorProfile\""));
    assert!(body.contains("\"resourcePools\""));
    assert!(body.contains("\"goroutines\""));
    assert!(body.contains("\"cpuUsagePercent\""));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn runtime_reclaim_report_includes_post_reload_idle_reclaim() {
    let mut report = json!({});
    append_runtime_reclaim_report(
        &mut report,
        Some(json!({"reason": "reload_old_owner_closed"})),
        json!({"reason": "startup_control_built"}),
        Some(json!({"reason": "reload_scoped_resources_flushed"})),
        Some(json!({"reason": "idle_after_reload"})),
    );

    assert_eq!(
        report["allocatorReclaim"]["idleAfterReload"]["reason"],
        json!("idle_after_reload")
    );
    assert_eq!(report["allocatorProfile"], json!(allocator_profile()));
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

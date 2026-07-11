use super::*;

fn socket_addr(socket: &str) -> std::net::SocketAddr {
    socket.parse().unwrap()
}

fn expected_transport_network(transport: &str, socket: &str) -> String {
    resident_socket_network_name(transport, socket_addr(socket))
}

fn mapped_ipv4_socket_addr(octets: [u8; 4], port: u16) -> std::net::SocketAddr {
    let mut mapped = [0_u8; 16];
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12..16].copy_from_slice(&octets);
    std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(mapped)), port)
}

fn assert_log_field_from_json(fields: &Value, key: &str, value: &Value) {
    assert_eq!(fields[key], json!(product_log_field_value(value)), "{key}");
}

#[test]
pub(crate) fn log_scan_cursor_does_not_skip_ids_after_prune_rename() {
    let dir = std::env::temp_dir().join(format!(
        "daed-product-log-prune-cursor-{}",
        fastrand::u64(..)
    ));
    fs::create_dir_all(product_log_dir(&dir)).unwrap();
    let path = product_log_file(&dir);
    let mut initial = String::new();
    for id in 1..=510_u64 {
        initial.push_str(&format!(
            "{{\"id\":{id},\"ts\":\"2026-07-12T00:00:00Z\",\"level\":\"info\",\"message\":\"entry-{id:04}\",\"fields\":{{}}}}\n"
        ));
    }
    fs::write(&path, initial).unwrap();
    let cursor = ProductLogScanCursor::at_end(&dir).unwrap();
    let mut appended = fs::OpenOptions::new().append(true).open(&path).unwrap();
    for id in 511..=700_u64 {
        writeln!(
            appended,
            "{{\"id\":{id},\"ts\":\"2026-07-12T00:00:00Z\",\"level\":\"info\",\"message\":\"entry-{id:04}\",\"fields\":{{}}}}"
        )
        .unwrap();
    }
    appended.flush().unwrap();
    prune_log_file_with_settings(&path, 500, MIN_LOG_MAX_BYTES).unwrap();

    let mut ids = Vec::new();
    let scan = scan_log_entries_from_cursor(&dir, cursor, 510, |entry| {
        ids.push(log_entry_value(entry)["id"].as_u64().unwrap());
        Ok(())
    })
    .unwrap();

    assert!(scan.reset);
    assert_eq!(ids, (511..=700_u64).collect::<Vec<_>>());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn log_scan_batch_limits_scanned_lines_before_after_id() {
    const TOTAL_LINES: u64 = 1_024;
    const BATCH_LINES: usize = 32;

    let dir = std::env::temp_dir().join(format!(
        "daed-product-log-bounded-scan-{}",
        fastrand::u64(..)
    ));
    fs::create_dir_all(product_log_dir(&dir)).unwrap();
    let path = product_log_file(&dir);
    let mut contents = String::new();
    for id in 1..=TOTAL_LINES {
        contents.push_str(&format!(
            "{{\"id\":{id},\"ts\":\"2026-07-12T00:00:00Z\",\"level\":\"info\",\"message\":\"entry-{id:04}\",\"fields\":{{}}}}\n"
        ));
    }
    fs::write(path, contents).unwrap();

    let mut cursor = ProductLogScanCursor::start();
    let mut batches = 0_usize;
    loop {
        let batch = read_log_entry_batch_from_cursor(
            &dir,
            cursor,
            TOTAL_LINES.saturating_add(1),
            BATCH_LINES,
        )
        .unwrap();
        batches = batches.saturating_add(1);
        assert!(batch.entries.is_empty());
        cursor = batch.state.cursor;
        if batch.reached_eof {
            break;
        }
        assert!(batches <= TOTAL_LINES as usize / BATCH_LINES);
    }

    assert_eq!(batches, TOTAL_LINES as usize / BATCH_LINES + 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn product_json_log_timestamp_uses_local_offset_shape() {
    assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(
        format_product_log_timestamp_with_offset(2026, 7, 7, 10, 35, 12, 8 * 3_600),
        "2026-07-07T10:35:12+08:00"
    );
    assert_eq!(
        format_product_log_timestamp_with_offset(2026, 1, 2, 3, 4, 5, -(5 * 3_600 + 30 * 60)),
        "2026-01-02T03:04:05-05:30"
    );

    #[cfg(target_family = "unix")]
    {
        let line =
            encode_log_entry_json_line(1, "info", "local timestamp", &BTreeMap::new()).unwrap();
        let entry: Value = serde_json::from_slice(&line).unwrap();
        let ts = entry["ts"].as_str().unwrap();
        assert_eq!(ts.len(), "2026-07-07T10:35:12+08:00".len(), "{ts}");
        assert_eq!(&ts[4..5], "-", "{ts}");
        assert_eq!(&ts[7..8], "-", "{ts}");
        assert_eq!(&ts[10..11], "T", "{ts}");
        assert_eq!(&ts[13..14], ":", "{ts}");
        assert_eq!(&ts[16..17], ":", "{ts}");
        assert!(matches!(&ts[19..20], "+" | "-"), "{ts}");
        assert_eq!(&ts[22..23], ":", "{ts}");
        assert!(!ts.ends_with('Z'), "{ts}");
    }
}

#[test]
pub(crate) fn runtime_log_level_defaults_to_error() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();

    assert_eq!(current_runtime_log_level(&state).unwrap(), "error");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn logs_filter_level_all_case_insensitive_query_and_sse_event_name() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    set_metadata(&state, "runtime_log_level", "info").unwrap();
    let conn = open_state_connection(&state).unwrap();
    let log_entries_table: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'log_entries'",
            [],
            |row| row.get(0),
        )
        .optional()
        .unwrap();
    assert!(log_entries_table.is_none());

    append_log_for_config(&dir, &state, "info", "Runtime started").unwrap();
    let mut fields = BTreeMap::new();
    fields.insert("subscription".to_owned(), "daily".to_owned());
    append_log_fields_for_config(&dir, &state, "warning", "Policy changed", fields).unwrap();
    append_log_for_config(&dir, &state, "error", "Dial failed").unwrap();

    let log_file = product_log_file(&dir);
    assert!(log_file.exists());
    assert!(fs::read_to_string(&log_file).unwrap().contains("\"id\":1"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(product_log_dir(&dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
        assert_eq!(
            fs::metadata(&log_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let all = list_logs_value(&dir, &state, Some("all"), Some("RUNTIME"), 500).unwrap();
    assert_eq!(all["items"].as_array().unwrap().len(), 1);
    assert_eq!(all["items"][0]["level"], json!("info"));

    let warn = list_logs_value(&dir, &state, Some("warning"), None, 500).unwrap();
    assert_eq!(warn["items"].as_array().unwrap().len(), 1);
    assert_eq!(warn["items"][0]["level"], json!("warn"));
    assert_eq!(warn["items"][0]["fields"]["subscription"], json!("daily"));

    let field = list_logs_value(&dir, &state, Some("all"), Some("DAILY"), 500).unwrap();
    assert_eq!(field["items"].as_array().unwrap().len(), 1);
    assert!(list_logs_value(&dir, &state, Some("not-a-level"), Some("runtime"), 500).is_err());
    let limit_zero = list_logs_value(&dir, &state, Some("all"), None, 0).unwrap();
    assert_eq!(limit_zero["items"].as_array().unwrap().len(), 3);
    let limit_one = list_logs_value(&dir, &state, Some("all"), None, 1).unwrap();
    assert_eq!(limit_one["items"].as_array().unwrap().len(), 1);
    assert_eq!(limit_one["items"][0]["message"], json!("Dial failed"));

    let mut query = HashMap::new();
    query.insert("level".to_owned(), vec!["all".to_owned()]);
    query.insert("q".to_owned(), vec!["dial".to_owned()]);
    let request = HttpRequest {
        method: "GET".to_owned(),
        path: "/api/events/logs".to_owned(),
        query,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let app = AppState {
        config_dir: dir.clone(),
        state: state.clone(),
        web_root: dir.clone(),
        api_only: true,
        control_socket: dir.join("control.sock"),
        runtime: Arc::new(ProductRuntimeManager::new()),
        latency_jobs: Arc::new(LatencyJobManager::default()),
        http_metrics: Arc::new(ProductHttpMetrics::default()),
        auth_runtime: product_test_auth_runtime(),
        geodata_updates: Arc::new(geodata::ProductGeodataUpdateCoordinator::default()),
        geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
        geodata_update_runtime: None,
    };
    for (raw_query, expected_len, expected_level) in [
        ("", 3, None),
        ("level=", 3, None),
        ("level=all", 3, None),
        ("level=ALL", 3, None),
        ("level=info", 1, Some("info")),
        ("level=INFO", 1, Some("info")),
        ("level=warn", 1, Some("warn")),
        ("level=warning", 1, Some("warn")),
        ("level=error", 1, Some("error")),
        ("level=debug", 0, None),
        ("level=trace", 0, None),
        ("level=fatal", 0, None),
        ("level=panic", 0, None),
        ("level=all&limit=0", 3, None),
        ("level=all&limit=1", 1, Some("error")),
    ] {
        let raw_path = if raw_query.is_empty() {
            "/api/logs".to_owned()
        } else {
            format!("/api/logs?{raw_query}")
        };
        let (path, query) = split_path_query(&raw_path);
        let response = api_logs(
            &app,
            &HttpRequest {
                method: "GET".to_owned(),
                path,
                query,
                headers: HashMap::new(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 200, "{raw_query}");
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        let items = value["items"].as_array().unwrap();
        assert_eq!(items.len(), expected_len, "{raw_query}: {value}");
        if let Some(expected_level) = expected_level {
            assert_eq!(items[0]["level"], json!(expected_level), "{raw_query}");
        }
    }
    let response = api_log_events(&app, &request);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains("retry: 3000"));
    assert!(!body.contains("event: log.entry"));
    assert!(!body.contains("Dial failed"));

    for raw_query in ["level=all&after_id=2", "level=all&afterId=2", "after_id="] {
        let (path, query) = split_path_query(&format!("/api/events/logs?{raw_query}"));
        let response = api_log_events(
            &app,
            &HttpRequest {
                method: "GET".to_owned(),
                path,
                query,
                headers: HashMap::new(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 200, "{raw_query}");
    }

    let (path, query) = split_path_query("/api/events/logs?level=all&after_id=not-a-number");
    let invalid_after_id = api_log_events(
        &app,
        &HttpRequest {
            method: "GET".to_owned(),
            path,
            query,
            headers: HashMap::new(),
            body: Vec::new(),
        },
    );
    assert_eq!(invalid_after_id.status, 400);

    for raw_query in ["level=any", "level=*", "level=invalid", "level=err"] {
        let (path, query) = split_path_query(&format!("/api/logs?{raw_query}"));
        let invalid = api_logs(
            &app,
            &HttpRequest {
                method: "GET".to_owned(),
                path,
                query,
                headers: HashMap::new(),
                body: Vec::new(),
            },
        );
        assert_eq!(invalid.status, 400, "{raw_query}");
    }

    let request = HttpRequest {
        method: "PATCH".to_owned(),
        path: "/api/runtime/log-level".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: br#"{"level":"debug"}"#.to_vec(),
    };
    let response = api_set_runtime_log_level(&app, &request);
    assert_eq!(response.status, 200);
    let after_debug_reset = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
    assert_eq!(after_debug_reset["items"].as_array().unwrap().len(), 0);
    append_log_for_config(&dir, &state, "debug", "debug runtime detail").unwrap();
    let debug = list_logs_value(&dir, &state, Some("debug"), None, 500).unwrap();
    assert_eq!(debug["items"].as_array().unwrap().len(), 1);
    assert_eq!(debug["items"][0]["id"], json!(1));
    assert_eq!(debug["items"][0]["level"], json!("debug"));
    assert_eq!(debug["items"][0]["message"], json!("debug runtime detail"));

    append_log_for_config(&dir, &state, "info", "info before stricter level").unwrap();
    append_log_for_config(&dir, &state, "error", "error before stricter level").unwrap();
    let request = HttpRequest {
        method: "PATCH".to_owned(),
        path: "/api/runtime/log-level".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: br#"{"level":"error"}"#.to_vec(),
    };
    let response = api_set_runtime_log_level(&app, &request);
    assert_eq!(response.status, 200);
    let after_level_change = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
    let after_level_items = after_level_change["items"].as_array().unwrap();
    assert_eq!(after_level_items.len(), 0, "{after_level_change}");
    append_log_for_config(&dir, &state, "error", "error after stricter level").unwrap();
    let after_stricter_write = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
    assert_eq!(after_stricter_write["items"].as_array().unwrap().len(), 1);
    assert_eq!(after_stricter_write["items"][0]["id"], json!(1));
    assert_eq!(
        after_stricter_write["items"][0]["message"],
        json!("error after stricter level")
    );

    let request = HttpRequest {
        method: "PATCH".to_owned(),
        path: "/api/runtime/log-level".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: br#"{"level":"debug"}"#.to_vec(),
    };
    let response = api_set_runtime_log_level(&app, &request);
    assert_eq!(response.status, 200);
    append_log_for_config(&dir, &state, "info", "info before config level").unwrap();
    append_log_for_config(&dir, &state, "warn", "warn before config level").unwrap();
    append_log_for_config(&dir, &state, "error", "error before config level").unwrap();
    let config_content = test_config_with_node(
        "config_level_node",
        "http://127.0.0.1:9/node-under-test#config-level",
        "egress",
    )
    .replace("global {}", "global { log_level: error }");
    let config = build_runtime_config_from_content(&config_content).unwrap();
    set_runtime_log_level_from_config(&state, &config).unwrap();
    refresh_log_policy_and_reset_logs(&dir, &state, Some(&app.runtime)).unwrap();
    assert_eq!(current_runtime_log_level(&state).unwrap(), "error");
    let after_config_level = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
    let config_items = after_config_level["items"].as_array().unwrap();
    assert_eq!(config_items.len(), 0, "{after_config_level}");
    append_log_for_config(&dir, &state, "info", "filtered after config level").unwrap();
    append_log_for_config(&dir, &state, "error", "error after config level").unwrap();
    let after_config_write = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
    assert_eq!(after_config_write["items"].as_array().unwrap().len(), 1);
    assert_eq!(after_config_write["items"][0]["id"], json!(1));
    assert_eq!(
        after_config_write["items"][0]["message"],
        json!("error after config level")
    );

    let cleared = api_clear_logs(&app);
    assert_eq!(cleared.status, 200);
    let empty = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
    assert_eq!(empty["items"].as_array().unwrap().len(), 0);

    set_metadata(&state, "runtime_log_level", "fatal").unwrap();
    append_log_for_config(&dir, &state, "info", "filtered after clear").unwrap();
    append_lifecycle_log_for_config(&dir, &state, "info", "[Startup] lifecycle after clear")
        .unwrap();
    append_log_for_config(&dir, &state, "fatal", "fatal after clear").unwrap();
    let after_clear = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
    assert_eq!(after_clear["items"].as_array().unwrap().len(), 2);
    assert_eq!(after_clear["items"][0]["id"], json!(1));
    assert_eq!(
        after_clear["items"][0]["message"],
        json!("[Startup] lifecycle after clear")
    );
    assert_eq!(
        after_clear["items"][0]["fields"]["lifecycle"],
        json!("startup")
    );
    assert_eq!(after_clear["items"][1]["id"], json!(2));
    assert_eq!(
        after_clear["items"][1]["message"],
        json!("fatal after clear")
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn product_log_level_contract_matches_logrus_compatibility() {
    for (input, expected) in [
        ("panic", Some("panic")),
        ("fatal", Some("fatal")),
        ("error", Some("error")),
        ("warn", Some("warn")),
        ("warning", Some("warn")),
        ("info", Some("info")),
        ("debug", Some("debug")),
        ("trace", Some("trace")),
        ("TRACE", Some("trace")),
        ("err", None),
    ] {
        assert_eq!(
            normalize_log_level_name(input).as_deref(),
            expected,
            "{input}"
        );
    }

    assert!(log_level_enabled("panic", "error"));
    assert!(log_level_enabled("fatal", "error"));
    assert!(log_level_enabled("error", "error"));
    assert!(!log_level_enabled("warn", "error"));
    assert!(log_level_enabled("debug", "debug"));
    assert!(!log_level_enabled("trace", "debug"));
    assert!(log_level_enabled("trace", "trace"));
}

#[test]
pub(crate) fn resident_product_log_level_policy_is_explicit_by_event_class() {
    assert!(resident_event_hidden_from_product_log("tcp_worker_started"));
    assert!(resident_event_hidden_from_product_log("tcp_worker_stopped"));
    assert!(resident_event_hidden_from_product_log(
        "udp_session_manager_started"
    ));
    assert!(resident_event_hidden_from_product_log(
        "udp_session_manager_stopped"
    ));
    assert!(resident_event_hidden_from_product_log(
        "resident_health_checker_started"
    ));
    assert!(resident_event_hidden_from_product_log(
        "resident_health_scheduler_started"
    ));
    assert!(resident_event_hidden_from_product_log(
        "resident_health_scheduler_stopped"
    ));

    for event_name in [
        "tcp_async_runtime_build_failed",
        "udp_socket_nonblocking_failed",
        "udp_session_manager_async_fd_failed",
    ] {
        assert_eq!(
            resident_event_product_log_level(event_name, &json!({"event": event_name})),
            "error",
            "{event_name}"
        );
    }

    for event_name in [
        "tcp_connection_failed",
        "tcp_accept_failed",
        "udp_packet_skipped",
        "udp_packet_dropped",
        "udp_exchange_failed",
        "dns_bind_query_failed",
        "resident_health_checker_runtime_failed",
    ] {
        assert_eq!(
            resident_event_product_log_level(event_name, &json!({"event": event_name})),
            "warn",
            "{event_name}"
        );
    }

    assert_eq!(
        resident_event_product_log_level(
            "tcp_connection_finished",
            &json!({"event": "tcp_connection_finished", "proxy_group": "egress_group"})
        ),
        "info"
    );
    assert_eq!(
        resident_event_product_log_level(
            "tcp_connection_finished",
            &json!({"event": "tcp_connection_finished"})
        ),
        "debug"
    );
    assert_eq!(
        resident_event_product_log_level(
            "udp_packet_finished",
            &json!({"event": "udp_packet_finished"})
        ),
        "debug"
    );
    assert_eq!(
        resident_event_product_log_level(
            "udp_session_stopped",
            &json!({"event": "udp_session_stopped"})
        ),
        "debug"
    );
    assert_eq!(
        resident_event_product_log_level(
            "dns_bind_listener_started",
            &json!({"event": "dns_bind_listener_started"})
        ),
        "info"
    );
    assert_eq!(
        resident_event_product_log_level(
            "resident_fatal_error",
            &json!({"event": "resident_fatal_error"})
        ),
        "fatal"
    );
    assert_eq!(
        resident_event_product_log_level(
            "resident_panic_error",
            &json!({"event": "resident_panic_error"})
        ),
        "panic"
    );
}

#[test]
pub(crate) fn resident_trace_events_respect_runtime_trace_threshold() {
    const TCP_ROUTE_CHOSEN: &str = "tcp_route_chosen";
    const TCP_ROUTE_OUTBOUND: &str = "trace_outbound";
    const TCP_ROUTE_DIAL_TARGET: &str = "example.com:443";
    const TCP_ROUTE_ORIGINAL_DST: &str = "198.51.100.7:443";

    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    initialize_log_store(&dir, &state).unwrap();

    for event_name in [
        "tcp_route_chosen",
        "udp_route_chosen",
        "dns_path_chosen",
        "routing_native_match",
    ] {
        assert!(resident_event_trace_product_log(event_name));
        assert_eq!(
            resident_event_product_log_level(event_name, &json!({"event": event_name})),
            "trace",
            "{event_name}"
        );
    }

    let tcp_route_network = expected_transport_network("tcp", TCP_ROUTE_ORIGINAL_DST);
    let tcp_route_event = json!({
        "event": TCP_ROUTE_CHOSEN,
        "network": tcp_route_network,
        "outbound": TCP_ROUTE_OUTBOUND,
        "dial_target": TCP_ROUTE_DIAL_TARGET,
        "original_dst": TCP_ROUTE_ORIGINAL_DST
    });

    set_metadata(&state, "runtime_log_level", "debug").unwrap();
    append_resident_event_product_log(&dir, &state, &tcp_route_event).unwrap();
    let debug_all = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
    assert_eq!(debug_all["items"].as_array().unwrap().len(), 0);

    set_metadata(&state, "runtime_log_level", "trace").unwrap();
    append_resident_event_product_log(&dir, &state, &tcp_route_event).unwrap();
    let trace = list_logs_value(&dir, &state, Some("trace"), None, 500).unwrap();
    let trace_items = trace["items"].as_array().unwrap();
    assert_eq!(trace_items.len(), 1, "{trace}");
    assert_eq!(trace_items[0]["level"], json!("trace"));
    assert_eq!(
        trace_items[0]["message"],
        json!("resident dataplane tcp route chosen")
    );
    assert_log_field_from_json(
        &trace_items[0]["fields"],
        "event",
        &tcp_route_event["event"],
    );
    assert_log_field_from_json(
        &trace_items[0]["fields"],
        "network",
        &tcp_route_event["network"],
    );
    assert_log_field_from_json(
        &trace_items[0]["fields"],
        "outbound",
        &tcp_route_event["outbound"],
    );

    for level in ["debug", "info", "error"] {
        let filtered = list_logs_value(&dir, &state, Some(level), None, 500).unwrap();
        assert_eq!(filtered["items"].as_array().unwrap().len(), 0, "{level}");
    }

    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn log_store_initialization_repairs_existing_jsonl_permissions() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    fs::create_dir_all(product_log_dir(&dir)).unwrap();
    let log_file = product_log_file(&dir);
    fs::write(
        &log_file,
        "{\"id\":1,\"ts\":\"2026-06-03T00:00:00Z\",\"level\":\"info\",\"message\":\"existing\"}\n\
         {\"id\":2,\"ts\":\"2026-06-03T00:00:01Z\",\"level\":\"info\",\"message\":\"[Startup] Finished\"}\n\
         {\"id\":3,\"ts\":\"2026-06-03T00:00:02Z\",\"level\":\"info\",\"message\":\"[Reload] Finished\"}\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&log_file, fs::Permissions::from_mode(0o644)).unwrap();
    }

    initialize_log_store(&dir, &state).unwrap();

    let retained = fs::read_to_string(&log_file).unwrap();
    assert!(!retained.contains("\"message\":\"existing\""), "{retained}");
    assert!(
        retained.contains("\"message\":\"[Startup] Finished\""),
        "{retained}"
    );
    assert!(
        retained.contains("\"message\":\"[Reload] Finished\""),
        "{retained}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(product_log_dir(&dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
        assert_eq!(
            fs::metadata(&log_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn runtime_cycle_log_reset_preserves_startup_and_reload_logs() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    initialize_log_store(&dir, &state).unwrap();
    set_metadata(&state, "runtime_log_level", "error").unwrap();
    append_log_for_config(&dir, &state, "error", "ordinary runtime log").unwrap();
    append_lifecycle_log_for_config(&dir, &state, "info", "[Startup] Finished").unwrap();
    append_lifecycle_log_for_config(&dir, &state, "info", "[Reload] Finished").unwrap();

    refresh_log_policy_and_reset_runtime_cycle_logs(&dir, &state, None).unwrap();

    let logs = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
    let items = logs["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{logs}");
    assert_eq!(items[0]["message"], json!("[Startup] Finished"));
    assert_eq!(items[0]["fields"]["lifecycle"], json!("startup"));
    assert_eq!(items[1]["message"], json!("[Reload] Finished"));
    assert_eq!(items[1]["fields"]["lifecycle"], json!("reload"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn resident_events_are_bridged_to_product_logs_with_runtime_level_filter() {
    const FLOW_DIAL_TARGET: &str = "flow-dial-target";
    const FLOW_FAILED_SOURCE: &str = "flow-failed-source";
    const FLOW_FAILED_TARGET: &str = "flow-failed-target";
    const FLOW_FAILED_ERROR: &str = "sample failure";
    const FLOW_ACCEPT_ERROR: &str = "accept failure";
    const FLOW_OUTBOUND: &str = "flow-outbound";
    const FLOW_POLICY: &str = "fixed";
    const FLOW_DIALER: &str = "flow-dialer";
    const FLOW_PID: u32 = 1;
    const FLOW_DSCP: u8 = 2;
    const FLOW_PROCESS: &str = "flow-process";
    const FLOW_MAC: &str = "flow-mac";
    let flow_source_addr = mapped_ipv4_socket_addr([192, 0, 2, 10], 49480);
    let flow_source = flow_source_addr.to_string();
    let flow_source_display = resident_socket_addr_display(flow_source_addr);
    let flow_destination_addr = mapped_ipv4_socket_addr([198, 51, 100, 50], 5222);
    let flow_destination = flow_destination_addr.to_string();
    let flow_destination_display = resident_socket_addr_display(flow_destination_addr);
    let udp_flow_source_addr = mapped_ipv4_socket_addr([192, 0, 2, 20], 61306);
    let udp_flow_source = udp_flow_source_addr.to_string();
    let udp_flow_source_display = resident_socket_addr_display(udp_flow_source_addr);
    let udp_flow_destination_addr = mapped_ipv4_socket_addr([203, 0, 113, 209], 443);
    let udp_flow_destination = udp_flow_destination_addr.to_string();
    let udp_flow_destination_display = resident_socket_addr_display(udp_flow_destination_addr);
    let tcp_event_network = expected_transport_network("tcp", "[2001:db8::1]:443");
    let udp_event_network = expected_transport_network("udp", "[2001:db8::2]:443");
    let tcp_execution_descriptor = json!({
        "schemaVersion": 1,
        "executor": "tcp-relay",
        "capability": "stream-transport",
        "network": "tcp",
        "securityUnderlay": "boringssl",
        "protocolFraming": "vless",
        "transportUnderlay": "tcp",
        "graphId": "resident-graph:tcp-sample"
    });
    let udp_execution_descriptor = json!({
        "schemaVersion": 1,
        "executor": "packet-relay",
        "capability": "packet-transport",
        "network": "udp",
        "packetSemantics": "xudp",
        "securityUnderlay": "boringssl",
        "protocolFraming": "vless",
        "transportUnderlay": "tcp",
        "graphId": "resident-graph:udp-sample"
    });

    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    set_metadata(&state, "runtime_log_level", "info").unwrap();
    initialize_log_store(&dir, &state).unwrap();

    append_resident_event_product_log(
        &dir,
        &state,
        &json!({"event": "tcp_worker_started", "proxy_count": 2, "dial_mode": "tls"}),
    )
    .unwrap();
    append_resident_event_product_log(
            &dir,
            &state,
            &json!({"event": "tcp_connection_finished", "peer": "ignored-flow-source", "bytes_client_to_proxy": 128}),
        )
        .unwrap();
    append_resident_event_product_log(
        &dir,
        &state,
        &json!({
            "event": "tcp_connection_failed",
            "peer": FLOW_FAILED_SOURCE,
            "dial_target": FLOW_FAILED_TARGET,
            "error": FLOW_FAILED_ERROR
        }),
    )
    .unwrap();
    append_resident_event_product_log(
        &dir,
        &state,
        &json!({"event": "tcp_accept_failed", "error": FLOW_ACCEPT_ERROR}),
    )
    .unwrap();

    let all = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
    let items = all["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{all}");
    assert_eq!(
        items[0]["message"],
        json!(format!(
            "{FLOW_FAILED_SOURCE} <-> {FLOW_FAILED_TARGET} failed"
        ))
    );
    assert_eq!(items[0]["level"], json!("warn"));
    assert_eq!(items[0]["fields"]["error"], json!(FLOW_FAILED_ERROR));
    assert!(items[0]["fields"].get("network").is_none());
    assert!(items[0]["fields"].get("event").is_none());
    assert_eq!(
        items[1]["message"],
        json!("resident dataplane tcp accept failed")
    );
    assert_eq!(items[1]["level"], json!("warn"));
    assert_eq!(items[1]["fields"]["error"], json!(FLOW_ACCEPT_ERROR));

    set_metadata(&state, "runtime_log_level", "debug").unwrap();
    append_resident_event_product_log(
        &dir,
        &state,
        &json!({
            "event": "tcp_connection_finished",
            "peer": &flow_source,
            "original_dst": &flow_destination,
            "dial_target": FLOW_DIAL_TARGET,
            "sniffed_domain": "",
            "network": tcp_event_network,
            "bytes_client_to_proxy": 256,
            "node_tag": FLOW_DIALER,
            "proxy_group": FLOW_OUTBOUND,
            "group_policy": FLOW_POLICY,
            "pid": FLOW_PID,
            "dscp": FLOW_DSCP,
            "pname": FLOW_PROCESS,
            "mac": FLOW_MAC,
            "executionDescriptor": tcp_execution_descriptor.clone(),
            "legacyExecution": "async-proxy-tls"
        }),
    )
    .unwrap();
    append_resident_event_product_log(
        &dir,
        &state,
        &json!({
            "event": "udp_packet_finished",
            "peer": &udp_flow_source,
            "original_dst": &udp_flow_destination,
            "network": udp_event_network,
            "request_len": 64,
            "response_len": 128,
            "executionDescriptor": udp_execution_descriptor.clone(),
            "legacyExecution": "vless-xudp"
        }),
    )
    .unwrap();
    let info = list_logs_value(&dir, &state, Some("info"), None, 500).unwrap();
    let info_items = info["items"].as_array().unwrap();
    let tcp = info_items.last().unwrap();
    assert_eq!(
        tcp["message"],
        json!(format!("{flow_source_display} <-> {FLOW_DIAL_TARGET}"))
    );
    assert!(tcp["fields"].get("event").is_none());
    assert_eq!(
        tcp["fields"]["network"],
        json!(expected_transport_network("tcp", &flow_destination))
    );
    assert_eq!(tcp["fields"]["outbound"], json!(FLOW_OUTBOUND));
    assert_eq!(tcp["fields"]["policy"], json!(FLOW_POLICY));
    assert_eq!(tcp["fields"]["dialer"], json!(FLOW_DIALER));
    assert_eq!(tcp["fields"]["ip"], json!(flow_destination_display));
    assert_eq!(tcp["fields"]["sniffed"], json!(""));
    assert_eq!(tcp["fields"]["pid"], json!(FLOW_PID.to_string()));
    assert_eq!(tcp["fields"]["dscp"], json!(FLOW_DSCP.to_string()));
    assert_eq!(tcp["fields"]["pname"], json!(FLOW_PROCESS));
    assert_eq!(tcp["fields"]["mac"], json!(FLOW_MAC));
    for key in [
        "executor",
        "capability",
        "securityUnderlay",
        "protocolFraming",
        "transportUnderlay",
    ] {
        assert_log_field_from_json(&tcp["fields"], key, &tcp_execution_descriptor[key]);
    }
    assert!(tcp["fields"].get("graphId").is_none());
    assert!(tcp["fields"].get("legacyExecution").is_none());

    let mut legacy_fields = BTreeMap::new();
    legacy_fields.insert("event".to_owned(), "tcp_connection_finished".to_owned());
    legacy_fields.insert("peer".to_owned(), "legacy-flow-source".to_owned());
    append_log_fields_for_config(
        &dir,
        &state,
        "debug",
        "resident dataplane tcp connection finished",
        legacy_fields,
    )
    .unwrap();
    let debug = list_logs_value(&dir, &state, Some("debug"), None, 500).unwrap();
    let items = debug["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{debug}");
    assert_eq!(
        items[0]["message"],
        json!(format!(
            "{udp_flow_source_display} <-> {udp_flow_destination_display}"
        ))
    );
    assert_eq!(
        items[0]["fields"]["network"],
        json!(expected_transport_network("udp", &udp_flow_destination))
    );
    assert_eq!(
        items[0]["fields"]["ip"],
        json!(udp_flow_destination_display)
    );
    for key in ["executor", "capability", "packetSemantics"] {
        assert_log_field_from_json(&items[0]["fields"], key, &udp_execution_descriptor[key]);
    }
    assert!(items[0]["fields"].get("graphId").is_none());
    assert!(items[0]["fields"].get("request_len").is_none());
    assert_eq!(
        items[1]["message"],
        json!("resident dataplane tcp connection finished")
    );

    clear_resident_event_product_log_sink();
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn resident_product_log_fields_hide_internal_graph_ids() {
    let source_octets = [192, 0, 2, 30];
    let source_addr = mapped_ipv4_socket_addr(source_octets, 61306);
    let source_display = source_addr.to_string();
    let normalized_source_display = resident_socket_addr_display(source_addr);
    let packet_session = json!({
        "schemaVersion": 1,
        "manager": "resident-udp-session-manager",
        "graphId": "resident-graph:internal",
        "graphIdentityHash": "sha256:internal",
        "graphLinkHash": "sha256:internal-link",
        "outbound": "egress_group",
        "packetSemantics": "xudp",
        "sourceDisplay": &source_display
    });
    let fields = resident_event_product_log_fields(
        "udp_session_stopped",
        &json!({
            "event": "udp_session_stopped",
            "graphId": "resident-graph:internal",
            "packetSession": packet_session
        }),
    );

    assert!(!fields.contains_key("graphId"));
    let sanitized_packet_session: Value = serde_json::from_str(fields["packetSession"].as_str())
        .unwrap_or_else(|err| panic!("packetSession should be serialized JSON: {err}"));
    assert!(sanitized_packet_session.get("graphId").is_none());
    assert!(sanitized_packet_session.get("graphIdentityHash").is_none());
    assert!(sanitized_packet_session.get("graphLinkHash").is_none());
    assert_eq!(
        sanitized_packet_session["outbound"],
        json!(product_log_field_value(&packet_session["outbound"]))
    );
    assert_eq!(
        sanitized_packet_session["packetSemantics"],
        json!(product_log_field_value(&packet_session["packetSemantics"]))
    );
    assert_eq!(
        sanitized_packet_session["sourceDisplay"],
        json!(normalized_source_display)
    );
}

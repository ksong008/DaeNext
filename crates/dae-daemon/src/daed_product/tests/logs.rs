use super::*;
#[test]
pub(crate) fn logs_filter_level_all_case_insensitive_query_and_sse_event_name() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
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
            fs::metadata(dir.join(PRODUCT_LOG_DIR))
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
        runtime: Arc::new(ProductRuntimeManager::new()),
        latency_jobs: Arc::new(LatencyJobManager::default()),
        http_metrics: Arc::new(ProductHttpMetrics::default()),
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
pub(crate) fn log_store_initialization_repairs_existing_jsonl_permissions() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    fs::create_dir_all(dir.join(PRODUCT_LOG_DIR)).unwrap();
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
            fs::metadata(dir.join(PRODUCT_LOG_DIR))
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
    append_lifecycle_log_for_config(
        &dir,
        &state,
        "info",
        "[Reload] Received signal reload request",
    )
    .unwrap();

    refresh_log_policy_and_reset_runtime_cycle_logs(&dir, &state, None).unwrap();

    let logs = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
    let items = logs["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{logs}");
    assert_eq!(items[0]["message"], json!("[Startup] Finished"));
    assert_eq!(items[0]["fields"]["lifecycle"], json!("startup"));
    assert_eq!(
        items[1]["message"],
        json!("[Reload] Received signal reload request")
    );
    assert_eq!(items[1]["fields"]["lifecycle"], json!("reload"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn resident_events_are_bridged_to_product_logs_with_runtime_level_filter() {
    const FLOW_DIAL_TARGET: &str = "flow-dial-target";
    const FLOW_FAILED_SOURCE: &str = "flow-failed-source";
    const FLOW_FAILED_TARGET: &str = "flow-failed-target";
    const FLOW_OUTBOUND: &str = "flow-outbound";
    const FLOW_POLICY: &str = "fixed";
    const FLOW_DIALER: &str = "flow-dialer";
    const FLOW_PID: u32 = 1;
    const FLOW_DSCP: u8 = 2;
    const FLOW_PROCESS: &str = "flow-process";
    const FLOW_MAC: &str = "flow-mac";
    let mapped_socket = |octets: [u8; 4], port: u16| {
        let mut mapped = [0_u8; 16];
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        mapped[12..16].copy_from_slice(&octets);
        std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(mapped)), port)
            .to_string()
    };
    let ipv4_socket = |octets: [u8; 4], port: u16| {
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)), port)
            .to_string()
    };
    let flow_source = mapped_socket([192, 0, 2, 10], 49480);
    let flow_source_display = ipv4_socket([192, 0, 2, 10], 49480);
    let flow_destination = mapped_socket([198, 51, 100, 50], 5222);
    let flow_destination_display = ipv4_socket([198, 51, 100, 50], 5222);
    let udp_flow_source = mapped_socket([192, 0, 2, 20], 61306);
    let udp_flow_source_display = ipv4_socket([192, 0, 2, 20], 61306);
    let udp_flow_destination = mapped_socket([203, 0, 113, 209], 443);
    let udp_flow_destination_display = ipv4_socket([203, 0, 113, 209], 443);

    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
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
            "error": "sample failure"
        }),
    )
    .unwrap();
    append_resident_event_product_log(
        &dir,
        &state,
        &json!({"event": "tcp_accept_failed", "error": "accept failure"}),
    )
    .unwrap();

    let all = list_logs_value(&dir, &state, Some("all"), None, 500).unwrap();
    let items = all["items"].as_array().unwrap();
    assert_eq!(items.len(), 3, "{all}");
    assert_eq!(
        items[0]["message"],
        json!("resident dataplane tcp worker started")
    );
    assert_eq!(items[0]["level"], json!("info"));
    assert_eq!(items[0]["fields"]["event"], json!("tcp_worker_started"));
    assert_eq!(items[0]["fields"]["proxy_count"], json!("2"));
    assert_eq!(
        items[1]["message"],
        json!(format!(
            "{FLOW_FAILED_SOURCE} <-> {FLOW_FAILED_TARGET} failed"
        ))
    );
    assert_eq!(items[1]["level"], json!("warn"));
    assert_eq!(items[1]["fields"]["error"], json!("sample failure"));
    assert_eq!(items[1]["fields"]["network"], json!("tcp4"));
    assert!(items[1]["fields"].get("event").is_none());
    assert_eq!(
        items[2]["message"],
        json!("resident dataplane tcp accept failed")
    );
    assert_eq!(items[2]["level"], json!("warn"));
    assert_eq!(items[2]["fields"]["error"], json!("accept failure"));

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
            "network": "tcp6",
            "bytes_client_to_proxy": 256,
            "node_tag": FLOW_DIALER,
            "proxy_group": FLOW_OUTBOUND,
            "group_policy": FLOW_POLICY,
            "pid": FLOW_PID,
            "dscp": FLOW_DSCP,
            "pname": FLOW_PROCESS,
            "mac": FLOW_MAC,
            "executionDescriptor": {
                "schemaVersion": 1,
                "executor": "tcp-relay",
                "capability": "stream-transport",
                "network": "tcp",
                "securityUnderlay": "boringssl",
                "protocolFraming": "vless",
                "transportUnderlay": "tcp",
                "graphId": "resident-graph:tcp-sample"
            },
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
            "network": "udp6",
            "request_len": 64,
            "response_len": 128,
            "executionDescriptor": {
                "schemaVersion": 1,
                "executor": "packet-relay",
                "capability": "packet-transport",
                "network": "udp",
                "packetSemantics": "xudp",
                "securityUnderlay": "boringssl",
                "protocolFraming": "vless",
                "transportUnderlay": "tcp",
                "graphId": "resident-graph:udp-sample"
            },
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
    assert_eq!(tcp["fields"]["network"], json!("tcp4"));
    assert_eq!(tcp["fields"]["outbound"], json!(FLOW_OUTBOUND));
    assert_eq!(tcp["fields"]["policy"], json!(FLOW_POLICY));
    assert_eq!(tcp["fields"]["dialer"], json!(FLOW_DIALER));
    assert_eq!(tcp["fields"]["ip"], json!(flow_destination_display));
    assert_eq!(tcp["fields"]["sniffed"], json!(""));
    assert_eq!(tcp["fields"]["pid"], json!(FLOW_PID.to_string()));
    assert_eq!(tcp["fields"]["dscp"], json!(FLOW_DSCP.to_string()));
    assert_eq!(tcp["fields"]["pname"], json!(FLOW_PROCESS));
    assert_eq!(tcp["fields"]["mac"], json!(FLOW_MAC));
    assert_eq!(tcp["fields"]["executor"], json!("tcp-relay"));
    assert_eq!(tcp["fields"]["capability"], json!("stream-transport"));
    assert_eq!(tcp["fields"]["securityUnderlay"], json!("boringssl"));
    assert_eq!(tcp["fields"]["protocolFraming"], json!("vless"));
    assert_eq!(tcp["fields"]["transportUnderlay"], json!("tcp"));
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
    assert_eq!(items[0]["fields"]["network"], json!("udp4"));
    assert_eq!(
        items[0]["fields"]["ip"],
        json!(udp_flow_destination_display)
    );
    assert_eq!(items[0]["fields"]["executor"], json!("packet-relay"));
    assert_eq!(items[0]["fields"]["capability"], json!("packet-transport"));
    assert_eq!(items[0]["fields"]["packetSemantics"], json!("xudp"));
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
    let mut mapped = [0_u8; 16];
    let source_octets = [192, 0, 2, 30];
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12..16].copy_from_slice(&source_octets);
    let source_display = std::net::SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(mapped)),
        61306,
    )
    .to_string();
    let normalized_source_display = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::from(source_octets)),
        61306,
    )
    .to_string();
    let fields = resident_event_product_log_fields(
        "udp_session_stopped",
        &json!({
            "event": "udp_session_stopped",
            "graphId": "resident-graph:internal",
            "packetSession": {
                "schemaVersion": 1,
                "manager": "resident-udp-session-manager",
                "graphId": "resident-graph:internal",
                "graphIdentityHash": "sha256:internal",
                "graphLinkHash": "sha256:internal-link",
                "outbound": "proxy",
                "packetSemantics": "xudp",
                "sourceDisplay": &source_display
            }
        }),
    );

    assert!(!fields.contains_key("graphId"));
    let packet_session = fields["packetSession"].as_str();
    assert!(!packet_session.contains("graphId"), "{packet_session}");
    assert!(
        !packet_session.contains("graphIdentityHash"),
        "{packet_session}"
    );
    assert!(
        !packet_session.contains("graphLinkHash"),
        "{packet_session}"
    );
    assert!(packet_session.contains("\"outbound\":\"proxy\""));
    assert!(packet_session.contains("\"packetSemantics\":\"xudp\""));
    assert!(packet_session.contains(&normalized_source_display));
    assert!(!packet_session.contains("ffff"), "{packet_session}");
}

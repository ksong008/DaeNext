use super::super::super::*;
use super::*;
#[test]
pub(crate) fn storage_paths_match_first_batch_contract() {
    let mut storage = "{}".to_owned();
    let paths = vec!["ui.sidebar".to_owned()];
    let values = vec!["open".to_owned()];
    assert_eq!(set_json_storage(&mut storage, &paths, &values).unwrap(), 1);
    assert_eq!(
        query_json_storage(&storage, &paths),
        vec!["open".to_owned()]
    );
    assert_eq!(remove_json_storage(&mut storage, &paths).unwrap(), 1);
    assert_eq!(query_json_storage(&storage, &paths), vec![String::new()]);
}

#[test]
pub(crate) fn jwt_roundtrip_uses_user_secret() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    let token = create_user(&state, "admin", "abc123").unwrap();
    let user = verify_token(&state, &token).unwrap().unwrap();
    assert_eq!(user.username, "admin");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn service_contract_declares_daed_db_with_final_go_free_blocked() {
    let report = daed_service_contract("test");
    assert_eq!(
        report["primary_state_store"].as_str().unwrap(),
        PRIMARY_STATE_STORE
    );
    assert_eq!(
        report["protected_rollback_state_store"].as_str().unwrap(),
        PROTECTED_ROLLBACK_STATE_STORE
    );
    assert!(
        !report["rust_daed_writes_wing_db_by_default"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["go_free_live_host_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["go_free_product_chain_ready"].as_bool().unwrap());
    assert!(
        !report["go_free_product_chain_remaining_work"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
pub(crate) fn product_package_reports_runtime_memory_defaults() {
    let contract = daed_service_contract("test");
    let defaults = &contract["rust_product_runtime_defaults"];
    assert_eq!(
        defaults["allocator"]["profile"].as_str().unwrap(),
        allocator_profile()
    );
    assert_eq!(
        defaults["http"]["queue"]["env"].as_str().unwrap(),
        PRODUCT_HTTP_QUEUE_ENV
    );
    assert_eq!(
        defaults["residentDataplane"]["tcpFlow"]["stackBytes"]["env"]
            .as_str()
            .unwrap(),
        "DAE_RESIDENT_TCP_FLOW_STACK_BYTES"
    );

    let manifest = product_package_manifest();
    assert_eq!(
        manifest["runtime"]["defaults"]["http"]["workerStackBytes"]["default"]
            .as_u64()
            .unwrap(),
        PRODUCT_HTTP_WORKER_STACK_BYTES_DEFAULT as u64
    );

    let unit = systemd_unit_text();
    assert!(unit.contains("Environment=\"DAED_HTTP_QUEUE=256\""));
    assert!(unit.contains("Environment=\"DAE_RESIDENT_UDP_PACKET_WORKERS=64\""));
    assert!(unit.contains("DAED_HTTP_WORKERS unset uses available_parallelism"));
}

#[test]
pub(crate) fn parsed_global_reads_dae_text_and_json_storage_shapes() {
    let text = r#"
global {
  tproxy_port:"12345"
  tproxy_port_protect:"true"
  so_mark_from_dae:"7"
  lan_interface:"enp1s0"
  wan_interface:"auto,enp1s0"
  tcp_check_url:"http://cp.cloudflare.com,1.1.1.1"
  udp_check_dns:"dns.google.com:53,8.8.8.8"
  dial_mode:"domain++"
  fallback_resolver:"8.8.8.8:53"
  auto_config_kernel_parameter:"true"
  bandwidth_max_tx:"200 mbps"
}
"#;
    let parsed = normalize_global_value(Some(text));
    assert_eq!(parsed["tproxyPort"], json!(12345));
    assert_eq!(parsed["tproxyPortProtect"], json!(true));
    assert_eq!(parsed["soMarkFromDae"], json!(7));
    assert_eq!(parsed["lanInterface"], json!(["enp1s0"]));
    assert_eq!(parsed["wanInterface"], json!(["auto", "enp1s0"]));
    assert_eq!(
        parsed["tcpCheckUrl"],
        json!(["http://cp.cloudflare.com", "1.1.1.1"])
    );
    assert_eq!(parsed["dialMode"], json!("domain++"));
    assert_eq!(parsed["fallbackResolver"], json!("8.8.8.8:53"));
    assert_eq!(parsed["autoConfigKernelParameter"], json!(true));
    assert_eq!(parsed["bandwidthMaxTx"], json!("200 mbps"));

    let parsed = normalize_global_value(Some(
        r#"{"tproxyPort":12345,"wanInterface":["auto"],"dialMode":"domain"}"#,
    ));
    assert_eq!(parsed["tproxyPort"], json!(12345));
    assert_eq!(parsed["wanInterface"], json!(["auto"]));
    assert_eq!(parsed["dialMode"], json!("domain"));
}

#[test]
pub(crate) fn parsed_global_request_renders_dae_global_text_for_webui_fields() {
    let parsed_global = json!({
        "logLevel": "debug",
        "tproxyPort": 12345,
        "tproxyPortProtect": false,
        "pprofPort": 0,
        "soMarkFromDae": 7,
        "allowInsecure": false,
        "checkInterval": "10s",
        "checkTolerance": "500ms",
        "sniffingTimeout": "250ms",
        "lanInterface": ["br-lan"],
        "wanInterface": ["auto", "eth0"],
        "udpCheckDns": ["dns.google:53", "8.8.8.8"],
        "tcpCheckUrl": ["http://cp.cloudflare.com/generate_204", "1.1.1.1"],
        "dialMode": "domain++",
        "tcpCheckHttpMethod": "GET",
        "disableWaitingNetwork": true,
        "autoConfigKernelParameter": true,
        "tlsImplementation": "tls",
        "utlsImitate": "chrome_auto",
        "fallbackResolver": "8.8.8.8:53",
        "mptcp": true,
        "enableLocalTcpFastRedirect": true,
        "bandwidthMaxTx": "200 mbps",
        "bandwidthMaxRx": "1 gbps"
    });
    let rendered = render_global_config_text(&parsed_global);
    assert!(rendered.starts_with("global {\n"));
    assert!(rendered.contains("tcp_check_http_method:'GET'"));
    assert!(rendered.contains("tproxy_port_protect:'false'"));
    assert!(rendered.contains("wan_interface:'auto,eth0'"));
    assert!(rendered.contains("enable_local_tcp_fast_redirect:'true'"));
    assert!(!rendered.trim_start().starts_with('{'));

    let sections = parse_config(&format!("{rendered}\nrouting {{ fallback: direct }}\n")).unwrap();
    let config = build_config(&sections).unwrap();
    assert_eq!(config.global.tcp_check_http_method, "GET");
    assert_eq!(
        config.global.tcp_check_url[0],
        "http://cp.cloudflare.com/generate_204"
    );
    assert_eq!(config.global.tcp_check_url[1], "1.1.1.1");
    assert_eq!(config.global.tproxy_port, 12345);
    assert!(!config.global.tproxy_port_protect);
    assert!(config.global.disable_waiting_network);
    assert!(config.global.enable_local_tcp_fast_redirect);

    let body = json!({
        "global": "global { tcp_check_http_method:'HEAD' }",
        "parsedGlobal": parsed_global,
    });
    let stored = section_request_value(SectionKind::Config, &body);
    assert!(stored.contains("tcp_check_http_method:'GET'"));
    assert!(!stored.contains("tcp_check_http_method:'HEAD'"));
}

#[test]
fn materialized_global_text_converts_legacy_json_storage() {
    let raw = r#"{"tcpCheckHttpMethod":"GET","tcpCheckUrl":["http://check.example","203.0.113.1"],"wanInterface":["auto"],"tproxyPort":12345}"#;
    let rendered = display_global_config_text(raw);
    assert!(rendered.starts_with("global {\n"));
    assert!(rendered.contains("tcp_check_http_method:'GET'"));
    assert!(rendered.contains("tcp_check_url:'http://check.example,203.0.113.1'"));
    assert!(!rendered.contains("allow_insecure:'false'"));
}

#[test]
fn runtime_traffic_stats_read_resident_event_bytes() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    fs::create_dir_all(&dir).unwrap();
    let event_file = dir.join("events.jsonl");
    let now = unix_now();
    fs::write(
            &event_file,
            format!(
                "{{\"event\":\"tcp_connection_finished\",\"timestampUnix\":{now},\"bytes_client_to_proxy\":100,\"bytes_proxy_to_client\":200}}\n{{\"event\":\"udp_packet_finished\",\"timestampUnix\":{now},\"request_len\":30,\"response_len\":40}}\n"
            ),
        )
        .unwrap();
    let runtime = json!({
        "residentDataplane": {
            "event_file": path_string(&event_file)
        }
    });
    let stats = resident_runtime_traffic_stats(&runtime, 60, 10);
    assert_eq!(stats.upload_total, 130);
    assert_eq!(stats.download_total, 240);
    assert_eq!(stats.active_connections, 1);
    assert_eq!(stats.udp_sessions, 1);
    assert_eq!(stats.samples.len(), 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn runtime_traffic_stats_event_file_cache_reads_new_tail() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    fs::create_dir_all(&dir).unwrap();
    let event_file = dir.join("events.jsonl");
    let now = unix_now();
    fs::write(
            &event_file,
            format!(
                "{{\"event\":\"tcp_connection_finished\",\"timestampUnix\":{now},\"bytes_client_to_proxy\":100,\"bytes_proxy_to_client\":200}}\n"
            ),
        )
        .unwrap();
    let runtime = json!({
        "residentDataplane": {
            "event_file": path_string(&event_file)
        }
    });

    let first = resident_runtime_traffic_stats(&runtime, 60, 10);
    assert_eq!(first.upload_total, 100);
    let offset_after_first = RUNTIME_TRAFFIC_EVENT_FILE_CACHE
        .get_or_init(|| Mutex::new(RuntimeTrafficEventFileCache::default()))
        .lock()
        .unwrap()
        .offset;
    let second = resident_runtime_traffic_stats(&runtime, 60, 10);
    assert_eq!(second.upload_total, 100);
    assert_eq!(
        RUNTIME_TRAFFIC_EVENT_FILE_CACHE
            .get_or_init(|| Mutex::new(RuntimeTrafficEventFileCache::default()))
            .lock()
            .unwrap()
            .offset,
        offset_after_first
    );

    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&event_file)
        .unwrap();
    writeln!(
            file,
            "{{\"event\":\"udp_packet_finished\",\"timestampUnix\":{now},\"request_len\":30,\"response_len\":40}}"
        )
        .unwrap();
    let third = resident_runtime_traffic_stats(&runtime, 60, 10);
    assert_eq!(third.upload_total, 130);
    assert_eq!(third.download_total, 240);
    assert_eq!(third.udp_sessions, 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn runtime_traffic_stats_prefer_live_resident_metrics() {
    *LAST_RUNTIME_TRAFFIC_TOTAL_SAMPLE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap() = None;
    RUNTIME_TRAFFIC_RATE_SAMPLES
        .get_or_init(|| Mutex::new(VecDeque::new()))
        .lock()
        .unwrap()
        .clear();

    let runtime = json!({
        "residentDataplane": {
            "metrics": {
                "uploadTotal": 100,
                "downloadTotal": 200,
                "activeTcpConnections": 3,
                "activeUdpSessions": 2
            }
        }
    });
    let first = resident_runtime_traffic_stats(&runtime, 60, 10);
    assert_eq!(first.upload_total, 100);
    assert_eq!(first.download_total, 200);
    assert_eq!(first.active_connections, 3);
    assert_eq!(first.udp_sessions, 2);

    thread::sleep(Duration::from_millis(10));
    let runtime = json!({
        "residentDataplane": {
            "metrics": {
                "uploadTotal": 300,
                "downloadTotal": 500,
                "activeTcpConnections": 1,
                "activeUdpSessions": 0
            }
        }
    });
    let second = resident_runtime_traffic_stats(&runtime, 60, 10);
    assert!(second.upload_rate > 0);
    assert!(second.download_rate > 0);
    assert_eq!(second.active_connections, 1);
    assert!(!second.samples.is_empty());
}

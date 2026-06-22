use super::*;
use base64::Engine;
#[test]
pub(crate) fn storage_paths_match_runtime_contract() {
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

#[cfg(unix)]
#[test]
pub(crate) fn state_schema_initialization_sets_private_file_and_dir_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();

    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o750
    );
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o640
    );
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
pub(crate) fn state_schema_open_repairs_existing_wide_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o666)).unwrap();

    let conn = open_state_connection(&state).unwrap();
    drop(conn);

    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o750
    );
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o640
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn state_connections_wait_briefly_for_sqlite_busy_locks() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();

    let conn = open_state_connection(&state).unwrap();
    let busy_timeout_ms: i64 = conn
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .unwrap();
    assert_eq!(busy_timeout_ms, STATE_DB_BUSY_TIMEOUT.as_millis() as i64);

    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn section_summary_lists_keep_only_lightweight_fields() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    conn.execute(
        "INSERT INTO configs(id, name, global, selected, version)
         VALUES(1, 'default', 'global { tproxy_port: 12345 }', 1, 7)",
        [],
    )
    .unwrap();
    drop(conn);

    let value = list_section_summaries_value(&state, SectionKind::Config).unwrap();
    let item = &value["items"][0];
    assert_eq!(item["id"], json!(1));
    assert_eq!(item["name"], json!("default"));
    assert_eq!(item["selected"], json!(true));
    assert_eq!(item["version"], json!(7));
    assert_eq!(item["parseStatus"], json!("ok"));
    assert!(item.get("global").is_none(), "{item}");
    assert!(item.get("parsedGlobal").is_none(), "{item}");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn jwt_roundtrip_uses_user_secret() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    let token = create_user(&state, "admin", "abc12345").unwrap();
    let user = verify_token(&state, &token).unwrap().unwrap();
    assert_eq!(user.username, "admin");
    assert!(user.password_hash.starts_with("$argon2id$"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn initial_user_creation_is_single_winner_under_concurrency() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();

    let thread_count = 4;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(thread_count));
    let mut handles = Vec::new();
    for index in 0..thread_count {
        let state = state.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            create_user(&state, &format!("admin{index}"), "abc12345")
        }));
    }

    let successes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .filter(Result::is_ok)
        .count();
    assert_eq!(successes, 1);
    assert_eq!(user_count(&state).unwrap(), 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn legacy_password_hash_migrates_to_argon2id_after_successful_login() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    let secret = random_secret_hex().unwrap();
    let legacy_hash = legacy_password_hash_for_test(secret.as_bytes(), "abc12345");
    conn.execute(
        "INSERT INTO users(username, password_hash, jwt_secret, json_storage) VALUES(?1, ?2, ?3, '{}')",
        params!["admin", legacy_hash, secret],
    )
    .unwrap();
    drop(conn);

    let token = issue_token(&state, "admin", "abc12345").unwrap();
    assert!(verify_token(&state, &token).unwrap().is_some());
    let migrated = load_user_by_username(&state, "admin").unwrap().unwrap();
    assert!(migrated.password_hash.starts_with("$argon2id$"));
    assert!(verify_password_hash(
        &migrated.password_hash,
        migrated.jwt_secret.as_bytes(),
        "abc12345"
    ));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn token_auth_prefers_bearer_header_over_event_query_token() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    let token = create_user(&state, "admin", "abc12345").unwrap();
    let app = product_test_app(&dir, &state);
    let request = token_request(
        "GET",
        "/api/events/runtime",
        Some(&token),
        Some("not-a-token"),
    );

    let user = authenticate_request(&app, &request).unwrap();
    assert_eq!(user.username, "admin");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn token_query_auth_is_limited_to_event_streams() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    let token = create_user(&state, "admin", "abc12345").unwrap();
    let app = product_test_app(&dir, &state);

    for path in ["/api/events/runtime", "/api/events/logs"] {
        let request = token_request("GET", path, None, Some(&token));
        assert!(
            authenticate_request(&app, &request).is_some(),
            "query token should authenticate {path}"
        );
    }

    let request = token_request("GET", "/api/runtime/overview", None, Some(&token));
    assert!(authenticate_request(&app, &request).is_none());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn token_verifier_rejects_expired_wrong_alg_and_bad_signature() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    let token = create_user(&state, "admin", "abc12345").unwrap();
    let user = load_user_by_username(&state, "admin").unwrap().unwrap();

    let expired = signed_test_token(
        &user,
        "HS256",
        json!({"role": "admin", "sub": "admin", "exp": unix_now().saturating_sub(1)}),
    );
    assert!(verify_token(&state, &expired).unwrap().is_none());

    let wrong_alg = signed_test_token(
        &user,
        "HS512",
        json!({"role": "admin", "sub": "admin", "exp": unix_now() + 300}),
    );
    assert!(verify_token(&state, &wrong_alg).unwrap().is_none());

    let bad_signature = format!("{token}x");
    assert!(verify_token(&state, &bad_signature).unwrap().is_none());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn password_update_rotates_secret_and_invalidates_old_token() {
    let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
    let state = dir.join("daed.db");
    let old_token = create_user(&state, "admin", "abc12345").unwrap();
    let app = product_test_app(&dir, &state);
    let mut headers = HashMap::new();
    headers.insert("authorization".to_owned(), format!("Bearer {old_token}"));
    let request = HttpRequest {
        method: "POST".to_owned(),
        path: "/api/user/me/password".to_owned(),
        query: HashMap::new(),
        headers,
        body: br#"{"currentPassword":"abc12345","newPassword":"def45678"}"#.to_vec(),
    };

    let response = route_request(&app, &request);
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    let new_token = body["token"].as_str().unwrap();
    assert!(verify_token(&state, &old_token).unwrap().is_none());
    assert_eq!(
        verify_token(&state, new_token).unwrap().unwrap().username,
        "admin"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn cors_origin_policy_allows_only_local_origins() {
    assert_eq!(
        allowed_cors_origin_value("http://localhost:5173"),
        Some("http://localhost:5173")
    );
    assert_eq!(
        allowed_cors_origin_value("http://127.0.0.1:2023"),
        Some("http://127.0.0.1:2023")
    );
    assert_eq!(
        allowed_cors_origin_value("http://[::1]:2023"),
        Some("http://[::1]:2023")
    );
    assert!(allowed_cors_origin_value("https://fixture.invalid").is_none());
    assert!(allowed_cors_origin_value("http://localhost:2023\r\nX-Test: 1").is_none());
}

#[test]
pub(crate) fn resetpass_recovery_password_uses_account_password_policy() {
    for _ in 0..16 {
        let password = random_recovery_password().unwrap();
        assert_eq!(password.len(), 12);
        assert!(password.chars().any(char::is_alphabetic), "{password}");
        assert!(password.chars().any(|ch| ch.is_ascii_digit()), "{password}");
        assert!(
            password.chars().all(|ch| ch.is_ascii_alphanumeric()),
            "{password}"
        );
    }
}

fn product_test_app(dir: &Path, state: &Path) -> AppState {
    AppState {
        config_dir: dir.to_owned(),
        state: state.to_owned(),
        web_root: dir.to_owned(),
        api_only: true,
        runtime: Arc::new(ProductRuntimeManager::new()),
        latency_jobs: Arc::new(LatencyJobManager::default()),
        http_metrics: Arc::new(ProductHttpMetrics::default()),
    }
}

fn token_request(
    method: &str,
    path: &str,
    bearer_token: Option<&str>,
    query_token: Option<&str>,
) -> HttpRequest {
    let mut headers = HashMap::new();
    if let Some(token) = bearer_token {
        headers.insert("authorization".to_owned(), format!("Bearer {token}"));
    }
    let mut query = HashMap::new();
    if let Some(token) = query_token {
        query.insert("access_token".to_owned(), vec![token.to_owned()]);
    }
    HttpRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query,
        headers,
        body: Vec::new(),
    }
}

fn signed_test_token(user: &UserRecord, alg: &str, payload: Value) -> String {
    let header = json!({"alg": alg, "typ": "JWT"}).to_string();
    let encoded_header = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    let signature = hmac_sha256(user.jwt_secret.as_bytes(), signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

#[test]
pub(crate) fn service_contract_declares_daed_db_with_production_blocked() {
    let report = daed_service_contract("test");
    assert_eq!(
        report["primary_state_store"].as_str().unwrap(),
        PRIMARY_STATE_STORE
    );
    assert_eq!(
        report["legacy_import_state_store"].as_str().unwrap(),
        LEGACY_IMPORT_STATE_STORE
    );
    assert!(
        !report["rust_daed_writes_wing_db_by_default"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["production_live_host_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["runtime_state_ready"].as_bool().unwrap());
    assert!(
        !report["runtime_state_remaining_work"]
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
    assert!(
        defaults["allocator"]["jemallocPolicy"]["default"]
            .as_str()
            .unwrap()
            .contains("percpu_arena:percpu")
    );
    assert!(
        defaults["allocator"]["jemallocPolicy"]["default"]
            .as_str()
            .unwrap()
            .contains("dirty_decay_ms:30000")
    );
    assert!(
        defaults["allocator"]["jemallocPolicy"]["default"]
            .as_str()
            .unwrap()
            .contains("muzzy_decay_ms:30000")
    );
    assert_eq!(
        defaults["allocator"]["jemallocPolicy"]["env"]
            .as_str()
            .unwrap(),
        PRODUCT_JEMALLOC_CONF_ENV
    );
    assert_eq!(
        defaults["allocator"]["jemallocPolicy"]["runtimeOverride"],
        json!(true)
    );
    assert_eq!(
        defaults["allocator"]["jemallocPolicy"]["serviceUnitSetsEnv"],
        json!(false)
    );
    assert_eq!(
        defaults["allocator"]["jemallocPolicy"]["buildEnv"]
            .as_str()
            .unwrap(),
        PRODUCT_JEMALLOC_BUILD_CONF_ENV
    );
    assert_eq!(
        defaults["allocator"]["jemallocPolicy"]["defaultSource"]
            .as_str()
            .unwrap(),
        PRODUCT_JEMALLOC_BUILD_CONF_SOURCE
    );
    let cargo_config =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.cargo/config.toml"))
            .unwrap();
    assert!(cargo_config.contains(PRODUCT_JEMALLOC_BUILD_CONF_ENV));
    assert!(cargo_config.contains(PRODUCT_JEMALLOC_CONF_DEFAULT));
    assert!(cargo_config.contains("force = false"));
    assert_eq!(
        defaults["allocator"]["reclaim"]["reloadCompleted"],
        json!(true)
    );
    assert_eq!(
        defaults["allocator"]["reclaim"]["hotPathPeriodicPurge"],
        json!(false)
    );
    assert_eq!(
        defaults["allocator"]["reclaim"]["idleMemoryPressure"]["idleDetection"],
        json!("traffic-rate-only")
    );
    assert_eq!(
        defaults["allocator"]["reclaim"]["idleMemoryPressure"]["sessionCountGate"],
        json!(false)
    );
    assert_eq!(
        defaults["http"]["queue"]["env"].as_str().unwrap(),
        PRODUCT_HTTP_QUEUE_ENV
    );
    assert_eq!(
        defaults["http"]["profile"]["env"].as_str().unwrap(),
        PRODUCT_HTTP_PROFILE_ENV
    );
    assert_eq!(
        defaults["http"]["profile"]["default"].as_str().unwrap(),
        PRODUCT_HTTP_PROFILE_STANDARD
    );
    assert_eq!(
        defaults["http"]["profile"]["lowMemory"]["queueDefault"],
        json!(PRODUCT_HTTP_LOW_MEMORY_QUEUE_DEFAULT)
    );
    assert_eq!(
        defaults["residentDataplane"]["tcpFlow"]["stackBytes"]["env"]
            .as_str()
            .unwrap(),
        "RESIDENT_TCP_FLOW_STACK_BYTES"
    );
    assert_eq!(
        defaults["residentDataplane"]["udpSessions"]["queueDepth"]["default"],
        json!(128)
    );

    let manifest = product_package_manifest();
    assert_eq!(
        manifest["runtime"]["defaults"]["http"]["workerStackBytes"]["default"]
            .as_u64()
            .unwrap(),
        PRODUCT_HTTP_WORKER_STACK_BYTES_DEFAULT as u64
    );

    let unit = systemd_unit_text();
    assert!(unit.contains("Description=daed is a integration solution of dae, API and UI."));
    assert!(unit.contains("ExecStart=/usr/bin/daed run -c /etc/daed/"));
    assert!(unit.contains("Restart=on-abnormal"));
    assert!(!unit.contains("Environment="));
    assert!(!unit.contains("MALLOC_CONF"));
    assert!(!unit.contains("ALLOCATOR_IDLE_RECLAIM"));
    assert!(!unit.contains("RESIDENT_UDP_SESSION_QUEUE_DEPTH"));
    assert!(!unit.contains("ALLOCATOR_IDLE_RECLAIM_REQUIRE_UDP_IDLE"));
    assert!(!unit.contains("ALLOCATOR_IDLE_RECLAIM_REQUIRE_TCP_IDLE"));
    let entrypoint = docker_entrypoint_text();
    assert!(entrypoint.contains("${PRODUCT_LISTEN:-${DAED_LISTEN:-0.0.0.0:2023}}"));

    let defaults_text = defaults.to_string();
    assert!(!defaults_text.contains("\"legacyEnv\""));
    assert!(!defaults_text.contains("legacyPacketStackBytes"));
    assert!(!defaults_text.contains("RESIDENT_UDP_PACKET_STACK_BYTES"));
    assert!(!defaults_text.contains("DAE_"));
    assert!(!defaults_text.contains("DAED_"));
}

#[test]
pub(crate) fn product_http_low_memory_profile_only_changes_unconfigured_defaults() {
    let standard = ProductHttpWorkerConfig::from_config_with_profile(
        None,
        ProductHttpProfile::Standard,
        "test",
    );
    assert_eq!(standard.profile.name(), PRODUCT_HTTP_PROFILE_STANDARD);
    assert!(
        (PRODUCT_HTTP_WORKER_DEFAULT_MIN..=PRODUCT_HTTP_WORKER_DEFAULT_MAX)
            .contains(&standard.worker_count)
    );
    assert_eq!(standard.queue_capacity, PRODUCT_HTTP_QUEUE_DEFAULT);
    assert_eq!(
        standard.worker_stack_bytes,
        PRODUCT_HTTP_WORKER_STACK_BYTES_DEFAULT
    );
    assert_eq!(standard.worker_count_source, "default");

    let low_memory = ProductHttpWorkerConfig::from_config_with_profile(
        None,
        ProductHttpProfile::LowMemory,
        "test",
    );
    assert_eq!(low_memory.profile.name(), PRODUCT_HTTP_PROFILE_LOW_MEMORY);
    assert!(
        (PRODUCT_HTTP_LOW_MEMORY_WORKER_DEFAULT_MIN..=PRODUCT_HTTP_LOW_MEMORY_WORKER_DEFAULT_MAX)
            .contains(&low_memory.worker_count)
    );
    assert!(low_memory.worker_count <= standard.worker_count);
    assert_eq!(
        low_memory.queue_capacity,
        PRODUCT_HTTP_LOW_MEMORY_QUEUE_DEFAULT
    );
    assert_eq!(
        low_memory.worker_stack_bytes,
        PRODUCT_HTTP_LOW_MEMORY_WORKER_STACK_BYTES_DEFAULT
    );
    assert_eq!(low_memory.worker_count_source, "default");

    let sections = parse_config(
        "global { http_workers:'9' http_queue:'512' http_worker_stack_bytes:'1048576' }\n\
         routing { fallback: direct }\n",
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let configured = ProductHttpWorkerConfig::from_config_with_profile(
        Some(&config),
        ProductHttpProfile::LowMemory,
        "test",
    );
    assert_eq!(configured.worker_count, 9);
    assert_eq!(configured.queue_capacity, 512);
    assert_eq!(configured.worker_stack_bytes, 1_048_576);
    assert_eq!(configured.worker_count_source, "config");

    let env_configured = ProductHttpWorkerConfig::from_config_with_profile_and_env(
        Some(&config),
        ProductHttpProfile::LowMemory,
        "test",
        &|name| match name {
            PRODUCT_HTTP_WORKERS_ENV => Some("3".to_owned()),
            PRODUCT_HTTP_QUEUE_ENV => Some("64".to_owned()),
            PRODUCT_HTTP_WORKER_STACK_BYTES_ENV => Some("786432".to_owned()),
            _ => None,
        },
    );
    assert_eq!(env_configured.worker_count, 3);
    assert_eq!(env_configured.queue_capacity, 64);
    assert_eq!(env_configured.worker_stack_bytes, 786_432);
    assert_eq!(env_configured.worker_count_source, "env");
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
  tcp_check_url:"http://localhost,127.0.0.1"
  udp_check_dns:"localhost:53"
  dial_mode:"domain++"
  fallback_resolver:"127.0.0.1:53"
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
        json!(["http://localhost", "127.0.0.1"])
    );
    assert_eq!(parsed["dialMode"], json!("domain++"));
    assert_eq!(parsed["fallbackResolver"], json!("127.0.0.1:53"));
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
        "udpCheckDns": ["localhost:8053", "127.0.0.1"],
        "tcpCheckUrl": ["http://localhost/generate_204", "127.0.0.1"],
        "dialMode": "domain++",
        "tcpCheckHttpMethod": "GET",
        "disableWaitingNetwork": true,
        "autoConfigKernelParameter": true,
        "tlsImplementation": "tls",
        "utlsImitate": "chrome_auto",
        "fallbackResolver": "127.0.0.1:53",
        "mptcp": true,
        "enableLocalTcpFastRedirect": true,
        "bandwidthMaxTx": "200 mbps",
        "bandwidthMaxRx": "1 gbps",
        "residentUdpSessionLimit": 128,
        "residentUdpSessionQueueDepth": 64,
        "residentTcpFlowStackBytes": 1048576,
        "residentEventQueueDepth": 8192,
        "residentManualProbeConcurrency": 12,
        "residentHealthCheckConcurrency": 4,
        "httpQueue": 512,
        "httpWorkers": 6,
        "httpWorkerStackBytes": 1048576,
        "allocatorIdleReclaimEnabled": true,
        "allocatorIdleReclaimSampleInterval": "2m",
        "allocatorIdleReclaimMinInterval": "10m",
        "allocatorIdleReclaimLowTrafficDuration": "5m",
        "allocatorIdleReclaimPressureThresholdBytes": 67108864,
        "allocatorIdleReclaimMaxTrafficRateBytesPerSecond": 65536
    });
    let rendered = render_global_config_text(&parsed_global);
    assert!(rendered.starts_with("global {\n"));
    assert!(rendered.contains("tcp_check_http_method:'GET'"));
    assert!(rendered.contains("tproxy_port_protect:'false'"));
    assert!(rendered.contains("wan_interface:'auto,eth0'"));
    assert!(rendered.contains("enable_local_tcp_fast_redirect:'true'"));
    assert!(rendered.contains("resident_udp_session_limit:'128'"));
    assert!(rendered.contains("resident_health_check_concurrency:'4'"));
    assert!(rendered.contains("http_queue:'512'"));
    assert!(rendered.contains("allocator_idle_reclaim_sample_interval:'2m'"));
    assert!(!rendered.trim_start().starts_with('{'));

    let sections = parse_config(&format!("{rendered}\nrouting {{ fallback: direct }}\n")).unwrap();
    let config = build_config(&sections).unwrap();
    assert_eq!(config.global.tcp_check_http_method, "GET");
    assert_eq!(
        config.global.tcp_check_url[0],
        "http://localhost/generate_204"
    );
    assert_eq!(config.global.tcp_check_url[1], "127.0.0.1");
    assert_eq!(config.global.tproxy_port, 12345);
    assert!(!config.global.tproxy_port_protect);
    assert!(config.global.disable_waiting_network);
    assert!(config.global.enable_local_tcp_fast_redirect);
    assert_eq!(config.global.resident_udp_session_limit, Some(128));
    assert_eq!(config.global.resident_health_check_concurrency, Some(4));
    assert_eq!(config.global.http_queue, Some(512));
    assert_eq!(
        config
            .global
            .allocator_idle_reclaim_sample_interval
            .map(|duration| duration.to_string()),
        Some("2m0s".to_owned())
    );

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
    let raw = r#"{"tcpCheckHttpMethod":"GET","tcpCheckUrl":["http://localhost","127.0.0.1"],"wanInterface":["auto"],"tproxyPort":12345}"#;
    let rendered = display_global_config_text(raw);
    assert!(rendered.starts_with("global {\n"));
    assert!(rendered.contains("tcp_check_http_method:'GET'"));
    assert!(rendered.contains("tcp_check_url:'http://localhost,127.0.0.1'"));
    assert!(!rendered.contains("allow_insecure:'false'"));
}

#[test]
fn runtime_traffic_carry_preserves_totals_when_live_metrics_reset() {
    let carry = RuntimeTrafficCarry::default().absorb_metrics(&json!({
        "uploadTotal": 500,
        "downloadTotal": "700",
    }));
    let mut summary = json!({
        "residentDataplane": {
            "metrics": {
                "uploadTotal": 25,
                "downloadTotal": "50",
                "activeTcpConnections": 3,
                "activeUdpSessions": 2,
            }
        }
    });

    carry.apply_to_runtime_summary(&mut summary);

    let metrics = &summary["residentDataplane"]["metrics"];
    assert_eq!(metrics["uploadTotal"], json!(525));
    assert_eq!(metrics["downloadTotal"], json!(750));
    assert_eq!(metrics["activeTcpConnections"], json!(3));
    assert_eq!(metrics["activeUdpSessions"], json!(2));

    let stats = resident_runtime_traffic_stats(&summary, 60, 10);
    assert_eq!(stats.upload_total, 525);
    assert_eq!(stats.download_total, 750);
}

#[test]
fn runtime_traffic_carry_zero_leaves_live_metrics_unchanged() {
    let mut metrics = json!({
        "uploadTotal": 25,
        "downloadTotal": 50,
    });

    RuntimeTrafficCarry::default().apply_to_metrics(&mut metrics);

    assert_eq!(metrics["uploadTotal"], json!(25));
    assert_eq!(metrics["downloadTotal"], json!(50));
}

#[test]
fn runtime_traffic_stats_ignore_legacy_event_file_without_live_metrics() {
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
    assert_eq!(stats.upload_total, 0);
    assert_eq!(stats.download_total, 0);
    assert_eq!(stats.active_connections, 0);
    assert_eq!(stats.udp_sessions, 0);
    assert!(stats.samples.is_empty());
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

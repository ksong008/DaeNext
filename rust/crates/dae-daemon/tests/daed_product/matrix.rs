#[test]
fn daed_resident_adapter_matrix_reports_admitted_selected_node_without_links() {
    let temp = temp_dir("resident-adapter-matrix-admitted");
    let config = temp.join("config.dae");
    fs::write(
        &config,
        r#"
global {
  lan_interface: daerust0
  allow_insecure: false
  so_mark_from_dae: 1234
  mptcp: false
  tls_implementation: utls
  utls_imitate: safari
}
node {
  vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=chrome&alpn=h2,http/1.1'
}
group {
  proxy {
    filter: name(vless_live)
    policy: fixed(0)
  }
}
routing {
  l4proto(tcp) && dport(443) -> proxy
  fallback: direct
}
"#,
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(binary())
        .args(["resident-adapter-matrix", "-c"])
        .arg(&config)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["schema"].as_str().unwrap(),
        "resident-live-adapter-config-assessment"
    );
    assert_eq!(report["status"].as_str().unwrap(), "admitted");
    assert!(report["read_only"].as_bool().unwrap());
    assert!(!report["host_mutation_executed"].as_bool().unwrap());
    assert!(!report["network_io_executed"].as_bool().unwrap());
    assert!(report["full_matrix_open"].as_bool().unwrap());
    assert_current_config_matrix_scope_contract(&report);
    assert!(
        report["full_matrix_row_count"].as_u64().unwrap() >= 10,
        "{report}"
    );
    assert!(report["planner_admitted"].as_bool().unwrap());
    assert_eq!(
        report["default_proxy"]["node_tag"].as_str().unwrap(),
        "vless_live"
    );
    assert!(
        report["default_proxy"]["fingerprint_underlay"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["default_proxy"]["utls_fingerprint"]["source"]
            .as_str()
            .unwrap(),
        "link fp"
    );
    let rows = report["full_matrix_rows"].as_array().unwrap();
    let live_row = rows
        .iter()
        .find(|row| row["formal_matrix_handler"].as_str().unwrap() == "vless")
        .unwrap();
    assert_eq!(
        live_row["matrix_scope"].as_str().unwrap(),
        "current-config-formal-handler-matrix"
    );
    assert_eq!(
        live_row["source_supported_scope"].as_str().unwrap(),
        "formal-handler-baseline"
    );
    assert_eq!(
        live_row["source_shape_registry_status"].as_str().unwrap(),
        "open"
    );
    assert_eq!(
        live_row["expanded_source_matrix_state"].as_str().unwrap(),
        "generated"
    );
    assert_eq!(live_row["planner_status"].as_str().unwrap(), "admitted");
    assert_eq!(live_row["admitted_count"].as_u64().unwrap(), 1);
    assert_eq!(
        live_row["generated_solver"]["executableGraphReady"]
            .as_bool()
            .unwrap(),
        true
    );
    assert_eq!(
        live_row["generated_solver"]["runtimeComponentsReady"]
            .as_bool()
            .unwrap(),
        true
    );
    assert_eq!(
        live_row["generated_solver"]["defaultReady"]
            .as_bool()
            .unwrap(),
        false
    );
    assert_eq!(
        live_row["generated_solver"]["goFreeReady"]
            .as_bool()
            .unwrap(),
        false
    );
    assert_eq!(
        live_row["candidates"][0]["runtimeComponents"]["probeExecutor"]["executor"]
            .as_str()
            .unwrap(),
        "resident-executable-graph"
    );
    let absent_row = rows
        .iter()
        .find(|row| row["formal_matrix_handler"].as_str().unwrap() == "trojan")
        .unwrap();
    assert_eq!(
        absent_row["planner_status"].as_str().unwrap(),
        "not-present"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("01234567-89ab"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("vless://"));
    let _ = fs::remove_dir_all(temp);
}

#[test]
fn daed_resident_adapter_matrix_reports_shadowsocks_2022_admitted() {
    let temp = temp_dir("resident-adapter-admitted-cipher-family");
    let config = temp.join("config.dae");
    fs::write(
        &config,
        r#"
global {
  lan_interface: daerust0
  allow_insecure: false
  so_mark_from_dae: 1234
  mptcp: false
}
node {
  ss_live: 'ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@203.0.113.10:8388'
}
group {
  proxy {
    filter: name(ss_live)
    policy: fixed(0)
  }
}
routing {
  l4proto(tcp) && dport(443) -> proxy
  fallback: direct
}
"#,
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(binary())
        .args(["resident-adapter-matrix", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str().unwrap(), "admitted");
    assert!(report["full_matrix_open"].as_bool().unwrap());
    assert_current_config_matrix_scope_contract(&report);
    assert!(report["planner_admitted"].as_bool().unwrap());
    assert!(report["selected_node_fail_closed"].as_bool().unwrap());
    assert!(report.get("planner_error").is_none());
    assert_eq!(
        report["default_proxy"]["security"].as_str().unwrap(),
        "aead-2022"
    );
    assert_eq!(
        report["default_proxy"]["executableGraph"]["packetSemantics"]
            .as_str()
            .unwrap(),
        "datagram-aead-2022"
    );
    let rows = report["full_matrix_rows"].as_array().unwrap();
    let row = rows
        .iter()
        .find(|row| row["formal_matrix_handler"].as_str().unwrap() == "shadowsocks")
        .unwrap();
    assert_eq!(row["planner_status"].as_str().unwrap(), "admitted");
    assert_eq!(row["candidate_count"].as_u64().unwrap(), 1);
    assert_eq!(row["blocked_count"].as_u64().unwrap(), 0);
    assert_eq!(
        row["candidates"][0]["admission"]["status"]
            .as_str()
            .unwrap(),
        "admitted"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("MTIzNDU2"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("ss://"));
    let _ = fs::remove_dir_all(temp);
}

#[test]
fn daed_resident_adapter_matrix_keeps_invalid_websocket_flow_fail_closed() {
    let temp = temp_dir("resident-adapter-source-websocket-flow-blocked");
    let config = temp.join("config.dae");
    fs::write(
        &config,
        r#"
global {
  lan_interface: daerust0
  allow_insecure: false
  so_mark_from_dae: 1234
  mptcp: false
}
node {
  vless_ws: 'vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?security=tls&type=websocket&sni=office.example&path=%2Fws&flow=xtls-rprx-vision&fp=chrome'
}
group {
  proxy {
    filter: name(vless_ws)
    policy: fixed(0)
  }
}
routing {
  l4proto(tcp) && dport(443) -> proxy
  fallback: direct
}
"#,
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(binary())
        .args(["resident-adapter-matrix", "-c"])
        .arg(&config)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str().unwrap(), "blocked");
    assert!(
        report["planner_error"]
            .as_str()
            .unwrap()
            .contains("wrapped-stream handler admits only empty flow")
    );

    let rows = report["expanded_source_matrix_rows"].as_array().unwrap();
    let websocket = rows
        .iter()
        .find(|row| row["shapeId"].as_str().unwrap() == "stream-wrapper-websocket")
        .unwrap();
    assert_eq!(websocket["planner_status"].as_str().unwrap(), "blocked");
    assert_eq!(
        websocket["capabilityReasonId"].as_str().unwrap(),
        "materialization-mismatch"
    );
    assert_eq!(websocket["candidate_count"].as_u64().unwrap(), 1);
    assert_eq!(websocket["admitted_count"].as_u64().unwrap(), 0);
    assert_eq!(websocket["blocked_count"].as_u64().unwrap(), 1);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("vless://"));
    let _ = fs::remove_dir_all(temp);
}

#[test]
fn daed_resident_adapter_matrix_admits_websocket_source_shape() {
    let temp = temp_dir("resident-adapter-source-websocket-admitted");
    let config = temp.join("config.dae");
    fs::write(
        &config,
        r#"
global {
  lan_interface: daerust0
  allow_insecure: false
  so_mark_from_dae: 1234
  mptcp: false
}
node {
  vless_ws: 'vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?security=tls&type=websocket&sni=office.example&host=front.example&path=%2Fws&fp=chrome#vless-ws-resident'
}
group {
  proxy {
    filter: name(vless_ws)
    policy: fixed(0)
  }
}
routing {
  l4proto(tcp) && dport(443) -> proxy
  fallback: direct
}
"#,
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(binary())
        .args(["resident-adapter-matrix", "-c"])
        .arg(&config)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str().unwrap(), "admitted");

    let rows = report["expanded_source_matrix_rows"].as_array().unwrap();
    let websocket = rows
        .iter()
        .find(|row| row["shapeId"].as_str().unwrap() == "stream-wrapper-websocket")
        .unwrap();
    assert_eq!(
        websocket["residentStatus"].as_str().unwrap(),
        "admitted-baseline"
    );
    assert_eq!(websocket["planner_status"].as_str().unwrap(), "admitted");
    assert_eq!(websocket["candidate_count"].as_u64().unwrap(), 1);
    assert_eq!(websocket["admitted_count"].as_u64().unwrap(), 1);
    assert_eq!(websocket["blocked_count"].as_u64().unwrap(), 0);
    assert!(websocket["capabilityReasonId"].is_null());
    assert_eq!(
        websocket["componentExecutorProof"]["proofState"]
            .as_str()
            .unwrap(),
        "runtime-executable"
    );
    let candidate = &websocket["candidates"].as_array().unwrap()[0];
    assert_eq!(
        candidate["executableGraph"]["streamWrapper"]
            .as_str()
            .unwrap(),
        "websocket"
    );
    assert_eq!(
        candidate["executableGraph"]["protocolFraming"]
            .as_str()
            .unwrap(),
        "vless"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("vless://"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("01234567-89ab"));
    let _ = fs::remove_dir_all(temp);
}

#[test]
fn daed_resident_adapter_matrix_admits_httpupgrade_source_shape() {
    let temp = temp_dir("resident-adapter-source-httpupgrade-admitted");
    let config = temp.join("config.dae");
    fs::write(
        &config,
        r#"
global {
  lan_interface: daerust0
  allow_insecure: false
  so_mark_from_dae: 1234
  mptcp: false
}
node {
  vless_httpupgrade: 'vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?security=tls&type=httpupgrade&sni=office.example&host=front.example&path=%2Fvless-upgrade&fp=chrome#vless-httpupgrade-resident'
}
group {
  proxy {
    filter: name(vless_httpupgrade)
    policy: fixed(0)
  }
}
routing {
  l4proto(tcp) && dport(443) -> proxy
  fallback: direct
}
"#,
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(binary())
        .args(["resident-adapter-matrix", "-c"])
        .arg(&config)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str().unwrap(), "admitted");

    let rows = report["expanded_source_matrix_rows"].as_array().unwrap();
    let httpupgrade = rows
        .iter()
        .find(|row| row["shapeId"].as_str().unwrap() == "stream-wrapper-httpupgrade")
        .unwrap();
    assert_eq!(
        httpupgrade["residentStatus"].as_str().unwrap(),
        "admitted-baseline"
    );
    assert_eq!(httpupgrade["planner_status"].as_str().unwrap(), "admitted");
    assert_eq!(httpupgrade["candidate_count"].as_u64().unwrap(), 1);
    assert_eq!(httpupgrade["admitted_count"].as_u64().unwrap(), 1);
    assert_eq!(httpupgrade["blocked_count"].as_u64().unwrap(), 0);
    assert!(httpupgrade["capabilityReasonId"].is_null());
    assert_eq!(
        httpupgrade["componentExecutorProof"]["proofState"]
            .as_str()
            .unwrap(),
        "runtime-executable"
    );
    let candidate = &httpupgrade["candidates"].as_array().unwrap()[0];
    assert_eq!(
        candidate["executableGraph"]["streamWrapper"]
            .as_str()
            .unwrap(),
        "httpupgrade"
    );
    assert_eq!(
        candidate["executableGraph"]["protocolFraming"]
            .as_str()
            .unwrap(),
        "vless"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("vless://"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("01234567-89ab"));
    let _ = fs::remove_dir_all(temp);
}

#[test]
fn daed_resident_adapter_matrix_reports_initial_rows_admitted_without_secrets() {
    let temp = temp_dir("resident-adapter-matrix-initial-rows");
    let config = temp.join("config.dae");
    let vless_live = vless_fixture_url("vless", "example.com", 443);
    let ss_live = shadowsocks_fixture_url("ss", "example.com", 28446);
    let trojan_live = trojan_fixture_url("trojan", "example.com", 28444);
    let vmess_live = vmess_fixture_url("vmess", "example.com", 28452, "tcp");
    let hy2_live = hysteria2_fixture_url("hy2", "example.com", 28453);
    let tuic_live = tuic_fixture_url("tuic", "example.com", 28454);
    let juicity_live = juicity_fixture_url("juicity", "example.com", 28455);
    let config_text = r#"
global {
  lan_interface: daerust0
  allow_insecure: false
  so_mark_from_dae: 1234
  mptcp: false
}
node {
  vless_live: '__VLESS_LIVE__'
  socks_live: 'socks5://user:socks-password@example.com:28447#socks'
  http_live: 'http://user:http-password@example.com:28448#http'
  ss_live: '__SS_LIVE__'
  trojan_live: '__TROJAN_LIVE__'
  anytls_live: 'anytls://anytls-password@example.com:28451?sni=office.example#anytls'
  vmess_live: '__VMESS_LIVE__'
  hy2_live: '__HY2_LIVE__'
  tuic_live: '__TUIC_LIVE__'
  juicity_live: '__JUICITY_LIVE__'
}
group {
  proxy {
    filter: name(vless_live)
    policy: fixed(0)
  }
}
routing {
  l4proto(tcp) && dport(443) -> proxy
  fallback: direct
}
"#
    .replace("__VLESS_LIVE__", &vless_live)
    .replace("__SS_LIVE__", &ss_live)
    .replace("__TROJAN_LIVE__", &trojan_live)
    .replace("__VMESS_LIVE__", &vmess_live)
    .replace("__HY2_LIVE__", &hy2_live)
    .replace("__TUIC_LIVE__", &tuic_live)
    .replace("__JUICITY_LIVE__", &juicity_live);
    fs::write(&config, config_text).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(binary())
        .args(["resident-adapter-matrix", "-c"])
        .arg(&config)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str().unwrap(), "admitted");
    assert!(report["full_matrix_open"].as_bool().unwrap());
    assert_current_config_matrix_scope_contract(&report);
    assert_eq!(
        report["full_matrix_admitted_row_count"].as_u64().unwrap(),
        10
    );
    let rows = report["full_matrix_rows"].as_array().unwrap();
    for handler in [
        "vless",
        "socks5",
        "http-proxy",
        "shadowsocks",
        "trojan",
        "anytls",
        "vmess",
        "hysteria2",
        "tuic",
        "juicity",
    ] {
        let row = rows
            .iter()
            .find(|row| row["formal_matrix_handler"].as_str().unwrap() == handler)
            .unwrap();
        assert_eq!(
            row["matrix_scope"].as_str().unwrap(),
            "current-config-formal-handler-matrix"
        );
        assert_eq!(
            row["source_shape_registry_status"].as_str().unwrap(),
            "open"
        );
        assert_eq!(
            row["expanded_source_matrix_state"].as_str().unwrap(),
            "generated"
        );
        assert_eq!(row["planner_status"].as_str().unwrap(), "admitted");
        assert_eq!(row["candidate_count"].as_u64().unwrap(), 1);
        assert_eq!(row["admitted_count"].as_u64().unwrap(), 1);
        assert_eq!(
            row["generated_solver"]["defaultReady"].as_bool().unwrap(),
            false
        );
        assert_eq!(
            row["generated_solver"]["goFreeReady"].as_bool().unwrap(),
            false
        );
    }
    for handler in [
        "vless",
        "socks5",
        "http-proxy",
        "shadowsocks",
        "trojan",
        "anytls",
        "vmess",
        "hysteria2",
        "tuic",
        "juicity",
    ] {
        let row = rows
            .iter()
            .find(|row| row["formal_matrix_handler"].as_str().unwrap() == handler)
            .unwrap();
        assert_eq!(row["remote_live_matrix"].as_bool().unwrap(), false);
    }
    assert_eq!(
        report["resident_live_adapter_remote_live_matrix_ready"]
            .as_bool()
            .unwrap(),
        false
    );
    let http_row = rows
        .iter()
        .find(|row| row["formal_matrix_handler"].as_str().unwrap() == "http-proxy")
        .unwrap();
    assert_eq!(http_row["udp_live_adapter"].as_bool().unwrap(), false);
    assert_eq!(
        http_row["udp_semantics"].as_str().unwrap(),
        "protocol-closed"
    );
    assert_eq!(http_row["udp_path_ready"].as_bool().unwrap(), true);
    assert_eq!(
        http_row["generated_solver"]["udpLoopbackReady"]
            .as_bool()
            .unwrap(),
        true
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for secret in [
        "vless://",
        "socks5://",
        "http://user",
        "ss://",
        "trojan://",
        "anytls://",
        "vmess://",
        "hy2://",
        "tuic://",
        "juicity://",
        "socks-password",
        "http-password",
        "ss-password",
        "trojan-password",
        "anytls-password",
        "hy2-auth",
        "tuic-password",
        "juicity-password",
        "01234567-89ab",
    ] {
        assert!(!stdout.contains(secret), "{secret} leaked in {stdout}");
    }
    let _ = fs::remove_dir_all(temp);
}

#[test]
fn daed_resident_adapter_udp_live_reports_protocol_closed_without_secrets() {
    let temp = temp_dir("resident-adapter-udp-live-http");
    let config = temp.join("config.dae");
    fs::write(
        &config,
        r#"
global {
  lan_interface: daerust0
  allow_insecure: false
  so_mark_from_dae: 0
  mptcp: false
}
node {
  http_live: 'http://fixture-user:fixture-credential@example.com:28448#http'
}
group {
  proxy {
    filter: name(http_live)
    policy: fixed(0)
  }
}
routing {
  l4proto(tcp) && dport(443) -> proxy
  fallback: direct
}
"#,
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(binary())
        .args([
            "resident-adapter-udp-live",
            "-c",
            config.to_str().unwrap(),
            "--target",
            "127.0.0.1:5353",
            "--payload",
            "probe",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["schema"].as_str().unwrap(),
        "resident-live-adapter-udp-live"
    );
    let rows = report["rows"].as_array().unwrap();
    let http_row = rows
        .iter()
        .find(|row| row["formal_matrix_handler"].as_str().unwrap() == "http-proxy")
        .unwrap();
    assert_eq!(http_row["status"].as_str().unwrap(), "protocol-closed");
    assert_eq!(http_row["ok"].as_bool().unwrap(), true);
    assert_eq!(http_row["protocol_closed"].as_bool().unwrap(), true);
    assert_eq!(
        http_row["udp_semantics"].as_str().unwrap(),
        "protocol-closed"
    );
    assert_eq!(
        http_row["packetSession"]["manager"].as_str().unwrap(),
        "bounded-resident-packet-session"
    );
    assert_eq!(
        http_row["packetSession"]["packetSemantics"]
            .as_str()
            .unwrap(),
        "protocol-closed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("http://fixture-user"));
    assert!(!stdout.contains("fixture-credential"));
    let _ = fs::remove_dir_all(temp);
}

#[test]
fn daed_resident_adapter_matrix_requires_config_path() {
    let output = Command::new(binary())
        .args(["resident-adapter-matrix"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("resident-adapter-matrix requires -c/--config")
    );
}

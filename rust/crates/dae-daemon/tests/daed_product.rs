use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::Value;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_daed")
}

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
        "resident-live-adapter-config-assessment-v1"
    );
    assert_eq!(report["status"].as_str().unwrap(), "admitted");
    assert!(report["read_only"].as_bool().unwrap());
    assert!(!report["host_mutation_executed"].as_bool().unwrap());
    assert!(!report["network_io_executed"].as_bool().unwrap());
    assert!(report["full_matrix_open"].as_bool().unwrap());
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
    assert_eq!(live_row["planner_status"].as_str().unwrap(), "admitted");
    assert_eq!(live_row["admitted_count"].as_u64().unwrap(), 1);
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
fn daed_resident_adapter_matrix_reports_fail_closed_selected_node() {
    let temp = temp_dir("resident-adapter-matrix-blocked");
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
  ss_live: 'ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@203.0.113.10:8388#ss2022'
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
    assert_eq!(report["status"].as_str().unwrap(), "blocked");
    assert!(report["full_matrix_open"].as_bool().unwrap());
    assert!(!report["planner_admitted"].as_bool().unwrap());
    assert!(report["selected_node_fail_closed"].as_bool().unwrap());
    assert!(
        report["planner_error"]
            .as_str()
            .unwrap()
            .contains("admit Shadowsocks cipher for node ss_live")
    );
    let rows = report["full_matrix_rows"].as_array().unwrap();
    let row = rows
        .iter()
        .find(|row| row["formal_matrix_handler"].as_str().unwrap() == "shadowsocks")
        .unwrap();
    assert_eq!(row["planner_status"].as_str().unwrap(), "blocked");
    assert_eq!(row["candidate_count"].as_u64().unwrap(), 1);
    assert_eq!(row["blocked_count"].as_u64().unwrap(), 1);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("MTIzNDU2"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("ss://"));
    let _ = fs::remove_dir_all(temp);
}

#[test]
fn daed_resident_adapter_matrix_reports_first_batch_rows_admitted_without_secrets() {
    let temp = temp_dir("resident-adapter-matrix-first-batch");
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
  vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=chrome&alpn=h2,http/1.1'
  socks_live: 'socks5://matrix:matrix-socks-pass@example.com:28447#socks'
  http_live: 'http://matrix:matrix-http-pass@example.com:28448#http'
  ss_live: 'ss://aes-128-gcm:matrix-ss-pass@example.com:28446#ss'
  trojan_live: 'trojan://matrix-trojan-pass@example.com:28444?security=tls&sni=office.example#trojan'
  anytls_live: 'anytls://matrix-anytls-pass@example.com:28451?sni=office.example#anytls'
  vmess_live: 'vmess://eyJ2IjoiMiIsInBzIjoidm1lc3MiLCJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiIyODQ1MiIsImlkIjoiMDEyMzQ1NjctODlhYi1jZGVmLTAxMjMtNDU2Nzg5YWJjZGVmIiwiYWlkIjoiMCIsIm5ldCI6InRjcCIsInR5cGUiOiJub25lIiwiaG9zdCI6IiIsInBhdGgiOiIiLCJ0bHMiOiIifQ=='
  hy2_live: 'hy2://matrix-hy2-auth@example.com:28453?sni=office.example&pinSHA256=AA-BB-CC#hy2'
  tuic_live: 'tuic://01234567-89ab-cdef-0123-456789abcdef:matrix-tuic-pass@example.com:28454?allow_insecure=1&sni=office.example&alpn=h3#tuic'
  juicity_live: 'juicity://01234567-89ab-cdef-0123-456789abcdef:matrix-juicity-pass@example.com:28455?allow_insecure=1&sni=office.example#juicity'
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
    assert_eq!(report["status"].as_str().unwrap(), "admitted");
    assert!(report["full_matrix_open"].as_bool().unwrap());
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
        assert_eq!(row["planner_status"].as_str().unwrap(), "admitted");
        assert_eq!(row["candidate_count"].as_u64().unwrap(), 1);
        assert_eq!(row["admitted_count"].as_u64().unwrap(), 1);
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
        assert_eq!(row["remote_live_matrix"].as_bool().unwrap(), true);
    }
    assert_eq!(
        report["resident_live_adapter_remote_live_matrix_ready"]
            .as_bool()
            .unwrap(),
        true
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
    let stdout = String::from_utf8_lossy(&output.stdout);
    for secret in [
        "vless://",
        "socks5://",
        "http://matrix",
        "ss://",
        "trojan://",
        "anytls://",
        "vmess://",
        "hy2://",
        "tuic://",
        "juicity://",
        "matrix-socks-pass",
        "matrix-http-pass",
        "matrix-ss-pass",
        "matrix-trojan-pass",
        "matrix-anytls-pass",
        "matrix-hy2-auth",
        "matrix-tuic-pass",
        "matrix-juicity-pass",
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
        "resident-live-adapter-udp-live-v1"
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

#[test]
fn daed_product_contract_reports_c10_first_batch_state_paths() {
    let output = Command::new(binary())
        .args(["service-contract", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["primary_state_store"].as_str().unwrap(),
        "/etc/daed/daed.db"
    );
    assert_eq!(
        report["protected_rollback_state_store"].as_str().unwrap(),
        "/etc/daed/wing.db"
    );
    assert!(
        !report["rust_daed_writes_wing_db_by_default"]
            .as_bool()
            .unwrap()
    );
    assert!(report["wing_db_import_supported"].as_bool().unwrap());
    assert!(
        report["rust_daed_validate_command_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_setup_auth_user_storage_api_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_static_webui_serving_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_resource_crud_api_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(report["rust_daed_materializer_ready"].as_bool().unwrap());
    assert!(report["rust_daed_runtime_owner_ready"].as_bool().unwrap());
    assert!(
        report["rust_daed_logs_sse_latency_subscription_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_import_export_package_surface_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_subscription_fetch_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_latency_probe_tcp_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_resetpass_parity_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_package_manifest_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_webui_route_audit_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_local_package_admission_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["go_free_product_chain_typed_report"]["rust_product_binary_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["go_free_product_chain_typed_report"]["status"]
            .as_str()
            .unwrap(),
        "blocked"
    );
    assert!(!report["go_free_product_chain_ready"].as_bool().unwrap());

    let package = Command::new(binary())
        .args(["package-info", "--json"])
        .output()
        .unwrap();
    assert!(package.status.success());
    let package: Value = serde_json::from_slice(&package.stdout).unwrap();
    assert_eq!(
        package["primary_state_store"].as_str().unwrap(),
        "/etc/daed/daed.db"
    );
    assert!(
        package["current_batch_ready"]["local_package_admission"]
            .as_bool()
            .unwrap()
    );
    assert!(
        package["current_batch_ready"]["validate_command"]
            .as_bool()
            .unwrap()
    );
    assert!(!package["webui"]["leptos_considered"].as_bool().unwrap());
}

#[test]
fn daed_version_command_supports_package_smoke_test() {
    let output = Command::new(binary())
        .env("DAE_DAEMON_VERSION", "c10-smoke")
        .arg("--version")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "c10-smoke\n");
}

#[test]
fn daed_validate_accepts_config_file_and_config_dir_without_state_mutation() {
    let temp = temp_dir("validate");
    let config_file = temp.join("empty.dae");
    fs::write(&config_file, "global {} routing {}").unwrap();
    fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(binary())
        .args(["validate", "-c"])
        .arg(&config_file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());

    let json_output = Command::new(binary())
        .args(["validate", "-c"])
        .arg(&config_file)
        .arg("--json")
        .output()
        .unwrap();
    assert!(json_output.status.success());
    let report: Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(report["status"].as_str().unwrap(), "pass");
    assert_eq!(report["kind"].as_str().unwrap(), "dae-config-file");
    assert!(!report["mutationExecuted"].as_bool().unwrap());

    let config_dir = temp.join("config-dir");
    fs::create_dir_all(&config_dir).unwrap();
    let dir_output = Command::new(binary())
        .args(["validate", "-c"])
        .arg(&config_dir)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        dir_output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&dir_output.stderr)
    );
    let dir_report: Value = serde_json::from_slice(&dir_output.stdout).unwrap();
    assert_eq!(dir_report["kind"].as_str().unwrap(), "daed-config-dir");
    assert!(!dir_report["statePresent"].as_bool().unwrap());
    assert!(dir_report["freshInstallStateOptional"].as_bool().unwrap());
    assert!(!config_dir.join("daed.db").exists());

    let bad_config = temp.join("bad.dae");
    fs::write(&bad_config, "this is not dae config").unwrap();
    let bad = Command::new(binary())
        .args(["validate", "-c"])
        .arg(&bad_config)
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("validate failed"),
        "stderr={}",
        String::from_utf8_lossy(&bad.stderr)
    );
    let _ = fs::remove_dir_all(temp);
}

#[test]
fn daed_state_migrate_does_not_modify_wing_db() {
    let temp = temp_dir("state-migrate");
    let wing = temp.join("wing.db");
    let daed = temp.join("daed.db");

    let check_wing = Command::new(binary())
        .args(["state", "check", "--state"])
        .arg(&wing)
        .output()
        .unwrap();
    assert!(check_wing.status.success());
    let wing_hash_before = sha256(&wing);

    let migrate = Command::new(binary())
        .args(["state", "migrate", "--from-wing-db"])
        .arg(&wing)
        .args(["--to"])
        .arg(&daed)
        .output()
        .unwrap();
    assert!(
        migrate.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&migrate.stderr)
    );
    let report: Value = serde_json::from_slice(&migrate.stdout).unwrap();
    assert!(report["wing_db_unchanged"].as_bool().unwrap());
    assert_eq!(wing_hash_before, sha256(&wing));

    let check_daed = Command::new(binary())
        .args(["state", "check", "--state"])
        .arg(&daed)
        .output()
        .unwrap();
    assert!(check_daed.status.success());
    let report: Value = serde_json::from_slice(&check_daed.stdout).unwrap();
    assert!(report["schema_ready"].as_bool().unwrap());

    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn daed_run_serves_minimal_api_and_static_webui() {
    let temp = temp_dir("run-api");
    let web = temp.join("web");
    fs::create_dir_all(&web).unwrap();
    fs::write(web.join("index.html"), "<!doctype html><title>daed</title>").unwrap();
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let mut child = Command::new(binary())
        .args(["run", "-c"])
        .arg(&temp)
        .args(["--listen", &listen, "--web-root"])
        .arg(&web)
        .env("DAED_PRODUCT_RUNTIME_FAKE_START", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    wait_for_http(port, "/api/health", &mut child);

    let health = http_request(port, "GET", "/api/health", None, None);
    assert!(health.contains("200 OK"));
    assert!(health.contains("\"healthCheck\":1"));

    let status = http_request(port, "GET", "/api/auth/status", None, None);
    assert!(status.contains("\"numberUsers\":0"));

    let create = http_request(
        port,
        "POST",
        "/api/auth/users",
        Some(r#"{"username":"admin","password":"abc123"}"#),
        None,
    );
    assert!(create.contains("201 Created"), "{create}");
    let token = json_body(&create)["token"].as_str().unwrap().to_owned();
    assert!(!token.is_empty());

    let me = http_request(port, "GET", "/api/user/me", None, Some(&token));
    assert!(me.contains("\"username\":\"admin\""), "{me}");

    let set_storage = http_request(
        port,
        "PUT",
        "/api/user/me/storage",
        Some(r#"{"paths":["ui.sidebar"],"values":["open"]}"#),
        Some(&token),
    );
    assert!(set_storage.contains("\"updated\":1"), "{set_storage}");

    let get_storage = http_request(
        port,
        "GET",
        "/api/user/me/storage?path=ui.sidebar",
        None,
        Some(&token),
    );
    assert!(
        get_storage.contains("\"values\":[\"open\"]"),
        "{get_storage}"
    );

    let index = http_request(port, "GET", "/", None, None);
    assert!(index.contains("<title>daed</title>"), "{index}");

    child.kill().unwrap();
    let _ = child.wait();
    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn daed_run_serves_c10_resource_runtime_log_latency_and_bundle_surface() {
    let temp = temp_dir("run-c10-api");
    let web = temp.join("web");
    fs::create_dir_all(&web).unwrap();
    fs::write(web.join("index.html"), "<!doctype html><title>daed</title>").unwrap();
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let mut child = Command::new(binary())
        .args(["run", "-c"])
        .arg(&temp)
        .args(["--listen", &listen, "--web-root"])
        .arg(&web)
        .env("DAED_PRODUCT_RUNTIME_FAKE_START", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    wait_for_http(port, "/api/health", &mut child);

    let create = http_request(
        port,
        "POST",
        "/api/auth/users",
        Some(r#"{"username":"admin","password":"abc123"}"#),
        None,
    );
    assert!(create.contains("201 Created"), "{create}");
    let token = json_body(&create)["token"].as_str().unwrap().to_owned();

    let (probe_port, probe_handle) = spawn_tcp_probe_server();
    let (subscription_port, subscription_handle) = spawn_text_server(&format!(
        "http://127.0.0.1:{probe_port}/sub-node#subscription-node\n"
    ));

    let config = http_request(
        port,
        "POST",
        "/api/configs",
        Some(r#"{"name":"global","global":"global {\n  log_level: \"info\"\n}"}"#),
        Some(&token),
    );
    assert!(config.contains("201 Created"), "{config}");
    let config_id = json_body(&config)["id"].as_i64().unwrap();
    let select_config = http_request(
        port,
        "POST",
        &format!("/api/configs/{config_id}/select"),
        Some("{}"),
        Some(&token),
    );
    assert!(
        select_config.contains("\"selected\":true"),
        "{select_config}"
    );

    let dns = http_request(
        port,
        "POST",
        "/api/dns",
        Some(r#"{"name":"dns","dns":"dns {}"}"#),
        Some(&token),
    );
    let dns_id = json_body(&dns)["id"].as_i64().unwrap();
    let _ = http_request(
        port,
        "POST",
        &format!("/api/dns/{dns_id}/select"),
        Some("{}"),
        Some(&token),
    );

    let routing = http_request(
        port,
        "POST",
        "/api/routings",
        Some(r#"{"name":"routing","routing":"routing {}"}"#),
        Some(&token),
    );
    let routing_id = json_body(&routing)["id"].as_i64().unwrap();
    let _ = http_request(
        port,
        "POST",
        &format!("/api/routings/{routing_id}/select"),
        Some("{}"),
        Some(&token),
    );

    let nodes = http_request(
        port,
        "POST",
        "/api/nodes",
        Some(&format!(
            r#"{{"args":[{{"link":"http://127.0.0.1:{probe_port}/node#n1","tag":"n1"}}]}}"#
        )),
        Some(&token),
    );
    let node_id = json_body(&nodes)["items"][0]["node"]["id"]
        .as_i64()
        .unwrap();
    let tag_node = http_request(
        port,
        "PUT",
        &format!("/api/nodes/{node_id}"),
        Some(r#"{"tag":"n1-renamed"}"#),
        Some(&token),
    );
    assert!(tag_node.contains("\"tag\":\"n1-renamed\""), "{tag_node}");

    let subscription = http_request(
        port,
        "POST",
        "/api/subscriptions",
        Some(&format!(
            r#"{{"link":"http://127.0.0.1:{subscription_port}/sub","tag":"sub1"}}"#
        )),
        Some(&token),
    );
    assert!(subscription.contains("201 Created"), "{subscription}");
    assert!(
        subscription.contains("subscription-node"),
        "subscription fetch did not import local node: {subscription}"
    );
    subscription_handle.join().unwrap();
    let subscription_id = json_body(&subscription)["subscription"]["id"]
        .as_i64()
        .unwrap();
    let tag_subscription = http_request(
        port,
        "PUT",
        &format!("/api/subscriptions/{subscription_id}"),
        Some(r#"{"tag":"sub-renamed"}"#),
        Some(&token),
    );
    assert!(
        tag_subscription.contains("\"tag\":\"sub-renamed\""),
        "{tag_subscription}"
    );
    let cron_subscription = http_request(
        port,
        "PUT",
        &format!("/api/subscriptions/{subscription_id}"),
        Some(r#"{"cronExp":"0 */2 * * *","cronEnable":false}"#),
        Some(&token),
    );
    assert!(
        cron_subscription.contains("\"tag\":\"sub-renamed\""),
        "{cron_subscription}"
    );
    let refreshed = http_request(
        port,
        "POST",
        &format!("/api/subscriptions/{subscription_id}/refresh"),
        Some("{}"),
        Some(&token),
    );
    assert!(
        refreshed.contains("\"status\":\"fetch_error\""),
        "{refreshed}"
    );

    let group = http_request(
        port,
        "POST",
        "/api/groups",
        Some(r#"{"name":"egress","policy":"min","policyParams":[{"key":"interval","val":"30s"}]}"#),
        Some(&token),
    );
    assert!(group.contains("201 Created"), "{group}");
    let group_id = json_body(&group)["id"].as_i64().unwrap();
    let bind_node = http_request(
        port,
        "POST",
        &format!("/api/groups/{group_id}/nodes"),
        Some(&format!(r#"{{"nodeIds":[{node_id}]}}"#)),
        Some(&token),
    );
    assert!(bind_node.contains("\"nodes\""), "{bind_node}");
    let bind_subscription = http_request(
        port,
        "POST",
        &format!("/api/groups/{group_id}/subscriptions"),
        Some(&format!(
            r#"{{"subscriptionIds":[{subscription_id}],"nameFilterRegex":"n.*"}}"#
        )),
        Some(&token),
    );
    assert!(
        bind_subscription.contains("\"matchedCount\""),
        "{bind_subscription}"
    );

    let groups = json_body(&http_request(
        port,
        "GET",
        "/api/groups",
        None,
        Some(&token),
    ));
    assert_eq!(groups["items"][0]["policy"].as_str().unwrap(), "min");
    assert_eq!(
        groups["items"][0]["nodes"][0]["id"].as_i64().unwrap(),
        node_id
    );

    let latency = http_request(
        port,
        "POST",
        "/api/nodes/latencies",
        Some(&format!(r#"{{"ids":[{node_id}]}}"#)),
        Some(&token),
    );
    let latency = json_body(&latency);
    assert_eq!(latency["items"][0]["id"].as_i64().unwrap(), node_id);
    assert!(latency["items"][0]["alive"].as_bool().unwrap());
    assert!(
        latency["items"][0]["message"]
            .as_str()
            .unwrap()
            .contains("tcp connect"),
        "{latency}"
    );
    probe_handle.join().unwrap();

    let settings = http_request(
        port,
        "PATCH",
        "/api/logs/settings",
        Some(r#"{"maxEntries":500,"maxBytes":131072}"#),
        Some(&token),
    );
    let settings = json_body(&settings);
    assert_eq!(settings["maxEntries"].as_i64().unwrap(), 500);
    assert_eq!(settings["minMaxEntries"].as_i64().unwrap(), 500);

    let log_level = http_request(
        port,
        "PATCH",
        "/api/runtime/log-level",
        Some(r#"{"level":"debug"}"#),
        Some(&token),
    );
    assert!(log_level.contains("\"level\":\"debug\""), "{log_level}");

    let reload = http_request(
        port,
        "POST",
        "/api/runtime/reload",
        Some(r#"{"dry":false}"#),
        Some(&token),
    );
    assert!(reload.contains("\"applied\":1"), "{reload}");
    assert!(reload.contains("\"runtimeStarted\":true"), "{reload}");
    assert!(
        reload.contains("\"runtimeControl\":\"fake-resident-runtime-test-only\""),
        "{reload}"
    );
    assert!(temp.join("runtime/generated.dae").is_file());
    let generated = fs::read_to_string(temp.join("runtime/generated.dae")).unwrap();
    assert!(generated.contains("generated by Rust daed C10 local product surface"));
    assert!(generated.contains("node {"), "{generated}");
    assert!(generated.contains("group {"), "{generated}");
    assert!(
        generated.contains("filter: name('n1-renamed'"),
        "{generated}"
    );

    let state = http_request(port, "GET", "/api/general/state", None, Some(&token));
    assert!(state.contains("\"running\":true"), "{state}");
    assert!(
        state.contains("\"attachBackend\":\"fake-resident-runtime-test-only\""),
        "{state}"
    );
    let overview = http_request(port, "GET", "/api/runtime/overview", None, Some(&token));
    assert!(overview.contains("\"rssBytes\""), "{overview}");
    assert!(overview.contains("\"runtime\""), "{overview}");
    let logs = http_request(port, "GET", "/api/logs?level=all", None, Some(&token));
    assert!(logs.contains("\"items\""), "{logs}");
    assert!(
        logs.contains("runtime reload applied") || logs.contains("subscription"),
        "{logs}"
    );
    let events = http_request_until(
        port,
        "GET",
        "/api/events/runtime",
        None,
        Some(&token),
        "event: runtime.overview",
    );
    assert!(events.contains("event: runtime.overview"), "{events}");
    let log_events = http_request_until(
        port,
        "GET",
        "/api/events/logs",
        None,
        Some(&token),
        "retry: 3000",
    );
    assert!(log_events.contains("retry: 3000"), "{log_events}");

    let bundle = json_body(&http_request(
        port,
        "GET",
        "/api/user/me/dae-bundle",
        None,
        Some(&token),
    ));
    assert_eq!(bundle["schemaVersion"].as_i64().unwrap(), 1);
    assert_eq!(bundle["groups"][0]["nodeIds"][0].as_i64().unwrap(), node_id);
    let import_bundle = http_request(
        port,
        "PUT",
        "/api/user/me/dae-bundle",
        Some(&bundle.to_string()),
        Some(&token),
    );
    assert!(
        import_bundle.contains("\"imported\":true"),
        "{import_bundle}"
    );

    let config_file = http_request(
        port,
        "GET",
        "/api/user/me/dae-config-file",
        None,
        Some(&token),
    );
    assert!(
        config_file.contains("\"filename\":\"generated.dae\""),
        "{config_file}"
    );
    let preview = http_request(
        port,
        "POST",
        "/api/user/me/dae-config-file/preview",
        Some(r#"{"content":"global {}"}"#),
        Some(&token),
    );
    assert!(preview.contains("\"bundle\""), "{preview}");

    let clear_logs = http_request(port, "DELETE", "/api/logs", Some("{}"), Some(&token));
    assert!(clear_logs.contains("\"cleared\":true"), "{clear_logs}");
    let stop = http_request(port, "POST", "/api/runtime/stop", Some("{}"), Some(&token));
    assert!(stop.contains("\"stopped\":true"), "{stop}");

    child.kill().unwrap();
    let _ = child.wait();
    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn daed_export_commands_report_c10_package_surface() {
    for command in ["openapi", "flatdesc", "outline"] {
        let output = Command::new(binary())
            .args(["export", command])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "command={command} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(value.to_string().contains("go-free-product-chain-v1"));
    }
    for command in ["package-manifest", "admission-report", "webui-route-audit"] {
        let output = Command::new(binary())
            .args(["export", command])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "command={command} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(value.to_string().contains("go-free-product-chain-v1"));
    }
    let route_audit = Command::new(binary())
        .args(["export", "webui-route-audit"])
        .output()
        .unwrap();
    let route_audit: Value = serde_json::from_slice(&route_audit.stdout).unwrap();
    assert!(route_audit["pass"].as_bool().unwrap());
    assert!(route_audit["missing"].as_array().unwrap().is_empty());
    let manifest = Command::new(binary())
        .args(["export", "package-manifest"])
        .output()
        .unwrap();
    let manifest: Value = serde_json::from_slice(&manifest.stdout).unwrap();
    assert_eq!(
        manifest["binary"]["validateArgs"][0].as_str().unwrap(),
        "validate"
    );

    let systemd = Command::new(binary())
        .args(["export", "systemd-unit"])
        .output()
        .unwrap();
    assert!(systemd.status.success());
    assert!(
        String::from_utf8_lossy(&systemd.stdout).contains("ExecStartPre=/usr/bin/daed validate")
    );
    assert!(String::from_utf8_lossy(&systemd.stdout).contains("ExecStart=/usr/bin/daed run"));

    let docker = Command::new(binary())
        .args(["export", "docker-entrypoint"])
        .output()
        .unwrap();
    assert!(docker.status.success());
    assert!(String::from_utf8_lossy(&docker.stdout).contains("/usr/bin/daed validate"));
    assert!(String::from_utf8_lossy(&docker.stdout).contains("exec /usr/bin/daed run"));
}

#[test]
fn daed_resetpass_updates_daed_db_users_without_wing_db() {
    let temp = temp_dir("resetpass");
    let web = temp.join("web");
    fs::create_dir_all(&web).unwrap();
    fs::write(web.join("index.html"), "<!doctype html><title>daed</title>").unwrap();
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let mut child = Command::new(binary())
        .args(["run", "-c"])
        .arg(&temp)
        .args(["--listen", &listen, "--web-root"])
        .arg(&web)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    wait_for_http(port, "/api/health", &mut child);
    let create = http_request(
        port,
        "POST",
        "/api/auth/users",
        Some(r#"{"username":"admin","password":"abc123"}"#),
        None,
    );
    assert!(create.contains("201 Created"), "{create}");
    child.kill().unwrap();
    let _ = child.wait();

    let wing = temp.join("wing.db");
    fs::write(&wing, b"protected rollback db").unwrap();
    let wing_hash_before = sha256(&wing);
    let reset = Command::new(binary())
        .args(["resetpass", "-c"])
        .arg(&temp)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        reset.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&reset.stderr)
    );
    assert_eq!(wing_hash_before, sha256(&wing));
    let report: Value = serde_json::from_slice(&reset.stdout).unwrap();
    let password = report["users"][0]["password"].as_str().unwrap().to_owned();
    assert_eq!(report["users"][0]["username"].as_str().unwrap(), "admin");

    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let mut child = Command::new(binary())
        .args(["run", "-c"])
        .arg(&temp)
        .args(["--listen", &listen, "--web-root"])
        .arg(&web)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_http(port, "/api/health", &mut child);
    let token = http_request(
        port,
        "POST",
        "/api/auth/token",
        Some(&format!(
            r#"{{"username":"admin","password":"{password}"}}"#
        )),
        None,
    );
    assert!(token.contains("\"token\""), "{token}");
    child.kill().unwrap();
    let _ = child.wait();

    fs::remove_dir_all(temp).unwrap();
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("daed-product-{name}-{}", fastrand::u64(..)));
    fs::create_dir_all(&path).unwrap();
    path
}

fn spawn_text_server(body: &str) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = body.to_owned();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request);
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    });
    (port, handle)
}

fn spawn_tcp_probe_server() -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
    });
    (port, handle)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_http(port: u16, path: &str, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            panic!("daed exited early: {status}; stderr={stderr}");
        }
        if let Ok(response) = try_http_request(port, "GET", path, None, None) {
            if response.contains("200 OK") {
                return;
            }
        }
        assert!(Instant::now() < deadline, "timed out waiting for daed");
        thread::sleep(Duration::from_millis(50));
    }
}

fn http_request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> String {
    try_http_request(port, method, path, body, token).unwrap()
}

fn try_http_request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    let body = body.unwrap_or("");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
    )?;
    if let Some(token) = token {
        write!(stream, "Authorization: Bearer {token}\r\n")?;
    }
    if !body.is_empty() {
        write!(
            stream,
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )?;
    }
    write!(stream, "\r\n")?;
    if !body.is_empty() {
        write!(stream, "{body}")?;
    }
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn http_request_until(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: Option<&str>,
    needle: &str,
) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let body = body.unwrap_or("");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
    )
    .unwrap();
    if let Some(token) = token {
        write!(stream, "Authorization: Bearer {token}\r\n").unwrap();
    }
    if !body.is_empty() {
        write!(
            stream,
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )
        .unwrap();
    }
    write!(stream, "\r\n").unwrap();
    if !body.is_empty() {
        write!(stream, "{body}").unwrap();
    }

    let mut response = String::new();
    let mut buf = [0_u8; 1024];
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(3) {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(read) => {
                response.push_str(&String::from_utf8_lossy(&buf[..read]));
                if response.contains(needle) {
                    break;
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                if response.contains(needle) {
                    break;
                }
            }
            Err(err) => panic!("stream request failed: {err}"),
        }
    }
    response
}

fn json_body(response: &str) -> Value {
    let (_, body) = response.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(body).unwrap()
}

fn sha256(path: &Path) -> String {
    let output = Command::new("sha256sum").arg(path).output().unwrap();
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

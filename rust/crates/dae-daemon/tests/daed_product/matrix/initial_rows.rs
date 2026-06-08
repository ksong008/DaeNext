use super::*;
#[test]
pub(crate) fn daed_resident_adapter_matrix_reports_initial_rows_admitted_without_secrets() {
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

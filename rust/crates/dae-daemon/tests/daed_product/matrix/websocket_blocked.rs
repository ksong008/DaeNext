use super::*;
#[test]
pub(crate) fn daed_resident_adapter_matrix_keeps_invalid_websocket_flow_fail_closed() {
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

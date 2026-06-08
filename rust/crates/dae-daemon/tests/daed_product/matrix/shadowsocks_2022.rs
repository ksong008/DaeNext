use super::*;
#[test]
pub(crate) fn daed_resident_adapter_matrix_reports_shadowsocks_2022_admitted() {
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

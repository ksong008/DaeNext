use super::*;
#[test]
pub(crate) fn daed_resident_adapter_matrix_reports_admitted_selected_node_without_links() {
    let temp = temp_dir("resident-adapter-matrix-admitted");
    let config = temp.join("config.dae");
    let primary_host = fixture_host(FixtureEndpoint::Primary);
    let source = vless_fixture_url("", &primary_host, fixture_port(1));
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
  vless_live: '__SOURCE__'
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
        .replace("__SOURCE__", &source),
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
        live_row["generated_solver"]["nativeReady"]
            .as_bool()
            .unwrap(),
        false
    );
    assert_eq!(
        live_row["generated_solver"]["productionReady"]
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
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(&fixture_client_id()));
    assert!(!stdout.contains(&["vless", "://"].concat()));
    let _ = fs::remove_dir_all(temp);
}

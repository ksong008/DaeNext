use super::*;
use serde_json::json;

#[test]
pub(crate) fn daed_resident_adapter_matrix_keeps_invalid_websocket_flow_fail_closed() {
    let temp = temp_dir("resident-adapter-source-websocket-flow-blocked");
    let config = temp.join("config.dae");
    let source = vless_transport_fixture_url("websocket", "/ws", "xtls-rprx-vision");
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
  vless_ws: '__SOURCE__'
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
    assert_eq!(report["schemaVersion"], 2);
    assert!(
        report["config"]
            .as_str()
            .is_some_and(|identity| identity.starts_with("sha256:"))
    );
    assert_eq!(report["configPathRedacted"], true);
    assert_eq!(report["status"].as_str().unwrap(), "blocked");
    assert_eq!(
        report["planner_error"].as_str().unwrap(),
        "resident matrix operation failed; inspect protected daemon logs for details"
    );

    let formal_rows = report["full_matrix_rows"].as_array().unwrap();
    let vless = formal_rows
        .iter()
        .find(|row| row["formal_matrix_handler"].as_str() == Some("vless"))
        .unwrap();
    assert_eq!(vless["planner_status"], "blocked");
    assert_eq!(vless["candidate_count"], 1);
    assert_eq!(vless["admitted_count"], 0);
    assert_eq!(vless["blocked_count"], 1);
    assert_eq!(vless["candidates"][0]["node_tag"], "vless_ws");
    assert_eq!(
        vless["candidates"][0]["node_tag_source"],
        "explicit-display-tag"
    );
    assert_eq!(
        vless["candidates"][0]["error"],
        "resident matrix operation failed; inspect protected daemon logs for details"
    );
    assert_eq!(report["source_admission_diagnostic_count"], 1);
    assert_eq!(report["source_materialization_failure_count"], 1);
    assert_eq!(report["unclassified_source_materialization_count"], 0);
    assert_eq!(report["source_ownership_mismatch_count"], 0);
    assert_eq!(report["current_config_source_admission_status"], "blocked");
    assert_eq!(
        report["current_config_source_admission_reason_ids"],
        json!(["source-materialization-failed"])
    );
    let diagnostic = &report["source_admission_diagnostics"][0];
    assert_eq!(diagnostic["status"], "source-materialization-failed");
    assert_eq!(diagnostic["nodeTag"], "vless_ws");
    assert_eq!(diagnostic["nodeTagSource"], "explicit-display-tag");
    assert_eq!(diagnostic["scheme"], "vless");
    assert!(
        diagnostic["nodeIdentity"]
            .as_str()
            .is_some_and(|identity| identity.starts_with("sha256:"))
    );

    let rows = report["expanded_source_matrix_rows"].as_array().unwrap();
    let websocket = rows
        .iter()
        .find(|row| row["shapeId"].as_str().unwrap() == "stream-wrapper-websocket")
        .unwrap();
    assert_eq!(websocket["planner_status"].as_str().unwrap(), "not-present");
    assert_eq!(websocket["schemaVersion"], 2);
    assert_eq!(websocket["currentConfigStatus"], "blocked");
    assert!(websocket["capabilityReasonId"].is_null());
    assert_eq!(websocket["candidate_count"].as_u64().unwrap(), 0);
    assert_eq!(websocket["admitted_count"].as_u64().unwrap(), 0);
    assert_eq!(websocket["blocked_count"].as_u64().unwrap(), 0);
    assert!(websocket["candidates"].as_array().unwrap().is_empty());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(&["vless", "://"].concat()));
    assert!(!stdout.contains(&config.display().to_string()));
    let _ = fs::remove_dir_all(temp);
}

use super::*;

#[test]
pub(crate) fn daed_resident_adapter_matrix_keeps_removed_connect_udp_source_fail_closed() {
    let temp = temp_dir("resident-adapter-matrix-connect-udp");
    let config = temp.join("config.dae");
    let source = "masque://matrix-user:matrix-secret@127.0.0.1:29443?transport=h3&auth=basic&template=%2F.well-known%2Fmasque%2Fudp%2F%7Btarget_host%7D%2F%7Btarget_port%7D%2F&sni=localhost&allowInsecure=1#matrix-connect-udp";
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
  connect_udp_live: '__SOURCE__'
}
group {
  proxy {
    filter: name(connect_udp_live)
    policy: fixed(0)
  }
}
routing {
  fallback: proxy
}
"#
        .replace("__SOURCE__", source),
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
    assert_eq!(report["status"].as_str(), Some("blocked"));
    assert_eq!(report["planner_admitted"].as_bool(), Some(false));
    assert_eq!(report["selected_node_fail_closed"].as_bool(), Some(true));
    assert!(
        report["full_matrix_rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["formal_matrix_handler"].as_str() != Some("connect-udp"))
    );

    let rows = report["expanded_source_matrix_rows"].as_array().unwrap();
    for shape_id in ["connect-udp-h2-endpoint", "connect-udp-h3-endpoint"] {
        let row = rows
            .iter()
            .find(|row| row["shapeId"].as_str() == Some(shape_id))
            .unwrap_or_else(|| panic!("missing removed source row {shape_id}"));
        assert_eq!(row["sourceSupport"].as_str(), Some("not-source-supported"));
        assert_eq!(row["planner_status"].as_str(), Some("not-source-supported"));
        assert_eq!(
            row["candidateEvaluation"].as_str(),
            Some("source-policy-rejected")
        );
        assert_eq!(
            row["capabilityReasonId"].as_str(),
            Some("unsupported-source-policy")
        );
        assert_eq!(row["candidate_count"].as_u64(), Some(0));
        assert_eq!(row["admitted_count"].as_u64(), Some(0));
        assert_eq!(row["blocked_count"].as_u64(), Some(0));
        assert_eq!(row["classifiedCandidateCount"].as_u64(), Some(0));
        assert_eq!(
            row["classifiedCurrentConfigStatus"].as_str(),
            Some("not-present")
        );
        assert!(row["candidates"].as_array().unwrap().is_empty());
    }
    assert_eq!(report["current_config_source_admission_status"], "resolved");
    assert!(
        report["current_config_source_admission_reason_ids"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(source));
    assert!(!stdout.contains("matrix-secret"));
    let _ = fs::remove_dir_all(temp);
}

use super::*;
#[test]
pub(crate) fn daed_resident_adapter_matrix_admits_httpupgrade_source_shape() {
    let temp = temp_dir("resident-adapter-source-httpupgrade-admitted");
    let config = temp.join("config.dae");
    let source = vless_transport_fixture_url("httpupgrade", "/resource", "");
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
  vless_httpupgrade: '__SOURCE__'
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
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(&["vless", "://"].concat()));
    assert!(!stdout.contains(&fixture_client_id()));
    let _ = fs::remove_dir_all(temp);
}

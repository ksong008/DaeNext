use super::*;

#[test]
fn resident_adapter_matrix_redacts_remote_evidence_source_and_error() {
    let temp = temp_dir("resident-adapter-matrix-evidence-redaction");
    let config = temp.join("config.dae");
    let evidence = temp.join("private-live-evidence-token.json");
    let source = vless_transport_fixture_url("websocket", "/matrix-redaction", "");
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
    fs::write(
        &evidence,
        r#"{"schema":"native-current-live-resident-matrix","schemaVersion":1}"#,
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(binary())
        .args(["resident-adapter-matrix", "-c"])
        .arg(&config)
        .arg("--json")
        .env("RESIDENT_LIVE_MATRIX_EVIDENCE", &evidence)
        .env_remove("DAE_RESIDENT_LIVE_MATRIX_EVIDENCE")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let live_evidence = &report["resident_live_adapter_remote_live_matrix_evidence"];
    assert!(
        live_evidence["source"]
            .as_str()
            .is_some_and(|identity| identity.starts_with("sha256:"))
    );
    assert_eq!(live_evidence["sourceRedacted"], true);
    assert_eq!(
        live_evidence["error"],
        "remote live matrix evidence is invalid; source detail redacted"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(&evidence.display().to_string()));
    assert!(!stdout.contains(&config.display().to_string()));
    let _ = fs::remove_dir_all(temp);
}

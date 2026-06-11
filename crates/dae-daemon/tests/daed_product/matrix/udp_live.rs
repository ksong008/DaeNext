use super::*;
#[test]
pub(crate) fn daed_resident_adapter_udp_live_reports_protocol_closed_without_secrets() {
    let temp = temp_dir("resident-adapter-udp-live-http");
    let config = temp.join("config.dae");
    let http_live =
        http_proxy_fixture_url(&fixture_host(FixtureEndpoint::Primary), fixture_port(1));
    let udp_target = format!(
        "{}:{}",
        std::net::Ipv4Addr::LOCALHOST,
        fixture_endpoint_port(FixtureEndpoint::Authority)
    );
    let config_text = r#"
global {
  lan_interface: daerust0
  allow_insecure: false
  so_mark_from_dae: 0
  mptcp: false
}
node {
  http_live: '__HTTP_LIVE__'
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
"#
    .replace("__HTTP_LIVE__", &http_live);
    fs::write(&config, config_text).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(binary())
        .args([
            "resident-adapter-udp-live",
            "-c",
            config.to_str().unwrap(),
            "--target",
            &udp_target,
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
        "resident-udp-session-manager"
    );
    assert_eq!(
        http_row["packetSession"]["packetSemantics"]
            .as_str()
            .unwrap(),
        "protocol-closed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(&fixture_user()));
    assert!(!stdout.contains(&fixture_secret()));
    let _ = fs::remove_dir_all(temp);
}

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
    assert_eq!(report["schemaVersion"], 2);
    assert!(
        report["config"]
            .as_str()
            .is_some_and(|identity| identity.starts_with("sha256:"))
    );
    assert_eq!(report["configPathRedacted"], true);
    let rows = report["rows"].as_array().unwrap();
    let http_row = rows
        .iter()
        .find(|row| row["formal_matrix_handler"].as_str().unwrap() == "http-proxy")
        .unwrap();
    assert_eq!(http_row["status"].as_str().unwrap(), "protocol-closed");
    assert!(http_row["ok"].as_bool().unwrap());
    assert!(http_row["protocol_closed"].as_bool().unwrap());
    assert_eq!(http_row["node_tag"], "http_live");
    assert_eq!(http_row["node_tag_source"], "explicit-display-tag");
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
    assert!(!stdout.contains(&config.display().to_string()));
    let _ = fs::remove_dir_all(temp);
}

#[test]
fn daed_resident_adapter_udp_live_redacts_derived_source_and_probe_error() {
    let temp = temp_dir("resident-adapter-udp-live-redaction");
    let config = temp.join("private-config-path.dae");
    let source = socks5_fixture_url(&std::net::Ipv4Addr::LOCALHOST.to_string(), 1);
    let udp_target = format!(
        "{}:{}",
        std::net::Ipv4Addr::LOCALHOST,
        fixture_endpoint_port(FixtureEndpoint::Authority)
    );
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
  '__SOURCE__'
}
routing {
  fallback: direct
}
"#
        .replace("__SOURCE__", &source),
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(binary())
        .args(["resident-adapter-udp-live", "-c"])
        .arg(&config)
        .args(["--target", &udp_target, "--payload", "probe", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schemaVersion"], 2);
    assert_eq!(report["configPathRedacted"], true);
    let socks = report["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["formal_matrix_handler"] == "socks5")
        .unwrap();
    assert_eq!(socks["status"], "fail");
    assert_eq!(socks["node_tag_source"], "derived-link-hash");
    assert!(
        socks["node_tag"]
            .as_str()
            .is_some_and(|identity| identity.starts_with("sha256:"))
    );
    assert_eq!(socks["reasonId"], "udp-probe-exchange-failed");
    assert_eq!(
        socks["error"],
        "resident UDP probe failed; protected detail redacted"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(&source));
    assert!(!stdout.contains(&fixture_user()));
    assert!(!stdout.contains(&fixture_secret()));
    assert!(!stdout.contains(&config.display().to_string()));
    let _ = fs::remove_dir_all(temp);
}

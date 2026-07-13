use super::*;

#[test]
pub(crate) fn daed_resident_adapter_matrix_reports_explicit_connect_udp_shape() {
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
    let row = report["full_matrix_rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["formal_matrix_handler"].as_str() == Some("connect-udp"))
        .expect("missing CONNECT-UDP current-config row");
    assert_eq!(row["planner_status"].as_str(), Some("admitted"));
    assert_eq!(row["candidate_count"].as_u64(), Some(1));
    assert_eq!(row["admitted_count"].as_u64(), Some(1));
    assert_eq!(row["tcp_live_adapter"].as_bool(), Some(false));
    assert_eq!(row["tcp_semantics"].as_str(), Some("protocol-closed"));
    assert_eq!(row["tcp_path_ready"].as_bool(), Some(true));
    assert_eq!(row["udp_live_adapter"].as_bool(), Some(true));
    assert_eq!(row["udp_semantics"].as_str(), Some("relay"));
    assert_eq!(
        row["generated_solver"]["executableGraphReady"].as_bool(),
        Some(true)
    );
    assert_eq!(
        row["generated_solver"]["tcpLoopbackReady"].as_bool(),
        Some(true)
    );
    assert_eq!(
        row["generated_solver"]["udpLoopbackReady"].as_bool(),
        Some(true)
    );
    let components = &row["candidates"][0]["runtimeComponents"];
    assert_eq!(
        components["streamWrapperFactory"]["provider"].as_str(),
        Some("resident-connect-udp-h3-datagram-session")
    );
    assert_eq!(
        components["streamWrapperFactory"]["runtimeLimits"]["carrierScope"].as_str(),
        Some("generation-owned-h3-actor-pool")
    );
    assert_eq!(
        components["generationCache"]["sharedProviderCaches"][1].as_str(),
        Some("connect-udp-h3-actor-pool")
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(source));
    assert!(!stdout.contains("matrix-secret"));
    let _ = fs::remove_dir_all(temp);
}

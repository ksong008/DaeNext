use super::*;

fn xhttp_child() -> ResidentProxyPlan {
    let mut proxy = ResidentProxyPlan {
        graph_id: "resident-graph:xhttp-chain".to_owned(),
        graph_link_hash: "sha256:xhttp-chain".to_owned(),
        redacted_link_source: "vless://<redacted>".to_owned(),
        protocol: "vless",
        group_name: "group".to_owned(),
        group_policy: "fixed".to_owned(),
        node_tag: "node".to_owned(),
        server_host: "child.invalid".to_owned(),
        server_port: 443,
        server_name: "child.invalid".to_owned(),
        alpn: vec!["h2".to_owned()],
        flow: String::new(),
        net: "xhttp".to_owned(),
        stream_host: "child.invalid".to_owned(),
        stream_path: "/xhttp".to_owned(),
        xhttp_download: None,
        xhttp_mode: ResidentXhttpMode::PacketUp,
        xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
        xhttp_xmux: Some(ResidentXhttpXmuxPlan::official_default()),
        tls: "tls".to_owned(),
        allow_insecure: false,
        tls_fragment: None,
        utls_fingerprint: None,
        reality: None,
        handler: ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [1; 16] },
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    };
    proxy.materialize_execution();
    proxy
}

#[test]
fn xhttp_child_is_rejected_by_the_typed_parent_chain_gate() {
    let child = xhttp_child();

    assert!(matches!(
        child.execution_plan().wrapper,
        ResidentStreamWrapperPlan::Xhttp(_)
    ));
    assert!(!resident_chain_child_supported(&child));
}

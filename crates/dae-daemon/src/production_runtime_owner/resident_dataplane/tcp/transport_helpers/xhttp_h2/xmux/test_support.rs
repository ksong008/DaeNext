use super::super::resolved_endpoint::XhttpResolvedEndpointIdentity;
use super::*;
use crate::production_runtime_owner::resident_dataplane::plan::ResidentRealityUnderlayPlan;
use std::sync::Arc;

pub(super) fn download_test_plan(runtime_generation: u64) -> ResidentXhttpXmuxPlan {
    ResidentXhttpXmuxPlan {
        runtime_generation,
        physical_connection_limit: 2,
        max_concurrency: Some((1, 1)),
        max_connections: None,
        c_max_reuse_times: None,
        h_max_request_times: Some((600, 900)),
        h_max_reusable_secs: Some((1800, 3000)),
        h_keep_alive_period: 0,
    }
}

pub(super) fn download_test_key(
    runtime_generation: u64,
    graph_link_hash: &str,
    reality_seed: u8,
    remote: &str,
    protocol: ResidentXhttpHttpVersion,
) -> XhttpXmuxKey {
    let plan = download_test_plan(runtime_generation);
    let reality = ResidentRealityUnderlayPlan {
        public_key: [reality_seed; 32],
        short_id: vec![reality_seed; 8],
        spider_x: format!("/route-{reality_seed}"),
    };
    let endpoint = ResidentXhttpEndpointPlan {
        server_host: "download.invalid".to_owned(),
        server_port: 443,
        server_name: "download.invalid".to_owned(),
        alpn: vec![protocol.alpn_label().to_owned()],
        stream_host: "download.invalid".to_owned(),
        stream_path: "/xhttp".to_owned(),
        mode: ResidentXhttpMode::PacketUp,
        settings: ResidentXhttpSettingsPlan::official_default(),
        xmux: Some(plan.clone()),
        allow_insecure: false,
        tls_fragment: None,
        reality: Some(reality.clone()),
    };
    let mut proxy = ResidentProxyPlan {
        graph_id: format!("resident-graph:{graph_link_hash}"),
        graph_link_hash: graph_link_hash.to_owned(),
        redacted_link_source: "vless://<redacted>".to_owned(),
        protocol: "vless",
        group_name: "group".to_owned(),
        group_policy: "fixed".to_owned(),
        node_tag: "node".to_owned(),
        server_host: endpoint.server_host.clone(),
        server_port: endpoint.server_port,
        server_name: endpoint.server_name.clone(),
        alpn: endpoint.alpn.clone(),
        flow: String::new(),
        net: "xhttp".to_owned(),
        stream_host: endpoint.stream_host.clone(),
        stream_path: endpoint.stream_path.clone(),
        xhttp_download: Some(endpoint.clone()),
        xhttp_mode: endpoint.mode,
        xhttp_settings: endpoint.settings.clone(),
        xhttp_xmux: Some(plan.clone()),
        tls: "reality".to_owned(),
        allow_insecure: false,
        tls_fragment: None,
        utls_fingerprint: None,
        reality: Some(reality),
        handler: ResidentProxyProtocolPlan::VlessVisionTcpTls {
            key: [1; 16],
            encryption: None,
        },
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    };
    proxy.materialize_execution();
    let binding = ResidentProxyBinding::resident(
        Arc::new(proxy),
        dae_runtime_control::OwnerGeneration::new(runtime_generation),
    )
    .unwrap();
    let resolved = XhttpResolvedEndpointIdentity::from_candidates(&[remote.parse().unwrap()]);
    XhttpXmuxKey::download(&binding, &endpoint, &resolved, &plan, 0, false).unwrap()
}

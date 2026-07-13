use super::*;

pub(crate) fn build_masque_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = MasqueLink::parse(&link)
        .map_err(|err| format!("parse CONNECT-UDP node {node_tag}: {err}"))?;
    let graph = resident_graph_identity(&link);
    let mptcp = parsed.transport == MasqueTransport::H2 && config.global.mptcp;
    let authentication = match parsed.authentication {
        MasqueAuthentication::None => ResidentConnectUdpAuthPlan::None,
        MasqueAuthentication::Basic { username, password } => {
            ResidentConnectUdpAuthPlan::Basic { username, password }
        }
    };
    let (tls, net, handler) = match parsed.transport {
        MasqueTransport::H2 => (
            "tls".to_owned(),
            "connect-udp-h2".to_owned(),
            ResidentProxyProtocolPlan::ConnectUdpH2Tls {
                authentication,
                target_template: parsed.target_template.clone(),
            },
        ),
        MasqueTransport::H3 => (
            "quic".to_owned(),
            "connect-udp-h3".to_owned(),
            ResidentProxyProtocolPlan::ConnectUdpH3Tls {
                authentication,
                target_template: parsed.target_template.clone(),
            },
        ),
    };
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "connect-udp",
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name: parsed.sni,
        alpn: vec![parsed.transport.alpn().to_owned()],
        flow: String::new(),
        net,
        stream_host: String::new(),
        stream_path: parsed.target_template,
        xhttp_download: None,
        xhttp_mode: ResidentXhttpMode::PacketUp,
        xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
        xhttp_xmux: None,
        tls,
        allow_insecure: parsed.allow_insecure || config.global.allow_insecure,
        tls_fragment: None,
        utls_fingerprint: None,
        reality: None,
        handler,
        execution: None,
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp,
    })
}

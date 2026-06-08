use super::*;
pub(crate) fn build_socks5_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = Url::parse(&link).map_err(|err| format!("parse SOCKS node {node_tag}: {err}"))?;
    if !matches!(parsed.scheme(), "socks" | "socks5") {
        return Err(format!(
            "resident dataplane socks5 handler got unsupported scheme {} for node {node_tag}",
            parsed.scheme()
        ));
    }
    let server_host = parsed
        .host_str()
        .ok_or_else(|| format!("parse SOCKS node {node_tag}: missing host"))?
        .to_owned();
    let server_port = parsed.port().unwrap_or(1080);
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "socks5".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host,
        server_port,
        server_name: String::new(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        tls: "none".to_owned(),
        allow_insecure: false,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::Socks5Tcp {
            username: parsed.username().to_owned(),
            password: parsed.password().unwrap_or_default().to_owned(),
        },
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

pub(crate) fn build_http_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = HttpProxyLink::parse(&link)
        .map_err(|err| format!("parse HTTP proxy node {node_tag}: {err}"))?;
    if parsed.allow_insecure || config.global.allow_insecure {
        return Err(format!(
            "resident dataplane HTTP proxy handler does not admit allow_insecure for node {node_tag}"
        ));
    }
    if parsed.protocol == HttpScheme::Https && !parsed.utls_imitate.is_empty() {
        return Err(format!(
            "resident dataplane HTTPS proxy handler does not admit fingerprint/utls imitation for node {node_tag}"
        ));
    }
    if parsed.protocol == HttpScheme::Https && parsed.tls_implementation != "tls" {
        return Err(format!(
            "resident dataplane HTTPS proxy handler admits standard tlsImplementation only for node {node_tag}"
        ));
    }
    let (tls, server_name, alpn) = match parsed.protocol {
        HttpScheme::Http => ("none".to_owned(), String::new(), Vec::new()),
        HttpScheme::Https => (
            "tls".to_owned(),
            parsed.effective_sni(),
            resident_csv_values(&parsed.alpn),
        ),
    };
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "http-proxy".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name,
        alpn,
        flow: String::new(),
        net: if parsed.transport {
            "http-transport".to_owned()
        } else {
            "tcp".to_owned()
        },
        stream_host: parsed.host.clone(),
        stream_path: parsed.path.clone(),
        tls,
        allow_insecure: false,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::HttpProxyTcp {
            username: parsed.username,
            password: parsed.password,
            transport: parsed.transport,
            transport_host: parsed.host,
            transport_path: parsed.path,
        },
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

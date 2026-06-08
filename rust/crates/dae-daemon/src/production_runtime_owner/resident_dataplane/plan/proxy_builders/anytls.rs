use super::*;
pub(crate) fn build_anytls_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        AnyTLSLink::parse(&link).map_err(|err| format!("parse AnyTLS node {node_tag}: {err}"))?;
    let allow_insecure = parsed.insecure || config.global.allow_insecure;
    let url =
        Url::parse(&link).map_err(|err| format!("parse AnyTLS endpoint {node_tag}: {err}"))?;
    let server_host = url
        .host_str()
        .ok_or_else(|| format!("parse AnyTLS endpoint {node_tag}: missing host"))?
        .to_owned();
    let server_port = url.port().unwrap_or(443);
    let utls_fingerprint = resident_utls_fingerprint_plan(config, None)?;
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "anytls".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host,
        server_port,
        server_name: parsed.tls_server_name,
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        tls: "tls".to_owned(),
        allow_insecure,
        tls_fragment: resident_tls_fragment_plan(config)?,
        utls_fingerprint,
        handler: ResidentProxyProtocolPlan::AnyTlsTcpTls { auth: parsed.auth },
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

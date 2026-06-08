use super::*;

pub(crate) fn build_shadowsocksr_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = ShadowsocksRLink::parse(&link)
        .map_err(|err| format!("parse ShadowsocksR node {node_tag}: {err}"))?;
    if !shadowsocksr_stream_cipher_supported(&parsed.cipher) {
        return Err(format!(
            "resident dataplane ShadowsocksR legacy stream executor admits AES CFB ciphers only for node {node_tag}; got {}",
            parsed.cipher
        ));
    }
    if parsed.proto != "origin" || parsed.obfs != "http_simple" {
        return Err(format!(
            "resident dataplane ShadowsocksR legacy stream executor admits origin/http_simple only for node {node_tag}; got {}/{}",
            parsed.proto, parsed.obfs
        ));
    }
    if !parsed.proto_param.is_empty() {
        return Err(format!(
            "resident dataplane ShadowsocksR legacy stream executor admits empty protocol parameter only for node {node_tag}"
        ));
    }
    let obfs_host = if parsed.obfs_param.is_empty() {
        parsed.server.clone()
    } else {
        parsed.obfs_param.clone()
    };
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "shadowsocksr".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name: String::new(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "legacy-obfs".to_owned(),
        stream_host: obfs_host.clone(),
        stream_path: String::new(),
        tls: "legacy-cipher".to_owned(),
        allow_insecure: false,
        tls_fragment: None,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp {
            cipher: parsed.cipher,
            password: parsed.password,
            obfs_host,
            obfs_port: parsed.port,
        },
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

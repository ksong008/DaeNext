use super::*;
pub(crate) fn build_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    if link.contains(" -> ") || link.contains("->") {
        return build_chained_proxy_plan(config, group_name, node_tag, link);
    }
    let scheme = link_scheme(&link).unwrap_or_default();
    let mut plan = match scheme.as_str() {
        "vless" => build_vless_proxy_plan(config, group_name, node_tag, link),
        "socks" | "socks5" => build_socks5_proxy_plan(config, group_name, node_tag, link),
        "http" | "https" => build_http_proxy_plan(config, group_name, node_tag, link),
        "ss" | "shadowsocks" => build_shadowsocks_proxy_plan(config, group_name, node_tag, link),
        "ssr" | "shadowsocksr" => build_shadowsocksr_proxy_plan(config, group_name, node_tag, link),
        "trojan" | "trojan-go" => build_trojan_proxy_plan(config, group_name, node_tag, link),
        "anytls" => build_anytls_proxy_plan(config, group_name, node_tag, link),
        "vmess" => build_vmess_proxy_plan(config, group_name, node_tag, link),
        "hysteria2" | "hy2" => build_hysteria2_proxy_plan(config, group_name, node_tag, link),
        "tuic" => build_tuic_proxy_plan(config, group_name, node_tag, link),
        "juicity" => build_juicity_proxy_plan(config, group_name, node_tag, link),
        _ => Err(format!(
            "resident dataplane selected unsupported {scheme} node {node_tag}; no resident executor is admitted for this node shape; shape remains fail-closed for this config",
        )),
    }?;
    plan.compact_allocations();
    Ok(plan)
}

pub(crate) fn build_chained_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        parse_link_chain(&link).map_err(|err| format!("parse chained node {node_tag}: {err}"))?;
    if parsed.nodes.len() != 2 {
        return Err(format!(
            "resident dataplane nested chain executor admits two-node chains only for node {node_tag}; got {} node(s)",
            parsed.nodes.len()
        ));
    }
    let parent_node = parsed.nodes[0].clone();
    let child_node = parsed.nodes[1].clone();
    let parent = build_proxy_plan(
        config,
        group_name.clone(),
        format!("{node_tag}:parent"),
        parent_node.raw,
    )?;
    let mut child = build_proxy_plan(config, group_name, node_tag.clone(), child_node.raw)?;
    if !resident_chain_parent_supported(&parent) {
        return Err(format!(
            "resident dataplane nested chain executor admits plain SOCKS5/HTTP CONNECT parent only for node {node_tag}; got {}",
            parent.protocol
        ));
    }
    if !resident_chain_child_supported(&child) {
        return Err(format!(
            "resident dataplane nested chain executor admits resident TCP child handlers only for node {node_tag}; got {}/{}",
            child.protocol, child.net
        ));
    }
    let graph = resident_graph_identity(&link);
    child.graph_id = graph.graph_id;
    child.graph_link_hash = graph.link_hash;
    child.redacted_link_source = graph.redacted_link_source;
    child.chain_parent = Some(Arc::new(parent));
    child.compact_allocations();
    Ok(child)
}

pub(crate) fn resident_chain_parent_supported(parent: &ResidentProxyPlan) -> bool {
    match &parent.handler {
        ResidentProxyProtocolPlan::Socks5Tcp { .. } => parent.tls == "none",
        ResidentProxyProtocolPlan::HttpProxyTcp { .. } => parent.tls == "none",
        _ => false,
    }
}

pub(crate) fn resident_chain_child_supported(child: &ResidentProxyPlan) -> bool {
    match &child.handler {
        ResidentProxyProtocolPlan::Socks5Tcp { .. } => true,
        ResidentProxyProtocolPlan::HttpProxyTcp { .. } => child.tls == "none",
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp { .. }
        | ResidentProxyProtocolPlan::Shadowsocks2022Tcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. }
        | ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. } => true,
        ResidentProxyProtocolPlan::VmessAeadTcp { .. } => {
            matches!(child.net.as_str(), "tcp" | "websocket" | "httpupgrade") && child.tls == "none"
        }
        _ => false,
    }
}

use super::*;

#[path = "entry_chain/udp_passthrough.rs"]
mod udp_passthrough;
use self::udp_passthrough::reject_requested_udp_passthrough;

pub(crate) fn build_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    reject_requested_udp_passthrough(&link, &node_tag)?;
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
    plan.apply_effective_so_mark_from_dae();
    plan.materialize_execution();
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
    if parsed.nodes.len() < 2 {
        return Err(format!(
            "resident dataplane nested chain executor requires at least two nodes for node {node_tag}; got {} node(s)",
            parsed.nodes.len()
        ));
    }
    let child_node = parsed.nodes.last().cloned().ok_or_else(|| {
        format!("resident dataplane nested chain parser returned no child for node {node_tag}")
    })?;
    let mut child = build_proxy_plan(config, group_name, node_tag.clone(), child_node.raw)?;
    let mut parent_chain: Option<Arc<ResidentProxyPlan>> = None;
    for (index, parent_node) in parsed.nodes[..parsed.nodes.len() - 1]
        .iter()
        .enumerate()
        .rev()
    {
        let mut parent = build_proxy_plan(
            config,
            child.group_name.clone(),
            format!("{node_tag}:parent{index}"),
            parent_node.raw.clone(),
        )?;
        parent.chain_parent = parent_chain;
        parent.compact_allocations();
        if !resident_chain_parent_supported(&parent) {
            return Err(format!(
                "resident dataplane nested chain executor admits plain SOCKS5/HTTP CONNECT parent only for node {node_tag}; parent {index} got {}",
                parent.protocol
            ));
        }
        parent_chain = Some(Arc::new(parent));
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
    child.chain_parent = parent_chain;
    child.compact_allocations();
    Ok(child)
}

pub(crate) fn resident_chain_parent_supported(parent: &ResidentProxyPlan) -> bool {
    let execution = parent.execution_plan();
    match execution.protocol {
        ResidentProtocolShape::Socks5 => execution.security == ResidentSecurityUnderlayPlan::None,
        ResidentProtocolShape::HttpProxy => {
            execution.security == ResidentSecurityUnderlayPlan::None
                && execution.wrapper == ResidentStreamWrapperPlan::None
        }
        _ => false,
    }
}

pub(crate) fn resident_chain_child_supported(child: &ResidentProxyPlan) -> bool {
    let execution = child.execution_plan();
    match execution.protocol {
        ResidentProtocolShape::Socks5 => true,
        ResidentProtocolShape::HttpProxy => {
            execution.security == ResidentSecurityUnderlayPlan::None
        }
        ResidentProtocolShape::ShadowsocksAead
        | ResidentProtocolShape::Shadowsocks2022
        | ResidentProtocolShape::ShadowsocksSimpleObfsHttp
        | ResidentProtocolShape::ShadowsocksSimpleObfsTls
        | ResidentProtocolShape::ShadowsocksV2rayPluginTlsWebSocket
        | ResidentProtocolShape::Shadowsocks2022SimpleObfsHttp
        | ResidentProtocolShape::ShadowsocksRHttpSimple => true,
        ResidentProtocolShape::VmessAead => {
            execution.security == ResidentSecurityUnderlayPlan::None
                && matches!(
                    execution.wrapper,
                    ResidentStreamWrapperPlan::None
                        | ResidentStreamWrapperPlan::TcpHttpHeader
                        | ResidentStreamWrapperPlan::WebSocket
                        | ResidentStreamWrapperPlan::HttpUpgrade
                )
        }
        _ => false,
    }
}

#[cfg(test)]
#[path = "entry_chain/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "entry_chain/udp_passthrough_tests.rs"]
mod udp_passthrough_tests;

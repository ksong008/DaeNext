use std::collections::BTreeMap;

use dae_config::{Config, DynamicFunctionValue, Group};
use dae_outbound::vless::{VLESSLink, password_to_key};

#[derive(Clone, Debug)]
pub(super) struct ResidentProxyPlan {
    pub(super) protocol: String,
    pub(super) group_name: String,
    pub(super) node_tag: String,
    pub(super) server_host: String,
    pub(super) server_port: u16,
    pub(super) server_name: String,
    pub(super) alpn: Vec<String>,
    pub(super) flow: String,
    pub(super) net: String,
    pub(super) tls: String,
    pub(super) allow_insecure: bool,
    pub(super) key: [u8; 16],
    pub(super) mark: u32,
    pub(super) mptcp: bool,
}

#[derive(Clone, Debug)]
pub(super) struct ResidentDataplanePlan {
    pub(super) enabled: bool,
    pub(super) unsupported_reason: Option<String>,
    pub(super) proxy: Option<ResidentProxyPlan>,
}

pub(super) fn build_resident_dataplane_plan(
    config: &Config,
) -> Result<ResidentDataplanePlan, String> {
    let node_links = tagged_node_links(config);
    let Some((group_name, node_tag, link)) = selected_proxy_node(config, &node_links)? else {
        return Ok(ResidentDataplanePlan {
            enabled: false,
            unsupported_reason: Some(
                "no user-defined routing outbound with a resolvable node link was found".to_owned(),
            ),
            proxy: None,
        });
    };
    let vless =
        VLESSLink::parse(&link).map_err(|err| format!("parse VLESS node {node_tag}: {err}"))?;
    vless
        .validate_flow_client(true)
        .map_err(|err| format!("validate VLESS flow for {node_tag}: {err}"))?;
    vless
        .validate_transport_contract()
        .map_err(|err| format!("validate VLESS transport for {node_tag}: {err}"))?;
    if vless.net != "tcp" {
        return Err(format!(
            "resident dataplane currently supports VLESS tcp transport only, got {} for node {node_tag}",
            vless.net
        ));
    }
    if vless.tls != "tls" {
        return Err(format!(
            "resident dataplane currently supports VLESS security=tls only, got {} for node {node_tag}",
            vless.tls
        ));
    }
    if vless.allow_insecure || config.global.allow_insecure {
        return Err(
            "resident VLESS TLS dataplane does not admit allow_insecure; keep Go fallback for this config"
                .to_owned(),
        );
    }
    let server_port = vless.port.parse::<u16>().map_err(|err| {
        format!(
            "invalid VLESS port {} for node {node_tag}: {err}",
            vless.port
        )
    })?;
    let key = password_to_key(&vless.id)
        .map_err(|err| format!("parse VLESS key for {node_tag}: {err}"))?;
    let server_name = if vless.sni.is_empty() {
        vless.add.clone()
    } else {
        vless.sni.clone()
    };
    let alpn = split_alpn(&vless.alpn);
    Ok(ResidentDataplanePlan {
        enabled: true,
        unsupported_reason: None,
        proxy: Some(ResidentProxyPlan {
            protocol: "vless".to_owned(),
            group_name,
            node_tag,
            server_host: vless.add,
            server_port,
            server_name,
            alpn,
            flow: vless.flow,
            net: vless.net,
            tls: vless.tls,
            allow_insecure: false,
            key,
            mark: config.global.so_mark_from_dae,
            mptcp: config.global.mptcp,
        }),
    })
}

fn selected_proxy_node(
    config: &Config,
    node_links: &BTreeMap<String, String>,
) -> Result<Option<(String, String, String)>, String> {
    for outbound in referenced_user_outbounds(config) {
        if let Some(link) = node_links.get(&outbound) {
            return Ok(Some((outbound.clone(), outbound, link.clone())));
        }
        let Some(group) = config.group.iter().find(|group| group.name == outbound) else {
            continue;
        };
        if let Some((node_tag, link)) = select_group_node(group, node_links)? {
            return Ok(Some((group.name.clone(), node_tag, link)));
        }
    }
    Ok(None)
}

fn referenced_user_outbounds(config: &Config) -> Vec<String> {
    let mut outbounds = Vec::new();
    for rule in &config.routing.rules {
        push_user_outbound(&mut outbounds, &rule.outbound.name);
    }
    match &config.routing.fallback {
        DynamicFunctionValue::String(name) => push_user_outbound(&mut outbounds, name),
        DynamicFunctionValue::Function(function) => {
            push_user_outbound(&mut outbounds, &function.name)
        }
        DynamicFunctionValue::FunctionList(functions) => {
            for function in functions {
                push_user_outbound(&mut outbounds, &function.name);
            }
        }
        DynamicFunctionValue::Nil => {}
    }
    outbounds
}

fn push_user_outbound(outbounds: &mut Vec<String>, name: &str) {
    if matches!(
        name,
        "direct" | "block" | "must_rules" | "logical_or" | "logical_and"
    ) {
        return;
    }
    if !outbounds.iter().any(|seen| seen == name) {
        outbounds.push(name.to_owned());
    }
}

fn select_group_node(
    group: &Group,
    node_links: &BTreeMap<String, String>,
) -> Result<Option<(String, String)>, String> {
    let mut candidates = Vec::<String>::new();
    for filter in &group.filter {
        for function in filter {
            if function.name == "name" && !function.not {
                for param in &function.params {
                    if param.key.is_empty() && node_links.contains_key(&param.val) {
                        candidates.push(param.val.clone());
                    }
                }
            }
        }
    }
    if candidates.is_empty() {
        candidates.extend(node_links.keys().cloned());
    }
    if candidates.is_empty() {
        return Ok(None);
    }
    let fixed_index = fixed_policy_index(&group.policy).unwrap_or(0);
    let Some(tag) = candidates
        .get(fixed_index)
        .or_else(|| candidates.first())
        .cloned()
    else {
        return Ok(None);
    };
    let link = node_links
        .get(&tag)
        .ok_or_else(|| format!("group {} selected missing node {tag}", group.name))?
        .clone();
    Ok(Some((tag, link)))
}

fn fixed_policy_index(policy: &DynamicFunctionValue) -> Option<usize> {
    let function = match policy {
        DynamicFunctionValue::Function(function) => function,
        DynamicFunctionValue::FunctionList(functions) if functions.len() == 1 => &functions[0],
        _ => return None,
    };
    if function.name != "fixed" {
        return None;
    }
    function
        .params
        .first()
        .and_then(|param| param.val.parse::<usize>().ok())
}

fn tagged_node_links(config: &Config) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for raw in &config.node {
        let (tag, link) = split_keyable_link(raw);
        if link.contains("://") {
            let tag = tag.unwrap_or_else(|| link.clone());
            out.insert(tag, link);
        }
    }
    out
}

fn split_keyable_link(raw: &str) -> (Option<String>, String) {
    let trimmed = raw.trim();
    let Some(scheme_pos) = trimmed.find("://") else {
        return (None, unquote_config_value(trimmed));
    };
    let before_scheme = &trimmed[..scheme_pos];
    if let Some(colon) = before_scheme.rfind(':') {
        let tag = unquote_config_value(&trimmed[..colon]);
        let link = unquote_config_value(&trimmed[colon + 1..]);
        if !tag.is_empty() {
            return (Some(tag), link);
        }
    }
    (None, unquote_config_value(trimmed))
}

fn unquote_config_value(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
        {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}

fn split_alpn(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_config(input: &str) -> Config {
        let sections = dae_config::parser::parse_config(input).unwrap();
        dae_config::schema::build_config(&sections).unwrap()
    }

    #[test]
    fn resident_dataplane_plan_selects_vless_group_node() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=chrome&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        pname(dae) -> must_direct
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.proxy.unwrap();
        assert!(plan.enabled);
        assert_eq!(proxy.group_name, "proxy");
        assert_eq!(proxy.node_tag, "vless_live");
        assert_eq!(proxy.server_host, "156.246.90.2");
        assert_eq!(proxy.server_port, 443);
        assert_eq!(proxy.server_name, "office.example");
        assert_eq!(proxy.flow, "xtls-rprx-vision");
        assert_eq!(proxy.alpn, ["h2", "http/1.1"]);
        assert_eq!(proxy.mark, 1234);
    }
}

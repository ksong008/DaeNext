use std::collections::BTreeMap;
use std::time::Duration;

use dae_config::{Config, DynamicFunctionValue, Group};
use dae_core_types::OutboundIndex;
use dae_datapath::TcpDialMode;
use dae_outbound::{
    shared_transport::{U_TLS_WIRE_STACK_DEFERRED, UtlsFingerprint, resolve_utls_client_hello_id},
    vless::{VLESSLink, password_to_key},
};

use super::{
    XTLS_RPRX_VISION,
    dns::{ResidentDnsPlan, build_resident_dns_plan},
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct SelectedGroupNode {
    tag: String,
    link: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentUtlsFingerprintPlan {
    pub(super) source: &'static str,
    pub(super) requested: String,
    pub(super) name: String,
    pub(super) canonical: String,
    pub(super) family: String,
    pub(super) client: String,
    pub(super) randomized: bool,
    pub(super) alpn_policy: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum GroupNodeSelection {
    Selected(SelectedGroupNode),
    NoCandidate {
        explicit_name_filter: bool,
        unresolved_names: Vec<String>,
    },
}

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
    pub(super) utls_fingerprint: Option<ResidentUtlsFingerprintPlan>,
    pub(super) key: [u8; 16],
    pub(super) mark: u32,
    pub(super) mptcp: bool,
}

#[derive(Clone, Debug)]
pub(super) struct ResidentDataplanePlan {
    pub(super) enabled: bool,
    pub(super) unsupported_reason: Option<String>,
    pub(super) proxies: BTreeMap<u8, ResidentProxyPlan>,
    pub(super) default_proxy: Option<ResidentProxyPlan>,
    pub(super) tcp_dial_mode: TcpDialMode,
    pub(super) sniffing_timeout: Duration,
    pub(super) dns: ResidentDnsPlan,
}

pub(super) fn build_resident_dataplane_plan(
    config: &Config,
) -> Result<ResidentDataplanePlan, String> {
    let node_links = tagged_node_links(config);
    let (proxies, default_outbound) = resident_proxy_plans(config, &node_links)?;
    let Some(default_proxy) = default_outbound.and_then(|outbound| proxies.get(&outbound).cloned())
    else {
        return Ok(ResidentDataplanePlan {
            enabled: false,
            unsupported_reason: Some(
                "no user-defined routing outbound with a resolvable node link was found".to_owned(),
            ),
            proxies,
            default_proxy: None,
            tcp_dial_mode: parse_tcp_dial_mode(config)?,
            sniffing_timeout: Duration::ZERO,
            dns: ResidentDnsPlan::asis(config.global.so_mark_from_dae),
        });
    };
    let tcp_dial_mode = parse_tcp_dial_mode(config)?;
    let sniffing_timeout = tcp_sniffing_timeout(config, tcp_dial_mode);
    let dns = build_resident_dns_plan(config)?;
    Ok(ResidentDataplanePlan {
        enabled: true,
        unsupported_reason: None,
        proxies,
        default_proxy: Some(default_proxy),
        tcp_dial_mode,
        sniffing_timeout,
        dns,
    })
}

fn resident_proxy_plans(
    config: &Config,
    node_links: &BTreeMap<String, String>,
) -> Result<(BTreeMap<u8, ResidentProxyPlan>, Option<u8>), String> {
    let mut proxies = BTreeMap::new();
    let mut default_outbound = None;
    for outbound in referenced_user_outbounds(config) {
        if node_links.contains_key(&outbound) {
            return Err(format!(
                "resident dataplane cannot assign direct node outbound {outbound} to a stable Go-compatible outbound index; put the node behind a group before enabling Rust resident dataplane",
            ));
        }
        let Some((group_index, group)) = config
            .group
            .iter()
            .enumerate()
            .find(|(_, group)| group.name == outbound)
        else {
            continue;
        };
        let outbound_index = (OutboundIndex::USER_DEFINED_MIN.value() as usize + group_index) as u8;
        if proxies.contains_key(&outbound_index) {
            continue;
        }
        let node = match select_group_node(group, node_links)? {
            GroupNodeSelection::Selected(node) => node,
            GroupNodeSelection::NoCandidate {
                explicit_name_filter,
                unresolved_names,
            } => {
                let names = if unresolved_names.is_empty() {
                    "<empty>".to_owned()
                } else {
                    unresolved_names.join(", ")
                };
                let reason = if explicit_name_filter {
                    format!(
                        "resident dataplane cannot resolve group {} name filter node(s): {names}; subscription-backed groups must be materialized before Rust resident dataplane can own runtime",
                        group.name
                    )
                } else {
                    format!(
                        "resident dataplane cannot resolve any node for referenced group {}",
                        group.name
                    )
                };
                return Err(reason);
            }
        };
        let proxy = build_proxy_plan(config, group.name.clone(), node.tag, node.link)?;
        default_outbound.get_or_insert(outbound_index);
        proxies.insert(outbound_index, proxy);
    }
    Ok((proxies, default_outbound))
}

fn build_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let scheme = link_scheme(&link).unwrap_or_default();
    if scheme != "vless" {
        return Err(format!(
            "resident dataplane selected unsupported {scheme} node {node_tag}; no Rust protocol handler is admitted for this node yet, keep Go outbound for this config",
        ));
    }
    let vless =
        VLESSLink::parse(&link).map_err(|err| format!("parse VLESS node {node_tag}: {err}"))?;
    vless
        .validate_flow_client(true)
        .map_err(|err| format!("validate VLESS flow for {node_tag}: {err}"))?;
    vless
        .validate_transport_contract()
        .map_err(|err| format!("validate VLESS transport for {node_tag}: {err}"))?;
    if vless.flow != XTLS_RPRX_VISION {
        return Err(format!(
            "resident dataplane vless native experiment admits only flow={XTLS_RPRX_VISION}, got '{}' for node {node_tag}; keep Go outbound for this config",
            vless.flow
        ));
    }
    if vless.net != "tcp" {
        return Err(format!(
            "resident dataplane vless handler currently supports tcp transport only, got {} for node {node_tag}",
            vless.net
        ));
    }
    if vless.tls != "tls" {
        return Err(format!(
            "resident dataplane vless handler currently supports security=tls only, got {} for node {node_tag}",
            vless.tls
        ));
    }
    if vless.allow_insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane vless TLS handler does not admit allow_insecure; keep Go fallback for this config"
                .to_owned(),
        );
    }
    let utls_fingerprint = resident_utls_fingerprint_plan(config, &vless)?;
    if let Some(utls) = &utls_fingerprint {
        if !vless_vision_fp_rust_native_experiment_enabled() {
            return Err(resident_utls_wire_not_admitted_error(utls, &node_tag));
        }
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
    Ok(ResidentProxyPlan {
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
        utls_fingerprint,
        key,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn vless_vision_fp_rust_native_experiment_enabled() -> bool {
    option_env!("DAE_EXPERIMENT_VLESS_VISION_FP_RUST_NATIVE")
        .is_some_and(|value| matches!(value, "1" | "true" | "TRUE" | "yes" | "YES"))
}

fn resident_utls_fingerprint_plan(
    config: &Config,
    vless: &VLESSLink,
) -> Result<Option<ResidentUtlsFingerprintPlan>, String> {
    let link_fingerprint = vless.fingerprint.trim();
    if !link_fingerprint.is_empty() {
        return resolve_resident_utls_fingerprint("link fp", link_fingerprint).map(Some);
    }

    if config
        .global
        .tls_implementation
        .trim()
        .eq_ignore_ascii_case("utls")
    {
        let global_fingerprint = config.global.utls_imitate.trim();
        if global_fingerprint.is_empty() {
            return Err(
                "resident dataplane vless TLS handler requires utls_imitate when tls_implementation=utls"
                    .to_owned(),
            );
        }
        return resolve_resident_utls_fingerprint("global utls_imitate", global_fingerprint)
            .map(Some);
    }

    Ok(None)
}

fn resident_utls_wire_not_admitted_error(
    utls: &ResidentUtlsFingerprintPlan,
    node_tag: &str,
) -> String {
    let wire_state = if U_TLS_WIRE_STACK_DEFERRED {
        "deferred"
    } else {
        "not connected"
    };
    format!(
        "resident dataplane vless TLS handler resolved {} uTLS ClientHello ID {} (name={}, canonical={}, family={}, client={}, randomized={}, alpn_policy={}) but native uTLS wire emission is {wire_state}; keep Go outbound for node {node_tag}",
        utls.source,
        utls.requested,
        utls.name,
        utls.canonical,
        utls.family,
        utls.client,
        utls.randomized,
        utls.alpn_policy
    )
}

fn resolve_resident_utls_fingerprint(
    source: &'static str,
    requested: &str,
) -> Result<ResidentUtlsFingerprintPlan, String> {
    let fingerprint = resolve_utls_client_hello_id(requested)
        .map_err(|err| format!("resident dataplane unsupported {source} {requested}: {err}"))?;
    Ok(resident_utls_fingerprint_plan_from(
        source,
        requested,
        fingerprint,
    ))
}

fn resident_utls_fingerprint_plan_from(
    source: &'static str,
    requested: &str,
    fingerprint: UtlsFingerprint,
) -> ResidentUtlsFingerprintPlan {
    ResidentUtlsFingerprintPlan {
        source,
        requested: requested.to_owned(),
        name: fingerprint.name.to_owned(),
        canonical: fingerprint.canonical.to_owned(),
        family: fingerprint.family.to_owned(),
        client: fingerprint.client.to_owned(),
        randomized: fingerprint.randomized,
        alpn_policy: fingerprint.alpn_policy.to_owned(),
    }
}

fn parse_tcp_dial_mode(config: &Config) -> Result<TcpDialMode, String> {
    config
        .global
        .dial_mode
        .parse::<TcpDialMode>()
        .map_err(|err| format!("resident dataplane dial_mode: {err}"))
}

fn tcp_sniffing_timeout(config: &Config, dial_mode: TcpDialMode) -> Duration {
    if dial_mode == TcpDialMode::Ip {
        return Duration::ZERO;
    }
    let nanos = config.global.sniffing_timeout.as_nanos();
    if nanos <= 0 {
        Duration::ZERO
    } else {
        Duration::from_nanos(nanos as u64)
    }
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
) -> Result<GroupNodeSelection, String> {
    let mut candidates = Vec::<String>::new();
    let mut unresolved_names = Vec::<String>::new();
    let mut explicit_name_filter = false;
    for filter in &group.filter {
        for function in filter {
            if function.name == "name" && !function.not {
                explicit_name_filter = true;
                for param in &function.params {
                    if param.key.is_empty() {
                        if node_links.contains_key(&param.val) {
                            candidates.push(param.val.clone());
                        } else {
                            unresolved_names.push(param.val.clone());
                        }
                    }
                }
            }
        }
    }
    if candidates.is_empty() {
        if explicit_name_filter {
            return Ok(GroupNodeSelection::NoCandidate {
                explicit_name_filter,
                unresolved_names,
            });
        }
        candidates.extend(node_links.keys().cloned());
    }
    if candidates.is_empty() {
        return Ok(GroupNodeSelection::NoCandidate {
            explicit_name_filter,
            unresolved_names,
        });
    }
    let fixed_index = fixed_policy_index(&group.policy).unwrap_or(0);
    let Some(tag) = candidates
        .get(fixed_index)
        .or_else(|| candidates.first())
        .cloned()
    else {
        return Ok(GroupNodeSelection::NoCandidate {
            explicit_name_filter,
            unresolved_names,
        });
    };
    let link = node_links
        .get(&tag)
        .ok_or_else(|| format!("group {} selected missing node {tag}", group.name))?
        .clone();
    Ok(GroupNodeSelection::Selected(SelectedGroupNode {
        tag,
        link,
    }))
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

fn link_scheme(link: &str) -> Option<String> {
    link.split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
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
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
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
        let proxy = plan.default_proxy.unwrap();
        assert!(plan.enabled);
        assert_eq!(plan.proxies.len(), 1);
        assert_eq!(proxy.group_name, "proxy");
        assert_eq!(proxy.node_tag, "vless_live");
        assert_eq!(proxy.server_host, "156.246.90.2");
        assert_eq!(proxy.server_port, 443);
        assert_eq!(proxy.server_name, "office.example");
        assert_eq!(proxy.flow, "xtls-rprx-vision");
        assert_eq!(proxy.alpn, ["h2", "http/1.1"]);
        assert_eq!(proxy.mark, 1234);
    }

    #[test]
    fn resident_dataplane_plan_does_not_fallback_unresolved_name_filter_to_static_ss_node() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        _022: 'ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@217.116.171.227:25868#ss2022'
        xhttp: 'vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?security=tls&type=xhttp&sni=office.example&path=%2Fxhttp&mode=packet-up&alpn=h3'
        }
        group {
        proxy {
            filter: name(node_17)
            policy: fixed
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("cannot resolve group proxy name filter node(s): node_17"));
        assert!(!err.contains("parse VLESS node _022"));
    }

    #[test]
    fn resident_dataplane_plan_rejects_non_vless_node_before_vless_parser() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        ss_live: 'ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@217.116.171.227:25868#ss2022'
        }
        group {
        proxy {
            filter: name(ss_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("selected unsupported ss node ss_live"));
        assert!(err.contains("no Rust protocol handler is admitted"));
        assert!(!err.contains("parse VLESS node ss_live"));
    }

    #[test]
    fn resident_dataplane_plan_builds_proxy_by_outbound_index() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        dial_mode: domain++
        }
        node {
        hk: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=hk.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        us: 'vless://01234567-89ab-cdef-0123-456789abcdef@203.0.113.2:443?security=tls&type=tcp&sni=us.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(hk)
            policy: fixed(0)
        }
        openai {
            filter: name(us)
            policy: fixed(0)
        }
        }
        routing {
        domain(suffix: googleapis.com) -> openai
        fallback: proxy
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        assert!(plan.enabled);
        assert_eq!(plan.tcp_dial_mode, TcpDialMode::DomainPlusPlus);
        assert_eq!(plan.proxies.get(&2).unwrap().group_name, "proxy");
        assert_eq!(plan.proxies.get(&2).unwrap().node_tag, "hk");
        assert_eq!(plan.proxies.get(&3).unwrap().group_name, "openai");
        assert_eq!(plan.proxies.get(&3).unwrap().node_tag, "us");
    }

    #[test]
    fn resident_dataplane_plan_rejects_vless_without_vision_flow() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("admits only flow=xtls-rprx-vision"));
        assert!(err.contains("keep Go outbound"));
    }

    #[test]
    fn resident_dataplane_plan_resolves_link_fingerprint_before_wire_gate() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=firefox_105&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let result = build_resident_dataplane_plan(&config);
        if vless_vision_fp_rust_native_experiment_enabled() {
            let plan = result.unwrap();
            let proxy = plan.default_proxy.unwrap();
            let utls = proxy.utls_fingerprint.unwrap();
            assert_eq!(utls.source, "link fp");
            assert_eq!(utls.requested, "firefox_105");
            assert_eq!(utls.name, "firefox_105");
            assert_eq!(utls.family, "firefox");
        } else {
            let err = result.unwrap_err();
            assert!(err.contains("resolved link fp uTLS ClientHello ID firefox_105"));
            assert!(err.contains("family=firefox"));
            assert!(err.contains("native uTLS wire emission is deferred"));
            assert!(err.contains("keep Go outbound"));
        }
    }

    #[test]
    fn resident_dataplane_plan_carries_generic_link_fingerprint_when_fp_native_experiment_enabled()
    {
        if !vless_vision_fp_rust_native_experiment_enabled() {
            return;
        }
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=safari_16_0&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy.unwrap();
        assert!(plan.enabled);
        assert_eq!(proxy.node_tag, "vless_live");
        assert_eq!(proxy.flow, XTLS_RPRX_VISION);
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "link fp");
        assert_eq!(utls.requested, "safari_16_0");
        assert_eq!(utls.family, "safari");
    }

    #[test]
    fn resident_dataplane_plan_keeps_no_fingerprint_auxiliary_rustls_path() {
        if !vless_vision_fp_rust_native_experiment_enabled() {
            return;
        }
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy.unwrap();
        assert!(proxy.utls_fingerprint.is_none());
    }

    #[test]
    fn resident_dataplane_plan_resolves_global_utls_alias_before_wire_gate() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: safari
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let result = build_resident_dataplane_plan(&config);
        if vless_vision_fp_rust_native_experiment_enabled() {
            let plan = result.unwrap();
            let proxy = plan.default_proxy.unwrap();
            let utls = proxy.utls_fingerprint.unwrap();
            assert_eq!(utls.source, "global utls_imitate");
            assert_eq!(utls.requested, "safari");
            assert_eq!(utls.canonical, "safari_auto");
            assert_eq!(utls.family, "safari");
        } else {
            let err = result.unwrap_err();
            assert!(err.contains("resolved global utls_imitate uTLS ClientHello ID safari"));
            assert!(err.contains("canonical=safari_auto"));
            assert!(err.contains("family=safari"));
            assert!(err.contains("keep Go outbound"));
        }
    }

    #[test]
    fn resident_dataplane_plan_rejects_unknown_utls_fingerprint() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=Chrome&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("unsupported link fp Chrome"));
        assert!(err.contains("unknown uTLS Client Hello ID: Chrome"));
    }

    #[test]
    fn resident_utls_fingerprint_resolution_uses_generic_registry() {
        for (name, canonical, family) in [
            ("chrome", "chrome_auto", "chrome"),
            ("firefox_105", "firefox_105", "firefox"),
            ("safari_16_0", "safari_16_0", "safari"),
            ("ios_14", "ios_14", "ios"),
            ("edge_106", "edge_106", "edge"),
            ("android_11_okhttp", "android_11_okhttp", "android"),
            ("randomizednoalpn", "randomizednoalpn", "random"),
        ] {
            let plan = resolve_resident_utls_fingerprint("test", name).unwrap();
            assert_eq!(plan.name, name);
            assert_eq!(plan.canonical, canonical);
            assert_eq!(plan.family, family);
        }

        let randomized_no_alpn =
            resolve_resident_utls_fingerprint("test", "randomizednoalpn").unwrap();
        assert!(randomized_no_alpn.randomized);
        assert_eq!(randomized_no_alpn.alpn_policy, "force-no-alpn");
    }
}

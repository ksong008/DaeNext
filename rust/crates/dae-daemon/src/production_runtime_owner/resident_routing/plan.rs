use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr},
    path::PathBuf,
    str::FromStr,
};

use dae_config::{Config, DynamicFunctionValue, Function, Param, RoutingRule};
use dae_core_types::OutboundIndex;
use dae_ebpf_support::MAX_MATCH_SET_LEN;
use dae_routing::{
    DomainKey, IpPrefix as RoutingIpPrefix, RoutingDomainSet, RoutingLpmSet, RoutingMatchKind,
    RoutingMatchSet,
};
use serde_json::{Value, json};

use super::geodata::{
    GeodataResolutionReport, GeodataResolver, load_geoip_params, load_geosite_params,
};
use super::types::{IpPrefix, MatchSetBytes, OutboundSpec, ResidentDomainSet, ResidentRoutingPlan};
use super::{
    IP_VERSION_4, IP_VERSION_6, L4_TCP, L4_UDP, MATCH_TYPE_DOMAIN_SET, MATCH_TYPE_DSCP,
    MATCH_TYPE_FALLBACK, MATCH_TYPE_IP_SET, MATCH_TYPE_IP_VERSION, MATCH_TYPE_L4_PROTO,
    MATCH_TYPE_MAC, MATCH_TYPE_PORT, MATCH_TYPE_PROCESS_NAME, MATCH_TYPE_SOURCE_IP_SET,
    MATCH_TYPE_SOURCE_PORT,
};

pub(super) fn build_routing_plan(config: &Config) -> Result<ResidentRoutingPlan, String> {
    build_routing_plan_with_asset_dirs(config, Vec::<PathBuf>::new())
}

pub(super) fn build_routing_plan_with_asset_dirs(
    config: &Config,
    asset_dirs: impl IntoIterator<Item = impl Into<PathBuf>>,
) -> Result<ResidentRoutingPlan, String> {
    let groups = outbound_groups(config)?;
    let resolver = GeodataResolver::new(asset_dirs);
    let mut geodata_report = GeodataResolutionReport::default();
    let rules = optimize_routing_rules(&config.routing.rules, &resolver, &mut geodata_report)?;
    let mut plan = ResidentRoutingPlan {
        matches: Vec::new(),
        lpm_sets: Vec::new(),
        domain_sets: Vec::new(),
        geodata_report,
        skipped_rules: Vec::new(),
    };
    for (index, rule) in rules.iter().enumerate() {
        if let Err(err) = compile_rule(&mut plan, &groups, rule) {
            return Err(format!(
                "resident routing rule {index} failed after generic optimization: {err}; rule={}",
                rule.to_config_string(false, false, true)
            ));
        }
    }
    let fallback = dynamic_to_single_function(&config.routing.fallback)?;
    let fallback = parse_outbound(&fallback, &groups)?;
    plan.matches.push(match_set(
        [0; 16],
        false,
        MATCH_TYPE_FALLBACK,
        fallback,
        "Fallback",
    ));
    if plan.matches.len() > MAX_MATCH_SET_LEN {
        return Err(format!(
            "resident routing_map match set overflow: {} > {}",
            plan.matches.len(),
            MAX_MATCH_SET_LEN
        ));
    }
    Ok(plan)
}

fn optimize_routing_rules(
    rules: &[RoutingRule],
    resolver: &GeodataResolver,
    geodata_report: &mut GeodataResolutionReport,
) -> Result<Vec<RoutingRule>, String> {
    let mut rules = rules.to_vec();
    for rule in &mut rules {
        for function in &mut rule.and_functions {
            *function = aliased_function(function);
            expand_function_params(function, resolver, geodata_report)?;
        }
        rule.and_functions
            .sort_by(|left, right| left.name.cmp(&right.name));
    }

    let mut merged: Vec<RoutingRule> = Vec::new();
    for rule in rules {
        if let Some(last) = merged.last_mut()
            && can_merge_singleton_rule(last, &rule)
        {
            last.and_functions[0]
                .params
                .extend(rule.and_functions[0].params.clone());
            continue;
        }
        merged.push(rule);
    }

    for rule in &mut merged {
        for function in &mut rule.and_functions {
            sort_function_params(function);
            deduplicate_function_params(function);
        }
    }

    Ok(merged)
}

fn expand_function_params(
    function: &mut Function,
    resolver: &GeodataResolver,
    geodata_report: &mut GeodataResolutionReport,
) -> Result<(), String> {
    let mut expanded = Vec::new();
    for param in &function.params {
        match param.key.as_str() {
            "geosite" => {
                expanded.extend(load_geosite_params(
                    resolver,
                    "geosite",
                    &param.val,
                    geodata_report,
                )?);
            }
            "geoip" => {
                expanded.extend(load_geoip_params(
                    resolver,
                    "geoip",
                    &param.val,
                    geodata_report,
                )?);
            }
            "ext" => {
                let (filename, code) = param
                    .val
                    .split_once(':')
                    .ok_or_else(|| format!("ext parameter must be file:code, got {}", param.val))?;
                match function.name.as_str() {
                    "domain" | "qname" => {
                        expanded.extend(load_geosite_params(
                            resolver,
                            filename,
                            code,
                            geodata_report,
                        )?);
                    }
                    "ip" => {
                        expanded.extend(load_geoip_params(
                            resolver,
                            filename,
                            code,
                            geodata_report,
                        )?);
                    }
                    other => {
                        return Err(format!(
                            "unsupported extension file extraction in function {other}"
                        ));
                    }
                }
            }
            _ => expanded.push(normalize_param(function, param)),
        }
    }
    function.params = expanded;
    Ok(())
}

fn normalize_param(function: &Function, param: &Param) -> Param {
    let mut param = param.clone();
    if function.name == "domain" {
        match param.key.as_str() {
            "" | "domain" => param.key = "suffix".to_owned(),
            "contains" => param.key = "keyword".to_owned(),
            _ => {}
        }
    }
    param
}

fn can_merge_singleton_rule(left: &RoutingRule, right: &RoutingRule) -> bool {
    left.and_functions.len() == 1
        && right.and_functions.len() == 1
        && left.and_functions[0].name == right.and_functions[0].name
        && left.and_functions[0].not == right.and_functions[0].not
        && left.outbound == right.outbound
}

fn sort_function_params(function: &mut Function) {
    if function.name == "ip" || function.name == "sip" {
        function.params.sort_by(|left, right| {
            let left_version = if left.val.contains(':') { 6 } else { 4 };
            let right_version = if right.val.contains(':') { 6 } else { 4 };
            left_version
                .cmp(&right_version)
                .then_with(|| left.val.cmp(&right.val))
        });
    } else {
        function.params.sort_by(|left, right| {
            left.key
                .cmp(&right.key)
                .then_with(|| left.val.cmp(&right.val))
        });
    }
}

fn deduplicate_function_params(function: &mut Function) {
    let mut seen = BTreeMap::<(String, String), ()>::new();
    function.params.retain(|param| {
        seen.insert((param.key.clone(), param.val.clone()), ())
            .is_none()
    });
}

pub(super) fn domain_set_json(set: &ResidentDomainSet) -> Value {
    json!({
        "rule_index": set.rule_index,
        "key": &set.key,
        "value_count": set.values.len(),
        "sample_values": set.values.iter().take(8).collect::<Vec<_>>(),
        "values_truncated": set.values.len() > 8,
    })
}

pub(super) fn userspace_matcher_typed_sets(
    plan: &ResidentRoutingPlan,
) -> Result<
    (
        Vec<RoutingDomainSet>,
        Vec<RoutingLpmSet>,
        Vec<RoutingMatchSet>,
    ),
    String,
> {
    let domain_sets = plan
        .domain_sets
        .iter()
        .map(|set| {
            let key = DomainKey::try_from(set.key.as_str())
                .map_err(|err| format!("domain set {} key: {err}", set.rule_index))?;
            Ok(RoutingDomainSet {
                bit: set.rule_index,
                key,
                patterns: set.values.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let lpm_sets = plan
        .lpm_sets
        .iter()
        .enumerate()
        .map(|(index, prefixes)| {
            let prefixes = prefixes
                .iter()
                .map(|prefix| {
                    RoutingIpPrefix::new(prefix.addr, prefix.bits)
                        .map_err(|err| format!("lpm set {index}: {err}"))
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(RoutingLpmSet {
                index: index as u32,
                prefixes,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let matches = plan
        .matches
        .iter()
        .map(match_set_typed)
        .collect::<Result<Vec<_>, String>>()?;
    Ok((domain_sets, lpm_sets, matches))
}

fn match_set_typed(set: &MatchSetBytes) -> Result<RoutingMatchSet, String> {
    let kind = match set.bytes[17] {
        MATCH_TYPE_DOMAIN_SET => RoutingMatchKind::DomainSet,
        MATCH_TYPE_IP_SET => RoutingMatchKind::IpSet {
            lpm_index: u32::from_le_bytes([set.bytes[0], set.bytes[1], set.bytes[2], set.bytes[3]]),
        },
        MATCH_TYPE_SOURCE_IP_SET => RoutingMatchKind::SourceIpSet {
            lpm_index: u32::from_le_bytes([set.bytes[0], set.bytes[1], set.bytes[2], set.bytes[3]]),
        },
        MATCH_TYPE_PORT => RoutingMatchKind::Port {
            start: u16::from_le_bytes([set.bytes[0], set.bytes[1]]),
            end: u16::from_le_bytes([set.bytes[2], set.bytes[3]]),
        },
        MATCH_TYPE_SOURCE_PORT => RoutingMatchKind::SourcePort {
            start: u16::from_le_bytes([set.bytes[0], set.bytes[1]]),
            end: u16::from_le_bytes([set.bytes[2], set.bytes[3]]),
        },
        MATCH_TYPE_L4_PROTO => RoutingMatchKind::L4Proto {
            value: set.bytes[0],
        },
        MATCH_TYPE_IP_VERSION => RoutingMatchKind::IpVersion {
            value: set.bytes[0],
        },
        MATCH_TYPE_MAC => RoutingMatchKind::Mac {
            lpm_index: u32::from_le_bytes([set.bytes[0], set.bytes[1], set.bytes[2], set.bytes[3]]),
        },
        MATCH_TYPE_PROCESS_NAME => {
            let mut value = [0_u8; 16];
            value.copy_from_slice(&set.bytes[..16]);
            RoutingMatchKind::ProcessName { value }
        }
        MATCH_TYPE_DSCP => RoutingMatchKind::Dscp {
            value: set.bytes[0],
        },
        MATCH_TYPE_FALLBACK => RoutingMatchKind::Fallback,
        other => return Err(format!("unknown resident routing match type: {other}")),
    };
    Ok(RoutingMatchSet {
        kind,
        outbound: OutboundIndex(set.outbound),
        not: set.bytes[16] != 0,
        mark: set.mark,
        must: set.must,
    })
}

fn compile_rule(
    plan: &mut ResidentRoutingPlan,
    groups: &BTreeMap<String, u8>,
    rule: &RoutingRule,
) -> Result<(), String> {
    let outbound = parse_outbound(&rule.outbound, groups)?;
    for (function_index, function) in rule.and_functions.iter().enumerate() {
        let function = aliased_function(function);
        let grouped = grouped_params(&function.params);
        if grouped.is_empty() {
            return Err(format!("function {} has no params", function.name));
        }
        for (group_index, (key, values)) in grouped.iter().enumerate() {
            let outbound = if group_index == grouped.len() - 1 {
                if function_index == rule.and_functions.len() - 1 {
                    outbound.clone()
                } else {
                    logical_outbound(OutboundIndex::LOGICAL_AND)
                }
            } else {
                logical_outbound(OutboundIndex::LOGICAL_OR)
            };
            add_function_match_sets(plan, &function, key, values, outbound)?;
        }
    }
    Ok(())
}

fn add_function_match_sets(
    plan: &mut ResidentRoutingPlan,
    function: &Function,
    param_key: &str,
    values: &[String],
    outbound: OutboundSpec,
) -> Result<(), String> {
    match function.name.as_str() {
        "domain" => {
            if !matches!(param_key, "full" | "keyword" | "suffix" | "regex") {
                return Err(format!(
                    "unsupported resident domain parameter key: {param_key}"
                ));
            }
            let rule_index = plan.matches.len();
            plan.domain_sets.push(ResidentDomainSet {
                rule_index,
                key: param_key.to_owned(),
                values: values.to_vec(),
            });
            plan.matches.push(match_set(
                [0; 16],
                function.not,
                MATCH_TYPE_DOMAIN_SET,
                outbound,
                "DomainSet",
            ));
            Ok(())
        }
        "ip" | "sip" | "mac" => {
            let lpm_index = plan.lpm_sets.len() as u32;
            let prefixes = match function.name.as_str() {
                "mac" => values
                    .iter()
                    .map(|value| parse_mac_prefix(value))
                    .collect::<Result<Vec<_>, _>>()?,
                _ => parse_ip_prefix_group(param_key, values)?,
            };
            plan.lpm_sets.push(prefixes);
            let mut raw = [0_u8; 16];
            raw[..4].copy_from_slice(&lpm_index.to_le_bytes());
            let kind = match function.name.as_str() {
                "sip" => (MATCH_TYPE_SOURCE_IP_SET, "SourceIpSet"),
                "mac" => (MATCH_TYPE_MAC, "Mac"),
                _ => (MATCH_TYPE_IP_SET, "IpSet"),
            };
            plan.matches
                .push(match_set(raw, function.not, kind.0, outbound, kind.1));
            Ok(())
        }
        "port" | "sport" => {
            let ranges = values
                .iter()
                .map(|value| parse_port_range(value))
                .collect::<Result<Vec<_>, _>>()?;
            let kind = if function.name == "sport" {
                (MATCH_TYPE_SOURCE_PORT, "SourcePort")
            } else {
                (MATCH_TYPE_PORT, "Port")
            };
            for (index, (start, end)) in ranges.into_iter().enumerate() {
                let outbound = if index == values.len() - 1 {
                    outbound.clone()
                } else {
                    logical_outbound(OutboundIndex::LOGICAL_OR)
                };
                let mut raw = [0_u8; 16];
                raw[..2].copy_from_slice(&start.to_le_bytes());
                raw[2..4].copy_from_slice(&end.to_le_bytes());
                plan.matches
                    .push(match_set(raw, function.not, kind.0, outbound, kind.1));
            }
            Ok(())
        }
        "l4proto" => {
            let mut raw = [0_u8; 16];
            raw[0] = parse_l4_proto(values)?;
            plan.matches.push(match_set(
                raw,
                function.not,
                MATCH_TYPE_L4_PROTO,
                outbound,
                "L4Proto",
            ));
            Ok(())
        }
        "ipversion" => {
            let mut raw = [0_u8; 16];
            raw[0] = parse_ip_version(values)?;
            plan.matches.push(match_set(
                raw,
                function.not,
                MATCH_TYPE_IP_VERSION,
                outbound,
                "IpVersion",
            ));
            Ok(())
        }
        "pname" => {
            for (index, value) in values.iter().enumerate() {
                let outbound = if index == values.len() - 1 {
                    outbound.clone()
                } else {
                    logical_outbound(OutboundIndex::LOGICAL_OR)
                };
                let mut raw = [0_u8; 16];
                let name = value.as_bytes();
                let copy_len = name.len().min(raw.len());
                raw[..copy_len].copy_from_slice(&name[..copy_len]);
                plan.matches.push(match_set(
                    raw,
                    function.not,
                    MATCH_TYPE_PROCESS_NAME,
                    outbound,
                    "ProcessName",
                ));
            }
            Ok(())
        }
        "dscp" => {
            for (index, value) in values.iter().enumerate() {
                let outbound = if index == values.len() - 1 {
                    outbound.clone()
                } else {
                    logical_outbound(OutboundIndex::LOGICAL_OR)
                };
                let mut raw = [0_u8; 16];
                raw[0] = value
                    .parse::<u8>()
                    .map_err(|err| format!("invalid dscp {value}: {err}"))?;
                plan.matches.push(match_set(
                    raw,
                    function.not,
                    MATCH_TYPE_DSCP,
                    outbound,
                    "Dscp",
                ));
            }
            Ok(())
        }
        other => Err(format!("unsupported resident routing function: {other}")),
    }
}

fn outbound_groups(config: &Config) -> Result<BTreeMap<String, u8>, String> {
    let mut groups = BTreeMap::new();
    groups.insert("direct".to_owned(), OutboundIndex::DIRECT.value());
    groups.insert("block".to_owned(), OutboundIndex::BLOCK.value());
    for (index, group) in config.group.iter().enumerate() {
        let outbound = index + OutboundIndex::USER_DEFINED_MIN.value() as usize;
        if outbound > OutboundIndex::USER_DEFINED_MAX.value() as usize {
            return Err("too many resident outbounds".to_owned());
        }
        if groups.insert(group.name.clone(), outbound as u8).is_some() {
            return Err(format!("duplicated outbound name: {}", group.name));
        }
    }
    Ok(groups)
}

fn parse_outbound(
    function: &Function,
    groups: &BTreeMap<String, u8>,
) -> Result<OutboundSpec, String> {
    let mut mark = 0_u32;
    let mut must = false;
    for param in &function.params {
        match param.key.as_str() {
            "mark" => {
                mark = parse_u32_auto(&param.val)
                    .map_err(|err| format!("invalid outbound mark {}: {err}", param.val))?;
            }
            "" if param.val == "must" => must = true,
            "" => return Err(format!("unknown outbound param: {}", param.val)),
            key => return Err(format!("unknown outbound param key: {key}")),
        }
    }
    let id = match function.name.as_str() {
        "must_rules" => OutboundIndex::MUST_RULES.value(),
        name => *groups
            .get(name)
            .ok_or_else(|| format!("outbound group not found: {name}"))?,
    };
    Ok(OutboundSpec {
        id,
        mark,
        must,
        name: function.name.clone(),
    })
}

fn dynamic_to_single_function(value: &DynamicFunctionValue) -> Result<Function, String> {
    match value {
        DynamicFunctionValue::String(name) => Ok(Function {
            name: name.clone(),
            not: false,
            params: Vec::new(),
        }),
        DynamicFunctionValue::Function(function) => Ok(function.clone()),
        DynamicFunctionValue::FunctionList(functions) if functions.len() == 1 => {
            Ok(functions[0].clone())
        }
        DynamicFunctionValue::FunctionList(functions) => Err(format!(
            "expected exactly 1 fallback function, got {}",
            functions.len()
        )),
        DynamicFunctionValue::Nil => Err("unsupported fallback type nil".to_owned()),
    }
}

fn aliased_function(function: &Function) -> Function {
    let mut function = function.clone();
    match function.name.as_str() {
        "dport" => function.name = "port".to_owned(),
        "dip" => function.name = "ip".to_owned(),
        _ => {}
    }
    function
}

fn grouped_params(params: &[Param]) -> Vec<(String, Vec<String>)> {
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut order = Vec::new();
    for param in params {
        if !groups.contains_key(&param.key) {
            order.push(param.key.clone());
        }
        groups
            .entry(param.key.clone())
            .or_default()
            .push(param.val.clone());
    }
    order
        .into_iter()
        .map(|key| {
            let values = groups.remove(&key).unwrap_or_default();
            (key, values)
        })
        .collect()
}

fn match_set(
    value: [u8; 16],
    not: bool,
    match_type: u8,
    outbound: OutboundSpec,
    kind: &'static str,
) -> MatchSetBytes {
    let mut bytes = [0_u8; 24];
    bytes[..16].copy_from_slice(&value);
    bytes[16] = u8::from(not);
    bytes[17] = match_type;
    bytes[18] = outbound.id;
    bytes[19] = u8::from(outbound.must);
    bytes[20..24].copy_from_slice(&outbound.mark.to_ne_bytes());
    MatchSetBytes {
        bytes,
        kind,
        outbound: outbound.id,
        mark: outbound.mark,
        must: outbound.must,
    }
}

fn logical_outbound(index: OutboundIndex) -> OutboundSpec {
    OutboundSpec {
        id: index.value(),
        mark: 0,
        must: false,
        name: index.to_string(),
    }
}

fn parse_l4_proto(values: &[String]) -> Result<u8, String> {
    let mut value = 0_u8;
    for item in values {
        match item.as_str() {
            "tcp" => value |= L4_TCP,
            "udp" => value |= L4_UDP,
            other => return Err(format!("unsupported l4proto: {other}")),
        }
    }
    if value == 0 {
        return Err("empty l4proto".to_owned());
    }
    Ok(value)
}

fn parse_ip_version(values: &[String]) -> Result<u8, String> {
    let mut value = 0_u8;
    for item in values {
        match item.as_str() {
            "4" => value |= IP_VERSION_4,
            "6" => value |= IP_VERSION_6,
            other => return Err(format!("unsupported ipversion: {other}")),
        }
    }
    if value == 0 {
        return Err("empty ipversion".to_owned());
    }
    Ok(value)
}

fn parse_port_range(value: &str) -> Result<(u16, u16), String> {
    if let Some((start, end)) = value.split_once('-') {
        let start = start
            .parse::<u16>()
            .map_err(|err| format!("invalid port range start {value}: {err}"))?;
        let end = end
            .parse::<u16>()
            .map_err(|err| format!("invalid port range end {value}: {err}"))?;
        if start > end {
            return Err(format!("invalid descending port range: {value}"));
        }
        return Ok((start, end));
    }
    let port = value
        .parse::<u16>()
        .map_err(|err| format!("invalid port {value}: {err}"))?;
    Ok((port, port))
}

fn parse_ip_prefix_group(param_key: &str, values: &[String]) -> Result<Vec<IpPrefix>, String> {
    match param_key {
        "" => values.iter().map(|value| parse_ip_prefix(value)).collect(),
        other => Err(format!("unsupported resident ip parameter key: {other}")),
    }
}

fn parse_ip_prefix(value: &str) -> Result<IpPrefix, String> {
    let value = value.trim_matches('\'').trim_matches('"');
    if let Some((addr, bits)) = value.split_once('/') {
        let addr = IpAddr::from_str(addr).map_err(|err| format!("invalid ip {value}: {err}"))?;
        let bits = bits
            .parse::<u8>()
            .map_err(|err| format!("invalid prefix bits {value}: {err}"))?;
        let max_bits = if addr.is_ipv4() { 32 } else { 128 };
        if bits > max_bits {
            return Err(format!("invalid prefix bits {bits} for {addr}"));
        }
        return Ok(IpPrefix { addr, bits });
    }
    let addr = IpAddr::from_str(value).map_err(|err| format!("invalid ip {value}: {err}"))?;
    let bits = if addr.is_ipv4() { 32 } else { 128 };
    Ok(IpPrefix { addr, bits })
}

fn parse_mac_prefix(value: &str) -> Result<IpPrefix, String> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        return Err(format!("invalid mac address: {value}"));
    }
    let mut octets = [0_u8; 16];
    for (index, part) in parts.iter().enumerate() {
        octets[index + 10] = u8::from_str_radix(part, 16)
            .map_err(|err| format!("invalid mac address {value}: {err}"))?;
    }
    Ok(IpPrefix {
        addr: IpAddr::V6(Ipv6Addr::from(octets)),
        bits: 128,
    })
}

fn parse_u32_auto(value: &str) -> Result<u32, std::num::ParseIntError> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16)
    } else {
        value.parse::<u32>()
    }
}

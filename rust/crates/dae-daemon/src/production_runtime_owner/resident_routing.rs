use std::collections::BTreeMap;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::str::FromStr;

use dae_config::{Config, DynamicFunctionValue, Function, Param, RoutingRule};
use dae_core_types::OutboundIndex;
use dae_ebpf_support::{RuntimeMapInfo, map_ids, map_info, open_map_fd, update_map_elem_bytes};
use serde_json::{Value, json};

const ROUTING_MAP_NAME: &str = "routing_map";
const LPM_ARRAY_MAP_NAME: &str = "lpm_array_map";
const UNUSED_LPM_TYPE_NAME: &str = "unused_lpm_type";
const ROUTING_MAP_KEY_SIZE: u32 = 4;
const ROUTING_MAP_VALUE_SIZE: u32 = 24;
const LPM_ARRAY_KEY_SIZE: u32 = 4;
const LPM_ARRAY_VALUE_SIZE: u32 = 4;
const LPM_KEY_SIZE: u32 = 20;
const LPM_VALUE_SIZE: u32 = 4;
const LPM_MAX_ENTRIES: u32 = 2_048_000;
const BPF_MAP_CREATE: libc::c_uint = 0;
const BPF_MAP_TYPE_LPM_TRIE: u32 = 11;
const BPF_F_NO_PREALLOC: u32 = 1;

const MATCH_TYPE_DOMAIN_SET: u8 = 0;
const MATCH_TYPE_IP_SET: u8 = 1;
const MATCH_TYPE_SOURCE_IP_SET: u8 = 2;
const MATCH_TYPE_PORT: u8 = 3;
const MATCH_TYPE_SOURCE_PORT: u8 = 4;
const MATCH_TYPE_L4_PROTO: u8 = 5;
const MATCH_TYPE_IP_VERSION: u8 = 6;
const MATCH_TYPE_MAC: u8 = 7;
const MATCH_TYPE_PROCESS_NAME: u8 = 8;
const MATCH_TYPE_DSCP: u8 = 9;
const MATCH_TYPE_FALLBACK: u8 = 10;

const L4_TCP: u8 = 1;
const L4_UDP: u8 = 2;
const IP_VERSION_4: u8 = 1;
const IP_VERSION_6: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResidentRoutingPlan {
    matches: Vec<MatchSetBytes>,
    lpm_sets: Vec<Vec<IpPrefix>>,
    skipped_rules: Vec<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MatchSetBytes {
    bytes: [u8; 24],
    kind: &'static str,
    outbound: u8,
    mark: u32,
    must: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OutboundSpec {
    id: u8,
    mark: u32,
    must: bool,
    name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IpPrefix {
    addr: IpAddr,
    bits: u8,
}

pub(super) fn update_new_resident_routing_map(
    before_map_ids: &[u32],
    config: &Config,
) -> Result<(Value, u32), String> {
    let current = map_ids().map_err(|err| err.to_string())?;
    let new_map_ids = current
        .iter()
        .copied()
        .filter(|id| !before_map_ids.contains(id))
        .collect::<Vec<_>>();
    let (routing_fd, routing_info) = open_unique_map(&new_map_ids, ROUTING_MAP_NAME)?;
    let lpm = open_optional_unique_map(&new_map_ids, LPM_ARRAY_MAP_NAME)?;
    update_resident_routing_map_fd(
        routing_fd.as_raw_fd(),
        routing_info,
        lpm.as_ref().map(|(fd, info)| (fd.as_raw_fd(), info)),
        config,
        "new_attached_map",
        new_map_ids,
    )
}

#[allow(dead_code)]
pub(super) fn update_existing_resident_routing_map(
    routing_map_id: u32,
    lpm_array_map_id: Option<u32>,
    config: &Config,
) -> Result<(Value, u32), String> {
    let routing_fd = open_map_fd(routing_map_id).map_err(|err| err.to_string())?;
    let routing_info = map_info(routing_fd.as_raw_fd()).map_err(|err| err.to_string())?;
    let lpm = match lpm_array_map_id {
        Some(id) => {
            let fd = open_map_fd(id).map_err(|err| err.to_string())?;
            let info = map_info(fd.as_raw_fd()).map_err(|err| err.to_string())?;
            Some((fd, info))
        }
        None => None,
    };
    update_resident_routing_map_fd(
        routing_fd.as_raw_fd(),
        routing_info,
        lpm.as_ref().map(|(fd, info)| (fd.as_raw_fd(), info)),
        config,
        "existing_loaded_map",
        Vec::new(),
    )
}

fn update_resident_routing_map_fd(
    routing_map_fd: i32,
    routing_info: RuntimeMapInfo,
    lpm_array: Option<(i32, &RuntimeMapInfo)>,
    config: &Config,
    source: &str,
    new_map_ids: Vec<u32>,
) -> Result<(Value, u32), String> {
    ensure_map_contract(
        &routing_info,
        ROUTING_MAP_NAME,
        ROUTING_MAP_KEY_SIZE,
        ROUTING_MAP_VALUE_SIZE,
    )?;
    let plan = build_routing_plan(config)?;
    if !plan.lpm_sets.is_empty() {
        let (lpm_fd, lpm_info) = lpm_array.ok_or_else(|| {
            "resident routing needs lpm_array_map but it was not found".to_owned()
        })?;
        ensure_map_contract(
            lpm_info,
            LPM_ARRAY_MAP_NAME,
            LPM_ARRAY_KEY_SIZE,
            LPM_ARRAY_VALUE_SIZE,
        )?;
        update_lpm_array_map(lpm_fd, &plan.lpm_sets)?;
    }

    for (index, match_set) in plan.matches.iter().enumerate() {
        let key = (index as u32).to_ne_bytes();
        update_map_elem_bytes(routing_map_fd, &key, &match_set.bytes)
            .map_err(|err| err.to_string())?;
    }

    Ok((
        json!({
            "status": "pass",
            "source": source,
            "map": map_json(&routing_info),
            "new_map_ids": new_map_ids,
            "match_set_count": plan.matches.len(),
            "lpm_set_count": plan.lpm_sets.len(),
            "skipped_rule_count": plan.skipped_rules.len(),
            "skipped_rules": plan.skipped_rules,
            "fallback_is_last": plan.matches.last().is_some_and(|set| set.kind == "Fallback"),
            "compiled_match_sets": plan.matches.iter().map(match_set_json).collect::<Vec<_>>(),
        }),
        routing_info.id,
    ))
}

fn build_routing_plan(config: &Config) -> Result<ResidentRoutingPlan, String> {
    let groups = outbound_groups(config)?;
    let mut plan = ResidentRoutingPlan {
        matches: Vec::new(),
        lpm_sets: Vec::new(),
        skipped_rules: Vec::new(),
    };
    for (index, rule) in config.routing.rules.iter().enumerate() {
        if let Err(err) = compile_rule(&mut plan, &groups, rule) {
            plan.skipped_rules.push(json!({
                "index": index,
                "rule": rule.to_config_string(false, false, true),
                "reason": err,
            }));
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
    if plan.matches.len() > 1024 {
        return Err(format!(
            "resident routing_map match set overflow: {} > 1024",
            plan.matches.len()
        ));
    }
    Ok(plan)
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
        for (group_index, (_key, values)) in grouped.iter().enumerate() {
            let outbound = if group_index == grouped.len() - 1 {
                if function_index == rule.and_functions.len() - 1 {
                    outbound.clone()
                } else {
                    logical_outbound(OutboundIndex::LOGICAL_AND)
                }
            } else {
                logical_outbound(OutboundIndex::LOGICAL_OR)
            };
            add_function_match_sets(plan, &function, values, outbound)?;
        }
    }
    Ok(())
}

fn add_function_match_sets(
    plan: &mut ResidentRoutingPlan,
    function: &Function,
    values: &[String],
    outbound: OutboundSpec,
) -> Result<(), String> {
    match function.name.as_str() {
        "domain" => {
            for value in or_split(values, outbound) {
                plan.matches.push(match_set(
                    [0; 16],
                    function.not,
                    MATCH_TYPE_DOMAIN_SET,
                    value,
                    "DomainSet",
                ));
            }
            Ok(())
        }
        "ip" | "sip" | "mac" => {
            let lpm_index = plan.lpm_sets.len() as u32;
            let prefixes = match function.name.as_str() {
                "mac" => values
                    .iter()
                    .map(|value| parse_mac_prefix(value))
                    .collect::<Result<Vec<_>, _>>()?,
                _ => values
                    .iter()
                    .map(|value| parse_ip_prefix(value))
                    .collect::<Result<Vec<_>, _>>()?,
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

fn or_split(values: &[String], outbound: OutboundSpec) -> Vec<OutboundSpec> {
    values
        .iter()
        .enumerate()
        .map(|(index, _)| {
            if index == values.len() - 1 {
                outbound.clone()
            } else {
                logical_outbound(OutboundIndex::LOGICAL_OR)
            }
        })
        .collect()
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

fn update_lpm_array_map(lpm_array_fd: i32, lpm_sets: &[Vec<IpPrefix>]) -> Result<(), String> {
    for (index, prefixes) in lpm_sets.iter().enumerate() {
        let inner = create_lpm_map(prefixes)?;
        let key = (index as u32).to_ne_bytes();
        let value = (inner.as_raw_fd() as u32).to_ne_bytes();
        update_map_elem_bytes(lpm_array_fd, &key, &value).map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn create_lpm_map(prefixes: &[IpPrefix]) -> Result<OwnedFd, String> {
    let fd = create_bpf_map(CreateBpfMapSpec {
        name: UNUSED_LPM_TYPE_NAME,
        map_type: BPF_MAP_TYPE_LPM_TRIE,
        key_size: LPM_KEY_SIZE,
        value_size: LPM_VALUE_SIZE,
        max_entries: LPM_MAX_ENTRIES,
        map_flags: BPF_F_NO_PREALLOC,
    })
    .map_err(|err| format!("create resident LPM trie map failed: {err}"))?;
    let one = 1_u32.to_ne_bytes();
    for prefix in prefixes {
        let key = prefix_to_lpm_key(prefix);
        update_map_elem_bytes(fd.as_raw_fd(), &key, &one)
            .map_err(|err| format!("update resident LPM trie map failed: {err}"))?;
    }
    Ok(fd)
}

fn prefix_to_lpm_key(prefix: &IpPrefix) -> [u8; 20] {
    let mut key = [0_u8; 20];
    let (bytes, bits) = match prefix.addr {
        IpAddr::V4(addr) => (addr.to_ipv6_mapped().octets(), prefix.bits as u32 + 96),
        IpAddr::V6(addr) => (addr.octets(), prefix.bits as u32),
    };
    key[..4].copy_from_slice(&bits.to_ne_bytes());
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let word = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        key[4 + index * 4..8 + index * 4].copy_from_slice(&word.to_ne_bytes());
    }
    key
}

fn ensure_map_contract(
    info: &RuntimeMapInfo,
    name: &str,
    key_size: u32,
    value_size: u32,
) -> Result<(), String> {
    if info.name != name || info.key_size != key_size || info.value_size != value_size {
        return Err(format!(
            "map contract mismatch: expected {name} key_size={key_size} value_size={value_size}; got name={} key_size={} value_size={}",
            info.name, info.key_size, info.value_size
        ));
    }
    Ok(())
}

fn open_unique_map(ids: &[u32], name: &str) -> Result<(OwnedFd, RuntimeMapInfo), String> {
    let mut candidates = Vec::new();
    for id in ids {
        let Some((fd, info)) = open_map_info_if_alive(*id)? else {
            continue;
        };
        if info.name == name {
            candidates.push((fd, info));
        }
    }
    if candidates.len() != 1 {
        return Err(format!(
            "expected exactly one resident map {name}, found {}",
            candidates.len()
        ));
    }
    Ok(candidates.remove(0))
}

fn open_optional_unique_map(
    ids: &[u32],
    name: &str,
) -> Result<Option<(OwnedFd, RuntimeMapInfo)>, String> {
    let mut candidates = Vec::new();
    for id in ids {
        let Some((fd, info)) = open_map_info_if_alive(*id)? else {
            continue;
        };
        if info.name == name {
            candidates.push((fd, info));
        }
    }
    if candidates.len() > 1 {
        return Err(format!(
            "expected at most one resident map {name}, found {}",
            candidates.len()
        ));
    }
    Ok(candidates.pop())
}

fn open_map_info_if_alive(id: u32) -> Result<Option<(OwnedFd, RuntimeMapInfo)>, String> {
    let fd = match open_map_fd(id) {
        Ok(fd) => fd,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.to_string()),
    };
    let info = match map_info(fd.as_raw_fd()) {
        Ok(info) => info,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.to_string()),
    };
    Ok(Some((fd, info)))
}

fn map_json(info: &RuntimeMapInfo) -> Value {
    json!({
        "id": info.id,
        "name": info.name,
        "map_type": info.map_type,
        "key_size": info.key_size,
        "value_size": info.value_size,
        "max_entries": info.max_entries,
        "flags": info.flags,
    })
}

fn match_set_json(set: &MatchSetBytes) -> Value {
    json!({
        "kind": set.kind,
        "outbound": set.outbound,
        "mark": set.mark,
        "must": set.must,
    })
}

#[derive(Clone, Copy, Debug)]
struct CreateBpfMapSpec {
    name: &'static str,
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
}

fn create_bpf_map(spec: CreateBpfMapSpec) -> io::Result<OwnedFd> {
    let mut attr = BpfMapCreateAttr {
        map_type: spec.map_type,
        key_size: spec.key_size,
        value_size: spec.value_size,
        max_entries: spec.max_entries,
        map_flags: spec.map_flags,
        ..BpfMapCreateAttr::default()
    };
    let name = spec.name.as_bytes();
    let copy_len = name.len().min(attr.map_name.len() - 1);
    attr.map_name[..copy_len].copy_from_slice(&name[..copy_len]);
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_CREATE,
            &attr as *const BpfMapCreateAttr,
            size_of::<BpfMapCreateAttr>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BpfMapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra: u64,
}

#[cfg(test)]
mod tests {
    use dae_config::parser::parse_config;
    use dae_config::schema::build_config;

    use super::*;

    #[test]
    fn resident_routing_plan_compiles_lan_proxy_rules() {
        let sections = parse_config(
            r#"
global {
    lan_interface: daerust0
}
group {
    proxy {
        policy: fixed(0)
    }
}
routing {
    dip(156.246.90.2) -> must_direct
    l4proto(tcp) && dport(443) -> proxy
    l4proto(udp) && dport(53) -> proxy
    fallback: direct
}
"#,
        )
        .unwrap();
        let config = build_config(&sections).unwrap();
        let plan = build_routing_plan(&config).unwrap();

        assert!(plan.skipped_rules.is_empty());
        assert_eq!(plan.lpm_sets.len(), 1);
        assert!(
            plan.matches
                .iter()
                .any(|set| set.kind == "IpSet" && set.must)
        );
        assert!(plan.matches.iter().any(|set| set.kind == "L4Proto"));
        assert!(plan.matches.iter().any(|set| set.kind == "Port"));
        assert_eq!(plan.matches.last().unwrap().kind, "Fallback");
        assert_eq!(
            plan.matches.last().unwrap().outbound,
            OutboundIndex::DIRECT.value()
        );
    }
}

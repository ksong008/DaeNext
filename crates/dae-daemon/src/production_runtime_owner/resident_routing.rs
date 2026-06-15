use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
    os::fd::AsRawFd,
    path::PathBuf,
};

use dae_config::{Config, Function, RoutingRule};
use dae_ebpf_support::{
    RuntimeMapInfo, RuntimeMapSnapshot, map_info, open_map_fd, update_map_elem_bytes,
};
use dae_routing::RoutingMatcher;
use serde_json::{Value, json};

mod geodata;
mod maps;
mod plan;
mod types;

#[cfg(test)]
mod tests;

pub(super) use geodata::GeodataResolver as ResidentGeodataStore;
use geodata::geodata_report_json;
use maps::{
    ensure_map_contract, map_json, open_all_maps, open_latest_map_in_ids, open_optional_unique_map,
    open_unique_map, update_lpm_array_map, update_outbound_connectivity_map,
};
use plan::{
    build_routing_plan_with_geodata_resolver, domain_set_json, userspace_matcher_typed_sets,
};
use types::MatchSetBytes;

const ROUTING_MAP_NAME: &str = "routing_map";
const LPM_ARRAY_MAP_NAME: &str = "lpm_array_map";
const OUTBOUND_CONNECTIVITY_MAP_NAME: &str = "outbound_connectivity_map";
const UNUSED_LPM_TYPE_NAME: &str = "unused_lpm_type";
const ROUTING_MAP_KEY_SIZE: u32 = 4;
const ROUTING_MAP_VALUE_SIZE: u32 = 24;
const LPM_ARRAY_KEY_SIZE: u32 = 4;
const LPM_ARRAY_VALUE_SIZE: u32 = 4;
const OUTBOUND_CONNECTIVITY_KEY_SIZE: u32 = 3;
const OUTBOUND_CONNECTIVITY_VALUE_SIZE: u32 = 4;
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
const CONNECTIVITY_L4_TCP: u8 = 6;
const CONNECTIVITY_L4_UDP: u8 = 17;
const CONNECTIVITY_L4_UDP_LEGACY: u8 = 22;
const CONNECTIVITY_IP_VERSION_4: u8 = 4;
const CONNECTIVITY_IP_VERSION_6: u8 = 6;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct ResidentRoutingApplyKey {
    routing_map_id: u32,
    lpm_array_map_id: Option<u32>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct ResidentRoutingApplyCache {
    applied: BTreeMap<ResidentRoutingApplyKey, u64>,
}

impl ResidentRoutingApplyCache {
    fn is_current(&self, key: ResidentRoutingApplyKey, checksum: u64) -> bool {
        self.applied.get(&key).copied() == Some(checksum)
    }

    fn record(&mut self, key: ResidentRoutingApplyKey, checksum: u64) {
        self.applied.insert(key, checksum);
    }
}

#[allow(dead_code)]
pub(super) fn expand_resident_dns_request_qname_rules(
    rules: &[RoutingRule],
) -> Result<Vec<RoutingRule>, String> {
    let resolver = geodata::GeodataResolver::new(Vec::<PathBuf>::new());
    expand_resident_dns_request_qname_rules_with_resolver(rules, &resolver)
}

pub(super) fn expand_resident_dns_request_qname_rules_with_resolver(
    rules: &[RoutingRule],
    resolver: &ResidentGeodataStore,
) -> Result<Vec<RoutingRule>, String> {
    let mut geodata_report = geodata::GeodataResolutionReport::default();
    let mut rules = rules.to_vec();
    for rule in &mut rules {
        for function in &mut rule.and_functions {
            if function.name != "qname" {
                continue;
            }
            expand_resident_dns_qname_function(function, &resolver, &mut geodata_report)?;
        }
    }
    Ok(rules)
}

fn expand_resident_dns_qname_function(
    function: &mut Function,
    resolver: &geodata::GeodataResolver,
    geodata_report: &mut geodata::GeodataResolutionReport,
) -> Result<(), String> {
    let mut expanded = Vec::new();
    for param in &function.params {
        match param.key.as_str() {
            "geosite" => {
                expanded.extend(geodata::load_geosite_params(
                    resolver,
                    "geosite",
                    &param.val,
                    geodata_report,
                )?);
            }
            "ext" => {
                let (filename, code) = param.val.split_once(':').ok_or_else(|| {
                    format!(
                        "dns.routing.request qname ext parameter must be file:code, got {}",
                        param.val
                    )
                })?;
                expanded.extend(geodata::load_geosite_params(
                    resolver,
                    filename,
                    code,
                    geodata_report,
                )?);
            }
            "geoip" => {
                return Err(
                    "dns.routing.request qname cannot use geoip parameters; use geosite or ext geosite data"
                        .to_owned(),
                );
            }
            _ => expanded.push(param.clone()),
        }
    }
    function.params = expanded;
    Ok(())
}

pub(super) fn update_new_resident_routing_map(
    before_map_ids: &[u32],
    config: &Config,
    geodata: &ResidentGeodataStore,
    apply_cache: &mut ResidentRoutingApplyCache,
) -> Result<(Value, u32), String> {
    let snapshot = RuntimeMapSnapshot::collect().map_err(|err| err.to_string())?;
    let new_map_ids = snapshot
        .maps()
        .iter()
        .map(|info| info.id)
        .filter(|id| !before_map_ids.contains(id))
        .collect::<Vec<_>>();
    let (routing_fd, routing_info) = open_unique_map(&snapshot, &new_map_ids, ROUTING_MAP_NAME)?;
    let lpm = open_optional_unique_map(&snapshot, &new_map_ids, LPM_ARRAY_MAP_NAME)?;
    let connectivity =
        open_latest_map_in_ids(&snapshot, &new_map_ids, OUTBOUND_CONNECTIVITY_MAP_NAME)?;
    update_resident_routing_map_fd(
        routing_fd.as_raw_fd(),
        routing_info,
        lpm.as_ref().map(|(fd, info)| (fd.as_raw_fd(), info)),
        connectivity
            .as_ref()
            .map(|(fd, info)| (fd.as_raw_fd(), info)),
        config,
        geodata,
        "new_attached_map",
        new_map_ids,
        apply_cache,
    )
}

#[allow(dead_code)]
pub(super) fn update_existing_resident_routing_map(
    routing_map_id: u32,
    lpm_array_map_id: Option<u32>,
    connectivity_map_id: Option<u32>,
    config: &Config,
    geodata: &ResidentGeodataStore,
    apply_cache: &mut ResidentRoutingApplyCache,
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
    let connectivity = match connectivity_map_id {
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
        connectivity
            .as_ref()
            .map(|(fd, info)| (fd.as_raw_fd(), info)),
        config,
        geodata,
        "existing_loaded_map",
        Vec::new(),
        apply_cache,
    )
}

pub(super) fn seed_resident_outbound_connectivity_maps(
    config: &Config,
    candidate_map_ids: &[u32],
) -> Result<Value, String> {
    let snapshot =
        RuntimeMapSnapshot::from_ids(candidate_map_ids).map_err(|err| err.to_string())?;
    let maps = open_all_maps(&snapshot, candidate_map_ids, OUTBOUND_CONNECTIVITY_MAP_NAME)?;
    let mut updates = Vec::new();
    for (fd, info) in maps {
        ensure_map_contract(
            &info,
            OUTBOUND_CONNECTIVITY_MAP_NAME,
            OUTBOUND_CONNECTIVITY_KEY_SIZE,
            OUTBOUND_CONNECTIVITY_VALUE_SIZE,
        )?;
        let update = update_outbound_connectivity_map(fd.as_raw_fd(), config)?;
        updates.push(json!({
            "map": map_json(&info),
            "update": update,
        }));
    }
    Ok(json!({
        "status": "pass",
        "map_count": updates.len(),
        "maps": updates,
        "candidate_map_ids": candidate_map_ids,
        "scope": "seed resident outbound connectivity maps owned by the current runtime after peer, LAN, and host attach",
    }))
}

#[allow(dead_code)]
pub(super) fn build_resident_userspace_routing_matcher(
    config: &Config,
) -> Result<RoutingMatcher, String> {
    let geodata = ResidentGeodataStore::new(Vec::<PathBuf>::new());
    build_resident_userspace_routing_matcher_with_geodata(config, &geodata)
}

pub(super) fn build_resident_userspace_routing_matcher_with_geodata(
    config: &Config,
    geodata: &ResidentGeodataStore,
) -> Result<RoutingMatcher, String> {
    let plan = build_routing_plan_with_geodata_resolver(config, geodata)?;
    let (domain_sets, lpm_sets, matches) = userspace_matcher_typed_sets(&plan)?;
    RoutingMatcher::from_shared_typed_sets(domain_sets, lpm_sets, matches)
        .map_err(|err| format!("build resident userspace routing matcher: {err}"))
}

fn update_resident_routing_map_fd(
    routing_map_fd: i32,
    routing_info: RuntimeMapInfo,
    lpm_array: Option<(i32, &RuntimeMapInfo)>,
    connectivity: Option<(i32, &RuntimeMapInfo)>,
    config: &Config,
    geodata: &ResidentGeodataStore,
    source: &str,
    new_map_ids: Vec<u32>,
    apply_cache: &mut ResidentRoutingApplyCache,
) -> Result<(Value, u32), String> {
    ensure_map_contract(
        &routing_info,
        ROUTING_MAP_NAME,
        ROUTING_MAP_KEY_SIZE,
        ROUTING_MAP_VALUE_SIZE,
    )?;
    let plan = build_routing_plan_with_geodata_resolver(config, geodata)?;
    let apply_key = ResidentRoutingApplyKey {
        routing_map_id: routing_info.id,
        lpm_array_map_id: lpm_array.map(|(_, info)| info.id),
    };
    let apply_checksum = resident_routing_apply_checksum(&plan);
    let routing_update_skipped = apply_cache.is_current(apply_key, apply_checksum);
    if !routing_update_skipped {
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
        apply_cache.record(apply_key, apply_checksum);
    }
    let connectivity_update = match connectivity {
        Some((fd, info)) => {
            ensure_map_contract(
                info,
                OUTBOUND_CONNECTIVITY_MAP_NAME,
                OUTBOUND_CONNECTIVITY_KEY_SIZE,
                OUTBOUND_CONNECTIVITY_VALUE_SIZE,
            )?;
            update_outbound_connectivity_map(fd, config)?
        }
        None => json!({
            "status": "skipped",
            "reason": "resident outbound connectivity map was not found",
        }),
    };

    Ok((
        json!({
            "status": "pass",
            "source": source,
            "map": map_json(&routing_info),
            "new_map_ids": new_map_ids,
            "routing_plan_checksum": apply_checksum,
            "routing_map_update_skipped": routing_update_skipped,
            "match_set_count": plan.matches.len(),
            "lpm_set_count": plan.lpm_sets.len(),
            "domain_set_count": plan.domain_sets.len(),
            "domain_sets": plan.domain_sets.iter().map(domain_set_json).collect::<Vec<_>>(),
            "geodata_resolution": geodata_report_json(&plan.geodata_report),
            "skipped_rule_count": plan.skipped_rules.len(),
            "skipped_rules": plan.skipped_rules,
            "fallback_is_last": plan.matches.last().is_some_and(|set| set.kind == "Fallback"),
            "compiled_match_sets": plan.matches.iter().map(match_set_json).collect::<Vec<_>>(),
            "outbound_connectivity_map_update": connectivity_update,
        }),
        routing_info.id,
    ))
}

fn resident_routing_apply_checksum(plan: &types::ResidentRoutingPlan) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for match_set in &plan.matches {
        match_set.bytes.hash(&mut hasher);
    }
    for prefixes in &plan.lpm_sets {
        prefixes.len().hash(&mut hasher);
        for prefix in prefixes.iter() {
            prefix.addr.hash(&mut hasher);
            prefix.bits.hash(&mut hasher);
        }
    }
    hasher.finish()
}

fn match_set_json(set: &MatchSetBytes) -> Value {
    json!({
        "kind": set.kind,
        "outbound": set.outbound,
        "mark": set.mark,
        "must": set.must,
    })
}

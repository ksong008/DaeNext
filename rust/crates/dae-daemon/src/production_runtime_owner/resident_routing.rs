use std::os::fd::AsRawFd;

use dae_config::Config;
use dae_ebpf_support::{RuntimeMapInfo, map_ids, map_info, open_map_fd, update_map_elem_bytes};
use dae_routing::RoutingMatcher;
use serde_json::{Value, json};

mod geodata;
mod maps;
mod plan;
mod types;

#[cfg(test)]
mod tests;

use geodata::geodata_report_json;
use maps::{
    ensure_map_contract, map_json, open_all_maps, open_optional_latest_map,
    open_optional_unique_map, open_unique_map, update_lpm_array_map,
    update_outbound_connectivity_map,
};
use plan::{build_routing_plan, domain_set_json, userspace_matcher_typed_sets};
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
const CONNECTIVITY_L4_UDP_GO_LEGACY: u8 = 22;
const CONNECTIVITY_IP_VERSION_4: u8 = 4;
const CONNECTIVITY_IP_VERSION_6: u8 = 6;

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
    let connectivity = match open_optional_unique_map(&new_map_ids, OUTBOUND_CONNECTIVITY_MAP_NAME)?
    {
        Some(map) => Some(map),
        None => open_optional_latest_map(&current, OUTBOUND_CONNECTIVITY_MAP_NAME)?,
    };
    update_resident_routing_map_fd(
        routing_fd.as_raw_fd(),
        routing_info,
        lpm.as_ref().map(|(fd, info)| (fd.as_raw_fd(), info)),
        connectivity
            .as_ref()
            .map(|(fd, info)| (fd.as_raw_fd(), info)),
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
        None,
        config,
        "existing_loaded_map",
        Vec::new(),
    )
}

pub(super) fn seed_resident_outbound_connectivity_maps(config: &Config) -> Result<Value, String> {
    let current = map_ids().map_err(|err| err.to_string())?;
    let maps = open_all_maps(&current, OUTBOUND_CONNECTIVITY_MAP_NAME)?;
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
        "scope": "seed all currently loaded resident outbound connectivity maps after peer, LAN, and host attach",
    }))
}

pub(super) fn build_resident_userspace_routing_matcher(
    config: &Config,
) -> Result<RoutingMatcher, String> {
    let plan = build_routing_plan(config)?;
    let (domain_sets, lpm_sets, matches) = userspace_matcher_typed_sets(&plan)?;
    RoutingMatcher::from_typed_sets(domain_sets, lpm_sets, matches)
        .map_err(|err| format!("build resident userspace routing matcher: {err}"))
}

fn update_resident_routing_map_fd(
    routing_map_fd: i32,
    routing_info: RuntimeMapInfo,
    lpm_array: Option<(i32, &RuntimeMapInfo)>,
    connectivity: Option<(i32, &RuntimeMapInfo)>,
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

fn match_set_json(set: &MatchSetBytes) -> Value {
    json!({
        "kind": set.kind,
        "outbound": set.outbound,
        "mark": set.mark,
        "must": set.must,
    })
}

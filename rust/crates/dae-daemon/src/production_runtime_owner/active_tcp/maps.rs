use std::os::fd::AsRawFd;

use dae_datapath::{active_tcp_routing_fallback_value, active_tcp_routing_map_contract};
use dae_ebpf_support::{RuntimeMapInfo, map_ids, map_info, open_map_fd, update_map_elem_bytes};
use serde_json::{Value, json};

pub(in crate::production_runtime_owner) fn update_routing_map(
    before_map_ids: &[u32],
    so_mark: u32,
) -> Result<(Value, u32), String> {
    let contract = active_tcp_routing_map_contract(so_mark);
    let (fd, info, new_map_ids) = open_unique_new_map(
        before_map_ids,
        contract.map_name,
        contract.key_size,
        contract.value_size,
    )
    .map_err(|err| err.to_string())?;
    update_routing_map_fd(
        fd.as_raw_fd(),
        info,
        new_map_ids,
        so_mark,
        "new_attached_map",
    )
}

pub(in crate::production_runtime_owner) fn update_existing_routing_map(
    map_id: u32,
    so_mark: u32,
) -> Result<(Value, u32), String> {
    let fd = open_map_fd(map_id).map_err(|err| err.to_string())?;
    let info = map_info(fd.as_raw_fd()).map_err(|err| err.to_string())?;
    update_routing_map_fd(
        fd.as_raw_fd(),
        info,
        Vec::new(),
        so_mark,
        "native_loaded_map",
    )
}

fn update_routing_map_fd(
    map_fd: i32,
    info: RuntimeMapInfo,
    new_map_ids: Vec<u32>,
    so_mark: u32,
    source: &str,
) -> Result<(Value, u32), String> {
    let contract = active_tcp_routing_map_contract(so_mark);
    if info.name != contract.map_name
        || info.key_size != contract.key_size
        || info.value_size != contract.value_size
    {
        return Err(format!(
            "routing map contract mismatch: name={} key_size={} value_size={}",
            info.name, info.key_size, info.value_size
        ));
    }
    let key = contract.key.to_ne_bytes();
    let value = active_tcp_routing_fallback_value(&contract);
    update_map_elem_bytes(map_fd, &key, &value).map_err(|err| err.to_string())?;
    Ok((
        json!({
            "status": "pass",
            "map": map_json(&info),
            "new_map_ids": new_map_ids,
            "source": source,
            "key": contract.key,
            "match_type": "Fallback",
            "match_type_value": contract.match_type,
            "outbound": contract.outbound,
            "mark": contract.mark,
            "must": contract.must,
        }),
        info.id,
    ))
}

fn open_unique_new_map(
    before_map_ids: &[u32],
    name: &str,
    key_size: u32,
    value_size: u32,
) -> std::io::Result<(std::os::fd::OwnedFd, RuntimeMapInfo, Vec<u32>)> {
    let current = map_ids()?;
    let new_map_ids = current
        .iter()
        .copied()
        .filter(|id| !before_map_ids.contains(id))
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    for id in &new_map_ids {
        let fd = open_map_fd(*id)?;
        let info = map_info(fd.as_raw_fd())?;
        if info.name == name && info.key_size == key_size && info.value_size == value_size {
            candidates.push((fd, info));
        }
    }
    if candidates.len() != 1 {
        return Err(std::io::Error::other(format!(
            "expected exactly one new map {name}, found {}",
            candidates.len()
        )));
    }
    let (fd, info) = candidates.remove(0);
    Ok((fd, info, new_map_ids))
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

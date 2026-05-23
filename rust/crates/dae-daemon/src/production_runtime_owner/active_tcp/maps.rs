use std::os::fd::AsRawFd;

use dae_ebpf_support::{RuntimeMapInfo, map_ids, map_info, open_map_fd, update_map_elem_bytes};
use serde_json::{Value, json};

use super::{MATCH_TYPE_FALLBACK, OUTBOUND_ACTIVE_TCP_PROXY, ROUTING_MAP_KERNEL_NAME};

pub(in crate::production_runtime_owner) fn update_routing_map(
    before_map_ids: &[u32],
    so_mark: u32,
) -> Result<(Value, u32), String> {
    let (fd, info, new_map_ids) =
        open_unique_new_map(before_map_ids, ROUTING_MAP_KERNEL_NAME, 4, 24)
            .map_err(|err| err.to_string())?;
    let key = 0_u32.to_ne_bytes();
    let value = fallback_match_set_value(OUTBOUND_ACTIVE_TCP_PROXY, so_mark);
    update_map_elem_bytes(fd.as_raw_fd(), &key, &value).map_err(|err| err.to_string())?;
    Ok((
        json!({
            "status": "pass",
            "map": map_json(&info),
            "new_map_ids": new_map_ids,
            "key": 0,
            "match_type": "Fallback",
            "match_type_value": MATCH_TYPE_FALLBACK,
            "outbound": OUTBOUND_ACTIVE_TCP_PROXY,
            "mark": so_mark,
            "must": false,
        }),
        info.id,
    ))
}

fn fallback_match_set_value(outbound: u8, mark: u32) -> [u8; 24] {
    let mut value = [0_u8; 24];
    value[17] = MATCH_TYPE_FALLBACK;
    value[18] = outbound;
    value[20..24].copy_from_slice(&mark.to_ne_bytes());
    value
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

use std::{
    io,
    mem::size_of,
    net::IpAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use dae_config::Config;
use dae_core_types::OutboundIndex;
use dae_ebpf_support::{RuntimeMapInfo, map_info, open_map_fd, update_map_elem_bytes};
use serde_json::{Value, json};

use super::types::{IpPrefix, OutboundConnectivityEntry};
use super::{
    BPF_F_NO_PREALLOC, BPF_MAP_CREATE, BPF_MAP_TYPE_LPM_TRIE, CONNECTIVITY_IP_VERSION_4,
    CONNECTIVITY_IP_VERSION_6, CONNECTIVITY_L4_TCP, CONNECTIVITY_L4_UDP,
    CONNECTIVITY_L4_UDP_GO_LEGACY, LPM_KEY_SIZE, LPM_MAX_ENTRIES, LPM_VALUE_SIZE,
    UNUSED_LPM_TYPE_NAME,
};

pub(super) fn update_lpm_array_map(
    lpm_array_fd: i32,
    lpm_sets: &[Vec<IpPrefix>],
) -> Result<(), String> {
    for (index, prefixes) in lpm_sets.iter().enumerate() {
        let inner = create_lpm_map(prefixes)?;
        let key = (index as u32).to_ne_bytes();
        let value = (inner.as_raw_fd() as u32).to_ne_bytes();
        update_map_elem_bytes(lpm_array_fd, &key, &value).map_err(|err| err.to_string())?;
    }
    Ok(())
}

pub(super) fn update_outbound_connectivity_map(
    connectivity_fd: i32,
    config: &Config,
) -> Result<Value, String> {
    let outbound_ids = resident_user_outbound_ids(config);
    let entries = resident_outbound_connectivity_entries(config);
    let mut written = Vec::new();
    let alive = 1_u32.to_ne_bytes();
    for entry in entries {
        let key = [entry.outbound, entry.l4proto, entry.ipversion];
        update_map_elem_bytes(connectivity_fd, &key, &alive).map_err(|err| err.to_string())?;
        written.push(json!({
            "outbound": entry.outbound,
            "l4proto": entry.l4proto,
            "ipversion": entry.ipversion,
            "alive": true,
        }));
    }
    Ok(json!({
        "status": "pass",
        "outbound_count": outbound_ids.len(),
        "entry_count": written.len(),
        "entries": written,
        "scope": "resident runtime seeds user-defined outbound connectivity because Go control-plane alive callbacks are not running in the Rust resident default daemon",
    }))
}

pub(super) fn resident_user_outbound_ids(config: &Config) -> Vec<u8> {
    config
        .group
        .iter()
        .enumerate()
        .filter_map(|(index, _)| {
            let outbound = index + OutboundIndex::USER_DEFINED_MIN.value() as usize;
            (outbound <= OutboundIndex::USER_DEFINED_MAX.value() as usize).then_some(outbound as u8)
        })
        .collect()
}

pub(super) fn resident_outbound_connectivity_entries(
    config: &Config,
) -> Vec<OutboundConnectivityEntry> {
    let mut entries = Vec::new();
    for outbound in resident_user_outbound_ids(config) {
        for l4proto in [
            CONNECTIVITY_L4_TCP,
            CONNECTIVITY_L4_UDP,
            CONNECTIVITY_L4_UDP_GO_LEGACY,
        ] {
            for ipversion in [CONNECTIVITY_IP_VERSION_4, CONNECTIVITY_IP_VERSION_6] {
                entries.push(OutboundConnectivityEntry {
                    outbound,
                    l4proto,
                    ipversion,
                });
            }
        }
    }
    entries
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

pub(super) fn ensure_map_contract(
    info: &RuntimeMapInfo,
    name: &str,
    key_size: u32,
    value_size: u32,
) -> Result<(), String> {
    if !runtime_map_name_matches(&info.name, name)
        || info.key_size != key_size
        || info.value_size != value_size
    {
        return Err(format!(
            "map contract mismatch: expected {name} key_size={key_size} value_size={value_size}; got name={} key_size={} value_size={}",
            info.name, info.key_size, info.value_size
        ));
    }
    Ok(())
}

pub(super) fn open_unique_map(
    ids: &[u32],
    name: &str,
) -> Result<(OwnedFd, RuntimeMapInfo), String> {
    let mut candidates = Vec::new();
    for id in ids {
        let Some((fd, info)) = open_map_info_if_alive(*id)? else {
            continue;
        };
        if runtime_map_name_matches(&info.name, name) {
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

pub(super) fn open_optional_unique_map(
    ids: &[u32],
    name: &str,
) -> Result<Option<(OwnedFd, RuntimeMapInfo)>, String> {
    let mut candidates = Vec::new();
    for id in ids {
        let Some((fd, info)) = open_map_info_if_alive(*id)? else {
            continue;
        };
        if runtime_map_name_matches(&info.name, name) {
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

pub(super) fn open_optional_latest_map(
    ids: &[u32],
    name: &str,
) -> Result<Option<(OwnedFd, RuntimeMapInfo)>, String> {
    let mut selected = None;
    for id in ids {
        let Some((fd, info)) = open_map_info_if_alive(*id)? else {
            continue;
        };
        if !runtime_map_name_matches(&info.name, name) {
            continue;
        }
        if selected
            .as_ref()
            .is_none_or(|(_, selected_info): &(OwnedFd, RuntimeMapInfo)| info.id > selected_info.id)
        {
            selected = Some((fd, info));
        }
    }
    Ok(selected)
}

pub(super) fn open_all_maps(
    ids: &[u32],
    name: &str,
) -> Result<Vec<(OwnedFd, RuntimeMapInfo)>, String> {
    let mut maps = Vec::new();
    for id in ids {
        let Some((fd, info)) = open_map_info_if_alive(*id)? else {
            continue;
        };
        if runtime_map_name_matches(&info.name, name) {
            maps.push((fd, info));
        }
    }
    Ok(maps)
}

pub(super) fn runtime_map_name_matches(actual: &str, expected: &str) -> bool {
    actual == expected || actual == kernel_map_name(expected)
}

fn kernel_map_name(name: &str) -> String {
    name.as_bytes()
        .iter()
        .take(15)
        .map(|byte| *byte as char)
        .collect()
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

pub(super) fn map_json(info: &RuntimeMapInfo) -> Value {
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

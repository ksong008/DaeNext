use std::io;
use std::mem::size_of;
use std::os::fd::{FromRawFd, OwnedFd};

use crate::{
    BPF_LPM_FULL_PREFIX_BITS, BpfDomainRouting, BpfLpmKey, BpfMatchSet, RuntimeMapUpdateDiffReport,
    ValidatedRuntimeMapHandle, apply_runtime_map_update_diff,
};

const BPF_MAP_CREATE: libc::c_uint = 0;
const BPF_MAP_TYPE_LPM_TRIE: u32 = 11;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingMapEntry {
    pub index: u32,
    pub value: BpfMatchSet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LpmArrayMapEntry {
    pub index: u32,
    pub map_id: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LpmMapEntry {
    pub key: BpfLpmKey,
    pub value: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LpmMapBuildSpec {
    pub index: u32,
    pub flags: u32,
    pub max_entries: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub entries: Vec<LpmMapEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainRoutingMapEntry {
    pub key: [u32; 4],
    pub value: BpfDomainRouting,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RoutingMapApplyReport {
    pub routing_entries_updated: usize,
    pub lpm_entries_updated: usize,
    pub lpm_maps_created: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DomainRoutingMapApplyReport {
    pub entries_updated: usize,
    pub entries_deleted: usize,
}

pub fn apply_routing_maps_by_id(
    routing_map_id: u32,
    lpm_array_map_id: u32,
    routing_entries: &[RoutingMapEntry],
    lpm_entries: &[LpmArrayMapEntry],
) -> io::Result<RoutingMapApplyReport> {
    let routing_map = ValidatedRuntimeMapHandle::open_by_id(routing_map_id)?;
    let lpm_array_map = ValidatedRuntimeMapHandle::open_by_id(lpm_array_map_id)?;

    for entry in lpm_entries {
        let inner = ValidatedRuntimeMapHandle::open_by_id(entry.map_id)?;
        let key = entry.index.to_ne_bytes();
        let value = (inner.as_raw_fd() as u32).to_ne_bytes();
        lpm_array_map.update_elem_bytes(&key, &value)?;
    }

    for entry in routing_entries {
        let key = entry.index.to_ne_bytes();
        routing_map.update_elem_bytes(&key, plain_bytes(&entry.value))?;
    }

    Ok(RoutingMapApplyReport {
        routing_entries_updated: routing_entries.len(),
        lpm_entries_updated: lpm_entries.len(),
        lpm_maps_created: 0,
    })
}

pub fn apply_routing_maps_with_lpm_build_by_id(
    routing_map_id: u32,
    lpm_array_map_id: u32,
    routing_entries: &[RoutingMapEntry],
    lpm_entries: &[LpmArrayMapEntry],
    lpm_maps: &[LpmMapBuildSpec],
) -> io::Result<RoutingMapApplyReport> {
    let routing_map = ValidatedRuntimeMapHandle::open_by_id(routing_map_id)?;
    let lpm_array_map = ValidatedRuntimeMapHandle::open_by_id(lpm_array_map_id)?;
    let mut created_lpm_maps = Vec::with_capacity(lpm_maps.len());

    for spec in lpm_maps {
        let inner = create_lpm_trie_map(spec)?;
        for entry in &spec.entries {
            inner.update_elem_bytes(plain_bytes(&entry.key), plain_bytes(&entry.value))?;
        }
        let key = spec.index.to_ne_bytes();
        let value = (inner.as_raw_fd() as u32).to_ne_bytes();
        lpm_array_map.update_elem_bytes(&key, &value)?;
        created_lpm_maps.push(inner);
    }

    for entry in lpm_entries {
        let inner = ValidatedRuntimeMapHandle::open_by_id(entry.map_id)?;
        let key = entry.index.to_ne_bytes();
        let value = (inner.as_raw_fd() as u32).to_ne_bytes();
        lpm_array_map.update_elem_bytes(&key, &value)?;
    }

    for entry in routing_entries {
        let key = entry.index.to_ne_bytes();
        routing_map.update_elem_bytes(&key, plain_bytes(&entry.value))?;
    }

    Ok(RoutingMapApplyReport {
        routing_entries_updated: routing_entries.len(),
        lpm_entries_updated: lpm_entries.len() + lpm_maps.len(),
        lpm_maps_created: created_lpm_maps.len(),
    })
}

pub fn apply_domain_routing_map_by_id(
    map_id: u32,
    updates: &[DomainRoutingMapEntry],
    deletes: &[[u32; 4]],
) -> io::Result<DomainRoutingMapApplyReport> {
    let map = ValidatedRuntimeMapHandle::open_by_id(map_id)?;
    let mut snapshots = Vec::with_capacity(updates.len().saturating_add(deletes.len()));
    for key in updates
        .iter()
        .map(|entry| entry.key)
        .chain(deletes.iter().copied())
    {
        if snapshots
            .iter()
            .any(|(snapshot_key, _)| *snapshot_key == key)
        {
            continue;
        }
        let mut old_value = [0_u8; size_of::<BpfDomainRouting>()];
        let old_value = match map.lookup_elem_bytes(plain_bytes(&key), &mut old_value) {
            Ok(()) => Some(old_value),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => None,
            Err(error) => return Err(error),
        };
        snapshots.push((key, old_value));
    }

    for entry in updates {
        if let Err(err) = map.update_elem_bytes(plain_bytes(&entry.key), plain_bytes(&entry.value))
        {
            return Err(domain_routing_apply_error(
                err,
                rollback_domain_routing_snapshot(&map, &snapshots),
            ));
        }
    }
    for key in deletes {
        if let Err(err) = map.delete_elem_bytes(plain_bytes(key))
            && err.raw_os_error() != Some(libc::ENOENT)
        {
            return Err(domain_routing_apply_error(
                err,
                rollback_domain_routing_snapshot(&map, &snapshots),
            ));
        }
    }
    Ok(DomainRoutingMapApplyReport {
        entries_updated: updates.len(),
        entries_deleted: deletes.len(),
    })
}

fn rollback_domain_routing_snapshot(
    map: &ValidatedRuntimeMapHandle,
    snapshots: &[([u32; 4], Option<[u8; size_of::<BpfDomainRouting>()]>)],
) -> io::Result<()> {
    let mut first_error = None;
    for (key, old_value) in snapshots.iter().rev() {
        let result = match old_value {
            Some(old_value) => map.update_elem_bytes(plain_bytes(key), old_value),
            None => map.delete_elem_bytes(plain_bytes(key)),
        };
        if let Err(error) = result
            && error.raw_os_error() != Some(libc::ENOENT)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn domain_routing_apply_error(operation: io::Error, rollback: io::Result<()>) -> io::Error {
    match rollback {
        Ok(()) => operation,
        Err(rollback) => io::Error::other(format!(
            "domain routing map operation failed: {operation}; rollback also failed: {rollback}"
        )),
    }
}

pub fn apply_domain_routing_map_diff_by_id(
    map_id: u32,
    current: &[DomainRoutingMapEntry],
    desired: &[DomainRoutingMapEntry],
) -> io::Result<RuntimeMapUpdateDiffReport> {
    let map = ValidatedRuntimeMapHandle::open_by_id(map_id)?;
    apply_runtime_map_update_diff(
        current.iter().map(|entry| (entry.key, entry.value)),
        desired.iter().map(|entry| (entry.key, entry.value)),
        |key, value| map.update_elem_bytes(plain_bytes(key), plain_bytes(value)),
        |key| {
            if let Err(err) = map.delete_elem_bytes(plain_bytes(key))
                && err.raw_os_error() != Some(libc::ENOENT)
            {
                return Err(err);
            }
            Ok(())
        },
    )
}

fn plain_bytes<T>(value: &T) -> &[u8] {
    // SAFETY: The caller only passes repr(C)/plain-old-data keys or values used by
    // the kernel BPF ABI. The returned slice is tied to the input reference.
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
}

fn create_lpm_trie_map(spec: &LpmMapBuildSpec) -> io::Result<ValidatedRuntimeMapHandle> {
    if spec.key_size != size_of::<BpfLpmKey>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "bad LPM key size for index {}: got {}, want {}",
                spec.index,
                spec.key_size,
                size_of::<BpfLpmKey>()
            ),
        ));
    }
    if spec.value_size != size_of::<u32>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "bad LPM value size for index {}: got {}, want {}",
                spec.index,
                spec.value_size,
                size_of::<u32>()
            ),
        ));
    }
    if spec.max_entries == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("bad LPM max entries for index {}: got 0", spec.index),
        ));
    }
    if spec.entries.len() > spec.max_entries as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "too many LPM entries for index {}: got {}, max {}",
                spec.index,
                spec.entries.len(),
                spec.max_entries
            ),
        ));
    }
    if let Some(entry) = spec
        .entries
        .iter()
        .find(|entry| entry.key.prefix_len > BPF_LPM_FULL_PREFIX_BITS)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "bad LPM prefix length for index {}: got {}, max {}",
                spec.index, entry.key.prefix_len, BPF_LPM_FULL_PREFIX_BITS
            ),
        ));
    }

    let mut attr = BpfMapCreateAttr {
        map_type: BPF_MAP_TYPE_LPM_TRIE,
        key_size: spec.key_size,
        value_size: spec.value_size,
        max_entries: spec.max_entries,
        map_flags: spec.flags,
        ..BpfMapCreateAttr::default()
    };
    attr.map_name[..12].copy_from_slice(b"dae_lpm_rust");
    // SAFETY: The attr pointer references a fully initialized BPF_MAP_CREATE
    // payload for the duration of the syscall.
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
    // SAFETY: A successful BPF_MAP_CREATE returns a new owned file descriptor.
    ValidatedRuntimeMapHandle::from_owned_fd(unsafe { OwnedFd::from_raw_fd(fd as i32) })
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

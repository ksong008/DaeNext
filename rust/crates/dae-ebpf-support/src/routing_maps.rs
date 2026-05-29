use std::io;
use std::os::fd::AsRawFd;

use crate::{
    BpfDomainRouting, BpfMatchSet, delete_map_elem_bytes, open_map_fd, update_map_elem_bytes,
};

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
pub struct DomainRoutingMapEntry {
    pub key: [u32; 4],
    pub value: BpfDomainRouting,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RoutingMapApplyReport {
    pub routing_entries_updated: usize,
    pub lpm_entries_updated: usize,
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
    let routing_map = open_map_fd(routing_map_id)?;
    let lpm_array_map = open_map_fd(lpm_array_map_id)?;

    for entry in lpm_entries {
        let inner = open_map_fd(entry.map_id)?;
        let key = entry.index.to_ne_bytes();
        let value = (inner.as_raw_fd() as u32).to_ne_bytes();
        update_map_elem_bytes(lpm_array_map.as_raw_fd(), &key, &value)?;
    }

    for entry in routing_entries {
        let key = entry.index.to_ne_bytes();
        update_map_elem_bytes(routing_map.as_raw_fd(), &key, plain_bytes(&entry.value))?;
    }

    Ok(RoutingMapApplyReport {
        routing_entries_updated: routing_entries.len(),
        lpm_entries_updated: lpm_entries.len(),
    })
}

pub fn apply_domain_routing_map_by_id(
    map_id: u32,
    updates: &[DomainRoutingMapEntry],
    deletes: &[[u32; 4]],
) -> io::Result<DomainRoutingMapApplyReport> {
    let map = open_map_fd(map_id)?;
    for entry in updates {
        update_map_elem_bytes(
            map.as_raw_fd(),
            plain_bytes(&entry.key),
            plain_bytes(&entry.value),
        )?;
    }
    for key in deletes {
        if let Err(err) = delete_map_elem_bytes(map.as_raw_fd(), plain_bytes(key)) {
            if err.raw_os_error() != Some(libc::ENOENT) {
                return Err(err);
            }
        }
    }
    Ok(DomainRoutingMapApplyReport {
        entries_updated: updates.len(),
        entries_deleted: deletes.len(),
    })
}

fn plain_bytes<T>(value: &T) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
}

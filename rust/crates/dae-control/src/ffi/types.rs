use super::*;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiRoutingMapEntry {
    pub index: u32,
    pub value: BpfMatchSet,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiLpmMapEntry {
    pub key: BpfLpmKey,
    pub value: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiLpmMapBuildSpec {
    pub index: u32,
    pub flags: u32,
    pub max_entries: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub entries: *const FfiLpmMapEntry,
    pub entries_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiDomainRoutingUpdate {
    pub key: [u32; 4],
    pub bitmap: [u32; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiRoutingOwnerApplyReport {
    pub routing_map_id: u32,
    pub lpm_array_map_id: u32,
    pub map_changed: u8,
    pub plan_changed: u8,
    pub skipped: u8,
    pub _padding: u8,
    pub checksum: u64,
    pub routing_entries_updated: usize,
    pub lpm_maps_created: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiDomainRoutingOwnerApplyReport {
    pub map_id: u32,
    pub map_id_changed: u8,
    pub skipped: u8,
    pub _padding: [u8; 2],
    pub entries_updated: usize,
    pub entries_deleted: usize,
    pub owner_count: usize,
    pub ip_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiDomainRoutingReloadClearReport {
    pub map_id: u32,
    pub map_id_changed: u8,
    pub _padding: [u8; 3],
    pub entries_deleted: usize,
    pub owner_count: usize,
    pub ip_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiConnectivityEvent {
    pub outbound: u8,
    pub l4proto: u8,
    pub ipversion: u8,
    pub alive: u8,
    pub is_init: u8,
    pub dryrun: u8,
    pub _padding: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiOutboundConnectivityOwnerApplyReport {
    pub map_id: u32,
    pub map_id_changed: u8,
    pub accepted: u8,
    pub changed: u8,
    pub skipped: u8,
    pub entries_updated: usize,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiReloadDnsCachePlan {
    pub dns_config_unchanged: u8,
    pub bpf_present: u8,
    pub restore_cache: u8,
    pub clear_domain_routing_map: u8,
    pub snapshot_entries: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiRuntimeStateReport {
    pub schema_version: u32,
    pub rust_owned_runtime: u8,
    pub reload_state_available: u8,
    pub backend_state_available: u8,
    pub routing_owner_available: u8,
    pub domain_owner_available: u8,
    pub connectivity_owner_available: u8,
    pub active_handoff_available: u8,
    pub api_compatible: u8,
    pub ready_for_default_control_plane: u8,
    pub _padding: [u8; 2],
}

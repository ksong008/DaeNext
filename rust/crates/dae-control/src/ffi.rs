use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;

use dae_ebpf_support::{
    BpfDomainRouting, BpfLpmKey, BpfMatchSet, ConnectivityEvent, ConnectivityKey,
    DomainRoutingMapEntry, LpmMapBuildSpec, LpmMapEntry, RoutingMapEntry,
    apply_domain_routing_map_by_id, apply_routing_maps_with_lpm_build_by_id,
};

use crate::{
    DomainRoutingIpKey, DomainRoutingOwner, DomainRoutingOwnerSnapshot,
    OutboundConnectivityMapOwner, RoutingMapOwner, RoutingNativeBuildPlan,
};

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

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("").expect("empty CString"));
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_last_error_message() -> *const c_char {
    LAST_ERROR.with(|last| last.borrow().as_ptr())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_ffi_abi_version() -> u32 {
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_apply_routing_maps_with_lpm_build_by_id(
    routing_map_id: u32,
    lpm_array_map_id: u32,
    routing_entries: *const FfiRoutingMapEntry,
    routing_entries_len: usize,
    lpm_maps: *const FfiLpmMapBuildSpec,
    lpm_maps_len: usize,
) -> i32 {
    ffi_result(|| {
        let plan = unsafe {
            routing_plan_from_ffi(routing_entries, routing_entries_len, lpm_maps, lpm_maps_len)?
        };
        apply_routing_maps_with_lpm_build_by_id(
            routing_map_id,
            lpm_array_map_id,
            &plan.routing_entries,
            &[],
            &plan.lpm_maps,
        )
        .map_err(|err| format!("apply routing maps via Rust in-process: {err}"))?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_routing_owner_new() -> *mut RoutingMapOwner {
    Box::into_raw(Box::<RoutingMapOwner>::default())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_routing_owner_free(owner: *mut RoutingMapOwner) {
    if owner.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(owner));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_domain_routing_owner_new() -> *mut DomainRoutingOwner {
    Box::into_raw(Box::<DomainRoutingOwner>::default())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_domain_routing_owner_free(owner: *mut DomainRoutingOwner) {
    if owner.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(owner));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_outbound_connectivity_owner_new()
-> *mut OutboundConnectivityMapOwner {
    Box::into_raw(Box::<OutboundConnectivityMapOwner>::default())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_outbound_connectivity_owner_free(
    owner: *mut OutboundConnectivityMapOwner,
) {
    if owner.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(owner));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_routing_owner_apply_snapshot_by_id(
    owner: *mut RoutingMapOwner,
    routing_map_id: u32,
    lpm_array_map_id: u32,
    routing_entries: *const FfiRoutingMapEntry,
    routing_entries_len: usize,
    lpm_maps: *const FfiLpmMapBuildSpec,
    lpm_maps_len: usize,
    report: *mut FfiRoutingOwnerApplyReport,
) -> i32 {
    ffi_result(|| {
        if owner.is_null() {
            return Err("nonnull routing owner required".to_owned());
        }
        let plan = unsafe {
            routing_plan_from_ffi(routing_entries, routing_entries_len, lpm_maps, lpm_maps_len)?
        };
        let owner = unsafe { &mut *owner };
        let applied = owner
            .apply_snapshot_by_id(routing_map_id, lpm_array_map_id, plan)
            .map_err(|err| {
                format!("apply routing map owner snapshot via Rust in-process: {err}")
            })?;
        if !report.is_null() {
            unsafe {
                *report = FfiRoutingOwnerApplyReport {
                    routing_map_id: applied.routing_map_id,
                    lpm_array_map_id: applied.lpm_array_map_id,
                    map_changed: u8::from(applied.map_changed),
                    plan_changed: u8::from(applied.plan_changed),
                    skipped: u8::from(applied.skipped),
                    _padding: 0,
                    checksum: applied.checksum,
                    routing_entries_updated: applied.routing_entries_updated,
                    lpm_maps_created: applied.lpm_maps_created,
                };
            }
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_apply_domain_routing_map_by_id(
    map_id: u32,
    updates: *const FfiDomainRoutingUpdate,
    updates_len: usize,
    deletes: *const [u32; 4],
    deletes_len: usize,
) -> i32 {
    ffi_result(|| {
        let updates = unsafe { slice_from_raw(updates, updates_len)? };
        let deletes = unsafe { slice_from_raw(deletes, deletes_len)? };
        let updates = updates
            .iter()
            .map(|entry| DomainRoutingMapEntry {
                key: entry.key,
                value: BpfDomainRouting {
                    bitmap: entry.bitmap,
                },
            })
            .collect::<Vec<_>>();
        apply_domain_routing_map_by_id(map_id, &updates, deletes)
            .map_err(|err| format!("apply domain routing map via Rust in-process: {err}"))?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_domain_routing_owner_apply_snapshot_by_id(
    owner: *mut DomainRoutingOwner,
    map_id: u32,
    owner_key: *const c_char,
    bitmap: *const [u32; 32],
    ips: *const DomainRoutingIpKey,
    ips_len: usize,
    report: *mut FfiDomainRoutingOwnerApplyReport,
) -> i32 {
    ffi_result(|| {
        if owner.is_null() {
            return Err("nonnull domain routing owner required".to_owned());
        }
        if owner_key.is_null() {
            return Err("nonnull domain routing owner key required".to_owned());
        }
        if bitmap.is_null() {
            return Err("nonnull domain routing bitmap required".to_owned());
        }
        let owner_key = unsafe { CStr::from_ptr(owner_key) }
            .to_str()
            .map_err(|err| format!("domain routing owner key is not UTF-8: {err}"))?;
        let bitmap = unsafe { *bitmap };
        let ips = unsafe { slice_from_raw(ips, ips_len)? };
        let snapshot = DomainRoutingOwnerSnapshot::from_keys(&bitmap, ips);
        let owner = unsafe { &mut *owner };
        let applied = owner
            .apply_owner_snapshot_by_id(map_id, owner_key, snapshot)
            .map_err(|err| {
                format!("apply domain routing owner snapshot via Rust in-process: {err}")
            })?;
        if !report.is_null() {
            unsafe {
                *report = FfiDomainRoutingOwnerApplyReport {
                    map_id: applied.map_id,
                    map_id_changed: u8::from(applied.map_id_changed),
                    skipped: u8::from(applied.skipped),
                    _padding: [0; 2],
                    entries_updated: applied.entries_updated,
                    entries_deleted: applied.entries_deleted,
                    owner_count: applied.owner_count,
                    ip_count: applied.ip_count,
                };
            }
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_domain_routing_owner_apply_snapshot_bytes_by_id(
    owner: *mut DomainRoutingOwner,
    map_id: u32,
    owner_key: *const u8,
    owner_key_len: usize,
    bitmap: *const [u32; 32],
    ips: *const DomainRoutingIpKey,
    ips_len: usize,
    report: *mut FfiDomainRoutingOwnerApplyReport,
) -> i32 {
    ffi_result(|| {
        if owner.is_null() {
            return Err("nonnull domain routing owner required".to_owned());
        }
        if bitmap.is_null() {
            return Err("nonnull domain routing bitmap required".to_owned());
        }
        let owner_key =
            unsafe { str_from_raw(owner_key, owner_key_len, "domain routing owner key")? };
        let bitmap = unsafe { *bitmap };
        let ips = unsafe { slice_from_raw(ips, ips_len)? };
        let snapshot = DomainRoutingOwnerSnapshot::from_keys(&bitmap, ips);
        let owner = unsafe { &mut *owner };
        let applied = owner
            .apply_owner_snapshot_by_id(map_id, owner_key, snapshot)
            .map_err(|err| {
                format!("apply domain routing owner snapshot via Rust in-process: {err}")
            })?;
        if !report.is_null() {
            unsafe {
                *report = FfiDomainRoutingOwnerApplyReport {
                    map_id: applied.map_id,
                    map_id_changed: u8::from(applied.map_id_changed),
                    skipped: u8::from(applied.skipped),
                    _padding: [0; 2],
                    entries_updated: applied.entries_updated,
                    entries_deleted: applied.entries_deleted,
                    owner_count: applied.owner_count,
                    ip_count: applied.ip_count,
                };
            }
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_domain_routing_owner_prepare_reload_map_by_id(
    owner: *mut DomainRoutingOwner,
    map_id: u32,
    existing_keys: *const DomainRoutingIpKey,
    existing_keys_len: usize,
    report: *mut FfiDomainRoutingReloadClearReport,
) -> i32 {
    ffi_result(|| {
        if owner.is_null() {
            return Err("nonnull domain routing owner required".to_owned());
        }
        let existing_keys = unsafe { slice_from_raw(existing_keys, existing_keys_len)? };
        let owner = unsafe { &mut *owner };
        let clear = owner
            .prepare_reload_map_by_id(map_id, existing_keys.iter().copied())
            .map_err(|err| format!("prepare domain routing reload via Rust in-process: {err}"))?;
        if !report.is_null() {
            unsafe {
                *report = FfiDomainRoutingReloadClearReport {
                    map_id: clear.map_id,
                    map_id_changed: u8::from(clear.map_id_changed),
                    _padding: [0; 3],
                    entries_deleted: clear.deletes.len(),
                    owner_count: clear.owner_count,
                    ip_count: clear.ip_count,
                };
            }
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_outbound_connectivity_owner_apply_event_by_id(
    owner: *mut OutboundConnectivityMapOwner,
    map_id: u32,
    event: FfiConnectivityEvent,
    report: *mut FfiOutboundConnectivityOwnerApplyReport,
) -> i32 {
    ffi_result(|| {
        if owner.is_null() {
            return Err("nonnull outbound connectivity owner required".to_owned());
        }
        let event = ConnectivityEvent {
            key: ConnectivityKey {
                outbound: event.outbound,
                l4proto: event.l4proto,
                ipversion: event.ipversion,
            },
            alive: event.alive != 0,
            is_init: event.is_init != 0,
            dryrun: event.dryrun != 0,
        };
        let owner = unsafe { &mut *owner };
        let applied = owner.apply_event_by_id(map_id, event).map_err(|err| {
            format!("apply outbound connectivity event via Rust in-process: {err}")
        })?;
        if !report.is_null() {
            unsafe {
                *report = FfiOutboundConnectivityOwnerApplyReport {
                    map_id: applied.map_id,
                    map_id_changed: u8::from(applied.map_id_changed),
                    accepted: u8::from(applied.accepted),
                    changed: u8::from(applied.changed),
                    skipped: u8::from(applied.skipped),
                    entries_updated: applied.entries_updated,
                    len: applied.len,
                };
            }
        }
        Ok(())
    })
}

unsafe fn slice_from_raw<'a, T>(ptr: *const T, len: usize) -> Result<&'a [T], String> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err("nonnull pointer required when length is nonzero".to_owned());
    }
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

unsafe fn str_from_raw<'a>(ptr: *const u8, len: usize, name: &str) -> Result<&'a str, String> {
    let bytes = unsafe { slice_from_raw(ptr, len)? };
    std::str::from_utf8(bytes).map_err(|err| format!("{name} is not UTF-8: {err}"))
}

unsafe fn routing_plan_from_ffi(
    routing_entries: *const FfiRoutingMapEntry,
    routing_entries_len: usize,
    lpm_maps: *const FfiLpmMapBuildSpec,
    lpm_maps_len: usize,
) -> Result<RoutingNativeBuildPlan, String> {
    let routing_entries = unsafe { slice_from_raw(routing_entries, routing_entries_len)? };
    let lpm_maps = unsafe { slice_from_raw(lpm_maps, lpm_maps_len)? };
    let routing_entries = routing_entries
        .iter()
        .map(|entry| RoutingMapEntry {
            index: entry.index,
            value: entry.value,
        })
        .collect::<Vec<_>>();
    let lpm_maps = lpm_maps
        .iter()
        .map(|spec| {
            let entries = unsafe { slice_from_raw(spec.entries, spec.entries_len)? };
            let entries = entries
                .iter()
                .map(|entry| LpmMapEntry {
                    key: entry.key,
                    value: entry.value,
                })
                .collect::<Vec<_>>();
            Ok(LpmMapBuildSpec {
                index: spec.index,
                flags: spec.flags,
                max_entries: spec.max_entries,
                key_size: spec.key_size,
                value_size: spec.value_size,
                entries,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(RoutingNativeBuildPlan {
        routing_entries,
        lpm_maps,
    })
}

fn ffi_result(f: impl FnOnce() -> Result<(), String>) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(f));
    match result {
        Ok(Ok(())) => {
            set_last_error("");
            0
        }
        Ok(Err(err)) => {
            set_last_error(&err);
            -1
        }
        Err(_) => {
            set_last_error("panic in dae-control FFI");
            -2
        }
    }
}

fn set_last_error(message: &str) {
    let sanitized = message.replace('\0', "\\0");
    let cstr =
        CString::new(sanitized).unwrap_or_else(|_| CString::new("invalid ffi error").unwrap());
    LAST_ERROR.with(|last| {
        *last.borrow_mut() = cstr;
    });
}

pub fn last_error_for_tests() -> String {
    LAST_ERROR.with(|last| unsafe {
        CStr::from_ptr(last.borrow().as_ptr())
            .to_string_lossy()
            .into_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_rejects_null_pointer_with_nonzero_len() {
        let rc = unsafe {
            dae_control_apply_domain_routing_map_by_id(0, std::ptr::null(), 1, std::ptr::null(), 0)
        };
        assert_eq!(rc, -1);
        assert!(last_error_for_tests().contains("nonnull pointer required"));
    }

    #[test]
    fn ffi_abi_version_is_stable() {
        assert_eq!(unsafe { dae_control_ffi_abi_version() }, 1);
    }

    #[test]
    fn ffi_routing_owner_rejects_null_owner() {
        let rc = unsafe {
            dae_control_routing_owner_apply_snapshot_by_id(
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, -1);
        assert!(last_error_for_tests().contains("routing owner"));
    }

    #[test]
    fn ffi_domain_routing_owner_rejects_null_owner() {
        let owner_key = CString::new("owner-a").unwrap();
        let rc = unsafe {
            dae_control_domain_routing_owner_apply_snapshot_by_id(
                std::ptr::null_mut(),
                0,
                owner_key.as_ptr(),
                &[0; 32],
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, -1);
        assert!(last_error_for_tests().contains("domain routing owner"));
    }

    #[test]
    fn ffi_outbound_connectivity_owner_rejects_null_owner() {
        let rc = unsafe {
            dae_control_outbound_connectivity_owner_apply_event_by_id(
                std::ptr::null_mut(),
                0,
                FfiConnectivityEvent::default(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, -1);
        assert!(last_error_for_tests().contains("outbound connectivity owner"));
    }
}

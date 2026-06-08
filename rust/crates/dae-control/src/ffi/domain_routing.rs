use super::*;
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
pub unsafe extern "C" fn dae_control_domain_routing_owner_apply_dns_event_by_id(
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
        let event = DomainRoutingDnsEvent::from_keys(owner_key, &bitmap, ips.iter().copied());
        let owner = unsafe { &mut *owner };
        let applied = owner
            .apply_dns_event_by_id(map_id, event)
            .map_err(|err| format!("apply domain routing DNS event via Rust in-process: {err}"))?;
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

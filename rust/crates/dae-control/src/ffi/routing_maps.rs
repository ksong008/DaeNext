use super::*;
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

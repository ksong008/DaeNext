use super::*;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_ffi_abi_version() -> u32 {
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_reload_dns_cache_plan(
    dns_config_unchanged: u8,
    bpf_present: u8,
    snapshot_entries: usize,
    report: *mut FfiReloadDnsCachePlan,
) -> i32 {
    ffi_result(|| {
        if report.is_null() {
            return Err("nonnull reload DNS cache plan report required".to_owned());
        }
        let plan = ReloadDnsCachePlan::decide(
            dns_config_unchanged != 0,
            bpf_present != 0,
            snapshot_entries,
        );
        unsafe {
            *report = FfiReloadDnsCachePlan {
                dns_config_unchanged: u8::from(plan.dns_config_unchanged),
                bpf_present: u8::from(plan.bpf_present),
                restore_cache: u8::from(plan.restore_cache),
                clear_domain_routing_map: u8::from(plan.clear_domain_routing_map),
                snapshot_entries: plan.snapshot_entries,
            };
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_runtime_state_report(
    rust_owned_runtime: u8,
    reload_state_available: u8,
    backend_state_available: u8,
    routing_owner_available: u8,
    domain_owner_available: u8,
    connectivity_owner_available: u8,
    active_handoff_available: u8,
    api_compatible: u8,
    report: *mut FfiRuntimeStateReport,
) -> i32 {
    ffi_result(|| {
        if report.is_null() {
            return Err("nonnull runtime state report required".to_owned());
        }
        let state = RuntimeStateReport {
            schema_version: RuntimeStateReport::SCHEMA_VERSION,
            rust_owned_runtime: rust_owned_runtime != 0,
            reload_state_available: reload_state_available != 0,
            backend_state_available: backend_state_available != 0,
            routing_owner_available: routing_owner_available != 0,
            domain_owner_available: domain_owner_available != 0,
            connectivity_owner_available: connectivity_owner_available != 0,
            active_handoff_available: active_handoff_available != 0,
            api_compatible: api_compatible != 0,
        };
        unsafe {
            *report = FfiRuntimeStateReport {
                schema_version: state.schema_version,
                rust_owned_runtime: u8::from(state.rust_owned_runtime),
                reload_state_available: u8::from(state.reload_state_available),
                backend_state_available: u8::from(state.backend_state_available),
                routing_owner_available: u8::from(state.routing_owner_available),
                domain_owner_available: u8::from(state.domain_owner_available),
                connectivity_owner_available: u8::from(state.connectivity_owner_available),
                active_handoff_available: u8::from(state.active_handoff_available),
                api_compatible: u8::from(state.api_compatible),
                ready_for_default_control_plane: u8::from(state.ready_for_default_control_plane()),
                _padding: [0; 2],
            };
        }
        Ok(())
    })
}

pub(crate) struct ProductRunRemainingBlockerFields {
    pub(super) resident_dataplane_admission_ready: bool,
    pub(super) final_native_daemon_admitted: bool,
    pub(super) production_dataplane_admitted: bool,
    pub(super) production_dataplane_harness_passed: bool,
    pub(super) reload_runtime_parity_passed: bool,
    pub(super) active_tcp_relay_passed: bool,
    pub(super) production_runtime_active_tcp_passed: bool,
    pub(super) production_runtime_owner_passed: bool,
}

pub(crate) fn product_run_remaining_blockers(
    fields: ProductRunRemainingBlockerFields,
) -> Vec<&'static str> {
    let mut remaining_blockers = Vec::new();
    if !fields.resident_dataplane_admission_ready {
        remaining_blockers
            .push("resident userspace dataplane is disabled by configuration override");
    }
    if fields.final_native_daemon_admitted {
        return remaining_blockers;
    }
    if fields.production_dataplane_admitted && !fields.reload_runtime_parity_passed {
        remaining_blockers
            .push("production dataplane is admitted, but reload/runtime parity is not complete");
    } else if fields.production_dataplane_harness_passed {
        remaining_blockers
            .push("production dataplane evidence is harness-only and not yet daemon-owned");
    } else if fields.reload_runtime_parity_passed {
        remaining_blockers.push(
            "reload/runtime parity is complete, but active TCP/UDP/DNS dataplane admission is incomplete",
        );
    } else if fields.active_tcp_relay_passed {
        remaining_blockers.push(
            "active TCP relay passed, but active UDP/DNS dataplane and reload/runtime parity remain incomplete",
        );
    } else if fields.production_runtime_active_tcp_passed {
        remaining_blockers.push(
            "active TCP ingress passed, but TCP relay plus UDP/DNS dataplane remain incomplete",
        );
    } else if fields.production_runtime_owner_passed {
        remaining_blockers.push(
            "production runtime owner smoke passed, but live dataplane evidence remains incomplete",
        );
    } else {
        remaining_blockers.push(
            "production runtime owner and active TCP/UDP/DNS dataplane are not proven in this run",
        );
    }
    remaining_blockers
}

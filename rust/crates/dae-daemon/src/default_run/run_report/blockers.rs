pub(crate) struct DefaultRunRemainingBlockerFields {
    pub(super) matched_benchmark_recorded: bool,
    pub(super) resident_dataplane_default_switch_ready: bool,
    pub(super) true_rust_default_daemon_admitted: bool,
    pub(super) release_gate_product_chain_switch_allowed: bool,
    pub(super) product_chain_switch_allowed: bool,
    pub(super) resident_default_daemon_switch_ready: bool,
    pub(super) production_dataplane_admitted: bool,
    pub(super) production_dataplane_harness_passed: bool,
    pub(super) reload_runtime_parity_passed: bool,
    pub(super) active_tcp_relay_passed: bool,
    pub(super) production_runtime_active_tcp_passed: bool,
    pub(super) production_runtime_owner_passed: bool,
    pub(super) product_chain_recertification_executed: bool,
    pub(super) product_chain_recertification_clean: bool,
}

pub(crate) fn default_run_remaining_blockers(
    fields: DefaultRunRemainingBlockerFields,
) -> Vec<&'static str> {
    let mut remaining_blockers =
        vec!["opt-in run now exists, but it still uses isolated pid/progress paths"];
    if !fields.matched_benchmark_recorded {
        remaining_blockers.push("matched Go/Rust default daemon benchmark remains blocked");
    }
    if !fields.resident_dataplane_default_switch_ready {
        remaining_blockers.push(
            "resident userspace dataplane is not enabled; default switch would redirect tproxy TCP/UDP payloads without the required Rust worker",
        );
    }
    if fields.true_rust_default_daemon_admitted {
        if fields.release_gate_product_chain_switch_allowed {
            remaining_blockers.push(
                "default path mutation request is admitted by clean product-chain recertification; production run command replacement is still not executed",
            );
        } else if fields.product_chain_switch_allowed {
            remaining_blockers.push(
                "product-chain recertification admits its local default path mutation inputs, but the stage 7 release gate remains closed until the default daemon live matrix is complete",
            );
        } else if !fields.resident_default_daemon_switch_ready {
            remaining_blockers.push(
                "resident default service path does not admit production dataplane; dae-daemon-optin run -c ... is still service-contract-only",
            );
        } else {
            remaining_blockers.push(
                "true Rust default daemon admission is recorded for the daemon-owned opt-in path; default/product switch stays closed pending clean production path mutation and dae-wing/daed recertification",
            );
        }
    } else if fields.production_dataplane_admitted {
        remaining_blockers.push(
            "production active TCP/UDP/DNS dataplane is admitted inside the daemon-owned opt-in run, but reload parity and matched benchmark must both be present before true Rust default daemon admission",
        );
    } else if fields.production_dataplane_harness_passed {
        remaining_blockers.push(
            "production dataplane evidence is integrated into run, but still harness-only and not default daemon owned",
        );
    } else if fields.reload_runtime_parity_passed {
        remaining_blockers.push(
            "production owner lifecycle now proves listener reuse, BPF/map owner handoff, DNS cache migration guard, bounded close, RuntimeOverview fields, rollback, and post-reload active TCP; active UDP/DNS dataplane or default path mutation remain unproven",
        );
    } else if fields.active_tcp_relay_passed {
        remaining_blockers.push(
            "production tproxy listener, tc/eBPF attach, active TCP ingress, and bounded TCP relay are proven inside this run, but full route-table RouteDialTcp, active UDP/DNS dataplane, and reload/runtime parity remain unproven",
        );
    } else if fields.production_runtime_active_tcp_passed {
        remaining_blockers.push(
            "production tproxy listener, tc/eBPF attach, and active TCP ingress are proven inside this run, but active TCP relay plus UDP/DNS dataplane remain unproven",
        );
    } else {
        remaining_blockers.push(
            "production tproxy listener, tc/eBPF attach, and active TCP/UDP/DNS dataplane are not yet proven inside this run",
        );
    }
    if fields.production_runtime_owner_passed && !fields.reload_runtime_parity_passed {
        remaining_blockers.push(
            "daemon-owned production runtime owner smoke passed, but active TCP relay, active UDP/DNS dataplane, and production reload/runtime parity may still be incomplete",
        );
    } else if fields.production_runtime_owner_passed && !fields.true_rust_default_daemon_admitted {
        remaining_blockers.push(
            "daemon-owned production runtime owner and reload/runtime parity passed, but full active UDP/DNS dataplane plus matched benchmark are required for true default daemon admission",
        );
    }
    if fields.active_tcp_relay_passed {
        remaining_blockers.push(
            "active TCP relay observed MagicNetwork mark/mptcp on a real outbound socket, but full route-table RouteDialTcp control-plane reroute remains unverified",
        );
    } else if fields.production_runtime_active_tcp_passed {
        remaining_blockers.push(
            "active TCP tproxy ingress reached the transparent listener, but RouteDialTcp MagicNetwork mark/mptcp relay parity remains unverified",
        );
    }
    if fields.product_chain_recertification_executed && !fields.product_chain_recertification_clean
    {
        remaining_blockers.push(
            "product-chain recertification was recorded but is not clean; default/product switch remains closed",
        );
    }
    remaining_blockers
}

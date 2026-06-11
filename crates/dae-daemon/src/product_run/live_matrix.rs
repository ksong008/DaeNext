use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn production_runtime_live_matrix_json(
    listener_smoke_executed: bool,
    listener_smoke_passed: bool,
    reload_owner_handoff_executed: bool,
    reload_owner_handoff_passed: bool,
    production_runtime_owner_executed: bool,
    production_runtime_owner_passed: bool,
    production_runtime_active_tcp_executed: bool,
    production_runtime_active_tcp_passed: bool,
    active_tcp_relay_executed: bool,
    active_tcp_relay_passed: bool,
    active_tcp_relay_benchmark_recorded: bool,
    route_dial_tcp_magic_network_observed: bool,
    production_runtime_active_udp_executed: bool,
    production_runtime_active_udp_passed: bool,
    active_udp_admitted: bool,
    active_udp_benchmark_recorded: bool,
    production_runtime_active_dns_executed: bool,
    production_runtime_active_dns_passed: bool,
    active_dns_admitted: bool,
    active_dns_benchmark_recorded: bool,
    reload_runtime_parity_executed: bool,
    reload_runtime_parity_admitted: bool,
    resident_dataplane_admission_ready: bool,
) -> Value {
    let rows = vec![
        live_matrix_row_json(
            "listener-loopback-smoke",
            listener_smoke_executed,
            listener_smoke_passed,
            "TCP and UDP loopback listener smoke must pass before bounded report admission",
            "run --exit-after-ready keeps listener smoke enabled by default",
        ),
        live_matrix_row_json(
            "reload-owner-handoff-smoke",
            reload_owner_handoff_executed,
            reload_owner_handoff_passed,
            "non-production reload owner handoff smoke must pass before production reload evidence is considered",
            "run --exit-after-ready keeps reload smoke enabled by default",
        ),
        live_matrix_row_json(
            "production-runtime-owner",
            production_runtime_owner_executed,
            production_runtime_owner_passed,
            "daemon-owned production runtime owner smoke must pass under the candidate root",
            "run with --execute-production-runtime-owner and --ack-root-gate",
        ),
        live_matrix_row_json(
            "active-tcp-ingress",
            production_runtime_active_tcp_executed,
            production_runtime_active_tcp_passed,
            "active TCP tproxy ingress must reach the transparent listener",
            "run with production runtime active TCP options and root/BPF/netns access",
        ),
        live_matrix_row_json(
            "active-tcp-relay-magic-network",
            active_tcp_relay_executed,
            active_tcp_relay_passed
                && active_tcp_relay_benchmark_recorded
                && route_dial_tcp_magic_network_observed,
            "active TCP relay must pass with benchmark evidence and MagicNetwork mark/mptcp observation",
            "run with active TCP relay benchmark enabled",
        ),
        live_matrix_row_json(
            "active-udp-datapath",
            production_runtime_active_udp_executed,
            production_runtime_active_udp_passed
                && active_udp_admitted
                && active_udp_benchmark_recorded,
            "active UDP datapath must pass with admission and benchmark evidence",
            "run with active UDP tproxy options and benchmark iterations",
        ),
        live_matrix_row_json(
            "active-dns-configured-target",
            production_runtime_active_dns_executed,
            production_runtime_active_dns_passed
                && active_dns_admitted
                && active_dns_benchmark_recorded,
            "active DNS path must pass with configured target, upstream/cache/domain-routing evidence, and benchmark record",
            "run with active DNS target/upstream options and benchmark iterations",
        ),
        live_matrix_row_json(
            "production-reload-runtime-parity",
            reload_runtime_parity_executed,
            reload_runtime_parity_admitted,
            "production reload/runtime parity must prove listener reuse, BPF owner handoff, DNS cache guard, bounded close, RuntimeOverview parity, and scoped cleanup",
            "run with production reload/runtime parity enabled",
        ),
        live_matrix_row_json(
            "resident-userspace-dataplane-admission",
            true,
            resident_dataplane_admission_ready,
            "resident userspace dataplane is enabled by Rust-native product runtime before redirected TCP/UDP payloads are owned by daed",
            "ensure no explicit resident dataplane disabling override is present",
        ),
    ];
    let matrix_complete = rows
        .iter()
        .all(|row| row["recorded"].as_bool().unwrap_or(false));
    let remaining = rows
        .iter()
        .filter(|row| !row["recorded"].as_bool().unwrap_or(false))
        .filter_map(|row| row["area"].as_str())
        .collect::<Vec<_>>();

    json!({
        "schema": "rust-native-production-runtime-live-matrix",
        "formal_surface": "rust-native-production-runtime-live-matrix",
        "matrix_complete": matrix_complete,
        "final_native_admission_allowed_by_this_matrix": matrix_complete,
        "host_write_performed": false,
        "host_mutation_performed": false,
        "rows": rows,
        "remaining_rows": remaining,
    })
}

pub(super) fn live_matrix_row_json(
    area: &'static str,
    executed: bool,
    passed: bool,
    required_evidence: &'static str,
    rerun_hint: &'static str,
) -> Value {
    json!({
        "area": area,
        "executed": executed,
        "passed": passed,
        "recorded": executed && passed,
        "status": if executed && passed { "pass" } else if executed { "fail" } else { "not-executed" },
        "required_evidence": required_evidence,
        "rerun_hint": rerun_hint,
    })
}

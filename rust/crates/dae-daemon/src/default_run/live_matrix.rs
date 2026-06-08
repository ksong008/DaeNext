fn default_daemon_live_matrix_json(
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
    matched_default_benchmark_executed: bool,
    matched_default_benchmark_recorded: bool,
    bpf_go_fallback_retired: bool,
    resident_dataplane_default_switch_required: bool,
    resident_dataplane_default_switch_ready: bool,
) -> Value {
    let rows = vec![
        live_matrix_row_json(
            "listener-loopback-smoke",
            listener_smoke_executed,
            listener_smoke_passed,
            "TCP and UDP loopback listener smoke must pass before any daemon default switch",
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
            "active-dns-udp53",
            production_runtime_active_dns_executed,
            production_runtime_active_dns_passed
                && active_dns_admitted
                && active_dns_benchmark_recorded,
            "DNS UDP/53 path must pass with upstream/cache/domain-routing evidence and benchmark record",
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
            "matched-go-rust-default-benchmark",
            matched_default_benchmark_executed,
            matched_default_benchmark_recorded,
            "matched Go default daemon vs true Rust default daemon benchmark must be recorded on the same host/config/corpus",
            "run with --execute-matched-default-benchmark and --ack-root-gate",
        ),
        live_matrix_row_json(
            "bpf-go-fallback-retirement",
            production_runtime_owner_executed,
            bpf_go_fallback_retired,
            "BPF-side Go fallback retirement evidence must be present without restoring the Go BPF loader",
            "run production runtime owner gate with BPF fallback retirement evidence",
        ),
        live_matrix_row_json(
            "resident-userspace-dataplane-default-switch",
            resident_dataplane_default_switch_required,
            resident_dataplane_default_switch_ready,
            "resident userspace dataplane must be explicitly enabled before the Rust default daemon owns redirected TCP/UDP payloads",
            "set DAE_RUST_RESIDENT_DATAPLANE=1 only after the resident dataplane worker path is expected to own the default daemon traffic",
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
        "schema": "default-daemon-live-matrix",
        "formal_surface": "default-daemon-live-matrix",
        "matrix_complete": matrix_complete,
        "release_gate_input": true,
        "default_switch_allowed_by_this_matrix": false,
        "host_write_performed": false,
        "default_path_mutation_performed": false,
        "go_runtime_outbound_fallback_required_until_release_gate": true,
        "rows": rows,
        "remaining_rows": remaining,
        "source": [
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:stage7",
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage22",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:33.8"
        ],
    })
}

fn live_matrix_row_json(
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

#[allow(clippy::too_many_arguments)]
fn release_product_chain_live_gate_json(
    production_dataplane_admitted: bool,
    reload_runtime_parity_admitted: bool,
    matched_benchmark_recorded: bool,
    bpf_go_fallback_retired: bool,
    true_rust_default_daemon_admitted: bool,
    default_daemon_live_matrix_complete: bool,
    resident_dataplane_default_switch_ready: bool,
    product_chain_recertification_executed: bool,
    product_chain_recertification_clean: bool,
    default_path_mutation_allowed: bool,
    product_chain_switch_allowed: bool,
    resident_default_daemon_switch_ready: bool,
    production_runtime_owner: &Value,
) -> Value {
    let fixed_queue_completed =
        production_runtime_owner["datapath_outbound_ebpf_deep_area"]["fixed_queue_completed"]
            .as_bool()
            .unwrap_or(false);
    let stage6_deep_area_recorded = production_runtime_owner["datapath_outbound_ebpf_deep_area"]
        ["datapath_native_assets_recorded"]
        .as_bool()
        .unwrap_or(false);
    let go_bpf_loader_restored =
        production_runtime_owner["datapath_outbound_ebpf_deep_area"]["go_bpf_loader_restored"]
            .as_bool()
            .unwrap_or(false);
    let aya_loader_direction_preserved = production_runtime_owner
        ["datapath_outbound_ebpf_deep_area"]["aya_loader_direction_preserved"]
        .as_bool()
        .unwrap_or(false);
    let full_live_matrix_admitted = default_daemon_live_matrix_complete
        && production_dataplane_admitted
        && reload_runtime_parity_admitted
        && matched_benchmark_recorded
        && bpf_go_fallback_retired
        && resident_dataplane_default_switch_ready
        && true_rust_default_daemon_admitted;
    let release_gate_open = fixed_queue_completed
        && full_live_matrix_admitted
        && product_chain_recertification_executed
        && product_chain_recertification_clean
        && default_path_mutation_allowed
        && product_chain_switch_allowed
        && resident_default_daemon_switch_ready
        && !go_bpf_loader_restored;

    let rows = vec![
        json!({
            "area": "fixed-native-queue",
            "status": if fixed_queue_completed { "pass" } else { "fail" },
            "recorded": fixed_queue_completed,
            "required_evidence": "stage1-stage6 native groups are accepted by production_runtime_owner and stage6 deep area is recorded",
            "blocker": if fixed_queue_completed { "" } else { "stage6 fixed queue completion evidence is absent from production_runtime_owner" },
        }),
        json!({
            "area": "default-daemon-live-matrix",
            "status": if full_live_matrix_admitted { "pass" } else { "fail" },
            "recorded": full_live_matrix_admitted,
            "required_evidence": "production dataplane, reload/runtime parity, matched Go/Rust default daemon benchmark, and BPF fallback retirement all pass together",
            "blocker": if full_live_matrix_admitted { "" } else { "full default daemon live matrix is incomplete" },
        }),
        json!({
            "area": "resident-userspace-dataplane-default-switch",
            "status": if resident_dataplane_default_switch_ready { "pass" } else { "fail" },
            "recorded": resident_dataplane_default_switch_ready,
            "required_evidence": "DAE_RUST_RESIDENT_DATAPLANE=1 is present before default path mutation",
            "blocker": if resident_dataplane_default_switch_ready { "" } else { "resident userspace dataplane is not enabled" },
        }),
        json!({
            "area": "product-chain-recertification",
            "status": if product_chain_recertification_clean { "pass" } else if product_chain_recertification_executed { "fail" } else { "not-executed" },
            "recorded": product_chain_recertification_clean,
            "required_evidence": "daed, dae-wing, release, package, service, WebUI/API, and dependency boundary recertification are clean",
            "blocker": if product_chain_recertification_clean { "" } else if product_chain_recertification_executed { "product-chain recertification executed but is not clean" } else { "product-chain recertification has not executed" },
        }),
        json!({
            "area": "fallback-policy",
            "status": if release_gate_open { "pass" } else { "fail" },
            "recorded": release_gate_open,
            "required_evidence": "Go runtime/outbound fallback deletion is only allowed after release gate opens and rollback is proven",
            "blocker": if release_gate_open { "" } else { "Go runtime/outbound fallback remains required" },
        }),
        json!({
            "area": "bpf-loader-boundary",
            "status": if aya_loader_direction_preserved && !go_bpf_loader_restored { "pass" } else { "fail" },
            "recorded": aya_loader_direction_preserved && !go_bpf_loader_restored,
            "required_evidence": "Rust/Aya loader direction is preserved and Go BPF loader is not restored",
            "blocker": if aya_loader_direction_preserved && !go_bpf_loader_restored { "" } else { "BPF loader boundary evidence is invalid" },
        }),
    ];

    let mut blockers = Vec::new();
    if !fixed_queue_completed {
        blockers.push("fixed stage1-stage6 native queue completion evidence is missing");
    }
    if !stage6_deep_area_recorded {
        blockers.push("stage6 datapath/outbound/eBPF deep area evidence is missing");
    }
    if !full_live_matrix_admitted {
        blockers.push("full default daemon live matrix is incomplete");
    }
    if !matched_benchmark_recorded {
        blockers.push("matched Go/Rust default daemon benchmark is not recorded");
    }
    if !resident_dataplane_default_switch_ready {
        blockers.push("resident userspace dataplane default switch env is not enabled");
    }
    if !product_chain_recertification_clean {
        blockers.push("product-chain recertification is not clean");
    }
    if !default_path_mutation_allowed {
        blockers.push("default path mutation is not allowed");
    }
    if !product_chain_switch_allowed {
        blockers.push("product-chain switch is not allowed");
    }
    if !resident_default_daemon_switch_ready {
        blockers.push("resident default daemon switch is not ready");
    }
    if go_bpf_loader_restored {
        blockers.push("Go BPF loader restoration would violate the Rust/Aya loader boundary");
    }

    json!({
        "schema": "release-product-chain-live-gate",
        "formal_surface": "release-product-chain-live-gate",
        "fixed_queue_range": "stage1-stage6",
        "fixed_queue_completed": fixed_queue_completed,
        "stage6_deep_area_recorded": stage6_deep_area_recorded,
        "stage7_gate_recorded": true,
        "release_gate_open": release_gate_open,
        "default_switch_allowed": release_gate_open && default_path_mutation_allowed,
        "product_chain_switch_allowed": release_gate_open && product_chain_switch_allowed,
        "go_default_path_preserved": !release_gate_open,
        "go_runtime_outbound_fallback_required": !release_gate_open,
        "go_runtime_outbound_fallback_deletion_allowed": release_gate_open,
        "go_bpf_loader_restored": go_bpf_loader_restored,
        "aya_loader_direction_preserved": aya_loader_direction_preserved,
        "production_dataplane_admitted": production_dataplane_admitted,
        "reload_runtime_parity_admitted": reload_runtime_parity_admitted,
        "matched_go_rust_default_daemon_benchmark_recorded": matched_benchmark_recorded,
        "bpf_go_fallback_retired": bpf_go_fallback_retired,
        "resident_dataplane_default_switch_required": true,
        "resident_dataplane_env": RESIDENT_DATAPLANE_ENV,
        "resident_dataplane_default_switch_ready": resident_dataplane_default_switch_ready,
        "true_rust_default_daemon_admitted": true_rust_default_daemon_admitted,
        "default_daemon_live_matrix_complete": default_daemon_live_matrix_complete,
        "product_chain_recertification_executed": product_chain_recertification_executed,
        "product_chain_recertification_clean": product_chain_recertification_clean,
        "default_path_mutation_allowed": default_path_mutation_allowed,
        "resident_default_daemon_switch_ready": resident_default_daemon_switch_ready,
        "gate_rows": rows,
        "remaining_blockers": blockers,
        "source": [
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:stage7",
            "rust/crates/dae-daemon/src/production_runtime_owner/deep_area.rs",
            "rust/crates/dae-product/src/release_gate.rs",
            "rust/crates/dae-product/src/product_chain_admission.rs",
            "rust/crates/dae-product/src/true_daemon_admission.rs"
        ],
    })
}

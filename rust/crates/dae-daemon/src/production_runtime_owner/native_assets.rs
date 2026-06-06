use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeNativeGroup {
    id: &'static str,
    queue_index: u8,
    name: &'static str,
    primary_crates: &'static [&'static str],
    accepted_native_assets: &'static [&'static str],
    default_switch_blockers: &'static [&'static str],
    source: &'static [&'static str],
}

const RUNTIME_NATIVE_GROUPS: &[RuntimeNativeGroup] = &[
    RuntimeNativeGroup {
        id: "control-plane-native-owner",
        queue_index: 1,
        name: "Control Plane Native Owner",
        primary_crates: &["dae-control", "dae-ebpf-support"],
        accepted_native_assets: &[
            "outbound_connectivity_state_owner",
            "domain_routing_owner_tracker",
            "reload_clear_restore_owner_model",
        ],
        default_switch_blockers: &[
            "go_dialer_group_alive_event_source_still_active",
            "runtime_map_fd_lifetime_not_yet_owned_by_default_rust_daemon",
        ],
        source: &[
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:stage1",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.1",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.12",
        ],
    },
    RuntimeNativeGroup {
        id: "routing-lpm-native-build",
        queue_index: 2,
        name: "Routing / LPM Native Build",
        primary_crates: &["dae-routing", "dae-geodata", "dae-ebpf-support"],
        accepted_native_assets: &[
            "routing_map_native_plan",
            "lpm_array_map_native_plan",
            "rule_order_fallback_last_parity",
            "geosite_geoip_reference_boundary",
        ],
        default_switch_blockers: &[
            "production_config_to_routing_map_input_chain_not_fully_rust_owned",
            "kernel_map_write_lifetime_remains_stage6_boundary",
        ],
        source: &[
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:stage2",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.2",
        ],
    },
    RuntimeNativeGroup {
        id: "dns-native-hot-path",
        queue_index: 3,
        name: "DNS Native Hot Path",
        primary_crates: &["dae-dns", "dae-control", "dae-routing"],
        accepted_native_assets: &[
            "dns_packet_question_view",
            "dns_request_cache_hit_packet_view",
            "dns_response_cache_plan_packet_view",
            "dns_cache_key_owner_semantics",
        ],
        default_switch_blockers: &[
            "go_dns_controller_forwarder_still_authoritative",
            "domain_routing_map_runtime_owner_not_default_rust_owned",
        ],
        source: &[
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:stage3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.4",
        ],
    },
    RuntimeNativeGroup {
        id: "sniffing-geodata-matcher-native",
        queue_index: 4,
        name: "Sniffing / Geodata / Matcher Native",
        primary_crates: &["dae-sniffing", "dae-geodata", "dae-routing"],
        accepted_native_assets: &[
            "borrowed_http_host_sniff",
            "borrowed_tls_sni_sniff",
            "tcp_sniff_buffer_preserve",
            "streaming_geodata_entry_view",
            "domain_matcher_bitmap_reuse",
            "userspace_routing_matcher_bitmap_reuse",
        ],
        default_switch_blockers: &[
            "dial_mode_sniff_runtime_entry_not_default_rust_owned",
            "sniffed_first_payload_relay_not_validated_in_default_daemon",
        ],
        source: &[
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:stage4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.7",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.1",
        ],
    },
    RuntimeNativeGroup {
        id: "datapath-outbound-ebpf-deep-area",
        queue_index: 6,
        name: "Datapath / Outbound / eBPF Deep Area",
        primary_crates: &[
            "dae-datapath",
            "dae-outbound",
            "dae-ebpf-support",
            "dae-netutil",
            "dae-daemon",
        ],
        accepted_native_assets: &[
            "tcp_active_datapath_native_assets",
            "udp_active_datapath_native_assets",
            "outbound_protocol_stack_native_assets",
            "ebpf_backend_host_ops_native_assets",
        ],
        default_switch_blockers: &[
            "product_chain_release_gate_not_opened_by_stage6_report",
            "go_runtime_and_go_outbound_still_authoritative_for_default_product_path",
            "full_live_protocol_matrix_not_completed_in_default_resident_daemon",
        ],
        source: &[
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:stage6",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:12",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22",
        ],
    },
];

const RUNTIME_OWNER_BLOCKERS: &[&str] = &[
    "default_daemon_runtime_not_switched",
    "go_runtime_reload_loop_still_authoritative",
    "control_api_runtime_overview_not_yet_rust_default_owned",
    "fd_link_map_lifetime_owner_not_yet_fully_rust_default_owned",
    "stage6_deep_area_recorded_but_default_switch_requires_release_gate",
    "go_runtime_and_go_outbound_still_authoritative_for_default_product_path",
];

pub(super) fn runtime_native_group_count() -> usize {
    RUNTIME_NATIVE_GROUPS.len()
}

pub(super) fn daemon_runtime_native_owner_summary_json() -> Value {
    json!({
        "schema": "daemon-runtime-native-owner",
        "formal_surface": "daemon-runtime-native-owner",
        "owner_boundary": "dae-daemon",
        "accepted_native_group_count": RUNTIME_NATIVE_GROUPS.len(),
        "accepted_native_groups": RUNTIME_NATIVE_GROUPS
            .iter()
            .map(runtime_native_group_json)
            .collect::<Vec<_>>(),
        "runtime_owner_blockers": RUNTIME_OWNER_BLOCKERS,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false,
        "stage_report_schema": false,
        "helper_bridge_allowed": false,
        "process_helper_target_architecture": false,
        "cgo_or_dlopen_target_architecture": false,
        "outbound_protocol_rewrite_claimed": false,
        "datapath_deep_area_recorded": true,
        "aya_tcx_default_switch_claimed": false,
        "go_bpf_loader_restored_or_required_by_this_stage": false,
        "go_default_path_preserved_until_runtime_owner_admission": true,
        "next_queue": "fixed-queue-complete-release-gates",
        "source": [
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:stage5",
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:stage6",
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:execution-discipline",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.1",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.2",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.12"
        ],
    })
}

fn runtime_native_group_json(group: &RuntimeNativeGroup) -> Value {
    json!({
        "id": group.id,
        "queue_index": group.queue_index,
        "name": group.name,
        "primary_crates": group.primary_crates,
        "accepted_native_assets": group.accepted_native_assets,
        "accepted_into_daemon_runtime_owner": true,
        "default_switch_allowed": false,
        "go_fallback_deletion_allowed_by_this_group": false,
        "default_switch_blockers": group.default_switch_blockers,
        "source": group.source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_keeps_stage_boundaries_closed() {
        let summary = daemon_runtime_native_owner_summary_json();
        assert_eq!(
            summary["schema"].as_str().unwrap(),
            "daemon-runtime-native-owner"
        );
        assert_eq!(
            summary["accepted_native_group_count"].as_u64().unwrap(),
            RUNTIME_NATIVE_GROUPS.len() as u64
        );
        assert!(
            !summary["default_switch_allowed"].as_bool().unwrap(),
            "stage 5 report must not open the default daemon switch"
        );
        assert!(
            !summary["outbound_protocol_rewrite_claimed"]
                .as_bool()
                .unwrap()
        );
        assert!(summary["datapath_deep_area_recorded"].as_bool().unwrap());
        assert!(
            !summary["go_bpf_loader_restored_or_required_by_this_stage"]
                .as_bool()
                .unwrap()
        );
    }
}

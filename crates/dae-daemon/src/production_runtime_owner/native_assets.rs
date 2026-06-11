use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeNativeGroup {
    id: &'static str,
    queue_index: u8,
    name: &'static str,
    primary_crates: &'static [&'static str],
    accepted_native_assets: &'static [&'static str],
    final_native_admission_blockers: &'static [&'static str],
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
        final_native_admission_blockers: &[
            "compatibility_dialer_group_alive_event_source_still_visible",
            "runtime_map_fd_lifetime_not_yet_owned_by_product_daemon",
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
        final_native_admission_blockers: &[
            "production_config_to_routing_map_input_chain_not_fully_rust_owned",
            "kernel_map_write_lifetime_remains_deep_area_boundary",
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
        final_native_admission_blockers: &[
            "compatibility_dns_controller_forwarder_still_visible",
            "domain_routing_map_runtime_owner_not_product_runtime_owned",
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
        final_native_admission_blockers: &[
            "dial_mode_sniff_runtime_entry_not_product_runtime_owned",
            "sniffed_first_payload_relay_not_validated_in_resident_daemon",
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
        final_native_admission_blockers: &[
            "final_native_gate_not_opened_by_report",
            "native_runtime_or_outbound_dependency_evidence_missing",
            "full_live_protocol_matrix_not_completed_in_resident_daemon",
        ],
    },
];

const RUNTIME_OWNER_BLOCKERS: &[&str] = &[
    "native_daemon_runtime_not_admitted",
    "native_reload_loop_evidence_missing",
    "control_api_runtime_overview_native_owner_evidence_missing",
    "fd_link_map_lifetime_owner_evidence_missing",
    "deep_area_recorded_but_final_native_admission_requires_release_gate",
    "native_runtime_or_outbound_dependency_evidence_missing",
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
        "final_native_admission_allowed": false,
        "final_state_admission_allowed": false,
        "current_report_schema": true,
        "helper_bridge_allowed": false,
        "process_helper_target_architecture": false,
        "ffi_or_dlopen_target_architecture": false,
        "outbound_protocol_rewrite_claimed": false,
        "datapath_deep_area_recorded": true,
        "aya_tcx_final_native_admission_claimed": false,
        "native_bpf_loader_product_ready_or_required_by_this_report": false,
        "native_runtime_path_preserved_until_runtime_owner_admission": true,
        "next_queue": "fixed-queue-complete-release-gates",
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
        "final_native_admission_allowed": false,
        "final_native_readiness_claimed_by_this_group": false,
        "final_native_admission_blockers": group.final_native_admission_blockers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_keeps_final_native_admission_boundaries_closed() {
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
            !summary["final_native_admission_allowed"].as_bool().unwrap(),
            "native owner report must not open the production daemon switch"
        );
        assert!(
            !summary["outbound_protocol_rewrite_claimed"]
                .as_bool()
                .unwrap()
        );
        assert!(summary["datapath_deep_area_recorded"].as_bool().unwrap());
        assert!(
            !summary["native_bpf_loader_product_ready_or_required_by_this_report"]
                .as_bool()
                .unwrap()
        );
    }
}

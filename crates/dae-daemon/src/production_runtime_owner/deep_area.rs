use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeepAreaSurface {
    id: &'static str,
    name: &'static str,
    primary_crates: &'static [&'static str],
    accepted_native_assets: &'static [&'static str],
    production_admission_blockers: &'static [&'static str],
    production_readiness_conditions: &'static [&'static str],
}

const DEEP_AREA_SURFACES: &[DeepAreaSurface] = &[
    DeepAreaSurface {
        id: "tcp-active-datapath",
        name: "TCP Active Datapath",
        primary_crates: &["dae-datapath", "dae-daemon", "dae-sniffing", "dae-outbound"],
        accepted_native_assets: &[
            "route_dial_tcp_plan",
            "tcp_direct_relay",
            "resident_tcp_selection",
            "sniffed_initial_payload_preservation",
            "active_tcp_relay_smoke_contract",
        ],
        production_admission_blockers: &[
            "resident_tcp_not_validated_for_every_outbound_protocol",
            "throughput_latency_and_reload_under_traffic_not_production_validated",
        ],
        production_readiness_conditions: &[
            "all_non_reserved_outbound_protocols_have_live_tcp_parity",
            "sniff_and_domain_plus_plus_reroute_pass_under_resident_daemon",
            "reload_abort_and_restore_keep_existing_tcp_flows_correct",
        ],
    },
    DeepAreaSurface {
        id: "udp-active-datapath",
        name: "UDP Active Datapath",
        primary_crates: &["dae-datapath", "dae-daemon", "dae-dns", "dae-outbound"],
        accepted_native_assets: &[
            "udp_endpoint_pool_model",
            "udp_direct_packet_conn",
            "active_udp_tproxy_contract",
            "udp_dns_datapath_contract",
            "dns_cache_hot_path_integration_boundary",
        ],
        production_admission_blockers: &[
            "udp_endpoint_task_pool_not_product_runtime_owned_for_all_flows",
            "non_dns_udp_protocol_relay_not_live_validated_for_all_outbounds",
        ],
        production_readiness_conditions: &[
            "udp_dns_and_non_dns_paths_pass_original_destination_parity",
            "packet_replay_and_sendpkt_reply_match_native_under_reload",
            "quic_udp_sessions_keep_domain_routing_and_sniff_semantics",
        ],
    },
    DeepAreaSurface {
        id: "outbound-protocol-stack",
        name: "Outbound Protocol Stack",
        primary_crates: &["dae-outbound", "dae-datapath", "dae-daemon"],
        accepted_native_assets: &[
            "direct_block_reserved_outbounds",
            "group_filter_policy_health_latency_models",
            "vless_vmess_trojan_native_dataplane_assets",
            "shadowsocks_ss2022_ssr_sip003_native_assets",
            "socks_http_anytls_hysteria2_tuic_juicity_native_assets",
            "shared_tls_ws_h2_grpc_quic_h3_mux_transport_assets",
        ],
        production_admission_blockers: &[
            "native_outbound_dependency_evidence_missing",
            "live_node_matrix_not_completed_for_every_protocol_transport_pair",
        ],
        production_readiness_conditions: &[
            "each_protocol_has_native_benchmark_and_fixture_evidence",
            "each_protocol_transport_pair_passes_live_or_loopback_admission",
            "group_min_random_fixed_policy_and_connectivity_map_events_are_rust_owned",
        ],
    },
    DeepAreaSurface {
        id: "ebpf-backend-host-ops",
        name: "eBPF Backend / Host Ops",
        primary_crates: &[
            "dae-ebpf-support",
            "dae-ebpf-loader",
            "dae-netutil",
            "dae-daemon",
        ],
        accepted_native_assets: &[
            "bpf_abi_contract",
            "param_object_rewrite",
            "runtime_map_fd_syscalls",
            "tcx_tc_netlink_command_attach_matrix",
            "aya_loader_explicit_request",
            "cgroup_attach_matrix",
            "listen_socket_sockmap_contract",
            "typed_host_ops_and_netns_link_policy",
        ],
        production_admission_blockers: &[
            "native_backend_requires_release_admission",
            "native_ebpf_program_final_evaluation_not_this_gate",
        ],
        production_readiness_conditions: &[
            "non_native_bpf_loader_absence_evidence_required",
            "tcx_tc_netlink_backend_has_root_gated_host_write_parity",
            "netkit_veth_and_same_iface_lan_wan_modes_pass_cleanup_checks",
        ],
    },
];

const PRODUCTION_ADMISSION_BLOCKERS: &[&str] = &[
    "native_daemon_admission_requires_production_admission_gate",
    "native_runtime_or_outbound_dependency_evidence_missing",
    "full_live_protocol_matrix_not_completed_in_resident_daemon",
    "long_running_soak_reload_and_failure_recovery_not_recorded_for_all_deep_area_surfaces",
];

pub(super) fn deep_area_surface_count() -> usize {
    DEEP_AREA_SURFACES.len()
}

pub(super) fn datapath_outbound_ebpf_deep_area_summary_json() -> Value {
    json!({
        "schema": "datapath-outbound-ebpf-deep-area",
        "formal_surface": "datapath-outbound-ebpf-deep-area",
        "fixed_queue_area": "datapath-outbound-ebpf-deep-area",
        "fixed_queue_completed": true,
        "owner_boundary": "dae-daemon",
        "surface_count": DEEP_AREA_SURFACES.len(),
        "surfaces": DEEP_AREA_SURFACES
            .iter()
            .map(deep_area_surface_json)
            .collect::<Vec<_>>(),
        "production_admission_blockers": PRODUCTION_ADMISSION_BLOCKERS,
        "production_admission_allowed": false,
        "final_state_admission_allowed": false,
        "current_report_schema": true,
        "production_readiness_claimed": false,
        "native_bpf_loader_required": false,
        "native_bpf_loader_product_ready": false,
        "aya_loader_direction_preserved": true,
        "tcx_tc_netlink_command_backend_is_linux_backend_compatibility": true,
        "native_ebpf_program_final_evaluation": true,
        "outbound_compatibility_module_still_visible": true,
        "datapath_native_assets_recorded": true,
        "outbound_protocol_native_assets_recorded": true,
        "ebpf_host_ops_native_assets_recorded": true,
        "next_queue": "fixed-queue-complete-release-gates",
    })
}

fn deep_area_surface_json(surface: &DeepAreaSurface) -> Value {
    json!({
        "id": surface.id,
        "name": surface.name,
        "primary_crates": surface.primary_crates,
        "accepted_native_assets": surface.accepted_native_assets,
        "accepted_into_deep_area": true,
        "production_admission_allowed": false,
        "production_readiness_claimed": false,
        "production_admission_blockers": surface.production_admission_blockers,
        "production_readiness_conditions": surface.production_readiness_conditions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_area_summary_closes_fixed_queue_without_opening_production_admission() {
        let summary = datapath_outbound_ebpf_deep_area_summary_json();
        assert_eq!(
            summary["schema"].as_str().unwrap(),
            "datapath-outbound-ebpf-deep-area"
        );
        assert!(summary["fixed_queue_completed"].as_bool().unwrap());
        assert_eq!(
            summary["surface_count"].as_u64().unwrap(),
            DEEP_AREA_SURFACES.len() as u64
        );
        assert!(!summary["production_admission_allowed"].as_bool().unwrap());
        assert!(!summary["production_readiness_claimed"].as_bool().unwrap());
        assert!(!summary["native_bpf_loader_required"].as_bool().unwrap());
        assert!(
            !summary["native_bpf_loader_product_ready"]
                .as_bool()
                .unwrap()
        );
        assert!(summary["aya_loader_direction_preserved"].as_bool().unwrap());
    }
}

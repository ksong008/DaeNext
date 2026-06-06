use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeepAreaSurface {
    id: &'static str,
    name: &'static str,
    primary_crates: &'static [&'static str],
    accepted_native_assets: &'static [&'static str],
    default_switch_blockers: &'static [&'static str],
    fallback_deletion_conditions: &'static [&'static str],
    source: &'static [&'static str],
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
        default_switch_blockers: &[
            "default_resident_tcp_not_validated_for_every_outbound_protocol",
            "throughput_latency_and_reload_under_traffic_not_release_gated",
        ],
        fallback_deletion_conditions: &[
            "all_non_reserved_outbound_protocols_have_live_tcp_parity",
            "sniff_and_domain_plus_plus_reroute_pass_under_default_daemon",
            "reload_abort_and_rollback_keep_existing_tcp_flows_correct",
        ],
        source: &[
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.1",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.2",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.10",
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
        default_switch_blockers: &[
            "udp_endpoint_task_pool_not_default_rust_owned_for_all_flows",
            "non_dns_udp_protocol_relay_not_live_validated_for_all_outbounds",
        ],
        fallback_deletion_conditions: &[
            "udp_dns_and_non_dns_paths_pass_original_destination_parity",
            "packet_replay_and_sendpkt_reply_match_go_under_reload",
            "quic_udp_sessions_keep_domain_routing_and_sniff_semantics",
        ],
        source: &[
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.5",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.6",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.10",
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
        default_switch_blockers: &[
            "replace_go_outbound_module_still_authoritative_in_product_path",
            "live_node_matrix_not_completed_for_every_protocol_transport_pair",
        ],
        fallback_deletion_conditions: &[
            "each_protocol_has_go_rust_benchmark_and_fixture_parity",
            "each_protocol_transport_pair_passes_live_or_loopback_admission",
            "group_min_random_fixed_policy_and_connectivity_map_events_are_rust_owned",
        ],
        source: &[
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:12.1",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:12.2",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:12.7",
        ],
    },
    DeepAreaSurface {
        id: "ebpf-backend-host-ops",
        name: "eBPF Backend / Host Ops",
        primary_crates: &[
            "dae-ebpf-support",
            "dae-aya-bpf-loader",
            "dae-netutil",
            "dae-daemon",
        ],
        accepted_native_assets: &[
            "bpf_abi_contract",
            "param_object_rewrite",
            "runtime_map_fd_syscalls",
            "tcx_tc_netlink_command_attach_matrix",
            "aya_loader_explicit_opt_in",
            "cgroup_attach_matrix",
            "listen_socket_sockmap_contract",
            "typed_host_ops_and_netns_link_policy",
        ],
        default_switch_blockers: &[
            "native_backend_default_requires_environment_gated_release_admission",
            "c_ebpf_program_rewrite_is_final_evaluation_not_this_default_gate",
        ],
        fallback_deletion_conditions: &[
            "go_bpf_loader_remains_absent_from_default_path",
            "tcx_tc_netlink_backend_has_root_gated_host_write_parity",
            "netkit_veth_and_same_iface_lan_wan_modes_pass_cleanup_checks",
        ],
        source: &[
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.1",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.1",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.12",
        ],
    },
];

const DEFAULT_SWITCH_BLOCKERS: &[&str] = &[
    "default_daemon_switch_requires_product_chain_release_gate",
    "go_runtime_and_go_outbound_are_still_authoritative_for_default_product_path",
    "full_live_protocol_matrix_not_completed_in_default_resident_daemon",
    "long_running_soak_reload_and_failure_recovery_not_recorded_for_all_deep_area_surfaces",
];

pub(super) fn deep_area_surface_count() -> usize {
    DEEP_AREA_SURFACES.len()
}

pub(super) fn datapath_outbound_ebpf_deep_area_summary_json() -> Value {
    json!({
        "schema": "datapath-outbound-ebpf-deep-area",
        "formal_surface": "datapath-outbound-ebpf-deep-area",
        "fixed_queue_stage": 6,
        "fixed_queue_completed": true,
        "owner_boundary": "dae-daemon",
        "surface_count": DEEP_AREA_SURFACES.len(),
        "surfaces": DEEP_AREA_SURFACES
            .iter()
            .map(deep_area_surface_json)
            .collect::<Vec<_>>(),
        "default_switch_blockers": DEFAULT_SWITCH_BLOCKERS,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false,
        "stage_report_schema": false,
        "go_fallback_deletion_allowed": false,
        "go_bpf_loader_required": false,
        "go_bpf_loader_restored": false,
        "aya_loader_direction_preserved": true,
        "tcx_tc_netlink_command_fallback_is_linux_backend_compatibility": true,
        "c_ebpf_program_rewrite_deferred_to_final_evaluation": true,
        "outbound_replace_go_module_still_authoritative": true,
        "datapath_native_assets_recorded": true,
        "outbound_protocol_native_assets_recorded": true,
        "ebpf_host_ops_native_assets_recorded": true,
        "next_queue": "fixed-queue-complete-release-gates",
        "source": [
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:stage6",
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:execution-discipline",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:12",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22"
        ],
    })
}

fn deep_area_surface_json(surface: &DeepAreaSurface) -> Value {
    json!({
        "id": surface.id,
        "name": surface.name,
        "primary_crates": surface.primary_crates,
        "accepted_native_assets": surface.accepted_native_assets,
        "accepted_into_stage6": true,
        "default_switch_allowed": false,
        "go_fallback_deletion_allowed": false,
        "default_switch_blockers": surface.default_switch_blockers,
        "fallback_deletion_conditions": surface.fallback_deletion_conditions,
        "source": surface.source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_area_summary_closes_fixed_queue_without_opening_default_switch() {
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
        assert!(!summary["default_switch_allowed"].as_bool().unwrap());
        assert!(!summary["go_fallback_deletion_allowed"].as_bool().unwrap());
        assert!(!summary["go_bpf_loader_required"].as_bool().unwrap());
        assert!(!summary["go_bpf_loader_restored"].as_bool().unwrap());
        assert!(summary["aya_loader_direction_preserved"].as_bool().unwrap());
    }
}

use std::path::Path;

use dae_ebpf_support::{
    AttachBackend, EbpfBackendCapabilityReport, KernelProgramFallbackRetirementEvidence,
    KernelProgramFallbackRetirementGateReport, KernelProgramParityAdmissionReport,
    KernelProgramParityEvidence, LiveLoadedTproxyListenSocketMap, LoaderBackend,
    NativeBackendAdmissionEvidence, NativeBackendAdmissionReport, TproxyDataplaneAdmissionReport,
    TproxySocketOptions, TraceDiagnosticGateReport, dae_cgroup_attach_matrix,
    kernel_program_fallback_retirement_gate_report, kernel_program_feasibility_report,
    kernel_program_parity_admission_report, native_backend_admission_report,
    report_only_ebpf_backend_capability, tproxy_dataplane_admission_report,
    trace_core_sideload_gate_report, trace_diagnostic_gate_report,
};
use serde_json::{Map, Value, json};

use super::command::path_string;
use super::deep_area;
use super::native_assets;
use super::native_ebpf::{native_backend_opt_in_decision_json, native_backend_runtime_decision};
use super::udp_dns_datapath_contract::udp_dns_datapath_contract_json;
use super::{
    ExecutionEvidence, FILTER_PREF, PRODUCTION_HOST_IFACE, PRODUCTION_NETNS, PRODUCTION_PEER_IFACE,
    ProductionRuntimeOwnerOptions,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TypedReportStatus {
    Pass,
    Fail,
    NotExecuted,
}

impl TypedReportStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NotExecuted => "not-executed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProductionRuntimeTypedReport {
    executed: bool,
    owner_smoke_passed: bool,
    production_dataplane_admitted: bool,
    reload_runtime_parity_admitted: bool,
    active_tcp_relay_benchmark_recorded: bool,
    active_udp_tproxy_benchmark_recorded: bool,
    active_dns_tproxy_benchmark_recorded: bool,
}

impl ProductionRuntimeTypedReport {
    fn status(self) -> TypedReportStatus {
        if !self.executed {
            TypedReportStatus::NotExecuted
        } else if self.production_dataplane_admitted && self.reload_runtime_parity_admitted {
            TypedReportStatus::Pass
        } else {
            TypedReportStatus::Fail
        }
    }

    fn to_json(self) -> Value {
        json!({
            "schema": "production-runtime-owner-typed-report",
            "formal_surface": "daemon-runtime-owner",
            "status": self.status().as_str(),
            "execute": self.executed,
            "owner_smoke_passed": self.owner_smoke_passed,
            "production_dataplane_admitted": self.production_dataplane_admitted,
            "reload_runtime_parity_admitted": self.reload_runtime_parity_admitted,
            "active_tcp_relay_benchmark_recorded": self.active_tcp_relay_benchmark_recorded,
            "active_udp_tproxy_benchmark_recorded": self.active_udp_tproxy_benchmark_recorded,
            "active_dns_tproxy_benchmark_recorded": self.active_dns_tproxy_benchmark_recorded,
            "matched_go_rust_default_daemon_benchmark_recorded": false,
            "true_rust_default_daemon_admitted": false,
            "default_switch_allowed": false,
            "product_chain_switch_allowed": false,
            "stage_report_schema": false,
            "daemon_runtime_native_owner_schema": "daemon-runtime-native-owner",
            "daemon_runtime_native_owner_admitted": true,
            "daemon_runtime_native_owner_group_count": native_assets::runtime_native_group_count(),
            "daemon_runtime_native_owner_default_switch_allowed": false,
            "datapath_outbound_ebpf_deep_area_schema": "datapath-outbound-ebpf-deep-area",
            "datapath_outbound_ebpf_deep_area_completed": true,
            "datapath_outbound_ebpf_deep_area_surface_count": deep_area::deep_area_surface_count(),
            "datapath_outbound_ebpf_deep_area_default_switch_allowed": false,
        })
    }
}

pub(super) fn report_value(
    options: &ProductionRuntimeOwnerOptions,
    artifact_dir: &Path,
    manifest_file: &Path,
    param_object: &Path,
    checks: Vec<Value>,
    evidence: ExecutionEvidence,
) -> Value {
    let mut report = Map::new();
    let daemon_runtime_native_owner = native_assets::daemon_runtime_native_owner_summary_json();
    let datapath_outbound_ebpf_deep_area =
        deep_area::datapath_outbound_ebpf_deep_area_summary_json();
    let udp_dns_contract = udp_dns_datapath_contract_json();
    let ebpf_capability = report_only_ebpf_backend_capability(None);
    let ebpf_capability_json = ebpf_backend_capability_json(&ebpf_capability, options);
    let active_tcp_executed = options.execute && options.execute_active_tcp;
    let active_tcp_ingress_passed = active_tcp_executed
        && evidence.active_tcp.tcp_accept["status"].as_str() == Some("pass")
        && evidence.active_tcp.client_traffic["status"].as_str() == Some("pass")
        && evidence.active_tcp.original_destination_observed
        && evidence.active_tcp.tcp_reply_path_succeeded;
    let active_tcp_passed = active_tcp_executed && evidence.active_tcp.passed;
    let active_tcp_relay_executed = active_tcp_executed && options.execute_active_tcp_relay;
    let active_tcp_relay_passed = active_tcp_relay_executed && evidence.active_tcp.relay_passed;
    let active_tcp_relay_benchmark_recorded = active_tcp_relay_passed
        && evidence.active_tcp.relay_benchmark["status"].as_str() == Some("pass");
    let active_udp_executed = options.execute && options.execute_active_udp;
    let active_udp_passed = active_udp_executed && evidence.active_udp.passed;
    let active_udp_admitted = active_udp_passed
        && evidence.active_udp.original_destination_observed
        && evidence.active_udp.endpoint_pool_live_recorded
        && evidence.active_udp.outbound_packet_conn_recorded
        && evidence.active_udp.sendpkt_reply_recorded
        && evidence.active_udp.so_mark_observed;
    let active_udp_benchmark_recorded =
        active_udp_admitted && evidence.active_udp.benchmark["status"].as_str() == Some("pass");
    let active_dns_executed = options.execute && options.execute_active_dns;
    let active_dns_passed = active_dns_executed && evidence.active_dns.passed;
    let active_dns_admitted = active_dns_passed
        && evidence.active_dns.original_destination_observed
        && evidence.active_dns.dns_controller_recorded
        && evidence.active_dns.dns_upstream_query_recorded
        && evidence.active_dns.dns_response_validation_recorded
        && evidence.active_dns.dns_cache_restore_recorded
        && evidence.active_dns.domain_routing_owner_migration_recorded
        && evidence.active_dns.sendpkt_reply_recorded
        && evidence.active_dns.so_mark_observed;
    let active_dns_benchmark_recorded =
        active_dns_admitted && evidence.active_dns.benchmark["status"].as_str() == Some("pass");
    let generic_udp_dns_datapath_benchmark_recorded =
        active_udp_benchmark_recorded && active_dns_benchmark_recorded;
    let generic_udp_dns_datapath_admitted =
        active_udp_admitted && active_dns_admitted && generic_udp_dns_datapath_benchmark_recorded;
    let route_dial_tcp_magic_network_observed = active_tcp_relay_passed
        && evidence.active_tcp.so_mark_observed
        && (!options.active_tcp_mptcp || evidence.active_tcp.mptcp_observed);
    let production_dataplane_admitted = active_tcp_relay_passed
        && route_dial_tcp_magic_network_observed
        && active_udp_admitted
        && active_dns_admitted;
    let reload_runtime_executed = options.execute && options.execute_reload_runtime_parity;
    let reload_runtime_passed = reload_runtime_executed && evidence.reload_runtime.passed;
    let typed_report = ProductionRuntimeTypedReport {
        executed: options.execute,
        owner_smoke_passed: options.execute && evidence.owner_smoke_passed,
        production_dataplane_admitted,
        reload_runtime_parity_admitted: reload_runtime_passed,
        active_tcp_relay_benchmark_recorded,
        active_udp_tproxy_benchmark_recorded: active_udp_benchmark_recorded,
        active_dns_tproxy_benchmark_recorded: active_dns_benchmark_recorded,
    }
    .to_json();
    report.insert(
        "name".to_owned(),
        json!("daemon-owned-production-runtime-owner"),
    );
    report.insert(
        "evidence_class".to_owned(),
        json!("daemon-owned-root-gated-production-param-listener-sockmap-owner-smoke"),
    );
    report.insert("execute_owner".to_owned(), json!(options.execute));
    report.insert(
        "root_gate_acknowledged".to_owned(),
        json!(options.ack_root_gate),
    );
    report.insert("read_only".to_owned(), json!(!options.execute));
    report.insert("artifact_dir".to_owned(), json!(path_string(artifact_dir)));
    report.insert(
        "manifest_file".to_owned(),
        json!(path_string(manifest_file)),
    );
    report.insert(
        "source_object".to_owned(),
        json!(path_string(&options.source_object)),
    );
    report.insert("param_object".to_owned(), json!(path_string(param_object)));
    report.insert("checks".to_owned(), json!(checks));
    report.insert(
        "contract".to_owned(),
        json!({
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "peer_section": options.peer_section,
            "host_section": options.host_section,
            "filter_pref": FILTER_PREF,
            "listen_socket_map_kernel_name": "listen_socket_m",
            "listener_keys": [0, 1],
            "tproxy_port": options.tproxy_port,
            "dae_netns_id": options.dae_netns_id,
            "netns_link": {
                "env": super::netns_link::netns_link_env_name(),
                "requested": options.netns_link_mode.as_str(),
                "auto_policy": "netkit_l2_scrub_none_then_legacy_netkit_l2_then_veth",
                "production_pair": [PRODUCTION_HOST_IFACE, PRODUCTION_PEER_IFACE],
                "active_tcp_lan_pair": [
                    dae_datapath::ACTIVE_TCP_LAN_HOST_IFACE,
                    dae_datapath::ACTIVE_TCP_LAN_CLIENT_IFACE,
                ],
            },
            "active_tcp": {
                "enabled": options.execute_active_tcp,
                "target_ip": options.active_tcp_target_ip,
                "client_ip": options.active_tcp_client_ip,
                "target_port": options.active_tcp_target_port,
                "so_mark": options.active_tcp_so_mark,
                "mptcp": options.active_tcp_mptcp,
                "relay_enabled": options.execute_active_tcp_relay,
                "upstream_mptcp": options.active_tcp_upstream_mptcp,
                "benchmark_iters": options.active_tcp_benchmark_iters,
                "scope": if options.execute_active_tcp_relay {
                    "tproxy ingress plus bounded Rust direct outbound relay; full route-table RouteDialTcp control-plane reroute remains separate"
                } else {
                    "tproxy ingress to transparent listener only; RouteDialTcp/MagicNetwork relay parity remains separate"
                },
            },
            "active_udp": {
                "enabled": options.execute_active_udp,
                "requires_active_tcp": true,
                "target_ip": options.active_udp_target_ip,
                "target_port": options.active_udp_target_port,
                "so_mark": options.active_tcp_so_mark,
                "mptcp_magic_network_flag": options.active_tcp_mptcp,
                "benchmark_iters": options.active_udp_benchmark_iters,
                "scope": "active UDP tproxy ingress plus full-cone endpoint pool, direct PacketConn, SO_MARK, and sendPkt-style transparent reply",
            },
            "active_dns": {
                "enabled": options.execute_active_dns,
                "requires_active_udp": true,
                "target_ip": options.active_dns_target_ip,
                "target_port": options.active_dns_target_port,
                "upstream_ip": options.active_dns_upstream_ip,
                "upstream_port": options.active_dns_upstream_port,
                "qname": options.active_dns_qname,
                "benchmark_iters": options.active_dns_benchmark_iters,
                "scope": "active DNS UDP/53 tproxy path with upstream miss, restored cache hit, domain routing owner migration, SO_MARK, and sendPkt-style transparent reply",
            },
            "reload_runtime": {
                "enabled": options.execute_reload_runtime_parity,
                "requires_active_tcp": true,
                "scope": "production owner lifecycle listener reuse, live listen_socket_map re-handoff, BPF/map owner transfer observation, DNS cache migration guard, bounded close, RuntimeOverview fields, invalid-config rollback, and post-reload active TCP probe",
            },
            "udp_dns_datapath": udp_dns_contract.clone(),
            "ebpf_backend": ebpf_capability_json.clone(),
            "native_ebpf": {
                "opt_in": options.native_ebpf_opt_in,
                "requested_backend": options.native_ebpf_backend.as_str(),
                "completed_a3_admission": options.native_ebpf_completed_a3_admission,
                "native_object": options.native_ebpf_object.as_ref().map(|path| path_string(path)),
                "fallback_object": path_string(&options.source_object),
                "fallback_object_preserved": true,
                "fallback_retirement_product_chain_recertified": options.fallback_retirement_product_chain_recertified,
                "fallback_retirement_explicit_user_approval": options.fallback_retirement_explicit_user_approval,
                "default_enable_allowed": false,
            },
            "owner_boundary": "dae-daemon",
        }),
    );
    report.insert(
        "ebpf_backend_capabilities".to_owned(),
        ebpf_capability_json.clone(),
    );
    report.insert(
        "generic_udp_dns_datapath_contract".to_owned(),
        udp_dns_contract,
    );
    report.insert(
        "generic_udp_dns_datapath_admitted".to_owned(),
        json!(generic_udp_dns_datapath_admitted),
    );
    report.insert(
        "generic_udp_dns_datapath_benchmark_recorded".to_owned(),
        json!(generic_udp_dns_datapath_benchmark_recorded),
    );
    report.insert(
        "generic_udp_dns_datapath_go_fallback_required".to_owned(),
        json!(!generic_udp_dns_datapath_admitted),
    );
    report.insert(
        "generic_udp_dns_default_switch_allowed".to_owned(),
        json!(false),
    );
    report.insert(
        "daemon_owned_production_runtime_owner_integrated_in_run".to_owned(),
        json!(true),
    );
    report.insert(
        "daemon_owned_production_runtime_owner_executed".to_owned(),
        json!(options.execute),
    );
    report.insert(
        "daemon_owned_production_runtime_owner_smoke_passed".to_owned(),
        json!(options.execute && evidence.owner_smoke_passed),
    );
    report.insert(
        "production_listener_bound_during_owner_smoke".to_owned(),
        json!(options.execute && evidence.owner_smoke_passed),
    );
    report.insert(
        "listen_socket_map_written_during_owner_smoke".to_owned(),
        json!(options.execute && evidence.owner_smoke_passed),
    );
    report.insert(
        "production_tc_attach_smoke_passed".to_owned(),
        json!(options.execute && evidence.owner_smoke_passed),
    );
    report.insert(
        "ebpf_attached_during_owner_smoke".to_owned(),
        json!(options.execute && evidence.owner_smoke_passed),
    );
    report.insert(
        "production_runtime_active_tcp_executed".to_owned(),
        json!(active_tcp_executed),
    );
    report.insert(
        "production_runtime_active_tcp_passed".to_owned(),
        json!(active_tcp_passed),
    );
    report.insert(
        "active_tcp_tproxy_ingress_smoke_passed".to_owned(),
        json!(active_tcp_ingress_passed),
    );
    report.insert(
        "active_tcp_syn_reached_transparent_listener".to_owned(),
        json!(
            active_tcp_executed
                && evidence.active_tcp.tcp_accept["status"].as_str() == Some("pass")
        ),
    );
    report.insert(
        "active_tcp_original_destination_observed".to_owned(),
        json!(active_tcp_executed && evidence.active_tcp.original_destination_observed),
    );
    report.insert(
        "active_tcp_reply_path_succeeded".to_owned(),
        json!(active_tcp_executed && evidence.active_tcp.tcp_reply_path_succeeded),
    );
    report.insert(
        "active_tcp_tproxy_admitted_during_owner_smoke".to_owned(),
        json!(active_tcp_ingress_passed),
    );
    report.insert(
        "route_dial_tcp_magic_network_mark_mptcp_observed".to_owned(),
        json!(route_dial_tcp_magic_network_observed),
    );
    report.insert(
        "active_tcp_relay_executed".to_owned(),
        json!(active_tcp_relay_executed),
    );
    report.insert(
        "active_tcp_relay_smoke_passed".to_owned(),
        json!(active_tcp_relay_passed),
    );
    report.insert(
        "route_dial_tcp_direct_path_executed".to_owned(),
        json!(active_tcp_relay_passed && evidence.active_tcp.outbound_relay_succeeded),
    );
    report.insert(
        "route_dial_tcp_rust_control_plane_executed".to_owned(),
        json!(false),
    );
    report.insert(
        "so_mark_real_outbound_socket_observed".to_owned(),
        json!(active_tcp_relay_passed && evidence.active_tcp.so_mark_observed),
    );
    report.insert(
        "mptcp_real_outbound_socket_observed".to_owned(),
        json!(
            active_tcp_relay_passed
                && (!options.active_tcp_mptcp || evidence.active_tcp.mptcp_observed)
        ),
    );
    report.insert(
        "active_tcp_relay_benchmark_recorded".to_owned(),
        json!(active_tcp_relay_benchmark_recorded),
    );
    report.insert(
        "production_runtime_active_udp_executed".to_owned(),
        json!(active_udp_executed),
    );
    report.insert(
        "production_runtime_active_udp_passed".to_owned(),
        json!(active_udp_passed),
    );
    report.insert(
        "active_udp_tproxy_smoke_passed".to_owned(),
        json!(active_udp_passed),
    );
    report.insert(
        "active_udp_tproxy_admitted".to_owned(),
        json!(active_udp_admitted),
    );
    report.insert(
        "active_udp_original_destination_observed".to_owned(),
        json!(active_udp_executed && evidence.active_udp.original_destination_observed),
    );
    report.insert(
        "udp_endpoint_pool_live_recorded".to_owned(),
        json!(active_udp_executed && evidence.active_udp.endpoint_pool_live_recorded),
    );
    report.insert(
        "udp_packetconn_write_read_recorded".to_owned(),
        json!(active_udp_executed && evidence.active_udp.outbound_packet_conn_recorded),
    );
    report.insert(
        "udp_sendpkt_reply_recorded".to_owned(),
        json!(active_udp_executed && evidence.active_udp.sendpkt_reply_recorded),
    );
    report.insert(
        "udp_so_mark_real_outbound_socket_observed".to_owned(),
        json!(active_udp_executed && evidence.active_udp.so_mark_observed),
    );
    report.insert(
        "active_udp_tproxy_benchmark_recorded".to_owned(),
        json!(active_udp_benchmark_recorded),
    );
    report.insert(
        "production_runtime_active_dns_executed".to_owned(),
        json!(active_dns_executed),
    );
    report.insert(
        "production_runtime_active_dns_passed".to_owned(),
        json!(active_dns_passed),
    );
    report.insert(
        "active_dns_tproxy_smoke_passed".to_owned(),
        json!(active_dns_passed),
    );
    report.insert(
        "active_dns_tproxy_admitted".to_owned(),
        json!(active_dns_admitted),
    );
    report.insert(
        "active_dns_original_destination_observed".to_owned(),
        json!(active_dns_executed && evidence.active_dns.original_destination_observed),
    );
    report.insert(
        "dns_controller_path_recorded".to_owned(),
        json!(active_dns_executed && evidence.active_dns.dns_controller_recorded),
    );
    report.insert(
        "dns_upstream_query_recorded".to_owned(),
        json!(active_dns_executed && evidence.active_dns.dns_upstream_query_recorded),
    );
    report.insert(
        "dns_response_validation_recorded".to_owned(),
        json!(active_dns_executed && evidence.active_dns.dns_response_validation_recorded),
    );
    report.insert(
        "dns_cache_restore_recorded".to_owned(),
        json!(active_dns_executed && evidence.active_dns.dns_cache_restore_recorded),
    );
    report.insert(
        "domain_routing_owner_migration_recorded".to_owned(),
        json!(active_dns_executed && evidence.active_dns.domain_routing_owner_migration_recorded),
    );
    report.insert(
        "dns_sendpkt_reply_recorded".to_owned(),
        json!(active_dns_executed && evidence.active_dns.sendpkt_reply_recorded),
    );
    report.insert(
        "dns_so_mark_upstream_socket_observed".to_owned(),
        json!(active_dns_executed && evidence.active_dns.so_mark_observed),
    );
    report.insert(
        "active_dns_tproxy_benchmark_recorded".to_owned(),
        json!(active_dns_benchmark_recorded),
    );
    report.insert(
        "production_dataplane_admitted".to_owned(),
        json!(production_dataplane_admitted),
    );
    report.insert(
        "production_reload_runtime_parity_executed".to_owned(),
        json!(reload_runtime_executed),
    );
    report.insert(
        "production_reload_runtime_parity_passed".to_owned(),
        json!(reload_runtime_passed),
    );
    report.insert(
        "live_reload_executed".to_owned(),
        json!(reload_runtime_executed && evidence.reload_runtime.live_reload_executed),
    );
    report.insert(
        "production_listener_reused".to_owned(),
        json!(reload_runtime_passed && evidence.reload_runtime.production_listener_reused),
    );
    report.insert(
        "production_bpf_owner_transferred".to_owned(),
        json!(reload_runtime_passed && evidence.reload_runtime.production_bpf_owner_transferred),
    );
    report.insert(
        "production_dns_cache_migrated".to_owned(),
        json!(reload_runtime_passed && evidence.reload_runtime.production_dns_cache_migrated),
    );
    report.insert(
        "dns_cache_migration_guard_verified".to_owned(),
        json!(reload_runtime_passed && evidence.reload_runtime.dns_cache_migration_guard_verified),
    );
    report.insert(
        "bounded_close_verified".to_owned(),
        json!(reload_runtime_passed && evidence.reload_runtime.bounded_close_verified),
    );
    report.insert(
        "runtime_overview_parity_verified".to_owned(),
        json!(reload_runtime_passed && evidence.reload_runtime.runtime_overview_parity_verified),
    );
    report.insert(
        "reload_scoped_resources_flushed".to_owned(),
        json!(reload_runtime_passed && evidence.reload_runtime.reload_scoped_resources_flushed),
    );
    report.insert(
        "invalid_config_rollback_verified".to_owned(),
        json!(reload_runtime_passed && evidence.reload_runtime.invalid_config_rollback_verified),
    );
    for key in [
        "matched_go_rust_default_daemon_benchmark_recorded",
        "true_rust_default_daemon_admitted",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
    ] {
        report.insert(key.to_owned(), json!(false));
    }
    report.insert(
        "reload_runtime_parity_admitted".to_owned(),
        json!(reload_runtime_passed),
    );
    report.insert("typed_report".to_owned(), typed_report);
    report.insert(
        "daemon_runtime_native_owner".to_owned(),
        daemon_runtime_native_owner,
    );
    report.insert(
        "datapath_outbound_ebpf_deep_area".to_owned(),
        datapath_outbound_ebpf_deep_area,
    );
    report.insert(
        "production_runtime_owner_scope".to_owned(),
        json!(if production_dataplane_admitted && reload_runtime_passed {
            "daemon-owned-production-runtime-active-tcp-udp-dns-reload-runtime-parity"
        } else if production_dataplane_admitted {
            "daemon-owned-production-runtime-active-tcp-udp-dns-dataplane"
        } else if reload_runtime_passed {
            "daemon-owned-production-runtime-reload-runtime-parity"
        } else if active_dns_passed {
            "daemon-owned-production-runtime-active-dns-smoke-failed-admission"
        } else if active_dns_executed {
            "daemon-owned-production-runtime-active-dns-smoke-failed"
        } else if active_udp_passed {
            "daemon-owned-production-runtime-active-udp-smoke-only"
        } else if active_udp_executed {
            "daemon-owned-production-runtime-active-udp-smoke-failed"
        } else if reload_runtime_executed {
            "daemon-owned-production-runtime-reload-runtime-parity-failed"
        } else if active_tcp_relay_passed {
            "daemon-owned-production-runtime-active-tcp-relay-smoke-only"
        } else if active_tcp_relay_executed {
            "daemon-owned-production-runtime-active-tcp-relay-smoke-failed"
        } else if active_tcp_passed {
            "daemon-owned-production-runtime-active-tcp-ingress-smoke-only"
        } else if active_tcp_executed {
            "daemon-owned-production-runtime-active-tcp-ingress-smoke-failed"
        } else if options.execute && evidence.owner_smoke_passed {
            "daemon-owned-production-param-listener-sockmap-owner-smoke-only"
        } else if options.execute {
            "daemon-owned-production-runtime-owner-smoke-failed"
        } else {
            "not-executed"
        }),
    );
    report.insert("topology_values".to_owned(), evidence.topology_values);
    report.insert("param_image".to_owned(), evidence.param_image);
    report.insert("native_param_image".to_owned(), evidence.native_param_image);
    report.insert("peer_attach_show".to_owned(), evidence.peer_attach_show);
    report.insert("host_attach_show".to_owned(), evidence.host_attach_show);
    report.insert("loaded_map_handoff".to_owned(), evidence.loaded_map_handoff);
    report.insert(
        "active_tcp".to_owned(),
        json!({
            "enabled": active_tcp_executed,
            "passed": active_tcp_passed,
            "ingress_passed": active_tcp_ingress_passed,
            "configured_target_ip": options.active_tcp_target_ip,
            "configured_client_ip": options.active_tcp_client_ip,
            "configured_target_port": options.active_tcp_target_port,
            "configured_so_mark": options.active_tcp_so_mark,
            "configured_mptcp": options.active_tcp_mptcp,
            "relay_enabled": active_tcp_relay_executed,
            "relay_passed": active_tcp_relay_passed,
            "upstream_mptcp": options.active_tcp_upstream_mptcp,
            "benchmark_iters": options.active_tcp_benchmark_iters,
            "lan_attach_show": evidence.active_tcp.lan_attach_show,
            "route_map_update": evidence.active_tcp.route_map_update,
            "discovered_routing_map_id": evidence.active_tcp.discovered_routing_map_id,
            "tcp_accept": evidence.active_tcp.tcp_accept,
            "client_traffic": evidence.active_tcp.client_traffic,
            "original_destination_observed": evidence.active_tcp.original_destination_observed,
            "tcp_reply_path_succeeded": evidence.active_tcp.tcp_reply_path_succeeded,
            "relay_accept": evidence.active_tcp.relay_accept,
            "upstream": evidence.active_tcp.upstream,
            "relay_client_traffic": evidence.active_tcp.relay_client_traffic,
            "outbound_dial": evidence.active_tcp.outbound_dial,
            "relay_benchmark": evidence.active_tcp.relay_benchmark,
            "relay_original_destination_observed": evidence.active_tcp.relay_original_destination_observed,
            "outbound_relay_succeeded": evidence.active_tcp.outbound_relay_succeeded,
            "so_mark_observed": evidence.active_tcp.so_mark_observed,
            "mptcp_observed": evidence.active_tcp.mptcp_observed,
            "post_traffic_peer_stats": evidence.active_tcp.post_traffic_peer_stats,
            "post_traffic_lan_stats": evidence.active_tcp.post_traffic_lan_stats,
            "post_traffic_host_stats": evidence.active_tcp.post_traffic_host_stats,
            "route_dial_tcp_magic_network_mark_mptcp_observed": active_tcp_relay_passed
                && evidence.active_tcp.so_mark_observed
                && (!options.active_tcp_mptcp || evidence.active_tcp.mptcp_observed),
            "route_dial_tcp_rust_control_plane_executed": false,
        }),
    );
    report.insert(
        "active_udp".to_owned(),
        json!({
            "enabled": evidence.active_udp.enabled,
            "passed": active_udp_passed,
            "admitted": active_udp_admitted,
            "configured_target_ip": options.active_udp_target_ip,
            "configured_target_port": options.active_udp_target_port,
            "configured_so_mark": options.active_tcp_so_mark,
            "configured_mptcp_magic_network_flag": options.active_tcp_mptcp,
            "benchmark_iters": options.active_udp_benchmark_iters,
            "udp_receive": evidence.active_udp.udp_receive,
            "udp_endpoint_pool": evidence.active_udp.udp_endpoint_pool,
            "outbound_packet_conn": evidence.active_udp.outbound_packet_conn,
            "upstream": evidence.active_udp.upstream,
            "client_traffic": evidence.active_udp.client_traffic,
            "sendpkt_reply": evidence.active_udp.sendpkt_reply,
            "benchmark": evidence.active_udp.benchmark,
            "original_destination_observed": evidence.active_udp.original_destination_observed,
            "endpoint_pool_live_recorded": evidence.active_udp.endpoint_pool_live_recorded,
            "outbound_packet_conn_recorded": evidence.active_udp.outbound_packet_conn_recorded,
            "sendpkt_reply_recorded": evidence.active_udp.sendpkt_reply_recorded,
            "so_mark_observed": evidence.active_udp.so_mark_observed,
            "post_traffic_peer_stats": evidence.active_udp.post_traffic_peer_stats,
            "post_traffic_lan_stats": evidence.active_udp.post_traffic_lan_stats,
            "post_traffic_host_stats": evidence.active_udp.post_traffic_host_stats,
        }),
    );
    report.insert(
        "active_dns".to_owned(),
        json!({
            "enabled": evidence.active_dns.enabled,
            "passed": active_dns_passed,
            "admitted": active_dns_admitted,
            "configured_target_ip": options.active_dns_target_ip,
            "configured_target_port": options.active_dns_target_port,
            "configured_upstream_ip": options.active_dns_upstream_ip,
            "configured_upstream_port": options.active_dns_upstream_port,
            "configured_qname": options.active_dns_qname,
            "configured_so_mark": options.active_tcp_so_mark,
            "configured_mptcp_magic_network_flag": options.active_tcp_mptcp,
            "benchmark_iters": options.active_dns_benchmark_iters,
            "dns_receive": evidence.active_dns.dns_receive,
            "dns_controller": evidence.active_dns.dns_controller,
            "dns_upstream": evidence.active_dns.dns_upstream,
            "dns_cache": evidence.active_dns.dns_cache,
            "domain_routing": evidence.active_dns.domain_routing,
            "upstream_packet_conn": evidence.active_dns.upstream_packet_conn,
            "client_traffic": evidence.active_dns.client_traffic,
            "sendpkt_reply": evidence.active_dns.sendpkt_reply,
            "benchmark": evidence.active_dns.benchmark,
            "original_destination_observed": evidence.active_dns.original_destination_observed,
            "dns_controller_recorded": evidence.active_dns.dns_controller_recorded,
            "dns_upstream_query_recorded": evidence.active_dns.dns_upstream_query_recorded,
            "dns_response_validation_recorded": evidence.active_dns.dns_response_validation_recorded,
            "dns_cache_restore_recorded": evidence.active_dns.dns_cache_restore_recorded,
            "domain_routing_owner_migration_recorded": evidence.active_dns.domain_routing_owner_migration_recorded,
            "sendpkt_reply_recorded": evidence.active_dns.sendpkt_reply_recorded,
            "so_mark_observed": evidence.active_dns.so_mark_observed,
            "post_traffic_peer_stats": evidence.active_dns.post_traffic_peer_stats,
            "post_traffic_lan_stats": evidence.active_dns.post_traffic_lan_stats,
            "post_traffic_host_stats": evidence.active_dns.post_traffic_host_stats,
        }),
    );
    report.insert(
        "reload_runtime".to_owned(),
        json!({
            "enabled": evidence.reload_runtime.enabled,
            "passed": reload_runtime_passed,
            "live_reload_executed": evidence.reload_runtime.live_reload_executed,
            "production_listener_reused": evidence.reload_runtime.production_listener_reused,
            "production_bpf_owner_transferred": evidence.reload_runtime.production_bpf_owner_transferred,
            "production_dns_cache_migrated": evidence.reload_runtime.production_dns_cache_migrated,
            "dns_cache_migration_guard_verified": evidence.reload_runtime.dns_cache_migration_guard_verified,
            "bounded_close_verified": evidence.reload_runtime.bounded_close_verified,
            "runtime_overview_parity_verified": evidence.reload_runtime.runtime_overview_parity_verified,
            "reload_scoped_resources_flushed": evidence.reload_runtime.reload_scoped_resources_flushed,
            "invalid_config_rollback_verified": evidence.reload_runtime.invalid_config_rollback_verified,
            "post_reload_active_tcp_passed": evidence.reload_runtime.post_reload_active_tcp_passed,
            "elapsed_ns": evidence.reload_runtime.elapsed_ns,
            "listener_reuse": evidence.reload_runtime.listener_reuse,
            "bpf_owner_transfer": evidence.reload_runtime.bpf_owner_transfer,
            "dns_cache_migration": evidence.reload_runtime.dns_cache_migration,
            "bounded_close": evidence.reload_runtime.bounded_close,
            "runtime_overview": evidence.reload_runtime.runtime_overview,
            "rollback": evidence.reload_runtime.rollback,
            "post_reload_active_tcp_accept": evidence.reload_runtime.post_reload_active_tcp_accept,
            "post_reload_active_tcp_client_traffic": evidence.reload_runtime.post_reload_active_tcp_client_traffic,
            "post_reload_active_tcp_original_destination_observed": evidence.reload_runtime.post_reload_active_tcp_original_destination_observed,
            "post_reload_active_tcp_reply_path_succeeded": evidence.reload_runtime.post_reload_active_tcp_reply_path_succeeded,
        }),
    );
    report.insert("executed_steps".to_owned(), json!(evidence.executed_steps));
    report.insert("cleanup_steps".to_owned(), json!(evidence.cleanup_steps));
    report.insert(
        "map_id_snapshots".to_owned(),
        json!({
            "before_attach": evidence.before_map_ids,
            "after_cleanup": evidence.after_map_ids,
            "discovered_map_id": evidence.discovered_map_id,
            "discovered_routing_map_id": evidence.discovered_routing_map_id,
            "loaded_map_cleaned": evidence.loaded_map_cleaned,
        }),
    );
    report.insert(
        "temporary_production_named_resources".to_owned(),
        json!({
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "active_tcp_client_netns": if options.execute_active_tcp { "dae50client" } else { "" },
            "active_tcp_lan_host_iface": if options.execute_active_tcp { "dae50lan0" } else { "" },
            "active_tcp_lan_client_iface": if options.execute_active_tcp { "dae50cli0" } else { "" },
            "active_udp_loopback_target": if options.execute_active_udp {
                format!("{}/32", options.active_udp_target_ip)
            } else {
                String::new()
            },
            "leftovers_after_cleanup": evidence.leftovers_after_cleanup,
        }),
    );
    report.insert(
        "sys_fs_bpf_dae".to_owned(),
        json!({
            "path": "/sys/fs/bpf/dae",
            "mutated": evidence.sys_fs_bpf_dae_mutated,
        }),
    );
    report.insert(
        "source".to_owned(),
        json!([
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:Post-Stage196",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.2",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.8",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.7",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.5",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.6",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.7",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.8",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.9",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.10"
        ]),
    );
    report.insert("go_default_path_preserved".to_owned(), json!(true));
    report.insert("go_fallback_required".to_owned(), json!(true));
    let fallback_retirement_gate = &ebpf_capability_json["kernel_program_fallback_retirement_gate"];
    let tproxy_dataplane_admission = &ebpf_capability_json["tproxy_dataplane_admission"];
    let go_bpf_fallback_required = fallback_retirement_gate["go_bpf_fallback_required"]
        .as_bool()
        .unwrap_or(true);
    let go_bpf_fallback_retired = fallback_retirement_gate["go_bpf_fallback_retirement_allowed"]
        .as_bool()
        .unwrap_or(false);
    report.insert(
        "go_bpf_loader_retirement_candidate".to_owned(),
        json!(
            tproxy_dataplane_admission["go_bpf_loader_retirement_candidate"]
                .as_bool()
                .unwrap_or(false)
        ),
    );
    report.insert(
        "go_bpf_fallback_retirement_gate_admitted".to_owned(),
        json!(
            fallback_retirement_gate["admitted"]
                .as_bool()
                .unwrap_or(false)
        ),
    );
    report.insert(
        "go_bpf_fallback_retirement_scope".to_owned(),
        fallback_retirement_gate["retirement_scope"].clone(),
    );
    report.insert(
        "go_bpf_fallback_required".to_owned(),
        json!(go_bpf_fallback_required),
    );
    report.insert(
        "go_bpf_fallback_retired".to_owned(),
        json!(go_bpf_fallback_retired),
    );
    Value::Object(report)
}

fn ebpf_backend_capability_json(
    report: &EbpfBackendCapabilityReport,
    options: &ProductionRuntimeOwnerOptions,
) -> Value {
    let go_bpf_fallback_retired = options.native_ebpf_completed_a3_admission;
    let native_admission = native_backend_admission_report(
        if go_bpf_fallback_retired {
            NativeBackendAdmissionEvidence::completed_a3_local()
        } else {
            NativeBackendAdmissionEvidence::report_only()
        },
        !go_bpf_fallback_retired,
    );
    let native_opt_in = native_backend_runtime_decision(options);
    let kernel_program = kernel_program_feasibility_report();
    let kernel_program_evidence = KernelProgramParityEvidence::from_feasibility(&kernel_program);
    let kernel_program_parity = kernel_program_parity_admission_report(kernel_program_evidence);
    let tproxy_dataplane_admission = tproxy_dataplane_admission_report(kernel_program_evidence);
    let trace_core_sideload_gate = trace_core_sideload_gate_report();
    let trace_diagnostic_gate = trace_diagnostic_gate_report(&trace_core_sideload_gate);
    let fallback_retirement_gate = kernel_program_fallback_retirement_gate_report(
        &tproxy_dataplane_admission,
        &trace_diagnostic_gate,
        KernelProgramFallbackRetirementEvidence {
            explicit_user_approval: options.fallback_retirement_explicit_user_approval,
            product_chain_recertified: options.fallback_retirement_product_chain_recertified,
        },
    );
    json!({
        "schema": "ebpf-backend-capability-report",
        "report_only": report.report_only,
        "aya_userspace_available": report.aya_userspace_available,
        "tc_netlink_available": report.tc_netlink_available,
        "tcx_supported": report.tcx_supported,
        "tcx_available": report.tcx_available,
        "selected_backend": attach_backend_value(report.selected_backend),
        "command_fallback_used": report.command_fallback_used,
        "fallback_reason": report.fallback_reason,
        "kernel_version_source": "not-probed-report-only",
        "attach_backend": {
            "requested": report.attach_plan.requested.as_str(),
            "attempt_order": report
                .attach_plan
                .attempt_order
                .iter()
                .map(|backend| backend.as_str())
                .collect::<Vec<_>>(),
            "selected": attach_backend_value(report.attach_plan.selected),
            "effective_backend": "tc_command_fallback",
            "default_native_backend_enabled": false,
            "native_backend_admission_required": true,
            "tcx_optional": true,
            "tc_netlink_optional": true,
            "command_fallback_used": report.attach_plan.command_fallback_used,
            "command_fallback_required": true,
            "go_netlink_parity_fields_required": [
                "netns",
                "iface",
                "direction",
                "priority",
                "handle",
                "tcx_order",
                "tcx_query_revision",
                "tcx_program_order",
                "tcx_order_verified",
                "protocol",
                "direct_action",
                "program_name",
                "link_lifetime"
            ],
        },
        "cgroup_attach": {
            "report_only": false,
            "default_native_backend_enabled": true,
            "aya_cgroup_optional": false,
            "go_attachcgroup_fallback_required": false,
            "go_attachcgroup_fallback_retired": true,
            "fallback_retirement_scope": "control-plane-cgroup-only",
            "cgroup2_mount_source": "/proc/mounts first cgroup2",
            "programs": dae_cgroup_attach_matrix()
                .iter()
                .map(|line| json!({
                    "role": format!("{:?}", line.role),
                    "section": line.section,
                    "program_name": line.program_name,
                    "go_attach_type": line.go_attach_type,
                    "aya_program_kind": line.aya_program_kind.as_str(),
                    "attach_mode": line.attach_mode,
                    "link_lifetime_owned_by_backend": line.link_lifetime_owned_by_backend,
                }))
                .collect::<Vec<_>>(),
        },
        "native_backend_admission": native_backend_admission_json(&native_admission),
        "native_backend_opt_in": native_backend_opt_in_decision_json(&native_opt_in),
        "kernel_program_feasibility": {
            "schema": kernel_program.schema,
            "tproxy_classifier_total": kernel_program.tproxy_classifier_total,
            "rust_tproxy_classifier_covered": kernel_program.rust_tproxy_classifier_covered,
            "tproxy_cgroup_total": kernel_program.tproxy_cgroup_total,
            "rust_tproxy_cgroup_covered": kernel_program.rust_tproxy_cgroup_covered,
            "trace_kprobe_total": kernel_program.trace_kprobe_total,
            "rust_trace_kprobe_covered": kernel_program.rust_trace_kprobe_covered,
            "rust_tproxy_runtime_admitted": kernel_program.rust_tproxy_runtime_admitted,
            "trace_rust_native_admitted": kernel_program.trace_rust_native_admitted,
            "default_switch_allowed": kernel_program.default_switch_allowed,
            "formal_kernel_program_parity_stage_required": kernel_program.formal_kernel_program_parity_stage_required,
            "c_tproxy_object_fallback_required": kernel_program.c_tproxy_object_fallback_required,
            "c_trace_object_fallback_required": kernel_program.c_trace_object_fallback_required,
            "tc_command_fallback_required": kernel_program.tc_command_fallback_required,
            "go_userspace_control_plane_authoritative": kernel_program.go_userspace_control_plane_authoritative,
            "go_bpf_loader_restored_by_this_stage": kernel_program.go_bpf_loader_restored_by_this_stage,
            "go_bpf_fallback_deletion_allowed_by_this_stage": kernel_program.go_bpf_fallback_deletion_allowed_by_this_stage,
            "param_model": kernel_program.param_model,
            "tproxy_coverage": kernel_program.tproxy_coverage
                .iter()
                .map(|line| json!({
                    "surface": line.surface.as_str(),
                    "c_section": line.c_section,
                    "rust_section": line.rust_section,
                    "program_name": line.program_name,
                    "status": line.status.as_str(),
                }))
                .collect::<Vec<_>>(),
            "trace_coverage": kernel_program.trace_coverage
                .iter()
                .map(|line| json!({
                    "surface": line.surface.as_str(),
                    "c_section": line.c_section,
                    "rust_section": line.rust_section,
                    "program_name": line.program_name,
                    "status": line.status.as_str(),
                }))
                .collect::<Vec<_>>(),
        },
        "kernel_program_parity_admission": kernel_program_parity_admission_json(&kernel_program_parity),
        "tproxy_dataplane_admission": tproxy_dataplane_admission_json(&tproxy_dataplane_admission),
        "trace_diagnostic_gate": trace_diagnostic_gate_json(&trace_diagnostic_gate),
        "kernel_program_fallback_retirement_gate": kernel_program_fallback_retirement_gate_json(&fallback_retirement_gate),
        "trace_core_sideload_gate": {
            "schema": trace_core_sideload_gate.schema,
            "enabled": trace_core_sideload_gate.enabled,
            "go_trace_adoption_ready": trace_core_sideload_gate.go_trace_adoption_ready,
            "default_daemon_path": trace_core_sideload_gate.default_daemon_path,
            "rust_skb_core_read_semantics_required": trace_core_sideload_gate.rust_skb_core_read_semantics_required,
            "rust_core_relocation_required": trace_core_sideload_gate.rust_core_relocation_required,
            "c_trace_object_required": trace_core_sideload_gate.c_trace_object_required,
            "go_trace_fallback_required": trace_core_sideload_gate.go_trace_fallback_required,
            "disabled_reason": trace_core_sideload_gate.disabled_reason,
            "restore_gate": trace_core_sideload_gate.restore_gate,
        },
        "loader": {
            "default_object_loader": loader_backend_str(report.loader_contract.default_object_loader),
            "runtime_map_backend": loader_backend_str(report.loader_contract.runtime_map_backend),
            "aya_userspace_loader_planned": report.loader_contract.aya_userspace_loader_planned,
            "c_ebpf_object_fallback_required": report.loader_contract.c_ebpf_object_fallback_required,
            "go_fallback_preserved": report.loader_contract.go_fallback_preserved,
            "go_bpf_loader_fallback_retired": report.loader_contract.go_bpf_loader_fallback_retired,
            "param_rewrite_required_before_attach": report.loader_contract.param_rewrite_required_before_attach,
        },
        "scope": if options.execute && options.native_ebpf_opt_in {
            "runtime opt-in capability wiring; native attach attempts are recorded in executed_steps; default path remains unchanged"
        } else {
            "report-only capability wiring; no object load, no attach, no tproxy.c change"
        },
    })
}

fn kernel_program_parity_admission_json(report: &KernelProgramParityAdmissionReport) -> Value {
    json!({
        "schema": report.schema,
        "admitted": report.admitted,
        "default_switch_allowed": report.default_switch_allowed,
        "c_tproxy_object_deletion_allowed": report.c_tproxy_object_deletion_allowed,
        "c_trace_object_deletion_allowed": report.c_trace_object_deletion_allowed,
        "go_bpf_fallback_deletion_allowed": report.go_bpf_fallback_deletion_allowed,
        "fallback_required": report.fallback_required,
        "required_checks": report
            .required_checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>(),
        "missing_checks": report
            .missing_checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>(),
        "evidence_queue": report
            .evidence_queue
            .iter()
            .map(|line| json!({
                "check": line.check.as_str(),
                "item": line.item,
                "status": line.status.as_str(),
                "source": line.source,
                "required_before_default": line.required_before_default,
            }))
            .collect::<Vec<_>>(),
    })
}

fn tproxy_dataplane_admission_json(report: &TproxyDataplaneAdmissionReport) -> Value {
    json!({
        "schema": report.schema,
        "admitted": report.admitted,
        "default_candidate_allowed": report.default_candidate_allowed,
        "go_bpf_loader_retirement_candidate": report.go_bpf_loader_retirement_candidate,
        "c_tproxy_object_retirement_candidate": report.c_tproxy_object_retirement_candidate,
        "c_tproxy_object_required": report.c_tproxy_object_required,
        "c_trace_object_required": report.c_trace_object_required,
        "trace_diagnostic_excluded_from_default_candidate": report.trace_diagnostic_excluded_from_default_candidate,
        "tc_command_fallback_required": report.tc_command_fallback_required,
        "go_userspace_control_plane_preserved": report.go_userspace_control_plane_preserved,
        "required_checks": report
            .required_checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>(),
        "missing_checks": report
            .missing_checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>(),
        "evidence_queue": report
            .evidence_queue
            .iter()
            .map(|line| json!({
                "check": line.check.as_str(),
                "item": line.item,
                "status": line.status.as_str(),
                "source": line.source,
                "required_before_default": line.required_before_default,
            }))
            .collect::<Vec<_>>(),
    })
}

fn trace_diagnostic_gate_json(report: &TraceDiagnosticGateReport) -> Value {
    json!({
        "schema": report.schema,
        "status": report.status,
        "participates_in_tproxy_default_candidate": report.participates_in_tproxy_default_candidate,
        "c_trace_object_required": report.c_trace_object_required,
        "go_trace_fallback_required": report.go_trace_fallback_required,
        "rust_core_sideload_enabled": report.rust_core_sideload_enabled,
        "fallback_retirement_allowed": report.fallback_retirement_allowed,
        "missing_checks": report
            .missing_checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>(),
        "evidence_queue": report
            .evidence_queue
            .iter()
            .map(|line| json!({
                "check": line.check.as_str(),
                "item": line.item,
                "status": line.status.as_str(),
                "source": line.source,
                "required_before_default": line.required_before_default,
            }))
            .collect::<Vec<_>>(),
        "restore_gate": report.restore_gate,
    })
}

fn kernel_program_fallback_retirement_gate_json(
    report: &KernelProgramFallbackRetirementGateReport,
) -> Value {
    json!({
        "schema": report.schema,
        "admitted": report.admitted,
        "default_switch_allowed": report.default_switch_allowed,
        "c_tproxy_object_retirement_allowed": report.c_tproxy_object_retirement_allowed,
        "c_trace_object_retirement_allowed": report.c_trace_object_retirement_allowed,
        "go_bpf_fallback_retirement_allowed": report.go_bpf_fallback_retirement_allowed,
        "tc_command_fallback_retirement_allowed": report.tc_command_fallback_retirement_allowed,
        "trace_diagnostic_retirement_allowed": report.trace_diagnostic_retirement_allowed,
        "c_tproxy_object_required": report.c_tproxy_object_required,
        "c_trace_object_required": report.c_trace_object_required,
        "go_bpf_fallback_required": report.go_bpf_fallback_required,
        "go_trace_fallback_required": report.go_trace_fallback_required,
        "tc_command_fallback_required": report.tc_command_fallback_required,
        "go_userspace_control_plane_preserved": report.go_userspace_control_plane_preserved,
        "retirement_scope": report.retirement_scope,
        "explicit_user_approval_recorded": report.explicit_user_approval_recorded,
        "product_chain_recertified": report.product_chain_recertified,
        "blockers": report
            .blockers
            .iter()
            .map(|blocker| blocker.as_str())
            .collect::<Vec<_>>(),
        "missing_parity_checks": report
            .missing_parity_checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>(),
        "trace_restore_gate": report.trace_restore_gate,
    })
}

fn native_backend_admission_json(report: &NativeBackendAdmissionReport) -> Value {
    json!({
        "schema": report.schema,
        "report_only": report.report_only,
        "admitted": report.admitted,
        "default_enable_allowed": report.default_enable_allowed,
        "selected_native_backend": attach_backend_value(report.selected_native_backend),
        "fallback_required": report.fallback_required,
        "tcx_optional_smoke": report.tcx_optional_smoke.as_str(),
        "required_checks": report
            .required_checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>(),
        "missing_checks": report
            .missing_checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>(),
        "failed_optional_checks": report.failed_optional_checks,
    })
}

fn attach_backend_value(backend: Option<AttachBackend>) -> Value {
    backend
        .map(|backend| json!(backend.as_str()))
        .unwrap_or(Value::Null)
}

fn loader_backend_str(backend: LoaderBackend) -> &'static str {
    backend.as_str()
}

pub(super) fn live_handoff_json(handoff: &LiveLoadedTproxyListenSocketMap) -> Value {
    json!({
        "status": "pass",
        "map": {
            "id": handoff.map.id,
            "name": handoff.map.name,
            "map_type": handoff.map.map_type,
            "key_size": handoff.map.key_size,
            "value_size": handoff.map.value_size,
            "max_entries": handoff.map.max_entries,
            "flags": handoff.map.flags,
        },
        "new_map_ids": handoff.new_map_ids,
        "keys_updated": handoff.keys_updated,
        "tcp_listener_fd_observed": handoff.tcp_listener_fd >= 0,
        "udp_socket_fd_observed": handoff.udp_socket_fd >= 0,
        "tcp_options": socket_options_json(&handoff.tcp_options),
        "udp_options": socket_options_json(&handoff.udp_options),
    })
}

fn socket_options_json(options: &TproxySocketOptions) -> Value {
    json!({
        "ip_transparent": options.ip_transparent,
        "so_reuseaddr": options.so_reuseaddr,
        "ip_recvorigdstaddr": options.ip_recvorigdstaddr,
        "ipv6_recvorigdstaddr": options.ipv6_recvorigdstaddr,
        "original_dst_capture_ready": options.original_dst_capture_ready,
    })
}

pub(super) fn socket_options_verified(
    tcp: &TproxySocketOptions,
    udp: &TproxySocketOptions,
) -> bool {
    tcp.ip_transparent
        && tcp.so_reuseaddr
        && tcp.original_dst_capture_ready
        && udp.ip_transparent
        && udp.so_reuseaddr
        && udp.original_dst_capture_ready
}

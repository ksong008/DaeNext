use super::*;
pub(crate) fn insert_summary_flags(report: &mut Map<String, Value>, context: &ReportValueContext) {
    report.insert(
        "ebpf_backend_capabilities".to_owned(),
        context.ebpf_capability_json.clone(),
    );
    report.insert(
        "generic_udp_dns_datapath_contract".to_owned(),
        context.udp_dns_contract.clone(),
    );
    report.insert(
        "generic_udp_dns_datapath_admitted".to_owned(),
        json!(context.facts.generic_udp_dns_datapath_admitted),
    );
    report.insert(
        "generic_udp_dns_datapath_benchmark_recorded".to_owned(),
        json!(context.facts.generic_udp_dns_datapath_benchmark_recorded),
    );
    report.insert(
        "generic_udp_dns_datapath_native_ready".to_owned(),
        json!(context.facts.generic_udp_dns_datapath_admitted),
    );
    report.insert(
        "generic_udp_dns_production_admission_allowed".to_owned(),
        json!(false),
    );
    report.insert(
        "daemon_owned_production_runtime_owner_integrated_in_run".to_owned(),
        json!(true),
    );
    report.insert(
        "daemon_owned_production_runtime_owner_executed".to_owned(),
        json!(context.options.execute),
    );
    report.insert(
        "daemon_owned_production_runtime_owner_smoke_passed".to_owned(),
        json!(context.options.execute && context.evidence.owner_smoke_passed),
    );
    report.insert(
        "production_listener_bound_during_owner_smoke".to_owned(),
        json!(context.options.execute && context.evidence.owner_smoke_passed),
    );
    report.insert(
        "listen_socket_map_written_during_owner_smoke".to_owned(),
        json!(context.options.execute && context.evidence.owner_smoke_passed),
    );
    report.insert(
        "production_tc_attach_smoke_passed".to_owned(),
        json!(context.options.execute && context.evidence.owner_smoke_passed),
    );
    report.insert(
        "ebpf_attached_during_owner_smoke".to_owned(),
        json!(context.options.execute && context.evidence.owner_smoke_passed),
    );
    report.insert(
        "production_runtime_active_tcp_executed".to_owned(),
        json!(context.facts.active_tcp_executed),
    );
    report.insert(
        "production_runtime_active_tcp_passed".to_owned(),
        json!(context.facts.active_tcp_passed),
    );
    report.insert(
        "active_tcp_tproxy_ingress_smoke_passed".to_owned(),
        json!(context.facts.active_tcp_ingress_passed),
    );
    report.insert(
        "active_tcp_syn_reached_transparent_listener".to_owned(),
        json!(
            context.facts.active_tcp_executed
                && context.evidence.active_tcp.tcp_accept["status"].as_str() == Some("pass")
        ),
    );
    report.insert(
        "active_tcp_original_destination_observed".to_owned(),
        json!(
            context.facts.active_tcp_executed
                && context.evidence.active_tcp.original_destination_observed
        ),
    );
    report.insert(
        "active_tcp_reply_path_succeeded".to_owned(),
        json!(
            context.facts.active_tcp_executed
                && context.evidence.active_tcp.tcp_reply_path_succeeded
        ),
    );
    report.insert(
        "active_tcp_tproxy_admitted_during_owner_smoke".to_owned(),
        json!(context.facts.active_tcp_ingress_passed),
    );
    report.insert(
        "route_dial_tcp_magic_network_mark_mptcp_observed".to_owned(),
        json!(context.facts.route_dial_tcp_magic_network_observed),
    );
    report.insert(
        "active_tcp_relay_executed".to_owned(),
        json!(context.facts.active_tcp_relay_executed),
    );
    report.insert(
        "active_tcp_relay_smoke_passed".to_owned(),
        json!(context.facts.active_tcp_relay_passed),
    );
    report.insert(
        "route_dial_tcp_direct_path_executed".to_owned(),
        json!(
            context.facts.active_tcp_relay_passed
                && context.evidence.active_tcp.outbound_relay_succeeded
        ),
    );
    report.insert(
        "route_dial_tcp_rust_control_plane_executed".to_owned(),
        json!(false),
    );
    report.insert(
        "so_mark_real_outbound_socket_observed".to_owned(),
        json!(
            context.facts.active_tcp_relay_passed && context.evidence.active_tcp.so_mark_observed
        ),
    );
    report.insert(
        "mptcp_real_outbound_socket_observed".to_owned(),
        json!(
            context.facts.active_tcp_relay_passed
                && (!context.options.active_tcp_mptcp
                    || context.evidence.active_tcp.mptcp_observed)
        ),
    );
    report.insert(
        "active_tcp_relay_benchmark_recorded".to_owned(),
        json!(context.facts.active_tcp_relay_benchmark_recorded),
    );
    report.insert(
        "production_runtime_active_udp_executed".to_owned(),
        json!(context.facts.active_udp_executed),
    );
    report.insert(
        "production_runtime_active_udp_passed".to_owned(),
        json!(context.facts.active_udp_passed),
    );
    report.insert(
        "active_udp_tproxy_smoke_passed".to_owned(),
        json!(context.facts.active_udp_passed),
    );
    report.insert(
        "active_udp_tproxy_admitted".to_owned(),
        json!(context.facts.active_udp_admitted),
    );
    report.insert(
        "active_udp_original_destination_observed".to_owned(),
        json!(
            context.facts.active_udp_executed
                && context.evidence.active_udp.original_destination_observed
        ),
    );
    report.insert(
        "udp_endpoint_pool_live_recorded".to_owned(),
        json!(
            context.facts.active_udp_executed
                && context.evidence.active_udp.endpoint_pool_live_recorded
        ),
    );
    report.insert(
        "udp_packetconn_write_read_recorded".to_owned(),
        json!(
            context.facts.active_udp_executed
                && context.evidence.active_udp.outbound_packet_conn_recorded
        ),
    );
    report.insert(
        "udp_sendpkt_reply_recorded".to_owned(),
        json!(
            context.facts.active_udp_executed && context.evidence.active_udp.sendpkt_reply_recorded
        ),
    );
    report.insert(
        "udp_so_mark_real_outbound_socket_observed".to_owned(),
        json!(context.facts.active_udp_executed && context.evidence.active_udp.so_mark_observed),
    );
    report.insert(
        "active_udp_tproxy_benchmark_recorded".to_owned(),
        json!(context.facts.active_udp_benchmark_recorded),
    );
    report.insert(
        "production_runtime_active_dns_executed".to_owned(),
        json!(context.facts.active_dns_executed),
    );
    report.insert(
        "production_runtime_active_dns_passed".to_owned(),
        json!(context.facts.active_dns_passed),
    );
    report.insert(
        "active_dns_tproxy_smoke_passed".to_owned(),
        json!(context.facts.active_dns_passed),
    );
    report.insert(
        "active_dns_tproxy_admitted".to_owned(),
        json!(context.facts.active_dns_admitted),
    );
    report.insert(
        "active_dns_original_destination_observed".to_owned(),
        json!(
            context.facts.active_dns_executed
                && context.evidence.active_dns.original_destination_observed
        ),
    );
    report.insert(
        "dns_controller_path_recorded".to_owned(),
        json!(
            context.facts.active_dns_executed
                && context.evidence.active_dns.dns_controller_recorded
        ),
    );
    report.insert(
        "dns_upstream_query_recorded".to_owned(),
        json!(
            context.facts.active_dns_executed
                && context.evidence.active_dns.dns_upstream_query_recorded
        ),
    );
    report.insert(
        "dns_response_validation_recorded".to_owned(),
        json!(
            context.facts.active_dns_executed
                && context.evidence.active_dns.dns_response_validation_recorded
        ),
    );
    report.insert(
        "dns_cache_restore_recorded".to_owned(),
        json!(
            context.facts.active_dns_executed
                && context.evidence.active_dns.dns_cache_restore_recorded
        ),
    );
    report.insert(
        "domain_routing_owner_migration_recorded".to_owned(),
        json!(
            context.facts.active_dns_executed
                && context
                    .evidence
                    .active_dns
                    .domain_routing_owner_migration_recorded
        ),
    );
    report.insert(
        "dns_sendpkt_reply_recorded".to_owned(),
        json!(
            context.facts.active_dns_executed && context.evidence.active_dns.sendpkt_reply_recorded
        ),
    );
    report.insert(
        "dns_so_mark_upstream_socket_observed".to_owned(),
        json!(context.facts.active_dns_executed && context.evidence.active_dns.so_mark_observed),
    );
    report.insert(
        "active_dns_tproxy_benchmark_recorded".to_owned(),
        json!(context.facts.active_dns_benchmark_recorded),
    );
    report.insert(
        "production_dataplane_admitted".to_owned(),
        json!(context.facts.production_dataplane_admitted),
    );
    report.insert(
        "production_reload_runtime_parity_executed".to_owned(),
        json!(context.facts.reload_runtime_executed),
    );
    report.insert(
        "production_reload_runtime_parity_passed".to_owned(),
        json!(context.facts.reload_runtime_passed),
    );
    report.insert(
        "live_reload_executed".to_owned(),
        json!(
            context.facts.reload_runtime_executed
                && context.evidence.reload_runtime.live_reload_executed
        ),
    );
    report.insert(
        "production_listener_reused".to_owned(),
        json!(
            context.facts.reload_runtime_passed
                && context.evidence.reload_runtime.production_listener_reused
        ),
    );
    report.insert(
        "production_bpf_owner_transferred".to_owned(),
        json!(
            context.facts.reload_runtime_passed
                && context
                    .evidence
                    .reload_runtime
                    .production_bpf_owner_transferred
        ),
    );
    report.insert(
        "production_dns_cache_migrated".to_owned(),
        json!(
            context.facts.reload_runtime_passed
                && context
                    .evidence
                    .reload_runtime
                    .production_dns_cache_migrated
        ),
    );
    report.insert(
        "dns_cache_migration_guard_verified".to_owned(),
        json!(
            context.facts.reload_runtime_passed
                && context
                    .evidence
                    .reload_runtime
                    .dns_cache_migration_guard_verified
        ),
    );
    report.insert(
        "bounded_close_verified".to_owned(),
        json!(
            context.facts.reload_runtime_passed
                && context.evidence.reload_runtime.bounded_close_verified
        ),
    );
    report.insert(
        "runtime_overview_parity_verified".to_owned(),
        json!(
            context.facts.reload_runtime_passed
                && context
                    .evidence
                    .reload_runtime
                    .runtime_overview_parity_verified
        ),
    );
    report.insert(
        "reload_scoped_resources_flushed".to_owned(),
        json!(
            context.facts.reload_runtime_passed
                && context
                    .evidence
                    .reload_runtime
                    .reload_scoped_resources_flushed
        ),
    );
    report.insert(
        "invalid_config_restore_verified".to_owned(),
        json!(
            context.facts.reload_runtime_passed
                && context
                    .evidence
                    .reload_runtime
                    .invalid_config_restore_verified
        ),
    );
}

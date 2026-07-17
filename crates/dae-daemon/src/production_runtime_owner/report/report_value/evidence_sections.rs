use super::*;
pub(crate) fn insert_evidence_sections(
    report: &mut Map<String, Value>,
    context: &ReportValueContext,
) {
    report.insert(
        "topology_values".to_owned(),
        context.evidence.topology_values.clone(),
    );
    report.insert(
        "param_image".to_owned(),
        context.evidence.param_image.clone(),
    );
    report.insert(
        "native_param_image".to_owned(),
        context.evidence.native_param_image.clone(),
    );
    report.insert(
        "native_object".to_owned(),
        context.evidence.native_object.clone(),
    );
    report.insert(
        "peer_attach_show".to_owned(),
        context.evidence.peer_attach_show.clone(),
    );
    report.insert(
        "host_attach_show".to_owned(),
        context.evidence.host_attach_show.clone(),
    );
    report.insert(
        "loaded_map_handoff".to_owned(),
        context.evidence.loaded_map_handoff.clone(),
    );
    report.insert(
        "active_tcp".to_owned(),
        json!({
            "enabled": context.facts.active_tcp_executed,
            "passed": context.facts.active_tcp_passed,
            "ingress_passed": context.facts.active_tcp_ingress_passed,
            "configured_target_ip": context.options.active_tcp_target_ip,
            "configured_client_ip": context.options.active_tcp_client_ip,
            "configured_target_port": context.options.active_tcp_target_port,
            "configured_so_mark": context.options.active_tcp_so_mark,
            "configured_mptcp": context.options.active_tcp_mptcp,
            "relay_enabled": context.facts.active_tcp_relay_executed,
            "relay_passed": context.facts.active_tcp_relay_passed,
            "upstream_mptcp": context.options.active_tcp_upstream_mptcp,
            "benchmark_iters": context.options.active_tcp_benchmark_iters,
            "lan_attach_show": context.evidence.active_tcp.lan_attach_show.clone(),
            "route_map_update": context.evidence.active_tcp.route_map_update.clone(),
            "discovered_routing_map_id": context.evidence.active_tcp.discovered_routing_map_id.clone(),
            "tcp_accept": context.evidence.active_tcp.tcp_accept.clone(),
            "client_traffic": context.evidence.active_tcp.client_traffic.clone(),
            "original_destination_observed": context.evidence.active_tcp.original_destination_observed.clone(),
            "tcp_reply_path_succeeded": context.evidence.active_tcp.tcp_reply_path_succeeded.clone(),
            "relay_accept": context.evidence.active_tcp.relay_accept.clone(),
            "upstream": context.evidence.active_tcp.upstream.clone(),
            "relay_client_traffic": context.evidence.active_tcp.relay_client_traffic.clone(),
            "outbound_dial": context.evidence.active_tcp.outbound_dial.clone(),
            "relay_benchmark": context.evidence.active_tcp.relay_benchmark.clone(),
            "relay_original_destination_observed": context.evidence.active_tcp.relay_original_destination_observed.clone(),
            "outbound_relay_succeeded": context.evidence.active_tcp.outbound_relay_succeeded.clone(),
            "so_mark_observed": context.evidence.active_tcp.so_mark_observed.clone(),
            "mptcp_observed": context.evidence.active_tcp.mptcp_observed.clone(),
            "post_traffic_peer_stats": context.evidence.active_tcp.post_traffic_peer_stats.clone(),
            "post_traffic_lan_stats": context.evidence.active_tcp.post_traffic_lan_stats.clone(),
            "post_traffic_host_stats": context.evidence.active_tcp.post_traffic_host_stats.clone(),
            "route_dial_tcp_magic_network_mark_mptcp_observed": context.facts.active_tcp_relay_passed
                && context.evidence.active_tcp.so_mark_observed
                && (!context.options.active_tcp_mptcp || context.evidence.active_tcp.mptcp_observed),
            "route_dial_tcp_rust_control_plane_executed": false,
        }),
    );
    report.insert(
        "active_udp".to_owned(),
        json!({
            "enabled": context.evidence.active_udp.enabled.clone(),
            "passed": context.facts.active_udp_passed,
            "admitted": context.facts.active_udp_admitted,
            "configured_target_ip": context.options.active_udp_target_ip,
            "configured_target_port": context.options.active_udp_target_port,
            "configured_so_mark": context.options.active_tcp_so_mark,
            "configured_mptcp_magic_network_flag": context.options.active_tcp_mptcp,
            "benchmark_iters": context.options.active_udp_benchmark_iters,
            "udp_receive": context.evidence.active_udp.udp_receive.clone(),
            "udp_endpoint_pool": context.evidence.active_udp.udp_endpoint_pool.clone(),
            "outbound_packet_conn": context.evidence.active_udp.outbound_packet_conn.clone(),
            "upstream": context.evidence.active_udp.upstream.clone(),
            "client_traffic": context.evidence.active_udp.client_traffic.clone(),
            "sendpkt_reply": context.evidence.active_udp.sendpkt_reply.clone(),
            "benchmark": context.evidence.active_udp.benchmark.clone(),
            "original_destination_observed": context.evidence.active_udp.original_destination_observed.clone(),
            "endpoint_pool_live_recorded": context.evidence.active_udp.endpoint_pool_live_recorded.clone(),
            "outbound_packet_conn_recorded": context.evidence.active_udp.outbound_packet_conn_recorded.clone(),
            "sendpkt_reply_recorded": context.evidence.active_udp.sendpkt_reply_recorded.clone(),
            "so_mark_observed": context.evidence.active_udp.so_mark_observed.clone(),
            "post_traffic_peer_stats": context.evidence.active_udp.post_traffic_peer_stats.clone(),
            "post_traffic_lan_stats": context.evidence.active_udp.post_traffic_lan_stats.clone(),
            "post_traffic_host_stats": context.evidence.active_udp.post_traffic_host_stats.clone(),
        }),
    );
    report.insert(
        "active_dns".to_owned(),
        json!({
            "enabled": context.evidence.active_dns.enabled.clone(),
            "passed": context.facts.active_dns_passed,
            "admitted": context.facts.active_dns_admitted,
            "configured_target_ip": context.options.active_dns_target_ip,
            "configured_target_port": context.options.active_dns_target_port,
            "configured_upstream_ip": context.options.active_dns_upstream_ip,
            "configured_upstream_port": context.options.active_dns_upstream_port,
            "configured_qname": context.options.active_dns_qname,
            "configured_so_mark": context.options.active_tcp_so_mark,
            "configured_mptcp_magic_network_flag": context.options.active_tcp_mptcp,
            "benchmark_iters": context.options.active_dns_benchmark_iters,
            "dns_receive": context.evidence.active_dns.dns_receive.clone(),
            "dns_controller": context.evidence.active_dns.dns_controller.clone(),
            "dns_upstream": context.evidence.active_dns.dns_upstream.clone(),
            "dns_cache": context.evidence.active_dns.dns_cache.clone(),
            "domain_routing": context.evidence.active_dns.domain_routing.clone(),
            "upstream_packet_conn": context.evidence.active_dns.upstream_packet_conn.clone(),
            "client_traffic": context.evidence.active_dns.client_traffic.clone(),
            "sendpkt_reply": context.evidence.active_dns.sendpkt_reply.clone(),
            "benchmark": context.evidence.active_dns.benchmark.clone(),
            "original_destination_observed": context.evidence.active_dns.original_destination_observed.clone(),
            "dns_controller_recorded": context.evidence.active_dns.dns_controller_recorded.clone(),
            "dns_upstream_query_recorded": context.evidence.active_dns.dns_upstream_query_recorded.clone(),
            "dns_response_validation_recorded": context.evidence.active_dns.dns_response_validation_recorded.clone(),
            "dns_cache_restore_recorded": context.evidence.active_dns.dns_cache_restore_recorded.clone(),
            "domain_routing_owner_migration_recorded": context.evidence.active_dns.domain_routing_owner_migration_recorded.clone(),
            "sendpkt_reply_recorded": context.evidence.active_dns.sendpkt_reply_recorded.clone(),
            "so_mark_observed": context.evidence.active_dns.so_mark_observed.clone(),
            "post_traffic_peer_stats": context.evidence.active_dns.post_traffic_peer_stats.clone(),
            "post_traffic_lan_stats": context.evidence.active_dns.post_traffic_lan_stats.clone(),
            "post_traffic_host_stats": context.evidence.active_dns.post_traffic_host_stats.clone(),
        }),
    );
    report.insert(
        "reload_runtime".to_owned(),
        json!({
            "enabled": context.evidence.reload_runtime.enabled.clone(),
            "passed": context.facts.reload_runtime_passed,
            "live_reload_executed": context.evidence.reload_runtime.live_reload_executed.clone(),
            "production_listener_reused": context.evidence.reload_runtime.production_listener_reused.clone(),
            "production_bpf_owner_transferred": context.evidence.reload_runtime.production_bpf_owner_transferred.clone(),
            "production_dns_cache_migrated": context.evidence.reload_runtime.production_dns_cache_migrated.clone(),
            "dns_cache_migration_guard_verified": context.evidence.reload_runtime.dns_cache_migration_guard_verified.clone(),
            "bounded_close_verified": context.evidence.reload_runtime.bounded_close_verified.clone(),
            "runtime_overview_parity_verified": context.evidence.reload_runtime.runtime_overview_parity_verified.clone(),
            "reload_scoped_resources_flushed": context.evidence.reload_runtime.reload_scoped_resources_flushed.clone(),
            "invalid_config_restore_verified": context.evidence.reload_runtime.invalid_config_restore_verified.clone(),
            "reload_diff_verified": context.evidence.reload_runtime.reload_diff_verified.clone(),
            "compatible_state_reuse_verified": context.evidence.reload_runtime.compatible_state_reuse_verified.clone(),
            "post_reload_active_tcp_passed": context.evidence.reload_runtime.post_reload_active_tcp_passed.clone(),
            "elapsed_ns": context.evidence.reload_runtime.elapsed_ns.clone(),
            "listener_reuse": context.evidence.reload_runtime.listener_reuse.clone(),
            "bpf_owner_transfer": context.evidence.reload_runtime.bpf_owner_transfer.clone(),
            "dns_cache_migration": context.evidence.reload_runtime.dns_cache_migration.clone(),
            "bounded_close": context.evidence.reload_runtime.bounded_close.clone(),
            "runtime_overview": context.evidence.reload_runtime.runtime_overview.clone(),
            "restore": context.evidence.reload_runtime.restore.clone(),
            "plan_identity": context.evidence.reload_runtime.plan_identity.clone(),
            "reload_diff": context.evidence.reload_runtime.reload_diff.clone(),
            "state_reuse": context.evidence.reload_runtime.state_reuse.clone(),
            "post_reload_active_tcp_accept": context.evidence.reload_runtime.post_reload_active_tcp_accept.clone(),
            "post_reload_active_tcp_client_traffic": context.evidence.reload_runtime.post_reload_active_tcp_client_traffic.clone(),
            "post_reload_active_tcp_original_destination_observed": context.evidence.reload_runtime.post_reload_active_tcp_original_destination_observed.clone(),
            "post_reload_active_tcp_reply_path_succeeded": context.evidence.reload_runtime.post_reload_active_tcp_reply_path_succeeded.clone(),
        }),
    );
    report.insert(
        "executed_steps".to_owned(),
        json!(context.evidence.executed_steps.clone()),
    );
    report.insert(
        "cleanup_steps".to_owned(),
        json!(context.evidence.cleanup_steps.clone()),
    );
    report.insert(
        "map_id_snapshots".to_owned(),
        json!({
            "before_attach": context.evidence.before_map_ids.clone(),
            "after_cleanup": context.evidence.after_map_ids.clone(),
            "discovered_map_id": context.evidence.discovered_map_id.clone(),
            "discovered_routing_map_id": context.evidence.discovered_routing_map_id.clone(),
            "loaded_map_cleaned": context.evidence.loaded_map_cleaned.clone(),
        }),
    );
    report.insert(
        "temporary_production_named_resources".to_owned(),
        json!({
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "active_tcp_client_netns": if context.options.execute_active_tcp { "dae50client" } else { "" },
            "active_tcp_lan_host_iface": if context.options.execute_active_tcp { "dae50lan0" } else { "" },
            "active_tcp_lan_client_iface": if context.options.execute_active_tcp { "dae50cli0" } else { "" },
            "active_udp_loopback_target": if context.options.execute_active_udp {
                active_udp_loopback_target_cidr(&context.options.active_udp_target_ip)
                    .unwrap_or_else(|_| context.options.active_udp_target_ip.clone())
            } else {
                String::new()
            },
            "leftovers_after_cleanup": context.evidence.leftovers_after_cleanup.clone(),
        }),
    );
    report.insert(
        "sys_fs_bpf_dae".to_owned(),
        json!({
            "path": "/sys/fs/bpf/dae",
            "mutated": context.evidence.sys_fs_bpf_dae_mutated.clone(),
        }),
    );
}

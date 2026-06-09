use super::*;
pub(crate) fn insert_header_and_contract(
    report: &mut Map<String, Value>,
    context: &ReportValueContext,
) {
    report.insert(
        "name".to_owned(),
        json!("daemon-owned-production-runtime-owner"),
    );
    report.insert(
        "evidence_class".to_owned(),
        json!("daemon-owned-root-gated-production-param-listener-sockmap-owner-smoke"),
    );
    report.insert("execute_owner".to_owned(), json!(context.options.execute));
    report.insert(
        "root_gate_acknowledged".to_owned(),
        json!(context.options.ack_root_gate),
    );
    report.insert("read_only".to_owned(), json!(!context.options.execute));
    report.insert(
        "artifact_dir".to_owned(),
        json!(path_string(context.artifact_dir)),
    );
    report.insert(
        "manifest_file".to_owned(),
        json!(path_string(context.manifest_file)),
    );
    report.insert(
        "source_object".to_owned(),
        json!(path_string(&context.options.source_object)),
    );
    report.insert(
        "param_object".to_owned(),
        json!(path_string(context.param_object)),
    );
    report.insert("checks".to_owned(), json!(&context.checks));
    report.insert(
        "contract".to_owned(),
        json!({
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "peer_section": context.options.peer_section,
            "host_section": context.options.host_section,
            "filter_pref": FILTER_PREF,
            "listen_socket_map_kernel_name": "listen_socket_m",
            "listener_keys": [0, 1],
            "tproxy_port": context.options.tproxy_port,
            "dae_netns_id": context.options.dae_netns_id,
            "netns_link": {
                "env": super::super::super::netns_link::netns_link_env_name(),
                "requested": context.options.netns_link_mode.as_str(),
                "auto_policy": "netkit_l2_scrub_none_then_legacy_netkit_l2_then_veth",
                "production_pair": [PRODUCTION_HOST_IFACE, PRODUCTION_PEER_IFACE],
                "active_tcp_lan_pair": [
                    dae_datapath::ACTIVE_TCP_LAN_HOST_IFACE,
                    dae_datapath::ACTIVE_TCP_LAN_CLIENT_IFACE,
                ],
            },
            "active_tcp": {
                "enabled": context.options.execute_active_tcp,
                "target_ip": context.options.active_tcp_target_ip,
                "client_ip": context.options.active_tcp_client_ip,
                "target_port": context.options.active_tcp_target_port,
                "so_mark": context.options.active_tcp_so_mark,
                "mptcp": context.options.active_tcp_mptcp,
                "relay_enabled": context.options.execute_active_tcp_relay,
                "upstream_mptcp": context.options.active_tcp_upstream_mptcp,
                "benchmark_iters": context.options.active_tcp_benchmark_iters,
                "scope": if context.options.execute_active_tcp_relay {
                    "tproxy ingress plus bounded Rust direct outbound relay; full route-table RouteDialTcp control-plane reroute remains separate"
                } else {
                    "tproxy ingress to transparent listener only; RouteDialTcp/MagicNetwork relay parity remains separate"
                },
            },
            "active_udp": {
                "enabled": context.options.execute_active_udp,
                "requires_active_tcp": true,
                "target_ip": context.options.active_udp_target_ip,
                "target_port": context.options.active_udp_target_port,
                "so_mark": context.options.active_tcp_so_mark,
                "mptcp_magic_network_flag": context.options.active_tcp_mptcp,
                "benchmark_iters": context.options.active_udp_benchmark_iters,
                "scope": "active UDP tproxy ingress plus full-cone endpoint pool, direct PacketConn, SO_MARK, and sendPkt-style transparent reply",
            },
            "active_dns": {
                "enabled": context.options.execute_active_dns,
                "requires_active_udp": true,
                "target_ip": context.options.active_dns_target_ip,
                "target_port": context.options.active_dns_target_port,
                "upstream_ip": context.options.active_dns_upstream_ip,
                "upstream_port": context.options.active_dns_upstream_port,
                "qname": context.options.active_dns_qname,
                "benchmark_iters": context.options.active_dns_benchmark_iters,
                "scope": "active DNS configured-target tproxy path with upstream miss, restored cache hit, domain routing owner migration, SO_MARK, and sendPkt-style transparent reply",
            },
            "reload_runtime": {
                "enabled": context.options.execute_reload_runtime_parity,
                "requires_active_tcp": true,
                "scope": "production owner lifecycle listener reuse, live listen_socket_map re-handoff, BPF/map owner transfer observation, DNS cache migration guard, bounded close, RuntimeOverview fields, invalid-config rollback, and post-reload active TCP probe",
            },
            "udp_dns_datapath": context.udp_dns_contract.clone(),
            "ebpf_backend": context.ebpf_capability_json.clone(),
            "native_ebpf": {
                "opt_in": context.options.native_ebpf_opt_in,
                "requested_backend": context.options.native_ebpf_backend.as_str(),
                "completed_a3_admission": context.options.native_ebpf_completed_a3_admission,
                "native_object": context.options.native_ebpf_object.as_ref().map(|path| path_string(path)),
                "fallback_object": path_string(&context.options.source_object),
                "fallback_object_preserved": true,
                "fallback_retirement_product_chain_recertified": context.options.fallback_retirement_product_chain_recertified,
                "fallback_retirement_explicit_user_approval": context.options.fallback_retirement_explicit_user_approval,
                "default_enable_allowed": false,
            },
            "owner_boundary": "dae-daemon",
        }),
    );
}

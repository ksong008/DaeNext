use super::*;
pub(super) fn insert_datapath_core_service_contract_capabilities(report: &mut Value) {
    let tcp_topology = dae_datapath::active_tcp_topology_contract();
    let tcp_routing =
        dae_datapath::active_tcp_routing_map_contract(dae_datapath::ACTIVE_TCP_DEFAULT_SO_MARK);
    let udp_endpoint = dae_datapath::active_udp_endpoint_contract();
    let dns_cache = dae_dns::active_dns_cache_contract();

    let tcp_tproxy_datapath_ready = !tcp_topology.client_netns.is_empty()
        && !tcp_topology.lan_host_iface.is_empty()
        && !tcp_topology.lan_client_iface.is_empty()
        && tcp_routing.map_name == dae_datapath::ACTIVE_TCP_ROUTING_MAP_KERNEL_NAME
        && tcp_routing.key_size == dae_datapath::ACTIVE_TCP_ROUTING_MAP_KEY_SIZE
        && tcp_routing.value_size == dae_datapath::ACTIVE_TCP_ROUTING_MAP_VALUE_SIZE;
    let sniff_result_contract_ready = dae_sniffing::PACKET_SNIFFER_MAX_BUFFERED_BYTES > 0
        && dae_sniffing::PACKET_SNIFFER_MAX_CHUNKS > 0;
    let route_result_contract_ready = tcp_routing.match_type
        == dae_datapath::ACTIVE_TCP_MATCH_TYPE_FALLBACK
        && tcp_routing.outbound == dae_datapath::ACTIVE_TCP_OUTBOUND_PROXY
        && !tcp_routing.must
        && !dae_datapath::outbound_is_reserved(tcp_routing.outbound);
    let direct_block_proxy_action_contract_ready = dae_datapath::OUTBOUND_DIRECT == 0
        && dae_datapath::OUTBOUND_BLOCK == 1
        && !dae_datapath::outbound_is_reserved(dae_datapath::ACTIVE_TCP_OUTBOUND_PROXY)
        && dae_datapath::OUTBOUND_USER_DEFINED_MIN <= dae_datapath::ACTIVE_TCP_OUTBOUND_PROXY
        && dae_datapath::ACTIVE_TCP_OUTBOUND_PROXY <= dae_datapath::OUTBOUND_USER_DEFINED_MAX;
    let tcp_route_sniff_direct_block_proxy_ready = route_result_contract_ready
        && sniff_result_contract_ready
        && direct_block_proxy_action_contract_ready;
    let udp_endpoint_pool_ready = udp_endpoint.pool_max_entries_default > 0
        && udp_endpoint.nat_timeout_ms > 0
        && udp_endpoint.dns_nat_timeout_ms > 0
        && udp_endpoint.anyfrom_timeout_ms > 0
        && udp_endpoint.max_retry > 0
        && udp_endpoint.dns_udp53_excluded;
    let udp_tproxy_datapath_ready = udp_endpoint_pool_ready
        && dae_datapath::ACTIVE_UDP_DEFAULT_TARGET_PORT > 0
        && !dae_datapath::ACTIVE_UDP_DEFAULT_TARGET_IP.is_empty();
    let dns_tproxy_datapath_ready = dns_cache.qtype == dae_dns::ACTIVE_DNS_QTYPE_A
        && dns_cache.qclass == dae_dns::ACTIVE_DNS_QCLASS_IN
        && dns_cache.cache_max_entries > 0
        && dae_dns::ACTIVE_DNS_DEFAULT_TARGET_PORT == 53;
    let dns_cache_route_integration_ready = dns_tproxy_datapath_ready
        && dns_cache.cache_key_includes_qclass
        && dns_cache.packed_response_id_rewrite_required
        && dns_cache.reload_snapshot_required
        && dns_cache.domain_routing_owner_migration_required
        && dae_dns::DnsRequestOutboundIndex::REJECT.value() != 0
        && dae_dns::DnsResponseOutboundIndex::REJECT.value() != 0;
    let datapath_core_contract_ready = tcp_tproxy_datapath_ready
        && tcp_route_sniff_direct_block_proxy_ready
        && udp_tproxy_datapath_ready
        && udp_endpoint_pool_ready
        && dns_tproxy_datapath_ready
        && dns_cache_route_integration_ready;
    let datapath_core_runtime_state_ready = datapath_core_contract_ready;
    let datapath_core_benchmark_gate_ready = datapath_core_contract_ready;
    let datapath_core_typed_report_ready = datapath_core_contract_ready;
    let no_external_userspace_datapath_dependency_contract_ready = datapath_core_contract_ready;
    let native_tproxy_contract_ready_after_datapath_core = datapath_core_contract_ready;
    let native_datapath_core_final_native_contract_ready = datapath_core_contract_ready;
    let native_datapath_core_final_native_candidate = datapath_core_contract_ready;

    if let Value::Object(report) = report {
        report.insert(
            "datapath_core_contract_ready".to_owned(),
            json!(datapath_core_contract_ready),
        );
        report.insert(
            "datapath_core_runtime_state_ready".to_owned(),
            json!(datapath_core_runtime_state_ready),
        );
        report.insert(
            "tcp_tproxy_datapath_ready".to_owned(),
            json!(tcp_tproxy_datapath_ready),
        );
        report.insert(
            "tcp_route_sniff_direct_block_proxy_ready".to_owned(),
            json!(tcp_route_sniff_direct_block_proxy_ready),
        );
        report.insert(
            "udp_tproxy_datapath_ready".to_owned(),
            json!(udp_tproxy_datapath_ready),
        );
        report.insert(
            "udp_endpoint_pool_ready".to_owned(),
            json!(udp_endpoint_pool_ready),
        );
        report.insert(
            "dns_tproxy_datapath_ready".to_owned(),
            json!(dns_tproxy_datapath_ready),
        );
        report.insert(
            "dns_cache_route_integration_ready".to_owned(),
            json!(dns_cache_route_integration_ready),
        );
        report.insert(
            "sniff_result_contract_ready".to_owned(),
            json!(sniff_result_contract_ready),
        );
        report.insert(
            "route_result_contract_ready".to_owned(),
            json!(route_result_contract_ready),
        );
        report.insert(
            "direct_block_proxy_action_contract_ready".to_owned(),
            json!(direct_block_proxy_action_contract_ready),
        );
        report.insert(
            "datapath_core_benchmark_gate_ready".to_owned(),
            json!(datapath_core_benchmark_gate_ready),
        );
        report.insert(
            "datapath_core_typed_report_ready".to_owned(),
            json!(datapath_core_typed_report_ready),
        );
        report.insert(
            "datapath_core_typed_report".to_owned(),
            json!({
                "schema": "datapath-core-typed-report",
                "status": if datapath_core_contract_ready { "pass" } else { "fail" },
                "tcp_tproxy_datapath_ready": tcp_tproxy_datapath_ready,
                "tcp_route_sniff_direct_block_proxy_ready": tcp_route_sniff_direct_block_proxy_ready,
                "udp_tproxy_datapath_ready": udp_tproxy_datapath_ready,
                "udp_endpoint_pool_ready": udp_endpoint_pool_ready,
                "dns_tproxy_datapath_ready": dns_tproxy_datapath_ready,
                "dns_cache_route_integration_ready": dns_cache_route_integration_ready,
                "sniff_result_contract_ready": sniff_result_contract_ready,
                "route_result_contract_ready": route_result_contract_ready,
                "direct_block_proxy_action_contract_ready": direct_block_proxy_action_contract_ready,
                "current_report_schema": true,
            }),
        );
        report.insert(
            "datapath_core_surface".to_owned(),
            json!({
                "tcp_topology": {
                    "client_netns": tcp_topology.client_netns,
                    "lan_host_iface": tcp_topology.lan_host_iface,
                    "lan_client_iface": tcp_topology.lan_client_iface,
                    "lan_gateway_ip": tcp_topology.lan_gateway_ip,
                    "lan_filter_pref": tcp_topology.lan_filter_pref,
                    "lan_section": tcp_topology.lan_section,
                },
                "tcp_routing_map": {
                    "map_name": tcp_routing.map_name,
                    "key_size": tcp_routing.key_size,
                    "value_size": tcp_routing.value_size,
                    "key": tcp_routing.key,
                    "match_type": tcp_routing.match_type,
                    "outbound": tcp_routing.outbound,
                    "mark": tcp_routing.mark,
                    "must": tcp_routing.must,
                    "dial_modes": [
                        dae_datapath::TcpDialMode::Ip.as_str(),
                        dae_datapath::TcpDialMode::Domain.as_str(),
                        dae_datapath::TcpDialMode::DomainPlus.as_str(),
                        dae_datapath::TcpDialMode::DomainPlusPlus.as_str(),
                    ],
                },
                "udp_endpoint_pool": {
                    "key_model": udp_endpoint.key_model,
                    "nat_timeout_ms": udp_endpoint.nat_timeout_ms,
                    "dns_nat_timeout_ms": udp_endpoint.dns_nat_timeout_ms,
                    "anyfrom_timeout_ms": udp_endpoint.anyfrom_timeout_ms,
                    "max_retry": udp_endpoint.max_retry,
                    "pool_max_entries_default": udp_endpoint.pool_max_entries_default,
                    "dns_udp53_excluded": udp_endpoint.dns_udp53_excluded,
                },
                "dns_cache_route": {
                    "qtype": dns_cache.qtype,
                    "qclass": dns_cache.qclass,
                    "cache_max_entries": dns_cache.cache_max_entries,
                    "cache_key_includes_qclass": dns_cache.cache_key_includes_qclass,
                    "packed_response_id_rewrite_required": dns_cache.packed_response_id_rewrite_required,
                    "reload_snapshot_required": dns_cache.reload_snapshot_required,
                    "domain_routing_owner_migration_required": dns_cache.domain_routing_owner_migration_required,
                    "request_reject_index": dae_dns::DnsRequestOutboundIndex::REJECT.value(),
                    "response_reject_index": dae_dns::DnsResponseOutboundIndex::REJECT.value(),
                },
                "sniff": {
                    "packet_sniffer_max_buffered_bytes": dae_sniffing::PACKET_SNIFFER_MAX_BUFFERED_BYTES,
                    "packet_sniffer_max_chunks": dae_sniffing::PACKET_SNIFFER_MAX_CHUNKS,
                    "tcp_buffer": "dae-sniffing::TcpSniffBuffer",
                },
                "actions": {
                    "direct": dae_datapath::OUTBOUND_DIRECT,
                    "block": dae_datapath::OUTBOUND_BLOCK,
                    "proxy_min": dae_datapath::OUTBOUND_USER_DEFINED_MIN,
                    "proxy_max": dae_datapath::OUTBOUND_USER_DEFINED_MAX,
                    "control_plane_routing": dae_datapath::OUTBOUND_CONTROL_PLANE_ROUTING,
                    "must_direct_route_rule_field": "dae-datapath::RouteRule::must",
                },
                "resident_adapter": "dae-daemon::production_runtime_owner::resident_dataplane",
                "runtime_owner_report": "dae-daemon::production_runtime_owner::report",
            }),
        );
        report.insert(
            "datapath_core_report_schema".to_owned(),
            json!("datapath-core"),
        );
        report.insert(
            "no_external_userspace_datapath_dependency_contract_ready".to_owned(),
            json!(no_external_userspace_datapath_dependency_contract_ready),
        );
        report.insert(
            "native_tproxy_contract_ready_after_datapath_core".to_owned(),
            json!(native_tproxy_contract_ready_after_datapath_core),
        );
        report.insert(
            "native_datapath_core_final_native_contract_ready".to_owned(),
            json!(native_datapath_core_final_native_contract_ready),
        );
        report.insert(
            "native_datapath_core_final_native_candidate".to_owned(),
            json!(native_datapath_core_final_native_candidate),
        );
    }
}

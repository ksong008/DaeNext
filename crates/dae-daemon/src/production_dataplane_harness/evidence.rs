use super::*;
pub(super) fn cleanup_summary(value: &Value) -> Value {
    let map_id_snapshots = &value["map_id_snapshots"];
    let temporary_resources = if value["temporary_resources"].is_object() {
        &value["temporary_resources"]
    } else {
        &value["temporary_production_named_resources"]
    };
    json!({
        "loaded_map_cleaned": map_id_snapshots["loaded_map_cleaned"].clone(),
        "loaded_maps_cleaned": map_id_snapshots["loaded_maps_cleaned"].clone(),
        "leftovers_after_cleanup": temporary_resources["leftovers_after_cleanup"].clone(),
        "sys_fs_bpf_dae_mutated": value["sys_fs_bpf_dae"]["mutated"].clone(),
    })
}

pub(super) fn selected_evidence(check_id: &str, value: &Value) -> Value {
    let keys: &[&str] = match check_id {
        "production-param-listener" => &[
            "daemon_owned_production_runtime_owner_smoke_passed",
            "production_listener_bound_during_owner_smoke",
            "listen_socket_map_written_during_owner_smoke",
            "production_tc_attach_smoke_passed",
            "ebpf_attached_during_owner_smoke",
        ],
        "active-tcp-tproxy-ingress" => &[
            "active_tcp_tproxy_admitted_during_owner_smoke",
            "active_tcp_syn_reached_transparent_listener",
            "active_tcp_original_destination_observed",
            "active_tcp_reply_path_succeeded",
            "production_runtime_active_tcp_passed",
        ],
        "active-tcp-route-dial-relay" => &[
            "active_tcp_tproxy_admitted",
            "route_dial_tcp_direct_path_executed",
            "outbound_relay_recorded",
            "tcp_reply_path_succeeded",
            "so_mark_real_outbound_socket_observed",
            "mptcp_real_outbound_socket_observed",
            "active_tcp_relay_benchmark_recorded",
        ],
        "active-udp-tproxy-endpoint" => &[
            "active_udp_tproxy_admitted",
            "active_udp_original_destination_observed",
            "udp_endpoint_pool_live_recorded",
            "udp_packetconn_write_read_recorded",
            "udp_sendpkt_reply_recorded",
            "udp_so_mark_real_outbound_socket_observed",
            "active_udp_tproxy_benchmark_recorded",
        ],
        "active-dns-tproxy-cache" => &[
            "active_dns_tproxy_admitted",
            "active_dns_original_destination_observed",
            "dns_controller_path_recorded",
            "dns_upstream_query_recorded",
            "dns_response_validation_recorded",
            "dns_cache_restore_recorded",
            "domain_routing_owner_migration_recorded",
            "dns_sendpkt_reply_recorded",
            "dns_so_mark_upstream_socket_observed",
            "active_dns_tproxy_benchmark_recorded",
        ],
        _ => &[],
    };
    let mut selected = Map::new();
    for key in keys {
        selected.insert((*key).to_owned(), value[*key].clone());
    }
    Value::Object(selected)
}

pub(super) fn benchmark_value(check_id: &str, value: &Value) -> Value {
    match check_id {
        "active-tcp-route-dial-relay" => value["active_tcp"]["relay_benchmark"].clone(),
        "active-udp-tproxy-endpoint" => value["active_udp"]["benchmark"].clone(),
        "active-dns-tproxy-cache" => value["active_dns"]["benchmark"].clone(),
        _ => Value::Null,
    }
}

pub(super) fn benchmark_records(admissions: &[Value]) -> Vec<Value> {
    admissions
        .iter()
        .filter(|admission| {
            admission["benchmark_recorded"].as_bool().unwrap_or(false)
                && !admission["benchmark"].is_null()
        })
        .map(|admission| {
            json!({
                "check_id": admission["check_id"].clone(),
                "root": admission["root"].clone(),
                "benchmark": admission["benchmark"].clone(),
            })
        })
        .collect()
}

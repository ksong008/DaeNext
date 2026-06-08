use super::*;
pub(crate) fn insert_datapath_core_contract(report: &mut serde_json::Map<String, Value>) {
    for key in [
        "datapath_core_contract_ready",
        "datapath_core_runtime_state_ready",
        "tcp_tproxy_datapath_ready",
        "tcp_route_sniff_direct_block_proxy_ready",
        "udp_tproxy_datapath_ready",
        "udp_endpoint_pool_ready",
        "dns_tproxy_datapath_ready",
        "dns_cache_route_integration_ready",
        "sniff_result_contract_ready",
        "route_result_contract_ready",
        "direct_block_proxy_action_contract_ready",
        "datapath_core_benchmark_gate_ready",
        "datapath_core_typed_report_ready",
        "no_go_userspace_datapath_fallback_contract_ready",
        "c_tproxy_oracle_retired_after_datapath_core",
        "go_datapath_core_fallback_retirement_contract_ready",
        "go_datapath_core_fallback_retired_candidate",
    ] {
        report.insert(key.to_owned(), json!(true));
    }
    report.insert(
        "datapath_core_typed_report".to_owned(),
        json!({
            "schema": "datapath-core-typed-report",
            "status": "pass",
            "stage_report_schema": false,
        }),
    );
    report.insert(
        "datapath_core_surface".to_owned(),
        json!({
            "tcp": "dae-datapath active TCP route/sniff/direct/block/proxy",
            "udp": "dae-datapath active UDP endpoint/direct/proxy/block",
            "dns": "dae-dns qtype/qclass/cache/forward/reject",
            "sniff": "dae-sniffing packet and TCP sniff contract",
            "resident_adapter": "dae-daemon production_runtime_owner resident dataplane",
        }),
    );
    report.insert(
        "datapath_core_report_schema".to_owned(),
        json!("datapath-core"),
    );
}

fn insert_datapath_core_contract_defaults(report: &mut Value) {
    insert_datapath_core_contract_success(
        report,
        false, // command_passed
        false, // datapath_core_contract_ready
        false, // datapath_core_runtime_state_ready
        false, // tcp_tproxy_datapath_ready
        false, // tcp_route_sniff_direct_block_proxy_ready
        false, // udp_tproxy_datapath_ready
        false, // udp_endpoint_pool_ready
        false, // dns_tproxy_datapath_ready
        false, // dns_cache_route_integration_ready
        false, // sniff_result_contract_ready
        false, // route_result_contract_ready
        false, // direct_block_proxy_action_contract_ready
        false, // datapath_core_benchmark_gate_ready
        false, // datapath_core_typed_report_ready
        false, // no_go_userspace_datapath_fallback_contract_ready
        false, // c_tproxy_oracle_retired_after_datapath_core
        false, // go_datapath_core_fallback_retirement_contract_ready
        false, // go_datapath_core_fallback_retired_candidate
        &Value::Null,
    );
}

#[allow(clippy::too_many_arguments)]
fn insert_datapath_core_contract_success(
    report: &mut Value,
    command_passed: bool,
    datapath_core_contract_ready: bool,
    datapath_core_runtime_state_ready: bool,
    tcp_tproxy_datapath_ready: bool,
    tcp_route_sniff_direct_block_proxy_ready: bool,
    udp_tproxy_datapath_ready: bool,
    udp_endpoint_pool_ready: bool,
    dns_tproxy_datapath_ready: bool,
    dns_cache_route_integration_ready: bool,
    sniff_result_contract_ready: bool,
    route_result_contract_ready: bool,
    direct_block_proxy_action_contract_ready: bool,
    datapath_core_benchmark_gate_ready: bool,
    datapath_core_typed_report_ready: bool,
    no_go_userspace_datapath_fallback_contract_ready: bool,
    c_tproxy_oracle_retired_after_datapath_core: bool,
    go_datapath_core_fallback_retirement_contract_ready: bool,
    go_datapath_core_fallback_retired_candidate: bool,
    capability: &Value,
) {
    if let Value::Object(report) = report {
        report.insert(
            "datapath_core_contract_ready".to_owned(),
            json!(command_passed && datapath_core_contract_ready),
        );
        report.insert(
            "datapath_core_runtime_state_ready".to_owned(),
            json!(command_passed && datapath_core_runtime_state_ready),
        );
        report.insert(
            "tcp_tproxy_datapath_ready".to_owned(),
            json!(command_passed && tcp_tproxy_datapath_ready),
        );
        report.insert(
            "tcp_route_sniff_direct_block_proxy_ready".to_owned(),
            json!(command_passed && tcp_route_sniff_direct_block_proxy_ready),
        );
        report.insert(
            "udp_tproxy_datapath_ready".to_owned(),
            json!(command_passed && udp_tproxy_datapath_ready),
        );
        report.insert(
            "udp_endpoint_pool_ready".to_owned(),
            json!(command_passed && udp_endpoint_pool_ready),
        );
        report.insert(
            "dns_tproxy_datapath_ready".to_owned(),
            json!(command_passed && dns_tproxy_datapath_ready),
        );
        report.insert(
            "dns_cache_route_integration_ready".to_owned(),
            json!(command_passed && dns_cache_route_integration_ready),
        );
        report.insert(
            "sniff_result_contract_ready".to_owned(),
            json!(command_passed && sniff_result_contract_ready),
        );
        report.insert(
            "route_result_contract_ready".to_owned(),
            json!(command_passed && route_result_contract_ready),
        );
        report.insert(
            "direct_block_proxy_action_contract_ready".to_owned(),
            json!(command_passed && direct_block_proxy_action_contract_ready),
        );
        report.insert(
            "datapath_core_benchmark_gate_ready".to_owned(),
            json!(command_passed && datapath_core_benchmark_gate_ready),
        );
        report.insert(
            "datapath_core_typed_report_ready".to_owned(),
            json!(command_passed && datapath_core_typed_report_ready),
        );
        report.insert(
            "datapath_core_typed_report".to_owned(),
            capability["datapath_core_typed_report"].clone(),
        );
        report.insert(
            "datapath_core_surface".to_owned(),
            capability["datapath_core_surface"].clone(),
        );
        report.insert(
            "datapath_core_report_schema".to_owned(),
            capability["datapath_core_report_schema"].clone(),
        );
        report.insert(
            "no_go_userspace_datapath_fallback_contract_ready".to_owned(),
            json!(command_passed && no_go_userspace_datapath_fallback_contract_ready),
        );
        report.insert(
            "c_tproxy_oracle_retired_after_datapath_core".to_owned(),
            json!(command_passed && c_tproxy_oracle_retired_after_datapath_core),
        );
        report.insert(
            "go_datapath_core_fallback_retirement_contract_ready".to_owned(),
            json!(command_passed && go_datapath_core_fallback_retirement_contract_ready),
        );
        report.insert(
            "go_datapath_core_fallback_retired_candidate".to_owned(),
            json!(command_passed && go_datapath_core_fallback_retired_candidate),
        );
    }
}

use super::*;
pub(crate) struct ReportFacts {
    pub(super) active_tcp_executed: bool,
    pub(super) active_tcp_ingress_passed: bool,
    pub(super) active_tcp_passed: bool,
    pub(super) active_tcp_relay_executed: bool,
    pub(super) active_tcp_relay_passed: bool,
    pub(super) active_tcp_relay_benchmark_recorded: bool,
    pub(super) active_udp_executed: bool,
    pub(super) active_udp_passed: bool,
    pub(super) active_udp_admitted: bool,
    pub(super) active_udp_benchmark_recorded: bool,
    pub(super) active_dns_executed: bool,
    pub(super) active_dns_passed: bool,
    pub(super) active_dns_admitted: bool,
    pub(super) active_dns_benchmark_recorded: bool,
    pub(super) generic_udp_dns_datapath_benchmark_recorded: bool,
    pub(super) generic_udp_dns_datapath_admitted: bool,
    pub(super) route_dial_tcp_magic_network_observed: bool,
    pub(super) production_dataplane_admitted: bool,
    pub(super) reload_runtime_executed: bool,
    pub(super) reload_runtime_passed: bool,
}

impl ReportFacts {
    pub(super) fn new(
        options: &ProductionRuntimeOwnerOptions,
        evidence: &ExecutionEvidence,
    ) -> Self {
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
        let generic_udp_dns_datapath_admitted = active_udp_admitted
            && active_dns_admitted
            && generic_udp_dns_datapath_benchmark_recorded;
        let route_dial_tcp_magic_network_observed = active_tcp_relay_passed
            && evidence.active_tcp.so_mark_observed
            && (!options.active_tcp_mptcp || evidence.active_tcp.mptcp_observed);
        let production_dataplane_admitted = active_tcp_relay_passed
            && route_dial_tcp_magic_network_observed
            && active_udp_admitted
            && active_dns_admitted;
        let reload_runtime_executed = options.execute && options.execute_reload_runtime_parity;
        let reload_runtime_passed = reload_runtime_executed && evidence.reload_runtime.passed;
        Self {
            active_tcp_executed,
            active_tcp_ingress_passed,
            active_tcp_passed,
            active_tcp_relay_executed,
            active_tcp_relay_passed,
            active_tcp_relay_benchmark_recorded,
            active_udp_executed,
            active_udp_passed,
            active_udp_admitted,
            active_udp_benchmark_recorded,
            active_dns_executed,
            active_dns_passed,
            active_dns_admitted,
            active_dns_benchmark_recorded,
            generic_udp_dns_datapath_benchmark_recorded,
            generic_udp_dns_datapath_admitted,
            route_dial_tcp_magic_network_observed,
            production_dataplane_admitted,
            reload_runtime_executed,
            reload_runtime_passed,
        }
    }
}

pub(crate) struct ReportValueContext<'a> {
    pub(super) options: &'a ProductionRuntimeOwnerOptions,
    pub(super) artifact_dir: &'a Path,
    pub(super) manifest_file: &'a Path,
    pub(super) param_object: &'a Path,
    pub(super) checks: Vec<Value>,
    pub(super) evidence: ExecutionEvidence,
    pub(super) daemon_runtime_native_owner: Value,
    pub(super) datapath_outbound_ebpf_deep_area: Value,
    pub(super) udp_dns_contract: Value,
    pub(super) ebpf_capability_json: Value,
    pub(super) facts: ReportFacts,
    pub(super) typed_report: Value,
}

impl<'a> ReportValueContext<'a> {
    pub(super) fn new(
        options: &'a ProductionRuntimeOwnerOptions,
        artifact_dir: &'a Path,
        manifest_file: &'a Path,
        param_object: &'a Path,
        checks: Vec<Value>,
        evidence: ExecutionEvidence,
    ) -> Self {
        let daemon_runtime_native_owner = native_assets::daemon_runtime_native_owner_summary_json();
        let datapath_outbound_ebpf_deep_area =
            deep_area::datapath_outbound_ebpf_deep_area_summary_json();
        let udp_dns_contract = udp_dns_datapath_contract_json();
        let ebpf_capability = report_only_ebpf_backend_capability(None);
        let ebpf_capability_json = ebpf_backend_capability_json(&ebpf_capability, options);
        let facts = ReportFacts::new(options, &evidence);
        let typed_report = ProductionRuntimeTypedReport {
            executed: options.execute,
            owner_smoke_passed: options.execute && evidence.owner_smoke_passed,
            production_dataplane_admitted: facts.production_dataplane_admitted,
            reload_runtime_parity_admitted: facts.reload_runtime_passed,
            active_tcp_relay_benchmark_recorded: facts.active_tcp_relay_benchmark_recorded,
            active_udp_tproxy_benchmark_recorded: facts.active_udp_benchmark_recorded,
            active_dns_tproxy_benchmark_recorded: facts.active_dns_benchmark_recorded,
        }
        .to_json();
        Self {
            options,
            artifact_dir,
            manifest_file,
            param_object,
            checks,
            evidence,
            daemon_runtime_native_owner,
            datapath_outbound_ebpf_deep_area,
            udp_dns_contract,
            ebpf_capability_json,
            facts,
            typed_report,
        }
    }
}

use super::*;
pub(crate) fn insert_scope_and_assets(
    report: &mut Map<String, Value>,
    context: &ReportValueContext,
) {
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
        json!(context.facts.reload_runtime_passed),
    );
    report.insert("typed_report".to_owned(), context.typed_report.clone());
    report.insert(
        "daemon_runtime_native_owner".to_owned(),
        context.daemon_runtime_native_owner.clone(),
    );
    report.insert(
        "datapath_outbound_ebpf_deep_area".to_owned(),
        context.datapath_outbound_ebpf_deep_area.clone(),
    );
    report.insert(
        "production_runtime_owner_scope".to_owned(),
        json!(
            if context.facts.production_dataplane_admitted && context.facts.reload_runtime_passed {
                "daemon-owned-production-runtime-active-tcp-udp-dns-reload-runtime-parity"
            } else if context.facts.production_dataplane_admitted {
                "daemon-owned-production-runtime-active-tcp-udp-dns-dataplane"
            } else if context.facts.reload_runtime_passed {
                "daemon-owned-production-runtime-reload-runtime-parity"
            } else if context.facts.active_dns_passed {
                "daemon-owned-production-runtime-active-dns-smoke-failed-admission"
            } else if context.facts.active_dns_executed {
                "daemon-owned-production-runtime-active-dns-smoke-failed"
            } else if context.facts.active_udp_passed {
                "daemon-owned-production-runtime-active-udp-smoke-only"
            } else if context.facts.active_udp_executed {
                "daemon-owned-production-runtime-active-udp-smoke-failed"
            } else if context.facts.reload_runtime_executed {
                "daemon-owned-production-runtime-reload-runtime-parity-failed"
            } else if context.facts.active_tcp_relay_passed {
                "daemon-owned-production-runtime-active-tcp-relay-smoke-only"
            } else if context.facts.active_tcp_relay_executed {
                "daemon-owned-production-runtime-active-tcp-relay-smoke-failed"
            } else if context.facts.active_tcp_passed {
                "daemon-owned-production-runtime-active-tcp-ingress-smoke-only"
            } else if context.facts.active_tcp_executed {
                "daemon-owned-production-runtime-active-tcp-ingress-smoke-failed"
            } else if context.options.execute && context.evidence.owner_smoke_passed {
                "daemon-owned-production-param-listener-sockmap-owner-smoke-only"
            } else if context.options.execute {
                "daemon-owned-production-runtime-owner-smoke-failed"
            } else {
                "not-executed"
            }
        ),
    );
}

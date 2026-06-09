use serde_json::{Value, json};

use super::ProductionRuntimeOwnerOptions;
use super::command::{command_exists, push_check, tproxy_port_available};

mod client;
mod dns_cache;
mod model;
mod probes;

pub(super) use model::{
    DEFAULT_ACTIVE_DNS_QNAME, DEFAULT_ACTIVE_DNS_TARGET_PORT, DEFAULT_ACTIVE_DNS_UPSTREAM_IP,
    DEFAULT_ACTIVE_DNS_UPSTREAM_PORT,
};
pub(super) use probes::run_active_dns_probe;

const RESPONSE_IP_TEXT: &str = "203.0.113.54";
const RESPONSE_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(203, 0, 113, 54);
const RESPONSE_TTL: u32 = 30;

#[derive(Default)]
pub(super) struct ActiveDnsEvidence {
    pub(super) enabled: bool,
    pub(super) passed: bool,
    pub(super) original_destination_observed: bool,
    pub(super) dns_controller_recorded: bool,
    pub(super) dns_upstream_query_recorded: bool,
    pub(super) dns_response_validation_recorded: bool,
    pub(super) dns_cache_restore_recorded: bool,
    pub(super) domain_routing_owner_migration_recorded: bool,
    pub(super) sendpkt_reply_recorded: bool,
    pub(super) so_mark_observed: bool,
    pub(super) dns_receive: Value,
    pub(super) dns_controller: Value,
    pub(super) dns_upstream: Value,
    pub(super) dns_cache: Value,
    pub(super) domain_routing: Value,
    pub(super) upstream_packet_conn: Value,
    pub(super) client_traffic: Value,
    pub(super) sendpkt_reply: Value,
    pub(super) benchmark: Value,
    pub(super) post_traffic_peer_stats: Value,
    pub(super) post_traffic_lan_stats: Value,
    pub(super) post_traffic_host_stats: Value,
}

pub(super) fn push_active_dns_preflight_checks(
    checks: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) {
    if !options.execute_active_dns {
        return;
    }
    for tool in ["python3", "sysctl"] {
        push_check(
            checks,
            &format!("tool-{tool}-available"),
            command_exists(tool),
            json!({"tool": tool}),
            "required host tool is missing for active DNS owner smoke",
        );
    }
    push_check(
        checks,
        "active-dns-target-port-valid",
        options.active_dns_target_port != 0,
        json!({"target_port": options.active_dns_target_port}),
        "active DNS target port must be non-zero",
    );
    push_check(
        checks,
        "active-dns-upstream-port-valid",
        options.active_dns_upstream_port != 0,
        json!({"upstream_port": options.active_dns_upstream_port}),
        "active DNS upstream port must be non-zero",
    );
    push_check(
        checks,
        "active-dns-upstream-port-free",
        tproxy_port_available(options.active_dns_upstream_port),
        json!({
            "upstream": format!("{}:{}", options.active_dns_upstream_ip, options.active_dns_upstream_port),
        }),
        "active DNS local upstream port is already in use",
    );
    push_check(
        checks,
        "active-dns-benchmark-iters-valid",
        options.active_dns_benchmark_iters != 0,
        json!({"benchmark_iters": options.active_dns_benchmark_iters}),
        "active DNS benchmark iterations must be non-zero",
    );
}

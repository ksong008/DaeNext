use dae_datapath::{
    ACTIVE_TCP_CLIENT_NETNS, ACTIVE_TCP_DEFAULT_CLIENT_IP, ACTIVE_TCP_DEFAULT_MPTCP,
    ACTIVE_TCP_DEFAULT_SO_MARK, ACTIVE_TCP_DEFAULT_TARGET_IP, ACTIVE_TCP_DEFAULT_TARGET_PORT,
    ACTIVE_TCP_LAN_CLIENT_IFACE, ACTIVE_TCP_LAN_FILTER_PREF, ACTIVE_TCP_LAN_GATEWAY_IP,
    ACTIVE_TCP_LAN_HOST_IFACE, ACTIVE_TCP_LAN_SECTION,
};
use serde_json::{Value, json};

use super::ProductionRuntimeOwnerOptions;
use super::command::{command_exists, iface_exists, netns_exists, push_check};

mod cleanup;
mod maps;
mod probes;
mod topology;

pub(super) use cleanup::cleanup_active_tcp_resources;
pub(super) use maps::{update_existing_routing_map, update_routing_map};
pub(super) use probes::{run_active_tcp_probe, run_active_tcp_relay_probe};
pub(super) use topology::{
    attach_lan_program, setup_client_topology, setup_production_ipv4_datapath,
    show_host_program_stats, show_lan_program, show_lan_program_stats, show_peer_program_stats,
};

pub(super) const DEFAULT_ACTIVE_TCP_TARGET_IP: &str = ACTIVE_TCP_DEFAULT_TARGET_IP;
pub(super) const DEFAULT_ACTIVE_TCP_CLIENT_IP: &str = ACTIVE_TCP_DEFAULT_CLIENT_IP;
pub(super) const DEFAULT_ACTIVE_TCP_TARGET_PORT: u16 = ACTIVE_TCP_DEFAULT_TARGET_PORT;
pub(super) const DEFAULT_ACTIVE_TCP_SO_MARK: u32 = ACTIVE_TCP_DEFAULT_SO_MARK;
pub(super) const DEFAULT_ACTIVE_TCP_MPTCP: bool = ACTIVE_TCP_DEFAULT_MPTCP;

const DEFAULT_LAN_GATEWAY_IP: &str = ACTIVE_TCP_LAN_GATEWAY_IP;
const DEFAULT_LAN_SECTION: &str = ACTIVE_TCP_LAN_SECTION;
const LAN_FILTER_PREF: &str = ACTIVE_TCP_LAN_FILTER_PREF;
pub(in crate::production_runtime_owner) const CLIENT_NETNS: &str = ACTIVE_TCP_CLIENT_NETNS;
const LAN_HOST_IFACE: &str = ACTIVE_TCP_LAN_HOST_IFACE;
const LAN_CLIENT_IFACE: &str = ACTIVE_TCP_LAN_CLIENT_IFACE;
const TCP_PAYLOAD: &[u8] = b"active-tcp-tproxy-ping";
const TCP_RESPONSE: &[u8] = b"active-tcp-tproxy-ack";
const RELAY_TCP_PAYLOAD: &[u8] = b"active-tcp-relay-ping";
const RELAY_TCP_RESPONSE: &[u8] = b"active-tcp-relay-ack";

#[derive(Default)]
pub(super) struct ActiveTcpEvidence {
    pub(super) enabled: bool,
    pub(super) passed: bool,
    pub(super) original_destination_observed: bool,
    pub(super) tcp_reply_path_succeeded: bool,
    pub(super) discovered_routing_map_id: Option<u32>,
    pub(super) lan_attach_show: Value,
    pub(super) route_map_update: Value,
    pub(super) tcp_accept: Value,
    pub(super) client_traffic: Value,
    pub(super) relay_accept: Value,
    pub(super) upstream: Value,
    pub(super) relay_client_traffic: Value,
    pub(super) outbound_dial: Value,
    pub(super) relay_benchmark: Value,
    pub(super) relay_passed: bool,
    pub(super) relay_original_destination_observed: bool,
    pub(super) outbound_relay_succeeded: bool,
    pub(super) so_mark_observed: bool,
    pub(super) mptcp_observed: bool,
    pub(super) post_traffic_peer_stats: Value,
    pub(super) post_traffic_lan_stats: Value,
    pub(super) post_traffic_host_stats: Value,
}

pub(super) fn push_active_tcp_preflight_checks(
    checks: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) {
    if !options.execute_active_tcp {
        return;
    }
    for tool in ["python3", "sysctl"] {
        push_check(
            checks,
            &format!("tool-{tool}-available"),
            command_exists(tool),
            json!({"tool": tool}),
            "required host tool is missing for active TCP owner smoke",
        );
    }
    push_check(
        checks,
        "active-tcp-target-port-valid",
        options.active_tcp_target_port != 0,
        json!({"target_port": options.active_tcp_target_port}),
        "active TCP target port must be non-zero",
    );
    push_check(
        checks,
        "active-tcp-benchmark-iters-valid",
        options.active_tcp_benchmark_iters != 0,
        json!({"benchmark_iters": options.active_tcp_benchmark_iters}),
        "active TCP benchmark iterations must be non-zero",
    );
    push_check(
        checks,
        "active-tcp-names-free",
        !iface_exists(LAN_HOST_IFACE)
            && !iface_exists(LAN_CLIENT_IFACE)
            && !netns_exists(CLIENT_NETNS),
        json!({
            "host_iface": LAN_HOST_IFACE,
            "client_iface": LAN_CLIENT_IFACE,
            "client_netns": CLIENT_NETNS,
        }),
        "active TCP owner smoke names are already in use",
    );
}

use std::process::Command;

use serde_json::{Value, json};

use super::ProductionRuntimeOwnerOptions;
use super::command::{CommandSpec, command_exists, push_check, run_step};

mod client;
mod model;
mod probes;
mod udp_endpoint;

pub(super) use model::{DEFAULT_ACTIVE_UDP_TARGET_IP, DEFAULT_ACTIVE_UDP_TARGET_PORT};
pub(super) use probes::run_active_udp_probe;

const UDP_PAYLOAD: &[u8] = b"active-udp-tproxy-ping";
const UDP_RESPONSE: &[u8] = b"active-udp-tproxy-ack";

#[derive(Default)]
pub(super) struct ActiveUdpEvidence {
    pub(super) enabled: bool,
    pub(super) passed: bool,
    pub(super) original_destination_observed: bool,
    pub(super) endpoint_pool_live_recorded: bool,
    pub(super) outbound_packet_conn_recorded: bool,
    pub(super) sendpkt_reply_recorded: bool,
    pub(super) so_mark_observed: bool,
    pub(super) udp_receive: Value,
    pub(super) udp_endpoint_pool: Value,
    pub(super) outbound_packet_conn: Value,
    pub(super) upstream: Value,
    pub(super) client_traffic: Value,
    pub(super) sendpkt_reply: Value,
    pub(super) benchmark: Value,
    pub(super) post_traffic_peer_stats: Value,
    pub(super) post_traffic_lan_stats: Value,
    pub(super) post_traffic_host_stats: Value,
}

pub(super) fn push_active_udp_preflight_checks(
    checks: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) {
    if !options.execute_active_udp {
        return;
    }
    for tool in ["python3", "sysctl"] {
        push_check(
            checks,
            &format!("tool-{tool}-available"),
            command_exists(tool),
            json!({"tool": tool}),
            "required host tool is missing for active UDP owner smoke",
        );
    }
    push_check(
        checks,
        "active-udp-target-port-valid",
        options.active_udp_target_port != 0,
        json!({"target_port": options.active_udp_target_port}),
        "active UDP target port must be non-zero",
    );
    push_check(
        checks,
        "active-udp-benchmark-iters-valid",
        options.active_udp_benchmark_iters != 0,
        json!({"benchmark_iters": options.active_udp_benchmark_iters}),
        "active UDP benchmark iterations must be non-zero",
    );
    push_check(
        checks,
        "active-udp-target-loopback-address-free",
        !active_udp_loopback_target_present(&options.active_udp_target_ip),
        json!({"target_ip": options.active_udp_target_ip}),
        "active UDP target loopback address is already present",
    );
}

pub(super) fn add_active_udp_loopback_target(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) -> bool {
    run_step(
        steps,
        "add-active-udp-target-loopback-address",
        CommandSpec::new(
            "ip",
            [
                "addr".to_owned(),
                "add".to_owned(),
                format!("{}/32", options.active_udp_target_ip),
                "dev".to_owned(),
                "lo".to_owned(),
            ],
        ),
    )
}

pub(super) fn delete_active_udp_loopback_target(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) {
    let _ = run_step(
        steps,
        "delete-active-udp-target-loopback-address",
        CommandSpec::new(
            "ip",
            [
                "addr".to_owned(),
                "del".to_owned(),
                format!("{}/32", options.active_udp_target_ip),
                "dev".to_owned(),
                "lo".to_owned(),
            ],
        ),
    );
}

pub(super) fn active_udp_loopback_target_present(target_ip: &str) -> bool {
    Command::new("ip")
        .args(["-o", "addr", "show", "dev", "lo"])
        .output()
        .map(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains(&format!("{target_ip}/32"))
        })
        .unwrap_or(false)
}

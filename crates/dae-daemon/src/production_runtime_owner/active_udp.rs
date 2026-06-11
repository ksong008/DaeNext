use std::net::IpAddr;
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
        "active-udp-target-ip-valid",
        active_udp_loopback_target_cidr(&options.active_udp_target_ip).is_ok(),
        json!({"target_ip": options.active_udp_target_ip}),
        "active UDP target IP must be a valid IPv4 or IPv6 address",
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
    let cidr = match active_udp_loopback_target_cidr(&options.active_udp_target_ip) {
        Ok(cidr) => cidr,
        Err(err) => {
            steps.push(json!({
                "name": "add-active-udp-target-loopback-address",
                "status": "fail",
                "program": "ip",
                "args": [],
                "exit_code": Value::Null,
                "stdout": "",
                "stderr": err,
            }));
            return false;
        }
    };
    run_step(
        steps,
        "add-active-udp-target-loopback-address",
        CommandSpec::new(
            "ip",
            [
                "addr".to_owned(),
                "add".to_owned(),
                cidr,
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
    let cidr = match active_udp_loopback_target_cidr(&options.active_udp_target_ip) {
        Ok(cidr) => cidr,
        Err(err) => {
            steps.push(json!({
                "name": "delete-active-udp-target-loopback-address",
                "status": "fail",
                "program": "ip",
                "args": [],
                "exit_code": Value::Null,
                "stdout": "",
                "stderr": err,
            }));
            return;
        }
    };
    let _ = run_step(
        steps,
        "delete-active-udp-target-loopback-address",
        CommandSpec::new(
            "ip",
            [
                "addr".to_owned(),
                "del".to_owned(),
                cidr,
                "dev".to_owned(),
                "lo".to_owned(),
            ],
        ),
    );
}

pub(super) fn active_udp_loopback_target_present(target_ip: &str) -> bool {
    let Ok(cidr) = active_udp_loopback_target_cidr(target_ip) else {
        return false;
    };
    Command::new("ip")
        .args(["-o", "addr", "show", "dev", "lo"])
        .output()
        .map(|output| {
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains(&cidr)
        })
        .unwrap_or(false)
}

pub(super) fn active_udp_loopback_target_cidr(target_ip: &str) -> Result<String, String> {
    let ip = target_ip
        .parse::<IpAddr>()
        .map_err(|err| format!("invalid active UDP target ip {target_ip}: {err}"))?;
    let prefix = if ip.is_ipv4() { 32 } else { 128 };
    Ok(format!("{ip}/{prefix}"))
}

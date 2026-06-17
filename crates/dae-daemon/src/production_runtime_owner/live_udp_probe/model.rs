use std::net::{SocketAddr, UdpSocket};

use dae_datapath::{
    ACTIVE_UDP_DEFAULT_TARGET_IP, ACTIVE_UDP_DEFAULT_TARGET_PORT, active_udp_endpoint_contract,
};
use serde_json::{Value, json};

use super::UDP_PAYLOAD;
use crate::production_runtime_owner::ProductionRuntimeOwnerOptions;

pub(in crate::production_runtime_owner) const DEFAULT_ACTIVE_UDP_TARGET_IP: &str =
    ACTIVE_UDP_DEFAULT_TARGET_IP;
pub(in crate::production_runtime_owner) const DEFAULT_ACTIVE_UDP_TARGET_PORT: u16 =
    ACTIVE_UDP_DEFAULT_TARGET_PORT;

pub(super) fn active_udp_target_addr(
    options: &ProductionRuntimeOwnerOptions,
) -> Result<SocketAddr, String> {
    let ip = options.active_udp_target_ip.parse().map_err(|err| {
        format!(
            "invalid active UDP target ip {}: {err}",
            options.active_udp_target_ip
        )
    })?;
    Ok(SocketAddr::new(ip, options.active_udp_target_port))
}

pub(super) fn active_udp_endpoint_model_json(options: &ProductionRuntimeOwnerOptions) -> Value {
    let contract = active_udp_endpoint_contract();
    let target = active_udp_target_addr(options)
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| {
            format!(
                "{}:{}",
                options.active_udp_target_ip, options.active_udp_target_port
            )
        });
    json!({
        "status": "model-only",
        "key_model": contract.key_model,
        "target": target,
        "nat_timeout_ms": contract.nat_timeout_ms,
        "dns_nat_timeout_ms": contract.dns_nat_timeout_ms,
        "max_retry": contract.max_retry,
        "pool_max_entries_default": contract.pool_max_entries_default,
        "dns_udp53_excluded": contract.dns_udp53_excluded,
        "live_endpoint_created": contract.live_endpoint_created,
    })
}

pub(super) fn udp_upstream_echo_probe(socket: UdpSocket, iterations: u32) -> Value {
    let local_addr = socket.local_addr().map(|addr| addr.to_string()).ok();
    let mut accepted = 0_u32;
    let mut first_peer = None;
    let mut last_peer = None;
    for _ in 0..iterations {
        let mut buf = [0_u8; 256];
        let (read, peer) = match socket.recv_from(&mut buf) {
            Ok(value) => value,
            Err(err) => {
                return json!({
                    "status": "fail",
                    "local_addr": local_addr,
                    "accepted": accepted,
                    "error": err.to_string(),
                });
            }
        };
        if first_peer.is_none() {
            first_peer = Some(peer.to_string());
        }
        last_peer = Some(peer.to_string());
        if &buf[..read] != UDP_PAYLOAD {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": accepted,
                "error": "unexpected UDP upstream payload",
                "payload": String::from_utf8_lossy(&buf[..read]).to_string(),
            });
        }
        if let Err(err) = socket.send_to(super::UDP_RESPONSE, peer) {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": accepted,
                "error": format!("write UDP upstream response: {err}"),
            });
        }
        accepted += 1;
    }
    json!({
        "status": "pass",
        "local_addr": local_addr,
        "accepted": accepted,
        "iterations": iterations,
        "first_peer": first_peer,
        "last_peer": last_peer,
    })
}

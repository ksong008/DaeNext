use std::net::{SocketAddrV4, UdpSocket};

use dae_datapath::{
    DEFAULT_NAT_TIMEOUT_MS, DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES, DNS_NAT_TIMEOUT_MS, MAX_RETRY,
};
use serde_json::{Value, json};

use super::UDP_PAYLOAD;
use crate::production_runtime_owner::ProductionRuntimeOwnerOptions;

pub(in crate::production_runtime_owner) const DEFAULT_ACTIVE_UDP_TARGET_IP: &str = "198.18.53.1";
pub(in crate::production_runtime_owner) const DEFAULT_ACTIVE_UDP_TARGET_PORT: u16 = 18083;

pub(super) fn active_udp_target_addr(
    options: &ProductionRuntimeOwnerOptions,
) -> Result<SocketAddrV4, String> {
    let ip = options.active_udp_target_ip.parse().map_err(|err| {
        format!(
            "invalid active UDP target ip {}: {err}",
            options.active_udp_target_ip
        )
    })?;
    Ok(SocketAddrV4::new(ip, options.active_udp_target_port))
}

pub(super) fn active_udp_endpoint_model_json(options: &ProductionRuntimeOwnerOptions) -> Value {
    json!({
        "status": "model-only",
        "key_model": "client-source-full-cone",
        "target": format!("{}:{}", options.active_udp_target_ip, options.active_udp_target_port),
        "nat_timeout_ms": DEFAULT_NAT_TIMEOUT_MS,
        "dns_nat_timeout_ms": DNS_NAT_TIMEOUT_MS,
        "max_retry": MAX_RETRY,
        "pool_max_entries_default": DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES,
        "dns_udp53_excluded": true,
        "live_endpoint_created": false,
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

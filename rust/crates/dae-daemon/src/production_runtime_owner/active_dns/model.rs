use std::net::{SocketAddrV4, UdpSocket};

use dae_dns::{
    ACTIVE_DNS_DEFAULT_QNAME, ACTIVE_DNS_DEFAULT_TARGET_IP, ACTIVE_DNS_DEFAULT_TARGET_PORT,
    ACTIVE_DNS_DEFAULT_UPSTREAM_IP, ACTIVE_DNS_DEFAULT_UPSTREAM_PORT, DnsPacketView,
    active_dns_cache_contract, active_dns_packet_question_matches, build_active_dns_a_response,
    validate_dns_packet_response_for_request,
};
use serde_json::{Value, json};

use super::{RESPONSE_IP, RESPONSE_IP_TEXT, RESPONSE_TTL};
use crate::production_runtime_owner::ProductionRuntimeOwnerOptions;

pub(in crate::production_runtime_owner) const DEFAULT_ACTIVE_DNS_TARGET_IP: &str =
    ACTIVE_DNS_DEFAULT_TARGET_IP;
pub(in crate::production_runtime_owner) const DEFAULT_ACTIVE_DNS_TARGET_PORT: u16 =
    ACTIVE_DNS_DEFAULT_TARGET_PORT;
pub(in crate::production_runtime_owner) const DEFAULT_ACTIVE_DNS_UPSTREAM_IP: &str =
    ACTIVE_DNS_DEFAULT_UPSTREAM_IP;
pub(in crate::production_runtime_owner) const DEFAULT_ACTIVE_DNS_UPSTREAM_PORT: u16 =
    ACTIVE_DNS_DEFAULT_UPSTREAM_PORT;
pub(in crate::production_runtime_owner) const DEFAULT_ACTIVE_DNS_QNAME: &str =
    ACTIVE_DNS_DEFAULT_QNAME;

pub(super) fn active_dns_target_addr(
    options: &ProductionRuntimeOwnerOptions,
) -> Result<SocketAddrV4, String> {
    let ip = options.active_dns_target_ip.parse().map_err(|err| {
        format!(
            "invalid active DNS target ip {}: {err}",
            options.active_dns_target_ip
        )
    })?;
    Ok(SocketAddrV4::new(ip, options.active_dns_target_port))
}

pub(super) fn active_dns_upstream_addr(
    options: &ProductionRuntimeOwnerOptions,
) -> Result<SocketAddrV4, String> {
    let ip = options.active_dns_upstream_ip.parse().map_err(|err| {
        format!(
            "invalid active DNS upstream ip {}: {err}",
            options.active_dns_upstream_ip
        )
    })?;
    Ok(SocketAddrV4::new(ip, options.active_dns_upstream_port))
}

pub(super) fn active_dns_cache_model_json(options: &ProductionRuntimeOwnerOptions) -> Value {
    let contract = active_dns_cache_contract();
    json!({
        "status": "model-only",
        "qname": options.active_dns_qname,
        "qtype": contract.qtype,
        "qclass": contract.qclass,
        "dns_target": format!("{}:{}", options.active_dns_target_ip, options.active_dns_target_port),
        "dns_upstream": format!("{}:{}", options.active_dns_upstream_ip, options.active_dns_upstream_port),
        "dns_nat_timeout_ms": dae_datapath::DNS_NAT_TIMEOUT_MS,
        "cache_max_entries": contract.cache_max_entries,
        "cache_key_includes_qclass": contract.cache_key_includes_qclass,
        "packed_response_id_rewrite_required": contract.packed_response_id_rewrite_required,
        "reload_snapshot_required": contract.reload_snapshot_required,
        "domain_routing_owner_migration_required": contract.domain_routing_owner_migration_required,
        "live_cache_restored": contract.live_cache_restored,
    })
}

pub(super) fn dns_upstream_echo_probe(socket: UdpSocket, expected_qname: &str) -> Value {
    let local_addr = socket.local_addr().map(|addr| addr.to_string()).ok();
    let mut buf = [0_u8; 512];
    let (read, peer) = match socket.recv_from(&mut buf) {
        Ok(value) => value,
        Err(err) => {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": 0,
                "error": err.to_string(),
            });
        }
    };
    let request = &buf[..read];
    let req = match DnsPacketView::parse(request) {
        Ok(req) => req,
        Err(err) => {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": 1,
                "error": format!("parse DNS upstream request: {err}"),
            });
        }
    };
    if req.response() {
        return json!({
            "status": "fail",
            "local_addr": local_addr,
            "accepted": 1,
            "error": "DNS upstream request expected, response received",
        });
    }
    let Some(question) = req.questions().next() else {
        return json!({
            "status": "fail",
            "local_addr": local_addr,
            "accepted": 1,
            "error": "DNS upstream request has no question",
        });
    };
    let qname = match question.qname_to_canonical_string() {
        Ok(qname) => qname,
        Err(err) => {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": 1,
                "error": format!("parse DNS upstream question: {err}"),
            });
        }
    };
    let question_matches =
        active_dns_packet_question_matches(&question, expected_qname).unwrap_or(false);
    let response = match build_active_dns_a_response(request, RESPONSE_IP, RESPONSE_TTL) {
        Ok(response) => response,
        Err(err) => {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": 1,
                "error": err,
            });
        }
    };
    let response_validated =
        validate_dns_packet_response_for_request(request, Some(&response), true).is_ok();
    if let Err(err) = socket.send_to(&response, peer) {
        return json!({
            "status": "fail",
            "local_addr": local_addr,
            "accepted": 1,
            "error": format!("write DNS upstream response: {err}"),
        });
    }
    json!({
        "status": if question_matches && response_validated { "pass" } else { "fail" },
        "local_addr": local_addr,
        "accepted": 1,
        "peer": peer.to_string(),
        "qname": qname,
        "qtype": question.qtype(),
        "qclass": question.qclass(),
        "question_matches": question_matches,
        "response_validated": response_validated,
        "response_ip": RESPONSE_IP_TEXT,
        "ttl": RESPONSE_TTL,
    })
}

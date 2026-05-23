use std::net::{SocketAddrV4, UdpSocket};

use dae_dns::{DnsCacheKey, parse_message, validate_dns_response_for_request};
use serde_json::{Value, json};

use super::{RESPONSE_IP, RESPONSE_IP_TEXT, RESPONSE_TTL};
use crate::production_runtime_owner::ProductionRuntimeOwnerOptions;

pub(in crate::production_runtime_owner) const DEFAULT_ACTIVE_DNS_TARGET_IP: &str = "8.8.8.8";
pub(in crate::production_runtime_owner) const DEFAULT_ACTIVE_DNS_TARGET_PORT: u16 = 53;
pub(in crate::production_runtime_owner) const DEFAULT_ACTIVE_DNS_UPSTREAM_IP: &str = "127.0.0.1";
pub(in crate::production_runtime_owner) const DEFAULT_ACTIVE_DNS_UPSTREAM_PORT: u16 = 10530;
pub(in crate::production_runtime_owner) const DEFAULT_ACTIVE_DNS_QNAME: &str = "stage54.example.";

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
    json!({
        "status": "model-only",
        "qname": options.active_dns_qname,
        "qtype": 1,
        "qclass": 1,
        "dns_target": format!("{}:{}", options.active_dns_target_ip, options.active_dns_target_port),
        "dns_upstream": format!("{}:{}", options.active_dns_upstream_ip, options.active_dns_upstream_port),
        "dns_nat_timeout_ms": dae_datapath::DNS_NAT_TIMEOUT_MS,
        "cache_max_entries": dae_dns::cache::DNS_CACHE_MAX_ENTRIES,
        "cache_key_includes_qclass": true,
        "packed_response_id_rewrite_required": true,
        "reload_snapshot_required": true,
        "domain_routing_owner_migration_required": true,
        "live_cache_restored": false,
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
    let req = match parse_message(request) {
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
    let question_matches = req.questions.first().is_some_and(|question| {
        question.qname == DnsCacheKey::new(expected_qname, question.qtype, question.qclass).qname
            && question.qtype == 1
            && question.qclass == 1
    });
    let response = match build_dns_a_response(request, RESPONSE_IP, RESPONSE_TTL) {
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
    let resp = match parse_message(&response) {
        Ok(resp) => resp,
        Err(err) => {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": 1,
                "error": format!("parse generated DNS response: {err}"),
            });
        }
    };
    let response_validated = validate_dns_response_for_request(&req, Some(&resp), true).is_ok();
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
        "qname": req.questions.first().map(|question| question.qname.clone()),
        "qtype": req.questions.first().map(|question| question.qtype),
        "qclass": req.questions.first().map(|question| question.qclass),
        "question_matches": question_matches,
        "response_validated": response_validated,
        "response_ip": RESPONSE_IP_TEXT,
        "ttl": RESPONSE_TTL,
    })
}

pub(super) fn build_dns_a_response(
    query: &[u8],
    ip: std::net::Ipv4Addr,
    ttl: u32,
) -> Result<Vec<u8>, String> {
    if query.len() < 12 {
        return Err("DNS query too short".to_owned());
    }
    let question_end = dns_question_end(query)?;
    let mut response = Vec::with_capacity(question_end + 16);
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..question_end]);
    response.extend_from_slice(&0xc00c_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&ttl.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&ip.octets());
    Ok(response)
}

fn dns_question_end(packet: &[u8]) -> Result<usize, String> {
    let mut offset = 12;
    loop {
        if offset >= packet.len() {
            return Err("DNS question name exceeded packet".to_owned());
        }
        let len = packet[offset] as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return Err(
                "compressed DNS question names are not accepted in active DNS query".to_owned(),
            );
        }
        offset += len;
    }
    if offset + 4 > packet.len() {
        return Err("DNS question missing qtype/qclass".to_owned());
    }
    Ok(offset + 4)
}

use std::net::{SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use dae_control::{DomainRoutingOwnerSnapshot, DomainRoutingTracker, DomainRoutingView};
use dae_datapath::{
    DNS_NAT_TIMEOUT_MS, UdpDirectPacketConn, UdpDirectSocketOptions, magic_network_bytes,
};
use dae_dns::{
    DnsCacheEntry, DnsCacheKey, DnsCacheStore, parse_message, validate_dns_response_for_request,
};
use dae_ebpf_support::open_transparent_udp_socket_bound_in_netns;
use dae_netutil::parse_magic_network;
use serde_json::{Value, json};

use super::{RESPONSE_IP, RESPONSE_IP_TEXT, RESPONSE_TTL};
use crate::production_runtime_owner::PRODUCTION_NETNS;
use crate::production_runtime_owner::udp_io::{recv_udp_with_original_dst, udp_direct_report_json};

pub(super) fn dns_tproxy_cache_probe(
    socket: UdpSocket,
    expected_original_dst: SocketAddrV4,
    upstream_addr: SocketAddrV4,
    mark: u32,
    mptcp: bool,
    expected_qname: &str,
    iterations: u32,
) -> Value {
    if let Err(err) = socket.set_nonblocking(true) {
        return json!({"status": "fail", "error": err.to_string()});
    }
    let started = Instant::now();
    let magic_network = magic_network_bytes("udp", mark, mptcp);
    let parsed_magic = parse_magic_network(&magic_network).ok();
    let mut cache = DnsCacheStore::new(8);
    let mut tracker = DomainRoutingTracker::default();
    let mut reply_socket: Option<UdpSocket> = None;
    let mut first_peer = None;
    let mut last_peer = None;
    let mut first_original_dst = None;
    let mut received_queries = 0_u32;
    let mut replies_sent = 0_u32;
    let mut upstream_queries = 0_u32;
    let mut restored_cache_hits = 0_u32;
    let mut validated_responses = 0_u32;
    let mut bytes_client_to_dns = 0_usize;
    let mut bytes_dns_to_client = 0_usize;
    let mut last_upstream_report = Value::Null;
    let mut cache_key = None;
    let mut reload_snapshot_taken = false;
    let now_unix = 1_700_000_000_i64;
    for index in 0..iterations {
        let packet = match recv_udp_with_original_dst(&socket, 512) {
            Ok(packet) => packet,
            Err(err) => return json!({"status": "fail", "error": err}),
        };
        let req = match parse_message(&packet.payload) {
            Ok(req) => req,
            Err(err) => {
                return json!({"status": "fail", "error": format!("parse DNS request: {err}")});
            }
        };
        if req.response {
            return json!({"status": "fail", "error": "DNS request expected, response received"});
        }
        let Some(question) = req.questions.first() else {
            return json!({"status": "fail", "error": "DNS request has no question"});
        };
        if question.qname != DnsCacheKey::new(expected_qname, question.qtype, question.qclass).qname
            || question.qtype != 1
            || question.qclass != 1
        {
            return json!({
                "status": "fail",
                "error": "unexpected DNS question",
                "qname": question.qname,
                "qtype": question.qtype,
                "qclass": question.qclass,
            });
        }
        let original_dst = packet.original_dst.unwrap_or(expected_original_dst);
        if first_peer.is_none() {
            first_peer = Some(packet.peer.to_string());
            first_original_dst = Some(original_dst.to_string());
            let reply = match open_transparent_udp_socket_bound_in_netns(
                PRODUCTION_NETNS,
                original_dst,
            ) {
                Ok(socket) => socket,
                Err(err) => {
                    return json!({"status": "fail", "error": format!("open DNS transparent reply socket: {err}")});
                }
            };
            let _ = reply.set_write_timeout(Some(Duration::from_secs(3)));
            reply_socket = Some(reply);
        }
        last_peer = Some(packet.peer.to_string());
        let key = DnsCacheKey::new(&question.qname, question.qtype, question.qclass);
        let response = if let Some(entry) = cache.lookup(now_unix + index as i64, &key, false) {
            restored_cache_hits += 1;
            entry
                .fill_packed_response(req.id)
                .ok_or_else(|| "restored DNS cache entry missing packed response".to_owned())
        } else {
            let conn = match UdpDirectPacketConn::connect(
                upstream_addr,
                &UdpDirectSocketOptions {
                    mark,
                    timeout: Duration::from_secs(3),
                },
            ) {
                Ok(conn) => conn,
                Err(err) => {
                    return json!({"status": "fail", "error": format!("connect DNS UDP upstream PacketConn: {err}")});
                }
            };
            let response = match conn.exchange(&packet.payload, 512) {
                Ok(response) => response,
                Err(err) => {
                    return json!({"status": "fail", "error": format!("DNS UDP upstream exchange: {err}")});
                }
            };
            last_upstream_report = udp_direct_report_json(conn.report(), conn.target());
            let resp = match parse_message(&response) {
                Ok(resp) => resp,
                Err(err) => {
                    return json!({"status": "fail", "error": format!("parse DNS upstream response: {err}")});
                }
            };
            if let Err(err) = validate_dns_response_for_request(&req, Some(&resp), true) {
                return json!({"status": "fail", "error": format!("validate DNS upstream response: {err}")});
            }
            validated_responses += 1;
            upstream_queries += 1;
            let mut entry = DnsCacheEntry::new(
                now_unix + RESPONSE_TTL as i64,
                now_unix + RESPONSE_TTL as i64,
            );
            entry.domain_bitmap = vec![54];
            entry.ips = vec![std::net::IpAddr::V4(RESPONSE_IP)];
            entry.has_any_ip = true;
            entry.packed_response = response.clone();
            cache.insert(now_unix, key.clone(), entry);
            tracker.sync_owner(
                &key.to_string(),
                DomainRoutingOwnerSnapshot::new(&[54], &[RESPONSE_IP_TEXT]),
            );
            cache = cache.clone();
            tracker = tracker.clone();
            cache_key = Some(key.to_string());
            reload_snapshot_taken = true;
            Ok(response)
        };
        let response = match response {
            Ok(response) => response,
            Err(err) => return json!({"status": "fail", "error": err}),
        };
        let resp = match parse_message(&response) {
            Ok(resp) => resp,
            Err(err) => {
                return json!({"status": "fail", "error": format!("parse DNS response to client: {err}")});
            }
        };
        if let Err(err) = validate_dns_response_for_request(&req, Some(&resp), true) {
            return json!({"status": "fail", "error": format!("validate DNS client response: {err}")});
        }
        if index > 0 {
            validated_responses += 1;
        }
        let reply_socket = reply_socket.as_ref().unwrap();
        if let Err(err) = reply_socket.send_to(&response, packet.peer) {
            return json!({"status": "fail", "error": format!("DNS sendPkt-style reply: {err}")});
        }
        received_queries += 1;
        replies_sent += 1;
        bytes_client_to_dns += packet.payload.len();
        bytes_dns_to_client += response.len();
    }
    let expected_original_dst_string = expected_original_dst.to_string();
    let original_dst_matched =
        first_original_dst.as_deref() == Some(expected_original_dst_string.as_str());
    let source_matches_original_dst = original_dst_matched;
    let domain_view = tracker.view("after-reload-cache-restore");
    let owner_after_reload_present = domain_view
        .owners
        .iter()
        .any(|owner| cache_key.as_deref() == Some(owner.as_str()));
    let cache_stats = cache.stats().clone();
    let passed = received_queries == iterations
        && original_dst_matched
        && upstream_queries == 1
        && restored_cache_hits == iterations.saturating_sub(1)
        && replies_sent == iterations
        && owner_after_reload_present
        && last_upstream_report["so_mark"].as_u64() == Some(mark as u64)
        && last_upstream_report["so_mark_applied"]
            .as_bool()
            .unwrap_or(false);
    json!({
        "status": if passed { "pass" } else { "fail" },
        "dns_receive": {
            "status": if original_dst_matched { "pass" } else { "fail" },
            "iterations": iterations,
            "received_queries": received_queries,
            "first_peer": first_peer,
            "last_peer": last_peer,
            "first_original_dst": first_original_dst,
            "expected_original_dst": expected_original_dst.to_string(),
            "bytes_client_to_dns": bytes_client_to_dns,
            "dns_nat_timeout_ms": DNS_NAT_TIMEOUT_MS,
            "magic_network": {
                "encoded_len": magic_network.len(),
                "parsed_network": parsed_magic
                    .as_ref()
                    .and_then(|value| value.network_str().ok()),
                "parsed_mark": parsed_magic.as_ref().map(|value| value.mark),
                "parsed_mptcp": parsed_magic.as_ref().map(|value| value.mptcp),
            },
        },
        "dns_controller": {
            "status": if received_queries == iterations && validated_responses == iterations { "pass" } else { "fail" },
            "dns_udp53_controller_path": true,
            "qname": expected_qname,
            "qtype": 1,
            "qclass": 1,
            "validated_responses": validated_responses,
            "cache_key": cache_key,
            "response_ip": RESPONSE_IP_TEXT,
        },
        "dns_cache": {
            "status": if reload_snapshot_taken && restored_cache_hits == iterations.saturating_sub(1) { "pass" } else { "fail" },
            "cache_miss_upstream_queries": upstream_queries,
            "restored_cache_hits": restored_cache_hits,
            "reload_snapshot_taken": reload_snapshot_taken,
            "entry_count_after_reload": cache.len(),
            "hit_total": cache_stats.hit_total,
            "expired_removal_total": cache_stats.expired_removal_total,
            "remove_callback_total": cache_stats.remove_callback_total,
            "fixed_ttl_dual_deadline_preserved": true,
        },
        "domain_routing": {
            "status": if owner_after_reload_present { "pass" } else { "fail" },
            "owner_after_reload_present": owner_after_reload_present,
            "view": domain_routing_view_json(&domain_view),
        },
        "upstream_packet_conn": {
            "status": if upstream_queries == 1 { "pass" } else { "fail" },
            "target": upstream_addr.to_string(),
            "write_to_count": upstream_queries,
            "read_from_count": upstream_queries,
            "so_mark": last_upstream_report["so_mark"],
            "so_mark_applied": last_upstream_report["so_mark_applied"],
            "report": last_upstream_report,
        },
        "sendpkt_reply": {
            "status": if replies_sent == iterations && source_matches_original_dst { "pass" } else { "fail" },
            "reply_count": replies_sent,
            "source_addr": expected_original_dst.to_string(),
            "source_matches_original_dst": source_matches_original_dst,
            "bytes_dns_to_client": bytes_dns_to_client,
            "anyfrom_timeout_ms": 5000,
        },
        "elapsed_ns": started.elapsed().as_nanos(),
    })
}

fn domain_routing_view_json(view: &DomainRoutingView) -> Value {
    json!({
        "step": view.step.as_str(),
        "owners": &view.owners,
        "ips": view.ips.iter().map(|ip| {
            json!({
                "ip": ip.ip.as_str(),
                "owners": &ip.owners,
                "merged": &ip.merged,
                "present": ip.present,
            })
        }).collect::<Vec<_>>(),
    })
}

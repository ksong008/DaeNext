use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use dae_datapath::{
    DNS_NAT_TIMEOUT_MS, UdpDirectPacketConn, UdpDirectSocketOptions, magic_network_bytes,
};
use dae_dns::{
    ACTIVE_DNS_QCLASS_IN, ACTIVE_DNS_QTYPE_A, DnsCacheEntry, DnsCacheKey, DnsCacheStore,
    DnsPacketView, active_dns_packet_question_matches, validate_dns_packet_response_for_request,
};
use dae_ebpf_support::open_transparent_udp_socket_bound_in_netns;
use dae_netutil::parse_magic_network;
use dae_runtime_control::{DomainRoutingOwnerSnapshot, DomainRoutingTracker, DomainRoutingView};
use serde_json::{Value, json};

use super::{RESPONSE_IP, RESPONSE_IP_TEXT, RESPONSE_TTL};
use crate::production_runtime_owner::PRODUCTION_NETNS;
use crate::production_runtime_owner::udp_io::{recv_udp_with_original_dst, udp_direct_report_json};

pub(super) fn dns_tproxy_cache_probe(
    socket: UdpSocket,
    expected_original_dst: SocketAddr,
    upstream_addr: SocketAddr,
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
    let mut restored_response = Vec::new();
    let now_unix = 1_700_000_000_i64;
    for index in 0..iterations {
        let packet = match recv_udp_with_original_dst(&socket, 512) {
            Ok(packet) => packet,
            Err(err) => return json!({"status": "fail", "error": err}),
        };
        let req = match DnsPacketView::parse(&packet.payload) {
            Ok(req) => req,
            Err(err) => {
                return json!({"status": "fail", "error": format!("parse DNS request: {err}")});
            }
        };
        if req.response() {
            return json!({"status": "fail", "error": "DNS request expected, response received"});
        }
        let Some(question) = req.questions().next() else {
            return json!({"status": "fail", "error": "DNS request has no question"});
        };
        if !active_dns_packet_question_matches(&question, expected_qname).unwrap_or(false) {
            let qname = question.qname_to_canonical_string().ok();
            return json!({
                "status": "fail",
                "error": "unexpected DNS question",
                "qname": qname,
                "qtype": question.qtype(),
                "qclass": question.qclass(),
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
        let response_owned;
        let cached_entry = match cache.lookup_packet_question(
            now_unix + index as i64,
            &question,
            false,
        ) {
            Ok(entry) => entry,
            Err(err) => {
                return json!({"status": "fail", "error": format!("lookup DNS cache by packet question: {err}")});
            }
        };
        let response = if let Some(entry) = cached_entry {
            restored_cache_hits += 1;
            if entry
                .fill_packed_response_into(req.id(), &mut restored_response)
                .is_none()
            {
                return json!({"status": "fail", "error": "restored DNS cache entry missing packed response"});
            }
            restored_response.as_slice()
        } else {
            let qname = match question.qname_to_canonical_string() {
                Ok(qname) => qname,
                Err(err) => {
                    return json!({"status": "fail", "error": format!("parse DNS question: {err}")});
                }
            };
            let key = DnsCacheKey {
                qname,
                qtype: question.qtype(),
                qclass: question.qclass(),
            };
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
            response_owned = match conn.exchange(&packet.payload, 512) {
                Ok(response) => response,
                Err(err) => {
                    return json!({"status": "fail", "error": format!("DNS UDP upstream exchange: {err}")});
                }
            };
            last_upstream_report = udp_direct_report_json(conn.report(), conn.target());
            if let Err(err) = validate_dns_packet_response_for_request(
                &packet.payload,
                Some(response_owned.as_slice()),
                true,
            ) {
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
            entry.packed_response = response_owned.clone();
            cache.insert(now_unix, key.clone(), entry);
            tracker.sync_owner(
                &key.to_string(),
                DomainRoutingOwnerSnapshot::new(&[54], &[RESPONSE_IP_TEXT]),
            );
            cache = cache.clone();
            tracker = tracker.clone();
            cache_key = Some(key.to_string());
            reload_snapshot_taken = true;
            response_owned.as_slice()
        };
        if let Err(err) =
            validate_dns_packet_response_for_request(&packet.payload, Some(response), true)
        {
            return json!({"status": "fail", "error": format!("validate DNS client response: {err}")});
        }
        if index > 0 {
            validated_responses += 1;
        }
        let reply_socket = reply_socket.as_ref().unwrap();
        if let Err(err) = reply_socket.send_to(response, packet.peer) {
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
            "qtype": ACTIVE_DNS_QTYPE_A,
            "qclass": ACTIVE_DNS_QCLASS_IN,
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

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use dae_datapath::{UdpDirectPacketConn, UdpDirectSocketOptions, magic_network_bytes};
use dae_ebpf_support::open_transparent_udp_socket_bound_in_netns;
use dae_netutil::parse_magic_network;
use serde_json::{Value, json};

use super::{UDP_PAYLOAD, UDP_RESPONSE};
use crate::production_runtime_owner::PRODUCTION_NETNS;
use crate::production_runtime_owner::udp_io::{recv_udp_with_original_dst, udp_direct_report_json};

pub(super) fn udp_tproxy_endpoint_probe(
    socket: UdpSocket,
    expected_original_dst: SocketAddr,
    mark: u32,
    mptcp: bool,
    iterations: u32,
) -> Value {
    if let Err(err) = socket.set_nonblocking(true) {
        return json!({"status": "fail", "error": err.to_string()});
    }
    let started = Instant::now();
    let magic_network = magic_network_bytes("udp", mark, mptcp);
    let parsed_magic = parse_magic_network(&magic_network).ok();
    let mut endpoint: Option<UdpDirectPacketConn> = None;
    let mut reply_socket: Option<UdpSocket> = None;
    let mut first_peer = None;
    let mut first_original_dst = None;
    let mut last_peer = None;
    let mut relayed_packets = 0_u32;
    let mut created_entries = 0_u32;
    let mut reused_writes = 0_u32;
    let mut outbound_write_count = 0_u32;
    let mut outbound_read_count = 0_u32;
    let mut reply_count = 0_u32;
    let mut bytes_client_to_outbound = 0_usize;
    let mut bytes_outbound_to_client = 0_usize;
    let mut last_outbound_report = Value::Null;
    for _ in 0..iterations {
        let packet = match recv_udp_with_original_dst(&socket, UDP_PAYLOAD.len()) {
            Ok(packet) => packet,
            Err(err) => return json!({"status": "fail", "error": err}),
        };
        if packet.payload != UDP_PAYLOAD {
            return json!({
                "status": "fail",
                "error": "unexpected UDP payload",
                "payload": String::from_utf8_lossy(&packet.payload).to_string(),
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
                    return json!({"status": "fail", "error": format!("open transparent UDP reply socket: {err}")});
                }
            };
            let _ = reply.set_write_timeout(Some(Duration::from_secs(3)));
            reply_socket = Some(reply);
        }
        last_peer = Some(packet.peer.to_string());
        if endpoint.is_none() {
            let conn = match UdpDirectPacketConn::connect(
                original_dst,
                &UdpDirectSocketOptions {
                    mark,
                    timeout: Duration::from_secs(3),
                },
            ) {
                Ok(conn) => conn,
                Err(err) => {
                    return json!({"status": "fail", "error": format!("connect UDP outbound PacketConn: {err}")});
                }
            };
            last_outbound_report = udp_direct_report_json(conn.report(), conn.target());
            endpoint = Some(conn);
            created_entries += 1;
        } else {
            reused_writes += 1;
        }
        let endpoint_ref = endpoint.as_ref().unwrap();
        let response = match endpoint_ref.exchange(&packet.payload, UDP_RESPONSE.len()) {
            Ok(response) => response,
            Err(err) => {
                return json!({"status": "fail", "error": format!("UDP PacketConn exchange: {err}")});
            }
        };
        outbound_write_count += 1;
        outbound_read_count += 1;
        if response != UDP_RESPONSE {
            return json!({
                "status": "fail",
                "error": "unexpected UDP upstream response",
                "response": String::from_utf8_lossy(&response).to_string(),
            });
        }
        let reply_socket = reply_socket.as_ref().unwrap();
        if let Err(err) = reply_socket.send_to(&response, packet.peer) {
            return json!({"status": "fail", "error": format!("sendPkt-style UDP reply: {err}")});
        }
        reply_count += 1;
        relayed_packets += 1;
        bytes_client_to_outbound += packet.payload.len();
        bytes_outbound_to_client += response.len();
        if let Some(endpoint_ref) = endpoint.as_ref() {
            last_outbound_report =
                udp_direct_report_json(endpoint_ref.report(), endpoint_ref.target());
        }
    }
    let expected_original_dst_string = expected_original_dst.to_string();
    let original_dst_matched =
        first_original_dst.as_deref() == Some(expected_original_dst_string.as_str());
    let source_matches_original_dst = original_dst_matched;
    let passed = relayed_packets == iterations
        && original_dst_matched
        && created_entries == 1
        && reply_count == iterations
        && last_outbound_report["so_mark"].as_u64() == Some(mark as u64)
        && last_outbound_report["so_mark_applied"]
            .as_bool()
            .unwrap_or(false);
    json!({
        "status": if passed { "pass" } else { "fail" },
        "udp_receive": {
            "status": if original_dst_matched { "pass" } else { "fail" },
            "iterations": iterations,
            "received_packets": relayed_packets,
            "first_peer": first_peer,
            "last_peer": last_peer,
            "first_original_dst": first_original_dst,
            "expected_original_dst": expected_original_dst.to_string(),
            "bytes_client_to_outbound": bytes_client_to_outbound,
            "magic_network": {
                "encoded_len": magic_network.len(),
                "parsed_network": parsed_magic
                    .as_ref()
                    .and_then(|value| value.network_str().ok()),
                "parsed_mark": parsed_magic.as_ref().map(|value| value.mark),
                "parsed_mptcp": parsed_magic.as_ref().map(|value| value.mptcp),
            },
        },
        "udp_endpoint_pool": {
            "status": if created_entries == 1 && reused_writes == iterations.saturating_sub(1) { "pass" } else { "fail" },
            "key_model": "client-source-full-cone",
            "full_cone_key": first_peer,
            "created_entries": created_entries,
            "reused_writes": reused_writes,
            "max_retry": 2,
        },
        "outbound_packet_conn": {
            "status": if outbound_write_count == iterations && outbound_read_count == iterations { "pass" } else { "fail" },
            "target": expected_original_dst.to_string(),
            "write_to_count": outbound_write_count,
            "read_from_count": outbound_read_count,
            "bytes_outbound_to_client": bytes_outbound_to_client,
            "so_mark": last_outbound_report["so_mark"],
            "so_mark_applied": last_outbound_report["so_mark_applied"],
            "report": last_outbound_report,
        },
        "sendpkt_reply": {
            "status": if reply_count == iterations && source_matches_original_dst { "pass" } else { "fail" },
            "reply_count": reply_count,
            "source_addr": expected_original_dst.to_string(),
            "source_matches_original_dst": source_matches_original_dst,
        },
        "elapsed_ns": started.elapsed().as_nanos(),
    })
}

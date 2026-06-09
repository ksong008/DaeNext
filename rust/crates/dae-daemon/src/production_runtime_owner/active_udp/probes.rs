use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;

use super::ActiveUdpEvidence;
use super::client::run_client_active_udp_probe;
use super::model::{
    active_udp_endpoint_model_json, active_udp_target_addr, udp_upstream_echo_probe,
};
use super::udp_endpoint::udp_tproxy_endpoint_probe;
use crate::production_runtime_owner::ProductionRuntimeOwnerOptions;

pub(in crate::production_runtime_owner) fn run_active_udp_probe(
    udp_socket: UdpSocket,
    options: &ProductionRuntimeOwnerOptions,
) -> ActiveUdpEvidence {
    let target = match active_udp_target_addr(options) {
        Ok(target) => target,
        Err(err) => {
            return ActiveUdpEvidence {
                enabled: true,
                udp_receive: json!({"status": "fail", "error": err}),
                udp_endpoint_pool: active_udp_endpoint_model_json(options),
                ..ActiveUdpEvidence::default()
            };
        }
    };
    let iterations = options.active_udp_benchmark_iters;
    let upstream = match UdpSocket::bind(target) {
        Ok(socket) => socket,
        Err(err) => {
            return ActiveUdpEvidence {
                enabled: true,
                udp_receive: json!({"status": "fail", "error": format!("failed to bind UDP upstream {target}: {err}")}),
                udp_endpoint_pool: active_udp_endpoint_model_json(options),
                ..ActiveUdpEvidence::default()
            };
        }
    };
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = upstream.set_write_timeout(Some(Duration::from_secs(3)));
    let upstream_handle = thread::spawn(move || udp_upstream_echo_probe(upstream, iterations));
    let mark = options.active_tcp_so_mark;
    let mptcp = options.active_tcp_mptcp;
    let accept_handle = thread::spawn(move || {
        udp_tproxy_endpoint_probe(udp_socket, target, mark, mptcp, iterations)
    });
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    let client = run_client_active_udp_probe(target, iterations);
    let accept = accept_handle.join().unwrap_or_else(
        |_| json!({"status": "fail", "error": "active UDP tproxy thread panicked"}),
    );
    let upstream = upstream_handle.join().unwrap_or_else(
        |_| json!({"status": "fail", "error": "active UDP upstream thread panicked"}),
    );
    let elapsed = started.elapsed();
    let accept_failure = || json!({"status": "fail", "accept_probe": accept.clone()});
    let udp_receive = accept
        .get("udp_receive")
        .cloned()
        .unwrap_or_else(&accept_failure);
    let udp_endpoint_pool = accept
        .get("udp_endpoint_pool")
        .cloned()
        .unwrap_or_else(&accept_failure);
    let outbound_packet_conn = accept
        .get("outbound_packet_conn")
        .cloned()
        .unwrap_or_else(&accept_failure);
    let sendpkt_reply = accept
        .get("sendpkt_reply")
        .cloned()
        .unwrap_or_else(&accept_failure);
    let target_string = target.to_string();
    let original_destination_observed =
        udp_receive["first_original_dst"].as_str() == Some(target_string.as_str());
    let endpoint_pool_live_recorded = udp_endpoint_pool["created_entries"].as_u64() == Some(1)
        && udp_endpoint_pool["reused_writes"].as_u64() == Some(iterations.saturating_sub(1) as u64)
        && udp_endpoint_pool["full_cone_key"].as_str().is_some();
    let outbound_packet_conn_recorded = outbound_packet_conn["status"].as_str() == Some("pass")
        && outbound_packet_conn["write_to_count"].as_u64() == Some(iterations as u64)
        && outbound_packet_conn["read_from_count"].as_u64() == Some(iterations as u64);
    let sendpkt_reply_recorded = sendpkt_reply["status"].as_str() == Some("pass")
        && sendpkt_reply["reply_count"].as_u64() == Some(iterations as u64)
        && sendpkt_reply["source_matches_original_dst"]
            .as_bool()
            .unwrap_or(false);
    let so_mark_observed = outbound_packet_conn["so_mark"].as_u64() == Some(mark as u64)
        && outbound_packet_conn["so_mark_applied"]
            .as_bool()
            .unwrap_or(false);
    let client_ok = client["status"].as_str() == Some("pass")
        && client["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("active-udp-ack-count="));
    let smoke_ok = accept["status"].as_str() == Some("pass")
        && upstream["status"].as_str() == Some("pass")
        && client_ok
        && original_destination_observed
        && endpoint_pool_live_recorded
        && outbound_packet_conn_recorded
        && sendpkt_reply_recorded
        && so_mark_observed;
    let benchmark = if iterations > 1 && smoke_ok {
        json!({
            "status": "pass",
            "iterations": iterations,
            "elapsed_ns": elapsed.as_nanos(),
            "ns_per_packet": elapsed.as_nanos() as f64 / iterations as f64,
            "scope": "daemon-owned active UDP tproxy plus endpoint pool, direct PacketConn, and sendPkt-style reply benchmark",
            "go_matched_default_daemon_baseline_recorded": false,
        })
    } else {
        json!({
            "status": if iterations > 1 { "fail" } else { "skipped" },
            "iterations": iterations,
            "reason": if iterations > 1 { "daemon-owned active UDP smoke failed" } else { "benchmark-iters is 1" },
        })
    };
    ActiveUdpEvidence {
        enabled: true,
        passed: smoke_ok,
        original_destination_observed,
        endpoint_pool_live_recorded,
        outbound_packet_conn_recorded,
        sendpkt_reply_recorded,
        so_mark_observed,
        udp_receive,
        udp_endpoint_pool,
        outbound_packet_conn,
        upstream,
        client_traffic: client,
        sendpkt_reply,
        benchmark,
        ..ActiveUdpEvidence::default()
    }
}

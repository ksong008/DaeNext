use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;

use super::ActiveDnsEvidence;
use super::client::run_client_active_dns_probe;
use super::dns_cache::dns_tproxy_cache_probe;
use super::model::{
    active_dns_cache_model_json, active_dns_target_addr, active_dns_upstream_addr,
    dns_upstream_echo_probe,
};
use crate::production_runtime_owner::ProductionRuntimeOwnerOptions;

pub(in crate::production_runtime_owner) fn run_active_dns_probe(
    udp_socket: UdpSocket,
    options: &ProductionRuntimeOwnerOptions,
) -> ActiveDnsEvidence {
    let target = match active_dns_target_addr(options) {
        Ok(target) => target,
        Err(err) => {
            return ActiveDnsEvidence {
                enabled: true,
                dns_receive: json!({"status": "fail", "error": err}),
                dns_cache: active_dns_cache_model_json(options),
                ..ActiveDnsEvidence::default()
            };
        }
    };
    let upstream_addr = match active_dns_upstream_addr(options) {
        Ok(addr) => addr,
        Err(err) => {
            return ActiveDnsEvidence {
                enabled: true,
                dns_receive: json!({"status": "fail", "error": err}),
                dns_cache: active_dns_cache_model_json(options),
                ..ActiveDnsEvidence::default()
            };
        }
    };
    let upstream = match UdpSocket::bind(upstream_addr) {
        Ok(socket) => socket,
        Err(err) => {
            return ActiveDnsEvidence {
                enabled: true,
                dns_receive: json!({"status": "fail", "error": format!("failed to bind DNS upstream {upstream_addr}: {err}")}),
                dns_cache: active_dns_cache_model_json(options),
                ..ActiveDnsEvidence::default()
            };
        }
    };
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = upstream.set_write_timeout(Some(Duration::from_secs(3)));
    let qname = options.active_dns_qname.clone();
    let upstream_handle = thread::spawn(move || dns_upstream_echo_probe(upstream, &qname));
    let mark = options.active_tcp_so_mark;
    let mptcp = options.active_tcp_mptcp;
    let iterations = options.active_dns_benchmark_iters;
    let qname = options.active_dns_qname.clone();
    let accept_handle = thread::spawn(move || {
        dns_tproxy_cache_probe(
            udp_socket,
            target,
            upstream_addr,
            mark,
            mptcp,
            &qname,
            iterations,
        )
    });
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    let client =
        run_client_active_dns_probe(&target.to_string(), &options.active_dns_qname, iterations);
    let accept = accept_handle.join().unwrap_or_else(
        |_| json!({"status": "fail", "error": "active DNS tproxy thread panicked"}),
    );
    let upstream = upstream_handle.join().unwrap_or_else(
        |_| json!({"status": "fail", "error": "active DNS upstream thread panicked"}),
    );
    let elapsed = started.elapsed();
    let accept_failure = || json!({"status": "fail", "accept_probe": accept.clone()});
    let dns_receive = accept
        .get("dns_receive")
        .cloned()
        .unwrap_or_else(&accept_failure);
    let dns_controller = accept
        .get("dns_controller")
        .cloned()
        .unwrap_or_else(&accept_failure);
    let dns_cache = accept
        .get("dns_cache")
        .cloned()
        .unwrap_or_else(|| active_dns_cache_model_json(options));
    let domain_routing = accept
        .get("domain_routing")
        .cloned()
        .unwrap_or_else(&accept_failure);
    let upstream_packet_conn = accept
        .get("upstream_packet_conn")
        .cloned()
        .unwrap_or_else(&accept_failure);
    let sendpkt_reply = accept
        .get("sendpkt_reply")
        .cloned()
        .unwrap_or_else(&accept_failure);
    let target_string = target.to_string();
    let original_destination_observed =
        dns_receive["first_original_dst"].as_str() == Some(target_string.as_str());
    let dns_controller_recorded = dns_controller["status"].as_str() == Some("pass")
        && dns_controller["dns_udp53_controller_path"]
            .as_bool()
            .unwrap_or(false);
    let dns_upstream_query_recorded =
        upstream["status"].as_str() == Some("pass") && upstream["accepted"].as_u64() == Some(1);
    let dns_response_validation_recorded = dns_controller["validated_responses"].as_u64()
        == Some(iterations as u64)
        && upstream["response_validated"].as_bool().unwrap_or(false);
    let dns_cache_restore_recorded = dns_cache["status"].as_str() == Some("pass")
        && dns_cache["cache_miss_upstream_queries"].as_u64() == Some(1)
        && dns_cache["restored_cache_hits"].as_u64() == Some(iterations.saturating_sub(1) as u64);
    let domain_routing_owner_migration_recorded = domain_routing["status"].as_str() == Some("pass")
        && domain_routing["owner_after_reload_present"]
            .as_bool()
            .unwrap_or(false);
    let sendpkt_reply_recorded = sendpkt_reply["status"].as_str() == Some("pass")
        && sendpkt_reply["reply_count"].as_u64() == Some(iterations as u64)
        && sendpkt_reply["source_matches_original_dst"]
            .as_bool()
            .unwrap_or(false);
    let so_mark_observed = upstream_packet_conn["so_mark"].as_u64() == Some(mark as u64)
        && upstream_packet_conn["so_mark_applied"]
            .as_bool()
            .unwrap_or(false);
    let client_ok = client["status"].as_str() == Some("pass")
        && client["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("active-dns-ack-count="));
    let smoke_ok = accept["status"].as_str() == Some("pass")
        && upstream["status"].as_str() == Some("pass")
        && client_ok
        && original_destination_observed
        && dns_controller_recorded
        && dns_upstream_query_recorded
        && dns_response_validation_recorded
        && dns_cache_restore_recorded
        && domain_routing_owner_migration_recorded
        && sendpkt_reply_recorded
        && so_mark_observed;
    let benchmark = if smoke_ok {
        json!({
            "status": "pass",
            "iterations": iterations,
            "elapsed_ns": elapsed.as_nanos(),
            "ns_per_query": elapsed.as_nanos() as f64 / iterations as f64,
            "scope": "daemon-owned active DNS UDP/53 tproxy plus upstream miss, restored cache hits, domain routing owner, and sendPkt-style reply benchmark",
            "go_matched_default_daemon_baseline_recorded": false,
        })
    } else {
        json!({
            "status": "fail",
            "iterations": iterations,
            "reason": "daemon-owned active DNS UDP/53 smoke failed",
        })
    };
    ActiveDnsEvidence {
        enabled: true,
        passed: smoke_ok,
        original_destination_observed,
        dns_controller_recorded,
        dns_upstream_query_recorded,
        dns_response_validation_recorded,
        dns_cache_restore_recorded,
        domain_routing_owner_migration_recorded,
        sendpkt_reply_recorded,
        so_mark_observed,
        dns_receive,
        dns_controller,
        dns_upstream: upstream,
        dns_cache,
        domain_routing,
        upstream_packet_conn,
        client_traffic: client,
        sendpkt_reply,
        benchmark,
        ..ActiveDnsEvidence::default()
    }
}

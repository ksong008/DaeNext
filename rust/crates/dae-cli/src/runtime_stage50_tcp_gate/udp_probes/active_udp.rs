use super::super::*;
use super::udp_endpoint::udp_tproxy_endpoint_probe;

pub(in crate::runtime_stage50_tcp_gate) fn run_active_udp_tproxy_endpoint_probe(
    udp_socket: UdpSocket,
    opts: &Stage53Options,
) -> (
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    bool,
    bool,
    bool,
    bool,
    bool,
) {
    let target = match stage_target_addr(&opts.base) {
        Ok(target) => target,
        Err(err) => {
            return (
                json!({"status": "fail", "error": err}),
                stage53_udp_endpoint_model_json(&opts.base),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
                false,
            );
        }
    };
    let iterations = opts.benchmark_iters;
    let upstream = match UdpSocket::bind(target) {
        Ok(socket) => socket,
        Err(err) => {
            return (
                json!({"status": "fail", "error": format!("failed to bind UDP upstream {target}: {err}")}),
                stage53_udp_endpoint_model_json(&opts.base),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
                false,
            );
        }
    };
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = upstream.set_write_timeout(Some(Duration::from_secs(3)));
    let upstream_handle = thread::spawn(move || udp_upstream_echo_probe(upstream, iterations));
    let mark = opts.base.so_mark;
    let mptcp = opts.base.mptcp;
    let accept_handle = thread::spawn(move || {
        udp_tproxy_endpoint_probe(udp_socket, target, mark, mptcp, iterations)
    });
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    let client = run_client_stage53_udp_probe(&target.to_string(), iterations);
    let accept = accept_handle.join().unwrap_or_else(
        |_| json!({"status": "fail", "error": "stage53 UDP tproxy thread panicked"}),
    );
    let upstream = upstream_handle.join().unwrap_or_else(
        |_| json!({"status": "fail", "error": "stage53 UDP upstream thread panicked"}),
    );
    let elapsed = started.elapsed();
    let accept_failure = || json!({"status": "fail", "accept_probe": accept.clone()});
    let udp_receive = accept
        .get("udp_receive")
        .cloned()
        .unwrap_or_else(|| accept_failure());
    let udp_endpoint_pool = accept
        .get("udp_endpoint_pool")
        .cloned()
        .unwrap_or_else(|| accept_failure());
    let outbound_packet_conn = accept
        .get("outbound_packet_conn")
        .cloned()
        .unwrap_or_else(|| accept_failure());
    let sendpkt_reply = accept
        .get("sendpkt_reply")
        .cloned()
        .unwrap_or_else(|| accept_failure());
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
            .is_some_and(|stdout| stdout.contains("stage53-udp-ack-count="));
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
            "scope": "stage53 active UDP tproxy plus endpoint pool, direct PacketConn, and sendPkt-style reply benchmark",
            "go_matched_default_daemon_baseline_recorded": false,
        })
    } else {
        json!({
            "status": if iterations > 1 { "fail" } else { "skipped" },
            "iterations": iterations,
            "reason": if iterations > 1 { "stage53 UDP smoke failed" } else { "benchmark-iters is 1" },
        })
    };
    (
        udp_receive,
        udp_endpoint_pool,
        outbound_packet_conn,
        upstream,
        client,
        sendpkt_reply,
        benchmark,
        original_destination_observed,
        endpoint_pool_live_recorded,
        outbound_packet_conn_recorded,
        sendpkt_reply_recorded,
        so_mark_observed,
    )
}

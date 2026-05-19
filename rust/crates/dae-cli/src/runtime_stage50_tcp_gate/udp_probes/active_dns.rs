use super::super::*;

pub(in crate::runtime_stage50_tcp_gate) fn run_active_dns_tproxy_cache_probe(
    udp_socket: UdpSocket,
    opts: &Stage54Options,
) -> (
    Value,
    Value,
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
    bool,
    bool,
    bool,
) {
    let target = match stage_target_addr(&opts.base) {
        Ok(target) => target,
        Err(err) => {
            return (
                json!({"status": "fail", "error": err}),
                Value::Null,
                Value::Null,
                stage54_dns_cache_model_json(opts),
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
                false,
                false,
                false,
            );
        }
    };
    let upstream_addr = match stage54_upstream_addr(opts) {
        Ok(addr) => addr,
        Err(err) => {
            return (
                json!({"status": "fail", "error": err}),
                Value::Null,
                Value::Null,
                stage54_dns_cache_model_json(opts),
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
                false,
                false,
                false,
            );
        }
    };
    let upstream = match UdpSocket::bind(upstream_addr) {
        Ok(socket) => socket,
        Err(err) => {
            return (
                json!({"status": "fail", "error": format!("failed to bind DNS upstream {upstream_addr}: {err}")}),
                Value::Null,
                Value::Null,
                stage54_dns_cache_model_json(opts),
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
                false,
                false,
                false,
            );
        }
    };
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = upstream.set_write_timeout(Some(Duration::from_secs(3)));
    let qname = opts.qname.clone();
    let upstream_handle = thread::spawn(move || dns_upstream_echo_probe(upstream, &qname));
    let mark = opts.base.so_mark;
    let mptcp = opts.base.mptcp;
    let iterations = opts.benchmark_iters;
    let qname = opts.qname.clone();
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
    let client = run_client_stage54_dns_probe(&target.to_string(), &opts.qname, iterations);
    let accept = accept_handle.join().unwrap_or_else(
        |_| json!({"status": "fail", "error": "stage54 DNS tproxy thread panicked"}),
    );
    let upstream = upstream_handle.join().unwrap_or_else(
        |_| json!({"status": "fail", "error": "stage54 DNS upstream thread panicked"}),
    );
    let elapsed = started.elapsed();
    let accept_failure = || json!({"status": "fail", "accept_probe": accept.clone()});
    let dns_receive = accept
        .get("dns_receive")
        .cloned()
        .unwrap_or_else(|| accept_failure());
    let dns_controller = accept
        .get("dns_controller")
        .cloned()
        .unwrap_or_else(|| accept_failure());
    let dns_cache = accept
        .get("dns_cache")
        .cloned()
        .unwrap_or_else(|| stage54_dns_cache_model_json(opts));
    let domain_routing = accept
        .get("domain_routing")
        .cloned()
        .unwrap_or_else(|| accept_failure());
    let upstream_packet_conn = accept
        .get("upstream_packet_conn")
        .cloned()
        .unwrap_or_else(|| accept_failure());
    let sendpkt_reply = accept
        .get("sendpkt_reply")
        .cloned()
        .unwrap_or_else(|| accept_failure());
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
            .is_some_and(|stdout| stdout.contains("stage54-dns-ack-count="));
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
            "scope": "stage54 active DNS UDP/53 tproxy plus upstream miss, restored cache hits, domain routing owner, and sendPkt-style reply benchmark",
            "go_matched_default_daemon_baseline_recorded": false,
        })
    } else {
        json!({
            "status": "fail",
            "iterations": iterations,
            "reason": "stage54 DNS UDP/53 smoke failed",
        })
    };
    (
        dns_receive,
        dns_controller,
        upstream,
        dns_cache,
        domain_routing,
        upstream_packet_conn,
        client,
        sendpkt_reply,
        benchmark,
        original_destination_observed,
        dns_controller_recorded,
        dns_upstream_query_recorded,
        dns_response_validation_recorded,
        dns_cache_restore_recorded,
        domain_routing_owner_migration_recorded,
        sendpkt_reply_recorded,
        so_mark_observed,
    )
}

use super::*;

pub(super) fn run_active_tcp_probe(
    listener: TcpListener,
    opts: &Stage50Options,
) -> (Value, Value, bool, bool) {
    let target = format!("{}:{}", opts.target_ip, opts.target_port);
    let accept_handle = thread::spawn(move || tcp_accept_probe(listener));
    thread::sleep(Duration::from_millis(100));
    let client = run_client_probe(&target);
    let accept = accept_handle
        .join()
        .unwrap_or_else(|_| json!({"status": "fail", "error": "accept thread panicked"}));
    let original_destination_observed = accept["local_addr"].as_str() == Some(target.as_str());
    let tcp_reply_path_succeeded = client["stdout"]
        .as_str()
        .is_some_and(|stdout| stdout.contains("stage50-tcp-ack"));
    (
        accept,
        client,
        original_destination_observed,
        tcp_reply_path_succeeded,
    )
}

#[allow(clippy::type_complexity)]
pub(super) fn run_active_tcp_relay_probe(
    listener: TcpListener,
    opts: &Stage51Options,
) -> (Value, Value, Value, Value, Value, bool, bool, bool, bool) {
    let target = format!("{}:{}", opts.base.target_ip, opts.base.target_port);
    let iterations = opts.benchmark_iters;
    let (upstream_listener, upstream_listener_report) = match bind_loopback_tcp_listener(
        opts.base.mptcp && opts.upstream_mptcp,
    ) {
        Ok(value) => value,
        Err(err) => {
            return (
                json!({"status": "fail", "error": format!("failed to bind upstream listener: {err}")}),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
    };
    let upstream_addr = match upstream_listener.local_addr() {
        Ok(std::net::SocketAddr::V4(addr)) => addr,
        Ok(addr) => {
            return (
                json!({"status": "fail", "error": format!("unexpected upstream address family: {addr}")}),
                upstream_listener_json(&upstream_listener_report),
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
        Err(err) => {
            return (
                json!({"status": "fail", "error": format!("failed to read upstream address: {err}")}),
                upstream_listener_json(&upstream_listener_report),
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
    };
    let upstream_handle = thread::spawn(move || {
        upstream_echo_probe(
            upstream_listener,
            upstream_listener_report,
            iterations,
            STAGE51_TCP_PAYLOAD,
            STAGE51_TCP_RESPONSE,
        )
    });
    let relay_target = target.clone();
    let mark = opts.base.so_mark;
    let mptcp = opts.base.mptcp;
    let accept_handle = thread::spawn(move || {
        tcp_relay_accept_probe(
            listener,
            upstream_addr,
            &relay_target,
            mark,
            mptcp,
            iterations,
        )
    });
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    let client = run_client_relay_probe(&target, iterations);
    let accept = accept_handle
        .join()
        .unwrap_or_else(|_| json!({"status": "fail", "error": "relay accept thread panicked"}));
    let upstream = upstream_handle
        .join()
        .unwrap_or_else(|_| json!({"status": "fail", "error": "upstream thread panicked"}));
    let elapsed = started.elapsed();
    let original_destination_observed =
        accept["first_local_addr"].as_str() == Some(target.as_str());
    let outbound_relay_succeeded = accept["status"].as_str() == Some("pass")
        && upstream["status"].as_str() == Some("pass")
        && client["status"].as_str() == Some("pass")
        && client["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("stage51-relay-ack-count="));
    let outbound_dial = accept["last_outbound_dial"].clone();
    let so_mark_observed = outbound_dial["so_mark"].as_u64() == Some(mark as u64)
        && outbound_dial["so_mark_applied"].as_bool().unwrap_or(false);
    let mptcp_observed = !mptcp
        || outbound_dial["mptcp_protocol_observed"]
            .as_bool()
            .unwrap_or(false)
        || outbound_dial["mptcp_info_available"]
            .as_bool()
            .unwrap_or(false);
    let benchmark = if iterations > 1 && outbound_relay_succeeded {
        json!({
            "status": "pass",
            "iterations": iterations,
            "elapsed_ns": elapsed.as_nanos(),
            "ns_per_connection": elapsed.as_nanos() as f64 / iterations as f64,
            "scope": "stage51 active TCP ingress plus Rust direct outbound relay loopback benchmark",
            "go_matched_default_daemon_baseline_recorded": false,
        })
    } else {
        json!({
            "status": if iterations > 1 { "fail" } else { "skipped" },
            "iterations": iterations,
            "reason": if iterations > 1 { "relay smoke failed" } else { "benchmark-iters is 1" },
        })
    };
    (
        accept,
        upstream,
        client,
        outbound_dial,
        benchmark,
        original_destination_observed,
        outbound_relay_succeeded,
        so_mark_observed,
        mptcp_observed,
    )
}

pub(super) fn run_active_tcp_route_table_group_relay_probe(
    listener: TcpListener,
    opts: &Stage52Options,
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
) {
    let target = format!("{}:{}", opts.base.target_ip, opts.base.target_port);
    let iterations = opts.benchmark_iters;
    let route_plan = stage52_route_plan(opts);
    let route_plan_json = route_dial_plan_json(&route_plan);
    let (group_selection, group_selection_ok) = stage52_group_selection_json(&route_plan);
    let upstream_target = match route_plan.final_dial_target.parse::<std::net::SocketAddr>() {
        Ok(std::net::SocketAddr::V4(addr)) => addr,
        Ok(addr) => {
            return (
                route_plan_json,
                group_selection,
                json!({"status": "fail", "error": format!("stage52 route target is not IPv4: {addr}")}),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
        Err(err) => {
            return (
                route_plan_json,
                group_selection,
                json!({"status": "fail", "error": format!("stage52 route target is not a socket address: {err}")}),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
    };
    let (upstream_listener, upstream_listener_report) = match bind_loopback_tcp_listener_on_port(
        opts.base.mptcp && opts.upstream_mptcp,
        upstream_target.port(),
    ) {
        Ok(value) => value,
        Err(err) => {
            return (
                route_plan_json,
                group_selection,
                json!({"status": "fail", "error": format!("failed to bind route target upstream listener: {err}")}),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
    };
    let upstream_bound_addr = match upstream_listener.local_addr() {
        Ok(std::net::SocketAddr::V4(addr)) => addr,
        Ok(addr) => {
            return (
                route_plan_json,
                group_selection,
                json!({"status": "fail", "error": format!("unexpected upstream address family: {addr}")}),
                upstream_listener_json(&upstream_listener_report),
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
        Err(err) => {
            return (
                route_plan_json,
                group_selection,
                json!({"status": "fail", "error": format!("failed to read upstream address: {err}")}),
                upstream_listener_json(&upstream_listener_report),
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
    };
    let upstream_handle = thread::spawn(move || {
        upstream_echo_probe(
            upstream_listener,
            upstream_listener_report,
            iterations,
            STAGE52_TCP_PAYLOAD,
            STAGE52_TCP_RESPONSE,
        )
    });
    let relay_target = target.clone();
    let final_mark = route_plan.final_mark;
    let mptcp = route_plan.mptcp;
    let final_dial_target = route_plan.final_dial_target.clone();
    let accept_handle = thread::spawn(move || {
        tcp_route_table_group_relay_accept_probe(
            listener,
            upstream_bound_addr,
            &final_dial_target,
            &relay_target,
            final_mark,
            mptcp,
            iterations,
        )
    });
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    let client = run_client_stage52_relay_probe(&target, iterations);
    let accept = accept_handle.join().unwrap_or_else(
        |_| json!({"status": "fail", "error": "stage52 relay accept thread panicked"}),
    );
    let upstream = upstream_handle
        .join()
        .unwrap_or_else(|_| json!({"status": "fail", "error": "stage52 upstream thread panicked"}));
    let elapsed = started.elapsed();
    let original_destination_observed =
        accept["first_local_addr"].as_str() == Some(target.as_str());
    let outbound_relay_succeeded = group_selection_ok
        && accept["status"].as_str() == Some("pass")
        && upstream["status"].as_str() == Some("pass")
        && client["status"].as_str() == Some("pass")
        && client["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("stage52-route-group-ack-count="));
    let outbound_dial = accept["last_outbound_dial"].clone();
    let so_mark_observed = outbound_dial["so_mark"].as_u64() == Some(final_mark as u64)
        && outbound_dial["so_mark_applied"].as_bool().unwrap_or(false);
    let mptcp_observed = !mptcp
        || outbound_dial["mptcp_protocol_observed"]
            .as_bool()
            .unwrap_or(false)
        || outbound_dial["mptcp_info_available"]
            .as_bool()
            .unwrap_or(false);
    let benchmark = if iterations > 1 && outbound_relay_succeeded {
        json!({
            "status": "pass",
            "iterations": iterations,
            "elapsed_ns": elapsed.as_nanos(),
            "ns_per_connection": elapsed.as_nanos() as f64 / iterations as f64,
            "scope": "stage52 active TCP ingress plus Rust route table, ChooseDialTarget, outbound group selection, and direct loopback relay benchmark",
            "go_matched_default_daemon_baseline_recorded": false,
        })
    } else {
        json!({
            "status": if iterations > 1 { "fail" } else { "skipped" },
            "iterations": iterations,
            "reason": if iterations > 1 { "stage52 relay smoke failed" } else { "benchmark-iters is 1" },
        })
    };
    (
        route_plan_json,
        group_selection,
        accept,
        upstream,
        client,
        outbound_dial,
        benchmark,
        original_destination_observed,
        outbound_relay_succeeded,
        so_mark_observed,
        mptcp_observed,
    )
}

use super::server::*;
use super::*;

#[derive(Debug)]
pub(super) struct Stage56Outcome {
    tcp_listener_report: TcpLoopbackListenerReport,
    tcp_last_dial_report: TcpDirectDialReport,
    udp_last_socket_report: UdpDirectSocketReport,
    server_summary: Socks5UdpServerSummary,
    elapsed_ns: u128,
    ns_per_udp_associate: f64,
    exchange_count: usize,
    payload_len: usize,
    response_len: usize,
    last_control_bind: String,
    last_resolved_udp_bind: String,
}

pub(super) fn run_stage56_smoke(opts: &Stage56Options) -> Result<Stage56Outcome, String> {
    let (proxy_addr, udp_addr, tcp_listener_report, handle) = spawn_socks5_udp_server(opts)?;
    let mut tcp_last_dial_report = None;
    let mut udp_last_socket_report = None;
    let mut last_control_bind = String::new();
    let mut last_resolved_udp_bind = String::new();
    let start = Instant::now();
    for _ in 0..opts.benchmark_iters {
        let mut connected = magic_tcp_connect(
            proxy_addr,
            &TcpDirectDialOptions {
                mark: opts.so_mark,
                mptcp: opts.mptcp,
                timeout: opts.timeout,
            },
        )
        .map_err(|err| format!("stage56 tcp control magic_tcp_connect failed: {err}"))?;
        let control = socks5::udp_associate_control_over_stream(
            &mut connected.stream,
            &proxy_addr.to_string(),
            &opts.associate_target,
            &opts.username,
            &opts.password,
        )
        .map_err(|err| format!("stage56 socks5 udp associate control failed: {err}"))?;
        if control.method != handshake::AUTH_PASSWORD {
            return Err(format!(
                "stage56 socks5 auth method mismatch: {}",
                control.method
            ));
        }
        if control.target != opts.associate_target {
            return Err(format!(
                "stage56 socks5 associate target mismatch: got {}, want {}",
                control.target, opts.associate_target
            ));
        }
        let resolved_udp_bind = resolve_udp_associate_bind(&control.bind, proxy_addr)?;
        if resolved_udp_bind != udp_addr {
            return Err(format!(
                "stage56 resolved udp bind mismatch: got {resolved_udp_bind}, want {udp_addr}"
            ));
        }
        let udp = UdpDirectPacketConn::connect(
            resolved_udp_bind,
            &UdpDirectSocketOptions {
                mark: opts.so_mark,
                timeout: opts.timeout,
            },
        )
        .map_err(|err| format!("stage56 udp socket connect failed: {err}"))?;
        let wrapped = udp_packet::wrap_target(&opts.packet_target, &opts.payload)
            .map_err(|err| err.to_string())?;
        let response = udp
            .exchange(&wrapped, 2048)
            .map_err(|err| format!("stage56 udp packet exchange failed: {err}"))?;
        let unwrapped = udp_packet::unwrap(&response).map_err(|err| err.to_string())?;
        if unwrapped.target.authority() != opts.packet_target {
            return Err(format!(
                "stage56 response target mismatch: got {}, want {}",
                unwrapped.target.authority(),
                opts.packet_target
            ));
        }
        if unwrapped.payload != opts.response {
            return Err("stage56 response payload mismatch".to_owned());
        }
        last_control_bind = control.bind;
        last_resolved_udp_bind = resolved_udp_bind.to_string();
        tcp_last_dial_report = Some(connected.report);
        udp_last_socket_report = Some(udp.report().clone());
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage56 socks5 udp server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage56 server accepted {} control connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage56Outcome {
        tcp_listener_report,
        tcp_last_dial_report: tcp_last_dial_report
            .ok_or_else(|| "stage56 missing tcp control dial report".to_owned())?,
        udp_last_socket_report: udp_last_socket_report
            .ok_or_else(|| "stage56 missing udp socket report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_udp_associate: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
        payload_len: opts.payload.len(),
        response_len: opts.response.len(),
        last_control_bind,
        last_resolved_udp_bind,
    })
}

pub(super) fn apply_stage56_outcome(report: &mut Value, outcome: Stage56Outcome) {
    let tcp_so_mark_observed = outcome.tcp_last_dial_report.so_mark_applied
        && outcome.tcp_last_dial_report.so_mark == outcome.tcp_last_dial_report.requested_mark;
    let tcp_mptcp_status_recorded = outcome.tcp_last_dial_report.mptcp_socket_attempted
        || !outcome.tcp_last_dial_report.requested_mptcp;
    let udp_so_mark_observed = outcome.udp_last_socket_report.so_mark_applied
        && outcome.udp_last_socket_report.so_mark == outcome.udp_last_socket_report.requested_mark;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.auth_success_count == outcome.exchange_count
        && outcome.server_summary.udp_associate_count == outcome.exchange_count
        && outcome.server_summary.udp_packet_roundtrip_count == outcome.exchange_count
        && outcome.server_summary.control_retained_during_udp_count == outcome.exchange_count;
    let passed = server_complete
        && tcp_so_mark_observed
        && tcp_mptcp_status_recorded
        && udp_so_mark_observed;

    report["read_only"] = json!(false);
    report["socks5_udp_smoke_passed"] = json!(passed);
    report["socks5_udp_associate_admitted"] = json!(passed);
    report["socks5_protocol_true_dataplane_admitted"] = json!(passed);
    report["socks5_auth_observed"] = json!(outcome.server_summary.auth_success_count > 0);
    report["socks5_udp_associate_request_observed"] =
        json!(outcome.server_summary.udp_associate_count > 0);
    report["socks5_udp_packet_wrap_unwrap_recorded"] =
        json!(outcome.server_summary.udp_packet_roundtrip_count > 0);
    report["socks5_udp_payload_roundtrip_recorded"] =
        json!(outcome.server_summary.udp_packet_roundtrip_count > 0);
    report["socks5_tcp_control_connection_retained"] =
        json!(outcome.server_summary.control_retained_during_udp_count == outcome.exchange_count);
    report["socks5_udp_contract"]["tcp_control_proxy"] =
        json!(outcome.tcp_last_dial_report.peer_addr);
    report["socks5_udp_contract"]["observed_bind_reply"] = json!(outcome.last_control_bind);
    report["socks5_udp_contract"]["resolved_udp_bind"] = json!(outcome.last_resolved_udp_bind);
    report["tcp_control_underlay"]["listener"] = json!({
        "requested_mptcp": outcome.tcp_listener_report.requested_mptcp,
        "mptcp_socket_created": outcome.tcp_listener_report.mptcp_socket_created,
        "fallback_used": outcome.tcp_listener_report.fallback_used,
        "socket_protocol": outcome.tcp_listener_report.socket_protocol,
        "local_addr": outcome.tcp_listener_report.local_addr
    });
    report["tcp_control_underlay"]["last_dial_report"] = json!({
        "requested_mark": outcome.tcp_last_dial_report.requested_mark,
        "requested_mptcp": outcome.tcp_last_dial_report.requested_mptcp,
        "mptcp_socket_attempted": outcome.tcp_last_dial_report.mptcp_socket_attempted,
        "mptcp_socket_created": outcome.tcp_last_dial_report.mptcp_socket_created,
        "mptcp_connect_fallback_used": outcome.tcp_last_dial_report.mptcp_connect_fallback_used,
        "socket_protocol": outcome.tcp_last_dial_report.socket_protocol,
        "so_mark": outcome.tcp_last_dial_report.so_mark,
        "so_mark_applied": outcome.tcp_last_dial_report.so_mark_applied,
        "mptcp_info_available": outcome.tcp_last_dial_report.mptcp_info_available,
        "mptcp_fallen_back": outcome.tcp_last_dial_report.mptcp_fallen_back,
        "mptcp_protocol_observed": outcome.tcp_last_dial_report.mptcp_protocol_observed,
        "peer_addr": outcome.tcp_last_dial_report.peer_addr,
        "local_addr": outcome.tcp_last_dial_report.local_addr
    });
    report["tcp_control_underlay"]["so_mark_observed"] = json!(tcp_so_mark_observed);
    report["tcp_control_underlay"]["mptcp_status_recorded"] = json!(tcp_mptcp_status_recorded);
    report["tcp_control_underlay"]["mptcp_protocol_observed"] =
        json!(outcome.tcp_last_dial_report.mptcp_protocol_observed);
    report["udp_underlay_socket"]["last_socket_report"] = json!({
        "requested_mark": outcome.udp_last_socket_report.requested_mark,
        "so_mark": outcome.udp_last_socket_report.so_mark,
        "so_mark_applied": outcome.udp_last_socket_report.so_mark_applied,
        "peer_addr": outcome.udp_last_socket_report.peer_addr,
        "local_addr": outcome.udp_last_socket_report.local_addr
    });
    report["udp_underlay_socket"]["so_mark_observed"] = json!(udp_so_mark_observed);
    report["server_observation"] = json!({
        "accepted": outcome.server_summary.accepted,
        "auth_success_count": outcome.server_summary.auth_success_count,
        "udp_associate_count": outcome.server_summary.udp_associate_count,
        "udp_packet_roundtrip_count": outcome.server_summary.udp_packet_roundtrip_count,
        "control_retained_during_udp_count": outcome.server_summary.control_retained_during_udp_count,
        "associate_targets": outcome.server_summary.associate_targets,
        "packet_targets": outcome.server_summary.packet_targets,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "response_ascii": outcome.server_summary.response_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_udp_associate"] = json!(outcome.ns_per_udp_associate);
    report["benchmark"]["payload_len"] = json!(outcome.payload_len);
    report["benchmark"]["response_len"] = json!(outcome.response_len);
    report["protocol_matrix"]["socks5_udp_associate_admitted"] = json!(passed);
    report["protocol_matrix"]["socks5_protocol_true_dataplane_admitted"] = json!(passed);
}

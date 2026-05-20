use super::server::*;
use super::*;

#[derive(Debug)]
pub(super) struct Stage86Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    client_report: trojan::TrojanGoGrpcTcpExchangeReport,
    server_summary: TrojanGoGrpcServerSummary,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
}

pub(super) fn run_stage86_smoke(opts: &Stage86Options) -> Result<Stage86Outcome, String> {
    let (server_addr, listener_report, handle) = spawn_trojan_go_grpc_server(opts)?;
    let mut last_dial_report = None;
    let mut last_client_report = None;
    let start = Instant::now();
    for _ in 0..opts.benchmark_iters {
        let mut connected = magic_tcp_connect(
            server_addr,
            &TcpDirectDialOptions {
                mark: opts.so_mark,
                mptcp: opts.mptcp,
                timeout: opts.timeout,
            },
        )
        .map_err(|err| format!("stage86 magic_tcp_connect failed: {err}"))?;
        let grpc_options = opts.grpc_options(&server_addr.to_string());
        let report = trojan::tcp_exchange_over_grpc_hunk_stream(
            &mut connected.stream,
            &server_addr.to_string(),
            &opts.password,
            &opts.target,
            &grpc_options,
            &opts.payload,
        )
        .map_err(|err| format!("stage86 trojan-go gRPC hunk exchange failed: {err}"))?;
        if report.echoed_payload != opts.payload {
            return Err("stage86 trojan-go gRPC hunk payload response mismatch".to_owned());
        }
        last_dial_report = Some(connected.report);
        last_client_report = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage86 trojan-go gRPC server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage86 trojan-go gRPC server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage86Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage86 missing underlay dial report".to_owned())?,
        client_report: last_client_report
            .ok_or_else(|| "stage86 missing trojan-go gRPC client report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
    })
}

pub(super) fn apply_stage86_outcome(report: &mut Value, outcome: Stage86Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.grpc_stream_preface_count == outcome.exchange_count
        && outcome.server_summary.grpc_hunk_tunnel_count == outcome.exchange_count
        && outcome.server_summary.no_outer_tls_count == outcome.exchange_count
        && outcome.server_summary.password_hash_match_count == outcome.exchange_count
        && outcome.server_summary.tcp_command_count == outcome.exchange_count
        && outcome.server_summary.target_metadata_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let client_complete = outcome.client_report.true_dataplane
        && outcome.client_report.trojan_go_grpc
        && !outcome.client_report.outer_tls_wrapped
        && outcome.client_report.grpc_contains_tls_boundary
        && outcome.client_report.grpc_stream_preface_validated
        && outcome.client_report.grpc_hunk_frame_validated
        && outcome.client_report.cache_key_route_context_validated;
    let passed = server_complete && client_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["trojan_go_grpc_smoke_passed"] = json!(passed);
    report["trojan_go_grpc_admitted"] = json!(passed);
    report["trojan_go_shared_transport_partial_admitted"] = json!(true);
    report["trojan_go_grpc_contract"]["server"] = json!(outcome.last_dial_report.peer_addr);
    report["trojan_go_grpc_contract"]["grpc_cache_key"] =
        json!(outcome.client_report.grpc_cache_key);
    report["trojan_go_grpc_contract"]["outer_tls_wrapped"] =
        json!(outcome.client_report.outer_tls_wrapped);
    report["trojan_go_grpc_contract"]["grpc_contains_tls_boundary"] =
        json!(outcome.client_report.grpc_contains_tls_boundary);
    report["trojan_go_grpc_contract"]["full_grpc_http2_stack"] =
        json!(outcome.client_report.full_grpc_http2_stack);
    report["trojan_go_grpc_contract"]["grpc_stream_preface_validated"] = json!(passed);
    report["trojan_go_grpc_contract"]["grpc_hunk_tunnel_validated"] = json!(passed);
    report["trojan_go_grpc_contract"]["grpc_cache_key_route_context_validated"] = json!(passed);
    report["trojan_go_grpc_contract"]["no_outer_tls_validated"] = json!(passed);
    report["trojan_go_grpc_contract"]["password_sha224_validated"] = json!(passed);
    report["trojan_go_grpc_contract"]["tcp_command_validated"] = json!(passed);
    report["trojan_go_grpc_contract"]["target_metadata_validated"] = json!(passed);
    report["trojan_go_grpc_contract"]["payload_roundtrip_validated"] = json!(passed);
    report["trojan_go_grpc_contract"]["service_name_fallback_validated"] = json!(passed);
    report["underlay_socket"]["listener"] = json!({
        "requested_mptcp": outcome.listener_report.requested_mptcp,
        "mptcp_socket_created": outcome.listener_report.mptcp_socket_created,
        "fallback_used": outcome.listener_report.fallback_used,
        "socket_protocol": outcome.listener_report.socket_protocol,
        "local_addr": outcome.listener_report.local_addr
    });
    report["underlay_socket"]["last_dial_report"] = json!({
        "requested_mark": outcome.last_dial_report.requested_mark,
        "requested_mptcp": outcome.last_dial_report.requested_mptcp,
        "mptcp_socket_attempted": outcome.last_dial_report.mptcp_socket_attempted,
        "mptcp_socket_created": outcome.last_dial_report.mptcp_socket_created,
        "mptcp_connect_fallback_used": outcome.last_dial_report.mptcp_connect_fallback_used,
        "socket_protocol": outcome.last_dial_report.socket_protocol,
        "so_mark": outcome.last_dial_report.so_mark,
        "so_mark_applied": outcome.last_dial_report.so_mark_applied,
        "mptcp_info_available": outcome.last_dial_report.mptcp_info_available,
        "mptcp_fallen_back": outcome.last_dial_report.mptcp_fallen_back,
        "mptcp_protocol_observed": outcome.last_dial_report.mptcp_protocol_observed,
        "peer_addr": outcome.last_dial_report.peer_addr,
        "local_addr": outcome.last_dial_report.local_addr
    });
    report["underlay_socket"]["so_mark_observed"] = json!(so_mark_observed);
    report["underlay_socket"]["mptcp_status_recorded"] = json!(mptcp_status_recorded);
    report["underlay_socket"]["mptcp_protocol_observed"] =
        json!(outcome.last_dial_report.mptcp_protocol_observed);
    report["server_observation"] = json!({
        "accepted": outcome.server_summary.accepted,
        "grpc_stream_preface_count": outcome.server_summary.grpc_stream_preface_count,
        "grpc_hunk_tunnel_count": outcome.server_summary.grpc_hunk_tunnel_count,
        "no_outer_tls_count": outcome.server_summary.no_outer_tls_count,
        "password_hash_match_count": outcome.server_summary.password_hash_match_count,
        "tcp_command_count": outcome.server_summary.tcp_command_count,
        "target_metadata_count": outcome.server_summary.target_metadata_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "targets": outcome.server_summary.targets,
        "grpc_service_names": outcome.server_summary.grpc_service_names,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "response_ascii": outcome.server_summary.response_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_trojan_go_grpc_hunk_exchange"] = json!(outcome.ns_per_exchange);
    report["benchmark"]["payload_len"] = json!(outcome.client_report.payload_len);
    report["benchmark"]["request_header_len"] = json!(outcome.client_report.request_header_len);
    report["benchmark"]["grpc_preface_len"] = json!(outcome.client_report.grpc_preface_len);
    report["benchmark"]["grpc_request_hunk_len"] =
        json!(outcome.client_report.grpc_request_hunk_len);
    report["benchmark"]["grpc_response_hunk_len"] =
        json!(outcome.client_report.grpc_response_hunk_len);
    report["protocol_matrix"]["trojan_go_grpc_admitted"] = json!(passed);
}

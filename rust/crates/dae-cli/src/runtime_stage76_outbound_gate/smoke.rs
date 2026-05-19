use super::server::*;
use super::*;

#[derive(Debug)]
pub(super) struct Stage76Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    server_summary: VlessGrpcHunkServerSummary,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
    payload_len: usize,
    request_header_len: usize,
    response_header_len: usize,
    grpc_preface_len: usize,
    grpc_request_hunk_len: usize,
    grpc_response_hunk_len: usize,
    grpc_cache_key: String,
    key_hex: String,
}

pub(super) fn run_stage76_smoke(opts: &Stage76Options) -> Result<Stage76Outcome, String> {
    let key = vless::password_to_key(&opts.uuid)
        .map_err(|err| format!("stage76 uuid is invalid: {err}"))?;
    let (server_addr, listener_report, handle) = spawn_vless_grpc_hunk_server(opts)?;
    let mut last_dial_report = None;
    let mut last_exchange = None;
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
        .map_err(|err| format!("stage76 magic_tcp_connect failed: {err}"))?;
        let grpc_options = opts.grpc_options(&server_addr.to_string());
        let report = vless::tcp_exchange_over_grpc_hunk_stream(
            &mut connected.stream,
            &server_addr.to_string(),
            &key,
            &opts.target,
            &grpc_options,
            &opts.payload,
        )
        .map_err(|err| format!("stage76 VLESS gRPC hunk exchange failed: {err}"))?;
        if report.echoed_payload != opts.payload {
            return Err("stage76 VLESS gRPC hunk payload response mismatch".to_owned());
        }
        last_dial_report = Some(connected.report);
        last_exchange = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage76 VLESS gRPC hunk server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage76 VLESS gRPC hunk server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    let last_exchange =
        last_exchange.ok_or_else(|| "stage76 missing exchange report".to_owned())?;
    Ok(Stage76Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage76 missing underlay dial report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
        payload_len: opts.payload.len(),
        request_header_len: last_exchange.request_header_len,
        response_header_len: last_exchange.response_header_len,
        grpc_preface_len: last_exchange.grpc_preface_len,
        grpc_request_hunk_len: last_exchange.grpc_request_hunk_len,
        grpc_response_hunk_len: last_exchange.grpc_response_hunk_len,
        grpc_cache_key: last_exchange.grpc_cache_key,
        key_hex: last_exchange.key_hex,
    })
}

pub(super) fn apply_stage76_outcome(report: &mut Value, outcome: Stage76Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.grpc_stream_preface_count == outcome.exchange_count
        && outcome.server_summary.grpc_hunk_tunnel_count == outcome.exchange_count
        && outcome.server_summary.request_header_count == outcome.exchange_count
        && outcome.server_summary.response_header_count == outcome.exchange_count
        && outcome.server_summary.empty_addons_count == outcome.exchange_count
        && outcome.server_summary.tcp_command_count == outcome.exchange_count
        && outcome.server_summary.target_metadata_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let passed = server_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["vless_grpc_hunk_smoke_passed"] = json!(passed);
    report["vless_grpc_hunk_admitted"] = json!(passed);
    report["vless_shared_transport_partial_admitted"] = json!(true);
    report["vless_protocol_partial_admitted"] = json!(true);
    report["vless_grpc_hunk_contract"]["server"] = json!(outcome.last_dial_report.peer_addr);
    report["vless_grpc_hunk_contract"]["key_hex"] = json!(outcome.key_hex);
    report["vless_grpc_hunk_contract"]["grpc_cache_key"] = json!(outcome.grpc_cache_key);
    report["vless_grpc_hunk_contract"]["grpc_stream_preface_validated"] = json!(passed);
    report["vless_grpc_hunk_contract"]["grpc_hunk_tunnel_validated"] = json!(passed);
    report["vless_grpc_hunk_contract"]["grpc_cache_key_route_context_validated"] = json!(passed);
    report["vless_grpc_hunk_contract"]["request_header_validated"] = json!(passed);
    report["vless_grpc_hunk_contract"]["response_header_validated"] = json!(passed);
    report["vless_grpc_hunk_contract"]["empty_addons_validated"] = json!(passed);
    report["vless_grpc_hunk_contract"]["tcp_command_validated"] = json!(passed);
    report["vless_grpc_hunk_contract"]["target_metadata_validated"] = json!(passed);
    report["vless_grpc_hunk_contract"]["payload_roundtrip_validated"] = json!(passed);
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
        "request_header_count": outcome.server_summary.request_header_count,
        "response_header_count": outcome.server_summary.response_header_count,
        "empty_addons_count": outcome.server_summary.empty_addons_count,
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
    report["benchmark"]["ns_per_vless_grpc_hunk_exchange"] = json!(outcome.ns_per_exchange);
    report["benchmark"]["payload_len"] = json!(outcome.payload_len);
    report["benchmark"]["request_header_len"] = json!(outcome.request_header_len);
    report["benchmark"]["response_header_len"] = json!(outcome.response_header_len);
    report["benchmark"]["grpc_preface_len"] = json!(outcome.grpc_preface_len);
    report["benchmark"]["grpc_request_hunk_len"] = json!(outcome.grpc_request_hunk_len);
    report["benchmark"]["grpc_response_hunk_len"] = json!(outcome.grpc_response_hunk_len);
    report["protocol_matrix"]["vless_grpc_hunk_admitted"] = json!(passed);
}

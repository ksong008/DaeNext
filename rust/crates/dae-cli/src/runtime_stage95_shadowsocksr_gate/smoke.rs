use super::server::*;
use super::*;

#[derive(Debug)]
pub(super) struct Stage95Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    client_report: shadowsocks::ShadowsocksRThreeLayerExchangeReport,
    server_summary: ShadowsocksRServerSummary,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
}

pub(super) fn run_stage95_smoke(opts: &Stage95Options) -> Result<Stage95Outcome, String> {
    let (server_addr, listener_report, handle) = spawn_shadowsocksr_server(opts)?;
    let mut last_dial_report = None;
    let mut last_client_report = None;
    let start = Instant::now();
    for index in 0..opts.benchmark_iters {
        let mut connected = magic_tcp_connect(
            server_addr,
            &TcpDirectDialOptions {
                mark: opts.so_mark,
                mptcp: opts.mptcp,
                timeout: opts.timeout,
            },
        )
        .map_err(|err| format!("stage95 magic_tcp_connect failed: {err}"))?;
        let options = shadowsocks::ShadowsocksRThreeLayerOptions::http_simple_origin(
            &opts.obfs_host,
            server_addr.port(),
            iv_for(index, 0x45),
            iv_for(index, 0x95),
        );
        let report = shadowsocks::shadowsocksr_three_layer_tcp_exchange_over_stream(
            &mut connected.stream,
            &server_addr.to_string(),
            &opts.cipher,
            &opts.password,
            &opts.target,
            &opts.payload,
            &options,
        )
        .map_err(|err| format!("stage95 ShadowsocksR exchange failed: {err}"))?;
        if report.echoed_payload != opts.payload {
            return Err("stage95 ShadowsocksR payload mismatch".to_owned());
        }
        last_dial_report = Some(connected.report);
        last_client_report = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage95 ShadowsocksR server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage95 ShadowsocksR server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage95Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage95 missing underlay dial report".to_owned())?,
        client_report: last_client_report
            .ok_or_else(|| "stage95 missing ShadowsocksR client report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
    })
}

pub(super) fn apply_stage95_outcome(report: &mut Value, outcome: Stage95Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.obfs_layer_count == outcome.exchange_count
        && outcome.server_summary.stream_cipher_count == outcome.exchange_count
        && outcome.server_summary.protocol_wrapper_count == outcome.exchange_count
        && outcome.server_summary.target_metadata_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count
        && outcome.server_summary.response_count == outcome.exchange_count;
    let client_complete = outcome.client_report.protocol_name == "shadowsocksr"
        && outcome.client_report.obfs_layer_validated
        && outcome.client_report.stream_cipher_validated
        && outcome.client_report.protocol_wrapper_validated
        && outcome.client_report.three_layer_order_validated
        && outcome.client_report.true_dataplane
        && outcome.client_report.default_go_path;
    let passed = server_complete && client_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["shadowsocksr_three_layer_smoke_passed"] = json!(passed);
    report["shadowsocksr_true_dataplane_admitted"] = json!(passed);
    report["shadowsocks_protocol_true_dataplane_admitted"] = json!(passed);
    report["shadowsocksr_contract"]["obfs_port"] = json!(outcome.client_report.obfs_port);
    report["shadowsocksr_contract"]["obfs_layer_validated"] =
        json!(outcome.client_report.obfs_layer_validated);
    report["shadowsocksr_contract"]["stream_cipher_validated"] =
        json!(outcome.client_report.stream_cipher_validated);
    report["shadowsocksr_contract"]["protocol_wrapper_validated"] =
        json!(outcome.client_report.protocol_wrapper_validated);
    report["shadowsocksr_contract"]["three_layer_order_validated"] =
        json!(outcome.client_report.three_layer_order_validated);
    report["shadowsocksr_contract"]["stream_key_len"] = json!(outcome.client_report.stream_key_len);
    report["shadowsocksr_contract"]["stream_iv_len"] = json!(outcome.client_report.stream_iv_len);
    report["shadowsocksr_contract"]["ssr_protocol_addr_len"] =
        json!(outcome.client_report.ssr_protocol_addr_len);
    report["shadowsocksr_contract"]["payload_roundtrip_validated"] = json!(passed);
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
        "obfs_layer_count": outcome.server_summary.obfs_layer_count,
        "stream_cipher_count": outcome.server_summary.stream_cipher_count,
        "protocol_wrapper_count": outcome.server_summary.protocol_wrapper_count,
        "target_metadata_count": outcome.server_summary.target_metadata_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "response_count": outcome.server_summary.response_count,
        "targets": outcome.server_summary.targets,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "obfs_request_payload_lengths": outcome.server_summary.obfs_request_payload_lengths,
        "stream_iv_lengths": outcome.server_summary.stream_iv_lengths,
        "stream_key_lengths": outcome.server_summary.stream_key_lengths
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_shadowsocksr_three_layer_exchange"] =
        json!(outcome.ns_per_exchange);
    report["benchmark"]["exchange_count"] = json!(outcome.exchange_count);
    report["benchmark"]["payload_len"] = json!(outcome.client_report.payload_len);
    report["benchmark"]["obfs_request_head_len"] =
        json!(outcome.client_report.obfs_request_head_len);
    report["benchmark"]["obfs_request_payload_len"] =
        json!(outcome.client_report.obfs_request_payload_len);
    report["protocol_matrix"]["shadowsocksr_true_dataplane_admitted"] = json!(passed);
    report["protocol_matrix"]["shadowsocks_protocol_true_dataplane_admitted"] = json!(passed);
}

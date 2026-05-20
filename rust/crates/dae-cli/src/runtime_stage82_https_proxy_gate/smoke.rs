use super::server::*;
use super::*;

#[derive(Debug)]
pub(super) struct Stage82Outcome {
    pub(super) listener_report: TcpLoopbackListenerReport,
    pub(super) last_dial_report: TcpDirectDialReport,
    pub(super) client_report: http_proxy::HttpsProxyTlsExchangeReport,
    pub(super) server_summary: HttpsProxyServerSummary,
    pub(super) certificate_der_len: usize,
    pub(super) elapsed_ns: u128,
    pub(super) ns_per_connect: f64,
    pub(super) exchange_count: usize,
    pub(super) response_len: usize,
}

pub(super) fn run_stage82_smoke(opts: &Stage82Options) -> Result<Stage82Outcome, String> {
    let tls_options = opts
        .tls_options()
        .map_err(|err| format!("stage82 tls options invalid: {err}"))?;
    let material = shared_transport::tls_loopback_material(&tls_options)
        .map_err(|err| format!("stage82 build tls material failed: {err}"))?;
    let certificate_der_len = material.certificate_der_len;
    let (proxy_addr, listener_report, handle) = spawn_https_proxy(opts, &material)?;
    let mut last_dial_report = None;
    let mut last_client_report = None;
    let start = Instant::now();
    for _ in 0..opts.benchmark_iters {
        let connected = magic_tcp_connect(
            proxy_addr,
            &TcpDirectDialOptions {
                mark: opts.so_mark,
                mptcp: opts.mptcp,
                timeout: opts.timeout,
            },
        )
        .map_err(|err| format!("stage82 magic_tcp_connect failed: {err}"))?;
        let dae_datapath::TcpDirectConnection {
            stream,
            report: dial_report,
        } = connected;
        let report = http_proxy::connect_exchange_over_tls_stream(
            stream,
            &material,
            &tls_options,
            &proxy_addr.to_string(),
            &opts.http_options(),
            &opts.payload,
        )
        .map_err(|err| format!("stage82 https proxy exchange failed: {err}"))?;
        if report.status != 200 {
            return Err(format!(
                "stage82 https proxy status mismatch: {}",
                report.status
            ));
        }
        if report.echoed_payload != opts.response {
            return Err("stage82 https proxy payload response mismatch".to_owned());
        }
        last_dial_report = Some(dial_report);
        last_client_report = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage82 https proxy thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage82 https proxy accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage82Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage82 missing underlay dial report".to_owned())?,
        client_report: last_client_report
            .ok_or_else(|| "stage82 missing HTTPS proxy client report".to_owned())?,
        server_summary,
        certificate_der_len,
        elapsed_ns,
        ns_per_connect: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
        response_len: opts.response.len(),
    })
}

pub(super) fn apply_stage82_outcome(report: &mut Value, outcome: Stage82Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.tls_handshake_count == outcome.exchange_count
        && outcome.server_summary.alpn_validated_count == outcome.exchange_count
        && outcome.server_summary.connect_count == outcome.exchange_count
        && outcome.server_summary.auth_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let client_complete = outcome.client_report.true_dataplane
        && outcome.client_report.https_proxy_tls_underlay
        && outcome.client_report.tls_handshake_validated
        && outcome.client_report.certificate_chain_validated
        && outcome.client_report.server_name_validated
        && outcome.client_report.alpn_validated;
    let passed = server_complete && client_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["https_proxy_tls_smoke_passed"] = json!(passed);
    report["https_proxy_tls_underlay_admitted"] = json!(passed);
    report["https_proxy_true_dataplane_admitted"] = json!(passed);
    report["http_proxy_protocol_true_dataplane_admitted"] = json!(passed);
    report["https_proxy_contract"]["proxy"] = json!(outcome.last_dial_report.peer_addr);
    report["https_proxy_contract"]["selected_alpn"] = json!(outcome.client_report.selected_alpn);
    report["https_proxy_contract"]["certificate_der_len"] = json!(outcome.certificate_der_len);
    report["https_proxy_contract"]["tls_handshake_validated"] = json!(passed);
    report["https_proxy_contract"]["certificate_chain_validated"] = json!(passed);
    report["https_proxy_contract"]["server_name_validated"] = json!(passed);
    report["https_proxy_contract"]["alpn_validated"] = json!(passed);
    report["https_proxy_contract"]["connect_request_observed"] =
        json!(outcome.server_summary.connect_count > 0);
    report["https_proxy_contract"]["http_proxy_auth_observed"] =
        json!(outcome.server_summary.auth_count > 0);
    report["https_proxy_contract"]["payload_roundtrip_recorded"] =
        json!(outcome.server_summary.payload_roundtrip_count > 0);
    report["https_proxy_contract"]["observed_status"] = json!(outcome.client_report.status);
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
        "tls_handshake_count": outcome.server_summary.tls_handshake_count,
        "alpn_validated_count": outcome.server_summary.alpn_validated_count,
        "connect_count": outcome.server_summary.connect_count,
        "auth_count": outcome.server_summary.auth_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "selected_alpns": outcome.server_summary.selected_alpns,
        "connect_authorities": outcome.server_summary.connect_authorities,
        "host_headers": outcome.server_summary.host_headers,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "response_ascii": outcome.server_summary.response_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_https_proxy_tls_connect"] = json!(outcome.ns_per_connect);
    report["benchmark"]["payload_len"] = json!(outcome.client_report.payload_len);
    report["benchmark"]["response_len"] = json!(outcome.response_len);
    report["protocol_matrix"]["https_proxy_tls_underlay_admitted"] = json!(passed);
    report["protocol_matrix"]["https_proxy_true_dataplane_admitted"] = json!(passed);
}

use super::server::*;
use super::*;

#[derive(Debug)]
pub(super) struct Stage92Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    client_report: shadowsocks::Sip003SimpleObfsHttpExchangeReport,
    server_summary: Sip003SimpleObfsHttpServerSummary,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
}

pub(super) fn run_stage92_smoke(opts: &Stage92Options) -> Result<Stage92Outcome, String> {
    let spec = shadowsocks::cipher_spec(&opts.cipher)
        .map_err(|err| format!("stage92 unsupported AEAD cipher: {err}"))?;
    let (server_addr, listener_report, handle) = spawn_sip003_simple_obfs_http_server(opts)?;
    let options =
        shadowsocks::Sip003SimpleObfsHttpOptions::new(&opts.plugin_host, &opts.plugin_path);
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
        .map_err(|err| format!("stage92 magic_tcp_connect failed: {err}"))?;
        let client_salt = salt_for(index, spec.salt_len, 0x21);
        let server_salt = salt_for(index, spec.salt_len, 0x61);
        let report = shadowsocks::simple_obfs_http_shadowsocks_aead_exchange_over_stream(
            &mut connected.stream,
            &server_addr.to_string(),
            &opts.cipher,
            &opts.password,
            &opts.target,
            &opts.payload,
            AeadTcpSalts {
                client: &client_salt,
                server: &server_salt,
            },
            &options,
        )
        .map_err(|err| format!("stage92 SIP003 simple-obfs HTTP exchange failed: {err}"))?;
        if report.inner.echoed_payload != opts.payload {
            return Err("stage92 SIP003 simple-obfs HTTP payload mismatch".to_owned());
        }
        last_dial_report = Some(connected.report);
        last_client_report = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage92 SIP003 simple-obfs HTTP server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage92 SIP003 simple-obfs HTTP server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage92Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage92 missing underlay dial report".to_owned())?,
        client_report: last_client_report
            .ok_or_else(|| "stage92 missing SIP003 client report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
    })
}

pub(super) fn apply_stage92_outcome(report: &mut Value, outcome: Stage92Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.http_request_count == outcome.exchange_count
        && outcome.server_summary.host_match_count == outcome.exchange_count
        && outcome.server_summary.path_match_count == outcome.exchange_count
        && outcome.server_summary.content_length_match_count == outcome.exchange_count
        && outcome.server_summary.inner_decrypt_count == outcome.exchange_count
        && outcome.server_summary.target_metadata_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count
        && outcome.server_summary.response_count == outcome.exchange_count;
    let client_complete = outcome.client_report.plugin_name == "simple-obfs"
        && outcome.client_report.obfs == "http"
        && outcome.client_report.request_line_validated
        && outcome.client_report.host_validated
        && outcome.client_report.content_length_validated
        && outcome.client_report.inner.true_dataplane
        && outcome.client_report.inner.default_go_path;
    let passed = server_complete && client_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["sip003_simple_obfs_http_smoke_passed"] = json!(passed);
    report["sip003_simple_obfs_http_admitted"] = json!(passed);
    report["sip003_contract"]["server"] = json!(outcome.last_dial_report.peer_addr);
    report["sip003_contract"]["host"] = json!(outcome.client_report.host);
    report["sip003_contract"]["path"] = json!(outcome.client_report.path);
    report["sip003_contract"]["request_line_validated"] =
        json!(outcome.client_report.request_line_validated);
    report["sip003_contract"]["host_validated"] = json!(outcome.client_report.host_validated);
    report["sip003_contract"]["content_length_validated"] =
        json!(outcome.client_report.content_length_validated);
    report["sip003_contract"]["inner_shadowsocks_aead"]["cipher"] =
        json!(outcome.client_report.inner.cipher);
    report["sip003_contract"]["inner_shadowsocks_aead"]["target"] =
        json!(outcome.client_report.inner.target);
    report["sip003_contract"]["inner_shadowsocks_aead"]["client_salt_len"] =
        json!(outcome.client_report.inner.client_salt_len);
    report["sip003_contract"]["inner_shadowsocks_aead"]["server_salt_len"] =
        json!(outcome.client_report.inner.server_salt_len);
    report["sip003_contract"]["inner_shadowsocks_aead"]["payload_len"] =
        json!(outcome.client_report.inner.payload_len);
    report["sip003_contract"]["inner_shadowsocks_aead"]["payload_roundtrip_validated"] =
        json!(passed);
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
        "http_request_count": outcome.server_summary.http_request_count,
        "host_match_count": outcome.server_summary.host_match_count,
        "path_match_count": outcome.server_summary.path_match_count,
        "content_length_match_count": outcome.server_summary.content_length_match_count,
        "inner_decrypt_count": outcome.server_summary.inner_decrypt_count,
        "target_metadata_count": outcome.server_summary.target_metadata_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "response_count": outcome.server_summary.response_count,
        "request_lines": outcome.server_summary.request_lines,
        "hosts": outcome.server_summary.hosts,
        "paths": outcome.server_summary.paths,
        "content_lengths": outcome.server_summary.content_lengths,
        "targets": outcome.server_summary.targets,
        "payload_ascii": outcome.server_summary.payload_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_sip003_simple_obfs_http_exchange"] = json!(outcome.ns_per_exchange);
    report["benchmark"]["exchange_count"] = json!(outcome.exchange_count);
    report["benchmark"]["payload_len"] = json!(outcome.client_report.inner.payload_len);
    report["protocol_matrix"]["sip003_simple_obfs_http_admitted"] = json!(passed);
}

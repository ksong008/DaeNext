use super::server::*;
use super::*;

#[derive(Debug)]
pub(super) struct Stage93Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    client_report: shadowsocks::Sip003SimpleObfsTlsExchangeReport,
    server_summary: Sip003SimpleObfsTlsServerSummary,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
}

pub(super) fn run_stage93_smoke(opts: &Stage93Options) -> Result<Stage93Outcome, String> {
    let spec = shadowsocks::cipher_spec(&opts.cipher)
        .map_err(|err| format!("stage93 unsupported AEAD cipher: {err}"))?;
    let (server_addr, listener_report, handle) = spawn_sip003_simple_obfs_tls_server(opts)?;
    let options = shadowsocks::Sip003SimpleObfsTlsOptions::new(&opts.server_name);
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
        .map_err(|err| format!("stage93 magic_tcp_connect failed: {err}"))?;
        let client_salt = salt_for(index, spec.salt_len, 0x31);
        let server_salt = salt_for(index, spec.salt_len, 0x71);
        let report = shadowsocks::simple_obfs_tls_shadowsocks_aead_exchange_over_stream(
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
        .map_err(|err| format!("stage93 SIP003 simple-obfs TLS exchange failed: {err}"))?;
        if report.inner.echoed_payload != opts.payload {
            return Err("stage93 SIP003 simple-obfs TLS payload mismatch".to_owned());
        }
        last_dial_report = Some(connected.report);
        last_client_report = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage93 SIP003 simple-obfs TLS server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage93 SIP003 simple-obfs TLS server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage93Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage93 missing underlay dial report".to_owned())?,
        client_report: last_client_report
            .ok_or_else(|| "stage93 missing SIP003 TLS client report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
    })
}

pub(super) fn apply_stage93_outcome(report: &mut Value, outcome: Stage93Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.client_hello_count == outcome.exchange_count
        && outcome.server_summary.sni_match_count == outcome.exchange_count
        && outcome.server_summary.session_ticket_match_count == outcome.exchange_count
        && outcome.server_summary.inner_decrypt_count == outcome.exchange_count
        && outcome.server_summary.target_metadata_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count
        && outcome.server_summary.response_count == outcome.exchange_count;
    let client_complete = outcome.client_report.plugin_name == "simple-obfs"
        && outcome.client_report.obfs == "tls"
        && outcome.client_report.client_hello_validated
        && outcome.client_report.sni_validated
        && outcome.client_report.session_ticket_validated
        && outcome.client_report.inner.true_dataplane
        && outcome.client_report.inner.default_go_path;
    let passed = server_complete && client_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["sip003_simple_obfs_tls_smoke_passed"] = json!(passed);
    report["sip003_simple_obfs_tls_admitted"] = json!(passed);
    report["sip003_contract"]["server"] = json!(outcome.last_dial_report.peer_addr);
    report["sip003_contract"]["server_name"] = json!(outcome.client_report.server_name);
    report["sip003_contract"]["client_hello_validated"] =
        json!(outcome.client_report.client_hello_validated);
    report["sip003_contract"]["sni_validated"] = json!(outcome.client_report.sni_validated);
    report["sip003_contract"]["session_ticket_validated"] =
        json!(outcome.client_report.session_ticket_validated);
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
        "client_hello_count": outcome.server_summary.client_hello_count,
        "sni_match_count": outcome.server_summary.sni_match_count,
        "session_ticket_match_count": outcome.server_summary.session_ticket_match_count,
        "inner_decrypt_count": outcome.server_summary.inner_decrypt_count,
        "target_metadata_count": outcome.server_summary.target_metadata_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "response_count": outcome.server_summary.response_count,
        "server_names": outcome.server_summary.server_names,
        "session_ticket_lengths": outcome.server_summary.session_ticket_lengths,
        "client_hello_lengths": outcome.server_summary.client_hello_lengths,
        "targets": outcome.server_summary.targets,
        "payload_ascii": outcome.server_summary.payload_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_sip003_simple_obfs_tls_exchange"] = json!(outcome.ns_per_exchange);
    report["benchmark"]["exchange_count"] = json!(outcome.exchange_count);
    report["benchmark"]["payload_len"] = json!(outcome.client_report.inner.payload_len);
    report["protocol_matrix"]["sip003_simple_obfs_tls_admitted"] = json!(passed);
}

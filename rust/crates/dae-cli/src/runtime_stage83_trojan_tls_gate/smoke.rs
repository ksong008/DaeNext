use super::server::*;
use super::*;

#[derive(Debug)]
pub(super) struct Stage83Outcome {
    pub(super) listener_report: TcpLoopbackListenerReport,
    pub(super) last_dial_report: TcpDirectDialReport,
    pub(super) client_report: trojan::TrojanTlsTcpExchangeReport,
    pub(super) server_summary: TrojanTlsServerSummary,
    pub(super) certificate_der_len: usize,
    pub(super) elapsed_ns: u128,
    pub(super) ns_per_exchange: f64,
    pub(super) exchange_count: usize,
}

pub(super) fn run_stage83_smoke(opts: &Stage83Options) -> Result<Stage83Outcome, String> {
    let tls_options = opts
        .tls_options()
        .map_err(|err| format!("stage83 tls options invalid: {err}"))?;
    let material = shared_transport::tls_loopback_material(&tls_options)
        .map_err(|err| format!("stage83 build tls material failed: {err}"))?;
    let certificate_der_len = material.certificate_der_len;
    let (server_addr, listener_report, handle) = spawn_trojan_tls_server(opts, &material)?;
    let mut last_dial_report = None;
    let mut last_client_report = None;
    let start = Instant::now();
    for _ in 0..opts.benchmark_iters {
        let connected = magic_tcp_connect(
            server_addr,
            &TcpDirectDialOptions {
                mark: opts.so_mark,
                mptcp: opts.mptcp,
                timeout: opts.timeout,
            },
        )
        .map_err(|err| format!("stage83 magic_tcp_connect failed: {err}"))?;
        let dae_datapath::TcpDirectConnection {
            stream,
            report: dial_report,
        } = connected;
        let report = trojan::tcp_exchange_over_tls_stream(
            stream,
            &material,
            &tls_options,
            &server_addr.to_string(),
            &opts.password,
            &opts.target,
            &opts.payload,
        )
        .map_err(|err| format!("stage83 trojan TLS exchange failed: {err}"))?;
        if report.echoed_payload != opts.payload {
            return Err("stage83 trojan TLS payload response mismatch".to_owned());
        }
        last_dial_report = Some(dial_report);
        last_client_report = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage83 trojan TLS server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage83 trojan TLS server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage83Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage83 missing underlay dial report".to_owned())?,
        client_report: last_client_report
            .ok_or_else(|| "stage83 missing trojan TLS client report".to_owned())?,
        server_summary,
        certificate_der_len,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
    })
}

pub(super) fn apply_stage83_outcome(report: &mut Value, outcome: Stage83Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.tls_handshake_count == outcome.exchange_count
        && outcome.server_summary.alpn_validated_count == outcome.exchange_count
        && outcome.server_summary.password_hash_match_count == outcome.exchange_count
        && outcome.server_summary.tcp_command_count == outcome.exchange_count
        && outcome.server_summary.target_metadata_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let client_complete = outcome.client_report.true_dataplane
        && outcome.client_report.trojan_tls_underlay
        && outcome.client_report.tls_handshake_validated
        && outcome.client_report.certificate_chain_validated
        && outcome.client_report.server_name_validated
        && outcome.client_report.alpn_validated;
    let passed = server_complete && client_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["trojan_tls_smoke_passed"] = json!(passed);
    report["trojan_tls_underlay_admitted"] = json!(passed);
    report["trojan_standard_protocol_true_dataplane_admitted"] = json!(passed);
    report["trojan_protocol_true_dataplane_admitted"] = json!(passed);
    report["trojan_tls_contract"]["server"] = json!(outcome.last_dial_report.peer_addr);
    report["trojan_tls_contract"]["selected_alpn"] = json!(outcome.client_report.selected_alpn);
    report["trojan_tls_contract"]["certificate_der_len"] = json!(outcome.certificate_der_len);
    report["trojan_tls_contract"]["tls_handshake_validated"] = json!(passed);
    report["trojan_tls_contract"]["certificate_chain_validated"] = json!(passed);
    report["trojan_tls_contract"]["server_name_validated"] = json!(passed);
    report["trojan_tls_contract"]["alpn_validated"] = json!(passed);
    report["trojan_tls_contract"]["password_sha224_validated"] = json!(passed);
    report["trojan_tls_contract"]["tcp_command_validated"] = json!(passed);
    report["trojan_tls_contract"]["target_metadata_validated"] = json!(passed);
    report["trojan_tls_contract"]["payload_roundtrip_validated"] = json!(passed);
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
        "password_hash_match_count": outcome.server_summary.password_hash_match_count,
        "tcp_command_count": outcome.server_summary.tcp_command_count,
        "target_metadata_count": outcome.server_summary.target_metadata_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "selected_alpns": outcome.server_summary.selected_alpns,
        "targets": outcome.server_summary.targets,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "response_ascii": outcome.server_summary.response_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_trojan_tls_exchange"] = json!(outcome.ns_per_exchange);
    report["benchmark"]["payload_len"] = json!(outcome.client_report.payload_len);
    report["protocol_matrix"]["trojan_tls_underlay_admitted"] = json!(passed);
    report["protocol_matrix"]["trojan_standard_protocol_true_dataplane_admitted"] = json!(passed);
    report["protocol_matrix"]["trojan_protocol_true_dataplane_admitted"] = json!(passed);
}

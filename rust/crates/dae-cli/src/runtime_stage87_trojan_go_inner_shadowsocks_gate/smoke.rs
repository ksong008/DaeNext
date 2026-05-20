use super::server::*;
use super::*;

#[derive(Debug)]
pub(super) struct Stage87Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    client_report: trojan::TrojanGoInnerShadowsocksTcpExchangeReport,
    server_summary: TrojanGoInnerShadowsocksServerSummary,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
}

pub(super) fn run_stage87_smoke(opts: &Stage87Options) -> Result<Stage87Outcome, String> {
    let spec =
        shadowsocks::cipher_spec(&opts.cipher).map_err(|err| format!("stage87 cipher: {err}"))?;
    let (server_addr, listener_report, handle) =
        spawn_trojan_go_inner_shadowsocks_server(opts, spec.salt_len)?;
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
        .map_err(|err| format!("stage87 magic_tcp_connect failed: {err}"))?;
        let client_salt = salt_for(index, spec.salt_len, 0x31);
        let server_salt = salt_for(index, spec.salt_len, 0x91);
        let report = trojan::tcp_exchange_over_inner_shadowsocks_stream(
            &mut connected.stream,
            &server_addr.to_string(),
            &opts.cipher,
            &opts.shadowsocks_password,
            &opts.trojan_password,
            &opts.target,
            &opts.response_metadata_target,
            &opts.payload,
            AeadTcpSalts {
                client: &client_salt,
                server: &server_salt,
            },
        )
        .map_err(|err| format!("stage87 trojan-go inner Shadowsocks exchange failed: {err}"))?;
        if report.echoed_payload != opts.payload {
            return Err("stage87 trojan-go inner Shadowsocks payload mismatch".to_owned());
        }
        last_dial_report = Some(connected.report);
        last_client_report = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage87 trojan-go inner Shadowsocks server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage87 trojan-go inner Shadowsocks server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage87Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage87 missing underlay dial report".to_owned())?,
        client_report: last_client_report
            .ok_or_else(|| "stage87 missing inner Shadowsocks client report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
    })
}

pub(super) fn apply_stage87_outcome(report: &mut Value, outcome: Stage87Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.decrypt_count == outcome.exchange_count
        && outcome.server_summary.no_request_metadata_count == outcome.exchange_count
        && outcome.server_summary.password_hash_match_count == outcome.exchange_count
        && outcome.server_summary.tcp_command_count == outcome.exchange_count
        && outcome.server_summary.target_metadata_count == outcome.exchange_count
        && outcome.server_summary.response_metadata_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let client_complete = outcome.client_report.true_dataplane
        && outcome.client_report.trojan_go_inner_shadowsocks
        && !outcome.client_report.inner_shadowsocks_is_client
        && !outcome
            .client_report
            .inner_shadowsocks_request_metadata_present
        && outcome.client_report.shadowsocks_chunk_validated;
    let passed = server_complete && client_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["trojan_go_inner_shadowsocks_smoke_passed"] = json!(passed);
    report["trojan_go_inner_shadowsocks_admitted"] = json!(passed);
    report["trojan_go_shared_transport_partial_admitted"] = json!(true);
    report["trojan_go_inner_shadowsocks_contract"]["server"] =
        json!(outcome.last_dial_report.peer_addr);
    report["trojan_go_inner_shadowsocks_contract"]["cipher"] = json!(outcome.client_report.cipher);
    report["trojan_go_inner_shadowsocks_contract"]["client_salt_len"] =
        json!(outcome.client_report.client_salt_len);
    report["trojan_go_inner_shadowsocks_contract"]["server_salt_len"] =
        json!(outcome.client_report.server_salt_len);
    report["trojan_go_inner_shadowsocks_contract"]["inner_shadowsocks_is_client"] =
        json!(outcome.client_report.inner_shadowsocks_is_client);
    report["trojan_go_inner_shadowsocks_contract"]["inner_shadowsocks_request_metadata_present"] = json!(
        outcome
            .client_report
            .inner_shadowsocks_request_metadata_present
    );
    report["trojan_go_inner_shadowsocks_contract"]["inner_shadowsocks_chunk_validated"] =
        json!(passed);
    report["trojan_go_inner_shadowsocks_contract"]["request_has_raw_trojanc_first"] = json!(passed);
    report["trojan_go_inner_shadowsocks_contract"]["response_metadata_validated"] = json!(passed);
    report["trojan_go_inner_shadowsocks_contract"]["password_sha224_validated"] = json!(passed);
    report["trojan_go_inner_shadowsocks_contract"]["tcp_command_validated"] = json!(passed);
    report["trojan_go_inner_shadowsocks_contract"]["target_metadata_validated"] = json!(passed);
    report["trojan_go_inner_shadowsocks_contract"]["payload_roundtrip_validated"] = json!(passed);
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
        "decrypt_count": outcome.server_summary.decrypt_count,
        "no_request_metadata_count": outcome.server_summary.no_request_metadata_count,
        "password_hash_match_count": outcome.server_summary.password_hash_match_count,
        "tcp_command_count": outcome.server_summary.tcp_command_count,
        "target_metadata_count": outcome.server_summary.target_metadata_count,
        "response_metadata_count": outcome.server_summary.response_metadata_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "targets": outcome.server_summary.targets,
        "response_metadata_targets": outcome.server_summary.response_metadata_targets,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "response_ascii": outcome.server_summary.response_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_trojan_go_inner_shadowsocks_exchange"] =
        json!(outcome.ns_per_exchange);
    report["benchmark"]["payload_len"] = json!(outcome.client_report.payload_len);
    report["benchmark"]["trojan_request_header_len"] =
        json!(outcome.client_report.trojan_request_header_len);
    report["benchmark"]["shadowsocks_request_len"] =
        json!(outcome.client_report.shadowsocks_request_len);
    report["benchmark"]["shadowsocks_response_metadata_len"] =
        json!(outcome.client_report.shadowsocks_response_metadata_len);
    report["protocol_matrix"]["trojan_go_inner_shadowsocks_admitted"] = json!(passed);
}

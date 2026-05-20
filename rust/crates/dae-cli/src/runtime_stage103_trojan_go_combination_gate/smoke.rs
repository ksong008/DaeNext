use super::server::*;
use super::*;

#[derive(Debug)]
pub(super) struct Stage103Outcome {
    pub(super) listener_report: TcpLoopbackListenerReport,
    pub(super) last_dial_report: TcpDirectDialReport,
    pub(super) client_report: trojan::TrojanGoWssInnerShadowsocksTcpExchangeReport,
    pub(super) server_summary: TrojanGoCombinationServerSummary,
    pub(super) fragment_stats: shared_transport::TlsFragmentStats,
    pub(super) certificate_der_len: usize,
    pub(super) elapsed_ns: u128,
    pub(super) ns_per_exchange: f64,
    pub(super) exchange_count: usize,
}

pub(super) fn run_stage103_smoke(opts: &Stage103Options) -> Result<Stage103Outcome, String> {
    let spec =
        shadowsocks::cipher_spec(&opts.cipher).map_err(|err| format!("stage103 cipher: {err}"))?;
    let tls_options = opts
        .tls_options()
        .map_err(|err| format!("stage103 tls options invalid: {err}"))?;
    let fragment_options = opts
        .fragment_options()
        .map_err(|err| format!("stage103 tls fragment options invalid: {err}"))?;
    let material = shared_transport::tls_loopback_material(&tls_options)
        .map_err(|err| format!("stage103 build tls material failed: {err}"))?;
    let certificate_der_len = material.certificate_der_len;
    let (server_addr, listener_report, handle) =
        spawn_trojan_go_combination_server(opts, &material, spec.salt_len)?;
    let fragment_stats = shared_transport::new_tls_fragment_stats();
    let mut last_dial_report = None;
    let mut last_client_report = None;
    let start = Instant::now();
    for index in 0..opts.benchmark_iters {
        let connected = magic_tcp_connect(
            server_addr,
            &TcpDirectDialOptions {
                mark: opts.so_mark,
                mptcp: opts.mptcp,
                timeout: opts.timeout,
            },
        )
        .map_err(|err| format!("stage103 magic_tcp_connect failed: {err}"))?;
        let dae_datapath::TcpDirectConnection {
            stream,
            report: dial_report,
        } = connected;
        let fragmented_stream = shared_transport::TlsFragmentingStream::new(
            stream,
            fragment_options.clone(),
            fragment_stats.clone(),
        );
        let client_salt = salt_for(index, spec.salt_len, 0x31);
        let server_salt = salt_for(index, spec.salt_len, 0x91);
        let report = trojan::tcp_exchange_over_wss_inner_shadowsocks_stream(
            fragmented_stream,
            &material,
            &tls_options,
            &server_addr.to_string(),
            &opts.cipher,
            &opts.shadowsocks_password,
            &opts.trojan_password,
            &opts.target,
            &opts.response_metadata_target,
            &opts.ws_host,
            &opts.ws_path,
            &opts.payload,
            AeadTcpSalts {
                client: &client_salt,
                server: &server_salt,
            },
        )
        .map_err(|err| format!("stage103 trojan-go combination exchange failed: {err}"))?;
        if report.echoed_payload != opts.payload {
            return Err("stage103 trojan-go combination payload response mismatch".to_owned());
        }
        last_dial_report = Some(dial_report);
        last_client_report = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage103 trojan-go combination server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage103 trojan-go combination server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage103Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage103 missing underlay dial report".to_owned())?,
        client_report: last_client_report
            .ok_or_else(|| "stage103 missing trojan-go combination client report".to_owned())?,
        server_summary,
        fragment_stats: shared_transport::snapshot_tls_fragment_stats(&fragment_stats),
        certificate_der_len,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
    })
}

pub(super) fn apply_stage103_outcome(report: &mut Value, outcome: Stage103Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.tls_handshake_count == outcome.exchange_count
        && outcome.server_summary.alpn_validated_count == outcome.exchange_count
        && outcome.server_summary.websocket_upgrade_count == outcome.exchange_count
        && outcome.server_summary.websocket_binary_request_count == outcome.exchange_count
        && outcome.server_summary.inner_shadowsocks_decrypt_count == outcome.exchange_count
        && outcome.server_summary.no_request_metadata_count == outcome.exchange_count
        && outcome.server_summary.password_hash_match_count == outcome.exchange_count
        && outcome.server_summary.tcp_command_count == outcome.exchange_count
        && outcome.server_summary.target_metadata_count == outcome.exchange_count
        && outcome.server_summary.response_metadata_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let client_complete = outcome.client_report.true_dataplane
        && outcome.client_report.trojan_go_wss_inner_shadowsocks
        && outcome.client_report.tls_handshake_validated
        && outcome.client_report.certificate_chain_validated
        && outcome.client_report.server_name_validated
        && outcome.client_report.alpn_validated
        && outcome.client_report.websocket_handshake_validated
        && outcome.client_report.websocket_binary_frame_validated
        && outcome.client_report.inner_shadowsocks_validated;
    let fragment_complete = outcome.fragment_stats.handshake_record_fragmented()
        && outcome.fragment_stats.total_fragment_records() >= outcome.exchange_count * 2
        && outcome.fragment_stats.all_fragmented_writes_reassembled();
    let passed = server_complete
        && client_complete
        && fragment_complete
        && so_mark_observed
        && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["trojan_go_wss_tls_fragment_inner_shadowsocks_combination_smoke_passed"] = json!(passed);
    report["trojan_go_wss_tls_fragment_inner_shadowsocks_combination_admitted"] = json!(passed);
    report["trojan_go_shared_transport_partial_admitted"] = json!(passed);
    report["combination_contract"]["server"] = json!(outcome.last_dial_report.peer_addr);
    report["combination_contract"]["selected_alpn"] = json!(outcome.client_report.selected_alpn);
    report["combination_contract"]["certificate_der_len"] = json!(outcome.certificate_der_len);
    report["combination_contract"]["tls_handshake_validated"] = json!(passed);
    report["combination_contract"]["certificate_chain_validated"] = json!(passed);
    report["combination_contract"]["server_name_validated"] = json!(passed);
    report["combination_contract"]["alpn_validated"] = json!(passed);
    report["combination_contract"]["websocket_upgrade_validated"] = json!(passed);
    report["combination_contract"]["websocket_binary_frame_validated"] = json!(passed);
    report["combination_contract"]["inner_shadowsocks_decrypt_validated"] = json!(passed);
    report["combination_contract"]["inner_shadowsocks_is_client"] = json!(false);
    report["combination_contract"]["inner_shadowsocks_request_metadata_present"] = json!(false);
    report["combination_contract"]["response_metadata_validated"] = json!(passed);
    report["combination_contract"]["password_sha224_validated"] = json!(passed);
    report["combination_contract"]["tcp_command_validated"] = json!(passed);
    report["combination_contract"]["target_metadata_validated"] = json!(passed);
    report["combination_contract"]["payload_roundtrip_validated"] = json!(passed);
    report["combination_contract"]["fragmented_write_count"] =
        json!(outcome.fragment_stats.fragmented_write_count());
    report["combination_contract"]["fragment_record_count"] =
        json!(outcome.fragment_stats.total_fragment_records());
    report["combination_contract"]["handshake_record_fragmented"] =
        json!(outcome.fragment_stats.handshake_record_fragmented());
    report["combination_contract"]["fragment_payload_lens"] =
        json!(outcome.fragment_stats.fragment_payload_lens());
    report["combination_contract"]["reassembled_record_matches"] =
        json!(outcome.fragment_stats.all_fragmented_writes_reassembled());
    if let Some(first) = outcome.fragment_stats.first_fragmented_write() {
        report["combination_contract"]["first_fragmented_write"] = json!({
            "input_len": first.input_len,
            "output_len": first.output_len,
            "original_record_len": first.original_record_len,
            "original_payload_len": first.original_payload_len,
            "trailing_len": first.trailing_len,
            "fragment_record_count": first.fragment_record_count,
            "fragment_payload_lens": first.fragment_payload_lens,
            "interval_enabled": first.interval_enabled,
            "reassembled_record_matches": first.reassembled_record_matches
        });
    }
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
        "websocket_upgrade_count": outcome.server_summary.websocket_upgrade_count,
        "websocket_binary_request_count": outcome.server_summary.websocket_binary_request_count,
        "inner_shadowsocks_decrypt_count": outcome.server_summary.inner_shadowsocks_decrypt_count,
        "no_request_metadata_count": outcome.server_summary.no_request_metadata_count,
        "password_hash_match_count": outcome.server_summary.password_hash_match_count,
        "tcp_command_count": outcome.server_summary.tcp_command_count,
        "target_metadata_count": outcome.server_summary.target_metadata_count,
        "response_metadata_count": outcome.server_summary.response_metadata_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "selected_alpns": outcome.server_summary.selected_alpns,
        "targets": outcome.server_summary.targets,
        "ws_hosts": outcome.server_summary.ws_hosts,
        "ws_paths": outcome.server_summary.ws_paths,
        "response_metadata_targets": outcome.server_summary.response_metadata_targets,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "response_ascii": outcome.server_summary.response_ascii,
        "websocket_request_frame_lens": outcome.server_summary.websocket_request_frame_lens
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_trojan_go_combination_exchange"] = json!(outcome.ns_per_exchange);
    report["benchmark"]["payload_len"] = json!(outcome.client_report.payload_len);
    report["benchmark"]["websocket_request_frame_len"] =
        json!(outcome.client_report.websocket_request_frame_len);
    report["benchmark"]["websocket_response_payload_len"] =
        json!(outcome.client_report.websocket_response_payload_len);
    report["benchmark"]["client_salt_len"] = json!(outcome.client_report.client_salt_len);
    report["benchmark"]["server_salt_len"] = json!(outcome.client_report.server_salt_len);
    report["protocol_matrix"]["trojan_go_wss_tls_fragment_inner_shadowsocks_combination_admitted"] =
        json!(passed);
    report["protocol_matrix"]["trojan_go_shared_transport_partial_admitted"] = json!(passed);
}

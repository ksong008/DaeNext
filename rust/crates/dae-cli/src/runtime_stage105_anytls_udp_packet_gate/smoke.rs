use super::server::*;
use super::*;

#[derive(Debug)]
pub(super) struct Stage105Outcome {
    pub(super) listener_report: TcpLoopbackListenerReport,
    pub(super) last_dial_report: TcpDirectDialReport,
    pub(super) client_report: anytls::AnyTlsUdpPacketStreamExchangeReport,
    pub(super) server_summary: AnyTlsUdpPacketServerSummary,
    pub(super) certificate_der_len: usize,
    pub(super) elapsed_ns: u128,
    pub(super) ns_per_exchange: f64,
    pub(super) exchange_count: usize,
}

pub(super) fn run_stage105_smoke(opts: &Stage105Options) -> Result<Stage105Outcome, String> {
    let tls_options = opts
        .tls_options()
        .map_err(|err| format!("stage105 tls options invalid: {err}"))?;
    let material = shared_transport::tls_loopback_material(&tls_options)
        .map_err(|err| format!("stage105 build tls material failed: {err}"))?;
    let certificate_der_len = material.certificate_der_len;
    let (server_addr, listener_report, handle) = spawn_anytls_udp_packet_server(opts, &material)?;
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
        .map_err(|err| format!("stage105 magic_tcp_connect failed: {err}"))?;
        let dae_datapath::TcpDirectConnection {
            stream,
            report: dial_report,
        } = connected;
        let report = anytls::udp_packet_stream_exchange_over_tls_stream(
            stream,
            &material,
            &tls_options,
            &server_addr.to_string(),
            &opts.auth,
            &opts.original_udp_target,
            &opts.first_payload,
            &opts.next_payload,
        )
        .map_err(|err| format!("stage105 anytls UDP packet exchange failed: {err}"))?;
        if report.echoed_first_payload != opts.first_payload {
            return Err("stage105 anytls first UDP packet response mismatch".to_owned());
        }
        if report.echoed_next_payload != opts.next_payload {
            return Err("stage105 anytls next UDP packet response mismatch".to_owned());
        }
        last_dial_report = Some(dial_report);
        last_client_report = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage105 anytls server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage105 anytls server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage105Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage105 missing underlay dial report".to_owned())?,
        client_report: last_client_report
            .ok_or_else(|| "stage105 missing anytls client report".to_owned())?,
        server_summary,
        certificate_der_len,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
    })
}

pub(super) fn apply_stage105_outcome(report: &mut Value, outcome: Stage105Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.tls_handshake_count == outcome.exchange_count
        && outcome.server_summary.alpn_validated_count == outcome.exchange_count
        && outcome.server_summary.auth_key_match_count == outcome.exchange_count
        && outcome.server_summary.settings_frame_count == outcome.exchange_count
        && outcome.server_summary.syn_frame_count == outcome.exchange_count
        && outcome.server_summary.psh_magic_target_frame_count == outcome.exchange_count
        && outcome.server_summary.first_packet_frame_count == outcome.exchange_count
        && outcome.server_summary.next_packet_frame_count == outcome.exchange_count
        && outcome.server_summary.synack_response_count == outcome.exchange_count
        && outcome.server_summary.first_packet_response_count == outcome.exchange_count
        && outcome.server_summary.next_packet_response_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let client_complete = outcome.client_report.true_dataplane
        && outcome.client_report.anytls_udp_packet_stream
        && outcome.client_report.tls_handshake_validated
        && outcome.client_report.certificate_chain_validated
        && outcome.client_report.server_name_validated
        && outcome.client_report.alpn_validated
        && outcome.client_report.auth_key_validated
        && outcome.client_report.settings_validated
        && outcome.client_report.syn_validated
        && outcome.client_report.psh_magic_target_validated
        && outcome.client_report.synack_validated
        && outcome.client_report.udp_magic_domain_validated
        && outcome.client_report.first_write_target_validated
        && outcome.client_report.first_write_payload_validated
        && outcome.client_report.next_write_payload_validated
        && outcome.client_report.payload_roundtrip_validated;
    let passed = server_complete && client_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["anytls_udp_packet_stream_smoke_passed"] = json!(passed);
    report["anytls_udp_packet_stream_true_dataplane_admitted"] = json!(passed);
    report["anytls_contract"]["server"] = json!(outcome.last_dial_report.peer_addr);
    report["anytls_contract"]["selected_alpn"] = json!(outcome.client_report.selected_alpn);
    report["anytls_contract"]["certificate_der_len"] = json!(outcome.certificate_der_len);
    report["anytls_contract"]["tls_handshake_validated"] = json!(passed);
    report["anytls_contract"]["certificate_chain_validated"] = json!(passed);
    report["anytls_contract"]["server_name_validated"] = json!(passed);
    report["anytls_contract"]["alpn_validated"] = json!(passed);
    report["anytls_contract"]["auth_key_validated"] = json!(passed);
    report["anytls_contract"]["settings_validated"] = json!(passed);
    report["anytls_contract"]["syn_validated"] = json!(passed);
    report["anytls_contract"]["psh_magic_target_validated"] = json!(passed);
    report["anytls_contract"]["synack_validated"] = json!(passed);
    report["anytls_contract"]["udp_magic_domain_validated"] = json!(passed);
    report["anytls_contract"]["first_write_target_validated"] = json!(passed);
    report["anytls_contract"]["first_write_payload_validated"] = json!(passed);
    report["anytls_contract"]["next_write_payload_validated"] = json!(passed);
    report["anytls_contract"]["payload_roundtrip_validated"] = json!(passed);
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
        "auth_key_match_count": outcome.server_summary.auth_key_match_count,
        "settings_frame_count": outcome.server_summary.settings_frame_count,
        "syn_frame_count": outcome.server_summary.syn_frame_count,
        "psh_magic_target_frame_count": outcome.server_summary.psh_magic_target_frame_count,
        "first_packet_frame_count": outcome.server_summary.first_packet_frame_count,
        "next_packet_frame_count": outcome.server_summary.next_packet_frame_count,
        "synack_response_count": outcome.server_summary.synack_response_count,
        "first_packet_response_count": outcome.server_summary.first_packet_response_count,
        "next_packet_response_count": outcome.server_summary.next_packet_response_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "selected_alpns": outcome.server_summary.selected_alpns,
        "stream_targets": outcome.server_summary.stream_targets,
        "original_udp_targets": outcome.server_summary.original_udp_targets,
        "first_payload_ascii": outcome.server_summary.first_payload_ascii,
        "next_payload_ascii": outcome.server_summary.next_payload_ascii,
        "response_first_ascii": outcome.server_summary.response_first_ascii,
        "response_next_ascii": outcome.server_summary.response_next_ascii,
        "settings_frame_lens": outcome.server_summary.settings_frame_lens,
        "psh_magic_target_frame_lens": outcome.server_summary.psh_magic_target_frame_lens,
        "first_packet_frame_lens": outcome.server_summary.first_packet_frame_lens,
        "next_packet_frame_lens": outcome.server_summary.next_packet_frame_lens
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_anytls_udp_packet_stream_exchange"] =
        json!(outcome.ns_per_exchange);
    report["benchmark"]["first_payload_len"] = json!(outcome.client_report.first_payload_len);
    report["benchmark"]["next_payload_len"] = json!(outcome.client_report.next_payload_len);
    report["benchmark"]["settings_frame_len"] = json!(outcome.client_report.settings_frame_len);
    report["benchmark"]["psh_addr_frame_len"] = json!(outcome.client_report.psh_addr_frame_len);
    report["benchmark"]["first_packet_frame_len"] =
        json!(outcome.client_report.first_packet_frame_len);
    report["benchmark"]["next_packet_frame_len"] =
        json!(outcome.client_report.next_packet_frame_len);
    report["protocol_matrix"]["anytls_udp_packet_stream_true_dataplane_admitted"] = json!(passed);
}

use super::server::*;
use super::*;

#[derive(Debug)]
pub(super) struct Stage94Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    client_report: shadowsocks::Sip003V2rayPluginExchangeReport,
    server_summary: Sip003V2rayPluginServerSummary,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
    certificate_der_len: usize,
}

pub(super) fn run_stage94_smoke(opts: &Stage94Options) -> Result<Stage94Outcome, String> {
    let spec = shadowsocks::cipher_spec(&opts.cipher)
        .map_err(|err| format!("stage94 unsupported AEAD cipher: {err}"))?;
    let plugin_options = shadowsocks::Sip003V2rayPluginOptions::new(
        &opts.tls_server_name,
        &opts.tls_alpn,
        &opts.ws_host,
        &opts.ws_path,
    )
    .map_err(|err| format!("stage94 v2ray-plugin options invalid: {err}"))?;
    let material = shared_transport::tls_loopback_material(&plugin_options.tls)
        .map_err(|err| format!("stage94 TLS loopback material failed: {err}"))?;
    let certificate_der_len = material.certificate_der_len;
    let (server_addr, listener_report, handle) =
        spawn_sip003_v2ray_plugin_server(opts, &plugin_options, &material)?;
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
        .map_err(|err| format!("stage94 magic_tcp_connect failed: {err}"))?;
        let client_salt = salt_for(index, spec.salt_len, 0x41);
        let server_salt = salt_for(index, spec.salt_len, 0x81);
        let report = shadowsocks::v2ray_plugin_tls_ws_mux_shadowsocks_aead_exchange_over_stream(
            connected.stream,
            &material,
            &plugin_options,
            &server_addr.to_string(),
            &opts.cipher,
            &opts.password,
            &opts.target,
            &opts.payload,
            AeadTcpSalts {
                client: &client_salt,
                server: &server_salt,
            },
        )
        .map_err(|err| format!("stage94 SIP003 v2ray-plugin exchange failed: {err}"))?;
        if report.inner.echoed_payload != opts.payload {
            return Err("stage94 SIP003 v2ray-plugin payload mismatch".to_owned());
        }
        last_dial_report = Some(connected.report);
        last_client_report = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage94 SIP003 v2ray-plugin server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage94 SIP003 v2ray-plugin server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage94Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage94 missing underlay dial report".to_owned())?,
        client_report: last_client_report
            .ok_or_else(|| "stage94 missing SIP003 v2ray-plugin client report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
        certificate_der_len,
    })
}

pub(super) fn apply_stage94_outcome(report: &mut Value, outcome: Stage94Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.tls_handshake_count == outcome.exchange_count
        && outcome.server_summary.websocket_handshake_count == outcome.exchange_count
        && outcome.server_summary.websocket_host_match_count == outcome.exchange_count
        && outcome.server_summary.mux_new_frame_count == outcome.exchange_count
        && outcome.server_summary.mux_data_frame_count == outcome.exchange_count
        && outcome.server_summary.inner_decrypt_count == outcome.exchange_count
        && outcome.server_summary.target_metadata_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count
        && outcome.server_summary.response_count == outcome.exchange_count;
    let client_complete = outcome.client_report.plugin_name == "v2ray-plugin"
        && outcome.client_report.tls_enabled
        && outcome.client_report.websocket_enabled
        && outcome.client_report.mux_enabled
        && outcome.client_report.tls_handshake_validated
        && outcome.client_report.certificate_chain_validated
        && outcome.client_report.server_name_validated
        && outcome.client_report.alpn_validated
        && outcome.client_report.websocket_handshake_validated
        && outcome.client_report.websocket_binary_frame_validated
        && outcome.client_report.mux_new_frame_validated
        && outcome.client_report.mux_data_frame_validated
        && outcome.client_report.tls_passthrough_udp
        && outcome.client_report.ws_passthrough_udp
        && outcome.client_report.mux_passthrough_udp
        && outcome.client_report.inner.true_dataplane
        && outcome.client_report.inner.default_go_path;
    let passed = server_complete && client_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["sip003_v2ray_plugin_smoke_passed"] = json!(passed);
    report["sip003_v2ray_plugin_admitted"] = json!(passed);
    report["sip003_plugin_transport_admitted"] = json!(passed);
    report["sip003_contract"]["server"] = json!(outcome.last_dial_report.peer_addr);
    report["sip003_contract"]["selected_alpn"] = json!(outcome.client_report.selected_alpn);
    report["sip003_contract"]["tls_handshake_validated"] =
        json!(outcome.client_report.tls_handshake_validated);
    report["sip003_contract"]["certificate_chain_validated"] =
        json!(outcome.client_report.certificate_chain_validated);
    report["sip003_contract"]["server_name_validated"] =
        json!(outcome.client_report.server_name_validated);
    report["sip003_contract"]["alpn_validated"] = json!(outcome.client_report.alpn_validated);
    report["sip003_contract"]["websocket_handshake_validated"] =
        json!(outcome.client_report.websocket_handshake_validated);
    report["sip003_contract"]["websocket_binary_frame_validated"] =
        json!(outcome.client_report.websocket_binary_frame_validated);
    report["sip003_contract"]["mux"]["id_hex"] = json!(outcome.client_report.mux_id_hex);
    report["sip003_contract"]["mux"]["host"] = json!(outcome.client_report.mux_host);
    report["sip003_contract"]["mux"]["port"] = json!(outcome.client_report.mux_port);
    report["sip003_contract"]["mux"]["network"] = json!(outcome.client_report.mux_network);
    report["sip003_contract"]["mux"]["new_frame_validated"] =
        json!(outcome.client_report.mux_new_frame_validated);
    report["sip003_contract"]["mux"]["data_frame_validated"] =
        json!(outcome.client_report.mux_data_frame_validated);
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
        "tls_handshake_count": outcome.server_summary.tls_handshake_count,
        "websocket_handshake_count": outcome.server_summary.websocket_handshake_count,
        "websocket_host_match_count": outcome.server_summary.websocket_host_match_count,
        "mux_new_frame_count": outcome.server_summary.mux_new_frame_count,
        "mux_data_frame_count": outcome.server_summary.mux_data_frame_count,
        "inner_decrypt_count": outcome.server_summary.inner_decrypt_count,
        "target_metadata_count": outcome.server_summary.target_metadata_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "response_count": outcome.server_summary.response_count,
        "selected_alpns": outcome.server_summary.selected_alpns,
        "ws_hosts": outcome.server_summary.ws_hosts,
        "ws_paths": outcome.server_summary.ws_paths,
        "mux_ids": outcome.server_summary.mux_ids,
        "mux_metadata_lengths": outcome.server_summary.mux_metadata_lengths,
        "websocket_payload_lengths": outcome.server_summary.websocket_payload_lengths,
        "targets": outcome.server_summary.targets,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "certificate_der_len": outcome.certificate_der_len
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_sip003_v2ray_plugin_exchange"] = json!(outcome.ns_per_exchange);
    report["benchmark"]["exchange_count"] = json!(outcome.exchange_count);
    report["benchmark"]["payload_len"] = json!(outcome.client_report.inner.payload_len);
    report["benchmark"]["websocket_request_frame_len"] =
        json!(outcome.client_report.websocket_request_frame_len);
    report["benchmark"]["mux_request_payload_len"] =
        json!(outcome.client_report.mux_request_payload_len);
    report["benchmark"]["mux_response_payload_len"] =
        json!(outcome.client_report.mux_response_payload_len);
    report["protocol_matrix"]["sip003_v2ray_plugin_admitted"] = json!(passed);
    report["protocol_matrix"]["sip003_plugin_transport_admitted"] = json!(passed);
}

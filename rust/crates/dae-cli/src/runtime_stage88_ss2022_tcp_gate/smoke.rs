use super::server::*;
use super::*;

#[derive(Debug)]
pub(super) struct Stage88Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    client_report: shadowsocks::Ss2022TcpExchangeReport,
    server_summary: Ss2022TcpServerSummary,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
}

pub(super) fn run_stage88_smoke(opts: &Stage88Options) -> Result<Stage88Outcome, String> {
    let conf = shadowsocks::ss2022::cipher_conf(&opts.cipher)
        .ok_or_else(|| format!("stage88 unsupported SS2022 cipher: {}", opts.cipher))?;
    let (server_addr, listener_report, handle) = spawn_ss2022_tcp_server(opts, conf.salt_len)?;
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
        .map_err(|err| format!("stage88 magic_tcp_connect failed: {err}"))?;
        let client_salt = salt_for(index, conf.salt_len, 0x41);
        let server_salt = salt_for(index, conf.salt_len, 0x81);
        let report = shadowsocks::ss2022_tcp_exchange_over_stream(
            &mut connected.stream,
            &server_addr.to_string(),
            &opts.cipher,
            &opts.password,
            &opts.target,
            &opts.payload,
            Ss2022TcpSalts {
                client: &client_salt,
                server: &server_salt,
            },
        )
        .map_err(|err| format!("stage88 SS2022 TCP exchange failed: {err}"))?;
        if report.echoed_payload != opts.payload {
            return Err("stage88 SS2022 TCP payload mismatch".to_owned());
        }
        last_dial_report = Some(connected.report);
        last_client_report = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage88 SS2022 TCP server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage88 SS2022 TCP server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage88Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage88 missing underlay dial report".to_owned())?,
        client_report: last_client_report
            .ok_or_else(|| "stage88 missing SS2022 TCP client report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
    })
}

pub(super) fn apply_stage88_outcome(report: &mut Value, outcome: Stage88Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.decrypt_count == outcome.exchange_count
        && outcome.server_summary.single_psk_count == outcome.exchange_count
        && outcome.server_summary.upsk_last_count == outcome.exchange_count
        && outcome.server_summary.no_identity_header_count == outcome.exchange_count
        && outcome.server_summary.request_header_count == outcome.exchange_count
        && outcome.server_summary.target_metadata_count == outcome.exchange_count
        && outcome.server_summary.request_salt_echo_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let client_complete = outcome.client_report.true_dataplane
        && outcome.client_report.psk_count == 1
        && outcome.client_report.upsk_index == 0
        && outcome.client_report.request_salt_echo_validated
        && !outcome
            .client_report
            .multi_psk_identity_header_dataplane_admitted
        && !outcome.client_report.ss2022_udp_true_dataplane_admitted;
    let passed = server_complete && client_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["ss2022_tcp_smoke_passed"] = json!(passed);
    report["ss2022_tcp_true_dataplane_admitted"] = json!(passed);
    report["ss2022_contract"]["server"] = json!(outcome.last_dial_report.peer_addr);
    report["ss2022_contract"]["cipher"] = json!(outcome.client_report.cipher);
    report["ss2022_contract"]["psk_count"] = json!(outcome.client_report.psk_count);
    report["ss2022_contract"]["upsk_index"] = json!(outcome.client_report.upsk_index);
    report["ss2022_contract"]["key_len"] = json!(outcome.client_report.key_len);
    report["ss2022_contract"]["client_salt_len"] = json!(outcome.client_report.client_salt_len);
    report["ss2022_contract"]["server_salt_len"] = json!(outcome.client_report.server_salt_len);
    report["ss2022_contract"]["request_header_type"] =
        json!(outcome.client_report.request_header_type);
    report["ss2022_contract"]["response_header_type"] =
        json!(outcome.client_report.response_header_type);
    report["ss2022_contract"]["fixed_header_len"] = json!(outcome.client_report.fixed_header_len);
    report["ss2022_contract"]["variable_header_len"] =
        json!(outcome.client_report.variable_header_len);
    report["ss2022_contract"]["target_metadata_len"] =
        json!(outcome.client_report.target_metadata_len);
    report["ss2022_contract"]["request_salt_echo_validated"] =
        json!(outcome.client_report.request_salt_echo_validated);
    report["ss2022_contract"]["payload_roundtrip_validated"] = json!(passed);
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
        "single_psk_count": outcome.server_summary.single_psk_count,
        "upsk_last_count": outcome.server_summary.upsk_last_count,
        "no_identity_header_count": outcome.server_summary.no_identity_header_count,
        "request_header_count": outcome.server_summary.request_header_count,
        "target_metadata_count": outcome.server_summary.target_metadata_count,
        "request_salt_echo_count": outcome.server_summary.request_salt_echo_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "targets": outcome.server_summary.targets,
        "payload_ascii": outcome.server_summary.payload_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_ss2022_tcp_exchange"] = json!(outcome.ns_per_exchange);
    report["benchmark"]["payload_len"] = json!(outcome.client_report.payload_len);
    report["benchmark"]["fixed_header_len"] = json!(outcome.client_report.fixed_header_len);
    report["benchmark"]["variable_header_len"] = json!(outcome.client_report.variable_header_len);
    report["benchmark"]["target_metadata_len"] = json!(outcome.client_report.target_metadata_len);
    report["protocol_matrix"]["ss2022_tcp_true_dataplane_admitted"] = json!(passed);
}

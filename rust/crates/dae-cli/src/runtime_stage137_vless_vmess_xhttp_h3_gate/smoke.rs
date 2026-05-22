use super::*;

#[derive(Debug)]
pub(super) struct Stage137Outcome {
    vless_report: vless::VlessXHttpH3ExchangeReport,
    vmess_report: vmess::VMessAeadXHttpH3ExchangeReport,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
}

pub(super) fn run_stage137_smoke(opts: &Stage137Options) -> Result<Stage137Outcome, String> {
    let vless_key = vless::password_to_key(&opts.vless_uuid)
        .map_err(|err| format!("stage137 vless uuid is invalid: {err}"))?;
    let mut last_vless = None;
    let mut last_vmess = None;
    let start = Instant::now();
    for index in 0..opts.benchmark_iters {
        let seq = opts.xhttp_seq + index as u64;
        last_vless = Some(run_vless_once(opts, vless_key, seq)?);
        last_vmess = Some(run_vmess_once(opts, seq + 10_000)?);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let exchange_count = opts.benchmark_iters * 2;
    Ok(Stage137Outcome {
        vless_report: last_vless
            .ok_or_else(|| "stage137 missing VLESS xHTTP H3 report".to_owned())?,
        vmess_report: last_vmess
            .ok_or_else(|| "stage137 missing VMess xHTTP H3 report".to_owned())?,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / exchange_count as f64,
        exchange_count,
    })
}

fn run_vless_once(
    opts: &Stage137Options,
    key: [u8; 16],
    seq: u64,
) -> Result<vless::VlessXHttpH3ExchangeReport, String> {
    let xhttp = opts
        .xhttp_options_for_seq(seq)
        .map_err(|err| format!("stage137 VLESS xhttp options invalid: {err}"))?;
    vless::tcp_exchange_over_xhttp_h3_loopback(
        &opts.xhttp_host,
        &key,
        &opts.vless_target,
        &xhttp,
        &opts.vless_payload,
        1,
        opts.timeout,
    )
    .map_err(|err| format!("stage137 VLESS H3 exchange failed: {err}"))
}

fn run_vmess_once(
    opts: &Stage137Options,
    seq: u64,
) -> Result<vmess::VMessAeadXHttpH3ExchangeReport, String> {
    let xhttp = opts
        .xhttp_options_for_seq(seq)
        .map_err(|err| format!("stage137 VMess xhttp options invalid: {err}"))?;
    vmess::aead_tcp_exchange_over_xhttp_h3_loopback(
        &opts.xhttp_host,
        &opts.vmess_uuid,
        &opts.vmess_target,
        &xhttp,
        &opts.vmess_payload,
        1,
        opts.timeout,
    )
    .map_err(|err| format!("stage137 VMess H3 exchange failed: {err}"))
}

pub(super) fn apply_stage137_outcome(report: &mut Value, outcome: Stage137Outcome) {
    let vless_passed = outcome.vless_report.true_dataplane
        && outcome.vless_report.quic_handshake_validated
        && outcome.vless_report.xhttp_h3_packet_up_validated
        && outcome.vless_report.h3_request_response_validated
        && outcome.vless_report.client_selected_alpn == shared_transport::XHTTP_H3_ALPN
        && outcome.vless_report.server_selected_alpn == shared_transport::XHTTP_H3_ALPN
        && outcome.vless_report.tls13_only_configured
        && outcome.vless_report.quic_datagram_disabled
        && outcome.vless_report.h3_status == 200
        && outcome.vless_report.reality_h3_rejected;
    let vmess_passed = outcome.vmess_report.true_dataplane
        && outcome.vmess_report.quic_handshake_validated
        && outcome.vmess_report.xhttp_h3_packet_up_validated
        && outcome.vmess_report.h3_request_response_validated
        && outcome.vmess_report.client_selected_alpn == shared_transport::XHTTP_H3_ALPN
        && outcome.vmess_report.server_selected_alpn == shared_transport::XHTTP_H3_ALPN
        && outcome.vmess_report.tls13_only_configured
        && outcome.vmess_report.quic_datagram_disabled
        && outcome.vmess_report.h3_status == 200
        && outcome.vmess_report.reality_rejected_for_vmess;
    let passed = vless_passed && vmess_passed;

    report["read_only"] = json!(false);
    report["vless_xhttp_h3_lifecycle_smoke_passed"] = json!(vless_passed);
    report["vmess_xhttp_h3_lifecycle_smoke_passed"] = json!(vmess_passed);
    report["vless_vmess_xhttp_h3_lifecycle_smoke_passed"] = json!(passed);
    report["vless_xhttp_h3_lifecycle_admitted"] = json!(vless_passed);
    report["vmess_xhttp_h3_lifecycle_admitted"] = json!(vmess_passed);
    report["vless_xhttp_h2_h3_lifecycle_admitted"] = json!(vless_passed);
    report["vmess_xhttp_h2_h3_lifecycle_admitted"] = json!(vmess_passed);

    report["vless_vmess_xhttp_h3_contract"]["vless"]["request_header_len"] =
        json!(outcome.vless_report.request_header_len);
    report["vless_vmess_xhttp_h3_contract"]["vless"]["response_header_len"] =
        json!(outcome.vless_report.response_header_len);
    report["vless_vmess_xhttp_h3_contract"]["vless"]["xhttp_request_body_len"] =
        json!(outcome.vless_report.xhttp_request_body_len);
    report["vless_vmess_xhttp_h3_contract"]["vless"]["xhttp_response_body_len"] =
        json!(outcome.vless_report.xhttp_response_body_len);
    report["vless_vmess_xhttp_h3_contract"]["vless"]["client_selected_alpn"] =
        json!(outcome.vless_report.client_selected_alpn);
    report["vless_vmess_xhttp_h3_contract"]["vless"]["server_selected_alpn"] =
        json!(outcome.vless_report.server_selected_alpn);
    report["vless_vmess_xhttp_h3_contract"]["vless"]["certificate_der_len"] =
        json!(outcome.vless_report.certificate_der_len);
    report["vless_vmess_xhttp_h3_contract"]["vless"]["h3_status"] =
        json!(outcome.vless_report.h3_status);
    report["vless_vmess_xhttp_h3_contract"]["vless"]["h3_lifecycle_validated"] =
        json!(vless_passed);
    report["vless_vmess_xhttp_h3_contract"]["vless"]["payload_roundtrip_validated"] =
        json!(vless_passed);
    report["vless_vmess_xhttp_h3_contract"]["vmess"]["cmd_key_hex"] =
        json!(outcome.vmess_report.cmd_key_hex);
    report["vless_vmess_xhttp_h3_contract"]["vmess"]["request_header_len"] =
        json!(outcome.vmess_report.request_header_len);
    report["vless_vmess_xhttp_h3_contract"]["vmess"]["request_chunk_len"] =
        json!(outcome.vmess_report.request_chunk_len);
    report["vless_vmess_xhttp_h3_contract"]["vmess"]["response_header_len"] =
        json!(outcome.vmess_report.response_header_len);
    report["vless_vmess_xhttp_h3_contract"]["vmess"]["response_chunk_len"] =
        json!(outcome.vmess_report.response_chunk_len);
    report["vless_vmess_xhttp_h3_contract"]["vmess"]["xhttp_request_body_len"] =
        json!(outcome.vmess_report.xhttp_request_body_len);
    report["vless_vmess_xhttp_h3_contract"]["vmess"]["xhttp_response_body_len"] =
        json!(outcome.vmess_report.xhttp_response_body_len);
    report["vless_vmess_xhttp_h3_contract"]["vmess"]["client_selected_alpn"] =
        json!(outcome.vmess_report.client_selected_alpn);
    report["vless_vmess_xhttp_h3_contract"]["vmess"]["server_selected_alpn"] =
        json!(outcome.vmess_report.server_selected_alpn);
    report["vless_vmess_xhttp_h3_contract"]["vmess"]["certificate_der_len"] =
        json!(outcome.vmess_report.certificate_der_len);
    report["vless_vmess_xhttp_h3_contract"]["vmess"]["h3_status"] =
        json!(outcome.vmess_report.h3_status);
    report["vless_vmess_xhttp_h3_contract"]["vmess"]["h3_lifecycle_validated"] =
        json!(vmess_passed);
    report["vless_vmess_xhttp_h3_contract"]["vmess"]["payload_roundtrip_validated"] =
        json!(vmess_passed);

    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["iterations_per_protocol"] = json!(outcome.exchange_count / 2);
    report["benchmark"]["total_exchange_count"] = json!(outcome.exchange_count);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_vless_vmess_xhttp_h3_exchange"] = json!(outcome.ns_per_exchange);
    report["benchmark"]["vless_payload_len"] = json!(outcome.vless_report.payload_len);
    report["benchmark"]["vmess_payload_len"] = json!(outcome.vmess_report.payload_len);
    report["benchmark"]["vless_xhttp_request_path"] =
        json!(outcome.vless_report.xhttp_request_path);
    report["benchmark"]["vmess_xhttp_request_path"] =
        json!(outcome.vmess_report.xhttp_request_path);
    report["benchmark"]["vless_xhttp_request_body_len"] =
        json!(outcome.vless_report.xhttp_request_body_len);
    report["benchmark"]["vless_xhttp_response_body_len"] =
        json!(outcome.vless_report.xhttp_response_body_len);
    report["benchmark"]["vmess_xhttp_request_body_len"] =
        json!(outcome.vmess_report.xhttp_request_body_len);
    report["benchmark"]["vmess_xhttp_response_body_len"] =
        json!(outcome.vmess_report.xhttp_response_body_len);
    report["benchmark"]["vless_client_selected_alpn"] =
        json!(outcome.vless_report.client_selected_alpn);
    report["benchmark"]["vless_server_selected_alpn"] =
        json!(outcome.vless_report.server_selected_alpn);
    report["benchmark"]["vmess_client_selected_alpn"] =
        json!(outcome.vmess_report.client_selected_alpn);
    report["benchmark"]["vmess_server_selected_alpn"] =
        json!(outcome.vmess_report.server_selected_alpn);
    report["benchmark"]["vless_certificate_der_len"] =
        json!(outcome.vless_report.certificate_der_len);
    report["benchmark"]["vmess_certificate_der_len"] =
        json!(outcome.vmess_report.certificate_der_len);
    report["benchmark"]["vless_h3_status"] = json!(outcome.vless_report.h3_status);
    report["benchmark"]["vmess_h3_status"] = json!(outcome.vmess_report.h3_status);

    report["protocol_matrix"]["vless_xhttp_h3_lifecycle_admitted"] = json!(vless_passed);
    report["protocol_matrix"]["vmess_xhttp_h3_lifecycle_admitted"] = json!(vmess_passed);
    report["protocol_matrix"]["vless_xhttp_h2_h3_lifecycle_admitted"] = json!(vless_passed);
    report["protocol_matrix"]["vmess_xhttp_h2_h3_lifecycle_admitted"] = json!(vmess_passed);
}

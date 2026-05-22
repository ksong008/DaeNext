use super::*;

#[derive(Debug)]
pub(super) struct Stage136Outcome {
    vless_report: vless::VlessXHttpHttp2ExchangeReport,
    vmess_report: vmess::VMessAeadXHttpHttp2ExchangeReport,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
}

pub(super) fn run_stage136_smoke(opts: &Stage136Options) -> Result<Stage136Outcome, String> {
    let vless_key = vless::password_to_key(&opts.vless_uuid)
        .map_err(|err| format!("stage136 vless uuid is invalid: {err}"))?;
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
    Ok(Stage136Outcome {
        vless_report: last_vless
            .ok_or_else(|| "stage136 missing VLESS xHTTP HTTP/2 report".to_owned())?,
        vmess_report: last_vmess
            .ok_or_else(|| "stage136 missing VMess xHTTP HTTP/2 report".to_owned())?,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / exchange_count as f64,
        exchange_count,
    })
}

fn run_vless_once(
    opts: &Stage136Options,
    key: [u8; 16],
    seq: u64,
) -> Result<vless::VlessXHttpHttp2ExchangeReport, String> {
    let xhttp = opts
        .xhttp_options_for_seq(seq)
        .map_err(|err| format!("stage136 VLESS xhttp options invalid: {err}"))?;
    let (mut client, mut server) = UnixStream::pair()
        .map_err(|err| format!("stage136 VLESS UnixStream pair failed: {err}"))?;
    client
        .set_read_timeout(Some(opts.timeout))
        .map_err(|err| format!("stage136 VLESS client read timeout failed: {err}"))?;
    client
        .set_write_timeout(Some(opts.timeout))
        .map_err(|err| format!("stage136 VLESS client write timeout failed: {err}"))?;
    server
        .set_read_timeout(Some(opts.timeout))
        .map_err(|err| format!("stage136 VLESS server read timeout failed: {err}"))?;
    server
        .set_write_timeout(Some(opts.timeout))
        .map_err(|err| format!("stage136 VLESS server write timeout failed: {err}"))?;

    let target = opts.vless_target.clone();
    let payload_len = opts.vless_payload.len();
    let server_xhttp = xhttp.clone();
    let handle = thread::spawn(move || -> Result<(), String> {
        let request = vless::read_tcp_request_from_xhttp_http2_stream(
            &mut server,
            payload_len,
            &server_xhttp,
        )
        .map_err(|err| format!("stage136 VLESS server read failed: {err}"))?;
        if request.request.key != key {
            return Err("stage136 VLESS key mismatch".to_owned());
        }
        if request.request.target != target {
            return Err(format!(
                "stage136 VLESS target mismatch: got {}, want {}",
                request.request.target, target
            ));
        }
        let response = vless::response_payload_bytes(&request.request.payload);
        vless::write_xhttp_http2_payload_response(&mut server, &response)
            .map_err(|err| format!("stage136 VLESS server response failed: {err}"))?;
        Ok(())
    });

    let report = vless::tcp_exchange_over_xhttp_http2_stream(
        &mut client,
        &opts.xhttp_host,
        &key,
        &opts.vless_target,
        &xhttp,
        &opts.vless_payload,
    )
    .map_err(|err| format!("stage136 VLESS exchange failed: {err}"))?;
    handle
        .join()
        .map_err(|_| "stage136 VLESS server thread panicked".to_owned())??;
    Ok(report)
}

fn run_vmess_once(
    opts: &Stage136Options,
    seq: u64,
) -> Result<vmess::VMessAeadXHttpHttp2ExchangeReport, String> {
    let xhttp = opts
        .xhttp_options_for_seq(seq)
        .map_err(|err| format!("stage136 VMess xhttp options invalid: {err}"))?;
    let (mut client, mut server) = UnixStream::pair()
        .map_err(|err| format!("stage136 VMess UnixStream pair failed: {err}"))?;
    client
        .set_read_timeout(Some(opts.timeout))
        .map_err(|err| format!("stage136 VMess client read timeout failed: {err}"))?;
    client
        .set_write_timeout(Some(opts.timeout))
        .map_err(|err| format!("stage136 VMess client write timeout failed: {err}"))?;
    server
        .set_read_timeout(Some(opts.timeout))
        .map_err(|err| format!("stage136 VMess server read timeout failed: {err}"))?;
    server
        .set_write_timeout(Some(opts.timeout))
        .map_err(|err| format!("stage136 VMess server write timeout failed: {err}"))?;

    let uuid = opts.vmess_uuid.clone();
    let target = opts.vmess_target.clone();
    let server_xhttp = xhttp.clone();
    let handle = thread::spawn(move || -> Result<(), String> {
        let request =
            vmess::read_aead_tcp_request_from_xhttp_http2_stream(&mut server, &uuid, &server_xhttp)
                .map_err(|err| format!("stage136 VMess server read failed: {err}"))?;
        if request.request.target != target {
            return Err(format!(
                "stage136 VMess target mismatch: got {}, want {}",
                request.request.target, target
            ));
        }
        vmess::write_aead_xhttp_http2_response(
            &mut server,
            &request.request,
            &request.request.payload,
        )
        .map_err(|err| format!("stage136 VMess server response failed: {err}"))?;
        Ok(())
    });

    let report = vmess::aead_tcp_exchange_over_xhttp_http2_stream(
        &mut client,
        &opts.xhttp_host,
        &opts.vmess_uuid,
        &opts.vmess_target,
        &xhttp,
        &opts.vmess_payload,
    )
    .map_err(|err| format!("stage136 VMess exchange failed: {err}"))?;
    handle
        .join()
        .map_err(|_| "stage136 VMess server thread panicked".to_owned())??;
    Ok(report)
}

pub(super) fn apply_stage136_outcome(report: &mut Value, outcome: Stage136Outcome) {
    let vless_passed = outcome.vless_report.true_dataplane
        && outcome.vless_report.http2_lifecycle
        && outcome.vless_report.h2_packet_up_validated
        && outcome.vless_report.http2_client_preface_validated
        && outcome.vless_report.http2_settings_validated
        && outcome.vless_report.http2_headers_validated
        && outcome.vless_report.http2_data_validated
        && !outcome.vless_report.use_h3;
    let vmess_passed = outcome.vmess_report.true_dataplane
        && outcome.vmess_report.http2_lifecycle
        && outcome.vmess_report.h2_packet_up_validated
        && outcome.vmess_report.http2_client_preface_validated
        && outcome.vmess_report.http2_settings_validated
        && outcome.vmess_report.http2_headers_validated
        && outcome.vmess_report.http2_data_validated
        && !outcome.vmess_report.use_h3
        && outcome.vmess_report.reality_rejected_for_vmess;
    let passed = vless_passed && vmess_passed;

    report["read_only"] = json!(false);
    report["vless_xhttp_http2_lifecycle_smoke_passed"] = json!(vless_passed);
    report["vmess_xhttp_http2_lifecycle_smoke_passed"] = json!(vmess_passed);
    report["vless_vmess_xhttp_http2_lifecycle_smoke_passed"] = json!(passed);
    report["vless_xhttp_http2_lifecycle_admitted"] = json!(vless_passed);
    report["vmess_xhttp_http2_lifecycle_admitted"] = json!(vmess_passed);

    report["vless_vmess_xhttp_http2_contract"]["vless"]["request_header_len"] =
        json!(outcome.vless_report.request_header_len);
    report["vless_vmess_xhttp_http2_contract"]["vless"]["response_header_len"] =
        json!(outcome.vless_report.response_header_len);
    report["vless_vmess_xhttp_http2_contract"]["vless"]["xhttp_request_body_len"] =
        json!(outcome.vless_report.xhttp_request_body_len);
    report["vless_vmess_xhttp_http2_contract"]["vless"]["xhttp_response_body_len"] =
        json!(outcome.vless_report.xhttp_response_body_len);
    report["vless_vmess_xhttp_http2_contract"]["vless"]["http2_lifecycle_validated"] =
        json!(vless_passed);
    report["vless_vmess_xhttp_http2_contract"]["vless"]["payload_roundtrip_validated"] =
        json!(vless_passed);
    report["vless_vmess_xhttp_http2_contract"]["vmess"]["cmd_key_hex"] =
        json!(outcome.vmess_report.cmd_key_hex);
    report["vless_vmess_xhttp_http2_contract"]["vmess"]["request_header_len"] =
        json!(outcome.vmess_report.request_header_len);
    report["vless_vmess_xhttp_http2_contract"]["vmess"]["request_chunk_len"] =
        json!(outcome.vmess_report.request_chunk_len);
    report["vless_vmess_xhttp_http2_contract"]["vmess"]["response_header_len"] =
        json!(outcome.vmess_report.response_header_len);
    report["vless_vmess_xhttp_http2_contract"]["vmess"]["response_chunk_len"] =
        json!(outcome.vmess_report.response_chunk_len);
    report["vless_vmess_xhttp_http2_contract"]["vmess"]["xhttp_request_body_len"] =
        json!(outcome.vmess_report.xhttp_request_body_len);
    report["vless_vmess_xhttp_http2_contract"]["vmess"]["xhttp_response_body_len"] =
        json!(outcome.vmess_report.xhttp_response_body_len);
    report["vless_vmess_xhttp_http2_contract"]["vmess"]["http2_lifecycle_validated"] =
        json!(vmess_passed);
    report["vless_vmess_xhttp_http2_contract"]["vmess"]["payload_roundtrip_validated"] =
        json!(vmess_passed);

    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["iterations_per_protocol"] = json!(outcome.exchange_count / 2);
    report["benchmark"]["total_exchange_count"] = json!(outcome.exchange_count);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_vless_vmess_xhttp_http2_exchange"] = json!(outcome.ns_per_exchange);
    report["benchmark"]["vless_payload_len"] = json!(outcome.vless_report.payload_len);
    report["benchmark"]["vmess_payload_len"] = json!(outcome.vmess_report.payload_len);
    report["benchmark"]["vless_xhttp_request_path"] =
        json!(outcome.vless_report.xhttp_request_path);
    report["benchmark"]["vmess_xhttp_request_path"] =
        json!(outcome.vmess_report.xhttp_request_path);
    report["benchmark"]["vless_request_http2_headers_frame_len"] = json!(
        outcome
            .vless_report
            .request_frames
            .request_headers_frame_len
    );
    report["benchmark"]["vless_request_http2_data_frame_len"] =
        json!(outcome.vless_report.request_frames.request_data_frame_len);
    report["benchmark"]["vless_response_http2_headers_frame_len"] = json!(
        outcome
            .vless_report
            .response_frames
            .response_headers_frame_len
    );
    report["benchmark"]["vless_response_http2_data_frame_len"] =
        json!(outcome.vless_report.response_frames.response_data_frame_len);
    report["benchmark"]["vmess_request_http2_headers_frame_len"] = json!(
        outcome
            .vmess_report
            .request_frames
            .request_headers_frame_len
    );
    report["benchmark"]["vmess_request_http2_data_frame_len"] =
        json!(outcome.vmess_report.request_frames.request_data_frame_len);
    report["benchmark"]["vmess_response_http2_headers_frame_len"] = json!(
        outcome
            .vmess_report
            .response_frames
            .response_headers_frame_len
    );
    report["benchmark"]["vmess_response_http2_data_frame_len"] =
        json!(outcome.vmess_report.response_frames.response_data_frame_len);

    report["protocol_matrix"]["vless_xhttp_http2_lifecycle_admitted"] = json!(vless_passed);
    report["protocol_matrix"]["vmess_xhttp_http2_lifecycle_admitted"] = json!(vmess_passed);
}

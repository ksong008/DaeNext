use super::server::*;
use super::*;

#[derive(Debug)]
pub(super) struct Stage90Outcome {
    pub aes: Stage90BranchOutcome,
    pub chacha: Stage90BranchOutcome,
    pub elapsed_ns: u128,
    pub ns_per_udp_exchange: f64,
    pub exchange_count: usize,
}

#[derive(Debug)]
pub(super) struct Stage90BranchOutcome {
    pub branch: Stage90Branch,
    pub socket_report: UdpDirectSocketReport,
    pub client_report: shadowsocks::Ss2022UdpEncodedPacket,
    pub response_report: shadowsocks::Ss2022UdpDecodedPacket,
    pub server_summary: Ss2022UdpServerSummary,
    pub duplicate_replay_rejected: bool,
    pub too_old_replay_rejected: bool,
    pub packet_len: usize,
}

pub(super) fn run_stage90_smoke(opts: &Stage90Options) -> Result<Stage90Outcome, String> {
    let start = Instant::now();
    let aes = run_stage90_branch(opts, Stage90Branch::AesSeparateHeader)?;
    let chacha = run_stage90_branch(opts, Stage90Branch::ChachaMergedHeader)?;
    let elapsed_ns = start.elapsed().as_nanos();
    let exchange_count = opts.benchmark_iters * 2;
    Ok(Stage90Outcome {
        aes,
        chacha,
        elapsed_ns,
        ns_per_udp_exchange: elapsed_ns as f64 / exchange_count as f64,
        exchange_count,
    })
}

pub(super) fn apply_stage90_outcome(report: &mut Value, outcome: Stage90Outcome) {
    let aes_complete = branch_complete(&outcome.aes, outcome.aes.server_summary.accepted, true);
    let chacha_complete = branch_complete(
        &outcome.chacha,
        outcome.chacha.server_summary.accepted,
        false,
    );
    let so_mark_observed = outcome.aes.socket_report.so_mark_applied
        && outcome.aes.socket_report.so_mark == outcome.aes.socket_report.requested_mark
        && outcome.chacha.socket_report.so_mark_applied
        && outcome.chacha.socket_report.so_mark == outcome.chacha.socket_report.requested_mark;
    let replay_complete = outcome.aes.duplicate_replay_rejected
        && outcome.aes.too_old_replay_rejected
        && outcome.chacha.duplicate_replay_rejected
        && outcome.chacha.too_old_replay_rejected;
    let passed = aes_complete && chacha_complete && so_mark_observed && replay_complete;

    report["read_only"] = json!(false);
    report["ss2022_udp_smoke_passed"] = json!(passed);
    report["ss2022_udp_aes_separate_header_admitted"] = json!(aes_complete);
    report["ss2022_udp_chacha_merged_header_admitted"] = json!(chacha_complete);
    report["ss2022_udp_replay_filter_admitted"] = json!(replay_complete);
    report["ss2022_udp_true_dataplane_admitted"] = json!(passed);
    report["ss2022_udp_contract"]["aes"]["server"] = json!(outcome.aes.socket_report.peer_addr);
    report["ss2022_udp_contract"]["aes"]["client_session_id"] =
        json!(session_hex(outcome.aes.client_report.session_id));
    report["ss2022_udp_contract"]["aes"]["server_session_id"] =
        json!(session_hex(outcome.aes.response_report.session_id));
    report["ss2022_udp_contract"]["aes"]["packet_id_first"] =
        json!(outcome.aes.client_report.packet_id);
    report["ss2022_udp_contract"]["aes"]["separate_header_len"] =
        json!(outcome.aes.client_report.separate_header_len);
    report["ss2022_udp_contract"]["aes"]["identity_header_count"] =
        json!(outcome.aes.client_report.identity_header_count);
    report["ss2022_udp_contract"]["aes"]["identity_header_bytes_len"] =
        json!(outcome.aes.client_report.identity_header_bytes_len);
    report["ss2022_udp_contract"]["aes"]["identity_header_validated"] =
        json!(outcome.aes.response_report.identity_header_validated);
    report["ss2022_udp_contract"]["aes"]["payload_roundtrip_validated"] = json!(aes_complete);
    report["ss2022_udp_contract"]["chacha"]["server"] =
        json!(outcome.chacha.socket_report.peer_addr);
    report["ss2022_udp_contract"]["chacha"]["client_session_id"] =
        json!(session_hex(outcome.chacha.client_report.session_id));
    report["ss2022_udp_contract"]["chacha"]["server_session_id"] =
        json!(session_hex(outcome.chacha.response_report.session_id));
    report["ss2022_udp_contract"]["chacha"]["packet_id_first"] =
        json!(outcome.chacha.client_report.packet_id);
    report["ss2022_udp_contract"]["chacha"]["packet_nonce_len"] =
        json!(outcome.chacha.client_report.packet_nonce_len);
    report["ss2022_udp_contract"]["chacha"]["payload_roundtrip_validated"] = json!(chacha_complete);
    report["ss2022_udp_contract"]["replay"]["duplicate_rejected"] =
        json!(outcome.aes.duplicate_replay_rejected && outcome.chacha.duplicate_replay_rejected);
    report["ss2022_udp_contract"]["replay"]["too_old_rejected"] =
        json!(outcome.aes.too_old_replay_rejected && outcome.chacha.too_old_replay_rejected);
    report["udp_underlay_socket"]["aes"] = json!({
        "requested_mark": outcome.aes.socket_report.requested_mark,
        "so_mark": outcome.aes.socket_report.so_mark,
        "so_mark_applied": outcome.aes.socket_report.so_mark_applied,
        "peer_addr": outcome.aes.socket_report.peer_addr,
        "local_addr": outcome.aes.socket_report.local_addr
    });
    report["udp_underlay_socket"]["chacha"] = json!({
        "requested_mark": outcome.chacha.socket_report.requested_mark,
        "so_mark": outcome.chacha.socket_report.so_mark,
        "so_mark_applied": outcome.chacha.socket_report.so_mark_applied,
        "peer_addr": outcome.chacha.socket_report.peer_addr,
        "local_addr": outcome.chacha.socket_report.local_addr
    });
    report["udp_underlay_socket"]["so_mark_observed"] = json!(so_mark_observed);
    report["server_observation"] = json!({
        "aes": server_summary_json(&outcome.aes.server_summary),
        "chacha": server_summary_json(&outcome.chacha.server_summary)
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_ss2022_udp_exchange"] = json!(outcome.ns_per_udp_exchange);
    report["benchmark"]["exchange_count"] = json!(outcome.exchange_count);
    report["benchmark"]["aes_packet_len"] = json!(outcome.aes.packet_len);
    report["benchmark"]["chacha_packet_len"] = json!(outcome.chacha.packet_len);
    report["benchmark"]["payload_len"] = json!(outcome.aes.client_report.payload_len);
    report["protocol_matrix"]["ss2022_udp_true_dataplane_admitted"] = json!(passed);
}

fn run_stage90_branch(
    opts: &Stage90Options,
    branch: Stage90Branch,
) -> Result<Stage90BranchOutcome, String> {
    let conf = shadowsocks::ss2022::cipher_conf(branch.cipher(opts))
        .ok_or_else(|| format!("stage90 unsupported cipher: {}", branch.cipher(opts)))?;
    let (server_addr, handle) = spawn_ss2022_udp_server(opts, branch)?;
    let conn = UdpDirectPacketConn::connect(
        server_addr,
        &UdpDirectSocketOptions {
            mark: opts.so_mark,
            timeout: opts.timeout,
        },
    )
    .map_err(|err| format!("stage90 UDP socket connect failed: {err}"))?;
    let mut codec = shadowsocks::Ss2022UdpCodec::new(
        branch.cipher(opts),
        branch.password(opts),
        branch.client_session_id(),
    )
    .map_err(|err| format!("stage90 SS2022 UDP codec init failed: {err}"))?;
    let mut last_packet = None;
    let mut last_response = None;
    let mut last_decoded_response = None;
    for index in 0..opts.benchmark_iters {
        let nonce = if conf.packet_cipher {
            Some(nonce_for(index, conf.packet_nonce_len, branch.nonce_base()))
        } else {
            None
        };
        let now = shadowsocks::ss2022_udp_unix_timestamp_now();
        let packet = codec
            .encode_client_packet(&opts.target, &opts.payload, now, nonce.as_deref())
            .map_err(|err| format!("stage90 encode client UDP packet failed: {err}"))?;
        let response = conn
            .exchange(&packet.wire, 4096)
            .map_err(|err| format!("stage90 UDP exchange failed: {err}"))?;
        let decoded_response = codec
            .decode_server_packet(&response, shadowsocks::ss2022_udp_unix_timestamp_now())
            .map_err(|err| format!("stage90 decode response UDP packet failed: {err}"))?;
        if decoded_response.target != opts.response_target {
            return Err(format!(
                "stage90 response target mismatch: got {}, want {}",
                decoded_response.target, opts.response_target
            ));
        }
        if decoded_response.payload != opts.payload {
            return Err("stage90 response payload mismatch".to_owned());
        }
        last_packet = Some(packet);
        last_response = Some(response);
        last_decoded_response = Some(decoded_response);
    }
    let duplicate_replay_rejected = match &last_response {
        Some(response) => codec
            .decode_server_packet(response, shadowsocks::ss2022_udp_unix_timestamp_now())
            .is_err(),
        None => false,
    };
    let too_old_replay_rejected = validate_too_old_replay(opts, branch, &mut codec, conf)?;
    let server_summary = handle
        .join()
        .map_err(|_| "stage90 SS2022 UDP server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage90 SS2022 UDP server accepted {} packets, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    let client_report = last_packet.ok_or_else(|| "stage90 missing client packet".to_owned())?;
    let packet_len = client_report.wire.len();
    Ok(Stage90BranchOutcome {
        branch,
        socket_report: conn.report().clone(),
        client_report,
        response_report: last_decoded_response
            .ok_or_else(|| "stage90 missing response packet".to_owned())?,
        server_summary,
        duplicate_replay_rejected,
        too_old_replay_rejected,
        packet_len,
    })
}

fn validate_too_old_replay(
    opts: &Stage90Options,
    branch: Stage90Branch,
    codec: &mut shadowsocks::Ss2022UdpCodec,
    conf: shadowsocks::ss2022::CipherConf2022,
) -> Result<bool, String> {
    let high_nonce = if conf.packet_cipher {
        Some(nonce_for(0, conf.packet_nonce_len, 0xc0))
    } else {
        None
    };
    let low_nonce = if conf.packet_cipher {
        Some(nonce_for(1, conf.packet_nonce_len, 0xd0))
    } else {
        None
    };
    let now = shadowsocks::ss2022_udp_unix_timestamp_now();
    let high = shadowsocks::encode_ss2022_udp_server_packet(
        branch.cipher(opts),
        branch.password(opts),
        branch.stale_session_id(),
        shadowsocks::ss2022::UDP_REPLAY_WINDOW_SIZE as u64 + 1,
        branch.client_session_id(),
        &opts.response_target,
        b"stage90-high-packet",
        now,
        high_nonce.as_deref(),
    )
    .map_err(|err| format!("stage90 high replay packet encode failed: {err}"))?;
    codec
        .decode_server_packet(&high.wire, now)
        .map_err(|err| format!("stage90 high replay packet decode failed: {err}"))?;
    let low = shadowsocks::encode_ss2022_udp_server_packet(
        branch.cipher(opts),
        branch.password(opts),
        branch.stale_session_id(),
        0,
        branch.client_session_id(),
        &opts.response_target,
        b"stage90-low-packet",
        now,
        low_nonce.as_deref(),
    )
    .map_err(|err| format!("stage90 low replay packet encode failed: {err}"))?;
    Ok(codec.decode_server_packet(&low.wire, now).is_err())
}

fn branch_complete(outcome: &Stage90BranchOutcome, expected: usize, expect_identity: bool) -> bool {
    let server = &outcome.server_summary;
    let branch_count = match outcome.branch {
        Stage90Branch::AesSeparateHeader => server.aes_separate_header_count,
        Stage90Branch::ChachaMergedHeader => server.chacha_merged_header_count,
    };
    let identity_ok = if expect_identity {
        server.multi_psk_count == expected
            && server.upsk_last_count == expected
            && server.identity_header_count == expected
            && server.identity_header_bytes_len == expected * 16
            && server.identity_header_validated_count == expected
    } else {
        server.identity_header_count == 0
            && server.identity_header_bytes_len == 0
            && server.identity_header_validated_count == expected
    };
    server.accepted == expected
        && server.decrypt_count == expected
        && branch_count == expected
        && server.request_header_count == expected
        && server.target_metadata_count == expected
        && server.replay_window_accept_count == expected
        && server.payload_roundtrip_count == expected
        && identity_ok
        && outcome.response_report.payload.len() == outcome.client_report.payload_len
}

fn server_summary_json(summary: &Ss2022UdpServerSummary) -> Value {
    json!({
        "accepted": summary.accepted,
        "decrypt_count": summary.decrypt_count,
        "aes_separate_header_count": summary.aes_separate_header_count,
        "chacha_merged_header_count": summary.chacha_merged_header_count,
        "multi_psk_count": summary.multi_psk_count,
        "upsk_last_count": summary.upsk_last_count,
        "identity_header_count": summary.identity_header_count,
        "identity_header_bytes_len": summary.identity_header_bytes_len,
        "identity_header_validated_count": summary.identity_header_validated_count,
        "request_header_count": summary.request_header_count,
        "target_metadata_count": summary.target_metadata_count,
        "replay_window_accept_count": summary.replay_window_accept_count,
        "payload_roundtrip_count": summary.payload_roundtrip_count,
        "packet_ids": summary.packet_ids,
        "targets": summary.targets,
        "payload_ascii": summary.payload_ascii
    })
}

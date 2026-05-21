use std::time::Instant;

use dae_outbound::juicity;
use serde_json::{Value, json};

use super::options::{DEFAULT_TARGET, Stage121Options};

pub(super) fn stage121_report(opts: &Stage121Options) -> Value {
    let mut report = json!({
        "name": "stage121-juicity-auth-stream-admission",
        "stage": "stage121",
        "evidence_class": "juicity-auth-uni-stream-transcript-order-before-live-h3-dialauth",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": !opts.execute_smoke,
        "blockers": [
            "stage121 read-only fixture has not executed the auth stream transcript smoke",
            "Juicity live QUIC TLS EKM token generation, live H3 auth stream, TransportPacketConn encryption, stream PacketConn relay, and congestion behavior remain blocked",
            "external outbound/quic-go remains required"
        ]
    });
    for key in [
        "quinn_dependency_available",
        "h3_dependency_available",
        "h3_quinn_dependency_available",
        "tokio_quic_runtime_admitted",
        "quinn_runtime_tokio_feature_admitted",
        "quinn_rustls_aws_lc_rs_feature_admitted",
        "h3_quinn_bridge_admitted",
        "juicity_h3_loopback_dependency_admitted",
        "juicity_h3_loopback_smoke_executed",
        "juicity_h3_loopback_benchmark_recorded",
        "juicity_tls_verify_peer_certificate_hook_admitted",
        "juicity_tls_certchain_verification_admitted",
        "juicity_pinned_certchain_live_callback_matched",
        "juicity_h3_handshake_admitted",
        "juicity_native_optin_contract_admitted",
        "juicity_certchain_hash_algorithm_admitted",
        "juicity_pinned_certchain_url_base64_verify_vector_admitted",
        "juicity_pinned_certchain_std_base64_verify_vector_admitted",
        "juicity_pinned_certchain_hex_decode_caveat_recorded",
        "juicity_pinned_certchain_forces_insecure_verify_contract_admitted",
        "juicity_pinned_certchain_full_chain_hash_contract_admitted",
        "juicity_pinned_certchain_not_hysteria2_pin_sha256_recorded",
        "juicity_tls13_h3_alpn_config_contract_admitted",
        "juicity_underlay_contract_admitted",
        "juicity_udp_port_zero_dialauth_contract_recorded",
        "juicity_stream_packet_conn_contract_recorded",
        "juicity_dialauth_record_protocol_state_admitted",
        "juicity_udp_port_zero_transport_packet_conn_route_admitted",
        "juicity_stream_packet_conn_frame_admitted",
        "hysteria2_udp_underlay_admitted",
        "tuic_udp_underlay_socket_admitted",
        "quic_h3_family_native_optin_contract_admitted",
        "anytls_true_dataplane_admitted",
        "protocol_outbound_partial_admitted",
        "outbound_quic_go_dependency_preserved",
        "external_outbound_required",
        "external_quic_go_required",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "juicity_authenticate_header_layout_admitted",
        "juicity_auth_uni_stream_write_order_admitted",
        "juicity_dialauth_record_over_auth_stream_admitted",
        "juicity_auth_token_live_ekm_admitted",
        "juicity_dialauth_over_h3_admitted",
        "juicity_transport_packet_conn_dataplane_admitted",
        "juicity_stream_packet_conn_dataplane_admitted",
        "juicity_packet_over_stream_admitted",
        "juicity_congestion_behavior_admitted",
        "juicity_true_quic_h3_dataplane_admitted",
        "hysteria2_true_quic_dataplane_admitted",
        "tuic_true_quic_dataplane_admitted",
        "quic_h3_family_true_dataplane_admitted",
        "outbound_true_dataplane_admitted",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
        "true_rust_default_daemon_admitted",
    ] {
        report[key] = json!(false);
    }
    report["auth_stream"] = json!({
        "target": opts.target,
        "default_target": DEFAULT_TARGET,
        "authenticate_version": juicity::JUICITY_AUTHENTICATE_VERSION0,
        "authenticate_type": juicity::JUICITY_AUTHENTICATE_TYPE,
        "authenticate_uuid_len": juicity::JUICITY_AUTHENTICATE_UUID_LEN,
        "authenticate_token_len": juicity::JUICITY_AUTHENTICATE_TOKEN_LEN,
        "authenticate_header_len": juicity::JUICITY_AUTHENTICATE_HEADER_LEN,
        "authenticate_token_source": "deterministic-fixture-not-live-ekm",
        "authenticate_header_layout_valid": false,
        "dialauth_metadata_len": null,
        "dialauth_iv_len": juicity::JUICITY_UNDERLAY_AUTH_IV_LEN,
        "dialauth_psk_len": juicity::JUICITY_UNDERLAY_AUTH_PSK_LEN,
        "dialauth_record_len": null,
        "transcript_len": null,
        "auth_header_offset": 0,
        "dialauth_record_offset": null,
        "auth_header_written_first": false,
        "dialauth_record_matches_stage120": false,
        "dialauth_record_order_valid": false,
        "boundary": "read-only fixture records Juicity/TUIC authenticate header layout only; execute --execute-smoke to admit local transcript order"
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations": opts.benchmark_iters,
        "elapsed_ns": null,
        "ns_per_juicity_auth_stream_contract": null,
        "authenticate_header_len": juicity::JUICITY_AUTHENTICATE_HEADER_LEN,
        "dialauth_record_len": null,
        "transcript_len": null,
        "scope": "local Juicity auth uni stream transcript contract smoke; not live QUIC TLS EKM token generation, live H3 auth stream, encrypted TransportPacketConn, stream relay, or congestion",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"] = json!({
        "hysteria2_udp_underlay_admitted": true,
        "hysteria2_true_quic_dataplane_admitted": false,
        "tuic_udp_underlay_socket_admitted": true,
        "tuic_true_quic_dataplane_admitted": false,
        "juicity_h3_handshake_admitted": true,
        "juicity_tls_certchain_verification_admitted": true,
        "juicity_dialauth_record_protocol_state_admitted": true,
        "juicity_udp_port_zero_transport_packet_conn_route_admitted": true,
        "juicity_stream_packet_conn_frame_admitted": true,
        "juicity_authenticate_header_layout_admitted": false,
        "juicity_auth_uni_stream_write_order_admitted": false,
        "juicity_dialauth_record_over_auth_stream_admitted": false,
        "juicity_auth_token_live_ekm_admitted": false,
        "juicity_dialauth_over_h3_admitted": false,
        "juicity_transport_packet_conn_dataplane_admitted": false,
        "juicity_stream_packet_conn_dataplane_admitted": false,
        "juicity_true_quic_h3_dataplane_admitted": false,
        "quic_h3_family_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": true,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Juicity live QUIC TLS ExportKeyingMaterial token generation for Authenticate",
        "Juicity DialAuth over the live H3 auth uni stream",
        "Juicity TransportPacketConn shadowsocks encryption/decryption with JuicityReusedInfo for UDP port 0",
        "Juicity stream_packet_conn packet-over-stream live relay for nonzero UDP targets",
        "Juicity congestion behavior and packet relay benchmark",
        "Hysteria2 full QUIC and TUIC true QUIC dataplanes",
        "outbound registry/dialer group/health policy parity while preserving direct/block indices and NewDialerSetFromLinks semantics",
        "matched Go default daemon vs true Rust candidate benchmark",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage121/juicity_auth_stream_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage121_juicity_auth_stream_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage121 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage121-juicity-auth-stream-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage121-juicity-auth-stream-admission --execute-smoke --benchmark-iters 1000",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage121 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage121 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage120 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage121",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.16",
        "/root/project/outbound/protocol/juicity/client.go:sendAuthentication",
        "/root/project/outbound/protocol/juicity/client.go:DialAuth",
        "/root/project/outbound/protocol/tuic/protocol.go:Authenticate",
        "rust/crates/dae-outbound/src/juicity/auth_stream.rs",
        "rust/crates/dae-outbound/src/juicity/packet.rs",
        "rust/crates/dae-cli/src/runtime_stage121_juicity_auth_stream_gate/"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    match run_auth_stream_benchmark(opts) {
        Ok((outcome, elapsed_ns)) => apply_stage121_outcome(&mut report, &outcome, elapsed_ns),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([format!("{err}")]);
        }
    }
    report
}

fn run_auth_stream_benchmark(
    opts: &Stage121Options,
) -> Result<(juicity::JuicityAuthStreamSmokeReport, u128), String> {
    let start = Instant::now();
    let mut last = None;
    for _ in 0..opts.benchmark_iters {
        last = Some(juicity::auth_stream_smoke(&opts.target).map_err(|err| err.to_string())?);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    Ok((last.unwrap(), elapsed_ns))
}

fn apply_stage121_outcome(
    report: &mut Value,
    outcome: &juicity::JuicityAuthStreamSmokeReport,
    elapsed_ns: u128,
) {
    let passed = outcome.juicity_authenticate_header_layout_admitted
        && outcome.juicity_auth_uni_stream_write_order_admitted
        && outcome.juicity_dialauth_record_over_auth_stream_admitted
        && outcome.dialauth_record_order_valid;
    let iterations = report["benchmark"]["iterations"].as_u64().unwrap_or(1);
    report["read_only"] = json!(false);
    report["blocked"] = json!(!passed);
    report["blockers"] = if passed {
        json!([])
    } else {
        json!(["stage121 auth-stream transcript smoke did not satisfy all admission checks"])
    };
    report["juicity_authenticate_header_layout_admitted"] =
        json!(outcome.juicity_authenticate_header_layout_admitted);
    report["juicity_auth_uni_stream_write_order_admitted"] =
        json!(outcome.juicity_auth_uni_stream_write_order_admitted);
    report["juicity_dialauth_record_over_auth_stream_admitted"] =
        json!(outcome.juicity_dialauth_record_over_auth_stream_admitted);
    report["auth_stream"] = json!({
        "target": outcome.target,
        "default_target": DEFAULT_TARGET,
        "authenticate_version": outcome.authenticate_version,
        "authenticate_type": outcome.authenticate_type,
        "authenticate_uuid_len": outcome.authenticate_uuid_len,
        "authenticate_token_len": outcome.authenticate_token_len,
        "authenticate_header_len": outcome.authenticate_header_len,
        "authenticate_token_source": outcome.authenticate_token_source,
        "authenticate_header_layout_valid": outcome.authenticate_header_layout_valid,
        "dialauth_metadata_len": outcome.dialauth_metadata_len,
        "dialauth_iv_len": outcome.dialauth_iv_len,
        "dialauth_psk_len": outcome.dialauth_psk_len,
        "dialauth_record_len": outcome.dialauth_record_len,
        "transcript_len": outcome.transcript_len,
        "auth_header_offset": outcome.auth_header_offset,
        "dialauth_record_offset": outcome.dialauth_record_offset,
        "auth_header_written_first": outcome.auth_header_written_first,
        "dialauth_record_matches_stage120": outcome.dialauth_record_matches_stage120,
        "dialauth_record_order_valid": outcome.dialauth_record_order_valid,
        "boundary": "local auth-stream transcript order is admitted, but live QUIC TLS EKM token generation, live H3 DialAuth, encrypted TransportPacketConn, stream relay, congestion, outbound/default/product remain closed"
    });
    report["benchmark"] = json!({
        "benchmark_recorded": passed,
        "iterations": iterations,
        "elapsed_ns": elapsed_ns,
        "ns_per_juicity_auth_stream_contract": elapsed_ns as f64 / iterations as f64,
        "authenticate_header_len": outcome.authenticate_header_len,
        "dialauth_record_len": outcome.dialauth_record_len,
        "transcript_len": outcome.transcript_len,
        "scope": "local Juicity auth uni stream transcript contract smoke; not live QUIC TLS EKM token generation, live H3 auth stream, encrypted TransportPacketConn, stream relay, or congestion",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"]["juicity_authenticate_header_layout_admitted"] =
        json!(outcome.juicity_authenticate_header_layout_admitted);
    report["protocol_matrix"]["juicity_auth_uni_stream_write_order_admitted"] =
        json!(outcome.juicity_auth_uni_stream_write_order_admitted);
    report["protocol_matrix"]["juicity_dialauth_record_over_auth_stream_admitted"] =
        json!(outcome.juicity_dialauth_record_over_auth_stream_admitted);
}

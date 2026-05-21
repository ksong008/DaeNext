use std::time::Instant;

use dae_outbound::juicity;
use serde_json::{Value, json};

use super::options::{
    DEFAULT_PAYLOAD, DEFAULT_PORT_ZERO_TARGET, DEFAULT_STREAM_TARGET, Stage120Options,
};

pub(super) fn stage120_report(opts: &Stage120Options) -> Value {
    let mut report = json!({
        "name": "stage120-juicity-packet-state-admission",
        "stage": "stage120",
        "evidence_class": "juicity-dialauth-and-stream-packet-protocol-state-before-real-packet-conn",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": !opts.execute_smoke,
        "blockers": [
            "stage120 read-only fixture has not executed the DialAuth/packet-state smoke",
            "Juicity DialAuth over live H3 auth stream, TransportPacketConn encryption, stream PacketConn relay, and congestion behavior remain blocked",
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
        "juicity_dialauth_record_protocol_state_admitted",
        "juicity_udp_port_zero_transport_packet_conn_route_admitted",
        "juicity_stream_packet_conn_frame_admitted",
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
    report["packet_state"] = json!({
        "port_zero_target": opts.port_zero_target,
        "stream_target": opts.stream_target,
        "default_port_zero_target": DEFAULT_PORT_ZERO_TARGET,
        "default_stream_target": DEFAULT_STREAM_TARGET,
        "default_payload_len": DEFAULT_PAYLOAD.len(),
        "payload_len": opts.payload.len(),
        "port_zero_kind": null,
        "stream_kind": null,
        "dialauth_iv_len": juicity::JUICITY_UNDERLAY_AUTH_IV_LEN,
        "dialauth_psk_len": juicity::JUICITY_UNDERLAY_AUTH_PSK_LEN,
        "dialauth_iv_zero_prefix_valid": false,
        "dialauth_psk_nonzero": false,
        "dialauth_packed_len": null,
        "dialauth_metadata_len": null,
        "underlay_auth_channel_capacity": null,
        "stream_packet_metadata_len": null,
        "stream_packet_frame_len": null,
        "stream_packet_payload_len_prefix_valid": false,
        "stream_packet_roundtrip_validated": false,
        "boundary": "read-only fixture records targets only; execute --execute-smoke to admit local packet-state contracts"
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations": opts.benchmark_iters,
        "elapsed_ns": null,
        "ns_per_juicity_packet_state_contract": null,
        "dialauth_packed_len": null,
        "stream_packet_frame_len": null,
        "payload_len": opts.payload.len(),
        "scope": "local Juicity DialAuth record and stream packet frame contract smoke; not live H3 auth stream, encrypted TransportPacketConn, stream relay, or congestion",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"] = json!({
        "hysteria2_udp_underlay_admitted": true,
        "hysteria2_true_quic_dataplane_admitted": false,
        "tuic_udp_underlay_socket_admitted": true,
        "tuic_true_quic_dataplane_admitted": false,
        "juicity_h3_handshake_admitted": true,
        "juicity_tls_certchain_verification_admitted": true,
        "juicity_dialauth_record_protocol_state_admitted": false,
        "juicity_udp_port_zero_transport_packet_conn_route_admitted": false,
        "juicity_stream_packet_conn_frame_admitted": false,
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
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage120/juicity_packet_state_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage120_juicity_packet_state_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage120 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage120-juicity-packet-state-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage120-juicity-packet-state-admission --execute-smoke --benchmark-iters 1000",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage120 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage120 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage119 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage120",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.16",
        "/root/project/outbound/protocol/juicity/client.go:DialAuth",
        "/root/project/outbound/protocol/juicity/dialer.go",
        "/root/project/outbound/protocol/juicity/stream_packet_conn.go",
        "/root/project/outbound/protocol/juicity/transport_packet_conn.go",
        "rust/crates/dae-outbound/src/juicity/packet.rs",
        "rust/crates/dae-cli/src/runtime_stage120_juicity_packet_state_gate/"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    match run_packet_state_benchmark(opts) {
        Ok((outcome, elapsed_ns)) => apply_stage120_outcome(&mut report, &outcome, elapsed_ns),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([format!("{err}")]);
        }
    }
    report
}

fn run_packet_state_benchmark(
    opts: &Stage120Options,
) -> Result<(juicity::JuicityPacketStateSmokeReport, u128), String> {
    let start = Instant::now();
    let mut last = None;
    for _ in 0..opts.benchmark_iters {
        last = Some(
            juicity::packet_state_smoke(&opts.port_zero_target, &opts.stream_target, &opts.payload)
                .map_err(|err| err.to_string())?,
        );
    }
    let elapsed_ns = start.elapsed().as_nanos();
    Ok((last.unwrap(), elapsed_ns))
}

fn apply_stage120_outcome(
    report: &mut Value,
    outcome: &juicity::JuicityPacketStateSmokeReport,
    elapsed_ns: u128,
) {
    let passed = outcome.juicity_dialauth_record_protocol_state_admitted
        && outcome.juicity_udp_port_zero_transport_packet_conn_route_admitted
        && outcome.juicity_stream_packet_conn_frame_admitted
        && outcome.stream_packet_roundtrip_validated;
    let iterations = report["benchmark"]["iterations"].as_u64().unwrap_or(1);
    report["read_only"] = json!(false);
    report["blocked"] = json!(!passed);
    report["blockers"] = if passed {
        json!([])
    } else {
        json!(["stage120 packet-state smoke did not satisfy all admission checks"])
    };
    report["juicity_dialauth_record_protocol_state_admitted"] =
        json!(outcome.juicity_dialauth_record_protocol_state_admitted);
    report["juicity_udp_port_zero_transport_packet_conn_route_admitted"] =
        json!(outcome.juicity_udp_port_zero_transport_packet_conn_route_admitted);
    report["juicity_stream_packet_conn_frame_admitted"] =
        json!(outcome.juicity_stream_packet_conn_frame_admitted);
    report["packet_state"] = json!({
        "port_zero_target": outcome.port_zero_target,
        "stream_target": outcome.stream_target,
        "default_port_zero_target": DEFAULT_PORT_ZERO_TARGET,
        "default_stream_target": DEFAULT_STREAM_TARGET,
        "default_payload_len": DEFAULT_PAYLOAD.len(),
        "payload_len": outcome.payload_len,
        "port_zero_kind": outcome.port_zero_kind,
        "stream_kind": outcome.stream_kind,
        "dialauth_iv_len": outcome.dialauth_iv_len,
        "dialauth_psk_len": outcome.dialauth_psk_len,
        "dialauth_iv_zero_prefix_valid": outcome.dialauth_iv_zero_prefix_valid,
        "dialauth_psk_nonzero": outcome.dialauth_psk_nonzero,
        "dialauth_packed_len": outcome.dialauth_packed_len,
        "dialauth_metadata_len": outcome.dialauth_metadata_len,
        "underlay_auth_channel_capacity": outcome.underlay_auth_channel_capacity,
        "stream_packet_metadata_len": outcome.stream_packet_metadata_len,
        "stream_packet_frame_len": outcome.stream_packet_frame_len,
        "stream_packet_payload_len": outcome.stream_packet_payload_len,
        "stream_packet_payload_len_prefix_valid": outcome.stream_packet_payload_len_prefix_valid,
        "stream_packet_roundtrip_validated": outcome.stream_packet_roundtrip_validated,
        "boundary": "local packet-state contracts are admitted, but live H3 DialAuth stream, encrypted TransportPacketConn, stream relay, congestion, outbound/default/product remain closed"
    });
    report["benchmark"] = json!({
        "benchmark_recorded": passed,
        "iterations": iterations,
        "elapsed_ns": elapsed_ns,
        "ns_per_juicity_packet_state_contract": elapsed_ns as f64 / iterations as f64,
        "dialauth_packed_len": outcome.dialauth_packed_len,
        "stream_packet_frame_len": outcome.stream_packet_frame_len,
        "payload_len": outcome.payload_len,
        "scope": "local Juicity DialAuth record and stream packet frame contract smoke; not live H3 auth stream, encrypted TransportPacketConn, stream relay, or congestion",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"]["juicity_dialauth_record_protocol_state_admitted"] =
        json!(outcome.juicity_dialauth_record_protocol_state_admitted);
    report["protocol_matrix"]["juicity_udp_port_zero_transport_packet_conn_route_admitted"] =
        json!(outcome.juicity_udp_port_zero_transport_packet_conn_route_admitted);
    report["protocol_matrix"]["juicity_stream_packet_conn_frame_admitted"] =
        json!(outcome.juicity_stream_packet_conn_frame_admitted);
}

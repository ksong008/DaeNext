use dae_outbound::juicity;
use serde_json::{Value, json};

use super::options::Stage123Options;

pub(super) fn stage123_report(opts: &Stage123Options) -> Value {
    let mut report = json!({
        "name": "stage123-juicity-live-ekm-auth-admission",
        "stage": "stage123",
        "evidence_class": "juicity-live-quic-ekm-auth-token-before-packet-relay",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": !opts.execute_smoke,
        "blockers": [
            "stage123 read-only fixture has not executed the live EKM auth smoke",
            "complete Juicity DialAuth over H3, TransportPacketConn encryption, stream PacketConn relay, and congestion behavior remain blocked",
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
        "juicity_authenticate_header_layout_admitted",
        "juicity_auth_uni_stream_write_order_admitted",
        "juicity_dialauth_record_over_auth_stream_admitted",
        "juicity_live_auth_uni_stream_harness_admitted",
        "juicity_live_auth_uni_stream_write_order_admitted",
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
        "juicity_auth_token_live_ekm_admitted",
        "juicity_live_ekm_auth_header_admitted",
        "juicity_live_ekm_auth_stream_transcript_admitted",
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
    report["live_ekm_auth"] = json!({
        "server_name": opts.server_name,
        "target": opts.target,
        "default_target": juicity::DEFAULT_LIVE_EKM_AUTH_TARGET,
        "alpn_protocol": juicity::DEFAULT_H3_ALPN,
        "client_selected_alpn": null,
        "server_selected_alpn": null,
        "ekm_label_len": juicity::JUICITY_AUTHENTICATE_UUID_LEN,
        "ekm_context_len": opts.password.len(),
        "ekm_token_len": juicity::JUICITY_AUTHENTICATE_TOKEN_LEN,
        "client_ekm_token_nonzero": false,
        "server_ekm_token_exported": false,
        "authenticate_header_len": juicity::JUICITY_AUTHENTICATE_HEADER_LEN,
        "dialauth_record_len": null,
        "transcript_len": null,
        "open_uni_stream_count": 0,
        "uni_stream_finish_count": 0,
        "uni_stream_acked_count": 0,
        "server_received_count": 0,
        "server_received_len": null,
        "server_transcript_match_count": 0,
        "quic_handshake_validated": false,
        "live_ekm_auth_stream_validated": false,
        "boundary": "read-only fixture records EKM inputs only; execute --execute-smoke to derive token from a local QUIC connection"
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations": opts.benchmark_iters,
        "elapsed_ns": null,
        "ns_per_juicity_live_ekm_auth_stream_exchange": null,
        "ekm_token_len": juicity::JUICITY_AUTHENTICATE_TOKEN_LEN,
        "transcript_len": null,
        "server_received_len": null,
        "scope": "local QUIC TLS1.3+h3 ALPN EKM token generation plus auth uni stream transcript exchange; not complete DialAuth over H3, encrypted TransportPacketConn, stream relay, or congestion",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"] = json!({
        "hysteria2_udp_underlay_admitted": true,
        "hysteria2_true_quic_dataplane_admitted": false,
        "tuic_udp_underlay_socket_admitted": true,
        "tuic_true_quic_dataplane_admitted": false,
        "juicity_h3_handshake_admitted": true,
        "juicity_tls_certchain_verification_admitted": true,
        "juicity_auth_token_live_ekm_admitted": false,
        "juicity_live_ekm_auth_header_admitted": false,
        "juicity_live_ekm_auth_stream_transcript_admitted": false,
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
        "complete Juicity DialAuth over H3 with client-ring lifecycle",
        "Juicity TransportPacketConn shadowsocks encryption/decryption with JuicityReusedInfo for UDP port 0",
        "Juicity stream_packet_conn packet-over-stream live relay for nonzero UDP targets",
        "Juicity congestion behavior and packet relay benchmark",
        "Hysteria2 full QUIC and TUIC true QUIC dataplanes",
        "outbound registry/dialer group/health policy parity while preserving direct/block indices and NewDialerSetFromLinks semantics",
        "matched Go default daemon vs true Rust candidate benchmark",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage123/juicity_live_ekm_auth_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage123_juicity_live_ekm_auth_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage123 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage123-juicity-live-ekm-auth-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage123-juicity-live-ekm-auth-admission --execute-smoke --benchmark-iters 5",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage123 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage123 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage122 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage123",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.16",
        "/root/project/outbound/protocol/tuic/protocol.go:GenToken",
        "/root/project/outbound/protocol/juicity/client.go:sendAuthentication",
        "rust/crates/dae-outbound/src/juicity/auth_stream_ekm.rs",
        "rust/crates/dae-outbound/src/juicity/auth_stream_live.rs",
        "rust/crates/dae-cli/src/runtime_stage123_juicity_live_ekm_auth_gate/"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    match juicity::run_live_ekm_auth_smoke(&juicity::JuicityLiveEkmAuthOptions {
        server_name: opts.server_name.clone(),
        target: opts.target.clone(),
        password: opts.password.clone(),
        iterations: opts.benchmark_iters,
        timeout: opts.timeout,
    }) {
        Ok(outcome) => apply_stage123_outcome(&mut report, &outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([format!("{err}")]);
        }
    }
    report
}

fn apply_stage123_outcome(report: &mut Value, outcome: &juicity::JuicityLiveEkmAuthReport) {
    let passed = outcome.juicity_auth_token_live_ekm_admitted
        && outcome.juicity_live_ekm_auth_header_admitted
        && outcome.juicity_live_ekm_auth_stream_transcript_admitted;
    report["read_only"] = json!(false);
    report["blocked"] = json!(!passed);
    report["blockers"] = if passed {
        json!([])
    } else {
        json!(["stage123 live EKM auth smoke did not satisfy all admission checks"])
    };
    report["juicity_auth_token_live_ekm_admitted"] =
        json!(outcome.juicity_auth_token_live_ekm_admitted);
    report["juicity_live_ekm_auth_header_admitted"] =
        json!(outcome.juicity_live_ekm_auth_header_admitted);
    report["juicity_live_ekm_auth_stream_transcript_admitted"] =
        json!(outcome.juicity_live_ekm_auth_stream_transcript_admitted);
    report["live_ekm_auth"] = json!({
        "server_name": outcome.server_name,
        "target": outcome.target,
        "default_target": juicity::DEFAULT_LIVE_EKM_AUTH_TARGET,
        "alpn_protocol": outcome.alpn_protocol,
        "client_selected_alpn": outcome.client_selected_alpn,
        "server_selected_alpn": outcome.server_selected_alpn,
        "ekm_label_len": outcome.ekm_label_len,
        "ekm_context_len": outcome.ekm_context_len,
        "ekm_token_len": outcome.ekm_token_len,
        "client_ekm_token_nonzero": outcome.client_ekm_token_nonzero,
        "server_ekm_token_exported": outcome.server_ekm_token_exported,
        "authenticate_header_len": outcome.authenticate_header_len,
        "dialauth_record_len": outcome.dialauth_record_len,
        "transcript_len": outcome.transcript_len,
        "open_uni_stream_count": outcome.open_uni_stream_count,
        "uni_stream_finish_count": outcome.uni_stream_finish_count,
        "uni_stream_acked_count": outcome.uni_stream_acked_count,
        "server_received_count": outcome.server_received_count,
        "server_received_len": outcome.server_received_len,
        "server_transcript_match_count": outcome.server_transcript_match_count,
        "quic_handshake_validated": outcome.quic_handshake_validated,
        "live_ekm_auth_stream_validated": outcome.live_ekm_auth_stream_validated,
        "boundary": "live QUIC EKM token and auth transcript are admitted, but complete DialAuth over H3, encrypted TransportPacketConn, stream relay, congestion, outbound/default/product remain closed"
    });
    report["benchmark"] = json!({
        "benchmark_recorded": passed,
        "iterations": outcome.iterations,
        "elapsed_ns": outcome.elapsed_ns,
        "ns_per_juicity_live_ekm_auth_stream_exchange": outcome.ns_per_juicity_live_ekm_auth_stream_exchange,
        "ekm_token_len": outcome.ekm_token_len,
        "transcript_len": outcome.transcript_len,
        "server_received_len": outcome.server_received_len,
        "scope": "local QUIC TLS1.3+h3 ALPN EKM token generation plus auth uni stream transcript exchange; not complete DialAuth over H3, encrypted TransportPacketConn, stream relay, or congestion",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"]["juicity_auth_token_live_ekm_admitted"] =
        json!(outcome.juicity_auth_token_live_ekm_admitted);
    report["protocol_matrix"]["juicity_live_ekm_auth_header_admitted"] =
        json!(outcome.juicity_live_ekm_auth_header_admitted);
    report["protocol_matrix"]["juicity_live_ekm_auth_stream_transcript_admitted"] =
        json!(outcome.juicity_live_ekm_auth_stream_transcript_admitted);
}

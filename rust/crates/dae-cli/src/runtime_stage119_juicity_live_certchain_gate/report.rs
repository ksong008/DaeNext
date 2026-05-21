use dae_outbound::juicity;
use serde_json::{Value, json};

use super::options::Stage119Options;

pub(super) fn stage119_report(opts: &Stage119Options) -> Value {
    let mut report = json!({
        "name": "stage119-juicity-live-certchain-admission",
        "stage": "stage119",
        "evidence_class": "rootless-local-juicity-h3-live-pinned-certchain-verification-before-dialauth-packet-conn",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": !opts.execute_smoke,
        "blockers": [
            "stage119 read-only fixture has not executed the live H3 cert-chain verification smoke",
            "Juicity DialAuth, TransportPacketConn, stream_packet_conn, packet-over-stream, and congestion behavior remain blocked",
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
        "juicity_h3_loopback_smoke_executed",
        "juicity_h3_loopback_benchmark_recorded",
        "juicity_tls_verify_peer_certificate_hook_admitted",
        "juicity_tls_certchain_verification_admitted",
        "juicity_pinned_certchain_live_callback_matched",
        "juicity_h3_handshake_admitted",
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
    report["h3_loopback"] = json!({
        "server_name": juicity::DEFAULT_H3_SERVER_NAME,
        "alpn_protocol": juicity::DEFAULT_H3_ALPN,
        "tls13_only_configured": true,
        "quic_datagram_disabled": true,
        "keepalive_secs": juicity::DEFAULT_H3_KEEPALIVE_SECS,
        "handshake_idle_timeout_secs": juicity::DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS,
        "loopback_addr": null,
        "client_selected_alpn": null,
        "server_selected_alpn": null,
        "h3_status": null,
        "payload_len": opts.payload.len(),
        "echoed_payload_len": null,
        "certificate_chain_callback_observed": false,
        "certificate_chain_der_count": null,
        "certificate_chain_hash_hex": null,
        "verifier_server_name": null,
        "boundary": "read-only fixture records configuration only; execute --execute-smoke to admit live H3 cert-chain verification"
    });
    report["live_certchain"] = json!({
        "requested_when_smoke_executes": true,
        "generated_pin_format": "url-base64",
        "generated_pin_len": null,
        "pinned_certchain_live_callback_matched": false,
        "pinned_certchain_live_callback_error": null,
        "forces_insecure_verify_contract": true,
        "verifies_full_chain_hash_contract": true,
        "not_hysteria2_pin_sha256": true,
        "boundary": "live cert-chain verification is not DialAuth, TransportPacketConn, stream_packet_conn, congestion, or outbound/default/product admission"
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations": opts.benchmark_iters,
        "elapsed_ns": null,
        "ns_per_juicity_live_certchain_h3_exchange": null,
        "pin_format": "url-base64",
        "certchain_hash_hex": null,
        "scope": "rootless local QUIC/H3 request-response loopback with TLS1.3+h3 ALPN and Stage115 pinned_certchain verifier executed inside the rustls certificate callback",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "Juicity DialAuth, packet conn, congestion behavior, outbound registry/group semantics, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "hysteria2_udp_underlay_admitted": true,
        "hysteria2_true_quic_dataplane_admitted": false,
        "tuic_udp_underlay_socket_admitted": true,
        "tuic_true_quic_dataplane_admitted": false,
        "juicity_h3_loopback_dependency_admitted": true,
        "juicity_h3_loopback_smoke_executed": false,
        "juicity_h3_handshake_admitted": false,
        "juicity_tls_verify_peer_certificate_hook_admitted": false,
        "juicity_tls_certchain_verification_admitted": false,
        "juicity_pinned_certchain_live_callback_matched": false,
        "juicity_true_quic_h3_dataplane_admitted": false,
        "quic_h3_family_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": true,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Juicity DialAuth TransportPacketConn for UDP port 0",
        "Juicity stream_packet_conn packet-over-stream behavior for nonzero UDP targets",
        "Juicity congestion behavior and packet relay benchmark",
        "Hysteria2 full QUIC and TUIC true QUIC dataplanes",
        "outbound registry/dialer group/health policy parity while preserving direct/block indices and NewDialerSetFromLinks semantics",
        "matched Go default daemon vs true Rust candidate benchmark",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage119/juicity_live_certchain_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage119_juicity_live_certchain_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage119 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage119-juicity-live-certchain-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage119-juicity-live-certchain-admission --execute-smoke --benchmark-iters 5",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage119 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage119 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage118 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage119",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.16",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.20",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "rust/crates/dae-outbound/src/juicity/certchain.rs",
        "rust/crates/dae-outbound/src/juicity/h3_loopback.rs",
        "rust/crates/dae-cli/src/runtime_stage119_juicity_live_certchain_gate/"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    let smoke_options = juicity::JuicityH3LoopbackOptions {
        payload: opts.payload.clone(),
        iterations: opts.benchmark_iters,
        timeout: opts.timeout,
        verify_pinned_certchain: true,
        ..Default::default()
    };
    match juicity::run_h3_loopback_smoke(&smoke_options) {
        Ok(outcome) => apply_stage119_outcome(&mut report, &outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([format!("{err}")]);
        }
    }
    report
}

fn apply_stage119_outcome(report: &mut Value, outcome: &juicity::JuicityH3LoopbackReport) {
    let passed = outcome.h3_request_response_validated
        && outcome.quic_handshake_validated
        && outcome.certificate_chain_callback_observed
        && outcome.live_certchain_pin_matched
        && outcome.juicity_tls_certchain_verification_admitted;
    report["read_only"] = json!(false);
    report["blocked"] = json!(!passed);
    report["blockers"] = if passed {
        json!([])
    } else {
        json!([
            "stage119 live H3 cert-chain verification smoke did not satisfy all admission checks"
        ])
    };
    report["juicity_h3_loopback_smoke_executed"] = json!(passed);
    report["juicity_h3_loopback_benchmark_recorded"] = json!(passed);
    report["juicity_tls_verify_peer_certificate_hook_admitted"] =
        json!(outcome.juicity_tls_verify_peer_certificate_hook_admitted);
    report["juicity_tls_certchain_verification_admitted"] =
        json!(outcome.juicity_tls_certchain_verification_admitted);
    report["juicity_pinned_certchain_live_callback_matched"] =
        json!(outcome.live_certchain_pin_matched);
    report["juicity_h3_handshake_admitted"] = json!(outcome.juicity_h3_handshake_admitted);
    report["h3_loopback"] = json!({
        "server_name": outcome.server_name,
        "alpn_protocol": outcome.alpn_protocol,
        "tls13_only_configured": outcome.tls13_only_configured,
        "quic_datagram_disabled": outcome.quic_datagram_disabled,
        "keepalive_secs": outcome.keepalive_secs,
        "handshake_idle_timeout_secs": outcome.handshake_idle_timeout_secs,
        "loopback_addr": outcome.loopback_addr,
        "client_selected_alpn": outcome.client_selected_alpn,
        "server_selected_alpn": outcome.server_selected_alpn,
        "h3_status": outcome.h3_status,
        "payload_len": outcome.payload_len,
        "echoed_payload_len": outcome.echoed_payload.len(),
        "certificate_chain_callback_observed": outcome.certificate_chain_callback_observed,
        "certificate_chain_der_count": outcome.certificate_chain_der_count,
        "certificate_chain_hash_hex": outcome.certificate_chain_hash_hex,
        "verifier_server_name": outcome.verifier_server_name,
        "boundary": "local H3 cert-chain verification is admitted, but DialAuth, packet conn, congestion, outbound/default/product remain closed"
    });
    report["live_certchain"] = json!({
        "requested_when_smoke_executes": true,
        "generated_pin_format": outcome.live_certchain_pin_format,
        "generated_pin_len": outcome.live_certchain_pin_len,
        "pinned_certchain_live_callback_matched": outcome.live_certchain_pin_matched,
        "pinned_certchain_live_callback_error": outcome.live_certchain_pin_error,
        "forces_insecure_verify_contract": true,
        "verifies_full_chain_hash_contract": true,
        "not_hysteria2_pin_sha256": true,
        "boundary": "Stage115 verifier is wired into the live rustls callback; Juicity DialAuth and packet relay are still not admitted"
    });
    report["benchmark"] = json!({
        "benchmark_recorded": passed,
        "iterations": outcome.iterations,
        "elapsed_ns": outcome.elapsed_ns,
        "ns_per_juicity_live_certchain_h3_exchange": outcome.ns_per_juicity_live_certchain_h3_exchange,
        "pin_format": outcome.live_certchain_pin_format,
        "certchain_hash_hex": outcome.certificate_chain_hash_hex,
        "scope": "rootless local QUIC/H3 request-response loopback with TLS1.3+h3 ALPN and Stage115 pinned_certchain verifier executed inside the rustls certificate callback",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "Juicity DialAuth, packet conn, congestion behavior, outbound registry/group semantics, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"]["juicity_h3_loopback_smoke_executed"] = json!(passed);
    report["protocol_matrix"]["juicity_h3_handshake_admitted"] =
        json!(outcome.juicity_h3_handshake_admitted);
    report["protocol_matrix"]["juicity_tls_verify_peer_certificate_hook_admitted"] =
        json!(outcome.juicity_tls_verify_peer_certificate_hook_admitted);
    report["protocol_matrix"]["juicity_tls_certchain_verification_admitted"] =
        json!(outcome.juicity_tls_certchain_verification_admitted);
    report["protocol_matrix"]["juicity_pinned_certchain_live_callback_matched"] =
        json!(outcome.live_certchain_pin_matched);
}

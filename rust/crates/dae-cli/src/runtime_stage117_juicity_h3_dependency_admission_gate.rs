use dae_outbound::juicity;
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage117_juicity_h3_dependency_admission(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage117 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage117_report()))
}

fn stage117_report() -> Value {
    let admission = juicity::dependency_admission();
    let mut report = json!({
        "name": "stage117-juicity-h3-dependency-admission",
        "stage": "stage117",
        "evidence_class": "read-only-juicity-h3-dependency-compile-admission-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": true,
        "blockers": [
            "H3/QUIC dependencies are compile-admitted but no live loopback handshake has been executed",
            "Juicity live TLS VerifyPeerCertificate hook over H3 remains unimplemented",
            "Juicity DialAuth, transport packet conn, stream packet conn, and congestion behavior remain blocked",
            "external outbound/quic-go remains required"
        ]
    });
    for key in [
        "rustls_dependency_available",
        "rcgen_dependency_available",
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
        "juicity_tls_verify_peer_certificate_hook_admitted",
        "juicity_tls_certchain_verification_admitted",
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
    report["dependency_inventory"] = json!({
        "quinn_version": admission.quinn_version,
        "h3_version": admission.h3_version,
        "h3_quinn_version": admission.h3_quinn_version,
        "tokio_version": admission.tokio_version,
        "quinn_features": juicity::h3_admission::QUINN_FEATURES,
        "tokio_features": juicity::h3_admission::TOKIO_FEATURES,
        "quinn_endpoint_type": admission.quinn_endpoint_type,
        "h3_quinn_connection_type": admission.h3_quinn_connection_type,
        "h3_client_builder_type": admission.h3_client_builder_type,
        "tokio_runtime_builder_type": admission.tokio_runtime_builder_type,
        "dependency_only": admission.dependency_only,
        "current_boundary": "dependencies are admitted and compile-referenced with the workspace rustls aws-lc-rs provider, but no H3 loopback handshake or Juicity protocol exchange has run"
    });
    report["queue_rows"] = json!([
        {
            "area": "H3/QUIC dependency admission",
            "status": "passed-compile-admission",
            "source_stage": "stage117",
            "admitted": true,
            "evidence": "dae-outbound now depends on quinn, h3, h3-quinn, and tokio; Stage117 compile test references Endpoint, h3_quinn Connection, h3 client Builder, and tokio runtime Builder",
            "boundary": "compile admission is not a live H3 handshake"
        },
        {
            "area": "Juicity TLS/cert-chain prerequisites",
            "status": "passed-carried-evidence",
            "source_stage": "stage115",
            "admitted": true,
            "evidence": "Stage115 cert-chain hash verifier vectors and Stage116 rustls/rcgen inventory are carried",
            "boundary": "cert-chain hash vector evidence is not wired into VerifyPeerCertificate over H3"
        },
        {
            "area": "live H3 loopback smoke",
            "status": "blocked-not-executed",
            "source_stage": "stage117",
            "admitted": false,
            "evidence": "Stage117 intentionally stops at dependency compile admission and does not create a quinn endpoint pair or h3 client/server session",
            "boundary": "juicity_h3_handshake_admitted remains false until a loopback smoke passes"
        },
        {
            "area": "DialAuth and packet conn dataplane",
            "status": "blocked",
            "source_stage": "stage117",
            "admitted": false,
            "evidence": "DialAuth, TransportPacketConn, stream_packet_conn, packet-over-stream, and congestion behavior still require real Juicity H3 session state",
            "boundary": "dependency admission does not admit juicity_true_quic_h3_dataplane_admitted"
        },
        {
            "area": "outbound/default/product",
            "status": "blocked",
            "source_stage": "stage117",
            "admitted": false,
            "evidence": "Juicity H3, TUIC true QUIC, Hysteria2 full QUIC, outbound registry/group/health, matched default daemon benchmark, and product-chain recertification remain open",
            "boundary": "dependency admission does not admit quic_h3_family/outbound/default/product switches"
        }
    ]);
    report["benchmark_carry_forward"] = json!({
        "stage112_ns_per_tuic_udp_underlay_exchange": 29366.5,
        "new_network_benchmark_recorded": false,
        "reason": "Stage 117 is a compile-only dependency admission gate and does not execute a network dataplane"
    });
    report["protocol_matrix"] = json!({
        "hysteria2_udp_underlay_admitted": true,
        "hysteria2_true_quic_dataplane_admitted": false,
        "tuic_udp_underlay_socket_admitted": true,
        "tuic_true_quic_dataplane_admitted": false,
        "juicity_h3_loopback_dependency_admitted": true,
        "juicity_h3_loopback_smoke_executed": false,
        "juicity_tls_certchain_verification_admitted": false,
        "juicity_true_quic_h3_dataplane_admitted": false,
        "quic_h3_family_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": true,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Juicity local H3 loopback endpoint pair and client/server session smoke",
        "Juicity live TLS VerifyPeerCertificate hook inside a real H3 handshake",
        "Juicity DialAuth TransportPacketConn for UDP port 0",
        "Juicity stream_packet_conn packet-over-stream behavior for nonzero UDP targets",
        "Juicity congestion behavior and H3 packet relay benchmark",
        "Hysteria2 full QUIC and TUIC true QUIC dataplanes",
        "outbound registry/dialer group/health policy parity while preserving direct/block indices and NewDialerSetFromLinks semantics",
        "matched Go default daemon vs true Rust candidate benchmark",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "cargo check --manifest-path rust/Cargo.toml -p dae-outbound",
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage117/juicity_h3_dependency_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage117_juicity_h3_dependency_admission_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage117 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage117-juicity-h3-dependency-admission",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage117 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage117 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage117",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.16",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.20",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "rust/Cargo.toml",
        "rust/crates/dae-outbound/Cargo.toml",
        "rust/crates/dae-outbound/src/juicity/h3_admission.rs",
        "rust/crates/dae-cli/src/runtime_stage117_juicity_h3_dependency_admission_gate.rs"
    ]);
    report
}

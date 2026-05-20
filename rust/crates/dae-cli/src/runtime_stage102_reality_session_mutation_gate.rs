use dae_outbound::shared_transport;
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage102_reality_session_id_mutation_readiness(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage102 argument: {arg}"));
    }
    match stage102_report() {
        Ok(report) => RunnerOutput::ok(format!("{report}\n")),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

fn stage102_report() -> Result<Value, dae_outbound::OutboundError> {
    let aes_options = default_reality_options(shared_transport::RealityAeadAlgorithm::AesGcm);
    let chacha_options =
        default_reality_options(shared_transport::RealityAeadAlgorithm::ChaCha20Poly1305);
    let aes_report = shared_transport::reality_session_id_mutation_report(&aes_options)?;
    let chacha_report = shared_transport::reality_session_id_mutation_report(&chacha_options)?;
    let mut report = json!({
        "name": "stage102-reality-session-id-mutation-readiness",
        "stage": "stage102",
        "evidence_class": "read-only-reality-session-id-aead-mutation",
        "read_only": true,
        "blocked": false,
        "blockers": []
    });
    report["trojan_go_tls_fragment_admitted"] = json!(true);
    report["trojan_go_utls_fingerprint_selection_admitted"] = json!(true);
    report["trojan_go_utls_fingerprint_wire_admitted"] = json!(false);
    report["reality_session_id_aead_mutation_admitted"] = json!(true);
    report["reality_full_utls_handshake_admitted"] = json!(false);
    report["trojan_go_reality_mutation_admitted"] = json!(false);
    report["trojan_go_cross_combination_recertified"] = json!(false);
    report["trojan_go_shared_transport_partial_admitted"] = json!(true);
    report["trojan_go_shared_transport_admitted"] = json!(false);
    report["shared_transport_true_dataplane_admitted"] = json!(false);
    report["protocol_outbound_partial_admitted"] = json!(true);
    report["outbound_true_dataplane_admitted"] = json!(false);
    report["matched_go_rust_default_daemon_benchmark_recorded"] = json!(false);
    report["default_switch_allowed"] = json!(false);
    report["default_path_mutation_allowed"] = json!(false);
    report["product_chain_switch_allowed"] = json!(false);
    report["true_rust_default_daemon_admitted"] = json!(false);
    report["go_default_path_preserved"] = json!(true);
    report["go_fallback_required"] = json!(true);
    report["reality_mutation_contract"] = json!({
        "go_source": "/root/project/outbound/transport/tls/reality.go",
        "version": [1, 8, 10],
        "session_id_plaintext_len": shared_transport::REALITY_SESSION_ID_PLAINTEXT_LEN,
        "session_id_len": shared_transport::REALITY_SESSION_ID_LEN,
        "hkdf_salt_len": shared_transport::REALITY_HKDF_SALT_LEN,
        "aead_nonce_len": shared_transport::REALITY_AEAD_NONCE_LEN,
        "session_id_raw_offset": shared_transport::REALITY_SESSION_ID_RAW_OFFSET,
        "aes_gcm": {
            "plaintext_session_id_hex": aes_report.plaintext_session_id_hex,
            "mutated_session_id_hex": aes_report.mutated_session_id_hex,
            "auth_key_hex": aes_report.auth_key_hex,
            "nonce_hex": aes_report.nonce_hex,
            "hello_raw_len": aes_report.hello_raw_len,
            "mutation_applied_to_hello_raw": aes_report.mutation_applied_to_hello_raw,
            "full_utls_stack": aes_report.full_utls_stack
        },
        "chacha20poly1305": {
            "plaintext_session_id_hex": chacha_report.plaintext_session_id_hex,
            "mutated_session_id_hex": chacha_report.mutated_session_id_hex,
            "auth_key_hex": chacha_report.auth_key_hex,
            "nonce_hex": chacha_report.nonce_hex,
            "hello_raw_len": chacha_report.hello_raw_len,
            "mutation_applied_to_hello_raw": chacha_report.mutation_applied_to_hello_raw,
            "full_utls_stack": chacha_report.full_utls_stack
        },
        "wire_utls_handshake_deferred": true,
        "verify_peer_certificate_deferred": true,
        "spider_behavior_deferred": true,
        "default_go_path_preserved": true
    });
    report["remaining_blockers"] = json!([
        "REALITY full uTLS handshake state mutation is still incomplete",
        "REALITY VerifyPeerCertificate and spider fallback behavior are still incomplete",
        "Trojan-Go uTLS wire-level ClientHello fingerprint row is still incomplete",
        "Trojan-Go cross-combination recertification is still incomplete",
        "VLESS and VMess TLS/WSS/gRPC/Meek/xHTTP full shared transport rows remain protocol-specific blockers",
        "Hysteria2, TUIC, Juicity, AnyTLS, Vision, and QUIC/H3 true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage102/reality_session_id_mutation_readiness.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage102_reality_session_id_mutation_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage102 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage102 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage102 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage102",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "/root/project/outbound/transport/tls/reality.go",
        "rust/crates/dae-outbound/src/shared_transport/reality_aead.rs"
    ]);
    Ok(report)
}

fn default_reality_options(
    algorithm: shared_transport::RealityAeadAlgorithm,
) -> shared_transport::RealitySessionIdMutationOptions {
    let sid = [0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44];
    let unix_seconds = 1_717_171_717;
    let mut client_random = [0_u8; shared_transport::REALITY_CLIENT_RANDOM_LEN];
    for (index, byte) in client_random.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(7).wrapping_add(3);
    }
    let mut shared_secret = [0_u8; 32];
    for (index, byte) in shared_secret.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(11).wrapping_add(5);
    }
    let plaintext = shared_transport::reality_session_id_plaintext(sid, unix_seconds);
    let mut hello_raw = vec![0x42; 96];
    hello_raw[shared_transport::REALITY_SESSION_ID_RAW_OFFSET
        ..shared_transport::REALITY_SESSION_ID_RAW_OFFSET
            + shared_transport::REALITY_SESSION_ID_PLAINTEXT_LEN]
        .copy_from_slice(&plaintext);
    shared_transport::RealitySessionIdMutationOptions {
        sid,
        unix_seconds,
        client_random,
        shared_secret,
        hello_raw,
        algorithm,
    }
}

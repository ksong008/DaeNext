use dae_outbound::juicity;
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const GO_CHAIN_HASH_HEX: &str = "584fb94485a58b9036f20086e915df79e51c4eb8b7dbb46fb75a113bb656bf4e";
const URL_SAFE_PIN: &str = "WE-5RIWli5A28gCG6RXfeeUcTri327Rvt1oRO7ZWv04=";
const STD_PIN: &str = "WE+5RIWli5A28gCG6RXfeeUcTri327Rvt1oRO7ZWv04=";

pub(crate) fn run_stage115_juicity_certchain_verifier_admission(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage115 argument: {arg}"));
    }
    match stage115_report() {
        Ok(report) => RunnerOutput::ok(format!("{report}\n")),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

fn stage115_report() -> Result<Value, String> {
    let raw = [b"leaf-0".as_slice(), b"intermediate-0".as_slice()];
    let url_check = juicity::verify_pinned_certchain(&raw, URL_SAFE_PIN)
        .map_err(|err| format!("stage115 url-base64 vector failed: {err}"))?;
    let std_check = juicity::verify_pinned_certchain(&raw, STD_PIN)
        .map_err(|err| format!("stage115 std-base64 vector failed: {err}"))?;
    let hex_looking_check = juicity::check_pinned_certchain(&raw, GO_CHAIN_HASH_HEX)
        .map_err(|err| format!("stage115 hex-looking vector failed: {err}"))?;
    let mismatch_error = juicity::verify_pinned_certchain(&raw, GO_CHAIN_HASH_HEX)
        .unwrap_err()
        .to_string();

    let chain_hash_hex = hex_encode(&url_check.chain_hash);
    let mut report = json!({
        "name": "stage115-juicity-certchain-verifier-admission",
        "stage": "stage115",
        "evidence_class": "juicity-certchain-hash-verifier-vector-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": true,
        "blockers": [
            "Juicity live TLS VerifyPeerCertificate hook over H3 is not implemented in Rust",
            "Juicity H3 handshake, DialAuth, transport packet conn, and stream packet conn remain blocked",
            "64-character SHA256 hex-looking pins are decoded as URL-base64 first for daenew parity and must not be treated as an admitted live hex verification path",
            "external outbound/quic-go remains required"
        ]
    });
    for key in [
        "juicity_native_optin_contract_admitted",
        "juicity_uuid_password_contract_admitted",
        "juicity_tls13_h3_alpn_config_contract_admitted",
        "juicity_pinned_certchain_decode_contract_admitted",
        "juicity_certchain_hash_algorithm_admitted",
        "juicity_pinned_certchain_url_base64_verify_vector_admitted",
        "juicity_pinned_certchain_std_base64_verify_vector_admitted",
        "juicity_pinned_certchain_forces_insecure_verify_contract_admitted",
        "juicity_pinned_certchain_full_chain_hash_contract_admitted",
        "juicity_pinned_certchain_not_hysteria2_pin_sha256_recorded",
        "juicity_pinned_certchain_hex_decode_caveat_recorded",
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
    report["certchain_vector"] = json!({
        "raw_cert_count": url_check.cert_count,
        "go_chain_hash_hex": GO_CHAIN_HASH_HEX,
        "rust_chain_hash_hex": chain_hash_hex,
        "url_base64_pin_format": url_check.pin_format,
        "url_base64_pin_matched": url_check.matched,
        "std_base64_pin_format": std_check.pin_format,
        "std_base64_pin_matched": std_check.matched,
        "forces_insecure_verify": url_check.forces_insecure_verify,
        "verifies_full_chain_hash": url_check.verifies_full_chain_hash,
        "not_hysteria2_pin_sha256": url_check.not_hysteria2_pin_sha256,
        "hex_looking_sha256_pin_input_len": GO_CHAIN_HASH_HEX.len(),
        "hex_looking_sha256_pin_format": hex_looking_check.pin_format,
        "hex_looking_sha256_decoded_pin_len": hex_looking_check.decoded_pin.len(),
        "hex_looking_sha256_chain_hash_len": hex_looking_check.chain_hash.len(),
        "hex_looking_sha256_pin_matched": hex_looking_check.matched,
        "hex_looking_sha256_mismatch_error": mismatch_error
    });
    report["queue_rows"] = json!([
        {
            "area": "Go cert-chain hash algorithm",
            "status": "passed-local-vector",
            "source_stage": "stage115",
            "admitted": true,
            "evidence": "Rust generate_cert_chain_hash matches daenew common.GenerateCertChainHash for leaf-0/intermediate-0 fixed vector",
            "boundary": "algorithm parity is not a live TLS VerifyPeerCertificate callback over H3"
        },
        {
            "area": "URL-base64 and std-base64 pin verification vectors",
            "status": "passed-local-vector",
            "source_stage": "stage115",
            "admitted": true,
            "evidence": "Rust verify_pinned_certchain accepts both URL-base64 and std-base64 encodings for the same chain hash",
            "boundary": "local vectors do not prove H3 handshake, certificate exchange, or verified server identity"
        },
        {
            "area": "64-character hex-looking SHA256 pin caveat",
            "status": "blocked-go-compat-caveat-recorded",
            "source_stage": "stage115",
            "admitted": false,
            "evidence": "daenew decode order tries URL-base64 before hex; a 64-character SHA256 hex-looking pin decodes as URL-base64 to 48 bytes and mismatches the 32-byte chain hash",
            "boundary": "Rust must preserve this daenew behavior unless a deliberate compatibility change is planned"
        },
        {
            "area": "live Juicity H3 TLS verification",
            "status": "blocked",
            "source_stage": "stage115",
            "admitted": false,
            "evidence": "Rust has no live TLS VerifyPeerCertificate hook wired to a Juicity H3 handshake",
            "boundary": "certchain hash vector admission does not admit juicity_tls_certchain_verification_admitted or juicity_true_quic_h3_dataplane_admitted"
        },
        {
            "area": "outbound/default/product",
            "status": "blocked",
            "source_stage": "stage115",
            "admitted": false,
            "evidence": "Juicity H3, TUIC true QUIC, Hysteria2 full QUIC, outbound registry/group/health, matched default daemon benchmark, and product-chain recertification remain open",
            "boundary": "certchain verifier vectors do not admit quic_h3_family/outbound/default/product switches"
        }
    ]);
    report["benchmark_carry_forward"] = json!({
        "stage112_ns_per_tuic_udp_underlay_exchange": 29366.5,
        "new_network_benchmark_recorded": false,
        "reason": "Stage 115 is a local Juicity cert-chain hash verifier vector gate and does not execute a network dataplane"
    });
    report["protocol_matrix"] = json!({
        "hysteria2_udp_underlay_admitted": true,
        "hysteria2_true_quic_dataplane_admitted": false,
        "tuic_udp_underlay_socket_admitted": true,
        "tuic_true_quic_dataplane_admitted": false,
        "juicity_certchain_hash_algorithm_admitted": true,
        "juicity_pinned_certchain_url_base64_verify_vector_admitted": true,
        "juicity_pinned_certchain_std_base64_verify_vector_admitted": true,
        "juicity_tls_certchain_verification_admitted": false,
        "juicity_true_quic_h3_dataplane_admitted": false,
        "quic_h3_family_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": true,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
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
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage115/juicity_certchain_verifier_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage115_juicity_certchain_verifier_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage115 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage115-juicity-certchain-verifier-admission",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage115 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage115 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage115",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:12.6",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.16",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.20",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "/root/project/outbound/common/common.go:GenerateCertChainHash",
        "/root/project/outbound/dialer/juicity/juicity.go",
        "rust/crates/dae-outbound/src/juicity/certchain.rs",
        "rust/crates/dae-cli/src/runtime_stage115_juicity_certchain_gate.rs"
    ]);
    Ok(report)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

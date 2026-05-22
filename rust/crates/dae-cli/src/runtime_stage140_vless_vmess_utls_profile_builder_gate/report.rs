use dae_outbound::shared_transport::{
    build_synthetic_utls_client_hello_record_hex, parse_utls_client_hello_record_hex,
};
use serde_json::{Value, json};

const GO_UTLS_CLIENTHELLO_PROFILE_JSON: &str = include_str!(
    "../../../../../testdata/rebuild-golden/outbound/protocol/stage139_go_utls_clienthello_profile.json"
);

pub(super) fn stage140_report() -> Result<Value, String> {
    let stats = builder_stats()?;
    let mut report = json!({
        "name": "stage140-vless-vmess-utls-profile-builder-gate",
        "stage": "stage140",
        "evidence_class": "read-only-vless-vmess-utls-synthetic-profile-builder-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": false,
        "blockers": []
    });
    for key in [
        "utls_wire_baseline_fixture_recorded",
        "utls_wire_profile_parser_admitted",
        "utls_wire_profile_builder_admitted",
        "vless_xhttp_h2_h3_lifecycle_admitted",
        "vmess_xhttp_h2_h3_lifecycle_admitted",
        "vless_protocol_partial_admitted",
        "vmess_protocol_partial_admitted",
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
        "utls_wire_full_handshake_builder_admitted",
        "vless_utls_fingerprint_wire_admitted",
        "vmess_utls_fingerprint_wire_admitted",
        "vless_reality_full_handshake_admitted",
        "vless_vision_tls_reality_admitted",
        "vless_protocol_true_dataplane_admitted",
        "vmess_protocol_true_dataplane_admitted",
        "trojan_go_shared_transport_admitted",
        "shared_transport_true_dataplane_admitted",
        "outbound_true_dataplane_admitted",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
        "true_rust_default_daemon_admitted",
    ] {
        report[key] = json!(false);
    }
    report["utls_profile_builder"] = json!({
        "source_fixture": "testdata/rebuild-golden/outbound/protocol/stage139_go_utls_clienthello_profile.json",
        "sample_count": stats.sample_count,
        "synthetic_record_count": stats.synthetic_record_count,
        "roundtrip_profile_match_count": stats.roundtrip_profile_match_count,
        "all_synthetic_profiles_match_source": stats.sample_count == stats.roundtrip_profile_match_count,
        "total_extension_type_count": stats.total_extension_type_count,
        "total_cipher_suite_count": stats.total_cipher_suite_count,
        "sample_profiles": stats.sample_profiles,
        "synthetic_profile_builder": true,
        "full_utls_handshake_builder": false,
        "random_and_key_share_bytes_are_synthetic": true,
        "wire_emission_order_validated": true
    });
    report["utls_wire_boundaries"] = json!({
        "profile_parser_admitted": true,
        "synthetic_profile_builder_admitted": true,
        "full_utls_handshake_builder_admitted": false,
        "rustls_is_not_utls": true,
        "reality_raw_hello_mutation_ready": false,
        "verify_peer_certificate_admitted": false,
        "vision_intrinsic_conn_hook_admitted": false,
        "required_next": "replace synthetic profile emission with a true uTLS-compatible handshake builder or keep Go outbound fallback for uTLS/REALITY/Vision paths"
    });
    report["benchmark"] = json!({
        "profile_metric_recorded": true,
        "network_benchmark_recorded": false,
        "fixture_sample_count": stats.sample_count,
        "synthetic_record_count": stats.synthetic_record_count,
        "roundtrip_profile_match_count": stats.roundtrip_profile_match_count,
        "total_extension_type_count": stats.total_extension_type_count,
        "total_cipher_suite_count": stats.total_cipher_suite_count,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "reason": "Stage140 validates synthetic ClientHello profile emission only; it is not a real uTLS network handshake benchmark"
    });
    report["remaining_blockers"] = json!([
        "Synthetic profile builder is not a full uTLS handshake implementation",
        "VLESS/VMess uTLS wire-level fingerprint admission remains closed",
        "VLESS REALITY full uTLS handshake, VerifyPeerCertificate, and spider fallback are incomplete",
        "VLESS XTLS Vision intrinsic TLS/REALITY conn hook is incomplete",
        "VMess uTLS full-combination recertification is incomplete",
        "Trojan-Go full shared transport remains blocked",
        "shared_transport_true_dataplane and outbound_true_dataplane remain closed until all protocol rows close",
        "matched Go default daemon vs true Rust candidate benchmark remains missing",
        "default daemon and product-chain switches remain closed"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage140/vless_vmess_utls_profile_builder_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage140_vless_vmess_utls_profile_builder_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage140 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage140-vless-vmess-utls-profile-builder-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage140 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage140 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage139 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage140",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "/root/project/outbound/transport/tls/utls.go",
        "/root/project/outbound/transport/tls/reality.go",
        "testdata/rebuild-golden/outbound/protocol/stage139_go_utls_clienthello_profile.json",
        "rust/crates/dae-outbound/src/shared_transport/utls_wire.rs",
        "rust/crates/dae-outbound/src/shared_transport/utls_wire_builder.rs"
    ]);
    Ok(report)
}

struct BuilderStats {
    sample_count: usize,
    synthetic_record_count: usize,
    roundtrip_profile_match_count: usize,
    total_extension_type_count: usize,
    total_cipher_suite_count: usize,
    sample_profiles: Vec<Value>,
}

fn builder_stats() -> Result<BuilderStats, String> {
    let fixture: Value = serde_json::from_str(GO_UTLS_CLIENTHELLO_PROFILE_JSON)
        .map_err(|err| format!("failed to parse stage139 Go uTLS fixture: {err}"))?;
    let samples = fixture["samples"]
        .as_array()
        .ok_or_else(|| "stage139 Go uTLS fixture missing samples".to_owned())?;
    let mut synthetic_record_count = 0;
    let mut roundtrip_profile_match_count = 0;
    let mut total_extension_type_count = 0;
    let mut total_cipher_suite_count = 0;
    let mut sample_profiles = Vec::new();
    for sample in samples {
        let fingerprint = sample["fingerprint"]
            .as_str()
            .ok_or_else(|| "stage139 Go uTLS fixture sample missing fingerprint".to_owned())?;
        let source_profile =
            parse_utls_client_hello_record_hex(sample["record_hex"].as_str().unwrap_or_default())
                .map_err(|err| format!("{fingerprint}: fixture parse failed: {err}"))?;
        let synthetic_hex = build_synthetic_utls_client_hello_record_hex(&source_profile)
            .map_err(|err| format!("{fingerprint}: synthetic build failed: {err}"))?;
        let synthetic_profile = parse_utls_client_hello_record_hex(&synthetic_hex)
            .map_err(|err| format!("{fingerprint}: synthetic parse failed: {err}"))?;
        synthetic_record_count += 1;
        if synthetic_profile == source_profile {
            roundtrip_profile_match_count += 1;
        }
        total_extension_type_count += synthetic_profile.extension_types.len();
        total_cipher_suite_count += synthetic_profile.cipher_suites.len();
        sample_profiles.push(json!({
            "fingerprint": fingerprint,
            "record_len": synthetic_profile.record_len,
            "handshake_len": synthetic_profile.handshake_len,
            "cipher_suite_count": synthetic_profile.cipher_suites.len(),
            "extension_type_count": synthetic_profile.extension_types.len(),
            "roundtrip_profile_matches_source": synthetic_profile == source_profile
        }));
    }
    Ok(BuilderStats {
        sample_count: samples.len(),
        synthetic_record_count,
        roundtrip_profile_match_count,
        total_extension_type_count,
        total_cipher_suite_count,
        sample_profiles,
    })
}

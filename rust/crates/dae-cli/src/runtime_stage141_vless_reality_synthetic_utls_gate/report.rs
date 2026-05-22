use dae_outbound::shared_transport::{
    RealityAeadAlgorithm, SyntheticRealityUtlsMutationOptions, parse_utls_client_hello_record_hex,
    synthetic_reality_utls_mutation_report,
};
use serde_json::{Value, json};

const GO_UTLS_CLIENTHELLO_PROFILE_JSON: &str = include_str!(
    "../../../../../testdata/rebuild-golden/outbound/protocol/stage139_go_utls_clienthello_profile.json"
);

pub(super) fn stage141_report() -> Result<Value, String> {
    let stats = mutation_stats()?;
    let mut report = json!({
        "name": "stage141-vless-reality-synthetic-utls-raw-mutation-gate",
        "stage": "stage141",
        "evidence_class": "read-only-vless-reality-synthetic-utls-raw-mutation-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": false,
        "blockers": []
    });
    for key in [
        "utls_wire_baseline_fixture_recorded",
        "utls_wire_profile_parser_admitted",
        "utls_wire_profile_builder_admitted",
        "vless_reality_synthetic_utls_raw_mutation_admitted",
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
        "vless_reality_full_handshake_admitted",
        "vless_reality_verify_peer_certificate_admitted",
        "vless_reality_spider_fallback_admitted",
        "vless_utls_fingerprint_wire_admitted",
        "vmess_utls_fingerprint_wire_admitted",
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
    report["synthetic_reality_utls_raw_mutation"] = json!({
        "source_fixture": "testdata/rebuild-golden/outbound/protocol/stage139_go_utls_clienthello_profile.json",
        "sample_count": stats.sample_count,
        "algorithm_count": 2,
        "mutation_report_count": stats.mutation_report_count,
        "profile_preserved_count": stats.profile_preserved_count,
        "all_profiles_preserved_after_mutation": stats.mutation_report_count == stats.profile_preserved_count,
        "session_id_hello_raw_offset": 39,
        "session_id_record_offset": 44,
        "session_id_len": 32,
        "reports": stats.reports,
        "full_utls_stack": false,
        "verify_peer_certificate_admitted": false,
        "spider_fallback_admitted": false
    });
    report["benchmark"] = json!({
        "profile_metric_recorded": true,
        "network_benchmark_recorded": false,
        "fixture_sample_count": stats.sample_count,
        "algorithm_count": 2,
        "mutation_report_count": stats.mutation_report_count,
        "profile_preserved_count": stats.profile_preserved_count,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "reason": "Stage141 mutates synthetic ClientHello raw bytes only; it is not a live REALITY handshake benchmark"
    });
    report["remaining_blockers"] = json!([
        "Synthetic REALITY raw mutation is not a full uTLS handshake implementation",
        "VLESS REALITY VerifyPeerCertificate and spider fallback are incomplete",
        "VLESS/VMess uTLS wire-level fingerprint admission remains closed",
        "VLESS XTLS Vision intrinsic TLS/REALITY conn hook is incomplete",
        "VMess uTLS full-combination recertification is incomplete",
        "Trojan-Go full shared transport remains blocked",
        "shared_transport_true_dataplane and outbound_true_dataplane remain closed until all protocol rows close",
        "matched Go default daemon vs true Rust candidate benchmark remains missing",
        "default daemon and product-chain switches remain closed"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage141/vless_reality_synthetic_utls_raw_mutation_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage141_vless_reality_synthetic_utls_raw_mutation_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage141 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage141-vless-reality-synthetic-utls-raw-mutation-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage141 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage141 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage140 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage141",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "/root/project/outbound/transport/tls/reality.go",
        "rust/crates/dae-outbound/src/shared_transport/reality_aead.rs",
        "rust/crates/dae-outbound/src/shared_transport/reality_utls_synthetic.rs",
        "rust/crates/dae-outbound/src/shared_transport/utls_wire_builder.rs"
    ]);
    Ok(report)
}

struct MutationStats {
    sample_count: usize,
    mutation_report_count: usize,
    profile_preserved_count: usize,
    reports: Vec<Value>,
}

fn mutation_stats() -> Result<MutationStats, String> {
    let fixture: Value = serde_json::from_str(GO_UTLS_CLIENTHELLO_PROFILE_JSON)
        .map_err(|err| format!("failed to parse stage139 Go uTLS fixture: {err}"))?;
    let samples = fixture["samples"]
        .as_array()
        .ok_or_else(|| "stage139 Go uTLS fixture missing samples".to_owned())?;
    let mut mutation_report_count = 0;
    let mut profile_preserved_count = 0;
    let mut reports = Vec::new();
    for sample in samples {
        let fingerprint = sample["fingerprint"]
            .as_str()
            .ok_or_else(|| "stage139 Go uTLS fixture sample missing fingerprint".to_owned())?;
        let profile =
            parse_utls_client_hello_record_hex(sample["record_hex"].as_str().unwrap_or_default())
                .map_err(|err| format!("{fingerprint}: fixture parse failed: {err}"))?;
        for algorithm in [
            RealityAeadAlgorithm::AesGcm,
            RealityAeadAlgorithm::ChaCha20Poly1305,
        ] {
            let report =
                synthetic_reality_utls_mutation_report(&options(profile.clone(), algorithm))
                    .map_err(|err| {
                        format!("{fingerprint}: synthetic REALITY mutation failed: {err}")
                    })?;
            mutation_report_count += 1;
            if report.profile_preserved_after_mutation {
                profile_preserved_count += 1;
            }
            reports.push(json!({
                "fingerprint": fingerprint,
                "algorithm": report.algorithm,
                "synthetic_record_len": report.synthetic_record_len,
                "hello_raw_len": report.hello_raw_len,
                "mutation_applied_to_hello_raw": report.mutation_applied_to_hello_raw,
                "mutation_applied_to_record": report.mutation_applied_to_record,
                "profile_preserved_after_mutation": report.profile_preserved_after_mutation
            }));
        }
    }
    Ok(MutationStats {
        sample_count: samples.len(),
        mutation_report_count,
        profile_preserved_count,
        reports,
    })
}

fn options(
    profile: dae_outbound::shared_transport::UtlsClientHelloProfile,
    algorithm: RealityAeadAlgorithm,
) -> SyntheticRealityUtlsMutationOptions {
    let mut client_random = [0_u8; 32];
    for (index, byte) in client_random.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(9).wrapping_add(7);
    }
    let mut shared_secret = [0_u8; 32];
    for (index, byte) in shared_secret.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(13).wrapping_add(11);
    }
    SyntheticRealityUtlsMutationOptions {
        profile,
        sid: [0x14, 0x15, 0x16, 0x17, 0x24, 0x25, 0x26, 0x27],
        unix_seconds: 1_717_141_141,
        client_random,
        shared_secret,
        algorithm,
    }
}

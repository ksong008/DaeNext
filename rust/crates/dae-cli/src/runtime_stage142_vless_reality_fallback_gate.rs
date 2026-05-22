use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage142_vless_reality_fallback_gate(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage142 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage142_report()))
}

fn stage142_report() -> Value {
    let mut report = json!({
        "name": "stage142-vless-reality-full-handshake-fallback-gate",
        "stage": "stage142",
        "evidence_class": "read-only-vless-reality-full-handshake-go-fallback-gate",
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
        "vless_reality_go_fallback_admitted",
        "vless_reality_full_handshake_go_fallback_required",
        "outbound_quic_go_dependency_preserved",
        "external_outbound_required",
        "external_quic_go_required",
        "go_default_path_preserved",
        "go_fallback_required",
        "protocol_outbound_partial_admitted",
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
    report["fallback_decision"] = json!({
        "decision": "keep VLESS REALITY full handshake on Go outbound fallback",
        "rust_completed_prerequisites": [
            "Go uTLS ClientHello profile fixture/parser",
            "synthetic ClientHello profile builder",
            "synthetic REALITY session-id raw mutation harness"
        ],
        "rust_missing_prerequisites": [
            "true uTLS-compatible handshake state machine",
            "REALITY VerifyPeerCertificate signature/x509 path",
            "REALITY spider fallback behavior",
            "Vision intrinsic TLS/REALITY conn hook"
        ],
        "go_fallback_source": "/root/project/outbound/transport/tls/reality.go",
        "default_path_mutation_allowed": false,
        "product_switch_allowed": false
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "network_benchmark_recorded": false,
        "reason": "Stage142 is a read-only fallback decision gate; it adds no network dataplane benchmark",
        "matched_go_rust_default_daemon_benchmark_recorded": false
    });
    report["remaining_blockers"] = json!([
        "true Rust uTLS-compatible full handshake state is incomplete",
        "VLESS REALITY VerifyPeerCertificate and spider fallback remain on Go outbound",
        "VLESS/VMess uTLS wire-level fingerprint admission remains closed",
        "VLESS XTLS Vision intrinsic TLS/REALITY conn hook is incomplete",
        "VMess uTLS full-combination recertification is incomplete",
        "Trojan-Go full shared transport remains blocked",
        "shared_transport_true_dataplane and outbound_true_dataplane remain closed until all protocol rows close",
        "matched Go default daemon vs true Rust candidate benchmark remains missing",
        "default daemon and product-chain switches remain closed"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage142/vless_reality_full_handshake_fallback_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage142_vless_reality_full_handshake_fallback_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage142-vless-reality-full-handshake-fallback-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage142 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage142 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage141 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage142",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "/root/project/outbound/transport/tls/reality.go",
        "rust/crates/dae-outbound/src/shared_transport/reality_utls_synthetic.rs",
        "testdata/rebuild-golden/engine/runtime_stage141/vless_reality_synthetic_utls_raw_mutation_gate.json"
    ]);
    report
}

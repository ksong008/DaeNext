use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage145_trojan_go_recertification_gate(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage145 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage145_report()))
}

fn stage145_report() -> Value {
    let mut report = json!({
        "name": "stage145-trojan-go-fallback-aware-recertification-gate",
        "stage": "stage145",
        "evidence_class": "read-only-trojan-go-fallback-aware-recertification-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": false,
        "blockers": []
    });
    for key in [
        "trojan_go_fallback_aware_recertified",
        "trojan_go_shared_transport_go_fallback_required",
        "trojan_go_wss_admitted",
        "trojan_go_httpupgrade_admitted",
        "trojan_go_grpc_hunk_admitted",
        "trojan_go_inner_shadowsocks_admitted",
        "trojan_go_tls_fragment_admitted",
        "trojan_go_wss_tls_fragment_inner_shadowsocks_combination_admitted",
        "trojan_go_grpc_no_double_tls_guarded",
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
        "trojan_go_utls_fingerprint_wire_admitted",
        "trojan_go_utls_fingerprint_admitted",
        "trojan_go_reality_mutation_admitted",
        "trojan_go_cross_combination_recertified",
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
    report["recertification_matrix"] = json!({
        "rust_completed_rows": [
            "Trojan-Go WSS lifecycle",
            "Trojan-Go HTTPUpgrade lifecycle",
            "Trojan-Go gRPC hunk lifecycle",
            "Trojan-Go gRPC HTTP/2 TLS lifecycle",
            "Trojan-Go gRPC cache/cancellation",
            "Trojan-Go inner Shadowsocks",
            "Trojan-Go TLS fragment",
            "Trojan-Go WSS + TLS fragment + inner Shadowsocks combination"
        ],
        "guarded_rows": [
            "gRPC transport includes TLS and must not be double-wrapped",
            "inner Shadowsocks encryption=ss uses IsClient=false before trojanc",
            "uTLS fingerprint selection is not uTLS wire parity"
        ],
        "go_fallback_rows": [
            "Trojan-Go full shared transport across all combinations",
            "Trojan-Go uTLS wire-level ClientHello",
            "Trojan-Go REALITY/full uTLS mutation",
            "Trojan-Go cross-combination protocol-wide recertification"
        ],
        "default_switch_allowed": false,
        "product_switch_allowed": false
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "network_benchmark_recorded": false,
        "reason": "Stage145 recertifies Trojan-Go fallback boundaries only; default daemon benchmark remains blocked",
        "matched_go_rust_default_daemon_benchmark_recorded": false
    });
    report["remaining_blockers"] = json!([
        "Trojan-Go shared transport is fallback-aware but not fully admitted",
        "Trojan-Go uTLS wire-level ClientHello fingerprint row remains closed",
        "Trojan-Go REALITY/full uTLS mutation row remains closed",
        "Trojan-Go cross-combination recertification remains closed",
        "shared_transport_true_dataplane and outbound_true_dataplane remain closed until all protocol rows close",
        "matched Go default daemon vs true Rust candidate benchmark remains missing",
        "default daemon and product-chain switches remain closed"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage145/trojan_go_fallback_aware_recertification_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage145_trojan_go_fallback_aware_recertification_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage145-trojan-go-fallback-aware-recertification-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage145 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage145 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage144 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage145",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.11",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "testdata/rebuild-golden/engine/runtime_stage103/trojan_go_wss_tls_fragment_inner_ss_combination_admission.json",
        "rust/crates/dae-cli/src/runtime_stage103_trojan_go_combination_gate",
        "/root/project/outbound/dialer/trojan/trojan.go"
    ]);
    report
}

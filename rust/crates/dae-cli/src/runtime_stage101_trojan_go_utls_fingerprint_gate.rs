use dae_outbound::shared_transport;
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage101_trojan_go_utls_fingerprint_readiness(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage101 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage101_report()))
}

fn stage101_report() -> Value {
    let names = shared_transport::utls_fingerprint_names();
    let mut report = json!({
        "name": "stage101-trojan-go-utls-fingerprint-readiness",
        "stage": "stage101",
        "evidence_class": "read-only-utls-fingerprint-selection-readiness",
        "read_only": true,
        "blocked": false,
        "blockers": []
    });
    report["trojan_go_wss_admitted"] = json!(true);
    report["trojan_go_httpupgrade_admitted"] = json!(true);
    report["trojan_go_grpc_hunk_admitted"] = json!(true);
    report["trojan_go_inner_shadowsocks_admitted"] = json!(true);
    report["trojan_go_grpc_http2_tls_lifecycle_admitted"] = json!(true);
    report["trojan_go_grpc_cache_cleanup_admitted"] = json!(true);
    report["trojan_go_grpc_cancellation_stress_admitted"] = json!(true);
    report["trojan_go_tls_fragment_admitted"] = json!(true);
    report["trojan_go_utls_fingerprint_selection_admitted"] = json!(true);
    report["trojan_go_utls_fingerprint_wire_admitted"] = json!(false);
    report["trojan_go_utls_fingerprint_admitted"] = json!(false);
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
    report["utls_fingerprint_contract"] = json!({
        "go_source": "/root/project/outbound/transport/tls/utls.go",
        "supported_name_count": shared_transport::supported_utls_fingerprint_count(),
        "supported_names": names,
        "alias_examples": {
            "chrome": "chrome_auto",
            "firefox": "firefox_auto",
            "ios": "ios_auto",
            "edge": "edge_auto",
            "safari": "safari_auto",
            "360": "360_auto",
            "qq": "qq_auto",
            "randomized": "random"
        },
        "randomized_alpn_names": ["randomizedalpn", "randomizednoalpn"],
        "unknown_error_text": "unknown uTLS Client Hello ID: <name>",
        "case_sensitive": true,
        "wire_stack_deferred": shared_transport::U_TLS_WIRE_STACK_DEFERRED,
        "rustls_is_not_utls": true,
        "selection_mapping_complete": true,
        "wire_fingerprint_complete": false,
        "default_go_path_preserved": true
    });
    report["remaining_blockers"] = json!([
        "Trojan-Go uTLS wire-level ClientHello fingerprint row is still incomplete",
        "Trojan-Go REALITY handshake mutation row is still incomplete",
        "Trojan-Go cross-combination recertification is still incomplete",
        "VLESS and VMess TLS/WSS/gRPC/Meek/xHTTP full shared transport rows remain protocol-specific blockers",
        "Hysteria2, TUIC, Juicity, AnyTLS, REALITY, Vision, and QUIC/H3 true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage101/trojan_go_utls_fingerprint_readiness.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage101_trojan_go_utls_fingerprint_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage101 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage101 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage101 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage101",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "/root/project/outbound/transport/tls/utls.go",
        "rust/crates/dae-outbound/src/shared_transport/utls_fingerprint.rs"
    ]);
    report
}

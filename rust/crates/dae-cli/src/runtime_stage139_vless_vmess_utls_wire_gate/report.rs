use dae_outbound::shared_transport;
use serde_json::{Value, json};

use super::fixture::stage139_utls_wire_stats;

pub(super) fn stage139_report() -> Result<Value, String> {
    let stats = stage139_utls_wire_stats()?;
    let mut report = json!({
        "name": "stage139-vless-vmess-utls-wire-baseline-gate",
        "stage": "stage139",
        "evidence_class": "read-only-vless-vmess-utls-wire-baseline-profile-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": false,
        "blockers": []
    });
    for key in [
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
        "utls_wire_baseline_fixture_recorded",
        "utls_wire_profile_parser_admitted",
    ] {
        report[key] = json!(true);
    }
    for key in [
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
    report["utls_wire_baseline"] = json!({
        "go_fixture": "testdata/rebuild-golden/outbound/protocol/stage139_go_utls_clienthello_profile.json",
        "go_source": [
            "/root/project/outbound/transport/tls/utls.go",
            "/root/project/outbound/transport/tls/tls.go",
            "github.com/refraction-networking/utls"
        ],
        "server_name": "stage139-utls.example",
        "requested_alpn": ["h2", "http/1.1"],
        "sample_count": stats.sample_count,
        "parsed_profile_count": stats.parsed_profile_count,
        "profile_match_count": stats.profile_match_count,
        "all_profiles_match_fixture": stats.sample_count == stats.profile_match_count,
        "total_extension_type_count": stats.total_extension_type_count,
        "total_cipher_suite_count": stats.total_cipher_suite_count,
        "fingerprints": stats.fingerprints,
        "sample_profiles": stats.sample_profiles,
        "normalized_profile_only": true,
        "random_and_key_share_bytes_not_used_for_admission": true,
        "android_11_okhttp_absent_alpn_preserved": true
    });
    report["utls_wire_boundaries"] = json!({
        "supported_name_count": shared_transport::supported_utls_fingerprint_count(),
        "selection_mapping_admitted": true,
        "wire_profile_parser_admitted": true,
        "wire_clienthello_builder_admitted": false,
        "wire_stack_deferred": shared_transport::U_TLS_WIRE_STACK_DEFERRED,
        "rustls_is_not_utls": true,
        "reality_raw_hello_mutation_ready": false,
        "verify_peer_certificate_admitted": false,
        "vision_intrinsic_conn_hook_admitted": false
    });
    report["implementation_admission_queue"] = json!([
        {
            "order": 1,
            "target": "Rust uTLS-compatible ClientHello builder",
            "required_outputs": [
                "generate ClientHello bytes for at least the Stage139 deterministic fingerprints",
                "match Go uTLS normalized wire profiles without relying on rustls",
                "only then reconsider vless_utls_fingerprint_wire_admitted and vmess_utls_fingerprint_wire_admitted"
            ]
        },
        {
            "order": 2,
            "target": "VLESS REALITY full uTLS handshake",
            "required_outputs": [
                "apply REALITY session id mutation to actual ClientHello Raw bytes",
                "cover VerifyPeerCertificate and spider fallback"
            ]
        },
        {
            "order": 3,
            "target": "VLESS XTLS Vision intrinsic TLS/REALITY conn hook",
            "required_outputs": [
                "Vision TCP and UDP packet conn smoke over intrinsic TLS/REALITY connection"
            ]
        },
        {
            "order": 4,
            "target": "VLESS/VMess protocol-wide recertification",
            "required_outputs": [
                "vless_protocol_true_dataplane_admitted=true",
                "vmess_protocol_true_dataplane_admitted=true"
            ]
        }
    ]);
    report["benchmark"] = json!({
        "profile_metric_recorded": true,
        "network_benchmark_recorded": false,
        "fixture_sample_count": stats.sample_count,
        "parsed_profile_count": stats.parsed_profile_count,
        "profile_match_count": stats.profile_match_count,
        "total_extension_type_count": stats.total_extension_type_count,
        "total_cipher_suite_count": stats.total_cipher_suite_count,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "reason": "Stage139 is a Go uTLS fixture and Rust profile parser gate, not a network dataplane or default daemon benchmark"
    });
    report["remaining_blockers"] = json!([
        "Rust can parse Go uTLS ClientHello profiles, but cannot yet generate uTLS-compatible ClientHello bytes",
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
        "python3 -m json.tool testdata/rebuild-golden/outbound/protocol/stage139_go_utls_clienthello_profile.json",
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage139/vless_vmess_utls_wire_baseline_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage139_vless_vmess_utls_wire_baseline_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage139 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage139-vless-vmess-utls-wire-baseline-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage139 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage139 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage138 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage139",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "/root/project/outbound/transport/tls/utls.go",
        "/root/project/outbound/transport/tls/tls.go",
        "/root/project/outbound/transport/tls/reality.go",
        "tools/rebuild/utls_clienthello_fixture/main.go",
        "testdata/rebuild-golden/outbound/protocol/stage139_go_utls_clienthello_profile.json",
        "rust/crates/dae-outbound/src/shared_transport/utls_wire.rs"
    ]);
    Ok(report)
}

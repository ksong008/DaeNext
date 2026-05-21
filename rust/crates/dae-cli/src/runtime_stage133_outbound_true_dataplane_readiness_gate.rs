use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage133_outbound_true_dataplane_readiness(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage133 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage133_report()))
}

fn stage133_report() -> Value {
    let mut report = json!({
        "name": "stage133-outbound-true-dataplane-readiness",
        "stage": "stage133",
        "evidence_class": "read-only-outbound-true-dataplane-readiness-after-quic-h3-family",
        "execute_smoke": false,
        "read_only": true,
        "blocked": true,
        "blockers": [
            "VLESS full shared transport and protocol-wide true dataplane remain blocked",
            "VMess full shared transport and protocol-wide true dataplane remain blocked",
            "Trojan-Go full shared transport remains blocked by uTLS wire and full REALITY/uTLS handshake gaps",
            "matched Go default daemon vs true Rust candidate benchmark is still missing",
            "default daemon and product-chain switches remain closed"
        ]
    });
    for key in [
        "socks5_protocol_true_dataplane_admitted",
        "socks5_udp_associate_admitted",
        "http_connect_true_dataplane_admitted",
        "https_proxy_true_dataplane_admitted",
        "shared_tls_underlay_admitted",
        "shadowsocks_aead_protocol_true_dataplane_admitted",
        "ss2022_true_dataplane_admitted",
        "sip003_plugin_transport_admitted",
        "shadowsocksr_true_dataplane_admitted",
        "shadowsocks_protocol_true_dataplane_admitted",
        "trojanc_tcp_true_dataplane_admitted",
        "trojan_udp_over_tcp_admitted",
        "trojan_tls_underlay_admitted",
        "trojan_protocol_true_dataplane_admitted",
        "trojan_go_shared_transport_partial_admitted",
        "vmess_protocol_partial_admitted",
        "vless_protocol_partial_admitted",
        "anytls_true_dataplane_admitted",
        "hysteria2_true_quic_dataplane_admitted",
        "tuic_true_quic_dataplane_admitted",
        "juicity_true_quic_h3_dataplane_admitted",
        "quic_h3_family_true_dataplane_admitted",
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
        "trojan_go_utls_fingerprint_wire_admitted",
        "reality_full_utls_handshake_admitted",
        "trojan_go_cross_combination_recertified",
        "trojan_go_shared_transport_admitted",
        "vmess_protocol_true_dataplane_admitted",
        "vless_protocol_true_dataplane_admitted",
        "shared_transport_true_dataplane_admitted",
        "tuic_udp_relay_mode_quic_effective_relay_admitted",
        "outbound_true_dataplane_admitted",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
        "true_rust_default_daemon_admitted",
    ] {
        report[key] = json!(false);
    }
    report["protocol_matrix"] = json!({
        "completed_rows": {
            "socks5_protocol_true_dataplane_admitted": true,
            "http_connect_true_dataplane_admitted": true,
            "https_proxy_true_dataplane_admitted": true,
            "shadowsocks_protocol_true_dataplane_admitted": true,
            "trojan_protocol_true_dataplane_admitted": true,
            "anytls_true_dataplane_admitted": true,
            "hysteria2_true_quic_dataplane_admitted": true,
            "tuic_true_quic_dataplane_admitted": true,
            "juicity_true_quic_h3_dataplane_admitted": true,
            "quic_h3_family_true_dataplane_admitted": true
        },
        "partial_rows": {
            "trojan_go_shared_transport_partial_admitted": true,
            "vmess_protocol_partial_admitted": true,
            "vless_protocol_partial_admitted": true,
            "protocol_outbound_partial_admitted": true
        },
        "blocked_rows": {
            "trojan_go_utls_fingerprint_wire_admitted": false,
            "reality_full_utls_handshake_admitted": false,
            "trojan_go_cross_combination_recertified": false,
            "trojan_go_shared_transport_admitted": false,
            "vmess_protocol_true_dataplane_admitted": false,
            "vless_protocol_true_dataplane_admitted": false,
            "shared_transport_true_dataplane_admitted": false,
            "tuic_udp_relay_mode_quic_effective_relay_admitted": false,
            "outbound_true_dataplane_admitted": false
        }
    });
    report["recertified_rows"] = json!([
        {
            "area": "base proxy protocols",
            "status": "passed-carried-evidence",
            "source_stages": ["stage55", "stage56", "stage57", "stage82"],
            "admitted": true,
            "boundary": "base protocol rows do not admit shared V2Ray/Trojan-Go transports or outbound default"
        },
        {
            "area": "Shadowsocks family",
            "status": "passed-carried-evidence",
            "source_stages": ["stage58", "stage59", "stage88", "stage89", "stage90", "stage91", "stage92", "stage93", "stage94", "stage95"],
            "admitted": true,
            "boundary": "SS/SS2022/SIP003/SSR completion does not cover VMess/VLESS/Trojan-Go shared transports"
        },
        {
            "area": "standard Trojan",
            "status": "passed-carried-evidence",
            "source_stages": ["stage60", "stage61", "stage83"],
            "admitted": true,
            "boundary": "standard trojanc TCP/TLS/UDP-over-TCP does not admit Trojan-Go shared transport"
        },
        {
            "area": "Trojan-Go shared transport",
            "status": "blocked",
            "source_stages": ["stage84", "stage85", "stage86", "stage87", "stage97", "stage98", "stage100", "stage101", "stage102", "stage103"],
            "admitted": false,
            "boundary": "WSS/HTTPUpgrade/gRPC/inner-SS/TLS-fragment subrows are partial; uTLS wire-level ClientHello, full REALITY/uTLS handshake, and cross-combination recertification remain blocked"
        },
        {
            "area": "VMess shared transports",
            "status": "blocked",
            "source_stages": ["stage65", "stage66", "stage67", "stage68", "stage69", "stage70", "stage71", "stage72", "stage73"],
            "admitted": false,
            "boundary": "VMess raw/mux/WS/HTTPUpgrade/gRPC-hunk/Meek/HTTP PUT are partial; full TLS/uTLS, HTTP2, WSS, xHTTP, full gRPC and full Meek lifecycle remain blocked"
        },
        {
            "area": "VLESS shared transports",
            "status": "blocked",
            "source_stages": ["stage62", "stage63", "stage64", "stage74", "stage75", "stage76", "stage77", "stage78", "stage79", "stage80"],
            "admitted": false,
            "boundary": "VLESS raw/mux/WS/HTTPUpgrade/gRPC-hunk/Meek/HTTP/xHTTP packet-up are partial; TLS/uTLS, REALITY, XTLS Vision, H2/H3 xHTTP and full protocol recertification remain blocked"
        },
        {
            "area": "AnyTLS and QUIC/H3 family",
            "status": "passed-carried-evidence",
            "source_stages": ["stage107", "stage129", "stage130", "stage131", "stage132"],
            "admitted": true,
            "boundary": "AnyTLS and QUIC/H3 family completion does not admit outbound-wide default until VLESS/VMess/Trojan-Go blockers and matched benchmark close"
        },
        {
            "area": "outbound default admission",
            "status": "blocked",
            "source_stages": ["stage133"],
            "admitted": false,
            "boundary": "outbound_true_dataplane_admitted, default_switch_allowed, and product_chain_switch_allowed remain false"
        }
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage134",
            "target": "VLESS and VMess shared transport residual closure",
            "required_outputs": [
                "vless_protocol_true_dataplane_admitted=true",
                "vmess_protocol_true_dataplane_admitted=true",
                "shared_transport_true_dataplane_admitted prerequisite evidence"
            ]
        },
        {
            "stage": "stage135",
            "target": "Trojan-Go uTLS/REALITY/shared-transport closure",
            "required_outputs": [
                "trojan_go_utls_fingerprint_wire_admitted=true or explicitly deferred with Go fallback",
                "reality_full_utls_handshake_admitted=true or explicitly deferred with Go fallback",
                "trojan_go_shared_transport_admitted=true"
            ]
        },
        {
            "stage": "stage136",
            "target": "outbound-wide true dataplane recertification",
            "required_outputs": [
                "shared_transport_true_dataplane_admitted=true",
                "outbound_true_dataplane_admitted=true only after all protocol rows close"
            ]
        },
        {
            "stage": "stage137",
            "target": "matched Go/Rust default daemon benchmark",
            "required_outputs": [
                "matched_go_rust_default_daemon_benchmark_recorded=true",
                "default switch remains closed until benchmark is recorded"
            ]
        }
    ]);
    report["benchmark_carry_forward"] = json!({
        "stage82_ns_per_https_proxy_tls_connect": 7963039.0,
        "stage83_ns_per_trojan_tls_exchange": 7457469.3,
        "stage91_stage88_ns_per_ss2022_tcp_exchange": 4714323.5,
        "stage91_stage89_ns_per_ss2022_multi_psk_exchange": 4717075.3,
        "stage91_stage90_ns_per_ss2022_udp_exchange": 315043.1,
        "stage94_ns_per_sip003_v2ray_plugin_exchange": 8092662.2,
        "stage95_ns_per_shadowsocksr_three_layer_exchange": 5179105.0,
        "stage103_ns_per_trojan_go_combination_exchange": 11237732.8,
        "stage107_anytls_recertification_read_only": true,
        "stage132_ns_per_quic_h3_family_exchange": 18472346.8,
        "new_network_benchmark_recorded": false,
        "reason": "Stage 133 is a read-only residual readiness gate and must not pretend to complete the matched Go/Rust default daemon benchmark"
    });
    report["remaining_blockers"] = json!([
        "VLESS full TLS/uTLS/REALITY/XTLS Vision/gRPC/Meek/xHTTP H2/H3 lifecycle and protocol-wide recertification",
        "VMess full TLS/uTLS/WSS/gRPC/Meek/xHTTP/H2 lifecycle and protocol-wide recertification",
        "Trojan-Go uTLS wire-level ClientHello, full REALITY/uTLS handshake, and cross-combination recertification",
        "outbound-wide protocol matrix recertification after remaining shared transport rows close",
        "matched Go default daemon vs true Rust candidate benchmark",
        "default daemon switch admission",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage133/outbound_true_dataplane_readiness.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage133_outbound_true_dataplane_readiness_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage133-outbound-true-dataplane-readiness",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage133 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage133 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage132 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage133",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.5-25.10",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.6",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.8",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.11",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.18",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.20",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "rust/crates/dae-cli/src/runtime_stage96_protocol_matrix_gate.rs",
        "rust/crates/dae-product/src/stage132_quic_h3_family_recertification_gate.rs"
    ]);
    report
}

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage96_protocol_matrix_recertification(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage96 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage96_report()))
}

fn stage96_report() -> Value {
    let mut report = json!({
        "name": "stage96-protocol-matrix-recertification",
        "stage": "stage96",
        "evidence_class": "read-only-protocol-matrix-recertification-after-shadowsocks-family-closure",
        "execute_smoke": false,
        "read_only": true,
        "blocked": false,
        "blockers": []
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
        "trojan_go_wss_admitted",
        "trojan_go_httpupgrade_admitted",
        "trojan_go_grpc_admitted",
        "trojan_go_inner_shadowsocks_admitted",
        "trojan_go_shared_transport_partial_admitted",
        "vmess_protocol_partial_admitted",
        "vless_protocol_partial_admitted",
        "protocol_outbound_partial_admitted",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "trojan_go_shared_transport_admitted",
        "vmess_protocol_true_dataplane_admitted",
        "vless_protocol_true_dataplane_admitted",
        "shared_transport_true_dataplane_admitted",
        "quic_h3_family_true_dataplane_admitted",
        "anytls_true_dataplane_admitted",
        "outbound_true_dataplane_admitted",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
        "true_rust_default_daemon_admitted",
    ] {
        report[key] = json!(false);
    }
    report["recertified_rows"] = json!([
        {
            "area": "SOCKS5 and HTTP proxy",
            "status": "passed-carried-evidence",
            "source_stages": ["stage55", "stage56", "stage57", "stage82"],
            "admitted": true,
            "boundary": "HTTPS proxy TLS uses rustls only; uTLS and TLS fragment remain shared-transport blockers"
        },
        {
            "area": "Shadowsocks family",
            "status": "passed-recertified-after-stage95",
            "source_stages": ["stage58", "stage59", "stage91", "stage92", "stage93", "stage94", "stage95"],
            "admitted": true,
            "boundary": "admission is opt-in true dataplane only; Go default outbound path remains preserved"
        },
        {
            "area": "Standard Trojan",
            "status": "passed-carried-evidence",
            "source_stages": ["stage60", "stage61", "stage83"],
            "admitted": true,
            "boundary": "standard Trojan admission does not admit Trojan-Go full shared transport"
        },
        {
            "area": "Trojan-Go",
            "status": "partial-blocked",
            "source_stages": ["stage84", "stage85", "stage86", "stage87"],
            "admitted": false,
            "boundary": "WSS, HTTPUpgrade, gRPC hunk, and inner Shadowsocks are admitted, but full grpc-go HTTP/2/TLS lifecycle, uTLS, REALITY, TLS fragment, and combination recertification remain blocked"
        },
        {
            "area": "VMess and VLESS shared transports",
            "status": "partial-blocked",
            "source_stages": ["stage62", "stage63", "stage64", "stage65", "stage66", "stage67", "stage68", "stage69", "stage70", "stage71", "stage72", "stage73", "stage74", "stage75", "stage76", "stage77", "stage78", "stage79", "stage80"],
            "admitted": false,
            "boundary": "full TLS/uTLS/REALITY/Vision/gRPC/Meek/xHTTP/H2/H3 lifecycle and protocol-wide recertification remain blocked"
        },
        {
            "area": "QUIC/H3/session protocols and default daemon",
            "status": "blocked",
            "source_stages": ["stage23", "stage96"],
            "admitted": false,
            "boundary": "Hysteria2, TUIC, Juicity, AnyTLS, matched Go/Rust default daemon benchmark, and product-chain recertification remain incomplete"
        }
    ]);
    report["benchmark_carry_forward"] = json!({
        "stage82_ns_per_https_proxy_tls_connect": 7963039.0,
        "stage83_ns_per_trojan_tls_exchange": 7457469.3,
        "stage86_ns_per_trojan_go_grpc_hunk_exchange": 4628029.0,
        "stage87_ns_per_trojan_go_inner_shadowsocks_exchange": 4816909.1,
        "stage91_stage88_ns_per_ss2022_tcp_exchange": 4714323.5,
        "stage91_stage89_ns_per_ss2022_multi_psk_exchange": 4717075.3,
        "stage91_stage90_ns_per_ss2022_udp_exchange": 315043.1,
        "stage94_ns_per_sip003_v2ray_plugin_exchange": 8092662.2,
        "stage95_ns_per_shadowsocksr_three_layer_exchange": 5179105.0,
        "new_network_benchmark_recorded": false,
        "reason": "Stage 96 is a read-only recertification gate and carries previously recorded protocol benchmarks"
    });
    report["remaining_blockers"] = json!([
        "Trojan-Go full grpc-go HTTP/2/TLS lifecycle, cancellation stress, global cache cleanup, and cross-combination recertification",
        "uTLS fingerprint, REALITY handshake mutation, and TLS fragmentation shared-transport rows",
        "VLESS TLS/REALITY/XTLS Vision and full gRPC/Meek/xHTTP/H2/H3 lifecycle",
        "VMess WSS/gRPC/Meek/xHTTP full shared-transport lifecycle and protocol-wide recertification",
        "Hysteria2, TUIC, Juicity, AnyTLS, QUIC/H3/session true dataplanes",
        "matched Go default daemon vs true Rust candidate benchmark",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage96/protocol_matrix_recertification.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage96_protocol_matrix_recertification_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage96-protocol-matrix-recertification",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage96 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage96 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage96",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.9",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.10",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.11",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.18",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "testdata/rebuild-golden/engine/runtime_stage95/shadowsocksr_three_layer_dataplane_admission.json"
    ]);
    report
}

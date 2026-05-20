use super::*;

pub(super) fn stage91_report() -> Value {
    let aes_conf =
        shadowsocks::ss2022::cipher_conf("2022-blake3-aes-128-gcm").expect("fixture cipher");
    let chacha_conf =
        shadowsocks::ss2022::cipher_conf("2022-blake3-chacha20-poly1305").expect("fixture cipher");
    let mut report = json!({
        "name": "stage91-ss2022-protocol-wide-admission",
        "stage": "stage91",
        "evidence_class": "opt-in-protocol-ss2022-wide-admission-carry-forward",
        "execute_smoke": false,
        "read_only": true,
        "blocked": false,
        "blockers": [],
        "socks5_protocol_true_dataplane_admitted": true,
        "http_connect_true_dataplane_admitted": true,
        "https_proxy_true_dataplane_admitted": true,
        "shared_tls_underlay_admitted": true,
        "shadowsocks_aead_protocol_true_dataplane_admitted": true,
        "ss2022_tcp_true_dataplane_admitted": true,
        "ss2022_multi_psk_identity_header_dataplane_admitted": true,
        "ss2022_udp_aes_separate_header_admitted": true,
        "ss2022_udp_chacha_merged_header_admitted": true,
        "ss2022_udp_replay_filter_admitted": true,
        "ss2022_udp_true_dataplane_admitted": true,
        "ss2022_true_dataplane_admitted": true,
        "shadowsocks_protocol_partial_admitted": true,
        "shadowsocks_protocol_true_dataplane_admitted": false,
        "sip003_plugin_transport_admitted": false,
        "shadowsocksr_true_dataplane_admitted": false,
        "trojan_protocol_true_dataplane_admitted": true,
        "trojan_go_shared_transport_partial_admitted": true,
        "trojan_go_shared_transport_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false,
        "default_path_mutation_allowed": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true
    });
    report["ss2022_protocol_contract"] = json!({
        "protocol": "shadowsocks_2022",
        "scope": "SS2022 protocol-wide carry-forward admission across TCP single-PSK, TCP multi-PSK identity header, and UDP/replay dataplanes",
        "tcp_single_psk": {
            "source_stage": "stage88",
            "cipher": "2022-blake3-aes-128-gcm",
            "admitted": true,
            "evidence": "BLAKE3 session subkey, fixed/variable TCP header, request salt echo, payload roundtrip, SO_MARK/MPTCP, benchmark"
        },
        "tcp_multi_psk_identity": {
            "source_stage": "stage89",
            "cipher": "2022-blake3-aes-128-gcm",
            "psk_count": 2,
            "upsk_index": 1,
            "identity_header_count": 1,
            "identity_header_bytes_len": 16,
            "admitted": true
        },
        "udp_replay": {
            "source_stage": "stage90",
            "aes_cipher": aes_conf.cipher,
            "aes_key_len": aes_conf.key_len,
            "chacha_cipher": chacha_conf.cipher,
            "chacha_key_len": chacha_conf.key_len,
            "chacha_packet_nonce_len": chacha_conf.packet_nonce_len,
            "duplicate_rejected": true,
            "too_old_rejected": true,
            "admitted": true
        },
        "ordinary_aead_boundary_preserved": true,
        "sip003_plugin_deferred": true,
        "ssr_deferred": true,
        "default_go_path_preserved": true
    });
    report["benchmark_carry_forward"] = json!({
        "stage88_ns_per_ss2022_tcp_exchange": 4714323.5,
        "stage89_ns_per_ss2022_multi_psk_exchange": 4717075.3,
        "stage90_ns_per_ss2022_udp_exchange": 315043.1,
        "stage90_iterations_per_branch": 10,
        "stage90_exchange_count": 20,
        "stage90_elapsed_ns": 6300862,
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "SS2022 protocol-wide is opt-in only; SIP003/SSR, remaining protocol rows, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "shadowsocks_aead_protocol_true_dataplane_admitted": true,
        "ss2022_tcp_true_dataplane_admitted": true,
        "ss2022_multi_psk_identity_header_dataplane_admitted": true,
        "ss2022_udp_true_dataplane_admitted": true,
        "ss2022_true_dataplane_admitted": true,
        "sip003_plugin_transport_admitted": false,
        "shadowsocksr_true_dataplane_admitted": false,
        "shadowsocks_protocol_true_dataplane_admitted": false,
        "trojan_go_shared_transport_partial_admitted": true,
        "trojan_go_shared_transport_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "SIP003 plugin and ShadowsocksR layered transport remain separate blockers",
        "Trojan-Go full shared transport remains blocked until transport combinations and full grpc-go HTTP/2/TLS lifecycle are recertified together",
        "uTLS fingerprint, REALITY, and TLS fragmentation are still deferred",
        "Hysteria2, TUIC, Juicity, AnyTLS, REALITY, Vision, and QUIC/H3 true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage91/ss2022_protocol_wide_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage91_ss2022_protocol_wide_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage91-ss2022-protocol-wide-admission",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage91 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage91 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --all --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage91",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.9",
        "testdata/rebuild-golden/engine/runtime_stage88/ss2022_tcp_dataplane_admission.json",
        "testdata/rebuild-golden/engine/runtime_stage89/ss2022_multi_psk_tcp_dataplane_admission.json",
        "testdata/rebuild-golden/engine/runtime_stage90/ss2022_udp_replay_dataplane_admission.json",
        "rust/crates/dae-outbound/src/shadowsocks/ss2022.rs",
        "rust/crates/dae-outbound/src/shadowsocks/ss2022_tcp_dataplane.rs",
        "rust/crates/dae-outbound/src/shadowsocks/ss2022_udp_dataplane.rs"
    ]);
    report
}

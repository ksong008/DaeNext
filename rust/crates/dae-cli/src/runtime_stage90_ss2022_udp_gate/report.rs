use super::smoke::{apply_stage90_outcome, run_stage90_smoke};
use super::*;

pub(super) fn stage90_report(opts: &Stage90Options) -> Value {
    let aes_conf = match shadowsocks::ss2022::cipher_conf(&opts.aes_cipher) {
        Some(conf) if !conf.packet_cipher => conf,
        _ => {
            return json!({
                "name": "stage90-ss2022-udp-replay-dataplane-admission",
                "stage": "stage90",
                "blocked": true,
                "blockers": [format!("stage90 requires AES SS2022 UDP cipher: {}", opts.aes_cipher)]
            });
        }
    };
    let chacha_conf = match shadowsocks::ss2022::cipher_conf(&opts.chacha_cipher) {
        Some(conf) if conf.packet_cipher => conf,
        _ => {
            return json!({
                "name": "stage90-ss2022-udp-replay-dataplane-admission",
                "stage": "stage90",
                "blocked": true,
                "blockers": [format!("stage90 requires Chacha SS2022 packet cipher: {}", opts.chacha_cipher)]
            });
        }
    };
    let aes_psk = match shadowsocks::ss2022::validate_psk_list(&opts.aes_cipher, &opts.aes_password)
    {
        Ok(psk) => psk,
        Err(err) => {
            return json!({
                "name": "stage90-ss2022-udp-replay-dataplane-admission",
                "stage": "stage90",
                "blocked": true,
                "blockers": [format!("stage90 AES PSK invalid: {err}")]
            });
        }
    };
    let chacha_psk =
        match shadowsocks::ss2022::validate_psk_list(&opts.chacha_cipher, &opts.chacha_password) {
            Ok(psk) => psk,
            Err(err) => {
                return json!({
                    "name": "stage90-ss2022-udp-replay-dataplane-admission",
                    "stage": "stage90",
                    "blocked": true,
                    "blockers": [format!("stage90 Chacha PSK invalid: {err}")]
                });
            }
        };
    if let Err(err) = shadowsocks::ShadowsocksMetadata::parse(&opts.target) {
        return json!({
            "name": "stage90-ss2022-udp-replay-dataplane-admission",
            "stage": "stage90",
            "blocked": true,
            "blockers": [format!("stage90 target is invalid: {err}")]
        });
    }
    if let Err(err) = shadowsocks::ShadowsocksMetadata::parse(&opts.response_target) {
        return json!({
            "name": "stage90-ss2022-udp-replay-dataplane-admission",
            "stage": "stage90",
            "blocked": true,
            "blockers": [format!("stage90 response target is invalid: {err}")]
        });
    }

    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let mut report = json!({
        "name": "stage90-ss2022-udp-replay-dataplane-admission",
        "stage": "stage90",
        "evidence_class": "opt-in-protocol-ss2022-udp-replay-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": [],
        "socks5_protocol_true_dataplane_admitted": true,
        "http_connect_true_dataplane_admitted": true,
        "https_proxy_true_dataplane_admitted": true,
        "shared_tls_underlay_admitted": true,
        "shadowsocks_aead_protocol_true_dataplane_admitted": true,
        "ss2022_tcp_true_dataplane_admitted": true,
        "ss2022_multi_psk_identity_header_dataplane_admitted": true,
        "ss2022_udp_smoke_passed": false,
        "ss2022_udp_aes_separate_header_admitted": false,
        "ss2022_udp_chacha_merged_header_admitted": false,
        "ss2022_udp_replay_filter_admitted": false,
        "ss2022_udp_true_dataplane_admitted": false,
        "ss2022_true_dataplane_admitted": false,
        "shadowsocks_protocol_partial_admitted": true,
        "shadowsocks_protocol_true_dataplane_admitted": false,
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
    report["ss2022_udp_contract"] = json!({
        "protocol": "shadowsocks_2022",
        "scope": "SS2022 UDP AES separate-header plus Chacha merged-header packet/replay true dataplane over SO_MARKed Rust UDP underlay",
        "target": opts.target,
        "response_target": opts.response_target,
        "payload_ascii": payload_ascii,
        "payload_len": opts.payload.len(),
        "aes": {
            "cipher": aes_conf.cipher,
            "key_len": aes_conf.key_len,
            "psk_count": aes_psk.psk_count,
            "upsk_index": aes_psk.upsk_index,
            "server": null,
            "client_session_id": null,
            "server_session_id": null,
            "packet_id_first": null,
            "separate_header_len": null,
            "identity_header_count": null,
            "identity_header_bytes_len": null,
            "identity_header_validated": false,
            "payload_roundtrip_validated": false
        },
        "chacha": {
            "cipher": chacha_conf.cipher,
            "key_len": chacha_conf.key_len,
            "psk_count": chacha_psk.psk_count,
            "upsk_index": chacha_psk.upsk_index,
            "packet_nonce_len": chacha_conf.packet_nonce_len,
            "server": null,
            "client_session_id": null,
            "server_session_id": null,
            "packet_id_first": null,
            "payload_roundtrip_validated": false
        },
        "replay": {
            "window_size": shadowsocks::ss2022::UDP_REPLAY_WINDOW_SIZE,
            "duplicate_rejected": false,
            "too_old_rejected": false,
            "timestamp_tolerance_seconds": 30
        },
        "ordinary_aead_boundary_preserved": true,
        "sip003_plugin_deferred": true,
        "ssr_deferred": true,
        "default_go_path_preserved": true
    });
    report["udp_underlay_socket"] = json!({
        "requested_mark": opts.so_mark,
        "aes": null,
        "chacha": null,
        "so_mark_observed": false,
        "mptcp_not_applicable": true
    });
    report["server_observation"] = json!(null);
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations_per_branch": opts.benchmark_iters,
        "exchange_count": null,
        "elapsed_ns": null,
        "ns_per_ss2022_udp_exchange": null,
        "scope": "SS2022 UDP packet encrypt/decrypt, AES identity header, XChaCha merged header, duplicate/too-old replay rejection, payload echo over SO_MARKed Rust UDP socket",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "SS2022 protocol-wide gate, SIP003/SSR, all remaining protocol rows, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "shadowsocks_aead_protocol_true_dataplane_admitted": true,
        "ss2022_tcp_true_dataplane_admitted": true,
        "ss2022_multi_psk_identity_header_dataplane_admitted": true,
        "ss2022_udp_true_dataplane_admitted": false,
        "ss2022_true_dataplane_admitted": false,
        "shadowsocks_protocol_true_dataplane_admitted": false,
        "trojan_go_shared_transport_partial_admitted": true,
        "trojan_go_shared_transport_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "SS2022 protocol-wide admission still needs a follow-up gate after TCP, identity, and UDP evidence are carried together",
        "SIP003 plugin and ShadowsocksR layered transport remain separate blockers",
        "Trojan-Go full shared transport remains blocked until transport combinations and full grpc-go HTTP/2/TLS lifecycle are recertified together",
        "uTLS fingerprint, REALITY, and TLS fragmentation are still deferred",
        "Hysteria2, TUIC, Juicity, AnyTLS, REALITY, Vision, and QUIC/H3 true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage90/ss2022_udp_replay_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage90_ss2022_udp_replay_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage90 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage90 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage90 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage90-ss2022-udp-replay-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --all --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage90",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.9",
        "/root/project/outbound/protocol/shadowsocks_2022/udp_conn.go",
        "/root/project/outbound/protocol/shadowsocks_2022/udp_conn_test.go",
        "/root/project/outbound/protocol/shadowsocks_2022/encrypt.go",
        "rust/crates/dae-outbound/src/shadowsocks/ss2022.rs",
        "rust/crates/dae-outbound/src/shadowsocks/ss2022_udp_dataplane.rs",
        "rust/crates/dae-datapath/src/udp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage90 root-gated smoke requires --ack-root-gate because it attempts SO_MARK UDP socket observation"
        ]);
        return report;
    }

    match run_stage90_smoke(opts) {
        Ok(outcome) => apply_stage90_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

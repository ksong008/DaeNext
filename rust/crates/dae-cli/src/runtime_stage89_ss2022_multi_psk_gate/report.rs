use super::smoke::{apply_stage89_outcome, run_stage89_smoke};
use super::*;

pub(super) fn stage89_report(opts: &Stage89Options) -> Value {
    let conf = match shadowsocks::ss2022::cipher_conf(&opts.cipher) {
        Some(conf) => conf,
        None => {
            return json!({
                "name": "stage89-ss2022-multi-psk-tcp-dataplane-admission",
                "stage": "stage89",
                "blocked": true,
                "blockers": [format!("stage89 requires SS2022 cipher: {}", opts.cipher)]
            });
        }
    };
    let psk = match shadowsocks::ss2022::validate_psk_list(&opts.cipher, &opts.password) {
        Ok(psk) => psk,
        Err(err) => {
            return json!({
                "name": "stage89-ss2022-multi-psk-tcp-dataplane-admission",
                "stage": "stage89",
                "blocked": true,
                "blockers": [format!("stage89 PSK invalid: {err}")]
            });
        }
    };
    if psk.psk_count < 2 {
        return json!({
            "name": "stage89-ss2022-multi-psk-tcp-dataplane-admission",
            "stage": "stage89",
            "blocked": true,
            "blockers": ["stage89 requires SS2022 multi-PSK password with at least two PSKs"]
        });
    }
    if let Err(err) = shadowsocks::ShadowsocksMetadata::parse(&opts.target) {
        return json!({
            "name": "stage89-ss2022-multi-psk-tcp-dataplane-admission",
            "stage": "stage89",
            "blocked": true,
            "blockers": [format!("stage89 target is invalid: {err}")]
        });
    }

    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let mut report = json!({
        "name": "stage89-ss2022-multi-psk-tcp-dataplane-admission",
        "stage": "stage89",
        "evidence_class": "opt-in-protocol-ss2022-multi-psk-identity-header-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": []
    });
    report["socks5_protocol_true_dataplane_admitted"] = json!(true);
    report["http_connect_true_dataplane_admitted"] = json!(true);
    report["https_proxy_true_dataplane_admitted"] = json!(true);
    report["shared_tls_underlay_admitted"] = json!(true);
    report["shadowsocks_aead_protocol_true_dataplane_admitted"] = json!(true);
    report["ss2022_tcp_true_dataplane_admitted"] = json!(true);
    report["ss2022_multi_psk_identity_header_smoke_passed"] = json!(false);
    report["ss2022_multi_psk_identity_header_dataplane_admitted"] = json!(false);
    report["ss2022_udp_true_dataplane_admitted"] = json!(false);
    report["ss2022_true_dataplane_admitted"] = json!(false);
    report["shadowsocks_protocol_partial_admitted"] = json!(true);
    report["shadowsocks_protocol_true_dataplane_admitted"] = json!(false);
    report["trojan_protocol_true_dataplane_admitted"] = json!(true);
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
    report["ss2022_contract"] = json!({
        "protocol": "shadowsocks_2022",
        "scope": "multi-PSK SS2022 TCP identity header plus client/server stream over SO_MARKed Rust TCP underlay",
        "cipher": conf.cipher,
        "key_len": conf.key_len,
        "salt_len": conf.salt_len,
        "nonce_len": conf.nonce_len,
        "tag_len": conf.tag_len,
        "psk_count": psk.psk_count,
        "upsk_index": psk.upsk_index,
        "identity_header_count": null,
        "identity_header_bytes_len": null,
        "identity_header_validated": false,
        "identity_header_context": "shadowsocks 2022 identity subkey",
        "session_subkey_context": "shadowsocks 2022 session subkey",
        "target": opts.target,
        "payload_ascii": payload_ascii,
        "payload_len": opts.payload.len(),
        "server": null,
        "client_salt_len": null,
        "server_salt_len": null,
        "request_header_type": null,
        "response_header_type": null,
        "fixed_header_len": null,
        "variable_header_len": null,
        "target_metadata_len": null,
        "request_salt_echo_validated": false,
        "payload_roundtrip_validated": false,
        "udp_deferred": true,
        "sip003_plugin_deferred": true,
        "ssr_deferred": true,
        "ordinary_aead_boundary_preserved": true,
        "default_go_path_preserved": true
    });
    report["underlay_socket"] = json!({
        "requested_mark": opts.so_mark,
        "requested_mptcp": opts.mptcp,
        "listener": null,
        "last_dial_report": null,
        "so_mark_observed": false,
        "mptcp_status_recorded": false,
        "mptcp_protocol_observed": false
    });
    report["server_observation"] = json!(null);
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations": opts.benchmark_iters,
        "elapsed_ns": null,
        "ns_per_ss2022_multi_psk_exchange": null,
        "scope": "SS2022 multi-PSK identity header AES block validation plus BLAKE3 session subkey, fixed/variable header encrypt/decrypt, server salt echo, payload echo over SO_MARKed Rust TCP socket",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "SS2022 UDP, all outbound protocols, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "shadowsocks_aead_protocol_true_dataplane_admitted": true,
        "ss2022_tcp_true_dataplane_admitted": true,
        "ss2022_multi_psk_identity_header_dataplane_admitted": false,
        "ss2022_udp_true_dataplane_admitted": false,
        "ss2022_true_dataplane_admitted": false,
        "shadowsocks_protocol_true_dataplane_admitted": false,
        "trojan_go_shared_transport_partial_admitted": true,
        "trojan_go_shared_transport_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "SS2022 UDP true dataplane and replay/packet evidence are still incomplete",
        "SIP003 plugin and ShadowsocksR layered transport remain separate blockers",
        "Trojan-Go full shared transport remains blocked until transport combinations and full grpc-go HTTP/2/TLS lifecycle are recertified together",
        "uTLS fingerprint, REALITY, and TLS fragmentation are still deferred",
        "Hysteria2, TUIC, Juicity, AnyTLS, REALITY, Vision, and QUIC/H3 true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage89/ss2022_multi_psk_tcp_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage89_ss2022_multi_psk_tcp_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage89 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage89 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage89 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage89-ss2022-multi-psk-tcp-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --all --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage89",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.9",
        "/root/project/outbound/protocol/shadowsocks_2022/tcp_conn.go",
        "/root/project/outbound/protocol/shadowsocks_2022/encrypt.go",
        "rust/crates/dae-outbound/src/shadowsocks/ss2022.rs",
        "rust/crates/dae-outbound/src/shadowsocks/ss2022_tcp_dataplane.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage89 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage89_smoke(opts) {
        Ok(outcome) => apply_stage89_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

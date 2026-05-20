use super::smoke::{apply_stage87_outcome, run_stage87_smoke};
use super::*;

pub(super) fn stage87_report(opts: &Stage87Options) -> Value {
    let spec = match shadowsocks::cipher_spec(&opts.cipher) {
        Ok(spec) => spec,
        Err(err) => {
            return json!({
                "name": "stage87-trojan-go-inner-shadowsocks-dataplane-admission",
                "stage": "stage87",
                "blocked": true,
                "blockers": [format!("stage87 requires AEAD cipher: {err}")]
            });
        }
    };
    if let Err(err) = trojan::TrojanMetadata::parse("tcp", &opts.target) {
        return json!({
            "name": "stage87-trojan-go-inner-shadowsocks-dataplane-admission",
            "stage": "stage87",
            "blocked": true,
            "blockers": [format!("stage87 target is invalid: {err}")]
        });
    }
    if let Err(err) = shadowsocks::ShadowsocksMetadata::parse(&opts.response_metadata_target) {
        return json!({
            "name": "stage87-trojan-go-inner-shadowsocks-dataplane-admission",
            "stage": "stage87",
            "blocked": true,
            "blockers": [format!("stage87 response metadata target is invalid: {err}")]
        });
    }
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let password_sha224_hex = trojan::packet::password_sha224_hex(&opts.trojan_password);
    let mut report = json!({
        "name": "stage87-trojan-go-inner-shadowsocks-dataplane-admission",
        "stage": "stage87",
        "evidence_class": "opt-in-protocol-trojan-go-inner-shadowsocks-true-dataplane-smoke",
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
    report["ss2022_true_dataplane_admitted"] = json!(false);
    report["trojanc_tcp_true_dataplane_admitted"] = json!(true);
    report["trojan_udp_over_tcp_admitted"] = json!(true);
    report["trojan_tls_underlay_admitted"] = json!(true);
    report["trojan_protocol_true_dataplane_admitted"] = json!(true);
    report["trojan_go_wss_admitted"] = json!(true);
    report["trojan_go_httpupgrade_admitted"] = json!(true);
    report["trojan_go_grpc_admitted"] = json!(true);
    report["trojan_go_inner_shadowsocks_smoke_passed"] = json!(false);
    report["trojan_go_inner_shadowsocks_admitted"] = json!(false);
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
    report["trojan_go_inner_shadowsocks_contract"] = json!({
        "protocol": "trojan-go",
        "transport": "inner_shadowsocks",
        "inner_protocol": "trojanc",
        "scope": "raw trojanc TCP request/response carried inside a Shadowsocks AEAD stream with IsClient=false",
        "encryption": format!("ss;{};<redacted>", spec.cipher),
        "cipher": spec.cipher,
        "salt_len": spec.salt_len,
        "target": opts.target,
        "response_metadata_target": opts.response_metadata_target,
        "payload_ascii": payload_ascii,
        "payload_len": opts.payload.len(),
        "password_sha224_hex": password_sha224_hex,
        "server": null,
        "inner_shadowsocks_is_client": false,
        "inner_shadowsocks_request_metadata_present": false,
        "inner_shadowsocks_chunk_validated": false,
        "client_salt_len": null,
        "server_salt_len": null,
        "request_has_raw_trojanc_first": false,
        "response_metadata_validated": false,
        "password_sha224_validated": false,
        "tcp_command_validated": false,
        "target_metadata_validated": false,
        "payload_roundtrip_validated": false,
        "ss2022_deferred": true,
        "ssr_deferred": true,
        "sip003_plugin_deferred": true,
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
        "ns_per_trojan_go_inner_shadowsocks_exchange": null,
        "scope": "Shadowsocks AEAD stream encrypt/decrypt plus raw trojanc TCP request header parse plus payload echo over SO_MARKed Rust TCP socket",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "all outbound protocols, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "trojan_protocol_true_dataplane_admitted": true,
        "trojan_go_wss_admitted": true,
        "trojan_go_httpupgrade_admitted": true,
        "trojan_go_grpc_admitted": true,
        "trojan_go_inner_shadowsocks_admitted": false,
        "trojan_go_shared_transport_partial_admitted": true,
        "trojan_go_shared_transport_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "outbound_true_dataplane_admitted": false,
        "ss2022_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Trojan-Go full shared transport remains blocked until transport combinations and full grpc-go HTTP/2/TLS lifecycle are recertified together",
        "Trojan-Go inner Shadowsocks admits ordinary AEAD only; SS2022, SSR, and SIP003 plugin paths remain separate",
        "uTLS fingerprint, REALITY, and TLS fragmentation are still deferred",
        "SS2022 TCP/UDP true dataplane is still incomplete",
        "VLESS and VMess TLS/WSS/gRPC/Meek/xHTTP full shared transport rows remain protocol-specific blockers",
        "Hysteria2, TUIC, Juicity, AnyTLS, REALITY, Vision, and QUIC/H3 true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage87/trojan_go_inner_shadowsocks_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage87_trojan_go_inner_shadowsocks_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage87 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage87 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage87 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage87-trojan-go-inner-shadowsocks-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --all --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage87",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.11",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.9",
        "/root/project/outbound/dialer/trojan/trojan.go",
        "/root/project/outbound/protocol/shadowsocks/tcp_conn.go",
        "rust/crates/dae-outbound/src/trojan/inner_shadowsocks_dataplane.rs",
        "rust/crates/dae-outbound/src/shadowsocks/aead.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage87 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage87_smoke(opts) {
        Ok(outcome) => apply_stage87_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

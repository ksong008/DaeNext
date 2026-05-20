use super::smoke::{apply_stage97_outcome, run_stage97_smoke};
use super::*;

pub(super) fn stage97_report(opts: &Stage97Options) -> Value {
    if let Err(err) = trojan::TrojanMetadata::parse("tcp", &opts.target) {
        return json!({
            "name": "stage97-trojan-go-grpc-http2-tls-lifecycle-admission",
            "stage": "stage97",
            "blocked": true,
            "blockers": [format!("stage97 target is invalid: {err}")]
        });
    }
    let tls_options = match opts.tls_options() {
        Ok(options) => options,
        Err(err) => {
            return json!({
                "name": "stage97-trojan-go-grpc-http2-tls-lifecycle-admission",
                "stage": "stage97",
                "blocked": true,
                "blockers": [format!("stage97 tls options invalid: {err}")]
            });
        }
    };
    let read_only_grpc_options = opts.grpc_options(&opts.grpc_address);
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let password_sha224_hex = trojan::packet::password_sha224_hex(&opts.password);
    let mut report = json!({
        "name": "stage97-trojan-go-grpc-http2-tls-lifecycle-admission",
        "stage": "stage97",
        "evidence_class": "opt-in-protocol-trojan-go-grpc-http2-tls-lifecycle-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": []
    });
    report["socks5_protocol_true_dataplane_admitted"] = json!(true);
    report["http_connect_true_dataplane_admitted"] = json!(true);
    report["https_proxy_true_dataplane_admitted"] = json!(true);
    report["shared_tls_underlay_admitted"] = json!(true);
    report["shadowsocks_protocol_true_dataplane_admitted"] = json!(true);
    report["ss2022_true_dataplane_admitted"] = json!(true);
    report["trojanc_tcp_true_dataplane_admitted"] = json!(true);
    report["trojan_udp_over_tcp_admitted"] = json!(true);
    report["trojan_tls_underlay_admitted"] = json!(true);
    report["trojan_protocol_true_dataplane_admitted"] = json!(true);
    report["trojan_go_wss_admitted"] = json!(true);
    report["trojan_go_httpupgrade_admitted"] = json!(true);
    report["trojan_go_grpc_hunk_admitted"] = json!(true);
    report["trojan_go_inner_shadowsocks_admitted"] = json!(true);
    report["trojan_go_grpc_http2_tls_lifecycle_smoke_passed"] = json!(false);
    report["trojan_go_grpc_http2_tls_lifecycle_admitted"] = json!(false);
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
    let mut contract = json!({
        "protocol": "trojan-go",
        "transport": "grpc_http2_tls",
        "inner_protocol": "trojanc",
        "scope": "SO_MARK/MPTCP TCP underlay, rustls TLS with ALPN h2 inside the gRPC dialer, HTTP/2 settings/headers/data frames, gRPC Hunk payload, and raw trojanc TCP request/response",
        "target": opts.target,
        "grpc_address": opts.grpc_address,
        "grpc_service_name": opts.grpc_service_name,
        "grpc_path": opts.grpc_path,
        "grpc_server_name": opts.grpc_server_name,
        "grpc_tls_alpn": tls_options.alpn_protocol,
        "grpc_dialer_id": opts.grpc_dialer_id,
        "grpc_allow_insecure": opts.allow_insecure,
        "grpc_cache_key": read_only_grpc_options.cache_key(),
        "outer_duplicate_tls_wrapped": false,
        "grpc_contains_tls_boundary": true,
        "http2_tls_lifecycle": false,
        "payload_ascii": payload_ascii,
        "payload_len": opts.payload.len(),
        "password_sha224_hex": password_sha224_hex,
        "server": null,
        "selected_alpn": null,
        "certificate_der_len": null
    });
    contract["tls_handshake_validated"] = json!(false);
    contract["tls_alpn_h2_validated"] = json!(false);
    contract["http2_client_preface_validated"] = json!(false);
    contract["http2_settings_validated"] = json!(false);
    contract["http2_headers_validated"] = json!(false);
    contract["http2_data_validated"] = json!(false);
    contract["grpc_hunk_tunnel_validated"] = json!(false);
    contract["grpc_cache_key_route_context_validated"] = json!(false);
    contract["no_outer_duplicate_tls_validated"] = json!(false);
    contract["password_sha224_validated"] = json!(false);
    contract["tcp_command_validated"] = json!(false);
    contract["target_metadata_validated"] = json!(false);
    contract["payload_roundtrip_validated"] = json!(false);
    contract["service_name_fallback_validated"] = json!(false);
    contract["cancellation_stress_deferred"] = json!(true);
    contract["global_cache_cleanup_deferred"] = json!(true);
    contract["utls_deferred"] = json!(true);
    contract["reality_deferred"] = json!(true);
    contract["tls_fragment_deferred"] = json!(true);
    contract["default_go_path_preserved"] = json!(true);
    report["trojan_go_grpc_contract"] = contract;
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
        "ns_per_trojan_go_grpc_http2_tls_exchange": null,
        "scope": "rustls TLS handshake with ALPN h2 plus HTTP/2 settings/headers/data lifecycle plus gRPC Hunk plus trojanc TCP request header parse plus payload echo over SO_MARKed Rust TCP socket",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "default daemon, cancellation/cache stress, cross-protocol shared transport combinations, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "socks5_protocol_true_dataplane_admitted": true,
        "http_connect_true_dataplane_admitted": true,
        "https_proxy_true_dataplane_admitted": true,
        "shadowsocks_protocol_true_dataplane_admitted": true,
        "trojan_protocol_true_dataplane_admitted": true,
        "trojan_go_wss_admitted": true,
        "trojan_go_httpupgrade_admitted": true,
        "trojan_go_grpc_hunk_admitted": true,
        "trojan_go_inner_shadowsocks_admitted": true,
        "trojan_go_grpc_http2_tls_lifecycle_admitted": false,
        "trojan_go_shared_transport_partial_admitted": true,
        "trojan_go_shared_transport_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Trojan-Go cancellation stress and global gRPC ClientConn cache cleanup are still not admitted",
        "Trojan-Go uTLS fingerprint, REALITY, TLS fragment, and shared transport combination recertification are still deferred",
        "VLESS and VMess TLS/WSS/gRPC/Meek/xHTTP full shared transport rows remain protocol-specific blockers",
        "Hysteria2, TUIC, Juicity, AnyTLS, REALITY, Vision, and QUIC/H3 true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage97/trojan_go_grpc_http2_tls_lifecycle_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage97_trojan_go_grpc_http2_tls_lifecycle_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage97 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage97 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage97 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage97-trojan-go-grpc-http2-tls-lifecycle-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage97",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.11",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.18",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "/root/project/outbound/dialer/trojan/trojan.go",
        "/root/project/outbound/transport/grpc/grpc_client.go",
        "rust/crates/dae-outbound/src/trojan/grpc_http2_dataplane.rs",
        "rust/crates/dae-outbound/src/shared_transport/grpc_http2.rs",
        "rust/crates/dae-outbound/src/shared_transport/tls.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage97 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage97_smoke(opts) {
        Ok(outcome) => apply_stage97_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

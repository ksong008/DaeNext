use super::smoke::{apply_stage95_outcome, run_stage95_smoke};
use super::*;

pub(super) fn stage95_report(opts: &Stage95Options) -> Value {
    if opts.cipher != "aes-128-cfb" {
        return json!({
            "name": "stage95-shadowsocksr-three-layer-dataplane-admission",
            "stage": "stage95",
            "blocked": true,
            "blockers": ["stage95 requires aes-128-cfb stream cipher"]
        });
    }
    if let Err(err) = shadowsocks::ShadowsocksMetadata::parse(&opts.target) {
        return json!({
            "name": "stage95-shadowsocksr-three-layer-dataplane-admission",
            "stage": "stage95",
            "blocked": true,
            "blockers": [format!("stage95 target is invalid: {err}")]
        });
    }

    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let mut report = json!({
        "name": "stage95-shadowsocksr-three-layer-dataplane-admission",
        "stage": "stage95",
        "evidence_class": "opt-in-protocol-shadowsocksr-http-simple-aes-128-cfb-origin-three-layer-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": [],
        "socks5_protocol_true_dataplane_admitted": true,
        "http_connect_true_dataplane_admitted": true,
        "https_proxy_true_dataplane_admitted": true,
        "shared_tls_underlay_admitted": true,
        "shadowsocks_aead_protocol_true_dataplane_admitted": true,
        "ss2022_true_dataplane_admitted": true,
        "sip003_plugin_transport_admitted": true,
        "shadowsocksr_three_layer_smoke_passed": false,
        "shadowsocksr_true_dataplane_admitted": false,
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
    report["shadowsocksr_contract"] = json!({
        "protocol": "shadowsocksr",
        "scheme_aliases": ["ssr", "shadowsocksr"],
        "dialer_layering": ["obfs.NewDialer", "shadowsocks_stream", "shadowsocksr proto.Dialer"],
        "obfs": "http_simple",
        "stream_cipher": opts.cipher,
        "ssr_protocol": "origin",
        "obfs_host": opts.obfs_host,
        "obfs_port": null,
        "target": opts.target,
        "payload_ascii": payload_ascii,
        "payload_len": opts.payload.len(),
        "parser_compatibility": {
            "direct_parse": true,
            "base64_fallback": true,
            "url_safe_padding": true,
            "ipv6_colon_host_merge": true,
            "remarks_proto_obfs_param_decode": true
        },
        "obfs_layer_validated": false,
        "stream_cipher_validated": false,
        "protocol_wrapper_validated": false,
        "three_layer_order_validated": false,
        "stream_key_len": null,
        "stream_iv_len": null,
        "ssr_protocol_addr_len": null,
        "payload_roundtrip_validated": false,
        "udp_wrapper_deferred": true,
        "additional_obfs_proto_matrix_deferred": true,
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
        "exchange_count": null,
        "elapsed_ns": null,
        "ns_per_shadowsocksr_three_layer_exchange": null,
        "scope": "SSR http_simple obfs request, aes-128-cfb stream cipher IV/key encryption/decryption, origin protocol target wrapper, payload echo, SO_MARK/MPTCP Rust TCP underlay",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "Stage 95 validates opt-in Rust dataplane only; outbound default daemon lifecycle and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "shadowsocks_aead_protocol_true_dataplane_admitted": true,
        "ss2022_true_dataplane_admitted": true,
        "sip003_plugin_transport_admitted": true,
        "shadowsocksr_true_dataplane_admitted": false,
        "shadowsocks_protocol_true_dataplane_admitted": false,
        "trojan_go_shared_transport_partial_admitted": true,
        "trojan_go_shared_transport_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "outbound protocol-wide default switch remains blocked until matched Go/Rust default daemon benchmark is recorded",
        "Trojan-Go full shared transport remains blocked until transport combinations and full grpc-go HTTP/2/TLS lifecycle are recertified together",
        "uTLS fingerprint, REALITY, and TLS fragmentation are still deferred",
        "Hysteria2, TUIC, Juicity, AnyTLS, REALITY, Vision, and QUIC/H3 true dataplanes are still incomplete",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage95/shadowsocksr_three_layer_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage95_shadowsocksr_three_layer_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage95 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage95 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage95 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage95-shadowsocksr-three-layer-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage95",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.10",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:12.5",
        "/root/project/outbound/dialer/shadowsocksr/shadowsocksr.go",
        "/root/project/outbound/protocol/shadowsocks_stream/tcp_conn.go",
        "/root/project/outbound/transport/shadowsocksr/obfs/http_simple.go",
        "/root/project/outbound/transport/shadowsocksr/proto/dialer.go",
        "rust/crates/dae-outbound/src/shadowsocks/ssr_dataplane.rs",
        "rust/crates/dae-outbound/src/shadowsocks/ssr_link.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage95 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage95_smoke(opts) {
        Ok(outcome) => apply_stage95_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

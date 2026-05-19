use super::smoke::{apply_stage56_outcome, run_stage56_smoke};
use super::*;

pub(super) fn stage56_report(opts: &Stage56Options) -> Value {
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let response_ascii = String::from_utf8_lossy(&opts.response).to_string();
    let mut report = json!({
        "name": "stage56-socks5-udp-associate-dataplane-admission",
        "stage": "stage56",
        "evidence_class": "opt-in-protocol-udp-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": [],
        "socks5_tcp_true_dataplane_admitted": true,
        "socks5_udp_smoke_passed": false,
        "socks5_udp_associate_admitted": false,
        "socks5_protocol_true_dataplane_admitted": false,
        "socks5_auth_observed": false,
        "socks5_udp_associate_request_observed": false,
        "socks5_udp_packet_wrap_unwrap_recorded": false,
        "socks5_udp_payload_roundtrip_recorded": false,
        "socks5_tcp_control_connection_retained": false,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false,
        "default_path_mutation_allowed": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "socks5_udp_contract": {
            "protocol": "SOCKS5",
            "scope": "UDP ASSOCIATE loopback true dataplane",
            "tcp_control_proxy": null,
            "associate_target": opts.associate_target,
            "packet_target": opts.packet_target,
            "username_password_auth_required": true,
            "command": "UDP ASSOCIATE",
            "bind_reply_uses_unspecified_ip": true,
            "unspecified_bind_falls_back_to_proxy_host": true,
            "payload_ascii": payload_ascii,
            "response_ascii": response_ascii,
            "tcp_control_connection_must_be_retained": true,
            "default_go_path_preserved": true
        },
        "tcp_control_underlay": {
            "requested_mark": opts.so_mark,
            "requested_mptcp": opts.mptcp,
            "listener": null,
            "last_dial_report": null,
            "so_mark_observed": false,
            "mptcp_status_recorded": false,
            "mptcp_protocol_observed": false
        },
        "udp_underlay_socket": {
            "requested_mark": opts.so_mark,
            "mptcp_not_applicable": true,
            "last_socket_report": null,
            "so_mark_observed": false
        },
        "server_observation": null,
        "benchmark": {
            "benchmark_recorded": false,
            "iterations": opts.benchmark_iters,
            "elapsed_ns": null,
            "ns_per_udp_associate": null,
            "scope": "SOCKS5 UDP ASSOCIATE plus TCP control retention plus UDP packet roundtrip over SO_MARKed Rust UDP socket",
            "go_matched_default_daemon_baseline_recorded": false,
            "go_baseline_gap": "all outbound protocols, daemon default lifecycle, and product-chain gates are not closed"
        },
        "protocol_matrix": {
            "socks5_tcp_true_dataplane_admitted": true,
            "socks5_udp_associate_admitted": false,
            "socks5_protocol_true_dataplane_admitted": false,
            "http_connect_true_dataplane_admitted": false,
            "shadowsocks_aead_true_dataplane_admitted": false,
            "vmess_vless_trojan_shared_transport_admitted": false,
            "quic_h3_session_protocols_admitted": false
        },
        "remaining_blockers": [
            "HTTP/HTTPS, Shadowsocks/SS2022, Trojan, VMess, VLESS, Hysteria2, TUIC, Juicity, AnyTLS, and shared transport true dataplanes are still incomplete",
            "matched Go default daemon vs true Rust candidate benchmark is still missing",
            "clean dae-wing and daed product-chain recertification is still missing"
        ],
        "validation_commands": [
            "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage56/socks5_udp_associate_dataplane_admission.json",
            "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage56_socks5_udp_associate_dataplane_gate.json",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage56 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-product stage56 -- --nocapture",
            "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage56-socks5-udp-associate-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
            "git diff --check"
        ],
        "source": [
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage56-item338",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.13",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:27.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:33.8",
            "rust/crates/dae-outbound/src/socks5/dataplane.rs",
            "rust/crates/dae-outbound/src/socks5/udp_packet.rs",
            "rust/crates/dae-datapath/src/udp_direct.rs"
        ]
    });

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage56 root-gated smoke requires --ack-root-gate because it attempts SO_MARK on TCP control and UDP associate sockets"
        ]);
        return report;
    }

    match run_stage56_smoke(opts) {
        Ok(outcome) => apply_stage56_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

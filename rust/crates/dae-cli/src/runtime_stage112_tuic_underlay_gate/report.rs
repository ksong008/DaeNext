use dae_outbound::tuic;
use serde_json::{Value, json};

use super::options::Stage112Options;
use super::smoke::{apply_stage112_outcome, run_stage112_smoke};

pub(super) fn stage112_report(opts: &Stage112Options) -> Value {
    let contract = tuic::underlay::admission_contract(opts.so_mark, opts.mptcp);
    let mut report = json!({
        "name": "stage112-tuic-udp-underlay-admission",
        "stage": "stage112",
        "evidence_class": "opt-in-protocol-tuic-udp-underlay-socket-smoke-before-full-quic",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": []
    });
    report["tuic_native_optin_contract_admitted"] = json!(true);
    report["tuic_uuid_password_contract_admitted"] = json!(true);
    report["tuic_tls13_datagram_config_contract_admitted"] = json!(true);
    report["tuic_disable_sni_contract_admitted"] = json!(true);
    report["tuic_udp_relay_mode_go_parity_caveat_recorded"] = json!(true);
    report["tuic_underlay_contract_admitted"] = json!(true);
    report["tuic_udp_underlay_socket_smoke_passed"] = json!(false);
    report["tuic_udp_underlay_socket_admitted"] = json!(false);
    report["tuic_so_mark_loopback_observed"] = json!(false);
    report["tuic_full_quic_handshake_admitted"] = json!(false);
    report["tuic_auth_stream_admitted"] = json!(false);
    report["tuic_datagram_packet_relay_admitted"] = json!(false);
    report["tuic_udp_relay_mode_quic_effective_relay_admitted"] = json!(false);
    report["tuic_true_quic_dataplane_admitted"] = json!(false);
    report["hysteria2_udp_underlay_admitted"] = json!(true);
    report["hysteria2_true_quic_dataplane_admitted"] = json!(false);
    report["juicity_true_quic_h3_dataplane_admitted"] = json!(false);
    report["quic_h3_family_native_optin_contract_admitted"] = json!(true);
    report["quic_h3_family_true_dataplane_admitted"] = json!(false);
    report["anytls_true_dataplane_admitted"] = json!(true);
    report["protocol_outbound_partial_admitted"] = json!(true);
    report["outbound_true_dataplane_admitted"] = json!(false);
    report["matched_go_rust_default_daemon_benchmark_recorded"] = json!(false);
    report["default_switch_allowed"] = json!(false);
    report["default_path_mutation_allowed"] = json!(false);
    report["product_chain_switch_allowed"] = json!(false);
    report["true_rust_default_daemon_admitted"] = json!(false);
    report["outbound_quic_go_dependency_preserved"] = json!(true);
    report["external_outbound_required"] = json!(true);
    report["external_quic_go_required"] = json!(true);
    report["go_default_path_preserved"] = json!(true);
    report["go_fallback_required"] = json!(true);
    report["tuic_underlay_contract"] = json!({
        "tcp_request": {
            "input_network": contract.tcp_request.input_network,
            "input_mark": contract.tcp_request.input_mark,
            "input_mptcp": contract.tcp_request.input_mptcp,
            "underlay_network": contract.tcp_request.underlay_network,
            "underlay_mark": contract.tcp_request.underlay_mark,
            "underlay_mptcp": contract.tcp_request.underlay_mptcp,
            "same_encoded_value": contract.tcp_request.same_encoded_value
        },
        "udp_request": {
            "input_network": contract.udp_request.input_network,
            "input_mark": contract.udp_request.input_mark,
            "input_mptcp": contract.udp_request.input_mptcp,
            "underlay_network": contract.udp_request.underlay_network,
            "underlay_mark": contract.udp_request.underlay_mark,
            "underlay_mptcp": contract.udp_request.underlay_mptcp,
            "same_encoded_value": contract.udp_request.same_encoded_value
        },
        "tcp_underlay_uses_udp": contract.tcp_underlay_uses_udp,
        "tcp_underlay_preserves_mark": contract.tcp_underlay_preserves_mark,
        "tcp_underlay_drops_mptcp": contract.tcp_underlay_drops_mptcp,
        "udp_underlay_uses_original": contract.udp_underlay_uses_original,
        "socket_so_mark_observation_required": contract.socket_so_mark_observation_required,
        "true_quic_dataplane_deferred": contract.true_quic_dataplane_deferred
    });
    report["underlay_socket"] = json!({
        "requested_mark": opts.so_mark,
        "requested_mptcp": opts.mptcp,
        "listener": null,
        "last_socket_report": null,
        "so_mark_observed": false,
        "tcp_underlay_drops_mptcp": contract.tcp_underlay_drops_mptcp,
        "udp_underlay_uses_original": contract.udp_underlay_uses_original
    });
    report["server_observation"] = json!(null);
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations": opts.benchmark_iters,
        "elapsed_ns": null,
        "ns_per_tuic_udp_underlay_exchange": null,
        "scope": "local UDP underlay datagram echo with TUIC TCP-request UDP-underlay, SO_MARK, and MPTCP-drop contract checks; not a full TUIC QUIC client dataplane",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "full TUIC QUIC handshake/auth/datagram behavior, outbound registry/group semantics, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "hysteria2_udp_underlay_admitted": true,
        "hysteria2_true_quic_dataplane_admitted": false,
        "tuic_native_optin_contract_admitted": true,
        "tuic_underlay_contract_admitted": true,
        "tuic_udp_underlay_socket_admitted": false,
        "tuic_true_quic_dataplane_admitted": false,
        "juicity_true_quic_h3_dataplane_admitted": false,
        "quic_h3_family_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": true,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "TUIC full QUIC handshake, certificate verification, and auth stream",
        "TUIC datagram packet relay, congestion behavior, and udp_relay_mode=quic effective relay parity",
        "Hysteria2 full QUIC and Juicity H3 true dataplanes",
        "outbound registry/dialer group/health policy parity while preserving direct/block indices and NewDialerSetFromLinks semantics",
        "matched Go default daemon vs true Rust candidate benchmark",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage112/tuic_udp_underlay_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage112_tuic_udp_underlay_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage112 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage112-tuic-udp-underlay-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage112-tuic-udp-underlay-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage112 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage112 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage112",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:12.6",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.15",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.20",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "/root/project/outbound/protocol/tuic/dialer.go",
        "/root/project/outbound/protocol/tuic/common/type.go",
        "rust/crates/dae-outbound/src/tuic/underlay.rs",
        "rust/crates/dae-cli/src/runtime_stage112_tuic_underlay_gate/",
        "rust/crates/dae-datapath/src/udp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage112 root-gated smoke requires --ack-root-gate because it attempts SO_MARK UDP underlay socket observation"
        ]);
        return report;
    }
    match run_stage112_smoke(opts) {
        Ok(outcome) => apply_stage112_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

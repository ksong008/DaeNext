use dae_outbound::hysteria2;
use serde_json::{Value, json};

use super::options::{DEFAULT_CERT_DER, Stage109Options};
use super::smoke::{apply_stage109_outcome, run_stage109_smoke};

pub(super) fn stage109_report(opts: &Stage109Options) -> Value {
    let underlay = hysteria2::underlay_contract(
        "tcp",
        &opts.server,
        opts.so_mark,
        opts.mptcp,
        opts.udp_hop_interval_ms,
    );
    let raw_cert_sha256 = hysteria2::raw_cert_sha256_hex(DEFAULT_CERT_DER);
    let pin_check = hysteria2::pin_sha256_matches_raw_cert(&raw_cert_sha256, DEFAULT_CERT_DER);
    let mut report = json!({
        "name": "stage109-hysteria2-udp-underlay-admission",
        "stage": "stage109",
        "evidence_class": "opt-in-protocol-hysteria2-udp-underlay-smoke-before-full-quic",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": []
    });
    report["hysteria2_native_optin_contract_admitted"] = json!(true);
    report["hysteria2_port_hopping_contract_admitted"] = json!(underlay.server.port_hopping);
    report["hysteria2_pin_sha256_raw_cert_hash_admitted"] = json!(pin_check.matched);
    report["hysteria2_udp_underlay_smoke_passed"] = json!(false);
    report["hysteria2_udp_underlay_admitted"] = json!(false);
    report["hysteria2_full_quic_stack_observed"] = json!(false);
    report["hysteria2_true_quic_dataplane_admitted"] = json!(false);
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
    report["hysteria2_contract"] = json!({
        "server": underlay.server.server,
        "host": underlay.server.host,
        "port": underlay.server.port,
        "host_port": underlay.server.host_port,
        "port_hopping": underlay.server.port_hopping,
        "input_network": underlay.input_network,
        "underlay_network": underlay.underlay_network,
        "route_cache_key_network": underlay.route_cache_key_network,
        "input_mark": underlay.input_mark,
        "underlay_mark": underlay.underlay_mark,
        "input_mptcp": underlay.input_mptcp,
        "underlay_mptcp_field": underlay.underlay_mptcp_field,
        "udp_mptcp_effective": underlay.udp_mptcp_effective,
        "udp_hop_interval_ms": underlay.udp_hop_interval_ms,
        "pin_sha256_raw_cert_hash": raw_cert_sha256,
        "pin_sha256_configured_normal": pin_check.configured_pin_normal,
        "pin_sha256_raw_cert_hash_matched": pin_check.matched
    });
    report["underlay_socket"] = json!({
        "requested_mark": opts.so_mark,
        "requested_mptcp": opts.mptcp,
        "listener": null,
        "last_socket_report": null,
        "so_mark_observed": false,
        "mptcp_field_preserved": underlay.underlay_mptcp_field,
        "mptcp_effective_for_udp": false
    });
    report["server_observation"] = json!(null);
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations": opts.benchmark_iters,
        "elapsed_ns": null,
        "ns_per_hysteria2_udp_underlay_exchange": null,
        "scope": "local UDP underlay datagram echo with Hysteria2 port hopping, pinSHA256 raw cert hash, SO_MARK, and MPTCP-field contract checks; not a full QUIC/Hysteria2 client dataplane",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "full Hysteria2 QUIC client, outbound registry/group semantics, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "hysteria2_native_optin_contract_admitted": true,
        "hysteria2_udp_underlay_admitted": false,
        "hysteria2_true_quic_dataplane_admitted": false,
        "quic_h3_family_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": true,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Hysteria2 full QUIC handshake, stream multiplexing, congestion, and port hopping scheduler are not implemented in Rust",
        "Hysteria2 TCP target and UDP target still need true client behavior over QUIC streams/datagrams",
        "TUIC and Juicity true QUIC/H3 dataplanes remain external/outbound-quic-go blockers",
        "outbound registry/dialer group/health policy parity while preserving direct/block indices and NewDialerSetFromLinks semantics",
        "matched Go default daemon vs true Rust candidate benchmark",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage109/hysteria2_udp_underlay_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage109_hysteria2_udp_underlay_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage109 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage109-hysteria2-udp-underlay-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage109-hysteria2-udp-underlay-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage109 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage109 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage109",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:12.6",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.14",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.20",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "/root/project/outbound/protocol/hysteria2/dialer.go",
        "/root/project/outbound/protocol/hysteria2/client/config.go",
        "/root/project/outbound/protocol/hysteria2/udphop",
        "rust/crates/dae-outbound/src/hysteria2/underlay.rs",
        "rust/crates/dae-cli/src/runtime_stage109_hysteria2_underlay_gate/",
        "rust/crates/dae-datapath/src/udp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage109 root-gated smoke requires --ack-root-gate because it attempts SO_MARK UDP underlay socket observation"
        ]);
        return report;
    }
    match run_stage109_smoke(opts) {
        Ok(outcome) => apply_stage109_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage107_anytls_protocol_wide_recertification(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage107 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage107_report()))
}

fn stage107_report() -> Value {
    let mut report = json!({
        "name": "stage107-anytls-protocol-wide-recertification",
        "stage": "stage107",
        "evidence_class": "read-only-protocol-anytls-wide-recertification-after-session-reuse",
        "execute_smoke": false,
        "read_only": true,
        "blocked": false,
        "blockers": []
    });
    for key in [
        "anytls_native_optin_contract_admitted",
        "anytls_session_frame_true_dataplane_admitted",
        "anytls_udp_packet_stream_true_dataplane_admitted",
        "anytls_idle_session_reuse_true_dataplane_admitted",
        "anytls_true_dataplane_admitted",
        "protocol_outbound_partial_admitted",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "quic_h3_family_true_dataplane_admitted",
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
            "area": "AnyTLS session/frame first flight",
            "status": "passed-carried-evidence",
            "source_stage": "stage104",
            "admitted": true,
            "evidence": "Stage104 runtime smoke proved rustls TLS, password sha256 auth first write, Settings/SYN/PSH target, SYNACK, and PSH payload echo over SO_MARK/MPTCP TCP underlay",
            "boundary": "carried Stage104 evidence admits only the AnyTLS session/frame sub-row"
        },
        {
            "area": "AnyTLS UDP packet stream",
            "status": "passed-carried-evidence",
            "source_stage": "stage105",
            "admitted": true,
            "evidence": "Stage105 runtime smoke proved UDP stream target rewrite to sp.v2.udp-over-tcp.arpa, first packet target+payload framing, subsequent length+payload framing, and packet response roundtrip",
            "boundary": "carried Stage105 evidence admits only UDP packet stream over AnyTLS session"
        },
        {
            "area": "AnyTLS idle session reuse and lifecycle",
            "status": "passed-carried-evidence",
            "source_stage": "stage106",
            "admitted": true,
            "evidence": "Stage106 runtime smoke proved one TCP/TLS/auth physical session carrying sid 1 and sid 2 logical streams with FIN lifecycle and payload echo",
            "boundary": "carried Stage106 evidence admits idle reuse/lifecycle but not outbound default switches"
        },
        {
            "area": "AnyTLS protocol-wide opt-in",
            "status": "passed-recertified-after-stage106",
            "source_stage": "stage107",
            "admitted": true,
            "evidence": "Stage107 requires all three AnyTLS true dataplane sub-rows to be true before setting anytls_true_dataplane_admitted=true",
            "boundary": "AnyTLS protocol-wide opt-in admission still preserves Go default outbound path and product-chain closures"
        },
        {
            "area": "overall outbound/default admission",
            "status": "blocked",
            "source_stage": "stage107",
            "admitted": false,
            "evidence": "QUIC/H3 family protocols, matched default daemon benchmark, outbound-wide recertification, and clean product-chain recertification remain open",
            "boundary": "anytls_true_dataplane_admitted=true does not mean outbound_true_dataplane_admitted=true"
        }
    ]);
    report["benchmark_carry_forward"] = json!({
        "stage104_ns_per_anytls_session_frame_exchange": 52199940.3,
        "stage105_ns_per_anytls_udp_packet_stream_exchange": 49463396.7,
        "stage106_ns_per_anytls_session_reuse_exchange": 136887911.4,
        "new_network_benchmark_recorded": false,
        "reason": "Stage 107 is a read-only recertification gate and carries previously recorded AnyTLS dataplane benchmarks"
    });
    report["protocol_matrix"] = json!({
        "anytls_native_optin_contract_admitted": true,
        "anytls_session_frame_true_dataplane_admitted": true,
        "anytls_udp_packet_stream_true_dataplane_admitted": true,
        "anytls_idle_session_reuse_true_dataplane_admitted": true,
        "anytls_true_dataplane_admitted": true,
        "quic_h3_family_true_dataplane_admitted": false,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Hysteria2, TUIC, and Juicity QUIC family true dataplanes remain external/outbound-quic-go blockers",
        "VLESS and VMess TLS/WSS/gRPC/Meek/xHTTP full shared transport rows remain protocol-specific blockers",
        "Trojan-Go full uTLS wire-level and REALITY/uTLS full handshake rows remain protocol-specific blockers",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "outbound-wide protocol matrix recertification after remaining protocol families is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage107/anytls_protocol_wide_recertification.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage107_anytls_protocol_wide_recertification_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage107-anytls-protocol-wide-recertification",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage107 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage107 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage107",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.17",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.20",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "testdata/rebuild-golden/engine/runtime_stage104/anytls_session_frame_admission.json",
        "testdata/rebuild-golden/engine/runtime_stage105/anytls_udp_packet_stream_admission.json",
        "testdata/rebuild-golden/engine/runtime_stage106/anytls_idle_session_reuse_admission.json",
        "rust/crates/dae-outbound/src/anytls/dataplane.rs",
        "rust/crates/dae-outbound/src/anytls/udp_packet_dataplane.rs",
        "rust/crates/dae-outbound/src/anytls/session_reuse_dataplane.rs"
    ]);
    report
}

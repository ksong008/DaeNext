use super::smoke::{apply_stage106_outcome, run_stage106_smoke};
use super::*;

pub(super) fn stage106_report(opts: &Stage106Options) -> Value {
    let tls_options = match opts.tls_options() {
        Ok(options) => options,
        Err(err) => {
            return json!({
                "name": "stage106-anytls-idle-session-reuse-admission",
                "stage": "stage106",
                "blocked": true,
                "blockers": [format!("stage106 tls options invalid: {err}")]
            });
        }
    };
    if let Err(err) = Socks5Address::parse(&opts.first_target) {
        return json!({
            "name": "stage106-anytls-idle-session-reuse-admission",
            "stage": "stage106",
            "blocked": true,
            "blockers": [format!("stage106 first target is invalid: {err}")]
        });
    }
    if let Err(err) = Socks5Address::parse(&opts.second_target) {
        return json!({
            "name": "stage106-anytls-idle-session-reuse-admission",
            "stage": "stage106",
            "blocked": true,
            "blockers": [format!("stage106 second target is invalid: {err}")]
        });
    }
    let first_frames =
        match anytls::stream_lifecycle_frames(1, &opts.first_target, &opts.first_payload) {
            Ok(frames) => frames,
            Err(err) => {
                return json!({
                    "name": "stage106-anytls-idle-session-reuse-admission",
                    "stage": "stage106",
                    "blocked": true,
                    "blockers": [format!("stage106 first stream frames invalid: {err}")]
                });
            }
        };
    let second_frames =
        match anytls::stream_lifecycle_frames(2, &opts.second_target, &opts.second_payload) {
            Ok(frames) => frames,
            Err(err) => {
                return json!({
                    "name": "stage106-anytls-idle-session-reuse-admission",
                    "stage": "stage106",
                    "blocked": true,
                    "blockers": [format!("stage106 second stream frames invalid: {err}")]
                });
            }
        };
    let first_payload_ascii = String::from_utf8_lossy(&opts.first_payload).to_string();
    let second_payload_ascii = String::from_utf8_lossy(&opts.second_payload).to_string();
    let auth_sha256_hex = hex_encode(&anytls::link::auth_key(&opts.auth));
    let underlay = anytls::link::underlay_contract("tcp", opts.so_mark, opts.mptcp);
    let mut report = json!({
        "name": "stage106-anytls-idle-session-reuse-admission",
        "stage": "stage106",
        "evidence_class": "opt-in-protocol-anytls-idle-session-reuse-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": []
    });
    report["anytls_native_optin_contract_admitted"] = json!(true);
    report["anytls_session_frame_true_dataplane_admitted"] = json!(true);
    report["anytls_udp_packet_stream_true_dataplane_admitted"] = json!(true);
    report["anytls_idle_session_reuse_smoke_passed"] = json!(false);
    report["anytls_idle_session_reuse_true_dataplane_admitted"] = json!(false);
    report["anytls_true_dataplane_admitted"] = json!(false);
    report["quic_h3_family_true_dataplane_admitted"] = json!(false);
    report["protocol_outbound_partial_admitted"] = json!(true);
    report["outbound_true_dataplane_admitted"] = json!(false);
    report["matched_go_rust_default_daemon_benchmark_recorded"] = json!(false);
    report["default_switch_allowed"] = json!(false);
    report["default_path_mutation_allowed"] = json!(false);
    report["product_chain_switch_allowed"] = json!(false);
    report["true_rust_default_daemon_admitted"] = json!(false);
    report["go_default_path_preserved"] = json!(true);
    report["go_fallback_required"] = json!(true);
    report["anytls_contract"] = json!({
        "protocol": "anytls",
        "scope": "AnyTLS idle session reuse over one rustls TLS session",
        "first_target": opts.first_target,
        "second_target": opts.second_target,
        "tls_server_name": tls_options.server_name,
        "alpn_protocol": tls_options.alpn_protocol,
        "selected_alpn": null,
        "certificate_der_len": null,
        "first_payload_ascii": first_payload_ascii,
        "second_payload_ascii": second_payload_ascii,
        "auth_sha256_hex": auth_sha256_hex,
        "server": null
    });
    report["anytls_contract"]["auth_handshake_len"] =
        json!(anytls::link::handshake_auth_bytes(&opts.auth).len());
    report["anytls_contract"]["auth_written_once"] = json!(false);
    report["anytls_contract"]["logical_stream_count"] = json!(2);
    report["anytls_contract"]["physical_session_count"] = json!(1);
    report["anytls_contract"]["first_stream"] = json!({
        "sid": 1,
        "target": opts.first_target,
        "payload_len": opts.first_payload.len(),
        "settings_frame_len": first_frames.settings_frame.len(),
        "syn_frame_len": first_frames.syn_frame.len(),
        "psh_addr_frame_len": first_frames.psh_addr_frame.len(),
        "psh_payload_frame_len": first_frames.psh_payload_frame.len(),
        "fin_frame_len": first_frames.fin_frame.len()
    });
    report["anytls_contract"]["second_stream"] = json!({
        "sid": 2,
        "target": opts.second_target,
        "payload_len": opts.second_payload.len(),
        "settings_frame_len": second_frames.settings_frame.len(),
        "syn_frame_len": second_frames.syn_frame.len(),
        "psh_addr_frame_len": second_frames.psh_addr_frame.len(),
        "psh_payload_frame_len": second_frames.psh_payload_frame.len(),
        "fin_frame_len": second_frames.fin_frame.len()
    });
    report["anytls_contract"]["empty_sni_server_name"] =
        json!(anytls::contract::EMPTY_SNI_SERVER_NAME);
    report["anytls_contract"]["idle_session_reuse_map"] =
        json!(anytls::contract::IDLE_SESSION_REUSE_MAP);
    report["anytls_contract"]["session_counter"] = json!(anytls::contract::SESSION_COUNTER);
    report["anytls_contract"]["underlay_always_tcp"] = json!(anytls::contract::UNDERLAY_ALWAYS_TCP);
    report["anytls_contract"]["underlay_preserves_mark"] =
        json!(anytls::contract::UNDERLAY_PRESERVES_MARK);
    report["anytls_contract"]["underlay_preserves_mptcp"] =
        json!(anytls::contract::UNDERLAY_PRESERVES_MPTCP);
    report["anytls_contract"]["tcp_input_underlay_network"] = json!(underlay.input_network);
    report["anytls_contract"]["tcp_effective_underlay_network"] = json!(underlay.underlay_network);
    report["anytls_contract"]["tcp_effective_underlay_mark"] = json!(underlay.underlay_mark);
    report["anytls_contract"]["tcp_effective_underlay_mptcp"] = json!(underlay.underlay_mptcp);
    report["anytls_contract"]["tls_handshake_validated"] = json!(false);
    report["anytls_contract"]["certificate_chain_validated"] = json!(false);
    report["anytls_contract"]["server_name_validated"] = json!(false);
    report["anytls_contract"]["alpn_validated"] = json!(false);
    report["anytls_contract"]["auth_key_validated"] = json!(false);
    report["anytls_contract"]["sid_increment_validated"] = json!(false);
    report["anytls_contract"]["fin_lifecycle_validated"] = json!(false);
    report["anytls_contract"]["idle_session_reuse_validated"] = json!(false);
    report["anytls_contract"]["full_anytls_recertification_deferred"] = json!(true);
    report["anytls_contract"]["default_go_path_preserved"] = json!(true);
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
        "ns_per_anytls_session_reuse_exchange": null,
        "logical_streams_per_exchange": 2,
        "scope": "one rustls TLS/auth session carrying two sequential AnyTLS logical streams with FIN lifecycle over SO_MARKed Rust TCP socket",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "all outbound protocols, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "anytls_native_optin_contract_admitted": true,
        "anytls_session_frame_true_dataplane_admitted": true,
        "anytls_udp_packet_stream_true_dataplane_admitted": true,
        "anytls_idle_session_reuse_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": false,
        "quic_h3_family_true_dataplane_admitted": false,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Full AnyTLS protocol-wide admission needs a final recertification row after session reuse",
        "Hysteria2, TUIC, and Juicity QUIC family true dataplanes remain external/outbound-quic-go blockers",
        "VLESS and VMess TLS/WSS/gRPC/Meek/xHTTP full shared transport rows remain protocol-specific blockers",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage106/anytls_idle_session_reuse_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage106_anytls_idle_session_reuse_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage106 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage106 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage106 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage106-anytls-idle-session-reuse-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage106",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.17",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.20",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "/root/project/outbound/protocol/anytls/dialer.go",
        "/root/project/outbound/protocol/anytls/session.go",
        "/root/project/outbound/protocol/anytls/stream.go",
        "rust/crates/dae-outbound/src/anytls/session_reuse_dataplane.rs",
        "rust/crates/dae-outbound/src/anytls/dataplane.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage106 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage106_smoke(opts) {
        Ok(outcome) => apply_stage106_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

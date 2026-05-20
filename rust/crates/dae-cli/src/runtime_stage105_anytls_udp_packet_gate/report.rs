use super::smoke::{apply_stage105_outcome, run_stage105_smoke};
use super::*;

pub(super) fn stage105_report(opts: &Stage105Options) -> Value {
    let tls_options = match opts.tls_options() {
        Ok(options) => options,
        Err(err) => {
            return json!({
                "name": "stage105-anytls-udp-packet-stream-admission",
                "stage": "stage105",
                "blocked": true,
                "blockers": [format!("stage105 tls options invalid: {err}")]
            });
        }
    };
    if let Err(err) = Socks5Address::parse(&opts.original_udp_target) {
        return json!({
            "name": "stage105-anytls-udp-packet-stream-admission",
            "stage": "stage105",
            "blocked": true,
            "blockers": [format!("stage105 original UDP target is invalid: {err}")]
        });
    }
    let session_stream_target = match anytls::link::udp_stream_target(&opts.original_udp_target) {
        Ok(target) => target,
        Err(err) => {
            return json!({
                "name": "stage105-anytls-udp-packet-stream-admission",
                "stage": "stage105",
                "blocked": true,
                "blockers": [format!("stage105 UDP stream target invalid: {err}")]
            });
        }
    };
    let stream_target_addr = match anytls::link::socks_addr(&session_stream_target) {
        Ok(addr) => addr,
        Err(err) => {
            return json!({
                "name": "stage105-anytls-udp-packet-stream-admission",
                "stage": "stage105",
                "blocked": true,
                "blockers": [format!("stage105 UDP stream target address invalid: {err}")]
            });
        }
    };
    let first_write =
        match anytls::link::packet_first_write(&opts.original_udp_target, &opts.first_payload) {
            Ok(packet) => packet,
            Err(err) => {
                return json!({
                    "name": "stage105-anytls-udp-packet-stream-admission",
                    "stage": "stage105",
                    "blocked": true,
                    "blockers": [format!("stage105 first UDP packet invalid: {err}")]
                });
            }
        };
    let next_write = anytls::link::packet_next_write(&opts.next_payload);
    let first_payload_ascii = String::from_utf8_lossy(&opts.first_payload).to_string();
    let next_payload_ascii = String::from_utf8_lossy(&opts.next_payload).to_string();
    let auth_sha256_hex = hex_encode(&anytls::link::auth_key(&opts.auth));
    let settings = anytls::link::settings_bytes();
    let underlay = anytls::link::underlay_contract("udp", opts.so_mark, opts.mptcp);
    let mut report = json!({
        "name": "stage105-anytls-udp-packet-stream-admission",
        "stage": "stage105",
        "evidence_class": "opt-in-protocol-anytls-udp-packet-stream-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": []
    });
    report["anytls_native_optin_contract_admitted"] = json!(true);
    report["anytls_session_frame_true_dataplane_admitted"] = json!(true);
    report["anytls_udp_packet_stream_smoke_passed"] = json!(false);
    report["anytls_udp_packet_stream_true_dataplane_admitted"] = json!(false);
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
        "scope": "AnyTLS UDP packet stream over rustls TLS session",
        "original_udp_target": opts.original_udp_target,
        "session_stream_target": session_stream_target,
        "tls_server_name": tls_options.server_name,
        "alpn_protocol": tls_options.alpn_protocol,
        "selected_alpn": null,
        "certificate_der_len": null,
        "first_payload_ascii": first_payload_ascii,
        "next_payload_ascii": next_payload_ascii,
        "auth_sha256_hex": auth_sha256_hex,
        "server": null
    });
    report["anytls_contract"]["auth_handshake_len"] =
        json!(anytls::link::handshake_auth_bytes(&opts.auth).len());
    report["anytls_contract"]["settings_frame_len"] =
        json!(anytls::contract::HEADER_OVERHEAD_SIZE + settings.len());
    report["anytls_contract"]["syn_frame_len"] = json!(anytls::contract::HEADER_OVERHEAD_SIZE);
    report["anytls_contract"]["psh_addr_frame_len"] =
        json!(anytls::contract::HEADER_OVERHEAD_SIZE + stream_target_addr.len());
    report["anytls_contract"]["first_packet_frame_len"] =
        json!(anytls::contract::HEADER_OVERHEAD_SIZE + first_write.len());
    report["anytls_contract"]["next_packet_frame_len"] =
        json!(anytls::contract::HEADER_OVERHEAD_SIZE + next_write.len());
    report["anytls_contract"]["settings_payload_len"] = json!(settings.len());
    report["anytls_contract"]["stream_target_addr_len"] = json!(stream_target_addr.len());
    report["anytls_contract"]["first_packet_write_len"] = json!(first_write.len());
    report["anytls_contract"]["next_packet_write_len"] = json!(next_write.len());
    report["anytls_contract"]["first_payload_len"] = json!(opts.first_payload.len());
    report["anytls_contract"]["next_payload_len"] = json!(opts.next_payload.len());
    report["anytls_contract"]["first_write_connected_mode"] = json!(first_write[0] == 1);
    report["anytls_contract"]["empty_sni_server_name"] =
        json!(anytls::contract::EMPTY_SNI_SERVER_NAME);
    report["anytls_contract"]["udp_magic_domain"] = json!(anytls::contract::UDP_MAGIC_DOMAIN);
    report["anytls_contract"]["underlay_always_tcp"] = json!(anytls::contract::UNDERLAY_ALWAYS_TCP);
    report["anytls_contract"]["underlay_preserves_mark"] =
        json!(anytls::contract::UNDERLAY_PRESERVES_MARK);
    report["anytls_contract"]["underlay_preserves_mptcp"] =
        json!(anytls::contract::UNDERLAY_PRESERVES_MPTCP);
    report["anytls_contract"]["udp_input_underlay_network"] = json!(underlay.input_network);
    report["anytls_contract"]["udp_effective_underlay_network"] = json!(underlay.underlay_network);
    report["anytls_contract"]["udp_effective_underlay_mark"] = json!(underlay.underlay_mark);
    report["anytls_contract"]["udp_effective_underlay_mptcp"] = json!(underlay.underlay_mptcp);
    report["anytls_contract"]["tls_handshake_validated"] = json!(false);
    report["anytls_contract"]["certificate_chain_validated"] = json!(false);
    report["anytls_contract"]["server_name_validated"] = json!(false);
    report["anytls_contract"]["alpn_validated"] = json!(false);
    report["anytls_contract"]["auth_key_validated"] = json!(false);
    report["anytls_contract"]["settings_validated"] = json!(false);
    report["anytls_contract"]["syn_validated"] = json!(false);
    report["anytls_contract"]["psh_magic_target_validated"] = json!(false);
    report["anytls_contract"]["synack_validated"] = json!(false);
    report["anytls_contract"]["udp_magic_domain_validated"] = json!(false);
    report["anytls_contract"]["first_write_target_validated"] = json!(false);
    report["anytls_contract"]["first_write_payload_validated"] = json!(false);
    report["anytls_contract"]["next_write_payload_validated"] = json!(false);
    report["anytls_contract"]["payload_roundtrip_validated"] = json!(false);
    report["anytls_contract"]["idle_session_reuse_deferred"] = json!(true);
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
        "ns_per_anytls_udp_packet_stream_exchange": null,
        "scope": "rustls TLS handshake plus AnyTLS auth/settings/SYN/PSH magic target plus first/next UDP packet stream PSH exchange over SO_MARKed Rust TCP socket",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "all outbound protocols, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "anytls_native_optin_contract_admitted": true,
        "anytls_session_frame_true_dataplane_admitted": true,
        "anytls_udp_packet_stream_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": false,
        "quic_h3_family_true_dataplane_admitted": false,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "AnyTLS idle session reuse map is not yet recertified as true Rust dataplane",
        "Full AnyTLS protocol admission still requires session lifecycle and reuse recertification after UDP packet stream",
        "Hysteria2, TUIC, and Juicity QUIC family true dataplanes remain external/outbound-quic-go blockers",
        "VLESS and VMess TLS/WSS/gRPC/Meek/xHTTP full shared transport rows remain protocol-specific blockers",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage105/anytls_udp_packet_stream_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage105_anytls_udp_packet_stream_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage105 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage105 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage105 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage105-anytls-udp-packet-stream-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage105",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.17",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.20",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "/root/project/outbound/protocol/anytls/session.go",
        "/root/project/outbound/protocol/anytls/stream.go",
        "/root/project/outbound/protocol/anytls/dialer.go",
        "rust/crates/dae-outbound/src/anytls/udp_packet_dataplane.rs",
        "rust/crates/dae-outbound/src/anytls/dataplane.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage105 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage105_smoke(opts) {
        Ok(outcome) => apply_stage105_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

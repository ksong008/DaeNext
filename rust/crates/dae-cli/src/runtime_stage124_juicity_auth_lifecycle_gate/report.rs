use dae_outbound::juicity;
use serde_json::{Value, json};

use super::options::Stage124Options;

pub(super) fn stage124_report(opts: &Stage124Options) -> Value {
    let mut report = json!({
        "name": "stage124-juicity-auth-lifecycle-admission",
        "stage": "stage124",
        "evidence_class": "juicity-send-authentication-lifecycle-before-packet-relay",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": !opts.execute_smoke,
        "blockers": [
            "stage124 read-only fixture has not executed the live sendAuthentication lifecycle smoke",
            "complete Juicity TransportPacketConn encryption, stream PacketConn relay, congestion behavior, and default/product switching remain blocked",
            "external outbound/quic-go remains required"
        ]
    });
    for key in [
        "quinn_dependency_available",
        "h3_dependency_available",
        "h3_quinn_dependency_available",
        "tokio_quic_runtime_admitted",
        "quinn_runtime_tokio_feature_admitted",
        "quinn_rustls_aws_lc_rs_feature_admitted",
        "h3_quinn_bridge_admitted",
        "juicity_h3_loopback_dependency_admitted",
        "juicity_h3_loopback_smoke_executed",
        "juicity_h3_loopback_benchmark_recorded",
        "juicity_tls_verify_peer_certificate_hook_admitted",
        "juicity_tls_certchain_verification_admitted",
        "juicity_pinned_certchain_live_callback_matched",
        "juicity_h3_handshake_admitted",
        "juicity_native_optin_contract_admitted",
        "juicity_certchain_hash_algorithm_admitted",
        "juicity_pinned_certchain_url_base64_verify_vector_admitted",
        "juicity_pinned_certchain_std_base64_verify_vector_admitted",
        "juicity_pinned_certchain_hex_decode_caveat_recorded",
        "juicity_pinned_certchain_forces_insecure_verify_contract_admitted",
        "juicity_pinned_certchain_full_chain_hash_contract_admitted",
        "juicity_pinned_certchain_not_hysteria2_pin_sha256_recorded",
        "juicity_tls13_h3_alpn_config_contract_admitted",
        "juicity_underlay_contract_admitted",
        "juicity_udp_port_zero_dialauth_contract_recorded",
        "juicity_stream_packet_conn_contract_recorded",
        "juicity_dialauth_record_protocol_state_admitted",
        "juicity_udp_port_zero_transport_packet_conn_route_admitted",
        "juicity_stream_packet_conn_frame_admitted",
        "juicity_authenticate_header_layout_admitted",
        "juicity_auth_uni_stream_write_order_admitted",
        "juicity_dialauth_record_over_auth_stream_admitted",
        "juicity_live_auth_uni_stream_harness_admitted",
        "juicity_live_auth_uni_stream_write_order_admitted",
        "juicity_auth_token_live_ekm_admitted",
        "juicity_live_ekm_auth_header_admitted",
        "juicity_live_ekm_auth_stream_transcript_admitted",
        "hysteria2_udp_underlay_admitted",
        "tuic_udp_underlay_socket_admitted",
        "quic_h3_family_native_optin_contract_admitted",
        "anytls_true_dataplane_admitted",
        "protocol_outbound_partial_admitted",
        "outbound_quic_go_dependency_preserved",
        "external_outbound_required",
        "external_quic_go_required",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "juicity_send_authentication_lifecycle_admitted",
        "juicity_underlay_auth_channel_order_admitted",
        "juicity_multiple_dialauth_records_over_auth_stream_admitted",
        "juicity_auth_stream_finish_boundary_admitted",
        "juicity_dialauth_over_h3_admitted",
        "juicity_transport_packet_conn_dataplane_admitted",
        "juicity_stream_packet_conn_dataplane_admitted",
        "juicity_packet_over_stream_admitted",
        "juicity_congestion_behavior_admitted",
        "juicity_true_quic_h3_dataplane_admitted",
        "hysteria2_true_quic_dataplane_admitted",
        "tuic_true_quic_dataplane_admitted",
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
    report["auth_lifecycle"] = json!({
        "server_name": opts.server_name,
        "targets": opts.targets,
        "default_targets": juicity::DEFAULT_AUTH_LIFECYCLE_TARGETS,
        "alpn_protocol": juicity::DEFAULT_H3_ALPN,
        "client_selected_alpn": null,
        "server_selected_alpn": null,
        "ekm_label_len": juicity::JUICITY_AUTHENTICATE_UUID_LEN,
        "ekm_context_len": opts.password.len(),
        "ekm_token_len": juicity::JUICITY_AUTHENTICATE_TOKEN_LEN,
        "client_ekm_token_nonzero": false,
        "server_ekm_token_exported": false,
        "authenticate_header_len": juicity::JUICITY_AUTHENTICATE_HEADER_LEN,
        "record_count": opts.targets.len(),
        "default_record_count": juicity::DEFAULT_AUTH_LIFECYCLE_RECORD_COUNT,
        "dialauth_record_lens": null,
        "dialauth_metadata_offsets": null,
        "transcript_len": null,
        "auth_header_offset": 0,
        "first_dialauth_record_offset": juicity::JUICITY_AUTHENTICATE_HEADER_LEN,
        "last_dialauth_record_end": null,
        "underlay_auth_channel_capacity": 64,
        "channel_enqueue_count": 0,
        "channel_receive_count": 0,
        "channel_closed_after_records": false,
        "auth_header_written_first": false,
        "underlay_auth_channel_order_validated": false,
        "multiple_dialauth_records_over_auth_stream_validated": false,
        "open_uni_stream_count": 0,
        "uni_stream_finish_count": 0,
        "uni_stream_acked_count": 0,
        "server_received_count": 0,
        "server_received_len": null,
        "server_read_to_end_count": 0,
        "server_transcript_match_count": 0,
        "quic_handshake_validated": false,
        "auth_stream_finish_boundary_validated": false,
        "send_authentication_lifecycle_validated": false,
        "boundary": "read-only fixture records lifecycle inputs only; execute --execute-smoke to run local QUIC EKM auth header plus bounded UnderlayAuth channel writes"
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations": opts.benchmark_iters,
        "elapsed_ns": null,
        "ns_per_juicity_auth_lifecycle_exchange": null,
        "record_count": opts.targets.len(),
        "transcript_len": null,
        "server_received_len": null,
        "scope": "local QUIC TLS1.3+h3 ALPN sendAuthentication lifecycle model: live EKM Authenticate header plus bounded UnderlayAuth channel multi-record writes; not encrypted TransportPacketConn, stream relay, congestion, or default/product switching",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"] = json!({
        "hysteria2_udp_underlay_admitted": true,
        "hysteria2_true_quic_dataplane_admitted": false,
        "tuic_udp_underlay_socket_admitted": true,
        "tuic_true_quic_dataplane_admitted": false,
        "juicity_h3_handshake_admitted": true,
        "juicity_tls_certchain_verification_admitted": true,
        "juicity_auth_token_live_ekm_admitted": true,
        "juicity_live_ekm_auth_header_admitted": true,
        "juicity_live_ekm_auth_stream_transcript_admitted": true,
        "juicity_send_authentication_lifecycle_admitted": false,
        "juicity_underlay_auth_channel_order_admitted": false,
        "juicity_multiple_dialauth_records_over_auth_stream_admitted": false,
        "juicity_auth_stream_finish_boundary_admitted": false,
        "juicity_dialauth_over_h3_admitted": false,
        "juicity_transport_packet_conn_dataplane_admitted": false,
        "juicity_stream_packet_conn_dataplane_admitted": false,
        "juicity_true_quic_h3_dataplane_admitted": false,
        "quic_h3_family_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": true,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Juicity TransportPacketConn shadowsocks encryption/decryption with JuicityReusedInfo for UDP port 0",
        "Juicity stream_packet_conn packet-over-stream live relay for nonzero UDP targets",
        "Juicity congestion behavior and packet relay benchmark",
        "Hysteria2 full QUIC and TUIC true QUIC dataplanes",
        "outbound registry/dialer group/health policy parity while preserving direct/block indices and NewDialerSetFromLinks semantics",
        "matched Go default daemon vs true Rust candidate benchmark",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage124/juicity_auth_lifecycle_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage124_juicity_auth_lifecycle_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage124 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage124-juicity-auth-lifecycle-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage124-juicity-auth-lifecycle-admission --execute-smoke --benchmark-iters 5",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage124 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage124 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage123 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage124",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.16",
        "/root/project/outbound/protocol/juicity/client.go:sendAuthentication",
        "/root/project/outbound/protocol/juicity/client.go:DialAuth",
        "/root/project/outbound/protocol/tuic/protocol.go:GenToken",
        "rust/crates/dae-outbound/src/juicity/auth_lifecycle.rs",
        "rust/crates/dae-cli/src/runtime_stage124_juicity_auth_lifecycle_gate/"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    match juicity::run_auth_lifecycle_smoke(&juicity::JuicityAuthLifecycleOptions {
        server_name: opts.server_name.clone(),
        targets: opts.targets.clone(),
        password: opts.password.clone(),
        iterations: opts.benchmark_iters,
        timeout: opts.timeout,
    }) {
        Ok(outcome) => apply_stage124_outcome(&mut report, &outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([format!("{err}")]);
        }
    }
    report
}

fn apply_stage124_outcome(report: &mut Value, outcome: &juicity::JuicityAuthLifecycleReport) {
    let passed = outcome.juicity_send_authentication_lifecycle_admitted
        && outcome.juicity_underlay_auth_channel_order_admitted
        && outcome.juicity_multiple_dialauth_records_over_auth_stream_admitted
        && outcome.juicity_auth_stream_finish_boundary_admitted;
    report["read_only"] = json!(false);
    report["blocked"] = json!(!passed);
    report["blockers"] = if passed {
        json!([])
    } else {
        json!(["stage124 auth lifecycle smoke did not satisfy all admission checks"])
    };
    report["juicity_send_authentication_lifecycle_admitted"] =
        json!(outcome.juicity_send_authentication_lifecycle_admitted);
    report["juicity_underlay_auth_channel_order_admitted"] =
        json!(outcome.juicity_underlay_auth_channel_order_admitted);
    report["juicity_multiple_dialauth_records_over_auth_stream_admitted"] =
        json!(outcome.juicity_multiple_dialauth_records_over_auth_stream_admitted);
    report["juicity_auth_stream_finish_boundary_admitted"] =
        json!(outcome.juicity_auth_stream_finish_boundary_admitted);
    report["auth_lifecycle"] = json!({
        "server_name": outcome.server_name,
        "targets": outcome.targets,
        "default_targets": juicity::DEFAULT_AUTH_LIFECYCLE_TARGETS,
        "alpn_protocol": outcome.alpn_protocol,
        "client_selected_alpn": outcome.client_selected_alpn,
        "server_selected_alpn": outcome.server_selected_alpn,
        "ekm_label_len": outcome.ekm_label_len,
        "ekm_context_len": outcome.ekm_context_len,
        "ekm_token_len": outcome.ekm_token_len,
        "client_ekm_token_nonzero": outcome.client_ekm_token_nonzero,
        "server_ekm_token_exported": outcome.server_ekm_token_exported,
        "authenticate_header_len": outcome.authenticate_header_len,
        "record_count": outcome.record_count,
        "default_record_count": juicity::DEFAULT_AUTH_LIFECYCLE_RECORD_COUNT,
        "dialauth_record_lens": outcome.dialauth_record_lens,
        "dialauth_metadata_offsets": outcome.dialauth_metadata_offsets,
        "transcript_len": outcome.transcript_len,
        "auth_header_offset": outcome.auth_header_offset,
        "first_dialauth_record_offset": outcome.first_dialauth_record_offset,
        "last_dialauth_record_end": outcome.last_dialauth_record_end,
        "underlay_auth_channel_capacity": outcome.underlay_auth_channel_capacity,
        "channel_enqueue_count": outcome.channel_enqueue_count,
        "channel_receive_count": outcome.channel_receive_count,
        "channel_closed_after_records": outcome.channel_closed_after_records,
        "auth_header_written_first": outcome.auth_header_written_first,
        "underlay_auth_channel_order_validated": outcome.underlay_auth_channel_order_validated,
        "multiple_dialauth_records_over_auth_stream_validated": outcome.multiple_dialauth_records_over_auth_stream_validated,
        "open_uni_stream_count": outcome.open_uni_stream_count,
        "uni_stream_finish_count": outcome.uni_stream_finish_count,
        "uni_stream_acked_count": outcome.uni_stream_acked_count,
        "server_received_count": outcome.server_received_count,
        "server_received_len": outcome.server_received_len,
        "server_read_to_end_count": outcome.server_read_to_end_count,
        "server_transcript_match_count": outcome.server_transcript_match_count,
        "quic_handshake_validated": outcome.quic_handshake_validated,
        "auth_stream_finish_boundary_validated": outcome.auth_stream_finish_boundary_validated,
        "send_authentication_lifecycle_validated": outcome.send_authentication_lifecycle_validated,
        "boundary": "sendAuthentication lifecycle model is admitted for local QUIC EKM auth header plus bounded UnderlayAuth channel ordering; encrypted packet relay, stream relay, congestion, outbound/default/product remain closed"
    });
    report["benchmark"] = json!({
        "benchmark_recorded": passed,
        "iterations": outcome.iterations,
        "elapsed_ns": outcome.elapsed_ns,
        "ns_per_juicity_auth_lifecycle_exchange": outcome.ns_per_juicity_auth_lifecycle_exchange,
        "record_count": outcome.record_count,
        "transcript_len": outcome.transcript_len,
        "server_received_len": outcome.server_received_len,
        "scope": "local QUIC TLS1.3+h3 ALPN sendAuthentication lifecycle model: live EKM Authenticate header plus bounded UnderlayAuth channel multi-record writes; not encrypted TransportPacketConn, stream relay, congestion, or default/product switching",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"]["juicity_send_authentication_lifecycle_admitted"] =
        json!(outcome.juicity_send_authentication_lifecycle_admitted);
    report["protocol_matrix"]["juicity_underlay_auth_channel_order_admitted"] =
        json!(outcome.juicity_underlay_auth_channel_order_admitted);
    report["protocol_matrix"]["juicity_multiple_dialauth_records_over_auth_stream_admitted"] =
        json!(outcome.juicity_multiple_dialauth_records_over_auth_stream_admitted);
    report["protocol_matrix"]["juicity_auth_stream_finish_boundary_admitted"] =
        json!(outcome.juicity_auth_stream_finish_boundary_admitted);
}

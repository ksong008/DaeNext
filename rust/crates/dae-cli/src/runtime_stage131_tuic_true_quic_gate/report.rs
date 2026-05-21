use dae_outbound::tuic;
use serde_json::{Value, json};

use super::options::Stage131Options;

pub(super) fn stage131_report(opts: &Stage131Options) -> Value {
    let total_exchange_count = 1 + opts.dataplane.quic.datagram_iterations;
    let mut report = json!({
        "name": "stage131-tuic-true-quic-dataplane-admission",
        "stage": "stage131",
        "evidence_class": "tuic-true-quic-auth-datagram-dataplane",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": !opts.execute_smoke,
        "blockers": [
            "stage131 read-only fixture has not executed TUIC true QUIC auth/datagram dataplane smoke",
            "overall QUIC/H3 family, outbound default daemon, and product switching remain blocked",
            "external outbound/quic-go remains required"
        ],
        "tuic_native_optin_contract_admitted": true,
        "tuic_uuid_password_contract_admitted": true,
        "tuic_tls13_datagram_config_contract_admitted": true,
        "tuic_disable_sni_contract_admitted": true,
        "tuic_udp_relay_mode_go_parity_caveat_recorded": true,
        "tuic_underlay_contract_admitted": true,
        "tuic_udp_underlay_socket_admitted": true,
        "tuic_so_mark_loopback_observed": true,
        "tuic_full_quic_handshake_admitted": false,
        "tuic_auth_stream_admitted": false,
        "tuic_datagram_packet_relay_admitted": false,
        "tuic_congestion_behavior_admitted": false,
        "tuic_udp_relay_mode_quic_effective_relay_admitted": false,
        "tuic_true_quic_dataplane_admitted": false,
        "hysteria2_true_quic_dataplane_admitted": true,
        "juicity_true_quic_h3_dataplane_admitted": true,
        "quic_h3_family_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": true,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false,
        "default_path_mutation_allowed": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "outbound_quic_go_dependency_preserved": true,
        "external_outbound_required": true,
        "external_quic_go_required": true,
        "go_default_path_preserved": true,
        "go_fallback_required": true
    });
    let read_only_underlay = json!({
        "tcp_request": {
            "input_network": "tcp",
            "input_mark": opts.dataplane.underlay_mark,
            "input_mptcp": opts.dataplane.underlay_mptcp,
            "underlay_network": "udp",
            "underlay_mark": opts.dataplane.underlay_mark,
            "underlay_mptcp": false,
            "same_encoded_value": false
        },
        "udp_request": {
            "input_network": "udp",
            "input_mark": opts.dataplane.underlay_mark,
            "input_mptcp": opts.dataplane.underlay_mptcp,
            "underlay_network": "udp",
            "underlay_mark": opts.dataplane.underlay_mark,
            "underlay_mptcp": opts.dataplane.underlay_mptcp,
            "same_encoded_value": true
        },
        "tcp_underlay_uses_udp": true,
        "tcp_underlay_preserves_mark": true,
        "tcp_underlay_drops_mptcp": true,
        "udp_underlay_uses_original": true,
        "socket_so_mark_observation_required": true,
        "true_quic_dataplane_deferred": false
    });
    let read_only_quic = json!({
        "server_name": opts.dataplane.quic.server_name,
        "alpn_protocols": [tuic::DEFAULT_TUIC_ALPN],
        "tls13_only_configured": true,
        "quic_datagram_enabled": true,
        "keepalive_secs": tuic::DEFAULT_TUIC_KEEPALIVE_SECS,
        "handshake_idle_timeout_secs": tuic::DEFAULT_TUIC_HANDSHAKE_IDLE_TIMEOUT_SECS,
        "initial_stream_receive_window": tuic::DEFAULT_TUIC_INITIAL_STREAM_RECEIVE_WINDOW,
        "max_stream_receive_window": tuic::DEFAULT_TUIC_MAX_STREAM_RECEIVE_WINDOW,
        "initial_connection_receive_window": tuic::DEFAULT_TUIC_INITIAL_CONNECTION_RECEIVE_WINDOW,
        "max_connection_receive_window": tuic::DEFAULT_TUIC_MAX_CONNECTION_RECEIVE_WINDOW,
        "max_udp_relay_packet_size": tuic::DEFAULT_TUIC_MAX_UDP_RELAY_PACKET_SIZE,
        "datagram_iterations": opts.dataplane.quic.datagram_iterations,
        "total_exchange_count": total_exchange_count,
        "uuid_len": 16,
        "ekm_token_len": tuic::TUIC_AUTH_TOKEN_LEN,
        "authenticate_frame_len": tuic::TUIC_AUTHENTICATE_FRAME_LEN,
        "udp_target": opts.dataplane.quic.udp_target,
        "quic_handshake_validated": false,
        "auth_stream_validated": false,
        "datagram_packet_relay_validated": false,
        "congestion_behavior_recorded": false
    });
    report["tuic_dataplane"] = json!({
        "link": tuic::DEFAULT_TRUE_QUIC_LINK,
        "subscription_tag": opts.dataplane.subscription_tag,
        "property_name": "stage131-tuic",
        "property_protocol": "tuic",
        "property_address": "stage131.example:443",
        "chain_adapter_mode": "native-opt-in",
        "chain_parent_dialer_non_nil": true,
        "user": tuic::DEFAULT_TUIC_UUID,
        "uuid_validated": true,
        "password_present": true,
        "server": "stage131.example:443",
        "sni": "localhost",
        "allow_insecure": true,
        "disable_sni": false,
        "disable_sni_probe": {
            "sni": "",
            "allow_insecure": true
        },
        "congestion_control": "bbr",
        "alpn": [tuic::DEFAULT_TUIC_ALPN],
        "udp_relay_mode": "quic",
        "udp_relay_mode_quic_effective_relay_admitted": false,
        "underlay": read_only_underlay,
        "quic": read_only_quic,
        "tuic_true_quic_dataplane_admitted": false,
        "boundary": "read-only fixture records TUIC link/underlay/TLS/QUIC shape; execute --execute-smoke to run local TLS1.3 QUIC EKM auth stream and datagram packet relay"
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "datagram_iterations": opts.dataplane.quic.datagram_iterations,
        "total_exchange_count": total_exchange_count,
        "elapsed_ns": null,
        "ns_per_tuic_true_quic_exchange": null,
        "auth_stream_match_count": 0,
        "udp_datagram_match_count": 0,
        "packet_frame_len": null,
        "scope": "TUIC local TLS1.3 QUIC handshake, EKM authenticate uni stream, native datagram packet relay, underlay contract, and congestion controller field record; not udp_relay_mode=quic effective relay, overall outbound default daemon, product-chain switching, or matched Go benchmark",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"] = json!({
        "hysteria2_true_quic_dataplane_admitted": true,
        "tuic_true_quic_dataplane_admitted": false,
        "tuic_udp_relay_mode_quic_effective_relay_admitted": false,
        "juicity_true_quic_h3_dataplane_admitted": true,
        "quic_h3_family_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": true,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "overall QUIC/H3 family recertification after Hysteria2/TUIC/Juicity are all admitted with their caveats",
        "TUIC udp_relay_mode=quic effective relay remains blocked by daenew parity FIXME",
        "overall outbound true dataplane recertification across all protocols",
        "matched Go default daemon vs true Rust candidate benchmark",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage131/tuic_true_quic_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage131_tuic_true_quic_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage131 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage131-tuic-true-quic-dataplane-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage131-tuic-true-quic-dataplane-admission --execute-smoke",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage131 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage131 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage130 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage131",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.5-25.10",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.15",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "/root/project/outbound/dialer/tuic/tuic.go",
        "/root/project/outbound/protocol/tuic/client.go",
        "/root/project/outbound/protocol/tuic/dialer.go",
        "/root/project/outbound/protocol/tuic/protocol.go",
        "/root/project/outbound/protocol/tuic/packet.go",
        "/root/project/outbound/protocol/tuic/common/type.go",
        "rust/crates/dae-outbound/src/tuic/dataplane.rs",
        "rust/crates/dae-outbound/src/tuic/quic_loopback.rs",
        "rust/crates/dae-outbound/src/tuic/wire.rs",
        "rust/crates/dae-cli/src/runtime_stage131_tuic_true_quic_gate/"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    match tuic::run_true_quic_dataplane_smoke(&opts.dataplane) {
        Ok(outcome) => apply_stage131_outcome(&mut report, &outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([format!("{err}")]);
        }
    }
    report
}

fn apply_stage131_outcome(report: &mut Value, outcome: &tuic::TuicTrueQuicDataplaneReport) {
    let passed = outcome.tuic_true_quic_dataplane_admitted;
    report["read_only"] = json!(false);
    report["blocked"] = json!(!passed);
    report["blockers"] = if passed {
        json!([])
    } else {
        json!(["stage131 TUIC true QUIC dataplane smoke did not satisfy all admission checks"])
    };
    report["tuic_full_quic_handshake_admitted"] = json!(outcome.tuic_full_quic_handshake_admitted);
    report["tuic_auth_stream_admitted"] = json!(outcome.tuic_auth_stream_admitted);
    report["tuic_datagram_packet_relay_admitted"] =
        json!(outcome.tuic_datagram_packet_relay_admitted);
    report["tuic_congestion_behavior_admitted"] = json!(outcome.tuic_congestion_behavior_admitted);
    report["tuic_udp_relay_mode_quic_effective_relay_admitted"] =
        json!(outcome.tuic_udp_relay_mode_quic_effective_relay_admitted);
    report["tuic_true_quic_dataplane_admitted"] = json!(outcome.tuic_true_quic_dataplane_admitted);

    let mut underlay = json!({});
    underlay["tcp_request"] = json!({
        "input_network": outcome.underlay.tcp_request.input_network,
        "input_mark": outcome.underlay.tcp_request.input_mark,
        "input_mptcp": outcome.underlay.tcp_request.input_mptcp,
        "underlay_network": outcome.underlay.tcp_request.underlay_network,
        "underlay_mark": outcome.underlay.tcp_request.underlay_mark,
        "underlay_mptcp": outcome.underlay.tcp_request.underlay_mptcp,
        "same_encoded_value": outcome.underlay.tcp_request.same_encoded_value
    });
    underlay["udp_request"] = json!({
        "input_network": outcome.underlay.udp_request.input_network,
        "input_mark": outcome.underlay.udp_request.input_mark,
        "input_mptcp": outcome.underlay.udp_request.input_mptcp,
        "underlay_network": outcome.underlay.udp_request.underlay_network,
        "underlay_mark": outcome.underlay.udp_request.underlay_mark,
        "underlay_mptcp": outcome.underlay.udp_request.underlay_mptcp,
        "same_encoded_value": outcome.underlay.udp_request.same_encoded_value
    });
    underlay["tcp_underlay_uses_udp"] = json!(outcome.underlay.tcp_underlay_uses_udp);
    underlay["tcp_underlay_preserves_mark"] = json!(outcome.underlay.tcp_underlay_preserves_mark);
    underlay["tcp_underlay_drops_mptcp"] = json!(outcome.underlay.tcp_underlay_drops_mptcp);
    underlay["udp_underlay_uses_original"] = json!(outcome.underlay.udp_underlay_uses_original);
    underlay["socket_so_mark_observation_required"] =
        json!(outcome.underlay.socket_so_mark_observation_required);
    underlay["true_quic_dataplane_deferred"] = json!(false);

    let mut quic = json!({});
    quic["server_name"] = json!(outcome.quic.server_name);
    quic["alpn_protocols"] = json!(outcome.quic.alpn_protocols);
    quic["client_selected_alpn"] = json!(outcome.quic.client_selected_alpn);
    quic["server_selected_alpn"] = json!(outcome.quic.server_selected_alpn);
    quic["tls13_only_configured"] = json!(outcome.quic.tls13_only_configured);
    quic["quic_datagram_enabled"] = json!(outcome.quic.quic_datagram_enabled);
    quic["keepalive_secs"] = json!(outcome.quic.keepalive_secs);
    quic["handshake_idle_timeout_secs"] = json!(outcome.quic.handshake_idle_timeout_secs);
    quic["initial_stream_receive_window"] = json!(outcome.quic.initial_stream_receive_window);
    quic["max_stream_receive_window"] = json!(outcome.quic.max_stream_receive_window);
    quic["initial_connection_receive_window"] =
        json!(outcome.quic.initial_connection_receive_window);
    quic["max_connection_receive_window"] = json!(outcome.quic.max_connection_receive_window);
    quic["max_udp_relay_packet_size"] = json!(outcome.quic.max_udp_relay_packet_size);
    quic["loopback_addr"] = json!(outcome.quic.loopback_addr);
    quic["datagram_iterations"] = json!(outcome.quic.datagram_iterations);
    quic["total_exchange_count"] = json!(outcome.quic.total_exchange_count);
    quic["uuid_len"] = json!(outcome.quic.uuid_len);
    quic["password_len"] = json!(outcome.quic.password_len);
    quic["ekm_label_len"] = json!(outcome.quic.ekm_label_len);
    quic["ekm_context_len"] = json!(outcome.quic.ekm_context_len);
    quic["ekm_token_len"] = json!(outcome.quic.ekm_token_len);
    quic["client_ekm_token_nonzero"] = json!(outcome.quic.client_ekm_token_nonzero);
    quic["server_ekm_token_exported"] = json!(outcome.quic.server_ekm_token_exported);
    quic["authenticate_frame_len"] = json!(outcome.quic.authenticate_frame_len);
    quic["open_uni_stream_count"] = json!(outcome.quic.open_uni_stream_count);
    quic["uni_stream_finish_count"] = json!(outcome.quic.uni_stream_finish_count);
    quic["uni_stream_acked_count"] = json!(outcome.quic.uni_stream_acked_count);
    quic["server_auth_stream_count"] = json!(outcome.quic.server_auth_stream_count);
    quic["server_auth_match_count"] = json!(outcome.quic.server_auth_match_count);
    quic["udp_target"] = json!(outcome.quic.udp_target);
    quic["udp_payload_len"] = json!(outcome.quic.udp_payload_len);
    quic["udp_response_payload_len"] = json!(outcome.quic.udp_response_payload_len);
    quic["packet_frame_len"] = json!(outcome.quic.packet_frame_len);
    quic["response_packet_frame_len"] = json!(outcome.quic.response_packet_frame_len);
    quic["client_datagram_send_count"] = json!(outcome.quic.client_datagram_send_count);
    quic["server_datagram_receive_count"] = json!(outcome.quic.server_datagram_receive_count);
    quic["server_datagram_match_count"] = json!(outcome.quic.server_datagram_match_count);
    quic["server_datagram_send_count"] = json!(outcome.quic.server_datagram_send_count);
    quic["client_datagram_receive_count"] = json!(outcome.quic.client_datagram_receive_count);
    quic["client_datagram_match_count"] = json!(outcome.quic.client_datagram_match_count);
    quic["assoc_id"] = json!(outcome.quic.assoc_id);
    quic["congestion_control"] = json!(outcome.quic.congestion_control);
    quic["cwnd"] = json!(outcome.quic.cwnd);
    quic["quic_handshake_validated"] = json!(outcome.quic.quic_handshake_validated);
    quic["auth_stream_validated"] = json!(outcome.quic.auth_stream_validated);
    quic["datagram_packet_relay_validated"] = json!(outcome.quic.datagram_packet_relay_validated);
    quic["congestion_behavior_recorded"] = json!(outcome.quic.congestion_behavior_recorded);

    let mut dataplane = json!({});
    dataplane["link"] = json!(outcome.link);
    dataplane["subscription_tag"] = json!(outcome.subscription_tag);
    dataplane["property_name"] = json!(outcome.property_name);
    dataplane["property_protocol"] = json!(outcome.property_protocol);
    dataplane["property_address"] = json!(outcome.property_address);
    dataplane["chain_adapter_mode"] = json!(outcome.chain_adapter_mode);
    dataplane["chain_parent_dialer_non_nil"] = json!(outcome.chain_parent_dialer_non_nil);
    dataplane["user"] = json!(outcome.user);
    dataplane["uuid_validated"] = json!(outcome.uuid_validated);
    dataplane["password_present"] = json!(outcome.password_present);
    dataplane["server"] = json!(outcome.server);
    dataplane["sni"] = json!(outcome.sni);
    dataplane["allow_insecure"] = json!(outcome.allow_insecure);
    dataplane["disable_sni"] = json!(outcome.disable_sni);
    dataplane["disable_sni_probe"] = json!({
        "sni": outcome.disable_sni_probe_sni,
        "allow_insecure": outcome.disable_sni_probe_allow_insecure
    });
    dataplane["congestion_control"] = json!(outcome.congestion_control);
    dataplane["alpn"] = json!(outcome.alpn);
    dataplane["udp_relay_mode"] = json!(outcome.udp_relay_mode);
    dataplane["udp_relay_mode_quic_effective_relay_admitted"] =
        json!(outcome.tuic_udp_relay_mode_quic_effective_relay_admitted);
    dataplane["underlay"] = underlay;
    dataplane["quic"] = quic;
    dataplane["tuic_true_quic_dataplane_admitted"] =
        json!(outcome.tuic_true_quic_dataplane_admitted);
    dataplane["boundary"] = json!(
        "TUIC local TLS1.3 QUIC auth/datagram dataplane is admitted for protocol-specific Rust opt-in; udp_relay_mode=quic effective relay, QUIC-family-wide admission, outbound default daemon, and product switches remain closed"
    );
    report["tuic_dataplane"] = dataplane;
    report["benchmark"] = json!({
        "benchmark_recorded": passed,
        "datagram_iterations": outcome.quic.datagram_iterations,
        "total_exchange_count": outcome.quic.total_exchange_count,
        "elapsed_ns": outcome.total_elapsed_ns,
        "loopback_elapsed_ns": outcome.quic.elapsed_ns,
        "ns_per_tuic_true_quic_exchange": outcome.ns_per_tuic_true_quic_exchange,
        "ns_per_tuic_quic_exchange": outcome.quic.ns_per_tuic_quic_exchange,
        "auth_stream_match_count": outcome.quic.server_auth_match_count,
        "udp_datagram_match_count": outcome.quic.client_datagram_match_count,
        "packet_frame_len": outcome.quic.packet_frame_len,
        "response_packet_frame_len": outcome.quic.response_packet_frame_len,
        "client_ekm_token_nonzero": outcome.quic.client_ekm_token_nonzero,
        "scope": "TUIC local TLS1.3 QUIC handshake, EKM authenticate uni stream, native datagram packet relay, underlay contract, and congestion controller field record; not udp_relay_mode=quic effective relay, overall outbound default daemon, product-chain switching, or matched Go benchmark",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"]["tuic_true_quic_dataplane_admitted"] =
        json!(outcome.tuic_true_quic_dataplane_admitted);
}

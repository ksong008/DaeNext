use dae_outbound::hysteria2;
use serde_json::{Value, json};

use super::options::Stage130Options;

pub(super) fn stage130_report(opts: &Stage130Options) -> Value {
    let total_exchange_count =
        opts.dataplane.quic.stream_iterations + opts.dataplane.quic.datagram_iterations;
    let mut report = json!({
        "name": "stage130-hysteria2-true-quic-dataplane-admission",
        "stage": "stage130",
        "evidence_class": "hysteria2-true-quic-stream-datagram-port-hop-dataplane",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": !opts.execute_smoke,
        "blockers": [
            "stage130 read-only fixture has not executed Hysteria2 true QUIC stream/datagram dataplane smoke",
            "TUIC true QUIC dataplane remains blocked",
            "overall QUIC/H3 family, outbound default daemon, and product switching remain blocked",
            "external outbound/quic-go remains required"
        ],
        "hysteria2_native_optin_contract_admitted": true,
        "hysteria2_port_hopping_contract_admitted": true,
        "hysteria2_pin_sha256_raw_cert_hash_admitted": true,
        "hysteria2_udp_underlay_admitted": true,
        "hysteria2_full_quic_handshake_admitted": false,
        "hysteria2_stream_mux_admitted": false,
        "hysteria2_packet_datagram_admitted": false,
        "hysteria2_port_hopping_scheduler_admitted": false,
        "hysteria2_tcp_target_over_quic_admitted": false,
        "hysteria2_udp_target_over_quic_admitted": false,
        "hysteria2_true_quic_dataplane_admitted": false,
        "juicity_true_quic_h3_dataplane_admitted": true,
        "tuic_true_quic_dataplane_admitted": false,
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
    report["hysteria2_dataplane"] = json!({
        "link": hysteria2::DEFAULT_TRUE_QUIC_LINK,
        "subscription_tag": opts.dataplane.subscription_tag,
        "property_name": "stage130-hy2",
        "property_protocol": "hysteria2",
        "property_address": "stage130.example:443,8443-8444",
        "chain_adapter_mode": "native-opt-in",
        "chain_parent_dialer_non_nil": true,
        "user": "stage130-auth",
        "password_present": true,
        "server": "stage130.example:443,8443-8444",
        "sni": "localhost",
        "insecure": true,
        "max_tx": 1048576,
        "max_rx": 2097152,
        "underlay": {
            "input_network": "tcp",
            "underlay_network": "udp",
            "underlay_mark": opts.dataplane.underlay_mark,
            "underlay_mptcp_field": opts.dataplane.underlay_mptcp,
            "udp_mptcp_effective": false,
            "route_cache_key_network": "udp",
            "udp_hop_interval_ms": opts.dataplane.udp_hop_interval_ms
        },
        "port_hopping": {
            "host": "stage130.example",
            "port_expr": "443,8443-8444",
            "port_hopping": true,
            "normalized_ports": [443, 8443, 8444],
            "selected_ports": [443, 8443, 8444, 443],
            "selected_endpoints": [
                "stage130.example:443",
                "stage130.example:8443",
                "stage130.example:8444",
                "stage130.example:443"
            ],
            "udp_hop_interval_ms": opts.dataplane.udp_hop_interval_ms,
            "scheduler_admitted": false
        },
        "quic": {
            "server_name": opts.dataplane.quic.server_name,
            "alpn_protocol": hysteria2::DEFAULT_HYSTERIA2_ALPN,
            "tls13_only_configured": true,
            "quic_datagram_enabled": true,
            "keepalive_secs": hysteria2::DEFAULT_HYSTERIA2_KEEPALIVE_SECS,
            "max_idle_timeout_secs": hysteria2::DEFAULT_HYSTERIA2_MAX_IDLE_TIMEOUT_SECS,
            "stream_iterations": opts.dataplane.quic.stream_iterations,
            "datagram_iterations": opts.dataplane.quic.datagram_iterations,
            "total_exchange_count": total_exchange_count,
            "tcp_target": opts.dataplane.quic.tcp_target,
            "udp_target": opts.dataplane.quic.udp_target,
            "raw_cert_pin_matched": false,
            "quic_handshake_validated": false,
            "tcp_target_over_quic_validated": false,
            "udp_target_over_quic_datagram_validated": false
        },
        "hysteria2_true_quic_dataplane_admitted": false,
        "boundary": "read-only fixture records Hysteria2 link/underlay/port-hop/QUIC shape; execute --execute-smoke to run local TLS1.3 QUIC stream/datagram dataplane"
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "stream_iterations": opts.dataplane.quic.stream_iterations,
        "datagram_iterations": opts.dataplane.quic.datagram_iterations,
        "total_exchange_count": total_exchange_count,
        "elapsed_ns": null,
        "ns_per_hysteria2_true_quic_exchange": null,
        "tcp_response_match_count": 0,
        "udp_datagram_match_count": 0,
        "scope": "Hysteria2 local TLS1.3 QUIC handshake, raw cert pinSHA256 verifier, TCP target stream relay, UDP target QUIC datagram relay, and port hopping scheduler; not overall outbound default daemon, product-chain switching, or matched Go benchmark",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"] = json!({
        "hysteria2_udp_underlay_admitted": true,
        "hysteria2_true_quic_dataplane_admitted": false,
        "tuic_udp_underlay_socket_admitted": true,
        "tuic_true_quic_dataplane_admitted": false,
        "juicity_true_quic_h3_dataplane_admitted": true,
        "quic_h3_family_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": true,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "TUIC true QUIC dataplane",
        "overall QUIC/H3 family recertification after Hysteria2/TUIC/Juicity are all admitted",
        "overall outbound true dataplane recertification across all protocols",
        "matched Go default daemon vs true Rust candidate benchmark",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage130/hysteria2_true_quic_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage130_hysteria2_true_quic_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage130 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage130-hysteria2-true-quic-dataplane-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage130-hysteria2-true-quic-dataplane-admission --execute-smoke",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage130 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage130 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage129 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage130",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.5-25.10",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.14",
        "/root/project/outbound/dialer/hysteria2/hysteria2.go",
        "/root/project/outbound/protocol/hysteria2/client/client.go",
        "/root/project/outbound/protocol/hysteria2/internal/protocol/proxy.go",
        "/root/project/outbound/protocol/hysteria2/udphop/addr.go",
        "rust/crates/dae-outbound/src/hysteria2/dataplane.rs",
        "rust/crates/dae-outbound/src/hysteria2/quic_loopback.rs",
        "rust/crates/dae-outbound/src/hysteria2/port_hopping.rs",
        "rust/crates/dae-cli/src/runtime_stage130_hysteria2_true_quic_gate/"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    match hysteria2::run_true_quic_dataplane_smoke(&opts.dataplane) {
        Ok(outcome) => apply_stage130_outcome(&mut report, &outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([format!("{err}")]);
        }
    }
    report
}

fn apply_stage130_outcome(
    report: &mut Value,
    outcome: &hysteria2::Hysteria2TrueQuicDataplaneReport,
) {
    let passed = outcome.hysteria2_true_quic_dataplane_admitted;
    report["read_only"] = json!(false);
    report["blocked"] = json!(!passed);
    report["blockers"] = if passed {
        json!([])
    } else {
        json!(["stage130 Hysteria2 true QUIC dataplane smoke did not satisfy all admission checks"])
    };
    report["hysteria2_full_quic_handshake_admitted"] =
        json!(outcome.hysteria2_full_quic_handshake_admitted);
    report["hysteria2_stream_mux_admitted"] = json!(outcome.hysteria2_stream_mux_admitted);
    report["hysteria2_packet_datagram_admitted"] =
        json!(outcome.hysteria2_packet_datagram_admitted);
    report["hysteria2_port_hopping_scheduler_admitted"] =
        json!(outcome.hysteria2_port_hopping_scheduler_admitted);
    report["hysteria2_tcp_target_over_quic_admitted"] =
        json!(outcome.hysteria2_tcp_target_over_quic_admitted);
    report["hysteria2_udp_target_over_quic_admitted"] =
        json!(outcome.hysteria2_udp_target_over_quic_admitted);
    report["hysteria2_true_quic_dataplane_admitted"] =
        json!(outcome.hysteria2_true_quic_dataplane_admitted);

    let mut underlay = json!({});
    underlay["input_network"] = json!(outcome.underlay.input_network);
    underlay["underlay_network"] = json!(outcome.underlay.underlay_network);
    underlay["underlay_mark"] = json!(outcome.underlay.underlay_mark);
    underlay["underlay_mptcp_field"] = json!(outcome.underlay.underlay_mptcp_field);
    underlay["udp_mptcp_effective"] = json!(outcome.underlay.udp_mptcp_effective);
    underlay["route_cache_key_network"] = json!(outcome.underlay.route_cache_key_network);
    underlay["udp_hop_interval_ms"] = json!(outcome.underlay.udp_hop_interval_ms);

    let mut port_hopping = json!({});
    port_hopping["host"] = json!(outcome.port_hopping.host);
    port_hopping["port_expr"] = json!(outcome.port_hopping.port_expr);
    port_hopping["port_hopping"] = json!(outcome.port_hopping.port_hopping);
    port_hopping["normalized_ports"] = json!(outcome.port_hopping.normalized_ports);
    port_hopping["selected_ports"] = json!(outcome.port_hopping.selected_ports);
    port_hopping["selected_endpoints"] = json!(outcome.port_hopping.selected_endpoints);
    port_hopping["udp_hop_interval_ms"] = json!(outcome.port_hopping.udp_hop_interval_ms);
    port_hopping["scheduler_admitted"] = json!(outcome.port_hopping.scheduler_admitted);

    let mut quic = json!({});
    quic["server_name"] = json!(outcome.quic.server_name);
    quic["alpn_protocol"] = json!(outcome.quic.alpn_protocol);
    quic["client_selected_alpn"] = json!(outcome.quic.client_selected_alpn);
    quic["server_selected_alpn"] = json!(outcome.quic.server_selected_alpn);
    quic["tls13_only_configured"] = json!(outcome.quic.tls13_only_configured);
    quic["quic_datagram_enabled"] = json!(outcome.quic.quic_datagram_enabled);
    quic["keepalive_secs"] = json!(outcome.quic.keepalive_secs);
    quic["max_idle_timeout_secs"] = json!(outcome.quic.max_idle_timeout_secs);
    quic["loopback_addr"] = json!(outcome.quic.loopback_addr);
    quic["configured_pin_sha256_normalized"] = json!(outcome.quic.configured_pin_sha256_normalized);
    quic["raw_cert_sha256_hex"] = json!(outcome.quic.raw_cert_sha256_hex);
    quic["raw_cert_pin_matched"] = json!(outcome.quic.raw_cert_pin_matched);
    quic["certificate_callback_observed"] = json!(outcome.quic.certificate_callback_observed);
    quic["certificate_der_len"] = json!(outcome.quic.certificate_der_len);
    quic["stream_iterations"] = json!(outcome.quic.stream_iterations);
    quic["datagram_iterations"] = json!(outcome.quic.datagram_iterations);
    quic["total_exchange_count"] = json!(outcome.quic.total_exchange_count);
    quic["tcp_target"] = json!(outcome.quic.tcp_target);
    quic["tcp_payload_len"] = json!(outcome.quic.tcp_payload_len);
    quic["tcp_response_payload_len"] = json!(outcome.quic.tcp_response_payload_len);
    quic["tcp_request_frame_len"] = json!(outcome.quic.tcp_request_frame_len);
    quic["tcp_response_frame_len"] = json!(outcome.quic.tcp_response_frame_len);
    quic["open_bi_stream_count"] = json!(outcome.quic.open_bi_stream_count);
    quic["client_stream_finish_count"] = json!(outcome.quic.client_stream_finish_count);
    quic["client_stream_acked_count"] = json!(outcome.quic.client_stream_acked_count);
    quic["server_accept_bi_stream_count"] = json!(outcome.quic.server_accept_bi_stream_count);
    quic["server_tcp_request_read_count"] = json!(outcome.quic.server_tcp_request_read_count);
    quic["server_tcp_request_match_count"] = json!(outcome.quic.server_tcp_request_match_count);
    quic["server_tcp_response_write_count"] = json!(outcome.quic.server_tcp_response_write_count);
    quic["client_tcp_response_read_count"] = json!(outcome.quic.client_tcp_response_read_count);
    quic["client_tcp_response_match_count"] = json!(outcome.quic.client_tcp_response_match_count);
    quic["udp_target"] = json!(outcome.quic.udp_target);
    quic["udp_payload_len"] = json!(outcome.quic.udp_payload_len);
    quic["udp_response_payload_len"] = json!(outcome.quic.udp_response_payload_len);
    quic["udp_message_frame_len"] = json!(outcome.quic.udp_message_frame_len);
    quic["udp_response_frame_len"] = json!(outcome.quic.udp_response_frame_len);
    quic["client_datagram_send_count"] = json!(outcome.quic.client_datagram_send_count);
    quic["server_datagram_receive_count"] = json!(outcome.quic.server_datagram_receive_count);
    quic["server_datagram_match_count"] = json!(outcome.quic.server_datagram_match_count);
    quic["server_datagram_send_count"] = json!(outcome.quic.server_datagram_send_count);
    quic["client_datagram_receive_count"] = json!(outcome.quic.client_datagram_receive_count);
    quic["client_datagram_match_count"] = json!(outcome.quic.client_datagram_match_count);
    quic["quic_handshake_validated"] = json!(outcome.quic.quic_handshake_validated);
    quic["tcp_target_over_quic_validated"] = json!(outcome.quic.tcp_target_over_quic_validated);
    quic["udp_target_over_quic_datagram_validated"] =
        json!(outcome.quic.udp_target_over_quic_datagram_validated);

    let mut dataplane = json!({});
    dataplane["link"] = json!(outcome.link);
    dataplane["subscription_tag"] = json!(outcome.subscription_tag);
    dataplane["property_name"] = json!(outcome.property_name);
    dataplane["property_protocol"] = json!(outcome.property_protocol);
    dataplane["property_address"] = json!(outcome.property_address);
    dataplane["chain_adapter_mode"] = json!(outcome.chain_adapter_mode);
    dataplane["chain_parent_dialer_non_nil"] = json!(outcome.chain_parent_dialer_non_nil);
    dataplane["user"] = json!(outcome.user);
    dataplane["password_present"] = json!(outcome.password_present);
    dataplane["server"] = json!(outcome.server);
    dataplane["sni"] = json!(outcome.sni);
    dataplane["insecure"] = json!(outcome.insecure);
    dataplane["max_tx"] = json!(outcome.max_tx);
    dataplane["max_rx"] = json!(outcome.max_rx);
    dataplane["underlay"] = underlay;
    dataplane["port_hopping"] = port_hopping;
    dataplane["quic"] = quic;
    dataplane["hysteria2_true_quic_dataplane_admitted"] =
        json!(outcome.hysteria2_true_quic_dataplane_admitted);
    dataplane["boundary"] = json!(
        "Hysteria2 local TLS1.3 QUIC stream/datagram dataplane is admitted for protocol-specific Rust opt-in; TUIC, family-wide outbound, default daemon, and product switches remain closed"
    );
    report["hysteria2_dataplane"] = dataplane;
    report["benchmark"] = json!({
        "benchmark_recorded": passed,
        "stream_iterations": outcome.quic.stream_iterations,
        "datagram_iterations": outcome.quic.datagram_iterations,
        "total_exchange_count": outcome.quic.total_exchange_count,
        "elapsed_ns": outcome.total_elapsed_ns,
        "loopback_elapsed_ns": outcome.quic.elapsed_ns,
        "ns_per_hysteria2_true_quic_exchange": outcome.ns_per_hysteria2_true_quic_exchange,
        "ns_per_hysteria2_quic_exchange": outcome.quic.ns_per_hysteria2_quic_exchange,
        "tcp_response_match_count": outcome.quic.client_tcp_response_match_count,
        "udp_datagram_match_count": outcome.quic.client_datagram_match_count,
        "tcp_request_frame_len": outcome.quic.tcp_request_frame_len,
        "udp_message_frame_len": outcome.quic.udp_message_frame_len,
        "selected_port_count": outcome.port_hopping.selected_ports.len(),
        "raw_cert_pin_matched": outcome.quic.raw_cert_pin_matched,
        "scope": "Hysteria2 local TLS1.3 QUIC handshake, raw cert pinSHA256 verifier, TCP target stream relay, UDP target QUIC datagram relay, and port hopping scheduler; not overall outbound default daemon, product-chain switching, or matched Go benchmark",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"]["hysteria2_true_quic_dataplane_admitted"] =
        json!(outcome.hysteria2_true_quic_dataplane_admitted);
}

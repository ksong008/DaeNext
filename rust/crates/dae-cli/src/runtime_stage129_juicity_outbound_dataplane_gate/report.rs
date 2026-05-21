use dae_outbound::juicity;
use serde_json::{Value, json};

use super::options::Stage129Options;

pub(super) fn stage129_report(opts: &Stage129Options) -> Value {
    let client = &opts.outbound.client_integration;
    let total_exchange_count = client.auth_iterations
        + client.transport_iterations
        + client.stream_iterations
        + client.congestion_iterations;
    let selected_latency_ms = juicity::DEFAULT_OUTBOUND_DATAPLANE_HEALTH_LATENCIES_MS[1]
        + juicity::DEFAULT_OUTBOUND_DATAPLANE_ADD_LATENCY_MS[1];

    let mut report = json!({
        "name": "stage129-juicity-outbound-dataplane-admission",
        "stage": "stage129",
        "evidence_class": "juicity-outbound-registry-group-health-true-h3-dataplane",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": !opts.execute_smoke,
        "blockers": [
            "stage129 read-only fixture has not executed Juicity outbound registry/group/health dataplane smoke",
            "overall QUIC/H3 family, outbound default daemon, and product switching remain blocked",
            "external outbound/quic-go remains required"
        ],
        "juicity_client_integration_candidate_admitted": true,
        "juicity_full_local_client_smoke_admitted": true,
        "juicity_client_capability_matrix_admitted": true,
        "juicity_outbound_registry_admitted": false,
        "juicity_group_selection_admitted": false,
        "juicity_health_policy_admitted": false,
        "juicity_true_quic_h3_dataplane_admitted": false,
        "hysteria2_true_quic_dataplane_admitted": false,
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
        "go_fallback_required": true,
    });

    report["outbound_dataplane"] = json!({
        "group_name": opts.outbound.group_name,
        "subscription_tag": opts.outbound.subscription_tag,
        "policy": opts.outbound.selection_policy.as_str(),
        "network_type": juicity::network_type_label(opts.outbound.network_type),
        "raw_link_count": opts.outbound.links.len(),
        "valid_dialer_count": 2,
        "skipped_link_count": 1,
        "direct_index": 0,
        "block_index": 1,
        "first_user_group_index": 2,
        "direct_block_indices_preserved": true,
        "property_protocols": ["juicity", "juicity"],
        "property_addresses": ["slow.example:443", "fast.example:8443"],
        "property_names": ["stage129-slow", "stage129-fast"],
        "health_latencies_ms": opts.outbound.health_latencies_ms,
        "annotation_add_latency_ms": opts.outbound.annotation_add_latency_ms,
        "alive_count": 2,
        "selected_index": 1,
        "selected_latency_ms": selected_latency_ms,
        "selected_name": "stage129-fast",
        "selected_subscription_tag": opts.outbound.subscription_tag,
        "selected_address": "fast.example:8443",
        "selected_protocol": "juicity",
        "selected_pin_forces_insecure_verify": true,
        "selected_pin_decode_format": "hex",
        "selected_chain_adapter_mode": "native-opt-in",
        "selected_chain_parent_dialer_non_nil": true,
        "registry_shape_recorded": true,
        "group_selection_shape_recorded": true,
        "health_policy_shape_recorded": true,
        "juicity_outbound_registry_admitted": false,
        "juicity_group_selection_admitted": false,
        "juicity_health_policy_admitted": false,
        "juicity_true_quic_h3_dataplane_admitted": false,
        "boundary": "read-only fixture records registry/group/health shape; execute --execute-smoke to run selected Juicity client integration dataplane"
    });
    report["client_integration"] = json!({
        "auth_iterations": client.auth_iterations,
        "transport_iterations": client.transport_iterations,
        "stream_iterations": client.stream_iterations,
        "congestion_iterations": client.congestion_iterations,
        "max_in_flight_streams": client.max_in_flight_streams,
        "total_exchange_count": total_exchange_count,
        "transport_roundtrip_match_count": 0,
        "stream_response_match_count": 0,
        "congestion_response_match_count": 0,
        "total_elapsed_ns": null,
        "ns_per_juicity_client_integration_exchange": null
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "auth_iterations": client.auth_iterations,
        "transport_iterations": client.transport_iterations,
        "stream_iterations": client.stream_iterations,
        "congestion_iterations": client.congestion_iterations,
        "total_exchange_count": total_exchange_count,
        "elapsed_ns": null,
        "ns_per_juicity_outbound_dataplane_exchange": null,
        "selected_latency_ms": selected_latency_ms,
        "transport_roundtrip_match_count": 0,
        "stream_response_match_count": 0,
        "congestion_response_match_count": 0,
        "scope": "Juicity outbound registry/group/health selection plus selected local H3 client integration smoke; not overall outbound default daemon, product-chain switching, or matched Go benchmark",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"] = json!({
        "hysteria2_udp_underlay_admitted": true,
        "hysteria2_true_quic_dataplane_admitted": false,
        "tuic_udp_underlay_socket_admitted": true,
        "tuic_true_quic_dataplane_admitted": false,
        "juicity_client_integration_candidate_admitted": true,
        "juicity_outbound_registry_admitted": false,
        "juicity_group_selection_admitted": false,
        "juicity_health_policy_admitted": false,
        "juicity_true_quic_h3_dataplane_admitted": false,
        "quic_h3_family_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": true,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Hysteria2 full QUIC and TUIC true QUIC dataplanes",
        "overall outbound true dataplane recertification across all protocols",
        "matched Go default daemon vs true Rust candidate benchmark",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage129/juicity_outbound_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage129_juicity_outbound_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage129 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage129-juicity-outbound-dataplane-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage129-juicity-outbound-dataplane-admission --execute-smoke",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage129 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage129 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage128 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage129",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.5-25.10",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.16",
        "/root/project/outbound/dialer/juicity/juicity.go",
        "/root/project/outbound/protocol/juicity/client.go",
        "rust/crates/dae-outbound/src/group.rs",
        "rust/crates/dae-outbound/src/alive.rs",
        "rust/crates/dae-outbound/src/juicity/outbound_dataplane.rs",
        "rust/crates/dae-cli/src/runtime_stage129_juicity_outbound_dataplane_gate/"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    match juicity::run_outbound_dataplane_smoke(&opts.outbound) {
        Ok(outcome) => apply_stage129_outcome(&mut report, &outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([format!("{err}")]);
        }
    }
    report
}

fn apply_stage129_outcome(report: &mut Value, outcome: &juicity::JuicityOutboundDataplaneReport) {
    let passed = outcome.juicity_outbound_registry_admitted
        && outcome.juicity_group_selection_admitted
        && outcome.juicity_health_policy_admitted
        && outcome.juicity_true_quic_h3_dataplane_admitted;
    report["read_only"] = json!(false);
    report["blocked"] = json!(!passed);
    report["blockers"] = if passed {
        json!([])
    } else {
        json!(["stage129 Juicity outbound dataplane smoke did not satisfy all admission checks"])
    };
    report["juicity_outbound_registry_admitted"] =
        json!(outcome.juicity_outbound_registry_admitted);
    report["juicity_group_selection_admitted"] = json!(outcome.juicity_group_selection_admitted);
    report["juicity_health_policy_admitted"] = json!(outcome.juicity_health_policy_admitted);
    report["juicity_true_quic_h3_dataplane_admitted"] =
        json!(outcome.juicity_true_quic_h3_dataplane_admitted);

    report["outbound_dataplane"] = json!({
        "group_name": outcome.group_name,
        "subscription_tag": outcome.subscription_tag,
        "policy": outcome.policy,
        "network_type": outcome.network_type,
        "raw_link_count": outcome.raw_link_count,
        "valid_dialer_count": outcome.valid_dialer_count,
        "skipped_link_count": outcome.skipped_link_count,
        "skipped_link_errors": outcome.skipped_link_errors,
        "direct_index": outcome.direct_index,
        "block_index": outcome.block_index,
        "first_user_group_index": outcome.first_user_group_index,
        "direct_block_indices_preserved": outcome.direct_block_indices_preserved,
        "property_protocols": outcome.property_protocols,
        "property_addresses": outcome.property_addresses,
        "property_names": outcome.property_names,
        "health_latencies_ms": outcome.health_latencies_ms,
        "annotation_add_latency_ms": outcome.annotation_add_latency_ms,
        "alive_count": outcome.alive_count,
        "selected_index": outcome.selected_index,
        "selected_latency_ms": outcome.selected_latency_ms,
        "selected_name": outcome.selected_name,
        "selected_subscription_tag": outcome.selected_subscription_tag,
        "selected_address": outcome.selected_address,
        "selected_protocol": outcome.selected_protocol,
        "selected_link": outcome.selected_link,
        "selected_pin_forces_insecure_verify": outcome.selected_pin_forces_insecure_verify,
        "selected_pin_decode_format": outcome.selected_pin_decode_format,
        "selected_chain_adapter_mode": outcome.selected_chain_adapter_mode,
        "selected_chain_parent_dialer_non_nil": outcome.selected_chain_parent_dialer_non_nil,
        "juicity_outbound_registry_admitted": outcome.juicity_outbound_registry_admitted,
        "juicity_group_selection_admitted": outcome.juicity_group_selection_admitted,
        "juicity_health_policy_admitted": outcome.juicity_health_policy_admitted,
        "juicity_true_quic_h3_dataplane_admitted": outcome.juicity_true_quic_h3_dataplane_admitted,
        "boundary": "selected Juicity dialer has passed registry/group/health selection and local H3 client integration; overall outbound/default/product switches remain closed"
    });
    report["client_integration"] = json!({
        "auth_iterations": outcome.client_integration.auth_iterations,
        "transport_iterations": outcome.client_integration.transport_iterations,
        "stream_iterations": outcome.client_integration.stream_iterations,
        "congestion_iterations": outcome.client_integration.congestion_iterations,
        "max_in_flight_streams": outcome.client_integration.max_in_flight_streams,
        "total_exchange_count": outcome.client_integration.total_exchange_count,
        "transport_roundtrip_match_count": outcome.client_integration.transport_roundtrip_match_count,
        "stream_response_match_count": outcome.client_integration.stream_response_match_count,
        "congestion_response_match_count": outcome.client_integration.congestion_response_match_count,
        "total_elapsed_ns": outcome.client_integration.total_elapsed_ns,
        "ns_per_juicity_client_integration_exchange": outcome.client_integration.ns_per_juicity_client_integration_exchange,
        "congestion_client_cwnd_bytes": outcome.client_integration.congestion_client_cwnd_bytes,
        "congestion_server_cwnd_bytes": outcome.client_integration.congestion_server_cwnd_bytes
    });
    report["benchmark"] = json!({
        "benchmark_recorded": passed,
        "auth_iterations": outcome.client_integration.auth_iterations,
        "transport_iterations": outcome.client_integration.transport_iterations,
        "stream_iterations": outcome.client_integration.stream_iterations,
        "congestion_iterations": outcome.client_integration.congestion_iterations,
        "total_exchange_count": outcome.client_integration.total_exchange_count,
        "elapsed_ns": outcome.total_elapsed_ns,
        "ns_per_juicity_outbound_dataplane_exchange": outcome.ns_per_juicity_outbound_dataplane_exchange,
        "selected_latency_ms": outcome.selected_latency_ms,
        "transport_roundtrip_match_count": outcome.client_integration.transport_roundtrip_match_count,
        "stream_response_match_count": outcome.client_integration.stream_response_match_count,
        "congestion_response_match_count": outcome.client_integration.congestion_response_match_count,
        "scope": "Juicity outbound registry/group/health selection plus selected local H3 client integration smoke; not overall outbound default daemon, product-chain switching, or matched Go benchmark",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"]["juicity_outbound_registry_admitted"] =
        json!(outcome.juicity_outbound_registry_admitted);
    report["protocol_matrix"]["juicity_group_selection_admitted"] =
        json!(outcome.juicity_group_selection_admitted);
    report["protocol_matrix"]["juicity_health_policy_admitted"] =
        json!(outcome.juicity_health_policy_admitted);
    report["protocol_matrix"]["juicity_true_quic_h3_dataplane_admitted"] =
        json!(outcome.juicity_true_quic_h3_dataplane_admitted);
}

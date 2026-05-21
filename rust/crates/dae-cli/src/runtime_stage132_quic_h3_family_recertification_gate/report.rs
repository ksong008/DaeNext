use std::time::Instant;

use dae_outbound::{hysteria2, juicity, tuic};
use serde_json::{Value, json};

use super::options::Stage132Options;

pub(super) fn stage132_report(opts: &Stage132Options) -> Value {
    let mut report = base_stage132_report(opts);
    if !opts.execute_smoke {
        return report;
    }
    match run_family_smoke(opts) {
        Ok(outcome) => apply_stage132_outcome(&mut report, &outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([format!("{err}")]);
        }
    }
    report
}

fn base_stage132_report(opts: &Stage132Options) -> Value {
    let hysteria2_exchanges =
        opts.hysteria2.quic.stream_iterations + opts.hysteria2.quic.datagram_iterations;
    let tuic_exchanges = 1 + opts.tuic.quic.datagram_iterations;
    let juicity_exchanges = opts.juicity.client_integration.auth_iterations
        + opts.juicity.client_integration.transport_iterations
        + opts.juicity.client_integration.stream_iterations
        + opts.juicity.client_integration.congestion_iterations;
    let total_exchanges = hysteria2_exchanges + tuic_exchanges + juicity_exchanges;

    let mut report = json!({
        "name": "stage132-quic-h3-family-recertification-admission",
        "stage": "stage132",
        "evidence_class": "quic-h3-family-true-dataplane-recertification",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": !opts.execute_smoke,
        "blockers": [
            "stage132 read-only fixture has not executed Hysteria2, TUIC, and Juicity family smoke",
            "overall outbound default daemon and product switching remain blocked",
            "external outbound/quic-go remains required"
        ],
        "quic_h3_family_native_optin_contract_admitted": true,
        "hysteria2_true_quic_dataplane_admitted": true,
        "tuic_true_quic_dataplane_admitted": true,
        "tuic_udp_relay_mode_quic_effective_relay_admitted": false,
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
    report["family_matrix"] = json!({
        "hysteria2": {
            "stage": "stage130",
            "true_dataplane_admitted": true,
            "default_exchange_count": hysteria2_exchanges,
            "scope": "TLS1.3 h3 QUIC stream/datagram target relay, raw cert pinSHA256, and port hopping scheduler"
        },
        "tuic": {
            "stage": "stage131",
            "true_dataplane_admitted": true,
            "udp_relay_mode_quic_effective_relay_admitted": false,
            "default_exchange_count": tuic_exchanges,
            "scope": "TLS1.3 h3 QUIC EKM auth stream and native datagram packet relay; effective QUIC relay remains blocked by Go parity FIXME"
        },
        "juicity": {
            "stage": "stage129",
            "true_h3_dataplane_admitted": true,
            "default_exchange_count": juicity_exchanges,
            "scope": "outbound registry/group/health selection plus selected TLS1.3 h3 client integration smoke"
        },
        "family_default_exchange_count": total_exchanges,
        "quic_h3_family_true_dataplane_admitted": false
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "hysteria2_exchange_count": hysteria2_exchanges,
        "tuic_exchange_count": tuic_exchanges,
        "juicity_exchange_count": juicity_exchanges,
        "family_total_exchange_count": total_exchanges,
        "family_elapsed_ns": null,
        "ns_per_quic_h3_family_exchange": null,
        "scope": "Stage132 executes and aggregates protocol-specific local Hysteria2, TUIC, and Juicity true QUIC/H3 smokes; not overall outbound default daemon, product-chain switching, or matched Go benchmark",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"] = json!({
        "hysteria2_true_quic_dataplane_admitted": true,
        "tuic_true_quic_dataplane_admitted": true,
        "tuic_udp_relay_mode_quic_effective_relay_admitted": false,
        "juicity_true_quic_h3_dataplane_admitted": true,
        "quic_h3_family_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": true,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "overall outbound true dataplane recertification across all protocols",
        "matched Go default daemon vs true Rust candidate benchmark",
        "default daemon switch admission",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage132/quic_h3_family_recertification_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage132_quic_h3_family_recertification_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage132-quic-h3-family-recertification-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage132-quic-h3-family-recertification-admission --execute-smoke",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage132 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage132 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage131 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage132",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.5-25.10",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.14",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.15",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.16",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.20",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "rust/crates/dae-cli/src/runtime_stage132_quic_h3_family_recertification_gate/",
        "rust/crates/dae-outbound/src/hysteria2/dataplane.rs",
        "rust/crates/dae-outbound/src/tuic/dataplane.rs",
        "rust/crates/dae-outbound/src/juicity/outbound_dataplane.rs"
    ]);
    report
}

#[derive(Debug)]
struct Stage132FamilyOutcome {
    hysteria2: hysteria2::Hysteria2TrueQuicDataplaneReport,
    tuic: tuic::TuicTrueQuicDataplaneReport,
    juicity: juicity::JuicityOutboundDataplaneReport,
    family_elapsed_ns: u128,
}

fn run_family_smoke(
    opts: &Stage132Options,
) -> Result<Stage132FamilyOutcome, dae_outbound::OutboundError> {
    let start = Instant::now();
    let hysteria2 = hysteria2::run_true_quic_dataplane_smoke(&opts.hysteria2)?;
    let tuic = tuic::run_true_quic_dataplane_smoke(&opts.tuic)?;
    let juicity = juicity::run_outbound_dataplane_smoke(&opts.juicity)?;
    Ok(Stage132FamilyOutcome {
        hysteria2,
        tuic,
        juicity,
        family_elapsed_ns: start.elapsed().as_nanos(),
    })
}

fn apply_stage132_outcome(report: &mut Value, outcome: &Stage132FamilyOutcome) {
    let tuic_effective_relay = outcome
        .tuic
        .tuic_udp_relay_mode_quic_effective_relay_admitted;
    let family_admitted = outcome.hysteria2.hysteria2_true_quic_dataplane_admitted
        && outcome.tuic.tuic_true_quic_dataplane_admitted
        && !tuic_effective_relay
        && outcome.juicity.juicity_true_quic_h3_dataplane_admitted;
    let hysteria2_exchanges = outcome.hysteria2.quic.total_exchange_count;
    let tuic_exchanges = outcome.tuic.quic.total_exchange_count;
    let juicity_exchanges = outcome.juicity.client_integration.total_exchange_count;
    let family_total_exchanges = hysteria2_exchanges + tuic_exchanges + juicity_exchanges;

    report["read_only"] = json!(false);
    report["blocked"] = json!(!family_admitted);
    report["blockers"] = if family_admitted {
        json!([])
    } else {
        json!(["stage132 QUIC/H3 family smoke did not satisfy all protocol admission checks"])
    };
    report["hysteria2_true_quic_dataplane_admitted"] =
        json!(outcome.hysteria2.hysteria2_true_quic_dataplane_admitted);
    report["tuic_true_quic_dataplane_admitted"] =
        json!(outcome.tuic.tuic_true_quic_dataplane_admitted);
    report["tuic_udp_relay_mode_quic_effective_relay_admitted"] = json!(tuic_effective_relay);
    report["juicity_true_quic_h3_dataplane_admitted"] =
        json!(outcome.juicity.juicity_true_quic_h3_dataplane_admitted);
    report["quic_h3_family_true_dataplane_admitted"] = json!(family_admitted);
    report["family_matrix"]["hysteria2"]["true_dataplane_admitted"] =
        json!(outcome.hysteria2.hysteria2_true_quic_dataplane_admitted);
    report["family_matrix"]["hysteria2"]["elapsed_ns"] = json!(outcome.hysteria2.total_elapsed_ns);
    report["family_matrix"]["hysteria2"]["ns_per_exchange"] =
        json!(outcome.hysteria2.ns_per_hysteria2_true_quic_exchange);
    report["family_matrix"]["tuic"]["true_dataplane_admitted"] =
        json!(outcome.tuic.tuic_true_quic_dataplane_admitted);
    report["family_matrix"]["tuic"]["udp_relay_mode_quic_effective_relay_admitted"] =
        json!(tuic_effective_relay);
    report["family_matrix"]["tuic"]["elapsed_ns"] = json!(outcome.tuic.total_elapsed_ns);
    report["family_matrix"]["tuic"]["ns_per_exchange"] =
        json!(outcome.tuic.ns_per_tuic_true_quic_exchange);
    report["family_matrix"]["juicity"]["true_h3_dataplane_admitted"] =
        json!(outcome.juicity.juicity_true_quic_h3_dataplane_admitted);
    report["family_matrix"]["juicity"]["elapsed_ns"] = json!(outcome.juicity.total_elapsed_ns);
    report["family_matrix"]["juicity"]["ns_per_exchange"] =
        json!(outcome.juicity.ns_per_juicity_outbound_dataplane_exchange);
    report["family_matrix"]["family_default_exchange_count"] = json!(family_total_exchanges);
    report["family_matrix"]["quic_h3_family_true_dataplane_admitted"] = json!(family_admitted);
    report["benchmark"] = json!({
        "benchmark_recorded": family_admitted,
        "hysteria2_exchange_count": hysteria2_exchanges,
        "hysteria2_elapsed_ns": outcome.hysteria2.total_elapsed_ns,
        "hysteria2_ns_per_exchange": outcome.hysteria2.ns_per_hysteria2_true_quic_exchange,
        "tuic_exchange_count": tuic_exchanges,
        "tuic_elapsed_ns": outcome.tuic.total_elapsed_ns,
        "tuic_ns_per_exchange": outcome.tuic.ns_per_tuic_true_quic_exchange,
        "tuic_udp_relay_mode_quic_effective_relay_admitted": tuic_effective_relay,
        "juicity_exchange_count": juicity_exchanges,
        "juicity_elapsed_ns": outcome.juicity.total_elapsed_ns,
        "juicity_ns_per_exchange": outcome.juicity.ns_per_juicity_outbound_dataplane_exchange,
        "family_total_exchange_count": family_total_exchanges,
        "family_elapsed_ns": outcome.family_elapsed_ns,
        "ns_per_quic_h3_family_exchange": outcome.family_elapsed_ns as f64 / family_total_exchanges.max(1) as f64,
        "scope": "Stage132 executes and aggregates protocol-specific local Hysteria2, TUIC, and Juicity true QUIC/H3 smokes; not overall outbound default daemon, product-chain switching, or matched Go benchmark",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"]["quic_h3_family_true_dataplane_admitted"] = json!(family_admitted);
}

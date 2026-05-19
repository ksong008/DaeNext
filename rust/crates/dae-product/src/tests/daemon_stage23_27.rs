use super::*;

#[test]
fn stage23_completion_gate_contract_matches_golden_fixture() {
    let fixture = load("product/integration/stage23_completion_gate.json");
    let contract = stage23_completion_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.repo_local_scope_complete,
        fixture["repo_local_scope_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.default_switch_allowed,
        fixture["default_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.default_path_mutation_allowed,
        fixture["default_path_mutation_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.product_chain_switch_allowed,
        fixture["product_chain_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.go_default_path_preserved,
        fixture["go_default_path_preserved"].as_bool().unwrap()
    );
    assert_eq!(
        contract.go_fallback_required,
        fixture["go_fallback_required"].as_bool().unwrap()
    );
    assert_eq!(
        contract.true_default_daemon_gate_complete,
        fixture["true_default_daemon_gate_complete"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.true_rust_default_daemon_admitted,
        fixture["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.stage24_required,
        fixture["stage24_required"].as_bool().unwrap()
    );
    assert_eq!(
        contract.completion_decision,
        fixture["completion_decision"].as_str().unwrap()
    );

    let row_fixtures = fixture["completion_rows"].as_array().unwrap();
    assert_eq!(contract.completion_rows.len(), row_fixtures.len());
    for (row, row_fixture) in contract.completion_rows.iter().zip(row_fixtures) {
        assert_eq!(row.area, row_fixture["area"].as_str().unwrap());
        assert_eq!(row.status, row_fixture["status"].as_str().unwrap());
        assert_eq!(row.evidence, row_fixture["evidence"].as_str().unwrap());
        assert_eq!(row.boundary, row_fixture["boundary"].as_str().unwrap());
        assert_eq!(
            row.next_action,
            row_fixture["next_action"].as_str().unwrap()
        );
    }

    assert_string_vec(&contract.carried_blockers, &fixture["carried_blockers"]);
    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.source, &fixture["source"]);
}

#[test]
fn stage23_completion_gate_keeps_defaults_blocked_for_stage24() {
    let contract = stage23_completion_contract();
    assert!(contract.stage_complete);
    assert!(contract.repo_local_scope_complete);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);
    assert!(contract.true_default_daemon_gate_complete);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.stage24_required);

    assert_contains_text(
        &contract.carried_blockers,
        "true Rust default daemon binary",
    );
    assert_contains_text(
        &contract.carried_blockers,
        "Go default daemon vs true Rust default daemon benchmark",
    );
    assert_contains_text(&contract.carried_blockers, "outbound protocols");
    assert_contains_text(&contract.carried_blockers, "dae-wing and daed");
    assert_contains_text(&contract.carried_blockers, "release/install defaults");
}

#[test]
fn stage23_completion_gate_covers_required_surfaces() {
    let contract = stage23_completion_contract();
    let areas = contract
        .completion_rows
        .iter()
        .map(|row| row.area)
        .collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "release workflow and package metadata",
            "package and systemd isolated smoke",
            "version, validate, and export outline",
            "asset and geodata lookup",
            "trace diagnostics",
            "sysdump diagnostics",
            "trace and sysdump benchmark record",
            "true Rust default daemon admission",
            "fallback and default path boundary",
            "dae-wing and daed handoff",
        ]
    );

    assert_contains_text(&contract.validation_commands, "stage23_completion");
    assert_contains_text(&contract.validation_commands, "go test ./common/assets");
    assert_contains_text(&contract.validation_commands, "dae-trace -p dae-sysdump");
    assert_contains_text(&contract.validation_commands, "make dae");
    assert_contains_text(
        &contract.source,
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:33.9",
    );
}

#[test]
fn stage24_product_gate_contract_matches_golden_fixture() {
    let fixture = load("product/integration/stage24_product_gate.json");
    let contract = stage24_product_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.cross_repo_validation_complete,
        fixture["cross_repo_validation_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.dae_wing_validation_passed,
        fixture["dae_wing_validation_passed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.daed_wing_validation_passed,
        fixture["daed_wing_validation_passed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.daed_web_validation_passed,
        fixture["daed_web_validation_passed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.final_100_percent_admitted,
        fixture["final_100_percent_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.default_switch_allowed,
        fixture["default_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.product_chain_switch_allowed,
        fixture["product_chain_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.true_rust_default_daemon_admitted,
        fixture["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.go_default_path_preserved,
        fixture["go_default_path_preserved"].as_bool().unwrap()
    );
    assert_eq!(
        contract.go_fallback_required,
        fixture["go_fallback_required"].as_bool().unwrap()
    );
    assert_eq!(
        contract.stage24_decision,
        fixture["stage24_decision"].as_str().unwrap()
    );

    let row_fixtures = fixture["product_rows"].as_array().unwrap();
    assert_eq!(contract.product_rows.len(), row_fixtures.len());
    for (row, row_fixture) in contract.product_rows.iter().zip(row_fixtures) {
        assert_eq!(row.area, row_fixture["area"].as_str().unwrap());
        assert_eq!(row.repo, row_fixture["repo"].as_str().unwrap());
        assert_eq!(row.status, row_fixture["status"].as_str().unwrap());
        assert_eq!(row.evidence, row_fixture["evidence"].as_str().unwrap());
        assert_eq!(row.boundary, row_fixture["boundary"].as_str().unwrap());
        assert_eq!(
            row.next_action,
            row_fixture["next_action"].as_str().unwrap()
        );
    }

    assert_string_vec(&contract.carried_blockers, &fixture["carried_blockers"]);
    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.source, &fixture["source"]);
}

#[test]
fn stage24_product_gate_blocks_final_default_rollout() {
    let contract = stage24_product_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.cross_repo_validation_complete);
    assert!(contract.dae_wing_validation_passed);
    assert!(contract.daed_wing_validation_passed);
    assert!(contract.daed_web_validation_passed);
    assert!(!contract.final_100_percent_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "true Rust default daemon");
    assert_contains_text(
        &contract.carried_blockers,
        "Go default daemon vs true Rust default daemon benchmark",
    );
    assert_contains_text(&contract.carried_blockers, "outbound protocols");
    assert_contains_text(&contract.carried_blockers, "temporary modfile");
    assert_contains_text(&contract.carried_blockers, "dirty wing submodule");
    assert_contains_text(&contract.carried_blockers, "Node.js");
}

#[test]
fn stage24_product_gate_covers_cross_repo_surfaces() {
    let contract = stage24_product_gate_contract();
    let areas = contract
        .product_rows
        .iter()
        .map(|row| row.area)
        .collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "dae-wing engine facade and service ports",
            "dae-wing route-aware subscription and lifecycle",
            "daed wing runtime API chain",
            "daed Web runtime and import-export surface",
            "bundle and dae config file import-export",
            "true Rust default daemon rollout",
            "final 100 percent daenew parity",
        ]
    );

    assert_contains_text(&contract.validation_commands, "stage24_product_gate");
    assert_contains_text(&contract.validation_commands, "dae-wing-stage24-go.mod");
    assert_contains_text(&contract.validation_commands, "pnpm check-types");
    assert_contains_text(&contract.validation_commands, "pnpm test");
    assert_contains_text(
        &contract.source,
        "/root/project/dae-wing/transport/httpapi/service_port.go",
    );
    assert_contains_text(
        &contract.source,
        "/root/project/daed/wing/transport/httpapi/openapi.go",
    );
}

#[test]
fn stage25_true_daemon_execution_queue_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage25_true_daemon_execution_queue.json");
    let contract = stage25_true_daemon_execution_queue_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.queue_complete,
        fixture["queue_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.implementation_ready,
        fixture["implementation_ready"].as_bool().unwrap()
    );
    assert_eq!(
        contract.default_switch_allowed,
        fixture["default_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.default_path_mutation_allowed,
        fixture["default_path_mutation_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.product_chain_switch_allowed,
        fixture["product_chain_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.true_rust_default_daemon_admitted,
        fixture["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.go_default_path_preserved,
        fixture["go_default_path_preserved"].as_bool().unwrap()
    );
    assert_eq!(
        contract.go_fallback_required,
        fixture["go_fallback_required"].as_bool().unwrap()
    );
    assert_eq!(
        contract.benchmark_required_before_admission,
        fixture["benchmark_required_before_admission"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.outbound_true_dataplane_required,
        fixture["outbound_true_dataplane_required"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.clean_product_chain_required,
        fixture["clean_product_chain_required"].as_bool().unwrap()
    );
    assert_eq!(
        contract.execution_decision,
        fixture["execution_decision"].as_str().unwrap()
    );

    let row_fixtures = fixture["queue_rows"].as_array().unwrap();
    assert_eq!(contract.queue_rows.len(), row_fixtures.len());
    for (row, row_fixture) in contract.queue_rows.iter().zip(row_fixtures) {
        assert_eq!(row.area, row_fixture["area"].as_str().unwrap());
        assert_eq!(row.status, row_fixture["status"].as_str().unwrap());
        assert_eq!(
            row.admission_target,
            row_fixture["admission_target"].as_str().unwrap()
        );
        assert_eq!(
            row.required_evidence,
            row_fixture["required_evidence"].as_str().unwrap()
        );
        assert_eq!(row.blocker, row_fixture["blocker"].as_str().unwrap());
        assert_eq!(
            row.next_action,
            row_fixture["next_action"].as_str().unwrap()
        );
    }

    assert_string_vec(
        &contract.first_execution_order,
        &fixture["first_execution_order"],
    );
    assert_string_vec(
        &contract.denied_until_admitted,
        &fixture["denied_until_admitted"],
    );
    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.source, &fixture["source"]);
}

#[test]
fn stage25_true_daemon_execution_queue_keeps_defaults_blocked() {
    let contract = stage25_true_daemon_execution_queue_contract();
    assert!(contract.queue_complete);
    assert!(contract.implementation_ready);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);
    assert!(contract.benchmark_required_before_admission);
    assert!(contract.outbound_true_dataplane_required);
    assert!(contract.clean_product_chain_required);

    assert_contains_text(&contract.denied_until_admitted, "dae run default owner");
    assert_contains_text(&contract.denied_until_admitted, "install/dae.service");
    assert_contains_text(&contract.denied_until_admitted, "dae-wing or daed defaults");
    assert_contains_text(
        &contract.denied_until_admitted,
        "final_100_percent_admitted",
    );
    assert_contains_text(
        &contract.first_execution_order,
        "Go default daemon baseline",
    );
    assert_contains_text(&contract.first_execution_order, "matched Go-vs-Rust");
}

#[test]
fn stage25_true_daemon_execution_queue_covers_admission_order() {
    let contract = stage25_true_daemon_execution_queue_contract();
    let areas = contract
        .queue_rows
        .iter()
        .map(|row| row.area)
        .collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "daemon artifact identity and CLI compatibility",
            "isolated default-entrypoint smoke harness",
            "config validate and export default corpus",
            "startup readiness pid progress and systemd notify",
            "control-plane owner reload suspend rollback",
            "active TCP tproxy and eBPF path",
            "active UDP DNS and endpoint pool path",
            "kernel owner and eBPF resource lifecycle",
            "outbound true dataplane admission dependency",
            "matched Go vs Rust default daemon benchmark",
            "clean product-chain recertification",
            "rollout fallback and denial controls",
        ]
    );

    assert_contains_text(
        &contract.validation_commands,
        "stage25_true_daemon_execution_queue.json",
    );
    assert_contains_text(&contract.validation_commands, "stage25");
    assert_contains_text(
        &contract.source,
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:30.4",
    );
    assert_contains_text(
        &contract.source,
        "rust/crates/dae-product/src/stage24_product_gate.rs",
    );
}

#[test]
fn stage26_daemon_candidate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage26_candidate_contract.json");
    let contract = stage26_daemon_candidate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.inventory_complete,
        fixture["inventory_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.cli_selector_contract_defined,
        fixture["cli_selector_contract_defined"].as_bool().unwrap()
    );
    assert_eq!(
        contract.optin_candidate_plan_helper_added,
        fixture["optin_candidate_plan_helper_added"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.isolated_smoke_layout_defined,
        fixture["isolated_smoke_layout_defined"].as_bool().unwrap()
    );
    assert_eq!(
        contract.go_baseline_commands_defined,
        fixture["go_baseline_commands_defined"].as_bool().unwrap()
    );
    assert_eq!(
        contract.default_switch_allowed,
        fixture["default_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.default_path_mutation_allowed,
        fixture["default_path_mutation_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.product_chain_switch_allowed,
        fixture["product_chain_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.candidate_live_run_allowed,
        fixture["candidate_live_run_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.true_rust_default_daemon_admitted,
        fixture["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.go_default_path_preserved,
        fixture["go_default_path_preserved"].as_bool().unwrap()
    );
    assert_eq!(
        contract.go_fallback_required,
        fixture["go_fallback_required"].as_bool().unwrap()
    );
    assert_eq!(
        contract.contract_decision,
        fixture["contract_decision"].as_str().unwrap()
    );

    let row_fixtures = fixture["inventory_rows"].as_array().unwrap();
    assert_eq!(contract.inventory_rows.len(), row_fixtures.len());
    for (row, row_fixture) in contract.inventory_rows.iter().zip(row_fixtures) {
        assert_eq!(row.area, row_fixture["area"].as_str().unwrap());
        assert_eq!(row.status, row_fixture["status"].as_str().unwrap());
        assert_eq!(row.evidence, row_fixture["evidence"].as_str().unwrap());
        assert_eq!(row.boundary, row_fixture["boundary"].as_str().unwrap());
        assert_eq!(
            row.next_action,
            row_fixture["next_action"].as_str().unwrap()
        );
    }

    assert_string_vec(&contract.selector_rules, &fixture["selector_rules"]);
    assert_string_vec(
        &contract.isolated_smoke_layout,
        &fixture["isolated_smoke_layout"],
    );
    assert_string_vec(
        &contract.go_baseline_commands,
        &fixture["go_baseline_commands"],
    );
    assert_string_vec(
        &contract.denied_default_mutations,
        &fixture["denied_default_mutations"],
    );
    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.source, &fixture["source"]);
}

#[test]
fn stage26_daemon_candidate_contract_blocks_live_and_default_switches() {
    let contract = stage26_daemon_candidate_contract();
    assert!(contract.stage_complete);
    assert!(contract.inventory_complete);
    assert!(contract.cli_selector_contract_defined);
    assert!(contract.optin_candidate_plan_helper_added);
    assert!(contract.isolated_smoke_layout_defined);
    assert!(contract.go_baseline_commands_defined);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.candidate_live_run_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.denied_default_mutations, "dae-cli-optin");
    assert_contains_text(&contract.denied_default_mutations, "install/dae.service");
    assert_contains_text(
        &contract.denied_default_mutations,
        "true_rust_default_daemon",
    );
    assert_contains_text(&contract.denied_default_mutations, "final_100_percent");
    assert_contains_text(&contract.selector_rules, "dae run remains Go-backed");
    assert_contains_text(&contract.go_baseline_commands, "make dae");
}

#[test]
fn stage26_daemon_candidate_contract_covers_inventory_and_layout() {
    let contract = stage26_daemon_candidate_contract();
    let areas = contract
        .inventory_rows
        .iter()
        .map(|row| row.area)
        .collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "dae-cli-optin artifact",
            "runtime stage26-candidate-plan selector",
            "Go-backed default artifact",
            "isolated smoke layout",
            "Go baseline command queue",
            "candidate live run",
            "carried admission blockers",
        ]
    );

    assert_contains_text(&contract.isolated_smoke_layout, "dae-stage26.progress");
    assert_contains_text(&contract.isolated_smoke_layout, "cache");
    assert_contains_text(&contract.validation_commands, "stage26-candidate-plan");
    assert_contains_text(
        &contract.source,
        "rust/crates/dae-cli/src/runtime_stage26_candidate.rs",
    );
    assert_contains_text(
        &contract.source,
        "testdata/rebuild-golden/engine/runtime_stage26/candidate_plan.json",
    );
}

#[test]
fn stage27_candidate_smoke_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage27_candidate_smoke.json");
    let contract = stage27_candidate_smoke_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.go_baseline_recorded,
        fixture["go_baseline_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.go_baseline_version,
        fixture["go_baseline_version"].as_str().unwrap()
    );
    assert_eq!(
        contract.candidate_smoke_implemented,
        fixture["candidate_smoke_implemented"].as_bool().unwrap()
    );
    assert_eq!(
        contract.candidate_smoke_passed,
        fixture["candidate_smoke_passed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.candidate_live_run_class,
        fixture["candidate_live_run_class"].as_str().unwrap()
    );
    assert_eq!(
        contract.matched_default_daemon_benchmark_recorded,
        fixture["matched_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.default_switch_allowed,
        fixture["default_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.default_path_mutation_allowed,
        fixture["default_path_mutation_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.product_chain_switch_allowed,
        fixture["product_chain_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.true_rust_default_daemon_admitted,
        fixture["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.go_default_path_preserved,
        fixture["go_default_path_preserved"].as_bool().unwrap()
    );
    assert_eq!(
        contract.go_fallback_required,
        fixture["go_fallback_required"].as_bool().unwrap()
    );
    assert_eq!(
        contract.stage27_decision,
        fixture["stage27_decision"].as_str().unwrap()
    );

    let row_fixtures = fixture["smoke_rows"].as_array().unwrap();
    assert_eq!(contract.smoke_rows.len(), row_fixtures.len());
    for (row, row_fixture) in contract.smoke_rows.iter().zip(row_fixtures) {
        assert_eq!(row.area, row_fixture["area"].as_str().unwrap());
        assert_eq!(row.status, row_fixture["status"].as_str().unwrap());
        assert_eq!(row.evidence, row_fixture["evidence"].as_str().unwrap());
        assert_eq!(row.boundary, row_fixture["boundary"].as_str().unwrap());
        assert_eq!(
            row.next_action,
            row_fixture["next_action"].as_str().unwrap()
        );
    }

    assert_string_vec(&contract.carried_blockers, &fixture["carried_blockers"]);
    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.source, &fixture["source"]);
}

#[test]
fn stage27_candidate_smoke_contract_blocks_default_admission() {
    let contract = stage27_candidate_smoke_contract();
    assert!(contract.stage_complete);
    assert!(contract.go_baseline_recorded);
    assert!(contract.candidate_smoke_implemented);
    assert!(contract.candidate_smoke_passed);
    assert_eq!(contract.candidate_live_run_class, "dry-runtime-only");
    assert!(!contract.matched_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "dry-runtime-only");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
    assert_contains_text(&contract.carried_blockers, "outbound true dataplane");
    assert_contains_text(&contract.validation_commands, "stage27-run-candidate");
}

#[test]
fn stage27_candidate_smoke_contract_covers_go_baseline_and_smoke_rows() {
    let contract = stage27_candidate_smoke_contract();
    let areas = contract
        .smoke_rows
        .iter()
        .map(|row| row.area)
        .collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "Go baseline artifact",
            "Go baseline validate and export",
            "Rust dry-runtime candidate smoke",
            "isolated pid progress and log",
            "default path and product chain",
            "real datapath admission",
            "matched default daemon benchmark",
        ]
    );

    assert_contains_text(&contract.source, "runtime_stage27_candidate.rs");
    assert_contains_text(&contract.source, "runtime_stage27/run_candidate.json");
    assert_contains_text(
        &contract.validation_commands,
        "/tmp/dae-stage27-go-baseline/dae",
    );
    assert_contains_text(&contract.validation_commands, "cargo test --manifest-path");
}

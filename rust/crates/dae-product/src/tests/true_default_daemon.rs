use super::*;

#[test]
fn true_default_daemon_admission_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage23_true_default_daemon_admission.json");
    let contract = true_default_daemon_admission_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.gate_complete,
        fixture["gate_complete"].as_bool().unwrap()
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
        contract.stage22_live_evidence_complete,
        fixture["stage22_live_evidence_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.product_chain_admission_defined,
        fixture["product_chain_admission_defined"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.true_rust_daemon_binary_exists,
        fixture["true_rust_daemon_binary_exists"].as_bool().unwrap()
    );
    assert_eq!(
        contract.true_rust_default_daemon_admitted,
        fixture["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.admission_decision,
        fixture["admission_decision"].as_str().unwrap()
    );

    let row_fixtures = fixture["admission_rows"].as_array().unwrap();
    assert_eq!(contract.admission_rows.len(), row_fixtures.len());
    for (row, row_fixture) in contract.admission_rows.iter().zip(row_fixtures) {
        assert_eq!(row.area, row_fixture["area"].as_str().unwrap());
        assert_eq!(row.status, row_fixture["status"].as_str().unwrap());
        assert_eq!(
            row.required_evidence,
            row_fixture["required_evidence"].as_str().unwrap()
        );
        assert_eq!(
            row.current_blocker,
            row_fixture["current_blocker"].as_str().unwrap()
        );
        assert_eq!(
            row.next_action,
            row_fixture["next_action"].as_str().unwrap()
        );
    }

    assert_string_vec(
        &contract.denied_default_mutations,
        &fixture["denied_default_mutations"],
    );
    assert_string_vec(
        &contract.required_benchmarks,
        &fixture["required_benchmarks"],
    );
    assert_string_vec(&contract.rollback_controls, &fixture["rollback_controls"]);
    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.source, &fixture["source"]);
}

#[test]
fn true_default_daemon_admission_blocks_default_switch_until_rows_pass() {
    let contract = true_default_daemon_admission_contract();
    assert!(contract.gate_complete);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);
    assert!(contract.stage22_live_evidence_complete);
    assert!(contract.product_chain_admission_defined);
    assert!(!contract.true_rust_daemon_binary_exists);
    assert!(!contract.true_rust_default_daemon_admitted);

    for row in &contract.admission_rows {
        assert!(
            row.status.starts_with("blocked"),
            "{} must remain blocked before true daemon evidence passes",
            row.area
        );
        assert!(
            !row.required_evidence.is_empty(),
            "{} lacks evidence",
            row.area
        );
        assert!(
            !row.current_blocker.is_empty(),
            "{} lacks blocker",
            row.area
        );
        assert!(
            !row.next_action.is_empty(),
            "{} lacks next action",
            row.area
        );
    }

    assert_contains_text(&contract.denied_default_mutations, "dae run default engine");
    assert_contains_text(
        &contract.denied_default_mutations,
        "control.NewControlPlane",
    );
    assert_contains_text(&contract.denied_default_mutations, "install/dae.service");
    assert_contains_text(&contract.denied_default_mutations, "release assets");
    assert_contains_text(&contract.denied_default_mutations, "dae-wing or daed");
    assert_contains_text(&contract.denied_default_mutations, "Go outbound");
}

#[test]
fn true_default_daemon_admission_covers_all_required_surfaces() {
    let contract = true_default_daemon_admission_contract();
    let areas = contract
        .admission_rows
        .iter()
        .map(|row| row.area)
        .collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "binary identity and entrypoint",
            "config validate and export parity",
            "startup, pid, progress, and systemd notify",
            "control-plane lifecycle",
            "active TCP datapath",
            "active UDP and DNS datapath",
            "eBPF and kernel ownership",
            "reload, suspend, and rollback",
            "RuntimeOverview and route-aware HTTP",
            "outbound true dataplane",
            "matched benchmark parity",
            "rollback and rollout controls",
        ]
    );

    assert_contains_text(
        &contract.required_benchmarks,
        "Go default daemon vs true Rust default daemon TCP",
    );
    assert_contains_text(
        &contract.required_benchmarks,
        "Go default daemon vs true Rust default daemon UDP",
    );
    assert_contains_text(&contract.required_benchmarks, "outbound protocol");
    assert_contains_text(&contract.required_benchmarks, "RSS, CPU");
    assert_contains_text(&contract.required_benchmarks, "raw logs");
    assert_contains_text(&contract.required_benchmarks, "rollback result");
    assert_contains_text(&contract.rollback_controls, "Go-backed dae binary");
    assert_contains_text(&contract.rollback_controls, "explicit opt-in selector");
    assert_contains_text(&contract.rollback_controls, "candidate process");
}

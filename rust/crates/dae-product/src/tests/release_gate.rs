use super::*;

#[test]
fn stage7_release_gate_contract_matches_golden_fixture() {
    let fixture = load("product/release/stage7_release_gate.json");
    let contract = stage7_release_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.fixed_queue_range,
        fixture["fixed_queue_range"].as_str().unwrap()
    );
    assert_eq!(
        contract.fixed_queue_complete,
        fixture["fixed_queue_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.stage7_gate_complete,
        fixture["stage7_gate_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.release_gate_open,
        fixture["release_gate_open"].as_bool().unwrap()
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
        contract.go_default_path_preserved,
        fixture["go_default_path_preserved"].as_bool().unwrap()
    );
    assert_eq!(
        contract.go_runtime_outbound_fallback_required,
        fixture["go_runtime_outbound_fallback_required"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.go_bpf_loader_restored,
        fixture["go_bpf_loader_restored"].as_bool().unwrap()
    );
    assert_eq!(
        contract.admission_decision,
        fixture["admission_decision"].as_str().unwrap()
    );

    assert_string_vec(
        &contract.accepted_native_groups,
        &fixture["accepted_native_groups"],
    );

    let row_fixtures = fixture["gate_rows"].as_array().unwrap();
    assert_eq!(contract.gate_rows.len(), row_fixtures.len());
    for (row, row_fixture) in contract.gate_rows.iter().zip(row_fixtures) {
        assert_eq!(row.area, row_fixture["area"].as_str().unwrap());
        assert_eq!(row.status, row_fixture["status"].as_str().unwrap());
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

    assert_string_vec(&contract.denied_actions, &fixture["denied_actions"]);
    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.source, &fixture["source"]);
}

#[test]
fn stage7_release_gate_closes_queue_without_opening_switch() {
    let contract = stage7_release_gate_contract();
    assert!(contract.fixed_queue_complete);
    assert!(contract.stage7_gate_complete);
    assert!(!contract.release_gate_open);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_runtime_outbound_fallback_required);
    assert!(!contract.go_bpf_loader_restored);

    assert_eq!(
        contract.accepted_native_groups,
        vec![
            "control-plane-native-owner",
            "routing-lpm-native-build",
            "dns-native-hot-path",
            "sniffing-geodata-matcher-native",
            "daemon-runtime-native-owner",
            "datapath-outbound-ebpf-deep-area",
        ]
    );

    assert_contains_text(
        &contract.denied_actions,
        "do not add a new fixed Rust native stage",
    );
    assert_contains_text(&contract.denied_actions, "do not switch dae run");
    assert_contains_text(&contract.denied_actions, "do not delete Go runtime");
    assert_contains_text(&contract.denied_actions, "do not restore Go BPF loader");
}

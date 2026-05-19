use super::*;

#[test]
fn protocol_dataplane_admission_contract_matches_golden_fixture() {
    let fixture = load("product/outbound/protocol_dataplane_admission.json");
    let contract = protocol_dataplane_admission_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(
        contract.queue_complete,
        fixture["queue_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.default_switch_allowed,
        fixture["default_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.go_default_path_preserved,
        fixture["go_default_path_preserved"].as_bool().unwrap()
    );
    assert_eq!(
        contract.admission_rule,
        fixture["admission_rule"].as_str().unwrap()
    );
    assert_string_vec(
        &contract.cross_cutting_gates,
        &fixture["cross_cutting_gates"],
    );
    assert_string_vec(
        &contract.first_batch_candidates,
        &fixture["first_batch_candidates"],
    );
    assert_string_vec(
        &contract.deferred_until_shared_transport,
        &fixture["deferred_until_shared_transport"],
    );

    let protocol_fixtures = fixture["protocols"].as_array().unwrap();
    assert_eq!(contract.protocols.len(), protocol_fixtures.len());
    for (row, protocol_fixture) in contract.protocols.iter().zip(protocol_fixtures) {
        assert_eq!(row.protocol, protocol_fixture["protocol"].as_str().unwrap());
        assert_eq!(
            row.current_state,
            protocol_fixture["current_state"].as_str().unwrap()
        );
        assert_eq!(
            row.default_switch_allowed,
            protocol_fixture["default_switch_allowed"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(row.priority, protocol_fixture["priority"].as_str().unwrap());
        assert_string_vec(
            &row.required_evidence,
            &protocol_fixture["required_evidence"],
        );
        assert_string_vec(&row.blockers, &protocol_fixture["blockers"]);
    }

    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.source, &fixture["source"]);
}

#[test]
fn complex_dataplane_gate_contract_matches_golden_fixture() {
    let fixture = load("product/outbound/complex_dataplane_gate.json");
    let contract = complex_dataplane_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(
        contract.gate_complete,
        fixture["gate_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.default_switch_allowed,
        fixture["default_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.go_fallback_required,
        fixture["go_fallback_required"].as_bool().unwrap()
    );
    assert_string_vec(
        &contract.first_batch_completed,
        &fixture["first_batch_completed"],
    );

    let row_fixtures = fixture["complex_rows"].as_array().unwrap();
    assert_eq!(contract.complex_rows.len(), row_fixtures.len());
    for (row, row_fixture) in contract.complex_rows.iter().zip(row_fixtures) {
        assert_eq!(row.protocol, row_fixture["protocol"].as_str().unwrap());
        assert_eq!(
            row.blocker_class,
            row_fixture["blocker_class"].as_str().unwrap()
        );
        assert_eq!(
            row.rust_current_state,
            row_fixture["rust_current_state"].as_str().unwrap()
        );
        assert_string_vec(
            &row.required_before_true_dataplane,
            &row_fixture["required_before_true_dataplane"],
        );
        assert_eq!(
            row.next_allowed_step,
            row_fixture["next_allowed_step"].as_str().unwrap()
        );
    }

    assert_string_vec(
        &contract.reopen_requirements,
        &fixture["reopen_requirements"],
    );
    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.source, &fixture["source"]);
}

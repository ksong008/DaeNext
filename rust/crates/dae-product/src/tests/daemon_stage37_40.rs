use super::*;

#[test]
fn stage37_loaded_listen_socket_map_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage37_loaded_listen_socket_map_gate.json");
    let contract = stage37_loaded_listen_socket_map_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.real_loaded_object_listen_socket_map_fd_update_recorded,
        fixture["real_loaded_object_listen_socket_map_fd_update_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.real_loaded_object_listen_socket_map_cleanup_recorded,
        fixture["real_loaded_object_listen_socket_map_cleanup_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.production_dae0_dae0peer_attach_executed,
        fixture["production_dae0_dae0peer_attach_executed"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.production_listen_socket_map_fd_update_executed,
        fixture["production_listen_socket_map_fd_update_executed"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_tproxy_traffic_executed,
        fixture["active_tproxy_traffic_executed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.matched_go_rust_default_daemon_benchmark_recorded,
        fixture["matched_go_rust_default_daemon_benchmark_recorded"]
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
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );

    let row_fixtures = fixture["rows"].as_array().unwrap();
    assert_eq!(contract.rows.len(), row_fixtures.len());
    for (row, row_fixture) in contract.rows.iter().zip(row_fixtures) {
        assert_eq!(row.area, row_fixture["area"].as_str().unwrap());
        assert_eq!(row.status, row_fixture["status"].as_str().unwrap());
        assert_eq!(row.evidence, row_fixture["evidence"].as_str().unwrap());
        assert_eq!(row.boundary, row_fixture["boundary"].as_str().unwrap());
        assert_eq!(
            row.next_action,
            row_fixture["next_action"].as_str().unwrap()
        );
    }

    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.carried_blockers, &fixture["carried_blockers"]);
    assert_string_vec(&contract.source, &fixture["source"]);
}

#[test]
fn stage37_loaded_listen_socket_map_gate_blocks_default_admission() {
    let contract = stage37_loaded_listen_socket_map_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.real_loaded_object_listen_socket_map_fd_update_recorded);
    assert!(contract.real_loaded_object_listen_socket_map_cleanup_recorded);
    assert!(!contract.production_dae0_dae0peer_attach_executed);
    assert!(!contract.production_listen_socket_map_fd_update_executed);
    assert!(!contract.active_tproxy_traffic_executed);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "production dae0/dae0peer");
    assert_contains_text(
        &contract.carried_blockers,
        "production daemon listener handoff",
    );
    assert_contains_text(&contract.carried_blockers, "active tproxy TCP UDP DNS");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
    assert_contains_text(&contract.carried_blockers, "clean dae-wing and daed");
}

#[test]
fn stage37_loaded_listen_socket_map_gate_covers_rows() {
    let contract = stage37_loaded_listen_socket_map_gate_contract();
    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "real loaded object map discovery",
            "real loaded object listener fd handoff"
        ]
    );
    assert_contains_text(&contract.source, "runtime_stage37_gate.rs");
    assert_contains_text(&contract.source, "dae-ebpf-support/src/runtime_maps.rs");
    assert_contains_text(
        &contract.source,
        "runtime_stage37/loaded_listen_socket_map_admission.json",
    );
    assert_contains_text(&contract.validation_commands, "dae-ebpf-support");
    assert_contains_text(
        &contract.validation_commands,
        "stage37-loaded-listen-socket-map",
    );
}

#[test]
fn stage38_production_dae_attach_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage38_production_dae_attach_gate.json");
    let contract = stage38_production_dae_attach_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.production_dae0_dae0peer_attach_recorded,
        fixture["production_dae0_dae0peer_attach_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.production_listen_socket_map_fd_update_recorded,
        fixture["production_listen_socket_map_fd_update_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.production_default_daemon_attach_recorded,
        fixture["production_default_daemon_attach_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_tproxy_traffic_executed,
        fixture["active_tproxy_traffic_executed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.matched_go_rust_default_daemon_benchmark_recorded,
        fixture["matched_go_rust_default_daemon_benchmark_recorded"]
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
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );

    let row_fixtures = fixture["rows"].as_array().unwrap();
    assert_eq!(contract.rows.len(), row_fixtures.len());
    for (row, row_fixture) in contract.rows.iter().zip(row_fixtures) {
        assert_eq!(row.area, row_fixture["area"].as_str().unwrap());
        assert_eq!(row.status, row_fixture["status"].as_str().unwrap());
        assert_eq!(row.evidence, row_fixture["evidence"].as_str().unwrap());
        assert_eq!(row.boundary, row_fixture["boundary"].as_str().unwrap());
        assert_eq!(
            row.next_action,
            row_fixture["next_action"].as_str().unwrap()
        );
    }

    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.carried_blockers, &fixture["carried_blockers"]);
    assert_string_vec(&contract.source, &fixture["source"]);
}

#[test]
fn stage38_production_dae_attach_gate_blocks_default_admission() {
    let contract = stage38_production_dae_attach_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.production_dae0_dae0peer_attach_recorded);
    assert!(contract.production_listen_socket_map_fd_update_recorded);
    assert!(!contract.production_default_daemon_attach_recorded);
    assert!(!contract.active_tproxy_traffic_executed);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(
        &contract.carried_blockers,
        "production default daemon attach",
    );
    assert_contains_text(&contract.carried_blockers, "active tproxy TCP UDP DNS");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
    assert_contains_text(&contract.carried_blockers, "clean dae-wing and daed");
}

#[test]
fn stage38_production_dae_attach_gate_covers_rows() {
    let contract = stage38_production_dae_attach_gate_contract();
    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "production-name dae topology",
            "production-name listener handoff"
        ]
    );
    assert_contains_text(&contract.source, "runtime_stage38_gate.rs");
    assert_contains_text(&contract.source, "dae-ebpf-support/src/runtime_maps.rs");
    assert_contains_text(
        &contract.source,
        "runtime_stage38/production_dae_attach_admission.json",
    );
    assert_contains_text(
        &contract.validation_commands,
        "stage38-production-dae-attach",
    );
}

#[test]
fn stage39_transparent_listener_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage39_transparent_listener_gate.json");
    let contract = stage39_transparent_listener_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.real_loaded_object_transparent_listener_fd_update_recorded,
        fixture["real_loaded_object_transparent_listener_fd_update_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.transparent_listener_socket_options_recorded,
        fixture["transparent_listener_socket_options_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.production_name_dae0_dae0peer_attach_executed,
        fixture["production_name_dae0_dae0peer_attach_executed"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_tproxy_traffic_executed,
        fixture["active_tproxy_traffic_executed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.matched_go_rust_default_daemon_benchmark_recorded,
        fixture["matched_go_rust_default_daemon_benchmark_recorded"]
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
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );

    let row_fixtures = fixture["rows"].as_array().unwrap();
    assert_eq!(contract.rows.len(), row_fixtures.len());
    for (row, row_fixture) in contract.rows.iter().zip(row_fixtures) {
        assert_eq!(row.area, row_fixture["area"].as_str().unwrap());
        assert_eq!(row.status, row_fixture["status"].as_str().unwrap());
        assert_eq!(row.evidence, row_fixture["evidence"].as_str().unwrap());
        assert_eq!(row.boundary, row_fixture["boundary"].as_str().unwrap());
        assert_eq!(
            row.next_action,
            row_fixture["next_action"].as_str().unwrap()
        );
    }

    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.carried_blockers, &fixture["carried_blockers"]);
    assert_string_vec(&contract.source, &fixture["source"]);
}

#[test]
fn stage39_transparent_listener_gate_blocks_default_admission() {
    let contract = stage39_transparent_listener_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.real_loaded_object_transparent_listener_fd_update_recorded);
    assert!(contract.transparent_listener_socket_options_recorded);
    assert!(!contract.production_name_dae0_dae0peer_attach_executed);
    assert!(!contract.active_tproxy_traffic_executed);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(
        &contract.carried_blockers,
        "production default daemon attach",
    );
    assert_contains_text(&contract.carried_blockers, "active tproxy TCP UDP DNS");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
    assert_contains_text(&contract.carried_blockers, "clean dae-wing and daed");
}

#[test]
fn stage39_transparent_listener_gate_covers_rows() {
    let contract = stage39_transparent_listener_gate_contract();
    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "transparent TCP listener handoff",
            "transparent UDP listener handoff"
        ]
    );
    assert_contains_text(&contract.source, "runtime_stage39_gate.rs");
    assert_contains_text(&contract.source, "tproxy_listener.rs");
    assert_contains_text(
        &contract.source,
        "runtime_stage39/transparent_listener_admission.json",
    );
    assert_contains_text(
        &contract.validation_commands,
        "stage39-transparent-listener",
    );
}

#[test]
fn stage40_param_aware_object_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage40_param_aware_object_gate.json");
    let contract = stage40_param_aware_object_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.param_symbol_contract_recorded,
        fixture["param_symbol_contract_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.param_payload_contract_recorded,
        fixture["param_payload_contract_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.direct_tc_object_loader_rejected_for_active_traffic,
        fixture["direct_tc_object_loader_rejected_for_active_traffic"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.rust_param_aware_loader_proven,
        fixture["rust_param_aware_loader_proven"].as_bool().unwrap()
    );
    assert_eq!(
        contract.param_aware_object_load_admitted,
        fixture["param_aware_object_load_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_tproxy_traffic_executed,
        fixture["active_tproxy_traffic_executed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.matched_go_rust_default_daemon_benchmark_recorded,
        fixture["matched_go_rust_default_daemon_benchmark_recorded"]
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
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );

    let row_fixtures = fixture["rows"].as_array().unwrap();
    assert_eq!(contract.rows.len(), row_fixtures.len());
    for (row, row_fixture) in contract.rows.iter().zip(row_fixtures) {
        assert_eq!(row.area, row_fixture["area"].as_str().unwrap());
        assert_eq!(row.status, row_fixture["status"].as_str().unwrap());
        assert_eq!(row.evidence, row_fixture["evidence"].as_str().unwrap());
        assert_eq!(row.boundary, row_fixture["boundary"].as_str().unwrap());
        assert_eq!(
            row.next_action,
            row_fixture["next_action"].as_str().unwrap()
        );
    }

    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.carried_blockers, &fixture["carried_blockers"]);
    assert_string_vec(&contract.source, &fixture["source"]);
}

#[test]
fn stage40_param_aware_object_gate_blocks_default_admission() {
    let contract = stage40_param_aware_object_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.param_symbol_contract_recorded);
    assert!(contract.param_payload_contract_recorded);
    assert!(contract.direct_tc_object_loader_rejected_for_active_traffic);
    assert!(!contract.rust_param_aware_loader_proven);
    assert!(!contract.param_aware_object_load_admitted);
    assert!(!contract.active_tproxy_traffic_executed);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "PARAM-aware Rust BPF");
    assert_contains_text(&contract.carried_blockers, "direct tc filter obj");
    assert_contains_text(&contract.carried_blockers, "active tproxy TCP UDP DNS");
    assert_contains_text(&contract.carried_blockers, "clean dae-wing and daed");
}

#[test]
fn stage40_param_aware_object_gate_covers_rows() {
    let contract = stage40_param_aware_object_gate_contract();
    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "PARAM object symbol",
            "PARAM payload packing",
            "loader admission"
        ]
    );
    assert_contains_text(&contract.source, "runtime_stage40_gate.rs");
    assert_contains_text(&contract.source, "param_loader.rs");
    assert_contains_text(
        &contract.source,
        "runtime_stage40/param_aware_object_admission.json",
    );
    assert_contains_text(&contract.validation_commands, "stage40-param-aware-object");
}

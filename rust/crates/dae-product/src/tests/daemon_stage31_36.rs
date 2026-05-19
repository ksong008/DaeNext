use super::*;

#[test]
fn stage31_34_admission_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage31_34_admission_gates.json");
    let contract = stage31_34_admission_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(
        contract.stage_range,
        fixture["stage_range"].as_str().unwrap()
    );
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage31_complete,
        fixture["stage31_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.stage32_complete,
        fixture["stage32_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.stage33_complete,
        fixture["stage33_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.stage34_complete,
        fixture["stage34_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.root_gated_filter_cleanup_recorded,
        fixture["root_gated_filter_cleanup_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.local_traffic_harness_recorded,
        fixture["local_traffic_harness_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.reload_dns_model_recorded,
        fixture["reload_dns_model_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.rust_micro_benchmark_required,
        fixture["rust_micro_benchmark_required"].as_bool().unwrap()
    );
    assert_eq!(
        contract.matched_go_rust_default_daemon_benchmark_recorded,
        fixture["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.actual_dae_ebpf_program_attach_executed,
        fixture["actual_dae_ebpf_program_attach_executed"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_tproxy_traffic_executed,
        fixture["active_tproxy_traffic_executed"].as_bool().unwrap()
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
        assert_eq!(row.stage, row_fixture["stage"].as_str().unwrap());
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
fn stage31_34_admission_contract_blocks_default_admission() {
    let contract = stage31_34_admission_contract();
    assert!(contract.stage31_complete);
    assert!(contract.stage32_complete);
    assert!(contract.stage33_complete);
    assert!(contract.stage34_complete);
    assert!(contract.root_gated_filter_cleanup_recorded);
    assert!(contract.local_traffic_harness_recorded);
    assert!(contract.reload_dns_model_recorded);
    assert!(contract.rust_micro_benchmark_required);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.actual_dae_ebpf_program_attach_executed);
    assert!(!contract.active_tproxy_traffic_executed);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "actual dae eBPF program attach");
    assert_contains_text(&contract.carried_blockers, "listen socket map update");
    assert_contains_text(&contract.carried_blockers, "active tproxy TCP UDP DNS");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
    assert_contains_text(&contract.carried_blockers, "clean dae-wing and daed");
}

#[test]
fn stage31_34_admission_contract_covers_rows() {
    let contract = stage31_34_admission_contract();
    let stages = contract
        .rows
        .iter()
        .map(|row| row.stage)
        .collect::<Vec<_>>();
    assert_eq!(stages, vec!["stage31", "stage32", "stage33", "stage34"]);
    assert_contains_text(&contract.source, "runtime_stage31_34_gates.rs");
    assert_contains_text(
        &contract.source,
        "runtime_stage31/ebpf_attach_admission.json",
    );
    assert_contains_text(
        &contract.source,
        "runtime_stage32/active_traffic_admission.json",
    );
    assert_contains_text(
        &contract.source,
        "runtime_stage33/reload_rollback_admission.json",
    );
    assert_contains_text(&contract.source, "runtime_stage34/benchmark_admission.json");
    assert_contains_text(&contract.validation_commands, "dae-datapath --release");
    assert_contains_text(&contract.validation_commands, "dae-control --release");
}

#[test]
fn stage35_36_admission_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage35_36_admission_gates.json");
    let contract = stage35_36_admission_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(
        contract.stage_range,
        fixture["stage_range"].as_str().unwrap()
    );
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage35_complete,
        fixture["stage35_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.stage36_complete,
        fixture["stage36_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.root_gated_actual_program_attach_recorded,
        fixture["root_gated_actual_program_attach_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.rust_temporary_sockmap_fd_update_recorded,
        fixture["rust_temporary_sockmap_fd_update_recorded"]
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
        assert_eq!(row.stage, row_fixture["stage"].as_str().unwrap());
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
fn stage35_36_admission_contract_blocks_default_admission() {
    let contract = stage35_36_admission_contract();
    assert!(contract.stage35_complete);
    assert!(contract.stage36_complete);
    assert!(contract.root_gated_actual_program_attach_recorded);
    assert!(contract.rust_temporary_sockmap_fd_update_recorded);
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
    assert_contains_text(&contract.carried_blockers, "production listen_socket_map");
    assert_contains_text(&contract.carried_blockers, "active tproxy TCP UDP DNS");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
    assert_contains_text(&contract.carried_blockers, "clean dae-wing and daed");
}

#[test]
fn stage35_36_admission_contract_covers_rows() {
    let contract = stage35_36_admission_contract();
    let stages = contract
        .rows
        .iter()
        .map(|row| row.stage)
        .collect::<Vec<_>>();
    assert_eq!(stages, vec!["stage35", "stage36"]);
    assert_contains_text(&contract.source, "runtime_stage35_36_gates.rs");
    assert_contains_text(&contract.source, "dae-ebpf-support/src/sockmap.rs");
    assert_contains_text(
        &contract.source,
        "runtime_stage35/real_ebpf_attach_admission.json",
    );
    assert_contains_text(
        &contract.source,
        "runtime_stage36/listen_socket_map_admission.json",
    );
    assert_contains_text(&contract.validation_commands, "dae-ebpf-support");
    assert_contains_text(&contract.validation_commands, "stage35-real-ebpf-attach");
    assert_contains_text(&contract.validation_commands, "stage36-listen-socket-map");
}

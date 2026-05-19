use super::*;

#[test]
fn stage41_48_admission_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage41_48_admission_gates.json");
    let contract = stage41_48_admission_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(
        contract.stage_range,
        fixture["stage_range"].as_str().unwrap()
    );
    assert_eq!(
        contract.stage41_complete,
        fixture["stage41_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.stage42_complete,
        fixture["stage42_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.stage43_complete,
        fixture["stage43_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.stage44_complete,
        fixture["stage44_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.stage45_complete,
        fixture["stage45_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.stage46_complete,
        fixture["stage46_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.stage47_complete,
        fixture["stage47_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.stage48_complete,
        fixture["stage48_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.param_object_image_admitted,
        fixture["param_object_image_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.param_aware_object_load_admitted,
        fixture["param_aware_object_load_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.combined_production_param_listener_admitted,
        fixture["combined_production_param_listener_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_tcp_tproxy_admitted,
        fixture["active_tcp_tproxy_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.active_udp_tproxy_admitted,
        fixture["active_udp_tproxy_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.active_dns_tproxy_admitted,
        fixture["active_dns_tproxy_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.outbound_true_dataplane_admitted,
        fixture["outbound_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
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
    assert_string_vec(&contract.carried_blockers, &fixture["carried_blockers"]);
}

#[test]
fn stage41_48_admission_contract_blocks_default_admission() {
    let contract = stage41_48_admission_contract();
    assert!(contract.stage41_complete);
    assert!(contract.stage42_complete);
    assert!(contract.param_object_image_admitted);
    assert!(contract.param_aware_object_load_admitted);
    assert!(!contract.combined_production_param_listener_admitted);
    assert!(!contract.active_tcp_tproxy_admitted);
    assert!(!contract.active_udp_tproxy_admitted);
    assert!(!contract.active_dns_tproxy_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "combined production-name");
    assert_contains_text(&contract.carried_blockers, "active tproxy TCP UDP DNS");
    assert_contains_text(&contract.carried_blockers, "outbound true dataplane");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
}

#[test]
fn stage41_48_admission_contract_covers_all_stages() {
    let contract = stage41_48_admission_contract();
    let stages = contract
        .rows
        .iter()
        .map(|row| row.stage)
        .collect::<Vec<_>>();
    assert_eq!(
        stages,
        vec![
            "stage41", "stage42", "stage43", "stage44", "stage45", "stage46", "stage47", "stage48"
        ]
    );
    assert_contains_text(&contract.source, "param_object.rs");
    assert_contains_text(&contract.source, "runtime_stage41_48_gates.rs");
    assert_contains_text(
        &contract.validation_commands,
        "stage42-param-object-load-admission",
    );
}

#[test]
fn stage49_production_param_listener_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage49_production_param_listener_gate.json");
    let contract = stage49_production_param_listener_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.combined_production_param_listener_recorded,
        fixture["combined_production_param_listener_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.production_name_dae0_dae0peer_attach_recorded,
        fixture["production_name_dae0_dae0peer_attach_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.param_aware_object_load_recorded,
        fixture["param_aware_object_load_recorded"]
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
        contract.production_param_transparent_listener_handoff_recorded,
        fixture["production_param_transparent_listener_handoff_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_tproxy_traffic_executed,
        fixture["active_tproxy_traffic_executed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.outbound_true_dataplane_admitted,
        fixture["outbound_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
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
    assert_string_vec(&contract.carried_blockers, &fixture["carried_blockers"]);
}

#[test]
fn stage49_production_param_listener_gate_blocks_default_admission() {
    let contract = stage49_production_param_listener_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.combined_production_param_listener_recorded);
    assert!(contract.production_name_dae0_dae0peer_attach_recorded);
    assert!(contract.param_aware_object_load_recorded);
    assert!(contract.transparent_listener_socket_options_recorded);
    assert!(contract.production_param_transparent_listener_handoff_recorded);
    assert!(!contract.active_tproxy_traffic_executed);
    assert!(!contract.active_tcp_tproxy_admitted);
    assert!(!contract.active_udp_tproxy_admitted);
    assert!(!contract.active_dns_tproxy_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "active tproxy TCP UDP DNS");
    assert_contains_text(&contract.carried_blockers, "outbound true dataplane");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
}

#[test]
fn stage49_production_param_listener_gate_covers_rows() {
    let contract = stage49_production_param_listener_gate_contract();
    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "production-name PARAM topology",
            "transparent listener handoff on PARAM object"
        ]
    );
    assert_contains_text(&contract.source, "runtime_stage49_gate.rs");
    assert_contains_text(&contract.source, "param_object.rs");
    assert_contains_text(
        &contract.validation_commands,
        "stage49-production-param-listener-admission",
    );
}

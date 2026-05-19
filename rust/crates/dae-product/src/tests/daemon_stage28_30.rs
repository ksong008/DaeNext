use super::*;

#[test]
fn stage28_live_admission_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage28_live_admission_gate.json");
    let contract = stage28_live_admission_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.live_admission_gate_defined,
        fixture["live_admission_gate_defined"].as_bool().unwrap()
    );
    assert_eq!(
        contract.candidate_dry_smoke_inherited,
        fixture["candidate_dry_smoke_inherited"].as_bool().unwrap()
    );
    assert_eq!(
        contract.live_candidate_run_allowed,
        fixture["live_candidate_run_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.root_bpf_netns_gate_required,
        fixture["root_bpf_netns_gate_required"].as_bool().unwrap()
    );
    assert_eq!(
        contract.active_datapath_evidence_required,
        fixture["active_datapath_evidence_required"]
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
        contract.matched_default_daemon_benchmark_required,
        fixture["matched_default_daemon_benchmark_required"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.clean_product_chain_required,
        fixture["clean_product_chain_required"].as_bool().unwrap()
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

    let row_fixtures = fixture["gate_rows"].as_array().unwrap();
    assert_eq!(contract.gate_rows.len(), row_fixtures.len());
    for (row, row_fixture) in contract.gate_rows.iter().zip(row_fixtures) {
        assert_eq!(row.area, row_fixture["area"].as_str().unwrap());
        assert_eq!(row.status, row_fixture["status"].as_str().unwrap());
        assert_eq!(
            row.required_evidence,
            row_fixture["required_evidence"].as_str().unwrap()
        );
        assert_eq!(
            row.blocked_until,
            row_fixture["blocked_until"].as_str().unwrap()
        );
        assert_eq!(
            row.next_action,
            row_fixture["next_action"].as_str().unwrap()
        );
    }

    assert_string_vec(&contract.admission_order, &fixture["admission_order"]);
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
fn stage28_live_admission_gate_blocks_default_admission() {
    let contract = stage28_live_admission_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.live_admission_gate_defined);
    assert!(contract.candidate_dry_smoke_inherited);
    assert!(!contract.live_candidate_run_allowed);
    assert!(contract.root_bpf_netns_gate_required);
    assert!(contract.active_datapath_evidence_required);
    assert!(contract.outbound_true_dataplane_required);
    assert!(contract.matched_default_daemon_benchmark_required);
    assert!(contract.clean_product_chain_required);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.denied_default_mutations, "Stage 28 gate itself");
    assert_contains_text(&contract.denied_default_mutations, "dae run default owner");
    assert_contains_text(&contract.denied_default_mutations, "/var/run/dae.progress");
    assert_contains_text(
        &contract.denied_default_mutations,
        "true_rust_default_daemon_admitted",
    );
    assert_contains_text(&contract.validation_commands, "stage28");
}

#[test]
fn stage28_live_admission_gate_covers_live_candidate_rows() {
    let contract = stage28_live_admission_gate_contract();
    let areas = contract
        .gate_rows
        .iter()
        .map(|row| row.area)
        .collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "pre-admission host and isolation gate",
            "candidate artifact identity and CLI parity",
            "control-plane and kernel owner split",
            "eBPF netns sysctl attach order",
            "active TCP tproxy datapath",
            "active UDP and DNS datapath",
            "outbound true dataplane protocols",
            "reload suspend rollback and cache survival",
            "matched Go vs Rust default daemon benchmark",
            "clean product-chain recertification",
            "rollout fallback and denial controls",
        ]
    );

    assert_contains_text(&contract.admission_order, "root/BPF/netns preflight");
    assert_contains_text(&contract.admission_order, "active TCP tproxy traffic");
    assert_contains_text(&contract.admission_order, "matched Go default daemon");
    assert_contains_text(&contract.source, "runtime_host_preflight.rs");
    assert_contains_text(&contract.source, "active_datapath_runner.rs");
    assert_contains_text(
        &contract.source,
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:33.8",
    );
}

#[test]
fn stage29_host_preflight_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage29_host_preflight_gate.json");
    let contract = stage29_host_preflight_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.host_preflight_helper_added,
        fixture["host_preflight_helper_added"].as_bool().unwrap()
    );
    assert_eq!(
        contract.exact_candidate_root_defined,
        fixture["exact_candidate_root_defined"].as_bool().unwrap()
    );
    assert_eq!(
        contract.host_probe_default_read_only,
        fixture["host_probe_default_read_only"].as_bool().unwrap()
    );
    assert_eq!(
        contract.host_probe_optional,
        fixture["host_probe_optional"].as_bool().unwrap()
    );
    assert_eq!(
        contract.require_existing_config_supported,
        fixture["require_existing_config_supported"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.live_candidate_run_allowed,
        fixture["live_candidate_run_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.root_bpf_netns_gate_recorded,
        fixture["root_bpf_netns_gate_recorded"].as_bool().unwrap()
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

    let row_fixtures = fixture["preflight_rows"].as_array().unwrap();
    assert_eq!(contract.preflight_rows.len(), row_fixtures.len());
    for (row, row_fixture) in contract.preflight_rows.iter().zip(row_fixtures) {
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
        &contract.required_probe_checks,
        &fixture["required_probe_checks"],
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
fn stage29_host_preflight_gate_blocks_live_candidate_and_defaults() {
    let contract = stage29_host_preflight_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.host_preflight_helper_added);
    assert!(contract.exact_candidate_root_defined);
    assert!(contract.host_probe_default_read_only);
    assert!(contract.host_probe_optional);
    assert!(contract.require_existing_config_supported);
    assert!(!contract.live_candidate_run_allowed);
    assert!(contract.root_bpf_netns_gate_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.denied_default_mutations, "start live candidate");
    assert_contains_text(&contract.denied_default_mutations, "attach eBPF");
    assert_contains_text(&contract.denied_default_mutations, "/var/run/dae.progress");
    assert_contains_text(
        &contract.denied_default_mutations,
        "true_rust_default_daemon_admitted",
    );
}

#[test]
fn stage29_host_preflight_gate_covers_probe_checks() {
    let contract = stage29_host_preflight_gate_contract();
    let areas = contract
        .preflight_rows
        .iter()
        .map(|row| row.area)
        .collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "exact isolated root and state paths",
            "stable default preflight plan",
            "optional host probe",
            "existing config prerequisite",
            "production conflict guard",
            "BPF netns mutation denial",
            "default admission and product chain",
        ]
    );

    assert_contains_text(&contract.required_probe_checks, "effective-root-permission");
    assert_contains_text(&contract.required_probe_checks, "bpffs-mounted");
    assert_contains_text(&contract.required_probe_checks, "memlock-nonzero");
    assert_contains_text(&contract.required_probe_checks, "tproxy-tcp-port-free");
    assert_contains_text(&contract.required_probe_checks, "client-netns-name-free");
    assert_contains_text(&contract.validation_commands, "stage29-host-preflight");
    assert_contains_text(&contract.source, "runtime_stage29_preflight.rs");
    assert_contains_text(&contract.source, "runtime_stage29/host_preflight.json");
}

#[test]
fn stage30_attach_cleanup_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage30_attach_cleanup_gate.json");
    let contract = stage30_attach_cleanup_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.attach_cleanup_helper_added,
        fixture["attach_cleanup_helper_added"].as_bool().unwrap()
    );
    assert_eq!(
        contract.stage29_preflight_required,
        fixture["stage29_preflight_required"].as_bool().unwrap()
    );
    assert_eq!(
        contract.root_gate_ack_required,
        fixture["root_gate_ack_required"].as_bool().unwrap()
    );
    assert_eq!(
        contract.execute_smoke_default,
        fixture["execute_smoke_default"].as_bool().unwrap()
    );
    assert_eq!(
        contract.current_attach_cleanup_smoke_passed,
        fixture["current_attach_cleanup_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.live_candidate_run_allowed,
        fixture["live_candidate_run_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.actual_dae_ebpf_program_attach_executed,
        fixture["actual_dae_ebpf_program_attach_executed"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_traffic_evidence_recorded,
        fixture["active_traffic_evidence_recorded"]
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

    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.carried_blockers, &fixture["carried_blockers"]);
    assert_string_vec(&contract.source, &fixture["source"]);
}

#[test]
fn stage30_attach_cleanup_gate_blocks_live_candidate_and_defaults() {
    let contract = stage30_attach_cleanup_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.attach_cleanup_helper_added);
    assert!(contract.stage29_preflight_required);
    assert!(contract.root_gate_ack_required);
    assert!(!contract.execute_smoke_default);
    assert!(contract.current_attach_cleanup_smoke_passed);
    assert!(!contract.live_candidate_run_allowed);
    assert!(!contract.actual_dae_ebpf_program_attach_executed);
    assert!(!contract.active_traffic_evidence_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "actual dae eBPF program attach");
    assert_contains_text(&contract.carried_blockers, "listen socket map update");
    assert_contains_text(&contract.carried_blockers, "active TCP UDP DNS");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
    assert_contains_text(
        &contract.validation_commands,
        "runtime stage30-attach-cleanup",
    );
}

#[test]
fn stage30_attach_cleanup_gate_covers_smoke_rows() {
    let contract = stage30_attach_cleanup_gate_contract();
    let areas = contract
        .smoke_rows
        .iter()
        .map(|row| row.area)
        .collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "stage29 preflight dependency",
            "root gate acknowledgement",
            "temporary netns and veth lifecycle",
            "temporary sysctl and tc cleanup",
            "eBPF ABI and reload ownership contract",
            "active traffic and outbound",
            "default path and product chain",
        ]
    );

    assert_contains_text(&contract.source, "runtime_stage30_attach_cleanup.rs");
    assert_contains_text(&contract.source, "active_datapath_runner.rs");
    assert_contains_text(&contract.source, "runtime_stage30/attach_cleanup.json");
    assert_contains_text(&contract.validation_commands, "dae-ebpf-support");
    assert_contains_text(&contract.validation_commands, "dae-control");
}

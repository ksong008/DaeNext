use serde_json::Value;

use crate::*;

#[test]
fn systemd_contract_matches_golden_fixture() {
    let fixture = load("product/install/systemd.json");
    let contract = systemd_contract();

    assert_eq!(
        contract.type_notify,
        fixture["service"]["type_notify"].as_bool().unwrap()
    );
    assert_eq!(
        contract.user_root,
        fixture["service"]["user_root"].as_bool().unwrap()
    );
    assert_eq!(
        contract.limit_nproc,
        fixture["service"]["limit_nproc"].as_str().unwrap()
    );
    assert_eq!(
        contract.limit_nofile,
        fixture["service"]["limit_nofile"].as_str().unwrap()
    );
    assert_eq!(
        contract.exec_start_pre,
        fixture["service"]["exec_start_pre"].as_str().unwrap()
    );
    assert_eq!(
        contract.exec_start,
        fixture["service"]["exec_start"].as_str().unwrap()
    );
    assert_eq!(
        contract.exec_reload,
        fixture["service"]["exec_reload"].as_str().unwrap()
    );
    assert_eq!(
        contract.restart,
        fixture["service"]["restart"].as_str().unwrap()
    );
    assert_eq!(
        contract.timeout_start_sec,
        fixture["service"]["timeout_start_sec"].as_str().unwrap()
    );
    assert_eq!(
        contract.after,
        fixture["service"]["after"].as_str().unwrap()
    );
    assert_eq!(
        contract.wants,
        fixture["service"]["wants"].as_str().unwrap()
    );
    assert_eq!(
        contract.after_install_daemon_reload,
        fixture["package_hooks"]["after_install_daemon_reload"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.after_install_restart_active,
        fixture["package_hooks"]["after_install_restart_active"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.after_remove_daemon_reload,
        fixture["package_hooks"]["after_remove_daemon_reload"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.validate_exec_start_pre,
        fixture["rust_parity"]["validate_exec_start_pre"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.run_systemd_notify,
        fixture["rust_parity"]["run_systemd_notify"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.reload_pid_progress,
        fixture["rust_parity"]["reload_pid_progress"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn release_workflow_contract_matches_golden_fixture() {
    let fixture = load("product/release/workflows.json");
    let contract = release_workflow_contract();
    let release = &fixture["release"];
    assert_eq!(
        contract.prepare_tag_job,
        release["prepare_tag_job"].as_bool().unwrap()
    );
    assert_eq!(
        contract.checks_existing_tag_sha,
        release["checks_existing_tag_sha"].as_bool().unwrap()
    );
    assert_eq!(
        contract.update_tag_gate,
        release["update_tag_gate"].as_bool().unwrap()
    );
    assert_eq!(
        contract.make_latest_input,
        release["make_latest_input"].as_bool().unwrap()
    );
    assert_eq!(
        contract.build_output_pkgdir,
        release["build_output_pkgdir"].as_bool().unwrap()
    );
    assert_eq!(
        contract.installs_systemd_service,
        release["installs_systemd_service"].as_bool().unwrap()
    );
    assert_eq!(
        contract.packages_deb_rpm_pacman,
        release["packages_deb_rpm_pacman"].as_bool().unwrap()
    );
    assert_eq!(
        contract.uploads_release_assets,
        release["uploads_release_assets"].as_bool().unwrap()
    );
    assert_eq!(
        contract.daenew_default_ref,
        fixture["daenew_release"]["default_ref"].as_str().unwrap()
    );
    assert_eq!(
        contract.daenew_default_make_latest_false,
        fixture["daenew_release"]["default_make_latest_false"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.daenew_update_tag_false,
        fixture["daenew_release"]["update_tag_false"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.seed_uses_friendly_filenames,
        fixture["seed_build"]["uses_friendly_filenames"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.seed_smoke_test_amd64_v1,
        fixture["seed_build"]["smoke_test_amd64_v1"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.seed_copies_service_example_geodata,
        fixture["seed_build"]["copies_service_example_geodata"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.maps_386_pacman_to_i486,
        fixture["package_arch"]["maps_386_pacman_to_i486"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.package_arch_assignment_shell_safe,
        fixture["package_arch"]["assignment_shell_safe"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.friendly_keys,
        fixture["friendly_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
}

#[test]
fn release_workflow_package_arch_mapping_is_shell_safe() {
    let root = dae_golden::repo_root_from_manifest().unwrap();
    for workflow in [
        ".github/workflows/release.yml",
        ".github/workflows/prerelease.yml",
    ] {
        let text = std::fs::read_to_string(root.join(workflow)).unwrap();
        assert!(
            !text.contains("pkg_arch'i486'"),
            "{workflow} contains a broken 386 pacman pkg_arch assignment"
        );
        assert!(
            text.contains("'pacman') pkg_arch='i486' ;;"),
            "{workflow} does not map 386 pacman packages to i486"
        );
    }
}

#[test]
fn daed_daewing_contract_matches_golden_fixture() {
    let fixture = load("product/integration/daed_contract.json");
    let contract = daed_daewing_contract();
    assert_eq!(
        contract.required_surfaces,
        fixture["required_surfaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        contract.local_dae_contract_fixed,
        fixture["local_dae_contract_fixed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.cross_repo_write_scope,
        fixture["cross_repo_write_scope"].as_str().unwrap()
    );
}

#[test]
fn outbound_native_migration_contract_matches_golden_fixture() {
    let fixture = load("product/outbound/native_migration_contract.json");
    let contract = outbound_native_migration_contract();
    assert_eq!(
        contract.current_boundary_contains_native_direct_block,
        fixture["current_boundary_contains_native_direct_block"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.current_boundary_contains_bridge_or_stub,
        fixture["current_boundary_contains_bridge_or_stub"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.replacement_rule,
        fixture["replacement_rule"].as_str().unwrap()
    );
    assert_eq!(
        contract.not_silent_complete,
        fixture["not_silent_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.minimum_before_replacing_default_path,
        fixture["minimum_before_replacing_default_path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
}

#[test]
fn daemon_default_readiness_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/default_path_readiness.json");
    let contract = daemon_default_readiness_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(
        contract.stage16_gate_complete,
        fixture["stage16_gate_complete"].as_bool().unwrap()
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
        contract.go_fallback_required,
        fixture["go_fallback_required"].as_bool().unwrap()
    );
    assert_eq!(
        contract.default_switch_decision,
        fixture["default_switch_decision"].as_str().unwrap()
    );
    assert_eq!(contract.rollback, fixture["rollback"].as_str().unwrap());
    assert_eq!(
        contract.optin_surfaces,
        fixture["optin_surfaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        contract.revalidation_required,
        fixture["revalidation_required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        contract.blockers,
        fixture["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        contract.validation_commands,
        fixture["validation_commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        contract.source,
        fixture["source"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
}

#[test]
fn daemon_gray_switch_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage22_gray_switch_gate.json");
    let contract = daemon_gray_switch_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage21_harness_complete,
        fixture["stage21_harness_complete"].as_bool().unwrap()
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
        contract.go_fallback_required,
        fixture["go_fallback_required"].as_bool().unwrap()
    );
    assert_eq!(
        contract.gray_switch_decision,
        fixture["gray_switch_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.allowed_gray_scope, &fixture["allowed_gray_scope"]);
    assert_string_vec(
        &contract.denied_default_scope,
        &fixture["denied_default_scope"],
    );

    let row_fixtures = fixture["readiness_rows"].as_array().unwrap();
    assert_eq!(contract.readiness_rows.len(), row_fixtures.len());
    for (row, row_fixture) in contract.readiness_rows.iter().zip(row_fixtures) {
        assert_eq!(row.area, row_fixture["area"].as_str().unwrap());
        assert_eq!(
            row.current_state,
            row_fixture["current_state"].as_str().unwrap()
        );
        assert_eq!(
            row.gray_switch_status,
            row_fixture["gray_switch_status"].as_str().unwrap()
        );
        assert_string_vec(&row.blockers, &row_fixture["blockers"]);
    }

    assert_string_vec(
        &contract.required_runtime_evidence,
        &fixture["required_runtime_evidence"],
    );
    assert_string_vec(&contract.rollback_controls, &fixture["rollback_controls"]);
    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.source, &fixture["source"]);
}

#[test]
fn daemon_live_evidence_queue_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage22_live_evidence_queue.json");
    let contract = daemon_live_evidence_queue_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.evidence_class,
        fixture["evidence_class"].as_str().unwrap()
    );
    assert_eq!(
        contract.live_evidence_complete,
        fixture["live_evidence_complete"].as_bool().unwrap()
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
        contract.live_daemon_started,
        fixture["live_daemon_started"].as_bool().unwrap()
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
        contract.queue_decision,
        fixture["queue_decision"].as_str().unwrap()
    );
    assert_string_vec(
        &contract.required_environment,
        &fixture["required_environment"],
    );

    let row_fixtures = fixture["queue_rows"].as_array().unwrap();
    assert_eq!(contract.queue_rows.len(), row_fixtures.len());
    for (row, row_fixture) in contract.queue_rows.iter().zip(row_fixtures) {
        assert_eq!(row.area, row_fixture["area"].as_str().unwrap());
        assert_eq!(row.status, row_fixture["status"].as_str().unwrap());
        assert_eq!(
            row.command_or_evidence,
            row_fixture["command_or_evidence"].as_str().unwrap()
        );
        assert_eq!(row.blocker, row_fixture["blocker"].as_str().unwrap());
        assert_eq!(row.rollback, row_fixture["rollback"].as_str().unwrap());
    }

    assert_string_vec(&contract.rollback_controls, &fixture["rollback_controls"]);
    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.source, &fixture["source"]);
}

#[test]
fn product_chain_admission_contract_matches_golden_fixture() {
    let fixture = load("product/integration/stage23_product_chain_admission.json");
    let contract = product_chain_admission_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.queue_complete,
        fixture["queue_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.product_chain_switch_allowed,
        fixture["product_chain_switch_allowed"].as_bool().unwrap()
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
        contract.go_fallback_required,
        fixture["go_fallback_required"].as_bool().unwrap()
    );
    assert_eq!(
        contract.daemon_live_evidence_complete,
        fixture["daemon_live_evidence_complete"].as_bool().unwrap()
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
        assert_eq!(row.blocker, row_fixture["blocker"].as_str().unwrap());
        assert_eq!(
            row.next_action,
            row_fixture["next_action"].as_str().unwrap()
        );
    }

    assert_string_vec(&contract.rollback_controls, &fixture["rollback_controls"]);
    assert_string_vec(
        &contract.validation_commands,
        &fixture["validation_commands"],
    );
    assert_string_vec(&contract.source, &fixture["source"]);
}

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

fn load(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}

fn assert_string_vec(actual: &[&str], fixture: &Value) {
    let expected = fixture
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected.as_slice());
}

fn assert_contains_text(values: &[&str], needle: &str) {
    assert!(
        values.iter().any(|value| value.contains(needle)),
        "expected one of {values:?} to contain {needle:?}"
    );
}

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

#[test]
fn stage50_active_tcp_ingress_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage50_active_tcp_ingress_gate.json");
    let contract = stage50_active_tcp_ingress_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.active_tcp_tproxy_ingress_recorded,
        fixture["active_tcp_tproxy_ingress_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_tcp_syn_reached_transparent_listener_recorded,
        fixture["active_tcp_syn_reached_transparent_listener_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.original_destination_recorded,
        fixture["original_destination_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.tcp_reply_path_recorded,
        fixture["tcp_reply_path_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.route_dial_tcp_rust_control_plane_recorded,
        fixture["route_dial_tcp_rust_control_plane_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.outbound_relay_recorded,
        fixture["outbound_relay_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.so_mark_mptcp_real_outbound_socket_recorded,
        fixture["so_mark_mptcp_real_outbound_socket_recorded"]
            .as_bool()
            .unwrap()
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
fn stage50_active_tcp_ingress_gate_blocks_default_admission() {
    let contract = stage50_active_tcp_ingress_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.active_tcp_tproxy_ingress_recorded);
    assert!(contract.active_tcp_syn_reached_transparent_listener_recorded);
    assert!(contract.original_destination_recorded);
    assert!(contract.tcp_reply_path_recorded);
    assert!(!contract.route_dial_tcp_rust_control_plane_recorded);
    assert!(!contract.outbound_relay_recorded);
    assert!(!contract.so_mark_mptcp_real_outbound_socket_recorded);
    assert!(!contract.active_udp_tproxy_admitted);
    assert!(!contract.active_dns_tproxy_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(
        &contract.carried_blockers,
        "RouteDialTcp Rust control-plane",
    );
    assert_contains_text(&contract.carried_blockers, "SO_MARK and MPTCP");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
}

#[test]
fn stage50_active_tcp_ingress_gate_covers_rows() {
    let contract = stage50_active_tcp_ingress_gate_contract();
    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "LAN ingress to transparent TCP listener",
            "original destination and reply smoke"
        ]
    );
    assert_contains_text(&contract.source, "runtime_stage50_tcp_gate.rs");
    assert_contains_text(&contract.source, "runtime_maps.rs");
    assert_contains_text(
        &contract.validation_commands,
        "stage50-active-tcp-tproxy-ingress-admission",
    );
}

#[test]
fn stage51_active_tcp_relay_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage51_active_tcp_relay_gate.json");
    let contract = stage51_active_tcp_relay_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.active_tcp_tproxy_ingress_recorded,
        fixture["active_tcp_tproxy_ingress_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.original_destination_recorded,
        fixture["original_destination_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.route_dial_tcp_direct_path_recorded,
        fixture["route_dial_tcp_direct_path_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.route_dial_tcp_rust_control_plane_recorded,
        fixture["route_dial_tcp_rust_control_plane_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.outbound_relay_recorded,
        fixture["outbound_relay_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.so_mark_mptcp_real_outbound_socket_recorded,
        fixture["so_mark_mptcp_real_outbound_socket_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_tcp_relay_benchmark_recorded,
        fixture["active_tcp_relay_benchmark_recorded"]
            .as_bool()
            .unwrap()
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
fn stage51_active_tcp_relay_gate_blocks_default_admission() {
    let contract = stage51_active_tcp_relay_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.active_tcp_tproxy_ingress_recorded);
    assert!(contract.original_destination_recorded);
    assert!(contract.route_dial_tcp_direct_path_recorded);
    assert!(!contract.route_dial_tcp_rust_control_plane_recorded);
    assert!(contract.outbound_relay_recorded);
    assert!(contract.so_mark_mptcp_real_outbound_socket_recorded);
    assert!(contract.active_tcp_relay_benchmark_recorded);
    assert!(!contract.active_udp_tproxy_admitted);
    assert!(!contract.active_dns_tproxy_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "Full RouteDialTcp");
    assert_contains_text(&contract.carried_blockers, "active UDP");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
}

#[test]
fn stage51_active_tcp_relay_gate_covers_rows() {
    let contract = stage51_active_tcp_relay_gate_contract();
    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "transparent accept to Rust direct outbound relay",
            "SO_MARK and MPTCP outbound socket",
            "active TCP relay benchmark"
        ]
    );
    assert_contains_text(&contract.source, "runtime_stage50_tcp_gate.rs");
    assert_contains_text(&contract.source, "tcp_direct.rs");
    assert_contains_text(
        &contract.validation_commands,
        "stage51-active-tcp-route-dial-relay-admission",
    );
}

#[test]
fn stage52_active_tcp_route_table_group_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage52_active_tcp_route_table_group_gate.json");
    let contract = stage52_active_tcp_route_table_group_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.active_tcp_tproxy_ingress_recorded,
        fixture["active_tcp_tproxy_ingress_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.original_destination_recorded,
        fixture["original_destination_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.route_dial_tcp_route_table_recorded,
        fixture["route_dial_tcp_route_table_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.choose_dial_target_recorded,
        fixture["choose_dial_target_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.outbound_group_selection_recorded,
        fixture["outbound_group_selection_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.route_dial_tcp_rust_control_plane_recorded,
        fixture["route_dial_tcp_rust_control_plane_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.outbound_relay_recorded,
        fixture["outbound_relay_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.so_mark_mptcp_real_outbound_socket_recorded,
        fixture["so_mark_mptcp_real_outbound_socket_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_tcp_route_table_group_benchmark_recorded,
        fixture["active_tcp_route_table_group_benchmark_recorded"]
            .as_bool()
            .unwrap()
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
fn stage52_active_tcp_route_table_group_gate_blocks_default_admission() {
    let contract = stage52_active_tcp_route_table_group_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.active_tcp_tproxy_ingress_recorded);
    assert!(contract.original_destination_recorded);
    assert!(contract.route_dial_tcp_route_table_recorded);
    assert!(contract.choose_dial_target_recorded);
    assert!(contract.outbound_group_selection_recorded);
    assert!(contract.route_dial_tcp_rust_control_plane_recorded);
    assert!(contract.outbound_relay_recorded);
    assert!(contract.so_mark_mptcp_real_outbound_socket_recorded);
    assert!(contract.active_tcp_route_table_group_benchmark_recorded);
    assert!(!contract.active_udp_tproxy_admitted);
    assert!(!contract.active_dns_tproxy_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "active UDP");
    assert_contains_text(&contract.carried_blockers, "bounded direct loopback");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
}

#[test]
fn stage52_active_tcp_route_table_group_gate_covers_rows() {
    let contract = stage52_active_tcp_route_table_group_gate_contract();
    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "RouteDialTcp userspace reroute",
            "outbound group min selection",
            "route-aware active TCP relay benchmark"
        ]
    );
    assert_contains_text(&contract.source, "runtime_stage50_tcp_gate.rs");
    assert_contains_text(&contract.source, "tcp_route_dial.rs");
    assert_contains_text(
        &contract.validation_commands,
        "stage52-active-tcp-route-table-group-relay-admission",
    );
}

#[test]
fn stage53_active_udp_tproxy_endpoint_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage53_active_udp_tproxy_endpoint_gate.json");
    let contract = stage53_active_udp_tproxy_endpoint_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.active_tcp_tproxy_ingress_recorded,
        fixture["active_tcp_tproxy_ingress_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.original_destination_recorded,
        fixture["original_destination_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.route_dial_tcp_route_table_recorded,
        fixture["route_dial_tcp_route_table_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.choose_dial_target_recorded,
        fixture["choose_dial_target_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.outbound_group_selection_recorded,
        fixture["outbound_group_selection_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.route_dial_tcp_rust_control_plane_recorded,
        fixture["route_dial_tcp_rust_control_plane_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.outbound_relay_recorded,
        fixture["outbound_relay_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.so_mark_mptcp_real_outbound_socket_recorded,
        fixture["so_mark_mptcp_real_outbound_socket_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_tcp_route_table_group_benchmark_recorded,
        fixture["active_tcp_route_table_group_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_udp_tproxy_admitted,
        fixture["active_udp_tproxy_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.active_udp_original_destination_recorded,
        fixture["active_udp_original_destination_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.udp_endpoint_pool_live_recorded,
        fixture["udp_endpoint_pool_live_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.udp_packetconn_write_read_recorded,
        fixture["udp_packetconn_write_read_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.udp_sendpkt_reply_recorded,
        fixture["udp_sendpkt_reply_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.udp_so_mark_real_outbound_socket_recorded,
        fixture["udp_so_mark_real_outbound_socket_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_udp_tproxy_benchmark_recorded,
        fixture["active_udp_tproxy_benchmark_recorded"]
            .as_bool()
            .unwrap()
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
fn stage53_active_udp_tproxy_endpoint_gate_blocks_default_admission() {
    let contract = stage53_active_udp_tproxy_endpoint_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.active_tcp_tproxy_ingress_recorded);
    assert!(contract.original_destination_recorded);
    assert!(contract.route_dial_tcp_route_table_recorded);
    assert!(contract.choose_dial_target_recorded);
    assert!(contract.outbound_group_selection_recorded);
    assert!(contract.route_dial_tcp_rust_control_plane_recorded);
    assert!(contract.outbound_relay_recorded);
    assert!(contract.so_mark_mptcp_real_outbound_socket_recorded);
    assert!(contract.active_tcp_route_table_group_benchmark_recorded);
    assert!(contract.active_udp_tproxy_admitted);
    assert!(contract.active_udp_original_destination_recorded);
    assert!(contract.udp_endpoint_pool_live_recorded);
    assert!(contract.udp_packetconn_write_read_recorded);
    assert!(contract.udp_sendpkt_reply_recorded);
    assert!(contract.udp_so_mark_real_outbound_socket_recorded);
    assert!(contract.active_udp_tproxy_benchmark_recorded);
    assert!(!contract.active_dns_tproxy_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "active DNS UDP/53");
    assert_contains_text(&contract.carried_blockers, "protocol true dataplane");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
}

#[test]
fn stage53_active_udp_tproxy_endpoint_gate_covers_rows() {
    let contract = stage53_active_udp_tproxy_endpoint_gate_contract();
    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "active UDP transparent receive",
            "UDP endpoint pool full-cone key",
            "UDP PacketConn outbound socket",
            "sendPkt-style reply and benchmark"
        ]
    );
    assert_contains_text(&contract.source, "runtime_stage50_tcp_gate.rs");
    assert_contains_text(&contract.source, "udp_direct.rs");
    assert_contains_text(&contract.source, "tproxy_listener.rs");
    assert_contains_text(
        &contract.validation_commands,
        "stage53-active-udp-tproxy-endpoint-admission",
    );
}

#[test]
fn stage54_active_dns_tproxy_cache_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage54_active_dns_tproxy_cache_gate.json");
    let contract = stage54_active_dns_tproxy_cache_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
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
        contract.active_dns_original_destination_recorded,
        fixture["active_dns_original_destination_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.dns_controller_path_recorded,
        fixture["dns_controller_path_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.dns_upstream_query_recorded,
        fixture["dns_upstream_query_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.dns_response_validation_recorded,
        fixture["dns_response_validation_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.dns_cache_restore_recorded,
        fixture["dns_cache_restore_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.domain_routing_owner_migration_recorded,
        fixture["domain_routing_owner_migration_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.dns_sendpkt_reply_recorded,
        fixture["dns_sendpkt_reply_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.dns_so_mark_upstream_socket_recorded,
        fixture["dns_so_mark_upstream_socket_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_dns_tproxy_benchmark_recorded,
        fixture["active_dns_tproxy_benchmark_recorded"]
            .as_bool()
            .unwrap()
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
fn stage54_active_dns_tproxy_cache_gate_blocks_default_admission() {
    let contract = stage54_active_dns_tproxy_cache_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.active_udp_tproxy_admitted);
    assert!(contract.active_dns_tproxy_admitted);
    assert!(contract.active_dns_original_destination_recorded);
    assert!(contract.dns_controller_path_recorded);
    assert!(contract.dns_upstream_query_recorded);
    assert!(contract.dns_response_validation_recorded);
    assert!(contract.dns_cache_restore_recorded);
    assert!(contract.domain_routing_owner_migration_recorded);
    assert!(contract.dns_sendpkt_reply_recorded);
    assert!(contract.dns_so_mark_upstream_socket_recorded);
    assert!(contract.active_dns_tproxy_benchmark_recorded);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "protocol true dataplane");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
}

#[test]
fn stage54_active_dns_tproxy_cache_gate_covers_rows() {
    let contract = stage54_active_dns_tproxy_cache_gate_contract();
    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "transparent DNS UDP/53 receive",
            "DNS upstream and response validation",
            "reload DNS cache and domain routing owner",
            "DNS sendPkt reply and benchmark"
        ]
    );
    assert_contains_text(&contract.source, "runtime_stage50_tcp_gate.rs");
    assert_contains_text(&contract.source, "cache.rs");
    assert_contains_text(&contract.source, "domain_routing.rs");
    assert_contains_text(
        &contract.validation_commands,
        "stage54-active-dns-tproxy-cache-admission",
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

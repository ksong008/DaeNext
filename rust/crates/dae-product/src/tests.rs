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

fn load(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}

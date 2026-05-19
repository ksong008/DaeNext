use super::*;

#[test]
fn stage26_candidate_plan_matches_golden_fixture() {
    let fixture = load("engine/runtime_stage26/candidate_plan.json");
    let candidate_plan = run_with_args([
        "runtime",
        "stage26-candidate-plan",
        "--root",
        fixture["root"].as_str().unwrap(),
    ]);
    assert_eq!(candidate_plan.exit_code, 0);
    assert_eq!(candidate_plan.stderr, "");
    let plan_json: Value = serde_json::from_str(&candidate_plan.stdout).unwrap();
    assert_eq!(
        plan_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        plan_json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        plan_json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert_eq!(
        plan_json["default_switch_allowed"].as_bool().unwrap(),
        fixture["default_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        plan_json["default_path_mutated"].as_bool().unwrap(),
        fixture["default_path_mutated"].as_bool().unwrap()
    );
    assert!(!plan_json["candidate_live_run_allowed"].as_bool().unwrap());
    assert_eq!(
        plan_json["live_daemon_started"].as_bool().unwrap(),
        fixture["live_daemon_started"].as_bool().unwrap()
    );
    assert_eq!(
        plan_json["go_default_path_preserved"].as_bool().unwrap(),
        fixture["go_default_path_preserved"].as_bool().unwrap()
    );
    assert_eq!(
        plan_json["go_fallback_required"].as_bool().unwrap(),
        fixture["go_fallback_required"].as_bool().unwrap()
    );
    assert_eq!(
        plan_json["write_requested"].as_bool().unwrap(),
        fixture["write_requested"].as_bool().unwrap()
    );
    assert_eq!(
        plan_json["candidate"]["artifact_binary"].as_str().unwrap(),
        fixture["candidate"]["artifact_binary"].as_str().unwrap()
    );
    assert_eq!(
        plan_json["candidate"]["current_default_owner"]
            .as_str()
            .unwrap(),
        fixture["candidate"]["current_default_owner"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        plan_json["candidate"]["requires_explicit_selector"]
            .as_bool()
            .unwrap(),
        fixture["candidate"]["requires_explicit_selector"]
            .as_bool()
            .unwrap()
    );
    assert!(!plan_json["candidate"]["starts_daemon"].as_bool().unwrap());
    assert_eq!(
        plan_json["selector_contract"]["accepted_selector"]
            .as_str()
            .unwrap(),
        fixture["selector_contract"]["accepted_selector"]
            .as_str()
            .unwrap()
    );
    assert!(
        plan_json["selector_contract"]["default_alias_forbidden"]
            .as_bool()
            .unwrap()
    );
    assert!(
        plan_json["selector_contract"]["product_chain_switch_forbidden"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        plan_json["paths"]["config"].as_str().unwrap(),
        fixture["paths"]["config"].as_str().unwrap()
    );
    assert_eq!(
        plan_json["paths"]["candidate_progress_file"]
            .as_str()
            .unwrap(),
        fixture["paths"]["candidate_progress_file"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        plan_json["paths"]["go_progress_file_fixed"]
            .as_str()
            .unwrap(),
        fixture["paths"]["go_progress_file_fixed"].as_str().unwrap()
    );
    assert_eq!(
        plan_json["minimum_config"]["tproxy_port"].as_u64().unwrap(),
        fixture["config"]["tproxy_port"].as_u64().unwrap()
    );
    assert_eq!(
        plan_json["minimum_config"]["so_mark_from_dae"]
            .as_u64()
            .unwrap(),
        fixture["config"]["so_mark_from_dae"].as_u64().unwrap()
    );
    assert_eq!(
        plan_json["minimum_config"]["mptcp"].as_bool().unwrap(),
        fixture["config"]["mptcp"].as_bool().unwrap()
    );
    assert!(
        plan_json["minimum_config"]["text"]
            .as_str()
            .unwrap()
            .contains("daex26lan0")
    );
    assert!(
        plan_json["production_safety"]["no_systemd_mutation"]
            .as_bool()
            .unwrap()
    );
    assert!(
        plan_json["production_safety"]["does_not_start_daemon"]
            .as_bool()
            .unwrap()
    );
    assert!(
        plan_json["production_safety"]["requires_progress_override_before_candidate_live_run"]
            .as_bool()
            .unwrap()
    );

    let inventory_names = plan_json["inventory"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        inventory_names,
        fixture["inventory"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    let go_command_names = plan_json["go_baseline_commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        go_command_names,
        fixture["go_baseline_commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    let candidate_commands = plan_json["candidate_commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| {
            (
                value["name"].as_str().unwrap(),
                value["status"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert!(
        candidate_commands.contains(&(
            fixture["candidate_commands"]["write_layout"]
                .as_str()
                .unwrap(),
            "ready-with-write-flag",
        ))
    );
    assert!(candidate_commands.contains(&("candidate-run", "blocked-unimplemented")));

    let plan_root = std::env::temp_dir().join(format!(
        "dae-stage26-candidate-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let plan_root_string = plan_root.to_string_lossy().into_owned();
    let write_plan = run_with_args([
        "runtime",
        "stage26-candidate-plan",
        "--root",
        &plan_root_string,
        "--artifact-binary",
        "/bin/true",
        "--write",
    ]);
    assert_eq!(write_plan.exit_code, 0, "{}", write_plan.stdout);
    assert_eq!(write_plan.stderr, "");
    let write_plan_json: Value = serde_json::from_str(&write_plan.stdout).unwrap();
    assert!(write_plan_json["write_requested"].as_bool().unwrap());
    assert!(write_plan_json["files_written"].as_array().unwrap().len() >= 2);
    assert!(!write_plan_json["live_daemon_started"].as_bool().unwrap());
    let config_path = plan_root.join("config.dae");
    assert!(config_path.exists());
    let validate_written = run_with_args(["validate", "-c", config_path.to_str().unwrap()]);
    assert_eq!(validate_written.exit_code, 0, "{}", validate_written.stdout);
    let _ = fs::remove_dir_all(plan_root);
}

#[test]
fn stage27_run_candidate_matches_golden_fixture() {
    let fixture = load("engine/runtime_stage27/run_candidate.json");
    let root = PathBuf::from(fixture["root"].as_str().unwrap());
    let root_string = root.to_string_lossy().into_owned();
    let _ = fs::remove_dir_all(&root);
    let plan = run_with_args([
        "runtime",
        "stage26-candidate-plan",
        "--root",
        &root_string,
        "--write",
    ]);
    assert_eq!(plan.exit_code, 0, "{}", plan.stdout);
    assert_eq!(plan.stderr, "");

    let candidate = run_with_args(["runtime", "stage27-run-candidate", "--root", &root_string]);
    assert_eq!(candidate.exit_code, 0, "{}", candidate.stdout);
    assert_eq!(candidate.stderr, "");
    let candidate_json: Value = serde_json::from_str(&candidate.stdout).unwrap();
    assert_eq!(
        candidate_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        candidate_json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        candidate_json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert_eq!(
        candidate_json["default_switch_allowed"].as_bool().unwrap(),
        fixture["default_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        candidate_json["default_path_mutated"].as_bool().unwrap(),
        fixture["default_path_mutated"].as_bool().unwrap()
    );
    assert_eq!(
        candidate_json["product_chain_switch_allowed"]
            .as_bool()
            .unwrap(),
        fixture["product_chain_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        candidate_json["candidate_live_run_class"].as_str().unwrap(),
        fixture["candidate_live_run_class"].as_str().unwrap()
    );
    assert_eq!(
        candidate_json["candidate_smoke_passed"].as_bool().unwrap(),
        fixture["candidate_smoke_passed"].as_bool().unwrap()
    );
    assert_eq!(
        candidate_json["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap(),
        fixture["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        candidate_json["go_default_path_preserved"]
            .as_bool()
            .unwrap(),
        fixture["go_default_path_preserved"].as_bool().unwrap()
    );
    assert_eq!(
        candidate_json["go_fallback_required"].as_bool().unwrap(),
        fixture["go_fallback_required"].as_bool().unwrap()
    );
    assert!(!candidate_json["live_tproxy_started"].as_bool().unwrap());
    assert!(!candidate_json["live_ebpf_started"].as_bool().unwrap());
    assert!(!candidate_json["live_outbound_started"].as_bool().unwrap());
    assert!(
        !candidate_json["live_dns_listener_started"]
            .as_bool()
            .unwrap()
    );

    assert_eq!(
        candidate_json["paths"]["config"].as_str().unwrap(),
        fixture["paths"]["config"].as_str().unwrap()
    );
    assert_eq!(
        candidate_json["paths"]["pid_file"].as_str().unwrap(),
        fixture["paths"]["pid_file"].as_str().unwrap()
    );
    assert_eq!(
        candidate_json["paths"]["progress_file"].as_str().unwrap(),
        fixture["paths"]["progress_file"].as_str().unwrap()
    );
    assert_eq!(
        candidate_json["paths"]["log_file"].as_str().unwrap(),
        fixture["paths"]["log_file"].as_str().unwrap()
    );
    assert_eq!(
        candidate_json["runtime"]["progress_first_byte"]
            .as_str()
            .unwrap(),
        fixture["runtime"]["progress_first_byte"].as_str().unwrap()
    );
    assert!(candidate_json["runtime"]["config_valid"].as_bool().unwrap());
    assert!(
        candidate_json["runtime"]["pid_file_written"]
            .as_bool()
            .unwrap()
    );
    assert!(
        candidate_json["runtime"]["dry_runtime_started"]
            .as_bool()
            .unwrap()
    );
    assert!(
        candidate_json["runtime"]["reload_requested"]
            .as_bool()
            .unwrap()
    );
    assert!(candidate_json["runtime"]["reload_ok"].as_bool().unwrap());
    assert!(
        candidate_json["runtime"]["stop_requested"]
            .as_bool()
            .unwrap()
    );
    assert!(candidate_json["runtime"]["stop_ok"].as_bool().unwrap());
    assert!(
        candidate_json["runtime"]["run_thread_ok"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        candidate_json["runtime"]["timeout_ms"].as_u64().unwrap(),
        fixture["runtime"]["timeout_ms"].as_u64().unwrap()
    );
    assert!(
        candidate_json["runtime"]["progress_content"]
            .as_str()
            .unwrap()
            .starts_with("2\nstage27 dry runtime candidate done")
    );
    assert!(
        candidate_json["production_safety"]["does_not_touch_var_run_dae_progress"]
            .as_bool()
            .unwrap()
    );
    assert!(
        candidate_json["production_safety"]["does_not_touch_var_run_dae_pid"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        candidate_json["remaining_blockers"]
            .as_array()
            .unwrap()
            .len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
    assert!(root.join("run").join("dae-stage27.pid").exists());
    assert!(root.join("run").join("dae-stage27.progress").exists());
    assert!(root.join("logs").join("dae-stage27.log").exists());

    let blocked = run_with_args(["runtime", "stage27-run-candidate", "--root", "/var/tmp/dae"]);
    assert_eq!(blocked.exit_code, 1);
    assert!(blocked.stdout.contains("must stay under /tmp"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn stage29_host_preflight_matches_golden_fixture() {
    let fixture = load("engine/runtime_stage29/host_preflight.json");
    let preflight = run_with_args([
        "runtime",
        "stage29-host-preflight",
        "--root",
        fixture["root"].as_str().unwrap(),
    ]);
    assert_eq!(preflight.exit_code, 0, "{}", preflight.stdout);
    assert_eq!(preflight.stderr, "");
    let preflight_json: Value = serde_json::from_str(&preflight.stdout).unwrap();
    assert_eq!(
        preflight_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        preflight_json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        preflight_json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert_eq!(
        preflight_json["root"].as_str().unwrap(),
        fixture["root"].as_str().unwrap()
    );
    assert_eq!(
        preflight_json["host_probe_executed"].as_bool().unwrap(),
        fixture["host_probe_executed"].as_bool().unwrap()
    );
    assert_eq!(
        preflight_json["require_existing_config"].as_bool().unwrap(),
        fixture["require_existing_config"].as_bool().unwrap()
    );
    assert!(preflight_json["read_only"].as_bool().unwrap());
    assert!(!preflight_json["preflight_passed"].as_bool().unwrap());
    assert!(
        !preflight_json["live_candidate_run_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(!preflight_json["default_switch_allowed"].as_bool().unwrap());
    assert!(!preflight_json["default_path_mutated"].as_bool().unwrap());
    assert!(
        !preflight_json["product_chain_switch_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !preflight_json["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        preflight_json["go_default_path_preserved"]
            .as_bool()
            .unwrap()
    );
    assert!(preflight_json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(preflight_json["blockers"].as_array().unwrap().len(), 0);

    assert_eq!(
        preflight_json["paths"]["config"].as_str().unwrap(),
        fixture["paths"]["config"].as_str().unwrap()
    );
    assert_eq!(
        preflight_json["paths"]["progress_file"].as_str().unwrap(),
        fixture["paths"]["progress_file"].as_str().unwrap()
    );
    assert_eq!(
        preflight_json["paths"]["production_progress_file_checked_when_probe_host"]
            .as_str()
            .unwrap(),
        "/var/run/dae.progress"
    );
    assert_eq!(
        preflight_json["inputs"]["tproxy_port"].as_u64().unwrap(),
        fixture["inputs"]["tproxy_port"].as_u64().unwrap()
    );
    assert!(preflight_json["inputs"]["mptcp"].as_bool().unwrap());
    assert_eq!(
        preflight_json["inputs"]["so_mark_from_dae"]
            .as_u64()
            .unwrap(),
        2234
    );

    let path_checks = preflight_json["path_checks"].as_array().unwrap();
    let fixture_path_checks = fixture["path_checks"].as_array().unwrap();
    assert_eq!(path_checks.len(), fixture_path_checks.len());
    let path_names = path_checks
        .iter()
        .map(|value| {
            (
                value["name"].as_str().unwrap(),
                value["status"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        path_names,
        fixture_path_checks
            .iter()
            .map(|value| (
                value["name"].as_str().unwrap(),
                value["status"].as_str().unwrap()
            ))
            .collect::<Vec<_>>()
    );
    assert!(path_names.contains(&("isolated-root-under-tmp", "pass")));
    assert!(path_names.contains(&("generated-minimum-config-valid", "pass")));
    assert!(path_names.contains(&("existing-isolated-config-valid", "not-run")));

    let host_checks = preflight_json["host_checks"].as_array().unwrap();
    assert_eq!(
        host_checks.len(),
        fixture["host_checks"].as_array().unwrap().len()
    );
    assert!(
        host_checks
            .iter()
            .all(|value| value["status"].as_str().unwrap() == "not-run")
    );
    assert!(
        preflight_json["production_safety"]["host_probe_requires_explicit_flag"]
            .as_bool()
            .unwrap()
    );
    assert!(
        preflight_json["production_safety"]["no_ebpf_attach"]
            .as_bool()
            .unwrap()
    );
    assert!(
        preflight_json["production_safety"]["no_netns_mutation"]
            .as_bool()
            .unwrap()
    );
    assert!(
        preflight_json["next_if_clear"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str().unwrap().contains("--probe-host output"))
    );
}

#[test]
fn stage30_attach_cleanup_matches_golden_fixture() {
    let fixture = load("engine/runtime_stage30/attach_cleanup.json");
    let cleanup = run_with_args([
        "runtime",
        "stage30-attach-cleanup",
        "--root",
        fixture["root"].as_str().unwrap(),
    ]);
    assert_eq!(cleanup.exit_code, 0, "{}", cleanup.stdout);
    assert_eq!(cleanup.stderr, "");
    let cleanup_json: Value = serde_json::from_str(&cleanup.stdout).unwrap();
    assert_eq!(
        cleanup_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        cleanup_json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        cleanup_json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert_eq!(
        cleanup_json["root"].as_str().unwrap(),
        fixture["root"].as_str().unwrap()
    );
    assert!(!cleanup_json["execute_smoke"].as_bool().unwrap());
    assert!(cleanup_json["read_only"].as_bool().unwrap());
    assert!(!cleanup_json["blocked"].as_bool().unwrap());
    assert!(!cleanup_json["smoke_passed"].as_bool().unwrap());
    assert!(
        !cleanup_json["live_candidate_run_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !cleanup_json["actual_dae_ebpf_program_attach_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !cleanup_json["active_traffic_evidence_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!cleanup_json["default_switch_allowed"].as_bool().unwrap());
    assert!(!cleanup_json["default_path_mutated"].as_bool().unwrap());
    assert!(
        !cleanup_json["product_chain_switch_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !cleanup_json["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(cleanup_json["go_default_path_preserved"].as_bool().unwrap());
    assert!(cleanup_json["go_fallback_required"].as_bool().unwrap());

    let checks = cleanup_json["checks"].as_array().unwrap();
    let fixture_checks = fixture["checks"].as_array().unwrap();
    assert_eq!(checks.len(), fixture_checks.len());
    let check_statuses = checks
        .iter()
        .map(|value| {
            (
                value["name"].as_str().unwrap(),
                value["status"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        check_statuses,
        fixture_checks
            .iter()
            .map(|value| (
                value["name"].as_str().unwrap(),
                value["status"].as_str().unwrap()
            ))
            .collect::<Vec<_>>()
    );
    assert!(check_statuses.contains(&("isolated-root-under-tmp", "pass")));
    assert!(check_statuses.contains(&("root-gate-acknowledged", "pass")));
    assert!(check_statuses.contains(&("stage29-preflight-report-passed", "pass")));

    assert_eq!(
        cleanup_json["temporary_resources"]["leftovers_after_cleanup"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        cleanup_json["ebpf_contract"]["listen_socket_map_keys"],
        fixture["ebpf_contract"]["listen_socket_map_keys"]
    );
    assert!(
        cleanup_json["ebpf_contract"]["dae_program_attach_deferred"]
            .as_bool()
            .unwrap()
    );
    assert!(
        cleanup_json["production_safety"]["no_sys_fs_bpf_dae_mutation"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        cleanup_json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage30_attach_cleanup_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage30-attach-cleanup",
        "--root",
        "/tmp/dae-stage30-candidate",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("root-gated smoke requires --ack-root-gate")
    );
    assert!(blocked.stderr.is_empty());

    let production_names = run_with_args([
        "runtime",
        "stage30-attach-cleanup",
        "--root",
        "/tmp/dae-stage30-candidate",
        "--host-iface",
        "dae0",
        "--peer-iface",
        "dae0peer",
        "--netns",
        "daens",
    ]);
    assert_eq!(production_names.exit_code, 0);
    let production_json: Value = serde_json::from_str(&production_names.stdout).unwrap();
    assert!(production_json["blocked"].as_bool().unwrap());
    assert!(
        production_json["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value
                .as_str()
                .unwrap()
                .contains("production dae0/dae0peer/daens"))
    );
    assert!(!production_json["default_path_mutated"].as_bool().unwrap());
    assert!(
        !production_json["actual_dae_ebpf_program_attach_executed"]
            .as_bool()
            .unwrap()
    );
}

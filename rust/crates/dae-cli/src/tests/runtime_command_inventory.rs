use super::*;

#[test]
fn optin_runner_runtime_commands_match_engine_fixtures() {
    let dry = run_with_args(["runtime", "dry-run-smoke"]);
    assert_eq!(dry.exit_code, 0);
    assert_eq!(dry.stdout, "");
    assert_eq!(dry.stderr, "");

    let target_fixture = load("engine/route_aware/target.json");
    let route = run_with_args([
        "runtime",
        "route-target",
        "--host",
        "example.com",
        "--port",
        "443",
    ]);
    assert_eq!(route.exit_code, 0);
    assert_eq!(route.stderr, "");
    let route_json: Value = serde_json::from_str(&route.stdout).unwrap();
    let domain_case = target_fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "domain")
        .unwrap();
    assert_eq!(
        route_json["domain"].as_str().unwrap(),
        domain_case["domain"].as_str().unwrap()
    );
    assert_eq!(
        route_json["dest"].as_str().unwrap(),
        domain_case["dest"].as_str().unwrap()
    );
    assert_eq!(
        route_json["dest_is_unspecified"].as_bool().unwrap(),
        domain_case["dest_is_unspecified"].as_bool().unwrap()
    );

    let overview_fixture = load("engine/runtime_overview/basic.json");
    let overview = run_with_args(["runtime", "overview-basic"]);
    assert_eq!(overview.exit_code, 0);
    assert_eq!(overview.stderr, "");
    let overview_json: Value = serde_json::from_str(&overview.stdout).unwrap();
    let no_control = &overview_fixture["no_control_plane"];
    assert_eq!(
        overview_json["dns_cache_hit_total"].as_u64().unwrap(),
        no_control["dns_cache_hit_total"].as_u64().unwrap()
    );
    assert_eq!(
        overview_json["samples"][0]["upload_rate"].as_u64().unwrap(),
        no_control["samples"][0]["upload_rate"].as_u64().unwrap()
    );

    let stage22_fixture = load("engine/runtime_stage22/smoke_helper.json");
    let stage22 = run_with_args(["runtime", "stage22-smoke"]);
    assert_eq!(stage22.exit_code, 0);
    assert_eq!(stage22.stderr, "");
    let stage22_json: Value = serde_json::from_str(&stage22.stdout).unwrap();
    assert_eq!(
        stage22_json["name"].as_str().unwrap(),
        stage22_fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        stage22_json["evidence_class"].as_str().unwrap(),
        stage22_fixture["evidence_class"].as_str().unwrap()
    );
    assert_eq!(
        stage22_json["default_switch_allowed"].as_bool().unwrap(),
        stage22_fixture["default_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        stage22_json["go_default_path_preserved"].as_bool().unwrap(),
        stage22_fixture["go_default_path_preserved"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        stage22_json["default_path_mutated"].as_bool().unwrap(),
        stage22_fixture["default_path_mutated"].as_bool().unwrap()
    );
    assert_eq!(
        stage22_json["live_daemon_started"].as_bool().unwrap(),
        stage22_fixture["live_daemon_started"].as_bool().unwrap()
    );
    assert_eq!(
        stage22_json["route_aware"]["dest"].as_str().unwrap(),
        stage22_fixture["route_aware"]["dest"].as_str().unwrap()
    );
    assert_eq!(
        stage22_json["overview"]["udp_task_queues"]
            .as_u64()
            .unwrap(),
        stage22_fixture["overview"]["udp_task_queues"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        stage22_json["remaining_runtime_evidence"]
            .as_array()
            .unwrap()
            .len(),
        stage22_fixture["remaining_runtime_evidence"]
            .as_array()
            .unwrap()
            .len()
    );

    let live_plan_fixture = load("engine/runtime_stage22/live_plan.json");
    let live_plan = run_with_args([
        "runtime",
        "stage22-live-plan",
        "--root",
        live_plan_fixture["root"].as_str().unwrap(),
    ]);
    assert_eq!(live_plan.exit_code, 0);
    assert_eq!(live_plan.stderr, "");
    let live_plan_json: Value = serde_json::from_str(&live_plan.stdout).unwrap();
    assert_eq!(
        live_plan_json["name"].as_str().unwrap(),
        live_plan_fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        live_plan_json["evidence_class"].as_str().unwrap(),
        live_plan_fixture["evidence_class"].as_str().unwrap()
    );
    assert_eq!(
        live_plan_json["default_switch_allowed"].as_bool().unwrap(),
        live_plan_fixture["default_switch_allowed"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        live_plan_json["default_path_mutated"].as_bool().unwrap(),
        live_plan_fixture["default_path_mutated"].as_bool().unwrap()
    );
    assert_eq!(
        live_plan_json["live_daemon_started"].as_bool().unwrap(),
        live_plan_fixture["live_daemon_started"].as_bool().unwrap()
    );
    assert_eq!(
        live_plan_json["write_requested"].as_bool().unwrap(),
        live_plan_fixture["write_requested"].as_bool().unwrap()
    );
    assert_eq!(
        live_plan_json["config_valid"].as_bool().unwrap(),
        live_plan_fixture["config_valid"].as_bool().unwrap()
    );
    assert_eq!(
        live_plan_json["paths"]["artifact_binary"].as_str().unwrap(),
        live_plan_fixture["paths"]["artifact_binary"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        live_plan_json["paths"]["config"].as_str().unwrap(),
        live_plan_fixture["paths"]["config"].as_str().unwrap()
    );
    assert_eq!(
        live_plan_json["paths"]["go_progress_file_fixed"]
            .as_str()
            .unwrap(),
        live_plan_fixture["paths"]["go_progress_file_fixed"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        live_plan_json["paths"]["go_pid_file_disabled"]
            .as_bool()
            .unwrap(),
        live_plan_fixture["paths"]["go_pid_file_disabled"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        live_plan_json["minimum_config"]["tproxy_port"]
            .as_u64()
            .unwrap(),
        live_plan_fixture["config"]["tproxy_port"].as_u64().unwrap()
    );
    assert_eq!(
        live_plan_json["minimum_config"]["so_mark_from_dae"]
            .as_u64()
            .unwrap(),
        live_plan_fixture["config"]["so_mark_from_dae"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        live_plan_json["minimum_config"]["mptcp"].as_bool().unwrap(),
        live_plan_fixture["config"]["mptcp"].as_bool().unwrap()
    );
    assert!(
        live_plan_json["minimum_config"]["text"]
            .as_str()
            .unwrap()
            .contains("mptcp: true")
    );
    assert_eq!(
        live_plan_json["production_safety"]["no_systemd_mutation"]
            .as_bool()
            .unwrap(),
        live_plan_fixture["production_safety"]["no_systemd_mutation"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        live_plan_json["production_safety"]["progress_file_fixed_path_blocker"]
            .as_bool()
            .unwrap(),
        live_plan_fixture["production_safety"]["progress_file_fixed_path_blocker"]
            .as_bool()
            .unwrap()
    );
    let command_names = live_plan_json["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(command_names.contains(&live_plan_fixture["commands"]["validate"].as_str().unwrap()));
    assert!(command_names.contains(&live_plan_fixture["commands"]["run"].as_str().unwrap()));
    assert!(command_names.contains(&live_plan_fixture["commands"]["cleanup"].as_str().unwrap()));
    let traffic_names = live_plan_json["traffic_matrix"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        traffic_names,
        live_plan_fixture["traffic_matrix"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );

    let live_plan_root = std::env::temp_dir().join(format!(
        "dae-stage22-live-plan-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let live_plan_root_string = live_plan_root.to_string_lossy().into_owned();
    let write_plan = run_with_args([
        "runtime",
        "stage22-live-plan",
        "--root",
        &live_plan_root_string,
        "--write",
    ]);
    assert_eq!(write_plan.exit_code, 0, "{}", write_plan.stdout);
    assert_eq!(write_plan.stderr, "");
    let write_plan_json: Value = serde_json::from_str(&write_plan.stdout).unwrap();
    assert!(write_plan_json["write_requested"].as_bool().unwrap());
    assert!(write_plan_json["files_written"].as_array().unwrap().len() >= 2);
    let config_path = live_plan_root.join("config.dae");
    assert!(config_path.exists());
    let validate_written = run_with_args(["validate", "-c", config_path.to_str().unwrap()]);
    assert_eq!(validate_written.exit_code, 0, "{}", validate_written.stdout);

    let host_preflight_fixture = load("engine/runtime_stage22/host_preflight.json");
    let progress_path = live_plan_root.join("run").join("dae.progress");
    let pid_path = live_plan_root.join("run").join("dae.pid");
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let lan_iface = format!("dxl{:010}", suffix);
    let wan_iface = format!("dxw{:010}", suffix);
    let netns = format!("dae-stage22-test-{suffix}");
    let tproxy_port = 39000 + (std::process::id() % 1000);
    let host_preflight = run_with_args([
        "runtime",
        "stage22-host-preflight",
        "--root",
        &live_plan_root_string,
        "--artifact-binary",
        "/bin/true",
        "--progress-file",
        progress_path.to_str().unwrap(),
        "--pid-file",
        pid_path.to_str().unwrap(),
        "--tproxy-port",
        &tproxy_port.to_string(),
        "--lan-iface",
        &lan_iface,
        "--wan-iface",
        &wan_iface,
        "--client-netns",
        &netns,
    ]);
    assert_eq!(host_preflight.exit_code, 0);
    assert_eq!(host_preflight.stderr, "");
    let host_preflight_json: Value = serde_json::from_str(&host_preflight.stdout).unwrap();
    assert_eq!(
        host_preflight_json["name"].as_str().unwrap(),
        host_preflight_fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        host_preflight_json["evidence_class"].as_str().unwrap(),
        host_preflight_fixture["evidence_class"].as_str().unwrap()
    );
    assert_eq!(
        host_preflight_json["default_switch_allowed"]
            .as_bool()
            .unwrap(),
        host_preflight_fixture["default_switch_allowed"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        host_preflight_json["default_path_mutated"]
            .as_bool()
            .unwrap(),
        host_preflight_fixture["default_path_mutated"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        host_preflight_json["live_daemon_started"]
            .as_bool()
            .unwrap(),
        host_preflight_fixture["live_daemon_started"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        host_preflight_json["read_only"].as_bool().unwrap(),
        host_preflight_fixture["read_only"].as_bool().unwrap()
    );
    assert!(
        host_preflight_json["allowed_to_start_candidate"]
            .as_bool()
            .unwrap(),
        "{}",
        host_preflight.stdout
    );
    assert_eq!(
        host_preflight_json["production_safety"]["no_daemon_start"]
            .as_bool()
            .unwrap(),
        host_preflight_fixture["production_safety"]["no_daemon_start"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        host_preflight_json["production_safety"]["fixed_progress_file_checked"]
            .as_bool()
            .unwrap(),
        host_preflight_fixture["production_safety"]["fixed_progress_file_checked"]
            .as_bool()
            .unwrap()
    );
    let check_names = host_preflight_json["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        check_names,
        host_preflight_fixture["check_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );

    fs::write(&progress_path, "2\nOK").unwrap();
    let blocked_preflight = run_with_args([
        "runtime",
        "stage22-host-preflight",
        "--root",
        &live_plan_root_string,
        "--artifact-binary",
        "/bin/true",
        "--progress-file",
        progress_path.to_str().unwrap(),
        "--pid-file",
        pid_path.to_str().unwrap(),
        "--tproxy-port",
        &tproxy_port.to_string(),
        "--lan-iface",
        &lan_iface,
        "--wan-iface",
        &wan_iface,
        "--client-netns",
        &netns,
    ]);
    assert_eq!(blocked_preflight.exit_code, 0);
    let blocked_json: Value = serde_json::from_str(&blocked_preflight.stdout).unwrap();
    assert!(
        !blocked_json["allowed_to_start_candidate"]
            .as_bool()
            .unwrap()
    );
    assert!(
        blocked_json["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value
                .as_str()
                .unwrap()
                .contains("fixed reload progress file already exists"))
    );
    let _ = fs::remove_dir_all(live_plan_root);
}

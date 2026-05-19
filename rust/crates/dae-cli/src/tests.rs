use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::*;

#[test]
fn cli_surface_matches_golden_fixture() {
    let fixture = load("cli/surface/basic.json");
    let surface = cli_surface();
    assert_eq!(surface.root_use, fixture["root"]["use"].as_str().unwrap());
    assert_eq!(
        surface.root_short,
        fixture["root"]["short"].as_str().unwrap()
    );
    assert_eq!(
        surface.completion_default_cmd_disabled,
        fixture["root"]["completion_default_cmd_disabled"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        surface.pid_file,
        fixture["paths"]["pid_file"].as_str().unwrap()
    );
    assert_eq!(
        surface.signal_progress_file,
        fixture["paths"]["signal_progress_file"].as_str().unwrap()
    );
    assert_eq!(
        surface.abort_file,
        fixture["paths"]["abort_file"].as_str().unwrap()
    );
    assert_commands(&surface.commands, fixture["commands"].as_array().unwrap());
}

#[test]
fn progress_bytes_and_parser_match_golden_fixture() {
    let fixture = load("cli/surface/basic.json");
    assert_eq!(
        String::from_utf8(vec![ReloadProgress::Send.byte()]).unwrap(),
        fixture["reload_progress"]["send"].as_str().unwrap()
    );
    assert_eq!(
        String::from_utf8(vec![ReloadProgress::Processing.byte()]).unwrap(),
        fixture["reload_progress"]["processing"].as_str().unwrap()
    );
    assert_eq!(
        String::from_utf8(vec![ReloadProgress::Done.byte()]).unwrap(),
        fixture["reload_progress"]["done"].as_str().unwrap()
    );
    assert_eq!(
        String::from_utf8(vec![ReloadProgress::Error.byte()]).unwrap(),
        fixture["reload_progress"]["error"].as_str().unwrap()
    );
    let (code, content) = parse_progress_content("2\nOK").unwrap();
    assert_eq!(code, ReloadProgress::Done.byte());
    assert_eq!(content, "OK");
    assert_eq!(
        parse_progress_content("bad\nformat")
            .unwrap_err()
            .to_string(),
        "unexpected format: bad\nformat"
    );
}

#[test]
fn completion_matches_golden_fixture() {
    let fixture = load("cli/surface/basic.json");
    for case in fixture["completion_cases"].as_array().unwrap() {
        let got = get_completion(case["shell"].as_str().unwrap());
        if case["ok"].as_bool().unwrap() {
            let got = got.unwrap();
            assert!(!got.is_empty());
            assert_eq!(got.contains("dae"), case["mentions_dae"].as_bool().unwrap());
        } else {
            assert_eq!(
                got.unwrap_err().to_string(),
                case["error"].as_str().unwrap()
            );
        }
    }
}

#[test]
fn validate_and_export_surfaces_are_callable() {
    validate_config_text("global {}\nrouting {}\n").unwrap();
    let outline = export_outline_json("unknown");
    assert!(outline.contains("\"global\""));
    assert!(outline.contains("\"routing\""));
}

#[test]
fn optin_runner_matches_validate_and_export_fixture() {
    let fixture = load("cli/surface/basic.json");
    let missing = run_with_args(["validate"]);
    assert_eq!(missing.exit_code, 1);
    assert_eq!(
        missing.stdout.trim_end(),
        fixture["validate"]["requires_config_message"]
            .as_str()
            .unwrap()
    );
    assert!(missing.stderr.is_empty());

    let path = write_config("global {}\nrouting {}\n");
    let validate = run_with_args(["validate", "-c", path.to_str().unwrap()]);
    assert_eq!(validate.exit_code, 0);
    assert_eq!(validate.stdout, "");
    assert_eq!(validate.stderr, "");
    let _ = fs::remove_file(path);

    let export = run_with_args(["export", "outline"]);
    assert_eq!(export.exit_code, 0);
    assert!(export.stdout.ends_with('\n'));
    assert_eq!(export.stderr, "");
    let outline: Value = serde_json::from_str(&export.stdout).unwrap();
    assert_eq!(
        outline["version"].as_str().unwrap(),
        fixture["export"]["outline_summary"]["version"]
            .as_str()
            .unwrap()
    );
    let sections = outline["structure"]
        .as_array()
        .unwrap()
        .iter()
        .map(|section| section["mapping"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(sections.contains(&"global"));
    assert!(sections.contains(&"routing"));

    let parse_api = run_with_args([
        "config",
        "parse-api",
        "--global",
        "global { log_level: debug }",
        "--routing",
        "routing { fallback: must_direct }",
    ]);
    assert_eq!(parse_api.exit_code, 0);
    assert_eq!(parse_api.stdout, "");
    assert_eq!(parse_api.stderr, "");
}

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

#[test]
fn stage31_to_stage34_runtime_admission_fixtures_match() {
    for (fixture_path, command) in [
        (
            "engine/runtime_stage31/ebpf_attach_admission.json",
            "stage31-ebpf-attach-admission",
        ),
        (
            "engine/runtime_stage32/active_traffic_admission.json",
            "stage32-active-traffic-admission",
        ),
        (
            "engine/runtime_stage33/reload_rollback_admission.json",
            "stage33-reload-rollback-admission",
        ),
        (
            "engine/runtime_stage34/benchmark_admission.json",
            "stage34-benchmark-admission",
        ),
    ] {
        let fixture = load(fixture_path);
        let output = run_with_args(["runtime", command]);
        assert_eq!(output.exit_code, 0, "{}", output.stdout);
        assert_eq!(output.stderr, "");
        let json: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            json["name"].as_str().unwrap(),
            fixture["name"].as_str().unwrap()
        );
        assert_eq!(
            json["stage"].as_str().unwrap(),
            fixture["stage"].as_str().unwrap()
        );
        assert_eq!(
            json["evidence_class"].as_str().unwrap(),
            fixture["evidence_class"].as_str().unwrap()
        );
        assert!(!json["default_switch_allowed"].as_bool().unwrap());
        assert!(!json["default_path_mutated"].as_bool().unwrap());
        assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
        assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
        assert!(json["go_default_path_preserved"].as_bool().unwrap());
        assert!(json["go_fallback_required"].as_bool().unwrap());
        assert_eq!(
            json["remaining_blockers"].as_array().unwrap().len(),
            fixture["remaining_blockers"].as_array().unwrap().len()
        );
    }
}

#[test]
fn stage31_to_stage34_runtime_admission_gates_block_defaults() {
    let stage31_blocked = run_with_args([
        "runtime",
        "stage31-ebpf-attach-admission",
        "--execute-smoke",
    ]);
    assert_eq!(stage31_blocked.exit_code, 1);
    assert!(
        stage31_blocked
            .stdout
            .contains("stage31 root-gated smoke requires --ack-root-gate")
    );

    let stage32_blocked = run_with_args([
        "runtime",
        "stage32-active-traffic-admission",
        "--execute-smoke",
    ]);
    assert_eq!(stage32_blocked.exit_code, 1);
    assert!(
        stage32_blocked
            .stdout
            .contains("stage32 local traffic smoke requires --ack-traffic-gate")
    );

    let report_path = std::env::temp_dir().join(format!(
        "dae-stage31-report-{}-{}.json",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::write(
        &report_path,
        r#"{"filter_cleanup_smoke_passed":true,"blockers":[]}"#,
    )
    .unwrap();
    let stage32 = run_with_args([
        "runtime",
        "stage32-active-traffic-admission",
        "--stage31-report",
        report_path.to_str().unwrap(),
        "--execute-smoke",
        "--ack-traffic-gate",
    ]);
    assert_eq!(stage32.exit_code, 0, "{}", stage32.stdout);
    let stage32_json: Value = serde_json::from_str(&stage32.stdout).unwrap();
    assert!(
        stage32_json["local_traffic_harness_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        stage32_json["local_tcp_udp_harness_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !stage32_json["active_tproxy_traffic_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(!stage32_json["default_switch_allowed"].as_bool().unwrap());
    let _ = fs::remove_file(report_path);
}

#[test]
fn stage35_to_stage36_runtime_admission_fixtures_match() {
    for (fixture_path, command) in [
        (
            "engine/runtime_stage35/real_ebpf_attach_admission.json",
            "stage35-real-ebpf-attach-admission",
        ),
        (
            "engine/runtime_stage36/listen_socket_map_admission.json",
            "stage36-listen-socket-map-admission",
        ),
    ] {
        let fixture = load(fixture_path);
        let output = run_with_args(["runtime", command]);
        assert_eq!(output.exit_code, 0, "{}", output.stdout);
        assert_eq!(output.stderr, "");
        let json: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            json["name"].as_str().unwrap(),
            fixture["name"].as_str().unwrap()
        );
        assert_eq!(
            json["stage"].as_str().unwrap(),
            fixture["stage"].as_str().unwrap()
        );
        assert_eq!(
            json["evidence_class"].as_str().unwrap(),
            fixture["evidence_class"].as_str().unwrap()
        );
        assert!(!json["default_switch_allowed"].as_bool().unwrap());
        assert!(!json["default_path_mutated"].as_bool().unwrap());
        assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
        assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
        assert!(json["go_default_path_preserved"].as_bool().unwrap());
        assert!(json["go_fallback_required"].as_bool().unwrap());
        assert_eq!(
            json["remaining_blockers"].as_array().unwrap().len(),
            fixture["remaining_blockers"].as_array().unwrap().len()
        );
    }
}

#[test]
fn stage35_to_stage36_runtime_admission_gates_block_defaults() {
    let stage35_blocked = run_with_args([
        "runtime",
        "stage35-real-ebpf-attach-admission",
        "--execute-smoke",
    ]);
    assert_eq!(stage35_blocked.exit_code, 1);
    assert!(
        stage35_blocked
            .stdout
            .contains("stage35 root-gated smoke requires --ack-root-gate")
    );

    let stage36_blocked = run_with_args([
        "runtime",
        "stage36-listen-socket-map-admission",
        "--execute-smoke",
    ]);
    assert_eq!(stage36_blocked.exit_code, 1);
    assert!(
        stage36_blocked
            .stdout
            .contains("stage36 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage37_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage37/loaded_listen_socket_map_admission.json");
    let output = run_with_args(["runtime", "stage37-loaded-listen-socket-map-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert_eq!(
        json["real_loaded_object_contract"]["section"],
        fixture["real_loaded_object_contract"]["section"]
    );
    assert!(
        !json["real_loaded_object_listen_socket_map_fd_update_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["default_path_mutated"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage37_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage37-loaded-listen-socket-map-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage37 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage38_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage38/production_dae_attach_admission.json");
    let output = run_with_args(["runtime", "stage38-production-dae-attach-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert_eq!(
        json["production_name_contract"]["peer_section"],
        fixture["production_name_contract"]["peer_section"]
    );
    assert!(
        !json["production_name_dae0_dae0peer_attach_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["production_name_listen_socket_map_fd_update_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["production_default_daemon_attach_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["default_path_mutated"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage38_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage38-production-dae-attach-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage38 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage39_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage39/transparent_listener_admission.json");
    let output = run_with_args(["runtime", "stage39-transparent-listener-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert_eq!(
        json["transparent_listener_contract"]["required_socket_options"],
        fixture["transparent_listener_contract"]["required_socket_options"]
    );
    assert!(
        !json["real_loaded_object_transparent_listener_fd_update_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["transparent_listener_socket_options_verified"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["active_tproxy_traffic_executed"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["default_path_mutated"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage39_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage39-transparent-listener-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage39 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage40_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage40/param_aware_object_admission.json");
    let output = run_with_args(["runtime", "stage40-param-aware-object-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert_eq!(
        json["object_contract"]["required_symbol"],
        fixture["object_contract"]["required_symbol"]
    );
    assert_eq!(
        json["object_contract"]["expected_symbol_size"],
        fixture["object_contract"]["expected_symbol_size"]
    );
    assert_eq!(
        json["param_payload"]["tproxy_port_big_endian"],
        fixture["param_payload"]["tproxy_port_big_endian"]
    );
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["direct_tc_object_loader_rejected_for_active_traffic"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["rust_param_aware_loader_proven"].as_bool().unwrap());
    assert!(!json["param_aware_object_load_admitted"].as_bool().unwrap());
    assert!(!json["active_tproxy_traffic_allowed"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["default_path_mutated"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage40_runtime_admission_blocks_required_admission() {
    let blocked = run_with_args([
        "runtime",
        "stage40-param-aware-object-admission",
        "--require-admission",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage40 PARAM-aware Rust object loader is not implemented/proven")
    );
}

#[test]
fn stage41_to_stage48_runtime_admission_fixtures_match() {
    for (fixture_path, command) in [
        (
            "engine/runtime_stage41/param_object_image_admission.json",
            "stage41-param-object-image-admission",
        ),
        (
            "engine/runtime_stage42/param_object_load_admission.json",
            "stage42-param-object-load-admission",
        ),
        (
            "engine/runtime_stage43/production_param_listener_admission.json",
            "stage43-production-param-listener-admission",
        ),
        (
            "engine/runtime_stage44/active_tcp_tproxy_admission.json",
            "stage44-active-tcp-tproxy-admission",
        ),
        (
            "engine/runtime_stage45/active_udp_tproxy_admission.json",
            "stage45-active-udp-tproxy-admission",
        ),
        (
            "engine/runtime_stage46/active_dns_tproxy_admission.json",
            "stage46-active-dns-tproxy-admission",
        ),
        (
            "engine/runtime_stage47/outbound_true_dataplane_admission.json",
            "stage47-outbound-true-dataplane-admission",
        ),
        (
            "engine/runtime_stage48/true_daemon_benchmark_admission.json",
            "stage48-true-daemon-benchmark-admission",
        ),
    ] {
        let fixture = load(fixture_path);
        let output = run_with_args(["runtime", command]);
        assert_eq!(output.exit_code, 0, "{}", output.stdout);
        assert_eq!(output.stderr, "");
        let json: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            json["name"].as_str().unwrap(),
            fixture["name"].as_str().unwrap()
        );
        assert_eq!(
            json["stage"].as_str().unwrap(),
            fixture["stage"].as_str().unwrap()
        );
        assert_eq!(
            json["evidence_class"].as_str().unwrap(),
            fixture["evidence_class"].as_str().unwrap()
        );
        assert!(!json["default_switch_allowed"].as_bool().unwrap());
        assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
        assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
        assert!(json["go_default_path_preserved"].as_bool().unwrap());
        assert!(json["go_fallback_required"].as_bool().unwrap());
        assert_eq!(
            json["remaining_blockers"].as_array().unwrap().len(),
            fixture["remaining_blockers"].as_array().unwrap().len()
        );
    }
}

#[test]
fn stage41_runtime_admission_writes_param_object_when_requested() {
    let source = dae_golden::repo_root_from_manifest()
        .unwrap()
        .join("control/bpf_bpfel.o");
    let output_path = temp_path("stage41-param-object.o");
    let output = run_with_args([
        "runtime",
        "stage41-param-object-image-admission",
        "--write-image",
        "--require-admission",
        "--object",
        source.to_str().unwrap(),
        "--output",
        output_path.to_str().unwrap(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["param_object_image_written"].as_bool().unwrap());
    assert!(json["param_object_image_admitted"].as_bool().unwrap());
    assert_eq!(
        json["rewritten_param"]["tproxy_port"].as_u64().unwrap(),
        14640
    );
    let _ = fs::remove_file(output_path);
}

#[test]
fn stage42_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage42-param-object-load-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage42 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage49_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage49/production_param_listener_admission.json");
    let output = run_with_args(["runtime", "stage49-production-param-listener-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(
        !json["combined_production_param_listener_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["combined_production_param_listener_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["active_tproxy_traffic_executed"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage49_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage49-production-param-listener-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage49 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage50_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage50/active_tcp_tproxy_ingress_admission.json");
    let output = run_with_args(["runtime", "stage50-active-tcp-tproxy-ingress-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(
        !json["active_tcp_tproxy_ingress_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["active_tcp_tproxy_ingress_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["active_tcp_tproxy_admitted"].as_bool().unwrap());
    assert!(
        !json["route_dial_tcp_rust_control_plane_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage50_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage50-active-tcp-tproxy-ingress-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage50 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage51_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage51/active_tcp_route_dial_relay_admission.json");
    let output = run_with_args(["runtime", "stage51-active-tcp-route-dial-relay-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["active_tcp_relay_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["active_tcp_relay_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["route_dial_tcp_direct_path_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["so_mark_mptcp_real_outbound_socket_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage51_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage51-active-tcp-route-dial-relay-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage51 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage52_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage52/active_tcp_route_table_group_admission.json");
    let output = run_with_args([
        "runtime",
        "stage52-active-tcp-route-table-group-relay-admission",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(
        json["route_dial_tcp_route_table_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(json["choose_dial_target_recorded"].as_bool().unwrap());
    assert!(json["outbound_group_selection_recorded"].as_bool().unwrap());
    assert!(
        json["route_dial_tcp_rust_control_plane_executed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["active_tcp_route_table_group_relay_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["active_tcp_route_table_group_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["route_dial_plan"]["final_dial_target"]
            .as_str()
            .unwrap(),
        fixture["route_dial_plan"]["final_dial_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["group_selection"]["selected_dialer"].as_str().unwrap(),
        fixture["group_selection"]["selected_dialer"]
            .as_str()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage52_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage52-active-tcp-route-table-group-relay-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage52 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage53_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage53/active_udp_tproxy_endpoint_admission.json");
    let output = run_with_args(["runtime", "stage53-active-udp-tproxy-endpoint-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["active_udp_tproxy_smoke_passed"].as_bool().unwrap());
    assert!(!json["active_udp_tproxy_admitted"].as_bool().unwrap());
    assert!(
        !json["active_udp_original_destination_observed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["udp_endpoint_pool_live_recorded"].as_bool().unwrap());
    assert!(
        !json["udp_packetconn_write_read_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["udp_sendpkt_reply_recorded"].as_bool().unwrap());
    assert!(
        !json["udp_so_mark_real_outbound_socket_observed"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["active_udp_contract"]["target"].as_str().unwrap(),
        fixture["active_udp_contract"]["target"].as_str().unwrap()
    );
    assert_eq!(
        json["udp_endpoint_pool"]["key_model"].as_str().unwrap(),
        fixture["udp_endpoint_pool"]["key_model"].as_str().unwrap()
    );
    assert!(
        json["udp_endpoint_pool"]["dns_udp53_excluded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["active_dns_tproxy_admitted"].as_bool().unwrap());
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage53_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage53-active-udp-tproxy-endpoint-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage53 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage54_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage54/active_dns_tproxy_cache_admission.json");
    let output = run_with_args(["runtime", "stage54-active-dns-tproxy-cache-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["active_dns_tproxy_smoke_passed"].as_bool().unwrap());
    assert!(!json["active_dns_tproxy_admitted"].as_bool().unwrap());
    assert!(
        !json["active_dns_original_destination_observed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["dns_controller_path_recorded"].as_bool().unwrap());
    assert!(!json["dns_upstream_query_recorded"].as_bool().unwrap());
    assert!(!json["dns_cache_restore_recorded"].as_bool().unwrap());
    assert!(
        !json["domain_routing_owner_migration_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["active_dns_contract"]["dns_target"].as_str().unwrap(),
        fixture["active_dns_contract"]["dns_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["active_dns_contract"]["dns_upstream"]
            .as_str()
            .unwrap(),
        fixture["active_dns_contract"]["dns_upstream"]
            .as_str()
            .unwrap()
    );
    assert!(
        json["dns_cache"]["cache_key_includes_qclass"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["dns_cache"]["packed_response_id_rewrite_required"]
            .as_bool()
            .unwrap()
    );
    assert!(json["active_udp_tproxy_admitted"].as_bool().unwrap());
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage54_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage54-active-dns-tproxy-cache-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage54 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage55_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage55/socks5_outbound_true_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage55-socks5-outbound-true-dataplane-admission",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(!json["socks5_tcp_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["socks5_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["socks5_auth_observed"].as_bool().unwrap());
    assert!(!json["socks5_connect_request_observed"].as_bool().unwrap());
    assert!(!json["socks5_payload_roundtrip_recorded"].as_bool().unwrap());
    assert_eq!(
        json["socks5_contract"]["target"].as_str().unwrap(),
        fixture["socks5_contract"]["target"].as_str().unwrap()
    );
    assert_eq!(
        json["socks5_contract"]["payload_ascii"].as_str().unwrap(),
        fixture["socks5_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage55_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage55-socks5-outbound-true-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage55 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage56_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage56/socks5_udp_associate_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage56-socks5-udp-associate-dataplane-admission",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["socks5_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["socks5_udp_smoke_passed"].as_bool().unwrap());
    assert!(!json["socks5_udp_associate_admitted"].as_bool().unwrap());
    assert!(
        !json["socks5_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["socks5_auth_observed"].as_bool().unwrap());
    assert!(
        !json["socks5_udp_associate_request_observed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["socks5_udp_packet_wrap_unwrap_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["socks5_tcp_control_connection_retained"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["socks5_udp_contract"]["associate_target"]
            .as_str()
            .unwrap(),
        fixture["socks5_udp_contract"]["associate_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["socks5_udp_contract"]["packet_target"]
            .as_str()
            .unwrap(),
        fixture["socks5_udp_contract"]["packet_target"]
            .as_str()
            .unwrap()
    );
    assert!(
        json["socks5_udp_contract"]["unspecified_bind_falls_back_to_proxy_host"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["tcp_control_underlay"]["requested_mark"]
            .as_u64()
            .unwrap(),
        fixture["tcp_control_underlay"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["udp_underlay_socket"]["mptcp_not_applicable"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage56_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage56-socks5-udp-associate-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage56 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage57_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage57/http_connect_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage57-http-connect-dataplane-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["socks5_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["http_connect_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["http_connect_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["https_proxy_tls_underlay_admitted"].as_bool().unwrap());
    assert!(
        !json["http_proxy_protocol_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["http_connect_request_observed"].as_bool().unwrap());
    assert!(!json["http_proxy_auth_observed"].as_bool().unwrap());
    assert!(
        !json["http_connect_payload_roundtrip_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["http_connect_contract"]["target"].as_str().unwrap(),
        fixture["http_connect_contract"]["target"].as_str().unwrap()
    );
    assert_eq!(
        json["http_connect_contract"]["host_override"]
            .as_str()
            .unwrap(),
        fixture["http_connect_contract"]["host_override"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["http_connect_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["http_connect_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage57_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage57-http-connect-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage57 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage58_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage58/shadowsocks_aead_tcp_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage58-shadowsocks-aead-tcp-dataplane-admission",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["socks5_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["http_connect_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["shadowsocks_aead_tcp_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["shadowsocks_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["shadowsocks_protocol_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["shadowsocks_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["ss2022_true_dataplane_admitted"].as_bool().unwrap());
    assert!(
        !json["shadowsocks_udp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["sip003_plugin_transport_admitted"].as_bool().unwrap());
    assert_eq!(
        json["shadowsocks_contract"]["cipher"].as_str().unwrap(),
        fixture["shadowsocks_contract"]["cipher"].as_str().unwrap()
    );
    assert_eq!(
        json["shadowsocks_contract"]["target"].as_str().unwrap(),
        fixture["shadowsocks_contract"]["target"].as_str().unwrap()
    );
    assert_eq!(
        json["shadowsocks_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["shadowsocks_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage58_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage58-shadowsocks-aead-tcp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage58 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage59_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage59/shadowsocks_aead_udp_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage59-shadowsocks-aead-udp-dataplane-admission",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["shadowsocks_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["shadowsocks_aead_udp_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["shadowsocks_aead_udp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["shadowsocks_aead_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["ss2022_true_dataplane_admitted"].as_bool().unwrap());
    assert_eq!(
        json["shadowsocks_udp_contract"]["target"].as_str().unwrap(),
        fixture["shadowsocks_udp_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["shadowsocks_udp_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["shadowsocks_udp_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["udp_underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap(),
        fixture["udp_underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["udp_underlay_socket"]["mptcp_not_applicable"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage59_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage59-shadowsocks-aead-udp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage59 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage60_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage60/trojan_tcp_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage60-trojan-tcp-dataplane-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["shadowsocks_aead_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["ss2022_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["trojanc_tcp_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["trojanc_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["trojan_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["trojan_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["trojan_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["trojan_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(
        !json["trojan_go_shared_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_inner_shadowsocks_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["trojan_contract"]["target"].as_str().unwrap(),
        fixture["trojan_contract"]["target"].as_str().unwrap()
    );
    assert_eq!(
        json["trojan_contract"]["payload_ascii"].as_str().unwrap(),
        fixture["trojan_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage60_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage60-trojan-tcp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage60 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage61_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage61/trojan_udp_over_tcp_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage61-trojan-udp-over-tcp-dataplane-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["trojanc_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["trojan_udp_over_tcp_smoke_passed"].as_bool().unwrap());
    assert!(!json["trojan_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(json["trojan_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["trojan_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["trojan_tls_underlay_admitted"].as_bool().unwrap());
    assert!(
        !json["trojan_go_shared_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_inner_shadowsocks_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["trojan_udp_over_tcp_contract"]["session_target"]
            .as_str()
            .unwrap(),
        fixture["trojan_udp_over_tcp_contract"]["session_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["trojan_udp_over_tcp_contract"]["packet_target"]
            .as_str()
            .unwrap(),
        fixture["trojan_udp_over_tcp_contract"]["packet_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["trojan_udp_over_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["trojan_udp_over_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage61_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage61-trojan-udp-over-tcp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage61 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage62_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage62/vless_tcp_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage62-vless-tcp-dataplane-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(!json["vless_tcp_raw_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["vless_tcp_raw_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_reality_admitted"].as_bool().unwrap());
    assert!(!json["vless_xtls_vision_admitted"].as_bool().unwrap());
    assert!(!json["vless_shared_transport_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vless_tcp_contract"]["target"].as_str().unwrap(),
        fixture["vless_tcp_contract"]["target"].as_str().unwrap()
    );
    assert_eq!(
        json["vless_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vless_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage62_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage62-vless-tcp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage62 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage63_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage63/vless_udp_over_tcp_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage63-vless-udp-over-tcp-dataplane-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["vless_tcp_raw_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_udp_over_tcp_smoke_passed"].as_bool().unwrap());
    assert!(!json["vless_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(!json["vless_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_reality_admitted"].as_bool().unwrap());
    assert!(!json["vless_xtls_vision_admitted"].as_bool().unwrap());
    assert!(!json["vless_shared_transport_admitted"].as_bool().unwrap());
    assert!(!json["vless_mux_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vless_udp_over_tcp_contract"]["target"]
            .as_str()
            .unwrap(),
        fixture["vless_udp_over_tcp_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_udp_over_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vless_udp_over_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage63_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage63-vless-udp-over-tcp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage63 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage64_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage64/vless_mux_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage64-vless-mux-dataplane-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["vless_tcp_raw_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vless_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(!json["vless_mux_smoke_passed"].as_bool().unwrap());
    assert!(!json["vless_mux_admitted"].as_bool().unwrap());
    assert!(!json["vless_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vless_reality_admitted"].as_bool().unwrap());
    assert!(!json["vless_xtls_vision_admitted"].as_bool().unwrap());
    assert!(!json["vless_shared_transport_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vless_mux_contract"]["target"].as_str().unwrap(),
        fixture["vless_mux_contract"]["target"].as_str().unwrap()
    );
    assert_eq!(
        json["vless_mux_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vless_mux_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vless_mux_contract"]["mux_id_hex"].as_str().unwrap(),
        fixture["vless_mux_contract"]["mux_id_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage64_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage64-vless-mux-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage64 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage65_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage65/vmess_aead_tcp_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage65-vmess-aead-tcp-dataplane-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(json["vless_mux_admitted"].as_bool().unwrap());
    assert!(!json["vmess_aead_tcp_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vmess_shared_transport_admitted"].as_bool().unwrap());
    assert!(!json["vmess_udp_packet_addr_admitted"].as_bool().unwrap());
    assert!(!json["vmess_mux_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vmess_aead_tcp_contract"]["target"].as_str().unwrap(),
        fixture["vmess_aead_tcp_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_aead_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vmess_aead_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_aead_tcp_contract"]["security_byte"]
            .as_u64()
            .unwrap(),
        fixture["vmess_aead_tcp_contract"]["security_byte"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage65_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage65-vmess-aead-tcp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage65 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage66_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage66/vmess_aead_udp_over_tcp_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage66-vmess-aead-udp-over-tcp-dataplane-admission",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vmess_aead_udp_over_tcp_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_aead_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(!json["vmess_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_udp_packet_addr_admitted"].as_bool().unwrap());
    assert!(!json["vmess_mux_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vmess_aead_udp_over_tcp_contract"]["target"]
            .as_str()
            .unwrap(),
        fixture["vmess_aead_udp_over_tcp_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_aead_udp_over_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vmess_aead_udp_over_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_aead_udp_over_tcp_contract"]["packet_len"]
            .as_u64()
            .unwrap(),
        fixture["vmess_aead_udp_over_tcp_contract"]["packet_len"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage66_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage66-vmess-aead-udp-over-tcp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage66 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage67_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage67/vmess_packet_addr_udp_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage67-vmess-packet-addr-udp-dataplane-admission",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vmess_aead_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_packet_addr_udp_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_udp_packet_addr_admitted"].as_bool().unwrap());
    assert!(!json["vmess_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_mux_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vmess_packet_addr_udp_contract"]["magic_domain"]
            .as_str()
            .unwrap(),
        fixture["vmess_packet_addr_udp_contract"]["magic_domain"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_packet_addr_udp_contract"]["request_target"]
            .as_str()
            .unwrap(),
        fixture["vmess_packet_addr_udp_contract"]["request_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_packet_addr_udp_contract"]["packet_target"]
            .as_str()
            .unwrap(),
        fixture["vmess_packet_addr_udp_contract"]["packet_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_packet_addr_udp_contract"]["packet_addr_len"]
            .as_u64()
            .unwrap(),
        fixture["vmess_packet_addr_udp_contract"]["packet_addr_len"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        json["vmess_packet_addr_udp_contract"]["packet_len"]
            .as_u64()
            .unwrap(),
        fixture["vmess_packet_addr_udp_contract"]["packet_len"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage67_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage67-vmess-packet-addr-udp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage67 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage68_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage68/vmess_mux_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage68-vmess-mux-dataplane-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vmess_aead_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(json["vmess_udp_packet_addr_admitted"].as_bool().unwrap());
    assert!(!json["vmess_mux_smoke_passed"].as_bool().unwrap());
    assert!(!json["vmess_mux_admitted"].as_bool().unwrap());
    assert!(!json["vmess_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vmess_shared_transport_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vmess_mux_contract"]["request_target"]
            .as_str()
            .unwrap(),
        fixture["vmess_mux_contract"]["request_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_mux_contract"]["mux_target"].as_str().unwrap(),
        fixture["vmess_mux_contract"]["mux_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_mux_contract"]["mux_id_hex"].as_str().unwrap(),
        fixture["vmess_mux_contract"]["mux_id_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_mux_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vmess_mux_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage68_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage68-vmess-mux-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage68 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage69_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage69/vmess_websocket_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage69-vmess-websocket-dataplane-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vmess_aead_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(json["vmess_udp_packet_addr_admitted"].as_bool().unwrap());
    assert!(json["vmess_mux_admitted"].as_bool().unwrap());
    assert!(!json["vmess_websocket_smoke_passed"].as_bool().unwrap());
    assert!(!json["vmess_websocket_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_shared_transport_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vmess_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vmess_shared_transport_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vmess_websocket_contract"]["target"].as_str().unwrap(),
        fixture["vmess_websocket_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_websocket_contract"]["ws_host"]
            .as_str()
            .unwrap(),
        fixture["vmess_websocket_contract"]["ws_host"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_websocket_contract"]["ws_path"]
            .as_str()
            .unwrap(),
        fixture["vmess_websocket_contract"]["ws_path"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_websocket_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vmess_websocket_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage69_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage69-vmess-websocket-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage69 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn optin_runner_userspace_commands_match_engine_fixture() {
    let fixture = load("engine/userspace_runtime/optin_contract.json");

    let routing = &fixture["routing"];
    let route = run_with_args([
        "userspace",
        "route-match",
        "--domain",
        routing["domain"].as_str().unwrap(),
        "--dest",
        routing["dest"].as_str().unwrap(),
        "--port",
        "443",
    ]);
    assert_eq!(route.exit_code, 0);
    assert_eq!(route.stderr, "");
    let route_json: Value = serde_json::from_str(&route.stdout).unwrap();
    assert_eq!(
        route_json["outbound"].as_str().unwrap(),
        routing["want_outbound"].as_str().unwrap()
    );
    assert!(route_json["userspace_only"].as_bool().unwrap());

    let dns = &fixture["dns"];
    let dns_key = run_with_args([
        "userspace",
        "dns-cache-key",
        "--qname",
        dns["qname"].as_str().unwrap(),
        "--qtype",
        "1",
        "--qclass",
        "1",
    ]);
    assert_eq!(dns_key.exit_code, 0);
    assert_eq!(dns_key.stderr, "");
    let dns_json: Value = serde_json::from_str(&dns_key.stdout).unwrap();
    assert_eq!(
        dns_json["key"].as_str().unwrap(),
        dns["cache_key"].as_str().unwrap()
    );

    let outbound = &fixture["outbound_group"];
    let select = run_with_args([
        "userspace",
        "outbound-select",
        "--policy",
        outbound["policy"].as_str().unwrap(),
        "--network",
        outbound["network"].as_str().unwrap(),
    ]);
    assert_eq!(select.exit_code, 0);
    assert_eq!(select.stderr, "");
    let select_json: Value = serde_json::from_str(&select.stdout).unwrap();
    assert_eq!(
        select_json["selected_index"].as_u64().unwrap(),
        outbound["selected_index"].as_u64().unwrap()
    );
    assert_eq!(
        select_json["latency_ms"].as_i64().unwrap(),
        outbound["selected_latency_ms"].as_i64().unwrap()
    );

    let sniff = run_with_args(["userspace", "sniff-tcp", "--kind", "http"]);
    assert_eq!(sniff.exit_code, 0);
    assert_eq!(sniff.stderr, "");
    let sniff_json: Value = serde_json::from_str(&sniff.stdout).unwrap();
    assert_eq!(
        sniff_json["domain"].as_str().unwrap(),
        fixture["sniffing"]["http_host_normalized"]
            .as_str()
            .unwrap()
    );

    let magic = run_with_args([
        "userspace",
        "magic-network",
        "--network",
        "tcp",
        "--mark",
        "1234",
        "--mptcp",
        "true",
    ]);
    assert_eq!(magic.exit_code, 0);
    assert_eq!(magic.stderr, "");
    let magic_json: Value = serde_json::from_str(&magic.stdout).unwrap();
    assert_eq!(
        magic_json["parsed_mark"].as_u64().unwrap(),
        fixture["magic_network"]["mark"].as_u64().unwrap()
    );
    assert_eq!(
        magic_json["parsed_mptcp"].as_bool().unwrap(),
        fixture["magic_network"]["mptcp"].as_bool().unwrap()
    );
    assert!(!magic_json["plain"].as_bool().unwrap());
}

#[test]
fn optin_runner_active_datapath_commands_match_control_fixture() {
    let fixture = load("control/active_datapath/optin_contract.json");

    let contract = run_with_args(["active-datapath", "contract"]);
    assert_eq!(contract.exit_code, 0);
    assert_eq!(contract.stderr, "");
    let contract_json: Value = serde_json::from_str(&contract.stdout).unwrap();
    assert_eq!(
        contract_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert!(contract_json["default_go_attach_path"].as_bool().unwrap());
    assert_eq!(
        contract_json["ebpf"]["pinned_reuse_maps"]
            .as_array()
            .unwrap()
            .len(),
        fixture["ebpf_loader"]["pinned_reuse_maps"]
            .as_array()
            .unwrap()
            .len()
    );
    assert_eq!(
        contract_json["ebpf"]["tproxy_port_big_endian"]
            .as_u64()
            .unwrap(),
        fixture["ebpf_loader"]["tproxy_port_big_endian"]
            .as_u64()
            .unwrap()
    );
    assert!(
        contract_json["reload_rollback_injects_old_bpf"]
            .as_bool()
            .unwrap()
    );
    assert!(
        contract_json["netns_same_interface_risk"]["tc_act_pipe_required"]
            .as_bool()
            .unwrap()
    );

    let reload = run_with_args(["active-datapath", "reload-ownership"]);
    assert_eq!(reload.exit_code, 0);
    assert_eq!(reload.stderr, "");
    let reload_json: Value = serde_json::from_str(&reload.stdout).unwrap();
    assert!(
        reload_json["reload_rollback_injects_old_bpf"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(reload_json["steps"].as_array().unwrap().len(), 5);

    let magic = run_with_args([
        "active-datapath",
        "magic-dial",
        "--network",
        "tcp",
        "--mark",
        "1234",
        "--mptcp",
        "true",
    ]);
    assert_eq!(magic.exit_code, 0);
    assert_eq!(magic.stderr, "");
    let magic_json: Value = serde_json::from_str(&magic.stdout).unwrap();
    assert_eq!(
        magic_json["parsed_mark"].as_u64().unwrap(),
        fixture["magic_network"]["mark"].as_u64().unwrap()
    );
    assert_eq!(
        magic_json["parsed_mptcp"].as_bool().unwrap(),
        fixture["magic_network"]["mptcp"].as_bool().unwrap()
    );
    assert!(magic_json["active_path"].as_bool().unwrap());
}

#[test]
fn optin_runner_outbound_socks5_commands_match_fixture() {
    let fixture = load("outbound/protocol/socks5_native_optin.json");

    let contract = run_with_args(["outbound", "socks5", "contract"]);
    assert_eq!(contract.exit_code, 0);
    assert_eq!(contract.stderr, "");
    let contract_json: Value = serde_json::from_str(&contract.stdout).unwrap();
    assert_eq!(
        contract_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        contract_json["rust_adapter_mode"].as_str().unwrap(),
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert!(contract_json["default_go_path"].as_bool().unwrap());
    assert_eq!(
        contract_json["link_parser"]["protocol"].as_str().unwrap(),
        fixture["link_parser"]["protocol"].as_str().unwrap()
    );

    let domain = fixture["address_codec"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "domain")
        .unwrap();
    let codec = run_with_args([
        "outbound",
        "socks5",
        "codec",
        "--target",
        domain["input"].as_str().unwrap(),
    ]);
    assert_eq!(codec.exit_code, 0);
    assert_eq!(codec.stderr, "");
    let codec_json: Value = serde_json::from_str(&codec.stdout).unwrap();
    assert_eq!(
        codec_json["encoded_hex"].as_str().unwrap(),
        domain["hex"].as_str().unwrap()
    );

    let handshake = &fixture["handshake"];
    let hs = run_with_args([
        "outbound",
        "socks5",
        "handshake",
        "--target",
        "example.com:443",
        "--username",
        "user",
        "--password",
        "pass",
    ]);
    assert_eq!(hs.exit_code, 0);
    assert_eq!(hs.stderr, "");
    let hs_json: Value = serde_json::from_str(&hs.stdout).unwrap();
    assert_eq!(
        hs_json["greeting_hex"].as_str().unwrap(),
        handshake["greeting_with_auth_hex"].as_str().unwrap()
    );
    assert_eq!(
        hs_json["auth_hex"].as_str().unwrap(),
        handshake["username_password_auth_hex"].as_str().unwrap()
    );
    assert_eq!(
        hs_json["request_hex"].as_str().unwrap(),
        handshake["connect_example_com_443_hex"].as_str().unwrap()
    );

    let udp = &fixture["udp_packet"];
    let packet = run_with_args([
        "outbound",
        "socks5",
        "udp-packet",
        "--target",
        udp["target"].as_str().unwrap(),
        "--payload",
        udp["payload_ascii"].as_str().unwrap(),
    ]);
    assert_eq!(packet.exit_code, 0);
    assert_eq!(packet.stderr, "");
    let packet_json: Value = serde_json::from_str(&packet.stdout).unwrap();
    assert_eq!(
        packet_json["packet_hex"].as_str().unwrap(),
        udp["write_packet_hex"].as_str().unwrap()
    );

    let (proxy, handle) = spawn_fake_socks5_server(true, 1);
    let smoke = run_with_args([
        "outbound",
        "socks5",
        "smoke",
        "--proxy",
        &proxy,
        "--target",
        "example.com:443",
        "--username",
        "user",
        "--password",
        "pass",
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    handle.join().unwrap();
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(smoke_json["method"].as_u64().unwrap(), 2);
    assert_eq!(smoke_json["bind"].as_str().unwrap(), "127.0.0.1:5300");

    let (proxy, handle) = spawn_fake_socks5_server(false, 3);
    let udp_smoke = run_with_args([
        "outbound",
        "socks5",
        "smoke",
        "--proxy",
        &proxy,
        "--target",
        "0.0.0.0:0",
        "--command",
        "udp-associate",
    ]);
    assert_eq!(udp_smoke.exit_code, 0, "{}", udp_smoke.stdout);
    assert_eq!(udp_smoke.stderr, "");
    handle.join().unwrap();
    let udp_smoke_json: Value = serde_json::from_str(&udp_smoke.stdout).unwrap();
    assert!(udp_smoke_json["ok"].as_bool().unwrap());
    assert_eq!(udp_smoke_json["method"].as_u64().unwrap(), 0);
    assert_eq!(udp_smoke_json["command"].as_str().unwrap(), "udp-associate");
}

#[test]
fn optin_runner_outbound_http_commands_match_fixture() {
    let fixture = load("outbound/protocol/http_native_optin.json");

    let contract = run_with_args(["outbound", "http", "contract"]);
    assert_eq!(contract.exit_code, 0);
    assert_eq!(contract.stderr, "");
    let contract_json: Value = serde_json::from_str(&contract.stdout).unwrap();
    assert_eq!(
        contract_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        contract_json["rust_adapter_mode"].as_str().unwrap(),
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert!(contract_json["default_go_path"].as_bool().unwrap());

    let link_case = fixture["link_parser"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "https-flags")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "http",
        "link",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(link.exit_code, 0);
    assert_eq!(link.stderr, "");
    let link_json: Value = serde_json::from_str(&link.stdout).unwrap();
    assert_eq!(
        link_json["export"].as_str().unwrap(),
        link_case["export"].as_str().unwrap()
    );
    assert!(link_json["allowInsecure"].as_bool().unwrap());

    let connect_case = fixture["connect"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "connect-basic-auth-host-override")
        .unwrap();
    let connect = run_with_args([
        "outbound",
        "http",
        "connect",
        "--target",
        connect_case["target"].as_str().unwrap(),
        "--username",
        connect_case["username"].as_str().unwrap(),
        "--password",
        connect_case["password"].as_str().unwrap(),
        "--host",
        connect_case["host_override"].as_str().unwrap(),
    ]);
    assert_eq!(connect.exit_code, 0);
    assert_eq!(connect.stderr, "");
    let connect_json: Value = serde_json::from_str(&connect.stdout).unwrap();
    assert_eq!(
        connect_json["request_hex"].as_str().unwrap(),
        connect_case["request_hex"].as_str().unwrap()
    );

    let forward = run_with_args([
        "outbound",
        "http",
        "forward",
        "--raw-hex",
        fixture["http_request_passthrough"]["input_hex"]
            .as_str()
            .unwrap(),
    ]);
    assert_eq!(forward.exit_code, 0);
    assert_eq!(forward.stderr, "");
    let forward_json: Value = serde_json::from_str(&forward.stdout).unwrap();
    assert_eq!(
        forward_json["request_hex"].as_str().unwrap(),
        fixture["http_request_passthrough"]["request_hex"]
            .as_str()
            .unwrap()
    );

    let (proxy, handle) =
        spawn_fake_http_proxy("CONNECT front.example HTTP/1.1", Some("Basic dXNlcjpwYXNz"));
    let smoke = run_with_args([
        "outbound",
        "http",
        "smoke",
        "--proxy",
        &proxy,
        "--target",
        "example.com:443",
        "--username",
        "user",
        "--password",
        "pass",
        "--host",
        "front.example",
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    handle.join().unwrap();
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(smoke_json["status"].as_u64().unwrap(), 200);

    let (proxy, handle) = spawn_fake_http_proxy(
        "PUT http://www.example.com/proxy-path HTTP/1.1",
        Some("Basic dXNlcjpwYXNz"),
    );
    let transport = run_with_args([
        "outbound",
        "http",
        "smoke",
        "--proxy",
        &proxy,
        "--target",
        "example.com:443",
        "--username",
        "user",
        "--password",
        "pass",
        "--transport",
        "true",
        "--path",
        "/proxy-path",
    ]);
    assert_eq!(transport.exit_code, 0, "{}", transport.stdout);
    assert_eq!(transport.stderr, "");
    handle.join().unwrap();
    let transport_json: Value = serde_json::from_str(&transport.stdout).unwrap();
    assert!(transport_json["ok"].as_bool().unwrap());
    assert!(transport_json["transport"].as_bool().unwrap());
}

#[test]
fn optin_runner_outbound_shadowsocks_commands_match_fixture() {
    let fixture = load("outbound/protocol/shadowsocks_native_optin.json");

    let contract = run_with_args(["outbound", "shadowsocks", "contract"]);
    assert_eq!(contract.exit_code, 0);
    assert_eq!(contract.stderr, "");
    let contract_json: Value = serde_json::from_str(&contract.stdout).unwrap();
    assert_eq!(
        contract_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        contract_json["rust_adapter_mode"].as_str().unwrap(),
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert!(contract_json["default_go_path"].as_bool().unwrap());

    let link_case = fixture["link_parser"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "ss2022-multi-psk")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "shadowsocks",
        "link",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(link.exit_code, 0, "{}", link.stdout);
    assert_eq!(link.stderr, "");
    let link_json: Value = serde_json::from_str(&link.stdout).unwrap();
    assert_eq!(
        link_json["export"].as_str().unwrap(),
        link_case["export"].as_str().unwrap()
    );
    assert_eq!(
        link_json["capability"].as_str().unwrap(),
        "shadowsocks-2022"
    );

    let cipher_case = fixture["cipher_dispatch"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "stream-legacy")
        .unwrap();
    let cipher = run_with_args([
        "outbound",
        "shadowsocks",
        "cipher",
        "--cipher",
        cipher_case["cipher"].as_str().unwrap(),
    ]);
    assert_eq!(cipher.exit_code, 0);
    assert_eq!(cipher.stderr, "");
    let cipher_json: Value = serde_json::from_str(&cipher.stdout).unwrap();
    assert_eq!(
        cipher_json["go_protocol_dialer"].as_str().unwrap(),
        cipher_case["go_protocol_dialer"].as_str().unwrap()
    );

    let metadata_case = fixture["metadata"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "domain")
        .unwrap();
    let metadata = run_with_args([
        "outbound",
        "shadowsocks",
        "metadata",
        "--target",
        metadata_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(metadata.exit_code, 0);
    assert_eq!(metadata.stderr, "");
    let metadata_json: Value = serde_json::from_str(&metadata.stdout).unwrap();
    assert_eq!(
        metadata_json["hex"].as_str().unwrap(),
        metadata_case["hex"].as_str().unwrap()
    );

    let psk_case = fixture["ss2022"]["psk"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "multi-aes128")
        .unwrap();
    let psk = run_with_args([
        "outbound",
        "shadowsocks",
        "ss2022-psk",
        "--cipher",
        psk_case["cipher"].as_str().unwrap(),
        "--password",
        psk_case["password"].as_str().unwrap(),
    ]);
    assert_eq!(psk.exit_code, 0);
    assert_eq!(psk.stderr, "");
    let psk_json: Value = serde_json::from_str(&psk.stdout).unwrap();
    assert_eq!(
        psk_json["psk_count"].as_u64().unwrap(),
        psk_case["psk_count"].as_u64().unwrap()
    );

    let replay = run_with_args(["outbound", "ss", "replay-filter", "--window", "4"]);
    assert_eq!(replay.exit_code, 0);
    assert_eq!(replay.stderr, "");
    let replay_json: Value = serde_json::from_str(&replay.stdout).unwrap();
    assert!(!replay_json["duplicate_packet_accepted"].as_bool().unwrap());
    assert!(!replay_json["too_old_packet_accepted"].as_bool().unwrap());

    let smoke = run_with_args([
        "outbound",
        "shadowsocks",
        "smoke",
        "--link",
        link_case["input"].as_str().unwrap(),
        "--target",
        metadata_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(
        smoke_json["metadata_hex"].as_str().unwrap(),
        metadata_case["hex"].as_str().unwrap()
    );
    assert!(smoke_json["replay_duplicate_rejected"].as_bool().unwrap());
}

#[test]
fn optin_runner_outbound_trojan_commands_match_fixture() {
    let fixture = load("outbound/protocol/trojan_native_optin.json");

    let contract = run_with_args(["outbound", "trojan", "contract"]);
    assert_eq!(contract.exit_code, 0);
    assert_eq!(contract.stderr, "");
    let contract_json: Value = serde_json::from_str(&contract.stdout).unwrap();
    assert_eq!(
        contract_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        contract_json["rust_adapter_mode"].as_str().unwrap(),
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert!(contract_json["default_go_path"].as_bool().unwrap());

    let link_case = fixture["link_parser"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "trojan-type-forces-trojan-go-grpc")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "trojan",
        "link",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(link.exit_code, 0, "{}", link.stdout);
    assert_eq!(link.stderr, "");
    let link_json: Value = serde_json::from_str(&link.stdout).unwrap();
    assert_eq!(
        link_json["export"].as_str().unwrap(),
        link_case["export"].as_str().unwrap()
    );
    assert_eq!(
        link_json["serviceName"].as_str().unwrap(),
        link_case["serviceName"].as_str().unwrap()
    );
    assert_eq!(link_json["protocol"].as_str().unwrap(), "trojan-go");

    let metadata_case = fixture["metadata"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "domain-udp")
        .unwrap();
    let metadata = run_with_args([
        "outbound",
        "trojan",
        "metadata",
        "--network",
        metadata_case["network"].as_str().unwrap(),
        "--target",
        metadata_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(metadata.exit_code, 0);
    assert_eq!(metadata.stderr, "");
    let metadata_json: Value = serde_json::from_str(&metadata.stdout).unwrap();
    assert_eq!(
        metadata_json["hex"].as_str().unwrap(),
        metadata_case["hex"].as_str().unwrap()
    );
    assert_eq!(
        metadata_json["network_byte"].as_u64().unwrap(),
        metadata_case["network_byte"].as_u64().unwrap()
    );

    let tcp_case = &fixture["framing"]["tcp_request_header"];
    let tcp = run_with_args([
        "outbound",
        "trojan",
        "tcp-header",
        "--password",
        fixture["framing"]["password"].as_str().unwrap(),
        "--network",
        tcp_case["network"].as_str().unwrap(),
        "--target",
        tcp_case["target"].as_str().unwrap(),
        "--payload",
        tcp_case["payload_ascii"].as_str().unwrap(),
    ]);
    assert_eq!(tcp.exit_code, 0);
    assert_eq!(tcp.stderr, "");
    let tcp_json: Value = serde_json::from_str(&tcp.stdout).unwrap();
    assert_eq!(
        tcp_json["header_hex"].as_str().unwrap(),
        tcp_case["header_hex"].as_str().unwrap()
    );

    let udp_case = &fixture["framing"]["udp_packet"];
    let udp = run_with_args([
        "outbound",
        "trojan",
        "udp-packet",
        "--target",
        udp_case["target"].as_str().unwrap(),
        "--payload",
        udp_case["payload_ascii"].as_str().unwrap(),
    ]);
    assert_eq!(udp.exit_code, 0);
    assert_eq!(udp.stderr, "");
    let udp_json: Value = serde_json::from_str(&udp.stdout).unwrap();
    assert_eq!(
        udp_json["packet_hex"].as_str().unwrap(),
        udp_case["packet_hex"].as_str().unwrap()
    );

    let smoke = run_with_args([
        "outbound",
        "trojan-go",
        "smoke",
        "--link",
        link_case["input"].as_str().unwrap(),
        "--target",
        tcp_case["target"].as_str().unwrap(),
        "--payload",
        tcp_case["payload_ascii"].as_str().unwrap(),
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(
        smoke_json["tcp_header_hex"].as_str().unwrap(),
        tcp_case["header_hex"].as_str().unwrap()
    );
    assert_eq!(
        smoke_json["udp_packet_hex"].as_str().unwrap(),
        udp_case["packet_hex"].as_str().unwrap()
    );
}

#[test]
fn optin_runner_outbound_vmess_commands_match_fixture() {
    let fixture = load("outbound/protocol/vmess_native_optin.json");

    let contract = run_with_args(["outbound", "vmess", "contract"]);
    assert_eq!(contract.exit_code, 0);
    assert_eq!(contract.stderr, "");
    let contract_json: Value = serde_json::from_str(&contract.stdout).unwrap();
    assert_eq!(
        contract_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        contract_json["rust_adapter_mode"].as_str().unwrap(),
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert!(contract_json["default_go_path"].as_bool().unwrap());
    assert_eq!(
        contract_json["transport_contract"]["shared_transport_deferred_to_item"]
            .as_u64()
            .unwrap(),
        113
    );

    let link_case = fixture["link_parser"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "legacy-websocket-tls")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "vmess",
        "link",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(link.exit_code, 0, "{}", link.stdout);
    assert_eq!(link.stderr, "");
    let link_json: Value = serde_json::from_str(&link.stdout).unwrap();
    assert_eq!(
        link_json["export"].as_str().unwrap(),
        link_case["export"].as_str().unwrap()
    );
    assert_eq!(link_json["net"].as_str().unwrap(), "ws");

    let metadata_case = fixture["metadata"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "domain-tcp")
        .unwrap();
    let metadata = run_with_args([
        "outbound",
        "vmess",
        "metadata",
        "--network",
        metadata_case["network"].as_str().unwrap(),
        "--target",
        metadata_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(metadata.exit_code, 0);
    assert_eq!(metadata.stderr, "");
    let metadata_json: Value = serde_json::from_str(&metadata.stdout).unwrap();
    assert_eq!(
        metadata_json["addr_hex"].as_str().unwrap(),
        metadata_case["addr_hex"].as_str().unwrap()
    );
    assert_eq!(
        metadata_json["network_byte"].as_u64().unwrap(),
        metadata_case["network_byte"].as_u64().unwrap()
    );

    let uuid = &fixture["uuid"];
    let uuid_cmd = run_with_args([
        "outbound",
        "vmess",
        "uuid",
        "--input",
        uuid["short_input"].as_str().unwrap(),
    ]);
    assert_eq!(uuid_cmd.exit_code, 0);
    assert_eq!(uuid_cmd.stderr, "");
    let uuid_json: Value = serde_json::from_str(&uuid_cmd.stdout).unwrap();
    assert_eq!(
        uuid_json["uuid"].as_str().unwrap(),
        uuid["short_uuid5"].as_str().unwrap()
    );

    let smoke = run_with_args([
        "outbound",
        "vmess",
        "smoke",
        "--link",
        link_case["input"].as_str().unwrap(),
        "--target",
        metadata_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(
        smoke_json["metadata_addr_hex"].as_str().unwrap(),
        metadata_case["addr_hex"].as_str().unwrap()
    );
    assert_eq!(
        smoke_json["transport_data_plane_deferred_to_item"]
            .as_u64()
            .unwrap(),
        113
    );

    let bad_aid = &fixture["unsupported"]["non_aead_alter_id_error"];
    let bad = run_with_args([
        "outbound",
        "vmess",
        "link",
        "--link",
        bad_aid["input"].as_str().unwrap(),
    ]);
    assert_eq!(bad.exit_code, 1);
    assert!(
        bad.stdout
            .contains(bad_aid["error_contains"].as_str().unwrap())
    );
}

#[test]
fn optin_runner_outbound_vless_commands_match_fixture() {
    let fixture = load("outbound/protocol/vless_native_optin.json");

    let contract = run_with_args(["outbound", "vless", "contract"]);
    assert_eq!(contract.exit_code, 0);
    assert_eq!(contract.stderr, "");
    let contract_json: Value = serde_json::from_str(&contract.stdout).unwrap();
    assert_eq!(
        contract_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        contract_json["rust_adapter_mode"].as_str().unwrap(),
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert!(contract_json["default_go_path"].as_bool().unwrap());

    let link_case = fixture["link_parser"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "xhttp-flow-none-omitted")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "vless",
        "link",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(link.exit_code, 0, "{}", link.stdout);
    assert_eq!(link.stderr, "");
    let link_json: Value = serde_json::from_str(&link.stdout).unwrap();
    assert_eq!(
        link_json["export"].as_str().unwrap(),
        link_case["export"].as_str().unwrap()
    );
    assert_eq!(link_json["flow"].as_str().unwrap(), "");

    let key = &fixture["key"];
    let key_cmd = run_with_args([
        "outbound",
        "vless",
        "key",
        "--password",
        key["short_input"].as_str().unwrap(),
    ]);
    assert_eq!(key_cmd.exit_code, 0);
    assert_eq!(key_cmd.stderr, "");
    let key_json: Value = serde_json::from_str(&key_cmd.stdout).unwrap();
    assert_eq!(
        key_json["key_hex"].as_str().unwrap(),
        key["short_key_hex"].as_str().unwrap()
    );

    let header_case = fixture["request_header"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "tcp-vision-addons")
        .unwrap();
    let header = run_with_args([
        "outbound",
        "vless",
        "request-header",
        "--password",
        key["canonical"].as_str().unwrap(),
        "--flow",
        header_case["flow"].as_str().unwrap(),
        "--network",
        header_case["network"].as_str().unwrap(),
        "--target",
        header_case["target"].as_str().unwrap(),
        "--payload",
        header_case["payload_ascii"].as_str().unwrap(),
    ]);
    assert_eq!(header.exit_code, 0, "{}", header.stdout);
    assert_eq!(header.stderr, "");
    let header_json: Value = serde_json::from_str(&header.stdout).unwrap();
    assert_eq!(
        header_json["captured_hex"].as_str().unwrap(),
        header_case["captured_hex"].as_str().unwrap()
    );

    let smoke = run_with_args([
        "outbound",
        "vless",
        "smoke",
        "--link",
        fixture["link_parser"][0]["input"].as_str().unwrap(),
        "--target",
        "example.com:443",
        "--payload",
        "ping",
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(
        smoke_json["transport_data_plane_deferred_to_item"]
            .as_u64()
            .unwrap(),
        113
    );

    let bad = run_with_args([
        "outbound",
        "vless",
        "link",
        "--link",
        fixture["unsupported"]["tcp_bad_header_type_error"]["input"]
            .as_str()
            .unwrap(),
    ]);
    assert_eq!(bad.exit_code, 1);
    assert!(
        bad.stdout.contains(
            fixture["unsupported"]["tcp_bad_header_type_error"]["error_contains"]
                .as_str()
                .unwrap()
        )
    );
}

#[test]
fn optin_runner_outbound_hysteria2_commands_match_fixture() {
    let fixture = load("outbound/protocol/hysteria2_native_optin.json");

    let contract = run_with_args(["outbound", "hysteria2", "contract"]);
    assert_eq!(contract.exit_code, 0);
    assert_eq!(contract.stderr, "");
    let contract_json: Value = serde_json::from_str(&contract.stdout).unwrap();
    assert_eq!(
        contract_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        contract_json["rust_adapter_mode"].as_str().unwrap(),
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert!(contract_json["default_go_path"].as_bool().unwrap());

    let link_case = fixture["link_parser"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "port-hopping")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "hy2",
        "link",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(link.exit_code, 0, "{}", link.stdout);
    assert_eq!(link.stderr, "");
    let link_json: Value = serde_json::from_str(&link.stdout).unwrap();
    assert_eq!(
        link_json["export"].as_str().unwrap(),
        link_case["export"].as_str().unwrap()
    );
    assert_eq!(
        link_json["pinSHA256_normal"].as_str().unwrap(),
        link_case["pinSHA256_normal"].as_str().unwrap()
    );

    let pin_case = &fixture["pin_sha256"][1];
    let pin = run_with_args([
        "outbound",
        "hysteria2",
        "pin",
        "--input",
        pin_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(pin.exit_code, 0);
    assert_eq!(pin.stderr, "");
    let pin_json: Value = serde_json::from_str(&pin.stdout).unwrap();
    assert_eq!(
        pin_json["normalized"].as_str().unwrap(),
        pin_case["normalized"].as_str().unwrap()
    );

    let server_case = fixture["server_contract"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["port_hopping"].as_bool().unwrap())
        .unwrap();
    let server = run_with_args([
        "outbound",
        "hysteria2",
        "server",
        "--server",
        server_case["server"].as_str().unwrap(),
    ]);
    assert_eq!(server.exit_code, 0);
    assert_eq!(server.stderr, "");
    let server_json: Value = serde_json::from_str(&server.stdout).unwrap();
    assert_eq!(
        server_json["host_port"].as_str().unwrap(),
        server_case["host_port"].as_str().unwrap()
    );
    assert!(server_json["port_hopping"].as_bool().unwrap());

    let smoke = run_with_args([
        "outbound",
        "hy2",
        "smoke",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(smoke_json["underlay_network"].as_str().unwrap(), "udp");
    assert_eq!(
        smoke_json["transport_data_plane_deferred_to_item"]
            .as_u64()
            .unwrap(),
        113
    );
}

#[test]
fn optin_runner_outbound_tuic_commands_match_fixture() {
    let fixture = load("outbound/protocol/tuic_native_optin.json");

    let contract = run_with_args(["outbound", "tuic", "contract"]);
    assert_eq!(contract.exit_code, 0);
    assert_eq!(contract.stderr, "");
    let contract_json: Value = serde_json::from_str(&contract.stdout).unwrap();
    assert_eq!(
        contract_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        contract_json["rust_adapter_mode"].as_str().unwrap(),
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert!(contract_json["default_go_path"].as_bool().unwrap());
    assert_eq!(
        contract_json["udp_relay_mode"]["go_protocol_effective_mode"]
            .as_str()
            .unwrap(),
        fixture["udp_relay_mode"]["go_protocol_effective_mode"]
            .as_str()
            .unwrap()
    );

    let link_case = fixture["link_parser"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "basic-quic-flag")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "tuic",
        "link",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(link.exit_code, 0, "{}", link.stdout);
    assert_eq!(link.stderr, "");
    let link_json: Value = serde_json::from_str(&link.stdout).unwrap();
    assert_eq!(
        link_json["export"].as_str().unwrap(),
        link_case["export"].as_str().unwrap()
    );
    assert_eq!(
        link_json["udp_relay_mode"].as_str().unwrap(),
        link_case["udp_relay_mode"].as_str().unwrap()
    );

    let uuid = run_with_args([
        "outbound",
        "tuic",
        "uuid",
        "--user",
        fixture["uuid_contract"]["valid"].as_str().unwrap(),
    ]);
    assert_eq!(uuid.exit_code, 0);
    assert_eq!(uuid.stderr, "");
    let uuid_json: Value = serde_json::from_str(&uuid.stdout).unwrap();
    assert!(uuid_json["ok"].as_bool().unwrap());

    let bad_uuid = run_with_args([
        "outbound",
        "tuic",
        "uuid",
        "--user",
        fixture["uuid_contract"]["invalid"].as_str().unwrap(),
    ]);
    assert_eq!(bad_uuid.exit_code, 1);
    assert!(
        bad_uuid.stdout.contains(
            fixture["uuid_contract"]["invalid_error"]["error_contains"]
                .as_str()
                .unwrap()
        )
    );

    let underlay = run_with_args([
        "outbound",
        "tuic",
        "underlay",
        "--network",
        "tcp",
        "--mark",
        "1234",
        "--mptcp",
        "true",
    ]);
    assert_eq!(underlay.exit_code, 0);
    assert_eq!(underlay.stderr, "");
    let underlay_json: Value = serde_json::from_str(&underlay.stdout).unwrap();
    assert_eq!(
        underlay_json["underlay_network"].as_str().unwrap(),
        fixture["underlay_contract"]["tcp_request"]["underlay_network"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        underlay_json["underlay_mptcp"].as_bool().unwrap(),
        fixture["underlay_contract"]["tcp_request"]["underlay_mptcp"]
            .as_bool()
            .unwrap()
    );

    let smoke = run_with_args([
        "outbound",
        "tuic",
        "smoke",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(
        smoke_json["udp_relay_effective_mode"].as_str().unwrap(),
        fixture["udp_relay_mode"]["go_protocol_effective_mode"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        smoke_json["transport_data_plane_deferred_to_item"]
            .as_u64()
            .unwrap(),
        fixture["underlay_contract"]["true_quic_data_plane_deferred"]
            .as_u64()
            .unwrap()
    );
}

#[test]
fn optin_runner_outbound_juicity_commands_match_fixture() {
    let fixture = load("outbound/protocol/juicity_native_optin.json");

    let contract = run_with_args(["outbound", "juicity", "contract"]);
    assert_eq!(contract.exit_code, 0);
    assert_eq!(contract.stderr, "");
    let contract_json: Value = serde_json::from_str(&contract.stdout).unwrap();
    assert_eq!(
        contract_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        contract_json["rust_adapter_mode"].as_str().unwrap(),
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert!(contract_json["default_go_path"].as_bool().unwrap());
    assert_eq!(
        contract_json["quic_contract"]["enable_datagrams"]
            .as_bool()
            .unwrap(),
        fixture["quic_contract"]["enable_datagrams"]
            .as_bool()
            .unwrap()
    );

    let link_case = fixture["link_parser"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "basic-urlbase64-pin")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "juicity",
        "link",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(link.exit_code, 0, "{}", link.stdout);
    assert_eq!(link.stderr, "");
    let link_json: Value = serde_json::from_str(&link.stdout).unwrap();
    assert_eq!(
        link_json["export"].as_str().unwrap(),
        link_case["export"].as_str().unwrap()
    );
    assert_eq!(
        link_json["pinned_certchain_decoded"]["format"]
            .as_str()
            .unwrap(),
        link_case["pinned_certchain_decoded"]["format"]
            .as_str()
            .unwrap()
    );

    let uuid = run_with_args([
        "outbound",
        "juicity",
        "uuid",
        "--user",
        fixture["uuid_contract"]["valid"].as_str().unwrap(),
    ]);
    assert_eq!(uuid.exit_code, 0);
    assert_eq!(uuid.stderr, "");
    let uuid_json: Value = serde_json::from_str(&uuid.stdout).unwrap();
    assert!(uuid_json["ok"].as_bool().unwrap());

    let bad_uuid = run_with_args([
        "outbound",
        "juicity",
        "uuid",
        "--user",
        fixture["uuid_contract"]["invalid"].as_str().unwrap(),
    ]);
    assert_eq!(bad_uuid.exit_code, 1);
    assert!(
        bad_uuid.stdout.contains(
            fixture["uuid_contract"]["invalid_error"]["error_contains"]
                .as_str()
                .unwrap()
        )
    );

    let pin_case = fixture["pinned_certchain_sha256"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "std-base64")
        .unwrap();
    let pin = run_with_args([
        "outbound",
        "juicity",
        "pin",
        "--input",
        pin_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(pin.exit_code, 0, "{}", pin.stdout);
    assert_eq!(pin.stderr, "");
    let pin_json: Value = serde_json::from_str(&pin.stdout).unwrap();
    assert_eq!(
        pin_json["format"].as_str().unwrap(),
        pin_case["format"].as_str().unwrap()
    );
    assert_eq!(
        pin_json["decoded_hex"].as_str().unwrap(),
        pin_case["decoded_hex"].as_str().unwrap()
    );

    let underlay = run_with_args([
        "outbound",
        "juicity",
        "underlay",
        "--network",
        "tcp",
        "--mark",
        "1234",
        "--mptcp",
        "true",
    ]);
    assert_eq!(underlay.exit_code, 0);
    assert_eq!(underlay.stderr, "");
    let underlay_json: Value = serde_json::from_str(&underlay.stdout).unwrap();
    assert_eq!(
        underlay_json["underlay_network"].as_str().unwrap(),
        fixture["underlay_contract"]["tcp_request"]["underlay_network"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        underlay_json["underlay_mptcp"].as_bool().unwrap(),
        fixture["underlay_contract"]["tcp_request"]["underlay_mptcp"]
            .as_bool()
            .unwrap()
    );

    let smoke = run_with_args([
        "outbound",
        "juicity",
        "smoke",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert!(!smoke_json["quic_enable_datagrams"].as_bool().unwrap());
    assert_eq!(
        smoke_json["udp_port_zero_packet_conn"].as_str().unwrap(),
        fixture["underlay_contract"]["udp_port_zero_packet_conn"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        smoke_json["transport_data_plane_deferred_to_item"]
            .as_u64()
            .unwrap(),
        fixture["underlay_contract"]["true_quic_data_plane_deferred"]
            .as_u64()
            .unwrap()
    );
}

#[test]
fn optin_runner_outbound_anytls_commands_match_fixture() {
    let fixture = load("outbound/protocol/anytls_native_optin.json");

    let contract = run_with_args(["outbound", "anytls", "contract"]);
    assert_eq!(contract.exit_code, 0);
    assert_eq!(contract.stderr, "");
    let contract_json: Value = serde_json::from_str(&contract.stdout).unwrap();
    assert_eq!(
        contract_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        contract_json["rust_adapter_mode"].as_str().unwrap(),
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert!(contract_json["default_go_path"].as_bool().unwrap());

    let link_case = fixture["link_parser"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["case"].as_str().unwrap() == "basic-insecure")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "anytls",
        "link",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(link.exit_code, 0, "{}", link.stdout);
    assert_eq!(link.stderr, "");
    let link_json: Value = serde_json::from_str(&link.stdout).unwrap();
    assert_eq!(
        link_json["link_preserved"].as_str().unwrap(),
        link_case["property_link"].as_str().unwrap()
    );
    assert_eq!(
        link_json["tls_server_name"].as_str().unwrap(),
        link_case["tls_server_name"].as_str().unwrap()
    );

    let auth = run_with_args([
        "outbound",
        "anytls",
        "auth-key",
        "--auth",
        fixture["auth_key"]["auth"].as_str().unwrap(),
    ]);
    assert_eq!(auth.exit_code, 0);
    assert_eq!(auth.stderr, "");
    let auth_json: Value = serde_json::from_str(&auth.stdout).unwrap();
    assert_eq!(
        auth_json["sha256_hex"].as_str().unwrap(),
        fixture["auth_key"]["sha256_hex"].as_str().unwrap()
    );
    assert_eq!(
        auth_json["handshake_hex"].as_str().unwrap(),
        fixture["session_contract"]["first_handshake"]["auth_key_then_zero_u16_hex"]
            .as_str()
            .unwrap()
    );

    let frame = run_with_args(["outbound", "anytls", "frame", "--target", "example.com:443"]);
    assert_eq!(frame.exit_code, 0);
    assert_eq!(frame.stderr, "");
    let frame_json: Value = serde_json::from_str(&frame.stdout).unwrap();
    assert_eq!(
        frame_json["settings_frame_hex"].as_str().unwrap(),
        fixture["session_contract"]["frame"]["settings_frame_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        frame_json["psh_addr_frame_hex"].as_str().unwrap(),
        fixture["session_contract"]["frame"]["psh_addr_frame_hex"]
            .as_str()
            .unwrap()
    );

    let packet = run_with_args([
        "outbound",
        "anytls",
        "packet",
        "--target",
        fixture["packet_stream"]["udp_input_target"]
            .as_str()
            .unwrap(),
        "--payload",
        "ping",
    ]);
    assert_eq!(packet.exit_code, 0);
    assert_eq!(packet.stderr, "");
    let packet_json: Value = serde_json::from_str(&packet.stdout).unwrap();
    assert_eq!(
        packet_json["udp_stream_target"].as_str().unwrap(),
        fixture["packet_stream"]["udp_stream_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        packet_json["first_write_hex"].as_str().unwrap(),
        fixture["packet_stream"]["first_write_hex"]
            .as_str()
            .unwrap()
    );

    let underlay = run_with_args([
        "outbound",
        "anytls",
        "underlay",
        "--network",
        "udp",
        "--mark",
        "1234",
        "--mptcp",
        "true",
    ]);
    assert_eq!(underlay.exit_code, 0);
    assert_eq!(underlay.stderr, "");
    let underlay_json: Value = serde_json::from_str(&underlay.stdout).unwrap();
    assert_eq!(
        underlay_json["underlay_network"].as_str().unwrap(),
        fixture["underlay_contract"]["udp_request"]["underlay_network"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        underlay_json["underlay_mptcp"].as_bool().unwrap(),
        fixture["underlay_contract"]["udp_request"]["underlay_mptcp"]
            .as_bool()
            .unwrap()
    );

    let smoke = run_with_args([
        "outbound",
        "anytls",
        "smoke",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(
        smoke_json["udp_stream_target"].as_str().unwrap(),
        fixture["packet_stream"]["udp_stream_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        smoke_json["transport_data_plane_deferred_to_item"]
            .as_u64()
            .unwrap(),
        fixture["underlay_contract"]["true_session_data_plane_deferred"]
            .as_u64()
            .unwrap()
    );
}

#[test]
fn optin_runner_outbound_transport_commands_match_fixture() {
    let fixture = load("outbound/protocol/shared_transport_native_optin.json");

    let contract = run_with_args(["outbound", "transport", "contract"]);
    assert_eq!(contract.exit_code, 0);
    assert_eq!(contract.stderr, "");
    let contract_json: Value = serde_json::from_str(&contract.stdout).unwrap();
    assert_eq!(
        contract_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        contract_json["rust_adapter_mode"].as_str().unwrap(),
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(contract_json["transport_scope"], fixture["transport_scope"]);
    assert_eq!(
        contract_json["grpc_transport"]["sample_cache_key_a"]
            .as_str()
            .unwrap(),
        fixture["grpc_transport"]["sample_cache_key_a"]
            .as_str()
            .unwrap()
    );

    let mode_case = fixture["xhttp_transport"]["mode_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "auto reality download")
        .unwrap();
    let mode = run_with_args([
        "outbound",
        "transport",
        "xhttp-mode",
        "--mode",
        mode_case["mode"].as_str().unwrap(),
        "--scheme",
        mode_case["scheme"].as_str().unwrap(),
        "--security",
        mode_case["security"].as_str().unwrap(),
        "--download",
        "true",
    ]);
    assert_eq!(mode.exit_code, 0);
    assert_eq!(mode.stderr, "");
    let mode_json: Value = serde_json::from_str(&mode.stdout).unwrap();
    assert_eq!(
        mode_json["normalized"].as_str().unwrap(),
        mode_case["normalized"].as_str().unwrap()
    );
    assert_eq!(
        mode_json["ok"].as_bool().unwrap(),
        mode_case["ok"].as_bool().unwrap()
    );

    let alpn_case = fixture["xhttp_transport"]["alpn_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "reality-h3")
        .unwrap();
    let alpn = run_with_args([
        "outbound",
        "transport",
        "xhttp-alpn",
        "--security",
        alpn_case["security"].as_str().unwrap(),
        "--alpn",
        alpn_case["alpn"].as_str().unwrap(),
    ]);
    assert_eq!(alpn.exit_code, 0);
    assert_eq!(alpn.stderr, "");
    let alpn_json: Value = serde_json::from_str(&alpn.stdout).unwrap();
    assert_eq!(
        alpn_json["ok"].as_bool().unwrap(),
        alpn_case["ok"].as_bool().unwrap()
    );
    assert_eq!(
        alpn_json["error_contains"].as_str().unwrap(),
        alpn_case["error_contains"].as_str().unwrap()
    );

    let path_case = &fixture["xhttp_transport"]["path_cases"][4];
    let path = run_with_args([
        "outbound",
        "transport",
        "xhttp-path",
        "--input",
        path_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(path.exit_code, 0);
    assert_eq!(path.stderr, "");
    let path_json: Value = serde_json::from_str(&path.stdout).unwrap();
    assert_eq!(
        path_json["path"].as_str().unwrap(),
        path_case["path"].as_str().unwrap()
    );
    assert_eq!(
        path_json["query"].as_str().unwrap(),
        path_case["query"].as_str().unwrap()
    );

    let extra = run_with_args([
        "outbound",
        "transport",
        "xhttp-extra",
        "--raw",
        fixture["xhttp_transport"]["extra_raw"].as_str().unwrap(),
    ]);
    assert_eq!(extra.exit_code, 0);
    assert_eq!(extra.stderr, "");
    let extra_json: Value = serde_json::from_str(&extra.stdout).unwrap();
    assert_eq!(
        extra_json["canonical"].as_str().unwrap(),
        fixture["xhttp_transport"]["extra_canonical"]
            .as_str()
            .unwrap()
    );

    let grpc = run_with_args([
        "outbound",
        "transport",
        "grpc-cache-key",
        "--address",
        "addr:443",
        "--server-name",
        "sni.example",
        "--dialer",
        "dialer-1",
        "--allow-insecure",
        "true",
        "--mark",
        "1234",
        "--mptcp",
        "true",
    ]);
    assert_eq!(grpc.exit_code, 0);
    assert_eq!(grpc.stderr, "");
    let grpc_json: Value = serde_json::from_str(&grpc.stdout).unwrap();
    assert_eq!(
        grpc_json["cache_key"].as_str().unwrap(),
        fixture["grpc_transport"]["sample_cache_key_a"]
            .as_str()
            .unwrap()
    );

    let reality = run_with_args([
        "outbound",
        "transport",
        "reality",
        "--sid",
        fixture["reality_transport"]["sid_input"].as_str().unwrap(),
        "--pbk",
        fixture["reality_transport"]["pbk_input"].as_str().unwrap(),
        "--spx",
        fixture["reality_transport"]["spx_input"].as_str().unwrap(),
    ]);
    assert_eq!(reality.exit_code, 0);
    assert_eq!(reality.stderr, "");
    let reality_json: Value = serde_json::from_str(&reality.stdout).unwrap();
    assert_eq!(
        reality_json["sid_decoded_hex"].as_str().unwrap(),
        fixture["reality_transport"]["sid_decoded_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        reality_json["pbk_decoded_hex"].as_str().unwrap(),
        fixture["reality_transport"]["pbk_decoded_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        reality_json["spider_y"],
        fixture["reality_transport"]["spider_y"]
    );

    let smoke = run_with_args(["outbound", "transport", "smoke"]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(
        smoke_json["rust_adapter_mode"].as_str().unwrap(),
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert!(
        smoke_json["true_transport_data_plane_deferred"]
            .as_bool()
            .unwrap()
    );
}

fn assert_commands(got: &[CommandSpec], want: &[Value]) {
    assert_eq!(got.len(), want.len());
    for (got, want) in got.iter().zip(want.iter()) {
        assert_eq!(got.name, want["name"].as_str().unwrap());
        assert_eq!(got.use_line, want["use"].as_str().unwrap());
        assert_eq!(got.short, want["short"].as_str().unwrap());
        assert_eq!(got.hidden, want["hidden"].as_bool().unwrap());
        assert_eq!(
            got.valid_args,
            want["valid_args"]
                .as_array()
                .map(|values| values
                    .iter()
                    .map(|value| value.as_str().unwrap())
                    .collect::<Vec<_>>())
                .unwrap_or_default()
                .as_slice()
        );
        assert_eq!(
            got.flags,
            want["flags"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<Vec<_>>()
                .as_slice()
        );
        let empty = Vec::new();
        let children = want["children"].as_array().unwrap_or(&empty);
        assert_commands(&got.children, children);
    }
}

fn load(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}

fn temp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "dae-cli-test-{}-{nanos}-{name}",
        std::process::id()
    ))
}

fn write_config(content: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "dae-cli-optin-test-{}-{nanos}.dae",
        std::process::id()
    ));
    fs::write(&path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

fn spawn_fake_socks5_server(
    require_auth: bool,
    expected_cmd: u8,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut head = [0_u8; 2];
        stream.read_exact(&mut head).unwrap();
        assert_eq!(head[0], 5);
        let mut methods = vec![0_u8; head[1] as usize];
        stream.read_exact(&mut methods).unwrap();
        let selected = if require_auth { 2 } else { 0 };
        assert!(methods.contains(&selected));
        stream.write_all(&[5, selected]).unwrap();

        if require_auth {
            let mut auth_head = [0_u8; 2];
            stream.read_exact(&mut auth_head).unwrap();
            assert_eq!(auth_head, [1, 4]);
            let mut user = vec![0_u8; auth_head[1] as usize];
            stream.read_exact(&mut user).unwrap();
            let mut pass_len = [0_u8; 1];
            stream.read_exact(&mut pass_len).unwrap();
            let mut pass = vec![0_u8; pass_len[0] as usize];
            stream.read_exact(&mut pass).unwrap();
            assert_eq!(user, b"user");
            assert_eq!(pass, b"pass");
            stream.write_all(&[1, 0]).unwrap();
        }

        let mut request_head = [0_u8; 3];
        stream.read_exact(&mut request_head).unwrap();
        assert_eq!(request_head, [5, expected_cmd, 0]);
        let _ = read_socks5_addr_for_test(&mut stream);
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x14, 0xb4])
            .unwrap();
    });
    (addr, handle)
}

fn read_socks5_addr_for_test(stream: &mut TcpStream) -> Vec<u8> {
    let mut atyp = [0_u8; 1];
    stream.read_exact(&mut atyp).unwrap();
    let mut out = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            stream.read_exact(&mut rest).unwrap();
            out.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).unwrap();
            out.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).unwrap();
            out.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream.read_exact(&mut rest).unwrap();
            out.extend_from_slice(&rest);
        }
        _ => {}
    }
    out
}

fn spawn_fake_http_proxy(
    expected_request_line: &'static str,
    expected_auth: Option<&'static str>,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut data = Vec::new();
        let mut buf = [0_u8; 256];
        loop {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0);
            data.extend_from_slice(&buf[..n]);
            if data.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(data).unwrap();
        let mut lines = request.split("\r\n");
        assert_eq!(lines.next().unwrap(), expected_request_line);
        if let Some(expected_auth) = expected_auth {
            assert!(request.contains(&format!("Proxy-Authorization: {expected_auth}\r\n")));
        }
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });
    (addr, handle)
}

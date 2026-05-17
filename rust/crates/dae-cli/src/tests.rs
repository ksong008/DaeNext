use serde_json::Value;
use std::fs;
use std::path::PathBuf;
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

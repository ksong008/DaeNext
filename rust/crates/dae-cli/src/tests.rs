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

use super::*;

#[test]
fn validate_and_export_surfaces_are_callable() {
    validate_config_text("global {}\nrouting {}\n").unwrap();
    let outline = export_outline_json("unknown");
    assert!(outline.contains("\"global\""));
    assert!(outline.contains("\"routing\""));
}

#[test]
fn runtime_runner_matches_validate_and_export_fixture() {
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

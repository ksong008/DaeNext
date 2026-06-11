use super::*;

#[test]
fn cli_surface_matches_nativelden_fixture() {
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
fn completion_matches_nativelden_fixture() {
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

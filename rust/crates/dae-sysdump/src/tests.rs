use serde_json::Value;

use crate::*;

#[test]
fn archive_path_safety_matches_golden_fixture() {
    let fixture = load("sysdump/archive/path_safety.json");
    let base = fixture["base_name"].as_str().unwrap();
    let entries = modeled_archive_entries(base);
    let want = fixture["entries"].as_array().unwrap();
    assert_eq!(entries.len(), want.len());

    for (got, want) in entries.iter().zip(want) {
        assert_eq!(got.name, want["name"].as_str().unwrap());
        assert_eq!(got.typeflag, want["typeflag"].as_u64().unwrap() as u8);
        assert_eq!(got.regular, want["regular"].as_bool().unwrap());
        if got.regular {
            assert_eq!(got.content.unwrap(), want["content"].as_str().unwrap());
        }
    }

    assert!(fixture["rules"]["uses_relative_paths"].as_bool().unwrap());
    assert!(entries.iter().all(|entry| !entry.name.starts_with('/')));
    assert!(entries.iter().all(|entry| entry.name.contains('/')));
    assert!(
        entries
            .iter()
            .filter(|entry| !entry.regular)
            .all(|entry| entry.content.is_none())
    );
}

#[test]
fn archive_reject_escape_contract_matches_golden_fixture() {
    let fixture = load("sysdump/archive/reject_escape.json");
    let prefix = fixture["unsafe_path_error_prefix"].as_str().unwrap();
    let absolute = archive_header_name("base", "/etc/passwd").unwrap_err();
    let dotdot = archive_header_name("base", "../routing.txt").unwrap_err();
    assert!(absolute.to_string().starts_with(prefix));
    assert!(dotdot.to_string().starts_with(prefix));
    assert_eq!(
        fixture["absolute_rel_rejected"].as_bool().unwrap(),
        !is_safe_archive_relative_path("/etc/passwd")
    );
    assert_eq!(
        fixture["dotdot_rel_rejected"].as_bool().unwrap(),
        !is_safe_archive_relative_path("../routing.txt")
    );
    assert!(fixture["walk_error_is_hard_error"].as_bool().unwrap());
}

#[test]
fn enum_strings_match_golden_fixture() {
    let fixture = load("sysdump/enum_strings.json");
    for case in fixture["scope"].as_array().unwrap() {
        assert_eq!(
            scope_to_string(case["value"].as_u64().unwrap() as u32),
            case["string"].as_str().unwrap()
        );
    }
    for case in fixture["protocol"].as_array().unwrap() {
        assert_eq!(
            protocol_to_string(case["value"].as_u64().unwrap() as u32),
            case["string"].as_str().unwrap()
        );
    }
    for case in fixture["route_type"].as_array().unwrap() {
        assert_eq!(
            route_type_to_string(case["value"].as_u64().unwrap() as u32),
            case["string"].as_str().unwrap()
        );
    }
}

#[test]
fn collector_best_effort_contract_matches_golden_fixture() {
    let fixture = load("sysdump/collector_best_effort.json");
    let collectors = stage8_collectors();
    let want = fixture["collectors"].as_array().unwrap();
    assert_eq!(collectors.len(), want.len());
    for (got, want) in collectors.iter().zip(want) {
        assert_eq!(got.name, want["name"].as_str().unwrap());
        assert_eq!(got.output, want["output"].as_str().unwrap());
        assert_eq!(got.failure, want["failure"].as_str().unwrap());
    }
    assert!(fixture["archive_failure_is_hard_error"].as_bool().unwrap());
    assert_eq!(
        fixture["external_command_missing_rule"].as_str().unwrap(),
        "print command error and continue collecting remaining sections"
    );
}

fn load(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}

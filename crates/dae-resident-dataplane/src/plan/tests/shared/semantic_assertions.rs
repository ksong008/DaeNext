pub(crate) fn assert_protocol_matrix_source_uses_generic_semantics(source: &str) {
    let lower = source.to_ascii_lowercase();
    let forbidden_terms = [
        ["matrix", "-"].concat(),
        ["invalid", "-", "test", "-", "format"].concat(),
        ["203", ".0.113"].concat(),
        ["198", ".51.100"].concat(),
        ["156", ".246"].concat(),
        ["127", ".0.0.1"].concat(),
        ["8", ".8.8"].concat(),
        ["proxy", ".example"].concat(),
        ["relay", ".example"].concat(),
        ["front", ".example"].concat(),
        ["office", ".example"].concat(),
        ["check", ".example"].concat(),
        ["global", ".example"].concat(),
        ["group", ".example"].concat(),
        ["dns", ".global"].concat(),
        ["dns", ".group"].concat(),
        ["example", ".com"].concat(),
        ["example", ".net"].concat(),
        ["password", "@"].concat(),
        [":", "password", "@"].concat(),
        ["01234567", "-89ab"].concat(),
        ["mti", "zndu2"].concat(),
    ];
    for forbidden in forbidden_terms {
        assert!(
            !lower.contains(&forbidden),
            "protocol matrix source fixtures must use protocol-generic semantics, found {forbidden}"
        );
    }
    {
        let forbidden = ["GENERIC", "_"].concat();
        assert!(
            !source.contains(&forbidden),
            "protocol matrix source fixtures must not use hardcoded generic constants, found {forbidden}"
        );
    }
    for link in url_like_source_literals(source) {
        assert_resident_source_fixture_uses_generic_semantics(&link);
    }
}

#[test]
pub(crate) fn protocol_matrix_source_fixtures_use_generic_semantics() {
    for path in PROTOCOL_MATRIX_SOURCE_PATHS {
        let source = read_daemon_source(path);
        assert_protocol_matrix_source_uses_generic_semantics(&source);
    }
}

const PROTOCOL_MATRIX_SOURCE_PATHS: &[&str] = &[
    "src/plan.rs",
    "src/plan/model.rs",
    "src/plan/transport_defaults.rs",
    "src/plan/group_plan.rs",
    "src/plan/dataplane_builder.rs",
    "src/plan/group_selector.rs",
    "src/plan/check_plans.rs",
    "src/plan/proxy_builders.rs",
    "src/plan/public_helpers.rs",
    "src/plan/fingerprint_dial.rs",
    "src/plan/selection_policy.rs",
    "src/plan/link_parsing.rs",
    "src/plan/tests.rs",
    "src/plan/tests/shared.rs",
    "src/plan/tests/group_selection.rs",
    "src/plan/tests/resident_handlers.rs",
    "src/plan/tests/matrix_blocked.rs",
    "src/plan/tests/fingerprint.rs",
    "src/plan/tests/shared/imports.rs",
    "src/plan/tests/shared/generic_fixtures.rs",
    "src/plan/tests/shared/semantic_assertions.rs",
    "src/plan/tests/shared/config.rs",
    "src/plan/tests/shared/shadowsocks_fixtures.rs",
    "src/plan/tests/shared/vless_fixtures.rs",
    "src/plan/tests/shared/trojan_fixtures.rs",
    "src/plan/tests/shared/quic_fixtures.rs",
    "src/plan/tests/shared/vmess_fixtures.rs",
    "src/plan/tests/shared/source_fixture_contract.rs",
    "src/plan/tests/group_selection/selection.rs",
    "src/plan/tests/group_selection/probes.rs",
    "src/plan/tests/group_selection/latency.rs",
    "src/plan/tests/group_selection/fail_closed.rs",
];

fn read_daemon_source(path: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|err| panic!("failed to read {}: {}", path, err))
}

pub(crate) fn url_like_source_literals(source: &str) -> Vec<String> {
    let mut links = Vec::new();
    let mut offset = 0;
    while let Some(relative_pos) = source[offset..].find("://") {
        let scheme_end = offset + relative_pos;
        let mut start = scheme_end;
        while start > 0 {
            let previous = source.as_bytes()[start - 1];
            if previous.is_ascii_alphanumeric() || matches!(previous, b'+' | b'-' | b'.') {
                start -= 1;
            } else {
                break;
            }
        }

        let mut end = scheme_end + 3;
        while end < source.len() {
            let next = source.as_bytes()[end];
            if next.is_ascii_whitespace()
                || matches!(next, b'"' | b'\'' | b'`' | b'<' | b'>' | b')' | b']')
            {
                break;
            }
            end += 1;
        }

        links.push(source[start..end].to_owned());
        offset = end;
    }
    links
}

pub(crate) fn assert_resident_source_fixture_uses_generic_semantics(link: &str) {
    let lower = link.to_ascii_lowercase();
    let forbidden_terms = [
        ["matrix", "-"].concat(),
        ["invalid", "-", "test", "-", "format"].concat(),
        ["203", ".0.113"].concat(),
        ["198", ".51.100"].concat(),
        ["156", ".246"].concat(),
        ["127", ".0.0.1"].concat(),
        ["8", ".8.8"].concat(),
        ["proxy", ".example"].concat(),
        ["relay", ".example"].concat(),
        ["front", ".example"].concat(),
        ["office", ".example"].concat(),
        ["check", ".example"].concat(),
        ["global", ".example"].concat(),
        ["group", ".example"].concat(),
        ["dns", ".global"].concat(),
        ["dns", ".group"].concat(),
        ["example", ".com"].concat(),
        ["example", ".net"].concat(),
        ["password", "@"].concat(),
        [":", "password", "@"].concat(),
        ["01234567", "-89ab"].concat(),
        ["mti", "zndu2"].concat(),
    ];
    for forbidden in forbidden_terms {
        assert!(
            !lower.contains(&forbidden),
            "source fixture must use common import semantics, found {forbidden} in {link}"
        );
    }
    assert!(
        !link.contains('#'),
        "source fixture must not use fragment labels as matrix evidence: {link}"
    );
    if let Some(userinfo) = source_link_userinfo(link) {
        let lower_userinfo = userinfo.to_ascii_lowercase();
        for forbidden in ["matrix", "-password", "-auth"] {
            assert!(
                !lower_userinfo.contains(forbidden),
                "source fixture userinfo must be protocol-generic, found {forbidden} in {link}"
            );
        }
    }
}

pub(crate) fn source_link_userinfo(link: &str) -> Option<&str> {
    let authority = link.split_once("://")?.1;
    let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
    authority.rsplit_once('@').map(|(userinfo, _)| userinfo)
}

use super::super::OUTBOUND_CONNECTIVITY_MAP_NAME;
use super::super::build_resident_userspace_routing_matcher;
use super::super::maps::{resident_user_outbound_ids, runtime_map_name_matches};
use super::super::plan::build_routing_plan;
use super::*;
use dae_routing::DomainKey;
#[test]
pub(super) fn resident_routing_plan_compiles_lan_proxy_rules() {
    let sections = parse_config(
        r#"
global {
    lan_interface: daerust0
}
group {
    proxy {
        policy: fixed(0)
    }
}
routing {
    dip(100.64.0.2) -> must_direct
    l4proto(tcp) && dport(443) -> proxy
    l4proto(udp) && dport(53) -> proxy
    fallback: direct
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let plan = build_routing_plan(&config).unwrap();

    assert!(plan.skipped_rules.is_empty());
    assert_eq!(plan.lpm_sets.len(), 1);
    assert!(
        plan.matches
            .iter()
            .any(|set| set.kind == "IpSet" && set.must)
    );
    assert!(plan.matches.iter().any(|set| set.kind == "L4Proto"));
    assert!(plan.matches.iter().any(|set| set.kind == "Port"));
    assert_eq!(plan.matches.last().unwrap().kind, "Fallback");
    assert_eq!(
        plan.matches.last().unwrap().outbound,
        OutboundIndex::DIRECT.value()
    );
    assert_eq!(
        resident_user_outbound_ids(&config),
        vec![OutboundIndex::USER_DEFINED_MIN.value()]
    );
    assert!(runtime_map_name_matches(
        "outbound_connec",
        OUTBOUND_CONNECTIVITY_MAP_NAME
    ));
}

#[test]
pub(super) fn resident_routing_plan_groups_domain_values_like_compatible_builder() {
    let sections = parse_config(
        r#"
global {
    lan_interface: daerust0
}
group {
    proxy {
        policy: fixed(0)
    }
}
routing {
    domain(suffix: fixture.invalid, suffix: org.fixture.invalid, full: exact.fixture.invalid) -> proxy
    fallback: direct
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let plan = build_routing_plan(&config).unwrap();

    assert_eq!(plan.domain_sets.len(), 2);
    assert!(plan.domain_sets.iter().any(|set| {
        domain_set_matches(
            set,
            DomainKey::Suffix,
            &["fixture.invalid", "org.fixture.invalid"],
        )
    }));
    assert!(
        plan.domain_sets
            .iter()
            .any(|set| { domain_set_matches(set, DomainKey::Full, &["exact.fixture.invalid"]) })
    );
    assert_eq!(
        plan.matches
            .iter()
            .filter(|set| set.kind == "DomainSet")
            .count(),
        plan.domain_sets.len()
    );
}

fn domain_set_matches(
    set: &super::super::types::ResidentDomainSet,
    key: DomainKey,
    values: &[&str],
) -> bool {
    set.values.key() == key
        && set
            .values
            .patterns()
            .iter()
            .map(String::as_str)
            .eq(values.iter().copied())
}

#[test]
pub(super) fn resident_routing_domain_rule_indices_match_main_match_positions() {
    let sections = parse_config(
        r#"
global {
    lan_interface: daerust0
}
group {
    proxy {
        policy: fixed(0)
    }
}
routing {
    ip(203.0.113.0/24) -> direct
    domain(full: exact.example.test, suffix: media.example.test) -> proxy
    port(443) && domain(keyword: video) -> proxy
    fallback: block
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let plan = build_routing_plan(&config).unwrap();

    let domain_rule_indices = plan
        .domain_sets
        .iter()
        .map(|set| set.rule_index)
        .collect::<Vec<_>>();
    assert_eq!(domain_rule_indices, vec![1, 2, 3]);
    for index in domain_rule_indices {
        assert_eq!(
            plan.matches[index].kind, "DomainSet",
            "domain set bit {index} must point at the main routing match slot"
        );
    }

    let matcher = build_resident_userspace_routing_matcher(&config).unwrap();
    assert_eq!(
        matcher
            .domain_bitmap_for_domain("exact.example.test")
            .unwrap(),
        vec![0x2]
    );
    assert_eq!(
        matcher
            .domain_bitmap_for_domain("www.media.example.test")
            .unwrap(),
        vec![0x4]
    );
    assert_eq!(
        matcher
            .domain_bitmap_for_domain("video.invalid.test")
            .unwrap(),
        vec![0x8]
    );
}

#[test]
pub(super) fn resident_routing_plan_compiles_full_function_matrix() {
    let sections = parse_config(
        r#"
global {
    lan_interface: daerust0
}
group {
    proxy {
        policy: fixed(0)
    }
}
routing {
    sip(100.65.0.0/24) && sport(40000-50000) -> direct
    ip(100.64.0.0/24) && port(443) -> proxy
    l4proto(tcp, udp) -> proxy
    ipversion(4, 6) -> proxy
    mac('aa:bb:cc:dd:ee:ff') -> proxy
    pname(curl) -> proxy
    dscp(46) -> must_rules
    domain(suffix: fixture.invalid) -> proxy(mark: 7)
    fallback: block
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let plan = build_routing_plan(&config).unwrap();

    assert!(plan.skipped_rules.is_empty());
    for kind in [
        "SourceIpSet",
        "SourcePort",
        "IpSet",
        "Port",
        "L4Proto",
        "IpVersion",
        "Mac",
        "ProcessName",
        "Dscp",
        "DomainSet",
        "Fallback",
    ] {
        assert!(
            plan.matches.iter().any(|set| set.kind == kind),
            "missing resident routing match kind {kind}"
        );
    }
    assert!(plan.lpm_sets.len() >= 3);
    assert!(
        plan.matches
            .iter()
            .any(|set| set.kind == "Dscp" && set.outbound == OutboundIndex::MUST_RULES.value())
    );
    assert!(
        plan.matches
            .iter()
            .any(|set| set.kind == "DomainSet" && set.mark == 7)
    );
    assert_eq!(
        plan.matches.last().unwrap().outbound,
        OutboundIndex::BLOCK.value()
    );
}

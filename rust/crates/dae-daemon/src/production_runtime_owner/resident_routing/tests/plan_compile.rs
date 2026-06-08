use super::super::OUTBOUND_CONNECTIVITY_MAP_NAME;
use super::super::maps::{resident_user_outbound_ids, runtime_map_name_matches};
use super::super::plan::build_routing_plan;
use super::*;
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
    dip(156.246.90.2) -> must_direct
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
pub(super) fn resident_routing_plan_groups_domain_values_like_go_builder() {
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
    domain(suffix: example.com, suffix: example.org, full: exact.example.net) -> proxy
    fallback: direct
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let plan = build_routing_plan(&config).unwrap();

    assert_eq!(plan.domain_sets.len(), 2);
    assert!(plan.domain_sets.iter().any(|set| {
        set.key == "suffix"
            && set.values == vec!["example.com".to_owned(), "example.org".to_owned()]
    }));
    assert!(
        plan.domain_sets
            .iter()
            .any(|set| { set.key == "full" && set.values == vec!["exact.example.net".to_owned()] })
    );
    assert_eq!(
        plan.matches
            .iter()
            .filter(|set| set.kind == "DomainSet")
            .count(),
        plan.domain_sets.len()
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
    sip(198.51.100.0/24) && sport(40000-50000) -> direct
    ip(203.0.113.0/24) && port(443) -> proxy
    l4proto(tcp, udp) -> proxy
    ipversion(4, 6) -> proxy
    mac('aa:bb:cc:dd:ee:ff') -> proxy
    pname(curl) -> proxy
    dscp(46) -> must_rules
    domain(suffix: example.com) -> proxy(mark: 7)
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

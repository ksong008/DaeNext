use super::super::build_resident_userspace_routing_matcher;
use super::*;
#[test]
pub(super) fn resident_userspace_routing_matcher_preserves_group_outbound_indices() {
    let sections = parse_config(
        r#"
global {
    lan_interface: daerust0
}
group {
    proxy {
        policy: fixed(0)
    }
    openai {
        policy: fixed(0)
    }
}
routing {
    domain(suffix: googleapis.com) -> openai
    fallback: proxy
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let matcher = build_resident_userspace_routing_matcher(&config).unwrap();

    let outcome = matcher
        .match_query_detail(&dae_routing::Query::tcp(
            "142.250.191.170".parse().unwrap(),
            443,
            "www.googleapis.com",
        ))
        .unwrap();
    assert_eq!(outcome.outbound, OutboundIndex(3));
    assert_eq!(outcome.mark, 0);
    assert!(!outcome.must);

    let fallback = matcher
        .match_query(&dae_routing::Query::tcp(
            "93.184.216.34".parse().unwrap(),
            443,
            "example.org",
        ))
        .unwrap();
    assert_eq!(fallback, OutboundIndex(2));
}

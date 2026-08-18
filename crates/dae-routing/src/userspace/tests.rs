#[cfg(test)]
mod userspace_matcher_tests {
    use super::super::*;
    use std::str::FromStr;

    #[test]
    fn userspace_matcher_matches_golden_fixture() {
        let fixture = dae_golden::load_json("routing/userspace/basic_matcher.json").unwrap();

        for case in fixture["cases"].as_array().unwrap() {
            let matcher = RoutingMatcher::from_fixture_value(&case["matcher"]).unwrap();
            for query in case["queries"].as_array().unwrap() {
                let parsed = Query {
                    dest: IpAddr::from_str(query["dest"].as_str().unwrap()).unwrap(),
                    dest_port: u16::try_from(query["dest_port"].as_u64().unwrap()).unwrap(),
                    domain: query["domain"].as_str().unwrap().to_owned(),
                    ..Query::default()
                };
                let outbound = matcher.match_query(&parsed).unwrap();

                assert_eq!(outbound.to_string(), query["want"].as_str().unwrap());
            }
        }
    }

    #[test]
    fn userspace_matcher_covers_full_native_function_matrix() {
        let matcher = RoutingMatcher::from_fixture_value(&serde_json::json!({
            "domain_sets": [
                {"bit": 9, "key": "suffix", "patterns": ["example.com"]}
            ],
            "lpm_sets": [
                {"index": 0, "prefixes": ["203.0.113.0/24"]},
                {"index": 1, "prefixes": ["198.51.100.0/24"]},
                {"index": 2, "prefixes": ["::aabb:ccdd:ee00/128"]}
            ],
            "matches": [
                {"type": "source_ip_set", "lpm_index": 1, "outbound": "logical_or"},
                {"type": "source_port", "port_start": 40000, "port_end": 50000, "outbound": "logical_and"},
                {"type": "ip_set", "lpm_index": 0, "outbound": "logical_and"},
                {"type": "port", "port_start": 443, "port_end": 443, "outbound": "logical_and"},
                {"type": "l4proto", "l4proto": "tcp", "outbound": "logical_and"},
                {"type": "ipversion", "ipversion": "4", "outbound": "logical_and"},
                {"type": "mac", "lpm_index": 2, "outbound": "logical_and"},
                {"type": "process_name", "process_name": "curl", "outbound": "logical_and"},
                {"type": "dscp", "dscp": 46, "outbound": "must_rules"},
                {"type": "domain_set", "outbound": "direct", "mark": 1234},
                {"type": "fallback", "outbound": "block"}
            ]
        }))
        .unwrap();
        let outcome = matcher
            .match_query_detail(&Query {
                source: Some(IpAddr::from_str("198.51.100.42").unwrap()),
                dest: IpAddr::from_str("203.0.113.42").unwrap(),
                source_port: Some(45000),
                dest_port: 443,
                l4proto: Some(L4_TCP),
                domain: "www.example.com".to_owned(),
                process_name: Some("curl".to_owned()),
                dscp: Some(46),
                mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00]),
                ..Query::default()
            })
            .unwrap();

        assert_eq!(outcome.outbound, OutboundIndex::DIRECT);
        assert_eq!(outcome.mark, 1234);
        assert!(outcome.must);

        let fallback = matcher
            .match_query(&Query {
                source: Some(IpAddr::from_str("198.51.100.42").unwrap()),
                dest: IpAddr::from_str("203.0.113.42").unwrap(),
                source_port: Some(45000),
                dest_port: 443,
                l4proto: Some(L4_UDP),
                domain: "www.invalid.test".to_owned(),
                process_name: Some("curl".to_owned()),
                dscp: Some(46),
                mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00]),
                ..Query::default()
            })
            .unwrap();
        assert_eq!(fallback, OutboundIndex::BLOCK);
    }

    #[test]
    fn userspace_matcher_reuses_domain_bitmap_buffer() {
        let fixture = dae_golden::load_json("routing/userspace/basic_matcher.json").unwrap();
        let case = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"].as_str() == Some("domain-suffix-direct-else-block"))
            .unwrap();
        let matcher = RoutingMatcher::from_fixture_value(&case["matcher"]).unwrap();
        let query = Query::tcp(
            IpAddr::from_str("203.0.113.42").unwrap(),
            443,
            "www.example.com",
        );
        let mut bitmap = vec![0xaaaaaaaa; matcher.domain_bitmap_words()];
        let outcome = matcher
            .match_query_detail_with_bitmap(&query, &mut bitmap)
            .unwrap();

        assert_eq!(outcome.outbound, OutboundIndex::DIRECT);
        assert_eq!(bitmap[0], 1);

        let err = matcher
            .match_query_detail_with_bitmap(&query, &mut [])
            .unwrap_err();
        assert!(err.to_string().contains("domain bitmap buffer too short"));
    }

    #[test]
    fn userspace_matcher_exposes_domain_bitmap_for_dns_routing_cache() {
        let matcher = RoutingMatcher::from_fixture_value(&serde_json::json!({
            "domain_sets": [
                {"bit": 0, "key": "suffix", "patterns": ["example.com"]},
                {"bit": 3, "key": "full", "patterns": ["api.service.test"]}
            ],
            "matches": [
                {"type": "domain_set", "outbound": "direct"},
                {"type": "fallback", "outbound": "block"},
                {"type": "fallback", "outbound": "block"},
                {"type": "domain_set", "outbound": "block"}
            ]
        }))
        .unwrap();

        assert_eq!(
            matcher
                .domain_bitmap_for_domain("WWW.EXAMPLE.COM.")
                .unwrap(),
            vec![0x1]
        );
        assert_eq!(
            matcher
                .domain_bitmap_for_domain("api.service.test.")
                .unwrap(),
            vec![0x8]
        );
        assert_eq!(
            matcher.domain_bitmap_for_domain("invalid.test").unwrap(),
            vec![0]
        );
    }

    #[test]
    fn indexed_prefix_sets_preserve_match_order_marks_and_ip_families() {
        let ipv4 = (0..64)
            .map(|index| IpPrefix::parse(&format!("198.51.{index}.42/32")).unwrap())
            .collect();
        let ipv6 = (0..64)
            .map(|index| IpPrefix::parse(&format!("2001:db8:{index:x}::/48")).unwrap())
            .collect();
        let matcher = RoutingMatcher::from_typed_sets(
            Vec::new(),
            vec![
                RoutingLpmSet {
                    index: 10,
                    prefixes: ipv4,
                },
                RoutingLpmSet {
                    index: 20,
                    prefixes: ipv6,
                },
            ],
            vec![
                RoutingMatchSet {
                    kind: RoutingMatchKind::IpSet { lpm_index: 10 },
                    outbound: OutboundIndex::BLOCK,
                    not: false,
                    mark: 11,
                    must: false,
                },
                RoutingMatchSet {
                    kind: RoutingMatchKind::IpSet { lpm_index: 20 },
                    outbound: OutboundIndex::DIRECT,
                    not: false,
                    mark: 22,
                    must: true,
                },
                RoutingMatchSet {
                    kind: RoutingMatchKind::Fallback,
                    outbound: OutboundIndex::DIRECT,
                    not: false,
                    mark: 33,
                    must: false,
                },
            ],
        )
        .unwrap();

        assert_eq!(
            matcher
                .match_query_detail(&Query::tcp("198.51.63.42".parse().unwrap(), 443, ""))
                .unwrap(),
            MatchOutcome {
                outbound: OutboundIndex::BLOCK,
                mark: 11,
                must: false,
            }
        );
        assert_eq!(
            matcher
                .match_query_detail(&Query::tcp("2001:db8:3f::1".parse().unwrap(), 443, ""))
                .unwrap(),
            MatchOutcome {
                outbound: OutboundIndex::DIRECT,
                mark: 22,
                must: true,
            }
        );
        assert_eq!(
            matcher
                .match_query_detail(&Query::tcp("203.0.113.1".parse().unwrap(), 443, ""))
                .unwrap(),
            MatchOutcome {
                outbound: OutboundIndex::DIRECT,
                mark: 33,
                must: false,
            }
        );
    }
}

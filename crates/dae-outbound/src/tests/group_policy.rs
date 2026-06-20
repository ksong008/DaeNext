use super::*;

#[test]
fn group_selection_matches_nativelden_fixtures() {
    let fixed = fixture("outbound/group/fixed.json");
    let mut group = DialerGroup::new(
        "fixed",
        vec![Dialer::new("dialer0", ""), Dialer::new("dialer1", "")],
        vec![Annotation::default(), Annotation::default()],
        SelectionPolicy::Fixed {
            index: fixed["policy"]["fixed_index"].as_u64().unwrap() as usize,
        },
        false,
        0,
    );
    assert!(!group.has_alive_state());
    for case in fixed["cases"].as_array().unwrap() {
        group = DialerGroup::new(
            "fixed",
            vec![Dialer::new("dialer0", ""), Dialer::new("dialer1", "")],
            vec![Annotation::default(), Annotation::default()],
            SelectionPolicy::Fixed {
                index: case["fixed_index"].as_u64().unwrap() as usize,
            },
            false,
            0,
        );
        for _ in 0..case["select_count"].as_u64().unwrap() {
            let selected = group.select(NetworkType::TCP4, false).unwrap();
            assert_eq!(
                selected.index,
                case["want_index"].as_u64().unwrap() as usize
            );
        }
    }

    let min = fixture("outbound/group/min_last_latency.json");
    for case in min["cases"].as_array().unwrap() {
        let mut group = make_group(4, SelectionPolicy::MinLastLatency);
        for (index, latency) in case["latency_ms"].as_array().unwrap().iter().enumerate() {
            group.set_last_latency(index, NetworkType::TCP4, latency.as_i64().unwrap());
            group.notify_alive(
                index,
                NetworkType::TCP4,
                case["alive"].as_array().unwrap()[index].as_bool().unwrap(),
            );
        }
        let selected = group.select(NetworkType::TCP4, false).unwrap();
        assert_eq!(
            selected.index,
            case["want_index"].as_u64().unwrap() as usize
        );
        assert_eq!(
            selected.latency_ms,
            case["want_latency_ms"].as_i64().unwrap()
        );
    }

    let avg10 = fixture("outbound/group/min_avg10.json");
    let case = &avg10["cases"][0];
    let mut group = make_group(2, SelectionPolicy::MinAverage10);
    for latency in case["dialer0_ms"].as_array().unwrap() {
        group.set_last_latency(0, NetworkType::TCP4, latency.as_i64().unwrap());
    }
    for latency in case["dialer1_ms"].as_array().unwrap() {
        group.set_last_latency(1, NetworkType::TCP4, latency.as_i64().unwrap());
    }
    group.notify_alive(0, NetworkType::TCP4, true);
    group.notify_alive(1, NetworkType::TCP4, true);
    let selected = group.select(NetworkType::TCP4, false).unwrap();
    assert_eq!(
        selected.index,
        case["want_index"].as_u64().unwrap() as usize
    );
    assert_eq!(
        selected.latency_ms,
        case["want_latency_ms"].as_i64().unwrap()
    );

    let moving = fixture("outbound/group/min_moving_avg.json");
    let mut group = make_group(2, SelectionPolicy::MinMovingAverage);
    for case in moving["cases"].as_array().unwrap() {
        for (index, latency) in case["moving_avg_ms"].as_array().unwrap().iter().enumerate() {
            group.set_moving_average(index, NetworkType::TCP4, latency.as_i64().unwrap());
            group.notify_alive(index, NetworkType::TCP4, true);
        }
        let selected = group.select(NetworkType::TCP4, false).unwrap();
        assert_eq!(
            selected.index,
            case["want_index"].as_u64().unwrap() as usize
        );
        assert_eq!(
            selected.latency_ms,
            case["want_latency_ms"].as_i64().unwrap()
        );
    }
}

#[test]
fn failed_check_without_latency_marks_dead_without_polluting_latency_history() {
    let mut group = make_group(2, SelectionPolicy::MinAverage10);
    group.record_check_result(0, NetworkType::TCP4, Some(80), 1);
    group.record_check_result(1, NetworkType::TCP4, Some(40), 2);
    assert_eq!(group.select(NetworkType::TCP4, false).unwrap().index, 1);

    group.record_check_failure_without_latency(1, NetworkType::TCP4, 3);
    assert_eq!(group.select(NetworkType::TCP4, false).unwrap().index, 0);

    group.record_check_result(1, NetworkType::TCP4, Some(30), 4);
    assert_eq!(group.select(NetworkType::TCP4, false).unwrap().index, 1);
}

#[test]
fn random_and_ipversion_fallback_match_golden_fixtures() {
    let random = fixture("outbound/group/random_alive.json");
    let mut group = make_group(
        random["dialer_count"].as_u64().unwrap() as usize,
        SelectionPolicy::Random,
    );
    let dead_index = random["dead_index"].as_u64().unwrap() as usize;
    group.notify_alive(dead_index, NetworkType::TCP4, false);
    let mut count = vec![0usize; group.dialers.len()];
    for _ in 0..random["selection_attempts"].as_u64().unwrap() {
        let selected = group.select(NetworkType::TCP4, false).unwrap();
        count[selected.index] += 1;
    }
    assert_eq!(
        count.iter().sum::<usize>(),
        random["want_total"].as_u64().unwrap() as usize
    );
    assert_eq!(
        count[dead_index],
        random["dead_selected_count"].as_u64().unwrap() as usize
    );
    assert!(
        !group
            .alive_set(NetworkType::TCP4)
            .unwrap()
            .latency_state_allocated
    );

    let fallback = fixture("outbound/group/ipversion_fallback_no_mutation.json");
    let mut group = make_group(1, SelectionPolicy::Random);
    group.notify_alive(
        0,
        NetworkType::TCP4,
        fallback["ipv4_alive"].as_bool().unwrap(),
    );
    group.notify_alive(
        0,
        NetworkType::TCP6,
        fallback["ipv6_alive"].as_bool().unwrap(),
    );
    let input = NetworkType::TCP4;
    assert_eq!(group.select(input, false).unwrap().index, 0);
    assert_eq!(input, NetworkType::TCP4);
}

#[test]
fn filter_annotation_and_bad_regex_match_golden_fixtures() {
    let filter_fixture = fixture("outbound/filter/name_and_subscription_tag.json");
    let set = DialerSet {
        dialers: filter_fixture["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|node| {
                Dialer::new(
                    node["name"].as_str().unwrap(),
                    node["subscription_tag"].as_str().unwrap(),
                )
            })
            .collect(),
    };
    let filter_groups = vec![
        vec![
            Filter::new(
                "name",
                vec![FilterParam::new(
                    "regex",
                    filter_fixture["filter_groups"][0]["filters"][0]["value"]
                        .as_str()
                        .unwrap(),
                )],
            ),
            Filter::new(
                "subtag",
                vec![FilterParam::new(
                    "regex",
                    filter_fixture["filter_groups"][0]["filters"][1]["value"]
                        .as_str()
                        .unwrap(),
                )],
            ),
        ],
        vec![Filter::new(
            "name",
            vec![FilterParam::new(
                "keyword",
                filter_fixture["filter_groups"][1]["filters"][0]["value"]
                    .as_str()
                    .unwrap(),
            )],
        )],
    ];
    let annotations = vec![
        Annotation { add_latency_ms: 10 },
        Annotation { add_latency_ms: 25 },
    ];
    let got = set
        .filter_and_annotate(&filter_groups, &annotations)
        .unwrap();
    let matched = filter_fixture["matched"].as_array().unwrap();
    assert_eq!(got.len(), matched.len());
    for want in matched {
        let found = got
            .iter()
            .find(|got| got.name == want["name"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            found.annotation.add_latency_ms,
            want["add_latency_ms"].as_i64().unwrap()
        );
    }

    let bad = fixture("outbound/filter/bad_regex.json");
    let bad_filter = vec![vec![Filter::new(
        "name",
        vec![FilterParam::new(
            "regex",
            bad["bad_regex"].as_str().unwrap(),
        )],
    )]];
    assert!(
        DialerSet {
            dialers: vec![Dialer::new("HK-Netflix", "premium-sub")]
        }
        .filter_and_annotate(&bad_filter, &[Annotation::default()])
        .is_err()
    );
    assert!(
        DialerSet { dialers: vec![] }
            .filter_and_annotate(&bad_filter, &[Annotation::default()])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn lazy_state_and_alive_sets_match_golden_fixtures() {
    let lazy = fixture("outbound/dialer/lazy_state.json");
    let mut dialer = Dialer::new("test", "");
    assert_eq!(
        dialer.probe_http_client_created(),
        !lazy["new_dialer"]["probe_http_client_nil"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(dialer.collection_allocated_count(), 0);
    assert!(!dialer.has_alive_dialer_sets());

    let (latency, alive, checked_at, ok) = dialer.last_latency_snapshot(NetworkType::TCP4);
    assert_eq!(latency, 0);
    assert!(alive);
    assert_eq!(checked_at, 0);
    assert!(!ok);
    assert_eq!(dialer.collection_allocated_count(), 0);
    assert!(dialer.must_get_alive(NetworkType::TCP4));
    assert_eq!(dialer.collection_allocated_count(), 0);
    dialer.must_get_latencies10(NetworkType::TCP4);
    assert_eq!(dialer.collection_allocated_count(), 1);
    let client = dialer.get_probe_http_client_id();
    assert!(dialer.probe_http_client_created());
    assert!(dialer.probe_http_transport_created());
    assert_eq!(dialer.get_probe_http_client_id(), client);

    let random = fixture("outbound/alive_set/random_skips_latency_state.json");
    let dialers = vec![Dialer::new("a", ""), Dialer::new("b", "")];
    let mut alive = AliveDialerSet::new(
        NetworkType::TCP4,
        SelectionPolicy::Random,
        &dialers,
        &[Annotation::default(), Annotation::default()],
        0,
        true,
    );
    assert_eq!(
        alive.latency_state_allocated,
        random["dialer_to_latency_allocated"].as_bool().unwrap()
    );
    assert_eq!(
        alive.alive_count(),
        random["initial_alive_count"].as_u64().unwrap() as usize
    );
    alive.set_alive(random["after_dead_index"].as_u64().unwrap() as usize, false);
    assert_eq!(
        alive.get_rand().unwrap(),
        random["want_remaining_selected_index"].as_u64().unwrap() as usize
    );

    let offsets = fixture("outbound/alive_set/latency_offset_sparse.json");
    let mut group = DialerGroup::new(
        "offset",
        vec![Dialer::new("a", ""), Dialer::new("b", "")],
        vec![
            Annotation { add_latency_ms: 0 },
            Annotation { add_latency_ms: 50 },
        ],
        SelectionPolicy::MinLastLatency,
        false,
        0,
    );
    for index in 0..2 {
        group.set_last_latency(
            index,
            NetworkType::TCP4,
            offsets["raw_latency_ms"][index].as_i64().unwrap(),
        );
        group.notify_alive(index, NetworkType::TCP4, true);
    }
    let alive = group.alive_set(NetworkType::TCP4).unwrap();
    assert_eq!(
        alive.stored_latency_offset_count(),
        offsets["latency_offset_entries"].as_u64().unwrap() as usize
    );
    assert_eq!(group.select(NetworkType::TCP4, false).unwrap().index, 0);
}

#[test]
fn direct_link_parser_group_override_and_connectivity_match_golden_fixtures() {
    let direct = fixture("outbound/direct/injected_resolver.json");
    for case in direct["cases"].as_array().unwrap() {
        match case["name"].as_str().unwrap() {
            "symmetric-prefers-resolver-dialer" => {
                let got = select_direct_resolver(
                    &DirectOption {
                        resolver_dialer: true,
                        ..DirectOption::default()
                    },
                    false,
                );
                assert_eq!(got.selected, case["selected"].as_str().unwrap());
                assert_eq!(got.property_name, case["property_name"].as_str().unwrap());
            }
            "fullcone-prefers-fullcone-resolver-dialer" => {
                let got = select_direct_resolver(
                    &DirectOption {
                        resolver_fullcone_dialer: true,
                        ..DirectOption::default()
                    },
                    true,
                );
                assert_eq!(got.selected, case["selected"].as_str().unwrap());
            }
            "globals-unset-still-builds-fallback" => {
                assert!(
                    select_direct_resolver(&DirectOption::default(), false).fallback_constructed
                );
                assert!(
                    select_direct_resolver(&DirectOption::default(), true).fallback_constructed
                );
            }
            name => panic!("unexpected direct case {name}"),
        }
    }

    let ss2022 = fixture("outbound/protocol/ss2022_no_global_direct_dependency.json");
    let parsed = parse_link_chain(ss2022["link"].as_str().unwrap()).unwrap();
    assert_eq!(parsed.nodes[0].protocol, "shadowsocks-2022");
    assert_eq!(
        parsed.nodes[0].parent_dialer_non_nil,
        ss2022["parent_dialer_non_nil"].as_bool().unwrap()
    );

    let matrix = fixture("outbound/link_parser/compatibility_matrix.json");
    for case in matrix["cases"].as_array().unwrap() {
        let got = parse_link_chain(case["link"].as_str().unwrap());
        assert_eq!(got.is_ok(), case["ok"].as_bool().unwrap(), "{case:?}");
        if let Ok(parsed) = got {
            if let Some(chain_len) = case["chain_len"].as_u64() {
                assert_eq!(parsed.nodes.len(), chain_len as usize);
            }
            if let Some(scheme) = case["scheme"].as_str() {
                assert_eq!(parsed.nodes[0].scheme, scheme);
            }
            if let Some(adapter_mode) = case["adapter_mode"].as_str() {
                assert_eq!(parsed.nodes[0].adapter_mode, adapter_mode);
            }
        }
    }

    let override_fixture = fixture("outbound/group_override/clone_profile_key.json");
    let tcp = vec!["https://check.fixture.invalid/generate_204".to_owned()];
    let udp = vec!["8.8.8.8:53".to_owned()];
    let profile = HealthProfile::new(Some(&tcp), Some(&udp));
    let mut cache = GroupOverrideCloneCache::default();
    let clone_a = cache.clone_id(1, profile.clone());
    let clone_b = cache.clone_id(1, profile.clone());
    assert_eq!(clone_a, clone_b);
    assert_eq!(
        cache.created_count(),
        override_fixture["same_base_equivalent_profile"]["created_clones"]
            .as_u64()
            .unwrap() as usize
    );
    assert_ne!(cache.clone_id(2, profile.clone()), clone_a);

    for case in override_fixture["string_slice_profile_key"]
        .as_array()
        .unwrap()
    {
        let a = optional_string_vec(&case["a"]);
        let b = optional_string_vec(&case["b"]);
        assert_ne!(
            string_slice_profile_key(a.as_deref()),
            string_slice_profile_key(b.as_deref())
        );
    }

    let connectivity = fixture("outbound/connectivity/map_dimensions.json");
    let mut map = ConnectivityMap::default();
    map.record(2, NetworkType::TCP4, true, true, true);
    assert_eq!(
        map.get(OutboundConnectivityKey {
            outbound: 2,
            l4proto: L4Proto::Tcp,
            ipversion: IpVersion::V4,
        }),
        Some(connectivity["init_callback"]["value"].as_u64().unwrap() as u32)
    );
    map.record(2, NetworkType::TCP6, false, false, true);
    assert_eq!(map.len(), 1);
    map.record(2, NetworkType::TCP6, false, false, false);
    assert_eq!(
        map.get(OutboundConnectivityKey {
            outbound: 2,
            l4proto: L4Proto::Tcp,
            ipversion: IpVersion::V6,
        }),
        Some(connectivity["alive_false_value"].as_u64().unwrap() as u32)
    );
}

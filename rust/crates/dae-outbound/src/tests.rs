use serde_json::Value;

use crate::*;

#[test]
fn group_selection_matches_golden_fixtures() {
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
    let tcp = vec!["https://check.example/generate_204".to_owned()];
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

#[test]
fn socks5_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/socks5_native_optin.json");

    assert_eq!(
        crate::socks5::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::socks5::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::socks5::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    let link = &fixture["link_parser"];
    let parsed = parse_link_chain(link["input"].as_str().unwrap()).unwrap();
    assert_eq!(
        parsed.plaintext_tag.as_deref(),
        Some(link["plaintext_tag"].as_str().unwrap())
    );
    assert_eq!(parsed.linklike, link["linklike"].as_str().unwrap());
    assert_eq!(parsed.property_name, link["name"].as_str().unwrap());
    assert_eq!(parsed.property_protocol, link["protocol"].as_str().unwrap());
    assert_eq!(parsed.property_address, link["address"].as_str().unwrap());
    assert_eq!(parsed.nodes[0].adapter_mode, "native-opt-in");
    assert_eq!(
        parsed.nodes[1].scheme,
        link["socks_alias_scheme"].as_str().unwrap()
    );
    assert_eq!(
        parsed.nodes[1].protocol,
        link["socks_alias_protocol"].as_str().unwrap()
    );

    for case in fixture["address_codec"].as_array().unwrap() {
        let addr = crate::socks5::Socks5Address::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(
            hex_encode(&addr.encode().unwrap()),
            case["hex"].as_str().unwrap()
        );
        let encoded = hex_decode(case["hex"].as_str().unwrap());
        let (decoded, consumed) = crate::socks5::Socks5Address::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.authority(), case["string"].as_str().unwrap());
    }

    let handshake = &fixture["handshake"];
    assert_eq!(
        hex_encode(&crate::socks5::handshake::greeting("", "")),
        handshake["greeting_no_auth_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::socks5::handshake::greeting("user", "pass")),
        handshake["greeting_with_auth_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::socks5::handshake::username_password_auth("user", "pass").unwrap()),
        handshake["username_password_auth_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::socks5::handshake::connect_request("example.com:443").unwrap()),
        handshake["connect_example_com_443_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::socks5::handshake::udp_associate_request("0.0.0.0:0").unwrap()),
        handshake["udp_associate_0_0_0_0_0_hex"].as_str().unwrap()
    );
    let reply = crate::socks5::handshake::parse_server_reply(&hex_decode(
        handshake["success_reply_hex"].as_str().unwrap(),
    ))
    .unwrap();
    assert_eq!(reply.bind.authority(), "127.0.0.1:5300");

    let packet = &fixture["udp_packet"];
    let wrapped = crate::socks5::udp_packet::wrap_target(
        packet["target"].as_str().unwrap(),
        packet["payload_ascii"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    assert_eq!(
        hex_encode(&wrapped),
        packet["write_packet_hex"].as_str().unwrap()
    );
    let unwrapped = crate::socks5::udp_packet::unwrap(&wrapped).unwrap();
    assert_eq!(unwrapped.reserved, [0, 0]);
    assert_eq!(unwrapped.fragment, 0);
    assert_eq!(
        unwrapped.target.authority(),
        packet["target"].as_str().unwrap()
    );
    assert_eq!(
        String::from_utf8(unwrapped.payload).unwrap(),
        packet["payload_ascii"].as_str().unwrap()
    );
}

#[test]
fn http_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/http_native_optin.json");

    assert_eq!(
        crate::http_proxy::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::http_proxy::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::http_proxy::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    for case in fixture["link_parser"].as_array().unwrap() {
        let parsed =
            crate::http_proxy::HttpProxyLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.server, case["server"].as_str().unwrap());
        assert_eq!(parsed.port, case["port"].as_u64().unwrap() as u16);
        assert_eq!(parsed.username, case["username"].as_str().unwrap());
        assert_eq!(parsed.password, case["password"].as_str().unwrap());
        assert_eq!(parsed.sni, case["sni"].as_str().unwrap());
        assert_eq!(parsed.protocol.as_str(), case["protocol"].as_str().unwrap());
        assert_eq!(
            parsed.allow_insecure,
            case["allowInsecure"].as_bool().unwrap()
        );
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
        let parsed_chain = parse_link_chain(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed_chain.nodes[0].adapter_mode, "native-opt-in");
    }

    for case in fixture["connect"].as_array().unwrap() {
        let mut options =
            crate::http_proxy::HttpConnectOptions::connect(case["target"].as_str().unwrap());
        options.username = case["username"].as_str().unwrap().to_owned();
        options.password = case["password"].as_str().unwrap().to_owned();
        options.host_override = case["host_override"].as_str().unwrap().to_owned();
        options.transport.enabled = case["transport"].as_bool().unwrap();
        options.transport.path = case["path"].as_str().unwrap().to_owned();
        assert_eq!(
            hex_encode(&crate::http_proxy::request::connect_request(&options)),
            case["request_hex"].as_str().unwrap(),
            "{}",
            case["name"].as_str().unwrap()
        );
    }

    let passthrough = &fixture["http_request_passthrough"];
    assert_eq!(
        hex_encode(
            &crate::http_proxy::request::forward_http_request(&hex_decode(
                passthrough["input_hex"].as_str().unwrap()
            ))
            .unwrap()
        ),
        passthrough["request_hex"].as_str().unwrap()
    );

    let flags = &fixture["https_flags"];
    assert_eq!(
        crate::http_proxy::contract::HTTPS_DEFAULT_TLS_IMPLEMENTATION,
        flags["tls_implementation_default"].as_str().unwrap()
    );
    assert_eq!(
        crate::http_proxy::contract::HTTPS_DEFAULT_ALPN_QUERY_VALUE,
        flags["alpn_default_query_value"].as_str().unwrap()
    );
    assert_eq!(
        crate::http_proxy::contract::HTTPS_H2_ROUTE_CONTEXT_REQUIRED,
        flags["h2_route_context_required"].as_bool().unwrap()
    );
}

#[test]
fn shadowsocks_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/shadowsocks_native_optin.json");

    assert_eq!(
        crate::shadowsocks::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::shadowsocks::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::shadowsocks::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    for case in fixture["link_parser"].as_array().unwrap() {
        let parsed =
            crate::shadowsocks::ShadowsocksLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.server, case["server"].as_str().unwrap());
        assert_eq!(parsed.port, case["port"].as_u64().unwrap() as u16);
        assert_eq!(parsed.cipher, case["cipher"].as_str().unwrap());
        assert_eq!(parsed.password, case["password"].as_str().unwrap());
        assert_eq!(parsed.protocol, case["protocol"].as_str().unwrap());
        assert_eq!(parsed.udp, case["udp"].as_bool().unwrap());
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
        assert_eq!(parsed.plugin.name, case["plugin"]["name"].as_str().unwrap());
        assert_eq!(
            parsed.plugin.opts.tls,
            case["plugin"]["tls"].as_str().unwrap()
        );
        assert_eq!(
            parsed.plugin.opts.obfs,
            case["plugin"]["obfs"].as_str().unwrap()
        );
        assert_eq!(
            parsed.plugin.opts.host,
            case["plugin"]["host"].as_str().unwrap()
        );
        assert_eq!(
            parsed.plugin.opts.path,
            case["plugin"]["path"].as_str().unwrap()
        );
        let chain = parse_link_chain(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(chain.nodes[0].adapter_mode, "native-opt-in");
        assert_eq!(
            chain.property_address,
            case["property_address"].as_str().unwrap()
        );
    }

    for case in fixture["cipher_dispatch"].as_array().unwrap() {
        let info = crate::shadowsocks::classify_cipher(case["cipher"].as_str().unwrap()).unwrap();
        assert_eq!(
            info.go_protocol_dialer,
            case["go_protocol_dialer"].as_str().unwrap()
        );
        assert_eq!(
            info.rust_capability_label,
            case["rust_capability_label"].as_str().unwrap()
        );
        assert_eq!(
            info.export_userinfo_plain,
            case["export_userinfo_plain"].as_bool().unwrap()
        );
    }

    for case in fixture["metadata"].as_array().unwrap() {
        let metadata =
            crate::shadowsocks::ShadowsocksMetadata::parse(case["input"].as_str().unwrap())
                .unwrap();
        assert_eq!(
            metadata.metadata_type().byte(),
            case["type"].as_u64().unwrap() as u8
        );
        assert_eq!(metadata.hostname(), case["hostname"].as_str().unwrap());
        assert_eq!(metadata.port(), case["port"].as_u64().unwrap() as u16);
        assert_eq!(
            hex_encode(&metadata.encode().unwrap()),
            case["hex"].as_str().unwrap()
        );
    }

    for case in fixture["ss2022"]["cipher_conf"].as_array().unwrap() {
        let conf =
            crate::shadowsocks::ss2022::cipher_conf(case["cipher"].as_str().unwrap()).unwrap();
        assert_eq!(conf.key_len, case["key_len"].as_u64().unwrap() as usize);
        assert_eq!(conf.salt_len, case["salt_len"].as_u64().unwrap() as usize);
        assert_eq!(conf.nonce_len, case["nonce_len"].as_u64().unwrap() as usize);
        assert_eq!(conf.tag_len, case["tag_len"].as_u64().unwrap() as usize);
        assert_eq!(
            conf.packet_nonce_len,
            case["packet_nonce_len"].as_u64().unwrap() as usize
        );
        assert_eq!(conf.packet_cipher, case["packet_cipher"].as_bool().unwrap());
    }

    for case in fixture["ss2022"]["psk"].as_array().unwrap() {
        let info = crate::shadowsocks::ss2022::validate_psk_list(
            case["cipher"].as_str().unwrap(),
            case["password"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(info.psk_count, case["psk_count"].as_u64().unwrap() as usize);
        assert_eq!(
            info.upsk_index,
            case["upsk_index"].as_u64().unwrap() as usize
        );
        assert_eq!(
            info.expected_key_len,
            case["expected_key_len"].as_u64().unwrap() as usize
        );
    }

    let tcp = &fixture["ss2022"]["tcp_header"];
    let tcp_contract = crate::shadowsocks::ss2022::tcp_header_contract(
        tcp["target"].as_str().unwrap(),
        tcp["timestamp"].as_u64().unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(
        tcp_contract.fixed_header_len,
        tcp["fixed_header_len"].as_u64().unwrap() as usize
    );
    assert_eq!(
        tcp_contract.address_hex,
        tcp["address_hex"].as_str().unwrap()
    );
    assert!(tcp_contract.empty_initial_payload_has_padding);

    let udp = &fixture["ss2022"]["udp_packet_id"];
    let udp_contract =
        crate::shadowsocks::ss2022::udp_packet_id_contract(udp["cipher"].as_str().unwrap());
    assert_eq!(
        udp_contract.first_packet_id,
        udp["first_packet_id"].as_u64().unwrap()
    );
    assert_eq!(
        udp_contract.replay_window_size,
        udp["replay_window_size"].as_u64().unwrap() as usize
    );

    let replay = &fixture["ss2022"]["replay_filter"];
    let mut duplicate = crate::shadowsocks::ss2022::SlidingWindowFilter::new(
        replay["window"].as_u64().unwrap() as usize,
    );
    assert_eq!(
        duplicate.check_and_update(1),
        replay["first_packet_accepted"].as_bool().unwrap()
    );
    assert_eq!(
        duplicate.check_and_update(1),
        replay["duplicate_packet_accepted"].as_bool().unwrap()
    );
    let mut old = crate::shadowsocks::ss2022::SlidingWindowFilter::new(
        replay["window"].as_u64().unwrap() as usize,
    );
    for packet_id in [10, 11, 12, 13, 14] {
        assert!(old.check_and_update(packet_id));
    }
    assert_eq!(
        old.check_and_update(10),
        replay["too_old_packet_accepted"].as_bool().unwrap()
    );
}

#[test]
fn trojan_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/trojan_native_optin.json");

    assert_eq!(
        crate::trojan::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::trojan::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::trojan::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    for case in fixture["link_parser"].as_array().unwrap() {
        let parsed = crate::trojan::TrojanLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.server, case["server"].as_str().unwrap());
        assert_eq!(parsed.port, case["port"].as_u64().unwrap() as u16);
        assert_eq!(parsed.password, case["password"].as_str().unwrap());
        assert_eq!(parsed.sni, case["sni"].as_str().unwrap());
        assert_eq!(parsed.transport_type, case["type"].as_str().unwrap());
        assert_eq!(parsed.encryption, case["encryption"].as_str().unwrap());
        assert_eq!(parsed.host, case["host"].as_str().unwrap());
        assert_eq!(parsed.path, case["path"].as_str().unwrap());
        assert_eq!(parsed.service_name, case["serviceName"].as_str().unwrap());
        assert_eq!(
            parsed.allow_insecure,
            case["allowInsecure"].as_bool().unwrap()
        );
        assert_eq!(parsed.protocol, case["protocol"].as_str().unwrap());
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
        let chain = parse_link_chain(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(chain.nodes[0].adapter_mode, "native-opt-in");
        assert_eq!(
            chain.property_address,
            case["property_address"].as_str().unwrap()
        );
        assert_eq!(
            chain.property_protocol,
            case["property_protocol"].as_str().unwrap()
        );
    }

    for case in fixture["metadata"].as_array().unwrap() {
        let metadata = crate::trojan::TrojanMetadata::parse(
            case["network"].as_str().unwrap(),
            case["input"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            metadata.network.byte(),
            case["network_byte"].as_u64().unwrap() as u8
        );
        assert_eq!(
            metadata.metadata_type_byte(),
            case["type"].as_u64().unwrap() as u8
        );
        assert_eq!(metadata.hostname(), case["hostname"].as_str().unwrap());
        assert_eq!(metadata.port(), case["port"].as_u64().unwrap() as u16);
        assert_eq!(
            metadata.len().unwrap(),
            case["len"].as_u64().unwrap() as usize
        );
        assert_eq!(
            hex_encode(&metadata.encode().unwrap()),
            case["hex"].as_str().unwrap()
        );
    }

    let framing = &fixture["framing"];
    assert_eq!(
        crate::trojan::packet::password_sha224_hex(framing["password"].as_str().unwrap()),
        framing["password_sha224_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(crate::trojan::packet::CRLF),
        framing["crlf_hex"].as_str().unwrap()
    );
    let tcp = &framing["tcp_request_header"];
    assert_eq!(
        hex_encode(
            &crate::trojan::packet::tcp_request_header(
                framing["password"].as_str().unwrap(),
                tcp["network"].as_str().unwrap(),
                tcp["target"].as_str().unwrap(),
                tcp["payload_ascii"].as_str().unwrap().as_bytes(),
            )
            .unwrap()
        ),
        tcp["header_hex"].as_str().unwrap()
    );
    let udp = &framing["udp_packet"];
    assert_eq!(
        hex_encode(
            &crate::trojan::packet::udp_packet(
                udp["target"].as_str().unwrap(),
                udp["payload_ascii"].as_str().unwrap().as_bytes(),
            )
            .unwrap()
        ),
        udp["packet_hex"].as_str().unwrap()
    );

    let transport = &fixture["transport_contract"];
    assert_eq!(
        crate::trojan::contract::DEFAULT_TROJAN_TLS_BEFORE_TROJANC,
        transport["default_trojan_tls_before_trojanc"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        crate::trojan::contract::TROJAN_GO_GRPC_CONTAINS_TLS,
        transport["trojan_go_grpc_contains_tls"].as_bool().unwrap()
    );
    assert_eq!(
        crate::trojan::contract::TROJAN_GO_GRPC_NO_OUTER_TLS,
        transport["trojan_go_grpc_no_outer_tls"].as_bool().unwrap()
    );
    assert_eq!(
        crate::trojan::contract::TROJAN_GO_SS_INNER_LAYER,
        transport["trojan_go_ss_inner_layer"].as_bool().unwrap()
    );
}

fn make_group(count: usize, policy: SelectionPolicy) -> DialerGroup {
    DialerGroup::new(
        "test",
        (0..count)
            .map(|index| Dialer::new(format!("dialer{index}"), ""))
            .collect(),
        vec![Annotation::default(); count],
        policy,
        false,
        0,
    )
}

fn fixture(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}

fn optional_string_vec(value: &Value) -> Option<Vec<String>> {
    value.as_array().map(|items| {
        items
            .iter()
            .map(|item| item.as_str().unwrap().to_owned())
            .collect()
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let high = hex_nibble(chunk[0]);
            let low = hex_nibble(chunk[1]);
            (high << 4) | low
        })
        .collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("bad hex byte: {byte}"),
    }
}

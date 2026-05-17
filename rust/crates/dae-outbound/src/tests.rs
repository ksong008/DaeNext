use base64::{Engine as _, engine::general_purpose::STANDARD};
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

#[test]
fn vmess_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/vmess_native_optin.json");

    assert_eq!(
        crate::vmess::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::vmess::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::vmess::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    for case in fixture["link_parser"].as_array().unwrap() {
        let parsed = crate::vmess::VMessLink::parse(case["input"].as_str().unwrap()).unwrap();
        parsed.validate_aead().unwrap();
        parsed.validate_transport().unwrap();
        assert_eq!(parsed.ps, case["ps"].as_str().unwrap());
        assert_eq!(parsed.add, case["add"].as_str().unwrap());
        assert_eq!(parsed.port, case["port"].as_str().unwrap());
        assert_eq!(parsed.id, case["id"].as_str().unwrap());
        assert_eq!(parsed.aid, case["aid"].as_str().unwrap());
        assert_eq!(parsed.net, case["net"].as_str().unwrap());
        assert_eq!(parsed.r#type, case["type"].as_str().unwrap());
        assert_eq!(parsed.host, case["host"].as_str().unwrap());
        assert_eq!(parsed.sni, case["sni"].as_str().unwrap());
        assert_eq!(parsed.path, case["path"].as_str().unwrap());
        assert_eq!(parsed.tls, case["tls"].as_str().unwrap());
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
        assert_eq!(chain.property_name, case["property_name"].as_str().unwrap());
        assert_eq!(
            chain.property_protocol,
            case["property_protocol"].as_str().unwrap()
        );
    }

    let bad_aid = &fixture["unsupported"]["non_aead_alter_id_error"];
    let bad = crate::vmess::VMessLink::parse(bad_aid["input"].as_str().unwrap()).unwrap();
    let err = bad.validate_aead().unwrap_err().to_string();
    assert!(err.contains(bad_aid["error_contains"].as_str().unwrap()));
    assert_eq!(
        crate::vmess::contract::VMESS_REALITY_MUST_ERROR,
        fixture["transport_contract"]["vmess_reality_must_error"]
            .as_bool()
            .unwrap()
    );

    let uuid = &fixture["uuid"];
    assert_eq!(
        crate::vmess::uuid::normalize_vmess_uuid(uuid["canonical"].as_str().unwrap()),
        uuid["canonical"].as_str().unwrap()
    );
    assert_eq!(
        crate::vmess::uuid::normalize_vmess_uuid(uuid["short_input"].as_str().unwrap()),
        uuid["short_uuid5"].as_str().unwrap()
    );
    assert_eq!(
        crate::vmess::uuid::normalize_vmess_uuid(uuid["long_input"].as_str().unwrap()),
        uuid["long_uuid5"].as_str().unwrap()
    );

    for case in fixture["metadata"].as_array().unwrap() {
        let metadata = crate::vmess::VMessMetadata::parse(
            case["network"].as_str().unwrap(),
            case["input"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            metadata.network.byte(),
            case["network_byte"].as_u64().unwrap() as u8
        );
        assert_eq!(
            metadata.metadata_type().byte(),
            case["type"].as_u64().unwrap() as u8
        );
        assert_eq!(metadata.hostname(), case["hostname"].as_str().unwrap());
        assert_eq!(metadata.port(), case["port"].as_u64().unwrap() as u16);
        assert_eq!(
            metadata.addr_len(),
            case["addr_len"].as_u64().unwrap() as usize
        );
        let encoded = metadata.encode_addr().unwrap();
        assert_eq!(encoded.len(), case["packed_len"].as_u64().unwrap() as usize);
        assert_eq!(hex_encode(&encoded), case["addr_hex"].as_str().unwrap());
    }

    let header = &fixture["header_contract"];
    assert_eq!(
        crate::vmess::contract::HEADER_VERSION,
        header["version"].as_u64().unwrap() as u8
    );
    assert_eq!(
        crate::vmess::contract::OPTION_CHUNK_STREAM,
        header["option_chunk_stream"].as_u64().unwrap() as u8
    );
    assert_eq!(
        crate::vmess::contract::OPTION_CHUNK_LENGTH_MASKING,
        header["option_chunk_length_masking"].as_u64().unwrap() as u8
    );
    assert_eq!(
        crate::vmess::contract::OPTION_GLOBAL_PADDING,
        header["option_global_padding"].as_u64().unwrap() as u8
    );
    assert_eq!(
        crate::vmess::contract::SECURITY_AUTO_CIPHER,
        header["security_auto_cipher"].as_u64().unwrap() as u8
    );
}

#[test]
fn vless_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/vless_native_optin.json");

    assert_eq!(
        crate::vless::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::vless::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::vless::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    for case in fixture["link_parser"].as_array().unwrap() {
        let parsed = crate::vless::VLESSLink::parse(case["input"].as_str().unwrap()).unwrap();
        parsed.validate_flow_client(true).unwrap();
        parsed.validate_transport_contract().unwrap();
        assert_eq!(parsed.ps, case["ps"].as_str().unwrap());
        assert_eq!(parsed.add, case["add"].as_str().unwrap());
        assert_eq!(parsed.port, case["port"].as_str().unwrap());
        assert_eq!(parsed.id, case["id"].as_str().unwrap());
        assert_eq!(parsed.net, case["net"].as_str().unwrap());
        assert_eq!(parsed.r#type, case["type"].as_str().unwrap());
        assert_eq!(parsed.host, case["host"].as_str().unwrap());
        assert_eq!(parsed.sni, case["sni"].as_str().unwrap());
        assert_eq!(parsed.path, case["path"].as_str().unwrap());
        assert_eq!(parsed.xhttp_mode, case["mode"].as_str().unwrap());
        assert_eq!(parsed.xhttp_extra, case["extra"].as_str().unwrap());
        assert_eq!(parsed.tls, case["tls"].as_str().unwrap());
        assert_eq!(parsed.flow, case["flow"].as_str().unwrap());
        assert_eq!(parsed.alpn, case["alpn"].as_str().unwrap());
        assert_eq!(
            parsed.allow_insecure,
            case["allowInsecure"].as_bool().unwrap()
        );
        assert_eq!(parsed.fingerprint, case["fp"].as_str().unwrap());
        assert_eq!(parsed.public_key, case["pbk"].as_str().unwrap());
        assert_eq!(parsed.short_id, case["sid"].as_str().unwrap());
        assert_eq!(parsed.spider_x, case["spx"].as_str().unwrap());
        assert_eq!(parsed.protocol, case["protocol"].as_str().unwrap());
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
        let chain = parse_link_chain(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(chain.nodes[0].adapter_mode, "native-opt-in");
        assert_eq!(
            chain.property_address,
            case["property_address"].as_str().unwrap()
        );
        assert_eq!(chain.property_name, case["property_name"].as_str().unwrap());
        assert_eq!(
            chain.property_protocol,
            case["property_protocol"].as_str().unwrap()
        );
    }

    for case in fixture["allow_insecure_aliases"].as_array().unwrap() {
        let parsed = crate::vless::VLESSLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(
            parsed.allow_insecure,
            case["allowInsecure"].as_bool().unwrap()
        );
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
    }

    let unsupported = &fixture["unsupported"];
    let bad = crate::vless::VLESSLink {
        flow: unsupported["unsupported_flow_error"]["input_flow"]
            .as_str()
            .unwrap()
            .to_owned(),
        ..crate::vless::VLESSLink::parse(fixture["link_parser"][0]["input"].as_str().unwrap())
            .unwrap()
    };
    assert!(
        bad.validate_flow_client(true)
            .unwrap_err()
            .to_string()
            .contains(
                unsupported["unsupported_flow_error"]["error_contains"]
                    .as_str()
                    .unwrap()
            )
    );
    let server = crate::vless::VLESSLink {
        flow: crate::vless::contract::XTLS_RPRX_VISION.to_owned(),
        ..crate::vless::VLESSLink::parse(fixture["link_parser"][0]["input"].as_str().unwrap())
            .unwrap()
    };
    assert!(
        server
            .validate_flow_client(false)
            .unwrap_err()
            .to_string()
            .contains(
                unsupported["server_mode_vision_error"]["error_contains"]
                    .as_str()
                    .unwrap()
            )
    );
    let bad_tcp = crate::vless::VLESSLink::parse(
        unsupported["tcp_bad_header_type_error"]["input"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert!(
        bad_tcp
            .validate_transport_contract()
            .unwrap_err()
            .to_string()
            .contains(
                unsupported["tcp_bad_header_type_error"]["error_contains"]
                    .as_str()
                    .unwrap()
            )
    );

    let key = &fixture["key"];
    assert_eq!(
        hex_encode(&crate::vless::password_to_key(key["canonical"].as_str().unwrap()).unwrap()),
        key["canonical_key_hex"].as_str().unwrap()
    );
    assert_eq!(
        crate::vmess::uuid::normalize_vmess_uuid(key["short_input"].as_str().unwrap()),
        key["short_uuid5"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::vless::password_to_key(key["short_input"].as_str().unwrap()).unwrap()),
        key["short_key_hex"].as_str().unwrap()
    );

    for case in fixture["request_header"].as_array().unwrap() {
        let key =
            crate::vless::password_to_key(fixture["key"]["canonical"].as_str().unwrap()).unwrap();
        let got = crate::vless::packet::first_write_bytes(
            &key,
            case["flow"].as_str().unwrap(),
            case["network"].as_str().unwrap(),
            case["target"].as_str().unwrap(),
            case["mux"].as_bool().unwrap(),
            case["payload_ascii"].as_str().unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(hex_encode(&got), case["captured_hex"].as_str().unwrap());
    }

    let transport = &fixture["transport_contract"];
    assert_eq!(
        crate::vless::contract::XTLS_RPRX_VISION,
        transport["vision_flow"].as_str().unwrap()
    );
    assert_eq!(
        crate::vless::contract::VISION_REQUIRES_TLS_OR_REALITY_HOOK,
        transport["vision_requires_tls_or_reality_hook"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        crate::vless::contract::SHARED_TRANSPORT_DEFERRED_TO_ITEM,
        transport["shared_transport_deferred_to_item"]
            .as_u64()
            .unwrap() as u16
    );
}

#[test]
fn hysteria2_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/hysteria2_native_optin.json");

    assert_eq!(
        crate::hysteria2::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::hysteria2::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::hysteria2::contract::PROTOCOL_SCOPE,
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
            crate::hysteria2::Hysteria2Link::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.user, case["user"].as_str().unwrap());
        assert_eq!(parsed.password, case["password"].as_str().unwrap());
        assert_eq!(parsed.server, case["server"].as_str().unwrap());
        assert_eq!(parsed.insecure, case["insecure"].as_bool().unwrap());
        assert_eq!(parsed.sni, case["sni"].as_str().unwrap());
        assert_eq!(parsed.pin_sha256, case["pinSHA256"].as_str().unwrap());
        assert_eq!(parsed.max_tx, case["maxTx"].as_u64().unwrap());
        assert_eq!(parsed.max_rx, case["maxRx"].as_u64().unwrap());
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
        assert_eq!(
            crate::hysteria2::link::normalize_pin_sha256(&parsed.pin_sha256),
            case["pinSHA256_normal"].as_str().unwrap()
        );
        let chain = parse_link_chain(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(chain.nodes[0].adapter_mode, "native-opt-in");
        assert_eq!(
            chain.property_address,
            case["property_address"].as_str().unwrap()
        );
        assert_eq!(chain.property_name, case["property_name"].as_str().unwrap());
        assert_eq!(
            chain.property_protocol,
            case["property_protocol"].as_str().unwrap()
        );
    }

    for case in fixture["pin_sha256"].as_array().unwrap() {
        assert_eq!(
            crate::hysteria2::link::normalize_pin_sha256(case["input"].as_str().unwrap()),
            case["normalized"].as_str().unwrap()
        );
    }

    for case in fixture["server_contract"].as_array().unwrap() {
        let contract = crate::hysteria2::link::server_contract(case["server"].as_str().unwrap());
        assert_eq!(contract.host, case["host"].as_str().unwrap());
        assert_eq!(contract.port, case["port"].as_str().unwrap());
        assert_eq!(contract.host_port, case["host_port"].as_str().unwrap());
        assert_eq!(
            contract.port_hopping,
            case["port_hopping"].as_bool().unwrap()
        );
    }

    let underlay = &fixture["underlay_contract"];
    assert_eq!(
        crate::hysteria2::contract::ALWAYS_UDP_UNDERLAY,
        underlay["always_udp_underlay"].as_bool().unwrap()
    );
    assert_eq!(
        crate::hysteria2::contract::PRESERVE_MARK,
        underlay["preserve_mark"].as_bool().unwrap()
    );
    assert_eq!(
        crate::hysteria2::contract::TRUE_QUIC_DATA_PLANE_DEFERRED_ITEM,
        underlay["true_quic_data_plane_deferred_item"]
            .as_u64()
            .unwrap() as u16
    );
}

#[test]
fn tuic_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/tuic_native_optin.json");

    assert_eq!(
        crate::tuic::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::tuic::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::tuic::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    for case in fixture["link_parser"].as_array().unwrap() {
        let parsed = crate::tuic::TuicLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.user, case["user"].as_str().unwrap());
        assert_eq!(parsed.password, case["password"].as_str().unwrap());
        assert_eq!(parsed.server, case["server"].as_str().unwrap());
        assert_eq!(parsed.port, case["port"].as_u64().unwrap() as u16);
        assert_eq!(parsed.sni, case["sni"].as_str().unwrap());
        assert_eq!(
            parsed.allow_insecure,
            case["allowInsecure"].as_bool().unwrap()
        );
        assert_eq!(parsed.disable_sni, case["disable_sni"].as_bool().unwrap());
        assert_eq!(
            parsed.congestion_control,
            case["congestion_control"].as_str().unwrap()
        );
        assert_eq!(
            parsed.alpn,
            case["alpn"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .map(|value| value.as_str().unwrap().to_owned())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        );
        assert_eq!(
            parsed.udp_relay_mode,
            case["udp_relay_mode"].as_str().unwrap()
        );
        assert_eq!(parsed.protocol, case["protocol"].as_str().unwrap());
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
        assert_eq!(parsed.address(), case["property_address"].as_str().unwrap());
        parsed.validate_uuid().unwrap();
        let chain = parse_link_chain(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(chain.nodes[0].adapter_mode, "native-opt-in");
        assert_eq!(
            chain.property_address,
            case["property_address"].as_str().unwrap()
        );
        assert_eq!(chain.property_name, case["property_name"].as_str().unwrap());
        assert_eq!(
            chain.property_protocol,
            case["property_protocol"].as_str().unwrap()
        );
    }

    for case in fixture["allow_insecure_aliases"].as_array().unwrap() {
        let parsed = crate::tuic::TuicLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(
            parsed.allow_insecure,
            case["allowInsecure"].as_bool().unwrap()
        );
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
    }

    assert!(
        crate::tuic::link::validate_uuid(fixture["uuid_contract"]["valid"].as_str().unwrap())
            .is_ok()
    );
    let invalid =
        crate::tuic::link::validate_uuid(fixture["uuid_contract"]["invalid"].as_str().unwrap())
            .unwrap_err()
            .to_string();
    assert!(
        invalid.contains(
            fixture["uuid_contract"]["invalid_error"]["error_contains"]
                .as_str()
                .unwrap()
        )
    );

    let quic = &fixture["quic_contract"];
    assert_eq!(
        crate::tuic::contract::TLS_MIN_VERSION,
        quic["tls_min_version"].as_u64().unwrap() as u16
    );
    assert_eq!(
        crate::tuic::contract::ENABLE_DATAGRAMS,
        quic["enable_datagrams"].as_bool().unwrap()
    );
    assert_eq!(
        crate::tuic::contract::KEEPALIVE_SECONDS,
        quic["keepalive_seconds"].as_u64().unwrap()
    );
    assert_eq!(
        crate::tuic::contract::HANDSHAKE_IDLE_TIMEOUT_SECONDS,
        quic["handshake_idle_timeout_seconds"].as_u64().unwrap()
    );
    assert_eq!(
        crate::tuic::contract::MAX_UDP_RELAY_PACKET_SIZE,
        quic["max_udp_relay_packet_size"].as_u64().unwrap() as u16
    );

    let udp_relay = &fixture["udp_relay_mode"];
    assert_eq!(
        crate::tuic::contract::UDP_RELAY_MODE_GO_PROTOCOL_EFFECTIVE_MODE,
        udp_relay["go_protocol_effective_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::tuic::contract::UDP_RELAY_MODE_QUIC_FIXME_DEFERRED,
        udp_relay["quic_mode_fixme_deferred"].as_bool().unwrap()
    );

    let underlay = &fixture["underlay_contract"];
    let tcp = crate::tuic::link::underlay_contract("tcp", 1234, true);
    assert_eq!(
        tcp.underlay_network,
        underlay["tcp_request"]["underlay_network"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        tcp.underlay_mptcp,
        underlay["tcp_request"]["underlay_mptcp"].as_bool().unwrap()
    );
    assert_eq!(
        STANDARD.encode(&tcp.underlay_encoded),
        underlay["tcp_request"]["underlay_b64"].as_str().unwrap()
    );
    let udp = crate::tuic::link::underlay_contract("udp", 1234, true);
    assert_eq!(
        udp.underlay_network,
        underlay["udp_request"]["underlay_network"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        udp.underlay_mptcp,
        underlay["udp_request"]["underlay_mptcp"].as_bool().unwrap()
    );
    assert_eq!(
        STANDARD.encode(&udp.underlay_encoded),
        underlay["udp_request"]["underlay_b64"].as_str().unwrap()
    );
    assert_eq!(
        crate::tuic::contract::TRUE_QUIC_DATA_PLANE_DEFERRED_ITEM,
        underlay["true_quic_data_plane_deferred"].as_u64().unwrap() as u16
    );
}

#[test]
fn juicity_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/juicity_native_optin.json");

    assert_eq!(
        crate::juicity::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::juicity::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::juicity::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    for case in fixture["link_parser"].as_array().unwrap() {
        let parsed = crate::juicity::JuicityLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.user, case["user"].as_str().unwrap());
        assert_eq!(parsed.password, case["password"].as_str().unwrap());
        assert_eq!(parsed.server, case["server"].as_str().unwrap());
        assert_eq!(parsed.port, case["port"].as_u64().unwrap() as u16);
        assert_eq!(parsed.sni, case["sni"].as_str().unwrap());
        assert_eq!(
            parsed.allow_insecure,
            case["allowInsecure"].as_bool().unwrap()
        );
        assert_eq!(
            parsed.congestion_control,
            case["congestion_control"].as_str().unwrap()
        );
        assert_eq!(
            parsed.pinned_certchain_sha256,
            case["pinned_certchain_sha256"].as_str().unwrap()
        );
        assert_eq!(parsed.protocol, case["protocol"].as_str().unwrap());
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
        assert_eq!(parsed.address(), case["property_address"].as_str().unwrap());
        assert_eq!(
            parsed.pin_forces_insecure_verify(),
            case["pin_forces_insecure_verify"].as_bool().unwrap()
        );
        parsed.validate_uuid().unwrap();
        let decoded =
            crate::juicity::link::decode_pinned_certchain(&parsed.pinned_certchain_sha256).unwrap();
        assert_eq!(
            decoded.format,
            case["pinned_certchain_decoded"]["format"].as_str().unwrap()
        );
        assert_eq!(
            hex_encode(&decoded.decoded),
            case["pinned_certchain_decoded"]["decoded_hex"]
                .as_str()
                .unwrap()
        );
        let chain = parse_link_chain(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(chain.nodes[0].adapter_mode, "native-opt-in");
        assert_eq!(
            chain.property_address,
            case["property_address"].as_str().unwrap()
        );
        assert_eq!(chain.property_name, case["property_name"].as_str().unwrap());
        assert_eq!(
            chain.property_protocol,
            case["property_protocol"].as_str().unwrap()
        );
    }

    for case in fixture["allow_insecure_aliases"].as_array().unwrap() {
        let parsed = crate::juicity::JuicityLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(
            parsed.allow_insecure,
            case["allowInsecure"].as_bool().unwrap()
        );
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
    }

    for case in fixture["pinned_certchain_sha256"].as_array().unwrap() {
        let got = crate::juicity::link::decode_pinned_certchain(case["input"].as_str().unwrap());
        if case["ok"].as_bool().unwrap() {
            let got = got.unwrap();
            assert_eq!(got.format, case["format"].as_str().unwrap());
            assert_eq!(
                hex_encode(&got.decoded),
                case["decoded_hex"].as_str().unwrap()
            );
        } else {
            assert!(
                got.unwrap_err()
                    .to_string()
                    .contains(case["error_contains"].as_str().unwrap())
            );
        }
    }

    assert!(
        crate::juicity::link::validate_uuid(fixture["uuid_contract"]["valid"].as_str().unwrap())
            .is_ok()
    );
    let invalid =
        crate::juicity::link::validate_uuid(fixture["uuid_contract"]["invalid"].as_str().unwrap())
            .unwrap_err()
            .to_string();
    assert!(
        invalid.contains(
            fixture["uuid_contract"]["invalid_error"]["error_contains"]
                .as_str()
                .unwrap()
        )
    );

    let quic = &fixture["quic_contract"];
    assert_eq!(
        crate::juicity::contract::ALPN,
        quic["alpn"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );
    assert_eq!(
        crate::juicity::contract::TLS_MIN_VERSION,
        quic["tls_min_version"].as_u64().unwrap() as u16
    );
    assert_eq!(
        crate::juicity::contract::ENABLE_DATAGRAMS,
        quic["enable_datagrams"].as_bool().unwrap()
    );
    assert_eq!(
        crate::juicity::contract::KEEPALIVE_SECONDS,
        quic["keepalive_seconds"].as_u64().unwrap()
    );
    assert_eq!(
        crate::juicity::contract::RESERVED_STREAMS_CAPABILITY,
        quic["reserved_streams_capability"].as_u64().unwrap()
    );

    let underlay = &fixture["underlay_contract"];
    let tcp = crate::juicity::link::underlay_contract("tcp", 1234, true);
    assert_eq!(
        tcp.underlay_network,
        underlay["tcp_request"]["underlay_network"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        tcp.underlay_mptcp,
        underlay["tcp_request"]["underlay_mptcp"].as_bool().unwrap()
    );
    assert_eq!(
        STANDARD.encode(&tcp.underlay_encoded),
        underlay["tcp_request"]["underlay_b64"].as_str().unwrap()
    );
    let udp = crate::juicity::link::underlay_contract("udp", 1234, true);
    assert_eq!(
        udp.underlay_network,
        underlay["udp_request"]["underlay_network"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        udp.underlay_mptcp,
        underlay["udp_request"]["underlay_mptcp"].as_bool().unwrap()
    );
    assert_eq!(
        crate::juicity::contract::UDP_PORT_ZERO_PACKET_CONN,
        underlay["udp_port_zero_packet_conn"].as_str().unwrap()
    );
    assert_eq!(
        crate::juicity::contract::UDP_NONZERO_PORT_PACKET_CONN,
        underlay["udp_nonzero_port_packet_conn"].as_str().unwrap()
    );
    assert_eq!(
        crate::juicity::contract::TRUE_QUIC_DATA_PLANE_DEFERRED_ITEM,
        underlay["true_quic_data_plane_deferred"].as_u64().unwrap() as u16
    );
}

#[test]
fn anytls_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/anytls_native_optin.json");

    assert_eq!(
        crate::anytls::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::anytls::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::anytls::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    for case in fixture["link_parser"].as_array().unwrap() {
        let parsed = crate::anytls::AnyTLSLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.name, case["name"].as_str().unwrap());
        assert_eq!(parsed.auth, case["auth"].as_str().unwrap());
        assert_eq!(parsed.host, case["host"].as_str().unwrap());
        assert_eq!(parsed.hostname, case["hostname"].as_str().unwrap());
        assert_eq!(parsed.sni, case["sni"].as_str().unwrap());
        assert_eq!(
            parsed.tls_server_name,
            case["tls_server_name"].as_str().unwrap()
        );
        assert_eq!(parsed.insecure, case["insecure"].as_bool().unwrap());
        assert_eq!(parsed.protocol, case["protocol"].as_str().unwrap());
        assert_eq!(parsed.export_url(), case["property_link"].as_str().unwrap());
        assert_eq!(parsed.address(), case["property_address"].as_str().unwrap());
        let chain = parse_link_chain(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(chain.nodes[0].adapter_mode, "native-opt-in");
        assert_eq!(
            chain.property_address,
            case["property_address"].as_str().unwrap()
        );
        assert_eq!(chain.property_name, case["property_name"].as_str().unwrap());
        assert_eq!(
            chain.property_protocol,
            case["property_protocol"].as_str().unwrap()
        );
    }

    for case in fixture["insecure_cases"].as_array().unwrap() {
        let parsed = crate::anytls::AnyTLSLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.insecure, case["insecure"].as_bool().unwrap());
    }

    let tls = &fixture["tls_contract"];
    assert_eq!(
        crate::anytls::contract::EMPTY_SNI_SERVER_NAME,
        tls["empty_sni_server_name"].as_str().unwrap()
    );
    assert_eq!(
        crate::anytls::contract::INSECURE_ONLY_WHEN,
        tls["insecure_only_when"].as_str().unwrap()
    );
    assert_eq!(
        crate::anytls::contract::PEER_OVERRIDES_SNI,
        tls["peer_overrides_sni"].as_bool().unwrap()
    );

    let auth = &fixture["auth_key"];
    assert_eq!(
        hex_encode(&crate::anytls::link::auth_key(
            auth["auth"].as_str().unwrap()
        )),
        auth["sha256_hex"].as_str().unwrap()
    );
    assert_eq!(
        crate::anytls::link::auth_key(auth["auth"].as_str().unwrap()).len(),
        auth["key_len"].as_u64().unwrap() as usize
    );

    let session = &fixture["session_contract"];
    assert_eq!(
        hex_encode(&crate::anytls::link::handshake_auth_bytes(
            auth["auth"].as_str().unwrap()
        )),
        session["first_handshake"]["auth_key_then_zero_u16_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        crate::anytls::contract::IDLE_SESSION_REUSE_MAP,
        session["idle_session_reuse_map"].as_bool().unwrap()
    );
    assert_eq!(
        crate::anytls::contract::DEFAULT_PADDING_MD5,
        session["padding"]["md5"].as_str().unwrap()
    );
    assert_eq!(
        String::from_utf8(crate::anytls::link::settings_bytes()).unwrap(),
        session["padding"]["settings"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::anytls::link::frame(
            crate::anytls::contract::CMD_SETTINGS,
            1,
            &crate::anytls::link::settings_bytes()
        )),
        session["frame"]["settings_frame_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::anytls::link::frame(
            crate::anytls::contract::CMD_SYN,
            1,
            &[]
        )),
        session["frame"]["syn_frame_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::anytls::link::frame(
            crate::anytls::contract::CMD_PSH,
            1,
            &crate::anytls::link::socks_addr("example.com:443").unwrap()
        )),
        session["frame"]["psh_addr_frame_hex"].as_str().unwrap()
    );

    let packet = &fixture["packet_stream"];
    assert_eq!(
        crate::anytls::contract::UDP_MAGIC_DOMAIN,
        packet["udp_magic_domain"].as_str().unwrap()
    );
    assert_eq!(
        crate::anytls::link::udp_stream_target(packet["udp_input_target"].as_str().unwrap())
            .unwrap(),
        packet["udp_stream_target"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(
            &crate::anytls::link::packet_first_write(
                packet["udp_input_target"].as_str().unwrap(),
                b"ping"
            )
            .unwrap()
        ),
        packet["first_write_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::anytls::link::packet_next_write(b"ping")),
        packet["next_write_hex"].as_str().unwrap()
    );

    let underlay = &fixture["underlay_contract"];
    let tcp = crate::anytls::link::underlay_contract("tcp", 1234, true);
    assert_eq!(
        STANDARD.encode(&tcp.underlay_encoded),
        underlay["tcp_request"]["underlay_b64"].as_str().unwrap()
    );
    assert_eq!(
        tcp.same_encoded_value,
        underlay["tcp_request"]["same_encoded_value"]
            .as_bool()
            .unwrap()
    );
    let udp = crate::anytls::link::underlay_contract("udp", 1234, true);
    assert_eq!(
        udp.underlay_network,
        underlay["udp_request"]["underlay_network"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        udp.underlay_mptcp,
        underlay["udp_request"]["underlay_mptcp"].as_bool().unwrap()
    );
    assert_eq!(
        crate::anytls::contract::TRUE_SESSION_DATA_PLANE_DEFERRED_ITEM,
        underlay["true_session_data_plane_deferred"]
            .as_u64()
            .unwrap() as u16
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

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

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

#[test]
fn shared_transport_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/shared_transport_native_optin.json");

    assert_eq!(
        crate::shared_transport::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::PROTOCOL_SCOPE,
        string_values(&fixture["protocol_scope"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::TRANSPORT_SCOPE,
        string_values(&fixture["transport_scope"]).as_slice()
    );

    let tls = &fixture["tls_transport"];
    assert_eq!(
        crate::shared_transport::contract::TLS_SCHEMES,
        string_values(&tls["schemes"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::ALLOW_INSECURE_ALIASES,
        string_values(&tls["allow_insecure_aliases"]).as_slice()
    );
    for case in tls["allow_insecure_samples"].as_array().unwrap() {
        assert_eq!(
            crate::shared_transport::ir::parse_bool(case["value"].as_str().unwrap()),
            case["parsed"].as_bool().unwrap()
        );
    }
    assert_eq!(
        crate::shared_transport::contract::GLOBAL_TLS_FRAGMENT,
        tls["global_tls_fragment"].as_bool().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::UDP_PASSTHROUGH_KEY,
        tls["udp_passthrough_key"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::UDP_WITHOUT_PASSTHROUGH,
        tls["udp_without_passthrough"].as_str().unwrap()
    );

    let reality = &fixture["reality_transport"];
    assert_eq!(
        hex_encode(
            &crate::shared_transport::ir::reality_sid_decode(
                reality["sid_input"].as_str().unwrap()
            )
            .unwrap()
        ),
        reality["sid_decoded_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(
            &crate::shared_transport::ir::reality_pbk_decode(
                reality["pbk_input"].as_str().unwrap()
            )
            .unwrap()
        ),
        reality["pbk_decoded_hex"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::REALITY_SPX_DEFAULT,
        reality["spx_default"].as_str().unwrap()
    );
    let spider_y =
        crate::shared_transport::ir::reality_spider_y(reality["spx_input"].as_str().unwrap());
    assert_eq!(
        spider_y.as_slice(),
        reality["spider_y"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_i64().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::REALITY_REQUIRES_UTLS_HANDSHAKE_STATE,
        reality["requires_utls_handshake_state"].as_bool().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::REALITY_VERIFY_PEER_CERTIFICATE,
        reality["verify_peer_certificate"].as_bool().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::REALITY_DATA_PLANE_DEFERRED,
        reality["data_plane_deferred"].as_bool().unwrap()
    );

    let ws = &fixture["ws_transport"];
    assert_eq!(
        crate::shared_transport::contract::WS_SCHEMES,
        string_values(&ws["schemes"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::ALLOW_INSECURE_ALIASES,
        string_values(&ws["allow_insecure_aliases"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::UDP_WITHOUT_PASSTHROUGH,
        ws["udp_without_passthrough"].as_str().unwrap()
    );

    let grpc = &fixture["grpc_transport"];
    assert_eq!(
        crate::shared_transport::contract::GRPC_CLEAN_CACHE_HOOK,
        grpc["clean_cache_hook"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::GRPC_CACHE_KEY_FIELDS,
        string_values(&grpc["cache_key_fields"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::ir::grpc_cache_key(
            "addr:443",
            "sni.example",
            "dialer-1",
            true,
            1234,
            true
        ),
        grpc["sample_cache_key_a"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::ir::grpc_cache_key(
            "addr:443",
            "sni.example",
            "dialer-1",
            true,
            1234,
            false
        ),
        grpc["sample_cache_key_b"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::GRPC_BACKOFF_BASE_MS,
        grpc["backoff_base_ms"].as_u64().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::GRPC_BACKOFF_MAX_SECONDS,
        grpc["backoff_max_seconds"].as_u64().unwrap()
    );
    assert!(
        (crate::shared_transport::contract::GRPC_BACKOFF_MULTIPLIER
            - grpc["backoff_multiplier"].as_f64().unwrap())
        .abs()
            < f64::EPSILON
    );
    assert!(
        (crate::shared_transport::contract::GRPC_BACKOFF_JITTER
            - grpc["backoff_jitter"].as_f64().unwrap())
        .abs()
            < f64::EPSILON
    );
    assert_eq!(
        crate::shared_transport::contract::GRPC_KEEPALIVE_SECONDS,
        grpc["keepalive_seconds"].as_u64().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::GRPC_KEEPALIVE_TIMEOUT_SECONDS,
        grpc["keepalive_timeout_seconds"].as_u64().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::GRPC_MIN_CONNECT_TIMEOUT_SECONDS,
        grpc["min_connect_timeout_seconds"].as_u64().unwrap()
    );

    let httpupgrade = &fixture["httpupgrade_transport"];
    assert_eq!(
        crate::shared_transport::contract::HTTPUPGRADE_REQUEST_METHOD,
        httpupgrade["request_method"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::HTTPUPGRADE_CONNECTION_HEADER,
        httpupgrade["connection_header"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::HTTPUPGRADE_UPGRADE_HEADER,
        httpupgrade["upgrade_header"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::HTTPUPGRADE_SUCCESS_STATUS,
        httpupgrade["success_status"].as_u64().unwrap() as u16
    );
    assert_eq!(
        crate::shared_transport::contract::HTTPUPGRADE_HTTPS_ALPN,
        string_values(&httpupgrade["https_alpn"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::HTTPUPGRADE_UDP,
        httpupgrade["udp"].as_str().unwrap()
    );

    let meek = &fixture["meek_transport"];
    assert_eq!(
        crate::shared_transport::contract::MEEK_URL_SCHEME_REQUIRED,
        meek["url_scheme_required"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::MEEK_DEFAULT_ALPN,
        string_values(&meek["default_alpn"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::MEEK_MAX_WRITE,
        meek["max_write"].as_u64().unwrap() as usize
    );
    assert_eq!(
        crate::shared_transport::contract::MEEK_INITIAL_POLLING_MS,
        meek["initial_polling_ms"].as_u64().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::MEEK_MAX_POLLING_MS,
        meek["max_polling_ms"].as_u64().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::MEEK_MIN_POLLING_MS,
        meek["min_polling_ms"].as_u64().unwrap()
    );
    assert!(
        (crate::shared_transport::contract::MEEK_BACKOFF - meek["backoff"].as_f64().unwrap()).abs()
            < f64::EPSILON
    );
    assert_eq!(
        crate::shared_transport::contract::MEEK_CLEAN_CACHE_HOOK,
        meek["clean_cache_hook"].as_str().unwrap()
    );

    let simpleobfs = &fixture["simpleobfs_transport"];
    assert_eq!(
        crate::shared_transport::contract::SIMPLEOBFS_SUPPORTED,
        string_values(&simpleobfs["supported"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::SIMPLEOBFS_TYPE_KEYS,
        string_values(&simpleobfs["type_keys"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::SIMPLEOBFS_PATH_KEYS,
        string_values(&simpleobfs["path_keys"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::SIMPLEOBFS_HOST_KEY,
        simpleobfs["host_key"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::SIMPLEOBFS_PROTOCOL_LABEL,
        simpleobfs["protocol_label"].as_str().unwrap()
    );

    let mux = &fixture["mux_transport"];
    assert_eq!(
        crate::shared_transport::contract::MUX_REQUEST_HEADER_HEX,
        mux["request_header_hex"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::MUX_DATA_PLANE_DEFERRED,
        mux["data_plane_deferred"].as_bool().unwrap()
    );

    let xhttp = &fixture["xhttp_transport"];
    for case in xhttp["mode_cases"].as_array().unwrap() {
        let got = crate::shared_transport::ir::normalize_xhttp_mode(
            case["mode"].as_str().unwrap(),
            case["scheme"].as_str().unwrap(),
            case["security"].as_str().unwrap(),
            case["hasDownload"].as_bool().unwrap(),
        );
        assert_eq!(got.normalized, case["normalized"].as_str().unwrap());
        assert_eq!(got.ok, case["ok"].as_bool().unwrap());
        assert_eq!(got.error_contains, case["error_contains"].as_str().unwrap());
    }
    for case in xhttp["alpn_cases"].as_array().unwrap() {
        let got = crate::shared_transport::ir::validate_xhttp_alpn(
            case["security"].as_str().unwrap(),
            case["alpn"].as_str().unwrap(),
        );
        assert_eq!(got.ok, case["ok"].as_bool().unwrap());
        assert_eq!(got.use_h3, case["use_h3"].as_bool().unwrap());
        assert_eq!(got.error_contains, case["error_contains"].as_str().unwrap());
    }
    assert_eq!(
        crate::shared_transport::ir::canonical_json(xhttp["extra_raw"].as_str().unwrap()).unwrap(),
        xhttp["extra_canonical"].as_str().unwrap()
    );
    for case in xhttp["path_cases"].as_array().unwrap() {
        let got = crate::shared_transport::ir::normalize_xhttp_path_and_query(
            case["input"].as_str().unwrap(),
        );
        assert_eq!(got.path, case["path"].as_str().unwrap());
        assert_eq!(got.query, case["query"].as_str().unwrap());
    }
    assert_eq!(
        crate::shared_transport::contract::XHTTP_PACKET_MAX_BYTES_DEFAULT,
        xhttp["packet_max_bytes_default"].as_u64().unwrap() as usize
    );
    assert_eq!(
        crate::shared_transport::contract::XHTTP_PACKET_MIN_GAP_MS_DEFAULT,
        xhttp["packet_min_gap_ms_default"].as_u64().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::XHTTP_UNSUPPORTED_EXTRA_FIELDS,
        string_values(&xhttp["unsupported_extra_fields"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::XHTTP_TRUE_DATA_PLANE_DEFERRED,
        xhttp["true_data_plane_deferred"].as_bool().unwrap()
    );
}

#[test]
fn stage18_socks5_tcp_dataplane_echoes_payload() {
    let fixture = fixture("outbound/protocol/stage18_first_batch_dataplane.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let (proxy, handle) = spawn_socks5_echo_proxy();
    let report = socks5::tcp_connect_exchange(
        &proxy,
        fixture["socks5"]["target"].as_str().unwrap(),
        fixture["socks5"]["username"].as_str().unwrap(),
        fixture["socks5"]["password"].as_str().unwrap(),
        payload,
        Duration::from_secs(2),
    )
    .unwrap();
    handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.method, 2);
    assert_eq!(
        report.bind,
        fixture["socks5"]["bind"].as_str().unwrap().to_owned()
    );
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn stage18_http_connect_dataplane_echoes_payload() {
    let fixture = fixture("outbound/protocol/stage18_first_batch_dataplane.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let (proxy, handle) = spawn_http_connect_echo_proxy();
    let mut options =
        http_proxy::HttpConnectOptions::connect(fixture["http"]["target"].as_str().unwrap());
    options.username = fixture["http"]["username"].as_str().unwrap().to_owned();
    options.password = fixture["http"]["password"].as_str().unwrap().to_owned();
    options.host_override = fixture["http"]["host_override"]
        .as_str()
        .unwrap()
        .to_owned();
    let report =
        http_proxy::connect_exchange(&proxy, &options, payload, Duration::from_secs(2)).unwrap();
    handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.status, 200);
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn stage18_shadowsocks_aead_tcp_dataplane_echoes_payload() {
    let fixture = fixture("outbound/protocol/stage18_first_batch_dataplane.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let cipher = fixture["shadowsocks"]["cipher"].as_str().unwrap();
    let password = fixture["shadowsocks"]["password"].as_str().unwrap();
    let client_salt = hex_decode(fixture["shadowsocks"]["client_salt_hex"].as_str().unwrap());
    let server_salt = hex_decode(fixture["shadowsocks"]["server_salt_hex"].as_str().unwrap());
    let (server, handle) = spawn_shadowsocks_aead_echo_server(
        cipher.to_owned(),
        password.to_owned(),
        server_salt.clone(),
    );
    let report = shadowsocks::tcp_exchange(
        &server,
        cipher,
        password,
        fixture["shadowsocks"]["target"].as_str().unwrap(),
        payload,
        shadowsocks::AeadTcpSalts {
            client: &client_salt,
            server: &server_salt,
        },
        Duration::from_secs(2),
    )
    .unwrap();
    let accepted_target = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(
        accepted_target,
        fixture["shadowsocks"]["target"].as_str().unwrap()
    );
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn stage59_shadowsocks_aead_udp_packet_wraps_target_and_payload() {
    let cipher = "aes-128-gcm";
    let password = "stage59-password";
    let target = "stage59.example:5353";
    let payload = b"stage59-shadowsocks-udp-ping";
    let salt = hex_decode("202122232425262728292a2b2c2d2e2f");
    let packet = shadowsocks::encode_udp_packet(cipher, password, &salt, target, payload).unwrap();
    let decoded = shadowsocks::decode_udp_packet(cipher, password, &packet).unwrap();

    assert_eq!(decoded.target, target);
    assert_eq!(decoded.payload, payload);
    assert_eq!(decoded.salt_len, salt.len());
    assert!(decoded.packet_len > payload.len() + salt.len());
}

#[test]
fn stage60_trojanc_tcp_dataplane_echoes_payload() {
    let password = "stage60-password";
    let target = "stage60.example:443";
    let payload = b"stage60-trojanc-tcp-ping";
    let (proxy, handle) = spawn_trojanc_tcp_echo_server(password.to_owned(), payload.len());
    let report = trojan::tcp_exchange_over_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        password,
        target,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.command, trojan::TrojanNetwork::Tcp.byte());
    assert_eq!(
        report.password_sha224_hex,
        trojan::packet::password_sha224_hex(password)
    );
    assert_eq!(report.target, target);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(
        accepted.password_sha224_hex,
        trojan::packet::password_sha224_hex(password)
    );
    assert_eq!(accepted.command, trojan::TrojanNetwork::Tcp.byte());
    assert_eq!(accepted.target, target);
    assert_eq!(accepted.payload, payload);
}

#[test]
fn stage61_trojan_udp_over_tcp_dataplane_echoes_packet_payload() {
    let password = "stage61-password";
    let session_target = "stage61-session.example:443";
    let packet_target = "stage61-packet.example:5353";
    let payload = b"stage61-trojan-udp-over-tcp-ping";
    let (proxy, handle) = spawn_trojan_udp_over_tcp_echo_server(password.to_owned(), payload.len());
    let report = trojan::udp_over_tcp_exchange_over_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        password,
        session_target,
        packet_target,
        payload,
    )
    .unwrap();
    let (accepted_header, accepted_packet) = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.command, trojan::TrojanNetwork::Udp.byte());
    assert_eq!(
        report.password_sha224_hex,
        trojan::packet::password_sha224_hex(password)
    );
    assert_eq!(report.session_target, session_target);
    assert_eq!(report.packet_target, packet_target);
    assert_eq!(report.echoed_payload, payload);
    assert!(report.packet_len > payload.len());
    assert_eq!(accepted_header.command, trojan::TrojanNetwork::Udp.byte());
    assert_eq!(accepted_header.target, session_target);
    assert_eq!(accepted_packet.target, packet_target);
    assert_eq!(accepted_packet.payload, payload);
}

#[test]
fn stage62_vless_tcp_dataplane_echoes_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "stage62-vless.example:443";
    let payload = b"stage62-vless-tcp-ping";
    let (proxy, handle) = spawn_vless_tcp_echo_server(key, payload.len());
    let report = vless::tcp_exchange_over_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        &key,
        target,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.target, target);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(accepted.version, vless::VLESS_VERSION);
    assert_eq!(accepted.key, key);
    assert_eq!(accepted.addons_len, 0);
    assert_eq!(accepted.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(accepted.target, target);
    assert_eq!(accepted.payload, payload);
}

#[test]
fn stage63_vless_udp_over_tcp_dataplane_echoes_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "1.2.3.4:53";
    let payload = b"stage63-vless-udp-ping";
    let (proxy, handle) = spawn_vless_udp_over_tcp_echo_server(key);
    let report = vless::udp_over_tcp_exchange_over_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        &key,
        target,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Udp.byte());
    assert_eq!(report.target, target);
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.packet_len, 2 + payload.len());
    assert_eq!(report.response_header_len, 2);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(accepted.version, vless::VLESS_VERSION);
    assert_eq!(accepted.key, key);
    assert_eq!(accepted.addons_len, 0);
    assert_eq!(accepted.command, crate::vmess::VMessNetwork::Udp.byte());
    assert_eq!(accepted.target, target);
    assert_eq!(accepted.payload_len, payload.len());
    assert_eq!(accepted.packet_len, 2 + payload.len());
    assert_eq!(accepted.payload, payload);
}

#[test]
fn stage64_vless_mux_dataplane_echoes_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "stage64-mux.example:443";
    let payload = b"stage64-vless-mux-ping";
    let mux_id = [0x64, 0x01];
    let (proxy, handle) = spawn_vless_mux_echo_server(key, mux_id, target.to_owned());
    let report = vless::mux_exchange_over_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        &key,
        mux_id,
        target,
        "tcp",
        payload,
    )
    .unwrap();
    let (request, new_frame, data_frame, end_frame) = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Mux.byte());
    assert_eq!(report.target, target);
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert!(report.new_frame_validated);
    assert!(report.data_frame_validated);
    assert!(report.end_frame_sent);
    assert_eq!(request.version, vless::VLESS_VERSION);
    assert_eq!(request.key, key);
    assert_eq!(request.addons_len, 0);
    assert_eq!(request.command, crate::vmess::VMessNetwork::Mux.byte());
    assert_eq!(new_frame.id, mux_id);
    assert_eq!(new_frame.status, shared_transport::mux::SESSION_STATUS_NEW);
    assert_eq!(data_frame.id, mux_id);
    assert_eq!(
        data_frame.status,
        shared_transport::mux::SESSION_STATUS_KEEP
    );
    assert_eq!(data_frame.option, shared_transport::mux::OPTION_DATA);
    assert_eq!(data_frame.payload, payload);
    assert_eq!(end_frame.id, mux_id);
    assert_eq!(end_frame.status, shared_transport::mux::SESSION_STATUS_END);
}

#[test]
fn stage65_vmess_aead_tcp_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "stage65-vmess.example:443";
    let payload = b"stage65-vmess-aead-ping";
    let (proxy, handle) = spawn_vmess_aead_tcp_echo_server(uuid.to_owned());
    let report = vmess::aead_tcp_exchange_over_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        uuid,
        target,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(report.target, target);
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert!(report.request_header_len > 58);
    assert!(report.request_chunk_len > payload.len() + 16);
    assert_eq!(report.response_header_len, 38);
    assert!(report.response_chunk_len > payload.len() + 16);
    assert_eq!(accepted.version, 1);
    assert!(accepted.eauth_crc_validated);
    assert_eq!(accepted.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(accepted.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(accepted.target, target);
    assert_eq!(accepted.payload, payload);
}

#[test]
fn stage20_httpupgrade_dataplane_echoes_payload() {
    let fixture = fixture("outbound/protocol/stage20_shared_transport_foundation.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let (endpoint, handle) = spawn_httpupgrade_echo_server();
    let options = shared_transport::HttpUpgradeOptions::new(
        fixture["httpupgrade"]["host"].as_str().unwrap(),
        fixture["httpupgrade"]["path"].as_str().unwrap(),
    );
    let report = shared_transport::http_upgrade_exchange(
        &endpoint,
        &options,
        payload,
        Duration::from_secs(2),
    )
    .unwrap();
    handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.transport, "httpupgrade");
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn stage20_websocket_dataplane_echoes_binary_frame() {
    let fixture = fixture("outbound/protocol/stage20_shared_transport_foundation.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let (endpoint, handle) = spawn_websocket_echo_server();
    let options = shared_transport::HttpUpgradeOptions::new(
        fixture["websocket"]["host"].as_str().unwrap(),
        fixture["websocket"]["path"].as_str().unwrap(),
    );
    let report =
        shared_transport::websocket_exchange(&endpoint, &options, payload, Duration::from_secs(2))
            .unwrap();
    handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.transport, "websocket");
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn stage20_simpleobfs_http_dataplane_echoes_payload() {
    let fixture = fixture("outbound/protocol/stage20_shared_transport_foundation.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let (endpoint, handle) = spawn_simpleobfs_http_echo_server();
    let options = shared_transport::SimpleObfsHttpOptions::new(
        fixture["simpleobfs_http"]["host"].as_str().unwrap(),
        fixture["simpleobfs_http"]["path"].as_str().unwrap(),
    );
    let report = shared_transport::simpleobfs_http_exchange(
        &endpoint,
        &options,
        payload,
        Duration::from_secs(2),
    )
    .unwrap();
    handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.transport, "simpleobfs-http");
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn stage21_reality_mutation_harness_echoes_payload() {
    let fixture = fixture("outbound/protocol/stage21_deep_transport_harness.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let reality = &fixture["reality"];
    let options = shared_transport::RealityMutationOptions::new(
        reality["server_name"].as_str().unwrap(),
        reality["fingerprint"].as_str().unwrap(),
        reality["sid_hex"].as_str().unwrap(),
        reality["pbk_input"].as_str().unwrap(),
        reality["spider_x"].as_str().unwrap(),
        reality["unix_seconds"].as_u64().unwrap() as u32,
        reality["entropy_hex"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        hex_encode(&options.public_key),
        reality["pbk_decoded_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&shared_transport::reality_session_id(&options)),
        reality["session_id_hex"].as_str().unwrap()
    );
    let (endpoint, handle) =
        spawn_reality_mutation_echo_server(shared_transport::reality_session_id(&options));
    let report = shared_transport::reality_mutation_exchange(
        &endpoint,
        &options,
        payload,
        Duration::from_secs(2),
    )
    .unwrap();
    handle.join().unwrap();

    assert!(report.mutation_harness);
    assert!(!report.full_utls_stack);
    assert!(report.default_go_path);
    assert_eq!(report.transport, "reality-mutation");
    assert_eq!(
        report.session_id_hex,
        reality["session_id_hex"].as_str().unwrap()
    );
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn stage21_xhttp_packet_lifecycle_harness_echoes_payload() {
    let fixture = fixture("outbound/protocol/stage21_deep_transport_harness.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let xhttp = &fixture["xhttp"];
    let options = shared_transport::XHttpLifecycleOptions::new(
        xhttp["host"].as_str().unwrap(),
        xhttp["path"].as_str().unwrap(),
        xhttp["mode"].as_str().unwrap(),
        xhttp["security"].as_str().unwrap(),
        xhttp["alpn_h3"].as_str().unwrap(),
        xhttp["session_id"].as_str().unwrap(),
        xhttp["seq"].as_u64().unwrap(),
    )
    .unwrap();
    assert_eq!(
        shared_transport::xhttp_request_path(&options),
        xhttp["request_path"].as_str().unwrap()
    );
    let h3 = shared_transport::ir::validate_xhttp_alpn("tls", xhttp["alpn_h3"].as_str().unwrap());
    assert_eq!(h3.use_h3, xhttp["h3_tls_allowed"].as_bool().unwrap());
    let reality_h3 =
        shared_transport::ir::validate_xhttp_alpn("reality", xhttp["alpn_h3"].as_str().unwrap());
    assert_eq!(
        reality_h3.ok,
        xhttp["reality_h3_allowed"].as_bool().unwrap()
    );

    let (endpoint, handle) =
        spawn_xhttp_packet_echo_server(xhttp["request_path"].as_str().unwrap().to_owned());
    let report = shared_transport::xhttp_packet_exchange(
        &endpoint,
        &options,
        payload,
        Duration::from_secs(2),
    )
    .unwrap();
    handle.join().unwrap();

    assert!(report.lifecycle_harness);
    assert!(!report.full_h2_h3_stack);
    assert!(report.use_h3);
    assert!(report.default_go_path);
    assert_eq!(report.transport, "xhttp-packet");
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn stage21_grpc_cache_and_stream_lifecycle_harness_echoes_payload() {
    let fixture = fixture("outbound/protocol/stage21_deep_transport_harness.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let grpc = &fixture["grpc"];
    let options = shared_transport::GrpcLifecycleOptions::new(
        grpc["address"].as_str().unwrap(),
        grpc["service_name"].as_str().unwrap(),
        grpc["server_name"].as_str().unwrap(),
        grpc["dialer_id"].as_str().unwrap(),
        grpc["allow_insecure"].as_bool().unwrap(),
        grpc["mark"].as_u64().unwrap() as u32,
        grpc["mptcp"].as_bool().unwrap(),
    );
    let mut cache = shared_transport::GrpcLifecycleCache::default();
    let first = cache.get_or_insert(&options);
    let second = cache.get_or_insert(&options);
    assert!(!first.reused);
    assert!(second.reused);
    assert_eq!(second.live_entries, 1);
    assert_eq!(cache.clean(), 1);
    assert_eq!(cache.closed_entries(), 1);

    let mut without_mptcp = options.clone();
    without_mptcp.mptcp = false;
    assert_ne!(options.cache_key(), without_mptcp.cache_key());

    let (endpoint, handle) = spawn_grpc_hunk_echo_server(grpc["service_name"].as_str().unwrap());
    let report =
        shared_transport::grpc_hunk_exchange(&endpoint, &options, payload, Duration::from_secs(2))
            .unwrap();
    handle.join().unwrap();

    assert!(report.stream_harness);
    assert!(!report.full_grpc_http2_stack);
    assert!(report.default_go_path);
    assert_eq!(report.transport, "grpc-hunk");
    assert_eq!(report.service_name, grpc["service_name"].as_str().unwrap());
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn stage21_meek_polling_roundtripper_harness_echoes_payload() {
    let fixture = fixture("outbound/protocol/stage21_deep_transport_harness.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let meek = &fixture["meek"];
    let options = shared_transport::MeekRoundTripOptions::from_https_url(
        meek["url"].as_str().unwrap(),
        hex_decode(meek["session_tag_hex"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(options.host, meek["host"].as_str().unwrap());
    assert_eq!(options.path, meek["path"].as_str().unwrap());
    assert_eq!(options.session_id(), meek["session_id"].as_str().unwrap());

    let (endpoint, handle) = spawn_meek_roundtripper_echo_server(
        meek["path"].as_str().unwrap().to_owned(),
        meek["session_id"].as_str().unwrap().to_owned(),
        meek["round_trips"].as_u64().unwrap() as usize,
    );
    let empty_poll: &[u8] = b"";
    let writes = [payload, empty_poll];
    let report = shared_transport::meek_polling_exchange(
        &endpoint,
        &options,
        &writes,
        Duration::from_secs(2),
    )
    .unwrap();
    handle.join().unwrap();

    assert!(report.polling_harness);
    assert!(!report.full_https_round_tripper);
    assert!(report.default_go_path);
    assert_eq!(report.transport, "meek-polling");
    assert_eq!(report.round_trips, 2);
    assert_eq!(report.echoed_payloads[0], payload);
    assert_eq!(report.echoed_payloads[1], b"poll-ok");
}

#[test]
fn stage21_mux_frame_lifecycle_harness_echoes_payload() {
    let fixture = fixture("outbound/protocol/stage21_deep_transport_harness.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let mux = &fixture["mux"];
    let id = [0_u8, 0_u8];
    let options = shared_transport::MuxFrameOptions::new(
        id,
        mux["host"].as_str().unwrap(),
        mux["port"].as_u64().unwrap() as u16,
        mux["network"].as_str().unwrap(),
    );
    assert_eq!(
        shared_transport::mux::SESSION_STATUS_NEW,
        mux["status_new"].as_u64().unwrap() as u8
    );
    assert_eq!(
        shared_transport::mux::SESSION_STATUS_KEEP,
        mux["status_keep"].as_u64().unwrap() as u8
    );
    assert_eq!(
        shared_transport::mux::SESSION_STATUS_END,
        mux["status_end"].as_u64().unwrap() as u8
    );
    assert_eq!(
        shared_transport::mux::OPTION_DATA,
        mux["option_data"].as_u64().unwrap() as u8
    );

    let (endpoint, handle) = spawn_mux_frame_echo_server(id);
    let report =
        shared_transport::mux_frame_exchange(&endpoint, &options, payload, Duration::from_secs(2))
            .unwrap();
    handle.join().unwrap();

    assert!(report.multiplexing_harness);
    assert!(!report.full_mux_runtime_stack);
    assert!(report.default_go_path);
    assert_eq!(report.transport, "mux-frame");
    assert_eq!(report.id_hex, mux["id_hex"].as_str().unwrap());
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn stage21_quic_h3_datagram_harness_echoes_payload() {
    let fixture = fixture("outbound/protocol/stage21_deep_transport_harness.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let quic = &fixture["quic_h3"];
    let options = shared_transport::QuicH3HarnessOptions::new(
        quic["flow_id"].as_u64().unwrap() as u32,
        quic["datagram_id"].as_u64().unwrap() as u32,
        quic["alpn"].as_str().unwrap(),
        quic["mark"].as_u64().unwrap() as u32,
        quic["mptcp"].as_bool().unwrap(),
    );
    let packet = shared_transport::quic_h3_datagram_packet(&options, payload).unwrap();
    let parsed = shared_transport::parse_quic_h3_datagram(&packet).unwrap();
    assert_eq!(parsed.payload, payload);

    let (endpoint, handle) = spawn_quic_h3_datagram_echo_server();
    let report = shared_transport::quic_h3_datagram_exchange(
        &endpoint,
        &options,
        payload,
        Duration::from_secs(2),
    )
    .unwrap();
    handle.join().unwrap();

    assert!(report.udp_datagram_harness);
    assert!(!report.full_quic_h3_stack);
    assert!(report.default_go_path);
    assert_eq!(report.transport, "quic-h3-datagram");
    assert_eq!(report.alpn, quic["alpn"].as_str().unwrap());
    assert_eq!(report.echoed_payload, payload);
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

fn spawn_socks5_echo_proxy() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut head = [0_u8; 2];
        stream.read_exact(&mut head).unwrap();
        assert_eq!(head[0], 5);
        let mut methods = vec![0_u8; head[1] as usize];
        stream.read_exact(&mut methods).unwrap();
        assert!(methods.contains(&2));
        stream.write_all(&[5, 2]).unwrap();

        let mut auth_head = [0_u8; 2];
        stream.read_exact(&mut auth_head).unwrap();
        assert_eq!(auth_head, [1, 4]);
        let mut user = vec![0_u8; auth_head[1] as usize];
        stream.read_exact(&mut user).unwrap();
        let mut pass_len = [0_u8; 1];
        stream.read_exact(&mut pass_len).unwrap();
        let mut pass = vec![0_u8; pass_len[0] as usize];
        stream.read_exact(&mut pass).unwrap();
        assert_eq!(user, b"user");
        assert_eq!(pass, b"pass");
        stream.write_all(&[1, 0]).unwrap();

        let mut request_head = [0_u8; 3];
        stream.read_exact(&mut request_head).unwrap();
        assert_eq!(request_head, [5, 1, 0]);
        let _target = read_socks5_addr_for_test(&mut stream);
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x14, 0xb4])
            .unwrap();
        echo_one_payload(&mut stream);
    });
    (addr, handle)
}

fn spawn_http_connect_echo_proxy() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_head_for_test(&mut stream);
        assert!(request.starts_with("CONNECT front.example HTTP/1.1\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        echo_one_payload(&mut stream);
    });
    (addr, handle)
}

fn spawn_shadowsocks_aead_echo_server(
    cipher: String,
    password: String,
    server_salt: Vec<u8>,
) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (target, request_payload) =
            shadowsocks::read_client_initial_from_stream(&mut stream, &cipher, &password).unwrap();
        let response =
            shadowsocks::encode_server_payload(&cipher, &password, &server_salt, &request_payload)
                .unwrap();
        stream.write_all(&response).unwrap();
        target.authority()
    });
    (addr, handle)
}

fn spawn_trojanc_tcp_echo_server(
    password: String,
    payload_len: usize,
) -> (String, thread::JoinHandle<trojan::TrojanTcpRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = trojan::read_tcp_request_from_stream(&mut stream, payload_len).unwrap();
        assert_eq!(
            request.password_sha224_hex,
            trojan::packet::password_sha224_hex(&password)
        );
        stream.write_all(&request.payload).unwrap();
        request
    });
    (addr, handle)
}

fn spawn_trojan_udp_over_tcp_echo_server(
    password: String,
    payload_len: usize,
) -> (
    String,
    thread::JoinHandle<(trojan::TrojanRequestHeader, trojan::TrojanUdpPacket)>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let header = trojan::read_request_header_from_stream(&mut stream).unwrap();
        assert_eq!(
            header.password_sha224_hex,
            trojan::packet::password_sha224_hex(&password)
        );
        assert_eq!(header.command, trojan::TrojanNetwork::Udp.byte());
        let packet = trojan::read_udp_packet_from_stream(&mut stream).unwrap();
        assert_eq!(packet.payload_len, payload_len);
        let response = trojan::packet::udp_packet(&packet.target, &packet.payload).unwrap();
        stream.write_all(&response).unwrap();
        (header, packet)
    });
    (addr, handle)
}

fn spawn_vless_tcp_echo_server(
    expected_key: [u8; 16],
    payload_len: usize,
) -> (String, thread::JoinHandle<vless::VlessTcpRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = vless::read_tcp_request_from_stream(&mut stream, payload_len).unwrap();
        assert_eq!(request.key, expected_key);
        assert_eq!(request.command, crate::vmess::VMessNetwork::Tcp.byte());
        stream.write_all(&request.payload).unwrap();
        request
    });
    (addr, handle)
}

fn spawn_vless_udp_over_tcp_echo_server(
    expected_key: [u8; 16],
) -> (String, thread::JoinHandle<vless::VlessUdpRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = vless::read_udp_request_from_stream(&mut stream).unwrap();
        assert_eq!(request.key, expected_key);
        assert_eq!(request.command, crate::vmess::VMessNetwork::Udp.byte());
        let response = vless::udp_response_packet(&request.payload).unwrap();
        stream.write_all(&response).unwrap();
        request
    });
    (addr, handle)
}

fn spawn_vless_mux_echo_server(
    expected_key: [u8; 16],
    expected_id: [u8; 2],
    expected_target: String,
) -> (
    String,
    thread::JoinHandle<(
        vless::VlessMuxRequest,
        shared_transport::mux::MuxFrame,
        shared_transport::mux::MuxFrame,
        shared_transport::mux::MuxFrame,
    )>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = vless::read_mux_request_from_stream(&mut stream).unwrap();
        assert_eq!(request.key, expected_key);
        assert_eq!(request.command, crate::vmess::VMessNetwork::Mux.byte());
        let (host, port) = expected_target.rsplit_once(':').unwrap();
        let options = shared_transport::MuxFrameOptions::new(
            expected_id,
            host,
            port.parse::<u16>().unwrap(),
            "tcp",
        );
        let new_frame = shared_transport::mux::read_mux_frame(&mut stream).unwrap();
        let expected_new = shared_transport::mux_new_frame(&options);
        assert_eq!(new_frame.metadata, expected_new[2..]);
        let data_frame = shared_transport::mux::read_mux_frame(&mut stream).unwrap();
        assert_eq!(data_frame.id, expected_id);
        assert_eq!(data_frame.option, shared_transport::mux::OPTION_DATA);
        stream
            .write_all(&shared_transport::mux_data_frame(expected_id, &data_frame.payload).unwrap())
            .unwrap();
        let end_frame = shared_transport::mux::read_mux_frame(&mut stream).unwrap();
        (request, new_frame, data_frame, end_frame)
    });
    (addr, handle)
}

fn spawn_vmess_aead_tcp_echo_server(
    uuid: String,
) -> (String, thread::JoinHandle<vmess::VMessAeadTcpRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = vmess::read_aead_tcp_request_from_stream(&mut stream, &uuid).unwrap();
        assert_eq!(request.command, crate::vmess::VMessNetwork::Tcp.byte());
        let response = vmess::aead_tcp_response_packet(&request, &request.payload).unwrap();
        stream.write_all(&response).unwrap();
        request
    });
    (addr, handle)
}

fn spawn_httpupgrade_echo_server() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_head_for_test(&mut stream);
        assert!(request.starts_with("GET /upgrade HTTP/1.1\r\n"));
        assert!(request.contains("Host: upgrade.example\r\n"));
        assert!(request.contains("Connection: upgrade\r\n"));
        assert!(request.contains("Upgrade: websocket\r\n"));
        stream
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n")
            .unwrap();
        echo_one_payload(&mut stream);
    });
    (addr, handle)
}

fn spawn_websocket_echo_server() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_head_for_test(&mut stream);
        assert!(request.starts_with("GET /ws HTTP/1.1\r\n"));
        assert!(request.contains("Host: ws.example\r\n"));
        assert!(request.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            )
            .unwrap();
        let payload =
            shared_transport::dataplane::read_websocket_binary_frame(&mut stream).unwrap();
        let frame = shared_transport::dataplane::websocket_server_binary_frame(&payload).unwrap();
        stream.write_all(&frame).unwrap();
    });
    (addr, handle)
}

fn spawn_simpleobfs_http_echo_server() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (request, leftover) = read_http_head_and_leftover_for_test(&mut stream);
        assert!(request.starts_with("GET / HTTP/1.1\r\n"));
        assert!(request.contains("Host: obfs.example\r\n"));
        assert!(request.contains("User-Agent: curl/7.64.1\r\n"));
        echo_one_payload_with_leftover(&mut stream, leftover);
    });
    (addr, handle)
}

fn spawn_reality_mutation_echo_server(
    expected_session_id: [u8; 32],
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let message = shared_transport::reality::read_reality_harness_message(&mut stream).unwrap();
        assert_eq!(message.session_id, expected_session_id);
        assert_eq!(message.server_name, "reality.example");
        shared_transport::reality::write_len_payload(&mut stream, &message.payload).unwrap();
    });
    (addr, handle)
}

fn spawn_xhttp_packet_echo_server(expected_path: String) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (request, leftover) = read_http_head_and_leftover_for_test(&mut stream);
        assert!(request.starts_with(&format!("POST {expected_path} HTTP/1.1\r\n")));
        assert!(request.contains("Host: xhttp.example\r\n"));
        assert!(request.contains("X-DAE-XHTTP-Mode: packet-up\r\n"));
        assert!(request.contains("X-DAE-XHTTP-ALPN: h3\r\n"));
        let body = read_http_body_for_test(&mut stream, &request, leftover);
        write_http_response_for_test(&mut stream, &body);
    });
    (addr, handle)
}

fn spawn_grpc_hunk_echo_server(expected_service_name: &str) -> (String, thread::JoinHandle<()>) {
    let expected_service_name = expected_service_name.to_owned();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (request, leftover) = read_http_head_and_leftover_for_test(&mut stream);
        assert!(request.starts_with(&format!("POST /{expected_service_name}/Tun HTTP/2\r\n")));
        assert!(request.contains("content-type: application/grpc\r\n"));
        let payload = read_grpc_hunk_frame_for_test(&mut stream, leftover);
        stream
            .write_all(&shared_transport::grpc_hunk_frame(&payload).unwrap())
            .unwrap();
    });
    (addr, handle)
}

fn spawn_meek_roundtripper_echo_server(
    expected_path: String,
    expected_session_id: String,
    round_trips: usize,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        for _ in 0..round_trips {
            let (mut stream, _) = listener.accept().unwrap();
            let (request, leftover) = read_http_head_and_leftover_for_test(&mut stream);
            assert!(request.starts_with(&format!("POST {expected_path} HTTP/1.1\r\n")));
            assert!(request.contains("Host: front.example\r\n"));
            assert!(request.contains(&format!("X-Session-ID: {expected_session_id}\r\n")));
            let body = read_http_body_for_test(&mut stream, &request, leftover);
            if body.is_empty() {
                write_http_response_for_test(&mut stream, b"poll-ok");
            } else {
                write_http_response_for_test(&mut stream, &body);
            }
        }
    });
    (addr, handle)
}

fn spawn_mux_frame_echo_server(expected_id: [u8; 2]) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let new_frame = shared_transport::mux::read_mux_frame(&mut stream).unwrap();
        assert_eq!(new_frame.id, expected_id);
        assert_eq!(new_frame.status, shared_transport::mux::SESSION_STATUS_NEW);
        let data_frame = shared_transport::mux::read_mux_frame(&mut stream).unwrap();
        assert_eq!(data_frame.id, expected_id);
        assert_eq!(
            data_frame.status,
            shared_transport::mux::SESSION_STATUS_KEEP
        );
        assert_eq!(data_frame.option, shared_transport::mux::OPTION_DATA);
        stream
            .write_all(&shared_transport::mux_data_frame(expected_id, &data_frame.payload).unwrap())
            .unwrap();
        let end_frame = shared_transport::mux::read_mux_frame(&mut stream).unwrap();
        assert_eq!(end_frame.id, expected_id);
        assert_eq!(end_frame.status, shared_transport::mux::SESSION_STATUS_END);
    });
    (addr, handle)
}

fn spawn_quic_h3_datagram_echo_server() -> (String, thread::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let mut buf = [0_u8; 2048];
        let (n, peer) = socket.recv_from(&mut buf).unwrap();
        let parsed = shared_transport::parse_quic_h3_datagram(&buf[..n]).unwrap();
        assert_eq!(parsed.flow_id, 7);
        assert_eq!(parsed.datagram_id, 11);
        socket.send_to(&buf[..n], peer).unwrap();
    });
    (addr, handle)
}

fn read_socks5_addr_for_test(stream: &mut TcpStream) -> Vec<u8> {
    let mut atyp = [0_u8; 1];
    stream.read_exact(&mut atyp).unwrap();
    let mut out = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            stream.read_exact(&mut rest).unwrap();
            out.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).unwrap();
            out.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).unwrap();
            out.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream.read_exact(&mut rest).unwrap();
            out.extend_from_slice(&rest);
        }
        _ => {}
    }
    out
}

fn read_http_head_for_test(stream: &mut TcpStream) -> String {
    read_http_head_and_leftover_for_test(stream).0
}

fn read_http_head_and_leftover_for_test(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut data = Vec::new();
    let mut buf = [0_u8; 256];
    loop {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        data.extend_from_slice(&buf[..n]);
        if let Some(index) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            let body_start = index + 4;
            let leftover = data[body_start..].to_vec();
            data.truncate(body_start);
            return (String::from_utf8(data).unwrap(), leftover);
        }
    }
}

fn read_http_body_for_test(
    stream: &mut TcpStream,
    request: &str,
    mut leftover: Vec<u8>,
) -> Vec<u8> {
    let content_length = content_length_for_test(request);
    while leftover.len() < content_length {
        let mut buf = vec![0_u8; content_length - leftover.len()];
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        leftover.extend_from_slice(&buf[..n]);
    }
    leftover.truncate(content_length);
    leftover
}

fn write_http_response_for_test(stream: &mut TcpStream, body: &[u8]) {
    stream
        .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes())
        .unwrap();
    stream.write_all(body).unwrap();
}

fn read_grpc_hunk_frame_for_test(stream: &mut TcpStream, mut data: Vec<u8>) -> Vec<u8> {
    while data.len() < 5 {
        let mut buf = [0_u8; 64];
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        data.extend_from_slice(&buf[..n]);
    }
    assert_eq!(data[0], 0);
    let payload_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    while data.len() < 5 + payload_len {
        let mut buf = vec![0_u8; 5 + payload_len - data.len()];
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        data.extend_from_slice(&buf[..n]);
    }
    data[5..5 + payload_len].to_vec()
}

fn content_length_for_test(request: &str) -> usize {
    request
        .split("\r\n")
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0)
}

fn echo_one_payload_with_leftover(stream: &mut TcpStream, mut leftover: Vec<u8>) {
    if leftover.is_empty() {
        let mut payload = [0_u8; 64];
        let n = stream.read(&mut payload).unwrap();
        assert!(n > 0);
        leftover.extend_from_slice(&payload[..n]);
    }
    stream.write_all(&leftover).unwrap();
}

fn echo_one_payload(stream: &mut TcpStream) {
    let mut payload = [0_u8; 64];
    let n = stream.read(&mut payload).unwrap();
    assert!(n > 0);
    stream.write_all(&payload[..n]).unwrap();
}

fn fixture(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}

fn string_values(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect()
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

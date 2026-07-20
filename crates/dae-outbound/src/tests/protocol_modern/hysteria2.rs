use super::*;
#[test]
pub(super) fn hysteria2_rust_native_matches_nativelden_fixture() {
    let fixture = fixture("outbound/protocol/hysteria2_rust_native.json");

    assert_eq!(
        crate::hysteria2::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
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
        assert_eq!(parsed.obfs, case["obfs"].as_str().unwrap());
        assert_eq!(
            parsed.obfs_password,
            case["obfs_password"].as_str().unwrap()
        );
        assert_eq!(parsed.max_tx, case["maxTx"].as_u64().unwrap());
        assert_eq!(parsed.max_rx, case["maxRx"].as_u64().unwrap());
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
        assert_eq!(
            crate::hysteria2::link::normalize_pin_sha256(&parsed.pin_sha256),
            case["pinSHA256_normal"].as_str().unwrap()
        );
        let chain = parse_link_chain(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(chain.nodes[0].adapter_mode, "rust-native");
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
pub(super) fn hysteria2_mport_query_normalizes_to_official_port_hopping_authority() {
    let parsed = crate::hysteria2::Hysteria2Link::parse(
        "hysteria2://auth@pq.us1.globals-download.com:35000/?insecure=1&sni=www.apple.com&mport=35000-39000#pq",
    )
    .unwrap();

    assert_eq!(parsed.server, "pq.us1.globals-download.com:35000-39000");
    assert_eq!(
        parsed.export_url(),
        "hysteria2://auth@pq.us1.globals-download.com:35000-39000?insecure=1&sni=www.apple.com#pq"
    );

    let schedule = crate::hysteria2::build_port_hop_schedule(&parsed.server, 30_000, 3).unwrap();
    assert!(schedule.port_hopping);
    assert_eq!(schedule.selected_ports, vec![35000, 35001, 35002]);
}

#[test]
pub(super) fn hysteria2_mport_query_accepts_comma_range_union() {
    let parsed = crate::hysteria2::Hysteria2Link::parse(
        "hy2://auth@example.com:60000/?mport=60000,61000-61002&sni=example.com#union",
    )
    .unwrap();

    assert_eq!(parsed.server, "example.com:60000,61000-61002");
    assert_eq!(
        parsed.export_url(),
        "hysteria2://auth@example.com:60000,61000-61002?sni=example.com#union"
    );
    assert_eq!(
        crate::hysteria2::parse_port_union(&crate::hysteria2::server_contract(&parsed.server).port)
            .unwrap(),
        vec![60000, 61000, 61001, 61002]
    );
}

#[test]
pub(super) fn hysteria2_mport_query_normalizes_ipv6_authority() {
    let parsed = crate::hysteria2::Hysteria2Link::parse(
        "hysteria2://auth@[2001:db8::1]:443/?mport=20000-20002&sni=v6.example#v6",
    )
    .unwrap();

    assert_eq!(parsed.server, "[2001:db8::1]:20000-20002");
    assert_eq!(
        parsed.export_url(),
        "hysteria2://auth@[2001:db8::1]:20000-20002?sni=v6.example#v6"
    );
}

#[test]
pub(super) fn hysteria2_mport_query_rejects_invalid_values() {
    for link in [
        "hysteria2://auth@example.com:443/?mport=#empty",
        "hysteria2://auth@example.com:443/?mport=abc#bad",
        "hysteria2://auth@example.com:443/?mport=60000,#bad-segment",
    ] {
        let err = crate::hysteria2::Hysteria2Link::parse(link).unwrap_err();
        assert!(
            err.to_string().contains("mport"),
            "unexpected error for {link}: {err}"
        );
    }
}

#[test]
pub(super) fn hysteria2_tls_fields_without_runtime_support_fail_before_construction() {
    for field in ["ca", "clientCertificate", "clientKey", "ech"] {
        let secret_value = "must-not-appear-in-error";
        let link = format!(
            "hysteria2://auth@example.com:443/?{field}={secret_value}#unsupported-tls-field"
        );
        let err = crate::hysteria2::Hysteria2Link::parse(&link).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains(field),
            "unexpected error for {field}: {err}"
        );
        assert!(!message.contains(secret_value));
    }
}

#[test]
pub(super) fn hysteria2_bandwidth_directions_and_congestion_options_round_trip_independently() {
    let max_tx = crate::hysteria2::Hysteria2Link::parse(
        "hysteria2://auth@example.com:443?maxTx=12500000&congestion=reno&disableLossCompensation=1#tx",
    )
    .unwrap();
    assert!(max_tx.max_tx_configured);
    assert!(!max_tx.max_rx_configured);
    assert_eq!(max_tx.max_tx, 12_500_000);
    assert_eq!(max_tx.max_rx, 0);
    assert_eq!(
        max_tx.congestion.controller,
        crate::hysteria2::Hysteria2CongestionController::Reno
    );
    assert!(max_tx.congestion.disable_loss_compensation);
    assert_eq!(
        max_tx.export_url(),
        "hysteria2://auth@example.com:443?congestion=reno&disableLossCompensation=1&maxTx=12500000#tx"
    );

    let max_rx = crate::hysteria2::Hysteria2Link::parse(
        "hysteria2://auth@example.com:443?maxRx=25000000#rx",
    )
    .unwrap();
    assert!(!max_rx.max_tx_configured);
    assert!(max_rx.max_rx_configured);
    assert_eq!(max_rx.max_tx, 0);
    assert_eq!(max_rx.max_rx, 25_000_000);
    assert_eq!(
        max_rx.export_url(),
        "hysteria2://auth@example.com:443?maxRx=25000000#rx"
    );

    let neither =
        crate::hysteria2::Hysteria2Link::parse("hysteria2://auth@example.com:443#none").unwrap();
    assert!(!neither.max_tx_configured);
    assert!(!neither.max_rx_configured);
}

#[test]
pub(super) fn hysteria2_unsupported_congestion_shapes_fail_without_echoing_values() {
    for link in [
        "hysteria2://auth@example.com:443?congestion=must-not-echo#bad-controller",
        "hysteria2://auth@example.com:443?bbrProfile=must-not-echo#bad-profile",
        "hysteria2://auth@example.com:443?congestion=reno&bbrProfile=aggressive#bad-combination",
    ] {
        let error = crate::hysteria2::Hysteria2Link::parse(link).unwrap_err();
        assert!(!error.to_string().contains("must-not-echo"));
    }
}

#[test]
pub(super) fn hysteria2_external_capabilities_are_admitted_or_rejected_during_parsing() {
    for link in [
        "hysteria2://auth@example.com:443?obfs=gecko&obfs-password=must-not-echo#gecko",
        "hysteria2://auth@example.com:443?obfs=unknown&obfs-password=must-not-echo#obfs",
        "hysteria2://auth@example.com:443?unknownField=must-not-echo#unknown",
        "hysteria2://auth@example.com:443?sni=one&sni=must-not-echo#duplicate",
        "hysteria2://auth@example.com:443?obfsPassword=one&obfs-password=must-not-echo#alias-duplicate",
    ] {
        let error = crate::hysteria2::Hysteria2Link::parse(link).unwrap_err();
        assert!(!error.to_string().contains("must-not-echo"));
    }

    let ledger = crate::hysteria2::hysteria2_capability_ledger();
    for capability in [
        "obfs-salamander",
        "periodic-port-hopping",
        "congestion-brutal",
        "randomized-protocol-padding",
    ] {
        assert!(ledger.iter().any(|entry| {
            entry.capability == capability
                && entry.disposition == crate::hysteria2::Hysteria2CapabilityDisposition::Admitted
        }));
    }
    for capability in [
        "obfs-gecko",
        "tls-ech",
        "tls-custom-ca",
        "tls-mtls",
        "unknown-query-field",
    ] {
        assert!(ledger.iter().any(|entry| {
            entry.capability == capability
                && entry.disposition == crate::hysteria2::Hysteria2CapabilityDisposition::Rejected
        }));
    }
}

#[test]
pub(super) fn hysteria2_salamander_requires_the_protocol_minimum_password_length() {
    for password in ["7", "77", "777"] {
        let link = format!(
            "hysteria2://auth@example.com:443?obfs=salamander&obfs-password={password}#short"
        );
        let error = crate::hysteria2::Hysteria2Link::parse(&link).unwrap_err();
        assert!(error.to_string().contains("protocol minimum"));
        assert!(!error.to_string().contains(password));
    }

    let admitted = crate::hysteria2::Hysteria2Link::parse(
        "hysteria2://auth@example.com:443?obfs=salamander&obfs-password=abcd#minimum",
    )
    .unwrap();
    assert_eq!(admitted.obfs, "salamander");
    assert_eq!(admitted.obfs_password, "abcd");
}

#[test]
pub(super) fn hysteria2_export_round_trips_reserved_userinfo_and_fragment_bytes() {
    let input = "hysteria2://user%40name%3Arole:p%40ss%3Aword%2F%25@fixture.invalid:443?sni=server.example#node%23name%3F%2F%25%20%E8%8A%82%E7%82%B9";
    let parsed = crate::hysteria2::Hysteria2Link::parse(input).unwrap();
    assert_eq!(parsed.user, "user@name:role");
    assert_eq!(parsed.password, "p@ss:word/%");
    assert_eq!(parsed.name, "node#name?/% 节点");

    let exported = parsed.export_url();
    assert_eq!(exported, input);
    assert_eq!(
        crate::hysteria2::Hysteria2Link::parse(&exported).unwrap(),
        parsed
    );
}

#[test]
pub(super) fn hysteria2_insecure_inputs_map_to_the_secure_default_boolean() {
    let absent =
        crate::hysteria2::Hysteria2Link::parse("hysteria2://auth@example.com:443#tls-policy")
            .unwrap();
    let explicit_false = crate::hysteria2::Hysteria2Link::parse(
        "hysteria2://auth@example.com:443?insecure=false#tls-policy",
    )
    .unwrap();
    let explicit_zero = crate::hysteria2::Hysteria2Link::parse(
        "hysteria2://auth@example.com:443?insecure=0#tls-policy",
    )
    .unwrap();
    let explicit_true = crate::hysteria2::Hysteria2Link::parse(
        "hysteria2://auth@example.com:443?insecure=true#tls-policy",
    )
    .unwrap();

    assert!(!absent.insecure);
    assert!(!explicit_false.insecure);
    assert!(!explicit_zero.insecure);
    assert!(explicit_true.insecure);
    assert_eq!(absent.export_url(), explicit_false.export_url());
    assert_eq!(absent.export_url(), explicit_zero.export_url());
    assert!(!explicit_false.export_url().contains("insecure"));
    assert!(explicit_true.export_url().contains("insecure=1"));
}

#[test]
pub(super) fn hysteria2_certificate_pin_does_not_enable_insecure_parsing() {
    let pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let absent = crate::hysteria2::Hysteria2Link::parse(&format!(
        "hysteria2://auth@example.com:443?pinSHA256={pin}#tls-pin"
    ))
    .unwrap();
    let explicit_false = crate::hysteria2::Hysteria2Link::parse(&format!(
        "hysteria2://auth@example.com:443?insecure=false&pinSHA256={pin}#tls-pin"
    ))
    .unwrap();

    assert!(!absent.insecure);
    assert!(!explicit_false.insecure);
    assert_eq!(absent.export_url(), explicit_false.export_url());
}

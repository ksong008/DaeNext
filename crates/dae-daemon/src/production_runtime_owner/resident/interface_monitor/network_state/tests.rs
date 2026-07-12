use super::procfs::{
    parse_ipv4_default_routes, parse_ipv6_default_routes, parse_ipv6_interface_addresses,
};
use super::*;

#[test]
fn parses_ipv4_and_ipv6_default_route_fingerprints() {
    let ipv4 = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
                 ppp0 00000000 0100000A 0003 0 0 7 00000000 0 0 0\n\
                 lan0 0002A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0\n";
    let ipv6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 FE800000000000000000000000000001 00000400 00000000 00000000 00000001 ppp0\n";

    assert_eq!(
        parse_ipv4_default_routes(ipv4).unwrap(),
        [DefaultRouteFingerprint {
            family: NetworkFamily::Ipv4,
            interface: "ppp0".to_owned(),
            gateway: "10.0.0.1".parse().unwrap(),
            metric: 7,
        }]
    );
    assert_eq!(
        parse_ipv6_default_routes(ipv6).unwrap(),
        [DefaultRouteFingerprint {
            family: NetworkFamily::Ipv6,
            interface: "ppp0".to_owned(),
            gateway: "fe80::1".parse().unwrap(),
            metric: 1024,
        }]
    );
}

#[test]
fn route_parser_ignores_down_and_reject_defaults() {
    let ipv4 = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
                 down0 00000000 0100000A 0000 0 0 1 00000000 0 0 0\n\
                 reject0 00000000 0100000A 0201 0 0 2 00000000 0 0 0\n";
    let ipv6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 FFFFFFFF 00000000 00000000 00000201 lo\n";

    assert!(parse_ipv4_default_routes(ipv4).unwrap().is_empty());
    assert!(parse_ipv6_default_routes(ipv6).unwrap().is_empty());
}

#[test]
fn ipv6_address_parser_ignores_temporary_tentative_and_unrelated_addresses() {
    let wanted = BTreeSet::from(["wan0".to_owned()]);
    let input = "20010db8000000000000000000000001 02 40 00 80 wan0\n\
                 20010db8000000000000000000000002 02 40 00 01 wan0\n\
                 20010db8000000000000000000000003 02 40 00 40 wan0\n\
                 20010db8000000000000000000000004 02 40 00 80 other0\n";

    let parsed = parse_ipv6_interface_addresses(input, &wanted).unwrap();
    let addresses = parsed.get("wan0").unwrap();
    assert_eq!(addresses.len(), 1);
    assert_eq!(
        addresses[0].address,
        IpAddr::V6("2001:db8::1".parse().unwrap())
    );
}

#[test]
fn explicit_wan_policy_ignores_unrelated_default_route_interfaces() {
    let policy = WanMonitorPolicy {
        auto_enabled: false,
        explicit_ifaces: BTreeSet::from(["wan0".to_owned()]),
        initial_resolved_ifaces: BTreeSet::from(["wan0".to_owned()]),
    };
    let wan = DefaultRouteFingerprint {
        family: NetworkFamily::Ipv4,
        interface: "wan0".to_owned(),
        gateway: "192.0.2.1".parse().unwrap(),
        metric: 10,
    };
    let unrelated = DefaultRouteFingerprint {
        family: NetworkFamily::Ipv4,
        interface: "other0".to_owned(),
        gateway: "198.51.100.1".parse().unwrap(),
        metric: 20,
    };
    assert!(policy.route_is_relevant(&wan));
    assert!(!policy.route_is_relevant(&unrelated));
}

#[test]
fn mixed_auto_and_explicit_policy_keeps_both_candidate_classes() {
    let policy = WanMonitorPolicy {
        auto_enabled: true,
        explicit_ifaces: BTreeSet::from(["fixed0".to_owned()]),
        initial_resolved_ifaces: BTreeSet::from(["auto0".to_owned(), "fixed0".to_owned()]),
    };
    let state = WanNetworkState {
        routes: Vec::new(),
        addresses: BTreeMap::new(),
        auto_route_ifaces: vec!["auto1".to_owned()],
        errors: Vec::new(),
    };

    assert_eq!(
        policy.current_required_ifaces(&state),
        BTreeSet::from(["auto1".to_owned(), "fixed0".to_owned()])
    );
    assert_eq!(
        policy.initial_auto_ifaces(),
        BTreeSet::from(["auto0".to_owned()])
    );
}

#[test]
fn auto_fallback_does_not_misclassify_an_explicit_interface_that_is_also_default() {
    let policy = WanMonitorPolicy {
        auto_enabled: true,
        explicit_ifaces: BTreeSet::from(["wan0".to_owned()]),
        initial_resolved_ifaces: BTreeSet::from(["wan0".to_owned()]),
    };

    assert!(!policy.auto_route_set_changed_from_initial(&BTreeSet::from(["wan0".to_owned()])));
    assert!(policy.auto_route_set_changed_from_initial(&BTreeSet::from(["wan1".to_owned()])));
}

#[test]
fn configuration_without_wan_interfaces_skips_wan_observation_work() {
    let policy = WanMonitorPolicy {
        auto_enabled: false,
        explicit_ifaces: BTreeSet::new(),
        initial_resolved_ifaces: BTreeSet::new(),
    };

    assert!(!policy.monitoring_enabled());
    assert_eq!(
        observe_wan_network_state(&policy),
        WanNetworkState::empty_verified()
    );
}

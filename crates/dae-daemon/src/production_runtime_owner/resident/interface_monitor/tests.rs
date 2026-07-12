use super::network_state::{
    DefaultRouteFingerprint, InterfaceAddressFingerprint, NetworkFamily, WanNetworkState,
};
use super::*;
use crate::production_runtime_owner::resident_interfaces::{
    ARPHRD_ETHER, ARPHRD_PPP, SYSFS_INTERFACE_TYPE_FILE,
};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

const TEST_LAN: &str = "test_lan0";
const TEST_WAN: &str = "test_wan0";

#[test]
fn monitor_marks_unchanged_interfaces_attached() {
    let dir = test_sys_class_net();
    write_iface(&dir, TEST_LAN, 11, ARPHRD_ETHER);
    write_iface(&dir, TEST_WAN, 12, ARPHRD_PPP);
    let specs = interface_specs(&dir, &[TEST_LAN.to_owned()], &[TEST_WAN.to_owned()]);

    let snapshot = interface_monitor_snapshot(&dir, &specs);

    assert_eq!(snapshot["status"], json!(MONITOR_STATUS_PASS));
    assert_eq!(snapshot["reattachRequired"], json!(false));
    assert_eq!(snapshot["reattachReady"], json!(false));
    let interfaces = snapshot["interfaces"].as_array().unwrap();
    assert_eq!(interfaces.len(), 2);
    assert!(interfaces.iter().all(|iface| {
        iface["state"] == json!(INTERFACE_STATE_ATTACHED)
            && iface["reattachRequired"] == json!(false)
            && iface["reattachReady"] == json!(true)
    }));
    let wan = interfaces
        .iter()
        .find(|iface| {
            iface["roles"]
                .as_array()
                .unwrap()
                .contains(&json!(INTERFACE_ROLE_WAN))
        })
        .unwrap();
    assert_eq!(wan["expectedLinkLayer"], json!("l3"));
    assert_eq!(wan["observedLinkLayer"], json!("l3"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn monitor_requires_reattach_when_interface_disappears() {
    let dir = test_sys_class_net();
    write_iface(&dir, TEST_WAN, 12, ARPHRD_PPP);
    let specs = interface_specs(&dir, &[], &[TEST_WAN.to_owned()]);
    fs::remove_dir_all(dir.join(TEST_WAN)).unwrap();

    let snapshot = interface_monitor_snapshot(&dir, &specs);
    let iface = &snapshot["interfaces"][0];

    assert_eq!(snapshot["status"], json!(MONITOR_STATUS_DEGRADED));
    assert_eq!(snapshot["reattachRequired"], json!(true));
    assert_eq!(snapshot["reattachReady"], json!(false));
    assert_eq!(iface["state"], json!(INTERFACE_STATE_MISSING));
    assert_eq!(iface["reattachRequired"], json!(true));
    assert_eq!(iface["reattachReady"], json!(false));
    assert!(
        iface["reattachReasons"]
            .as_array()
            .unwrap()
            .contains(&json!(REATTACH_REASON_INTERFACE_MISSING))
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn monitor_requires_reattach_when_interface_is_recreated() {
    let dir = test_sys_class_net();
    write_iface(&dir, TEST_WAN, 12, ARPHRD_PPP);
    let specs = interface_specs(&dir, &[], &[TEST_WAN.to_owned()]);
    write_iface(&dir, TEST_WAN, 21, ARPHRD_PPP);

    let snapshot = interface_monitor_snapshot(&dir, &specs);
    let iface = &snapshot["interfaces"][0];

    assert_eq!(snapshot["status"], json!(MONITOR_STATUS_DEGRADED));
    assert_eq!(snapshot["reattachReady"], json!(true));
    assert_eq!(iface["state"], json!(INTERFACE_STATE_STALE));
    assert_eq!(iface["reattachReady"], json!(true));
    assert_eq!(iface["expectedIfindex"], json!(12));
    assert_eq!(iface["observedIfindex"], json!(21));
    assert!(
        iface["reattachReasons"]
            .as_array()
            .unwrap()
            .contains(&json!(REATTACH_REASON_IFINDEX_CHANGED))
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn monitor_requires_reattach_when_link_layer_changes() {
    let dir = test_sys_class_net();
    write_iface(&dir, TEST_WAN, 12, ARPHRD_ETHER);
    let specs = interface_specs(&dir, &[], &[TEST_WAN.to_owned()]);
    write_iface(&dir, TEST_WAN, 12, ARPHRD_PPP);

    let snapshot = interface_monitor_snapshot(&dir, &specs);
    let iface = &snapshot["interfaces"][0];

    assert_eq!(iface["state"], json!(INTERFACE_STATE_STALE));
    assert_eq!(snapshot["reattachReady"], json!(true));
    assert_eq!(iface["reattachReady"], json!(true));
    assert_eq!(iface["expectedLinkLayer"], json!("l2"));
    assert_eq!(iface["observedLinkLayer"], json!("l3"));
    assert!(
        iface["reattachReasons"]
            .as_array()
            .unwrap()
            .contains(&json!(REATTACH_REASON_LINK_LAYER_CHANGED))
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn monitor_requires_reattach_when_interface_mtu_changes() {
    let dir = test_sys_class_net();
    write_iface_with_mtu(&dir, TEST_WAN, 12, ARPHRD_ETHER, 1500);
    let specs = interface_specs(&dir, &[], &[TEST_WAN.to_owned()]);
    write_iface_with_mtu(&dir, TEST_WAN, 12, ARPHRD_ETHER, 1420);

    let snapshot = interface_monitor_snapshot(&dir, &specs);
    let iface = &snapshot["interfaces"][0];

    assert_eq!(snapshot["reattachRequired"], json!(true));
    assert_eq!(snapshot["reattachReady"], json!(true));
    assert_eq!(iface["expectedMtu"], json!(1500));
    assert_eq!(iface["observedMtu"], json!(1420));
    assert!(
        iface["reattachReasons"]
            .as_array()
            .unwrap()
            .contains(&json!(REATTACH_REASON_INTERFACE_MTU_CHANGED))
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn schema_two_monitor_debounces_interface_mtu_changes() {
    let dir = test_sys_class_net();
    write_iface_with_mtu(&dir, TEST_WAN, 12, ARPHRD_ETHER, 1500);
    let specs = interface_specs(&dir, &[], &[TEST_WAN.to_owned()]);
    let policy = explicit_policy(TEST_WAN);
    let wan = wan_state(TEST_WAN, "192.0.2.10", "192.0.2.1", false);
    let mut debounce = RecoveryDebounce::default();
    write_iface_with_mtu(&dir, TEST_WAN, 12, ARPHRD_ETHER, 1420);

    let first =
        interface_monitor_snapshot_with_wan_state(&dir, &specs, &policy, &wan, &wan, &mut debounce);
    let second =
        interface_monitor_snapshot_with_wan_state(&dir, &specs, &policy, &wan, &wan, &mut debounce);

    assert_eq!(first["schemaVersion"], json!(2));
    assert_eq!(first["reattachRequired"], json!(true));
    assert_eq!(first["reattachReady"], json!(false));
    assert_eq!(second["reattachReady"], json!(true));
    assert!(
        second["reattachReasons"]
            .as_array()
            .unwrap()
            .contains(&json!(REATTACH_REASON_INTERFACE_MTU_CHANGED))
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn initially_unverified_interface_self_heals_after_a_verified_observation() {
    let dir = test_sys_class_net();
    write_iface(&dir, TEST_WAN, 12, ARPHRD_ETHER);
    fs::remove_file(dir.join(TEST_WAN).join(SYSFS_INTERFACE_MTU_FILE)).unwrap();
    let specs = interface_specs(&dir, &[], &[TEST_WAN.to_owned()]);
    write_iface(&dir, TEST_WAN, 12, ARPHRD_ETHER);
    let policy = explicit_policy(TEST_WAN);
    let wan = wan_state(TEST_WAN, "192.0.2.10", "192.0.2.1", false);
    let mut debounce = RecoveryDebounce::default();

    let first =
        interface_monitor_snapshot_with_wan_state(&dir, &specs, &policy, &wan, &wan, &mut debounce);
    let second =
        interface_monitor_snapshot_with_wan_state(&dir, &specs, &policy, &wan, &wan, &mut debounce);

    assert_eq!(first["reattachReady"], json!(false));
    assert_eq!(second["reattachReady"], json!(true));
    assert!(
        second["reattachReasons"]
            .as_array()
            .unwrap()
            .contains(&json!(REATTACH_REASON_INITIAL_UNVERIFIED))
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn same_ifindex_wan_address_change_waits_for_stability_then_recovers() {
    let dir = test_sys_class_net();
    write_iface(&dir, TEST_WAN, 12, ARPHRD_ETHER);
    let specs = interface_specs(&dir, &[], &[TEST_WAN.to_owned()]);
    let policy = explicit_policy(TEST_WAN);
    let baseline = wan_state(TEST_WAN, "192.0.2.10", "192.0.2.1", false);
    let current = wan_state(TEST_WAN, "192.0.2.20", "192.0.2.1", false);
    let mut debounce = RecoveryDebounce::default();

    let first = interface_monitor_snapshot_with_wan_state(
        &dir,
        &specs,
        &policy,
        &baseline,
        &current,
        &mut debounce,
    );
    assert_eq!(first["reattachRequired"], json!(true));
    assert_eq!(first["reattachReady"], json!(false));
    assert_eq!(first["recoveryDebounce"]["stableObservations"], json!(1));
    assert!(
        first["reattachReasons"]
            .as_array()
            .unwrap()
            .contains(&json!("wan-address-changed"))
    );

    let second = interface_monitor_snapshot_with_wan_state(
        &dir,
        &specs,
        &policy,
        &baseline,
        &current,
        &mut debounce,
    );
    assert_eq!(second["reattachReady"], json!(true));
    assert_eq!(second["recoveryDebounce"]["stableObservations"], json!(2));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn stale_default_route_without_its_stable_address_waits_for_dhcp_recovery() {
    let dir = test_sys_class_net();
    write_iface(&dir, TEST_WAN, 12, ARPHRD_ETHER);
    let specs = interface_specs(&dir, &[], &[TEST_WAN.to_owned()]);
    let policy = explicit_policy(TEST_WAN);
    let baseline = wan_state(TEST_WAN, "192.0.2.10", "192.0.2.1", false);
    let mut addressless = baseline.clone();
    addressless
        .addresses
        .insert(TEST_WAN.to_owned(), Vec::new());
    let recovered = wan_state(TEST_WAN, "192.0.2.20", "192.0.2.1", false);
    let mut debounce = RecoveryDebounce::default();

    for _ in 0..3 {
        let snapshot = interface_monitor_snapshot_with_wan_state(
            &dir,
            &specs,
            &policy,
            &baseline,
            &addressless,
            &mut debounce,
        );
        assert_eq!(snapshot["reattachRequired"], json!(true));
        assert_eq!(snapshot["reattachReady"], json!(false));
        assert_eq!(
            snapshot["wanState"]["currentCandidates"][0]["identityReady"],
            json!(true)
        );
        assert_eq!(
            snapshot["wanState"]["currentCandidates"][0]["addressStateReady"],
            json!(false)
        );
        assert_eq!(snapshot["recoveryDebounce"]["stableObservations"], 0);
    }

    let first = interface_monitor_snapshot_with_wan_state(
        &dir,
        &specs,
        &policy,
        &baseline,
        &recovered,
        &mut debounce,
    );
    let second = interface_monitor_snapshot_with_wan_state(
        &dir,
        &specs,
        &policy,
        &baseline,
        &recovered,
        &mut debounce,
    );
    assert_eq!(first["reattachReady"], json!(false));
    assert_eq!(second["reattachReady"], json!(true));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn default_route_gateway_change_triggers_bounded_recovery() {
    let dir = test_sys_class_net();
    write_iface(&dir, TEST_WAN, 12, ARPHRD_ETHER);
    let specs = interface_specs(&dir, &[], &[TEST_WAN.to_owned()]);
    let policy = explicit_policy(TEST_WAN);
    let baseline = wan_state(TEST_WAN, "192.0.2.10", "192.0.2.1", false);
    let current = wan_state(TEST_WAN, "192.0.2.10", "192.0.2.254", false);
    let mut debounce = RecoveryDebounce::default();

    let first = interface_monitor_snapshot_with_wan_state(
        &dir,
        &specs,
        &policy,
        &baseline,
        &current,
        &mut debounce,
    );
    assert_eq!(first["reattachRequired"], json!(true));
    assert_eq!(first["reattachReady"], json!(false));
    assert!(
        first["reattachReasons"]
            .as_array()
            .unwrap()
            .contains(&json!("wan-default-route-changed"))
    );
    let second = interface_monitor_snapshot_with_wan_state(
        &dir,
        &specs,
        &policy,
        &baseline,
        &current,
        &mut debounce,
    );
    assert_eq!(second["reattachReady"], json!(true));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn stable_ipv6_address_change_uses_the_same_bounded_recovery_path() {
    let dir = test_sys_class_net();
    write_iface(&dir, TEST_WAN, 12, ARPHRD_ETHER);
    let specs = interface_specs(&dir, &[], &[TEST_WAN.to_owned()]);
    let policy = explicit_policy(TEST_WAN);
    let baseline = with_ipv6_address(
        wan_state(TEST_WAN, "192.0.2.10", "192.0.2.1", false),
        TEST_WAN,
        "2001:db8:1::10",
    );
    let current = with_ipv6_address(
        wan_state(TEST_WAN, "192.0.2.10", "192.0.2.1", false),
        TEST_WAN,
        "2001:db8:2::10",
    );
    let mut debounce = RecoveryDebounce::default();

    let first = interface_monitor_snapshot_with_wan_state(
        &dir,
        &specs,
        &policy,
        &baseline,
        &current,
        &mut debounce,
    );
    let second = interface_monitor_snapshot_with_wan_state(
        &dir,
        &specs,
        &policy,
        &baseline,
        &current,
        &mut debounce,
    );

    assert_eq!(first["reattachReady"], json!(false));
    assert_eq!(second["reattachReady"], json!(true));
    assert!(
        second["reattachReasons"]
            .as_array()
            .unwrap()
            .contains(&json!("wan-address-changed"))
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn auto_wan_interface_rename_recovers_after_new_candidate_is_stable() {
    let dir = test_sys_class_net();
    write_iface(&dir, "ppp0", 12, ARPHRD_PPP);
    let specs = interface_specs(&dir, &[], &["ppp0".to_owned()]);
    fs::remove_dir_all(dir.join("ppp0")).unwrap();
    write_iface(&dir, "ppp1", 21, ARPHRD_PPP);
    let policy = auto_policy("ppp0");
    let baseline = wan_state("ppp0", "192.0.2.10", "192.0.2.1", true);
    let current = wan_state("ppp1", "198.51.100.20", "198.51.100.1", true);
    let mut debounce = RecoveryDebounce::default();

    let first = interface_monitor_snapshot_with_wan_state(
        &dir,
        &specs,
        &policy,
        &baseline,
        &current,
        &mut debounce,
    );
    assert_eq!(first["reattachRequired"], json!(true));
    assert_eq!(first["reattachReady"], json!(false));
    assert!(
        first["reattachReasons"]
            .as_array()
            .unwrap()
            .contains(&json!("wan-interface-set-changed"))
    );
    assert_eq!(
        first["wanState"]["currentCandidates"][0]["interface"],
        json!("ppp1")
    );

    let second = interface_monitor_snapshot_with_wan_state(
        &dir,
        &specs,
        &policy,
        &baseline,
        &current,
        &mut debounce,
    );
    assert_eq!(second["reattachReady"], json!(true));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn auto_wan_waits_until_a_default_route_candidate_exists() {
    let dir = test_sys_class_net();
    write_iface(&dir, "ppp0", 12, ARPHRD_PPP);
    let specs = interface_specs(&dir, &[], &["ppp0".to_owned()]);
    let policy = auto_policy("ppp0");
    let baseline = wan_state("ppp0", "192.0.2.10", "192.0.2.1", true);
    let current = WanNetworkState {
        routes: Vec::new(),
        addresses: BTreeMap::from([("ppp0".to_owned(), Vec::new())]),
        auto_route_ifaces: Vec::new(),
        errors: Vec::new(),
    };
    let mut debounce = RecoveryDebounce::default();

    for _ in 0..3 {
        let snapshot = interface_monitor_snapshot_with_wan_state(
            &dir,
            &specs,
            &policy,
            &baseline,
            &current,
            &mut debounce,
        );
        assert_eq!(snapshot["reattachRequired"], json!(true));
        assert_eq!(snapshot["reattachReady"], json!(false));
        assert_eq!(
            snapshot["recoveryDebounce"]["structurallyReady"],
            json!(false)
        );
        assert_eq!(snapshot["recoveryDebounce"]["stableObservations"], json!(0));
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn auto_wan_stability_window_starts_only_after_a_route_reappears() {
    let dir = test_sys_class_net();
    write_iface(&dir, "wan0", 12, ARPHRD_ETHER);
    write_iface(&dir, "wan1", 21, ARPHRD_ETHER);
    let specs = interface_specs(&dir, &[], &["wan0".to_owned()]);
    let policy = auto_policy("wan0");
    let baseline = wan_state("wan0", "192.0.2.10", "192.0.2.1", true);
    let missing = WanNetworkState {
        routes: Vec::new(),
        addresses: BTreeMap::from([("wan0".to_owned(), Vec::new())]),
        auto_route_ifaces: Vec::new(),
        errors: Vec::new(),
    };
    let recovered = wan_state("wan1", "198.51.100.20", "198.51.100.1", true);
    let mut debounce = RecoveryDebounce::default();

    let unavailable = interface_monitor_snapshot_with_wan_state(
        &dir,
        &specs,
        &policy,
        &baseline,
        &missing,
        &mut debounce,
    );
    let first_stable = interface_monitor_snapshot_with_wan_state(
        &dir,
        &specs,
        &policy,
        &baseline,
        &recovered,
        &mut debounce,
    );
    let second_stable = interface_monitor_snapshot_with_wan_state(
        &dir,
        &specs,
        &policy,
        &baseline,
        &recovered,
        &mut debounce,
    );

    assert_eq!(unavailable["recoveryDebounce"]["stableObservations"], 0);
    assert_eq!(first_stable["recoveryDebounce"]["stableObservations"], 1);
    assert_eq!(first_stable["reattachReady"], json!(false));
    assert_eq!(second_stable["reattachReady"], json!(true));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn explicit_wan_ifindex_recovery_does_not_depend_on_procfs_observation() {
    let dir = test_sys_class_net();
    write_iface(&dir, TEST_WAN, 12, ARPHRD_ETHER);
    let specs = interface_specs(&dir, &[], &[TEST_WAN.to_owned()]);
    write_iface(&dir, TEST_WAN, 21, ARPHRD_ETHER);
    let policy = explicit_policy(TEST_WAN);
    let baseline = wan_state(TEST_WAN, "192.0.2.10", "192.0.2.1", false);
    let mut unverified = baseline.clone();
    unverified
        .errors
        .push("temporary procfs failure".to_owned());
    let mut debounce = RecoveryDebounce::default();

    let first = interface_monitor_snapshot_with_wan_state(
        &dir,
        &specs,
        &policy,
        &baseline,
        &unverified,
        &mut debounce,
    );
    let second = interface_monitor_snapshot_with_wan_state(
        &dir,
        &specs,
        &policy,
        &baseline,
        &unverified,
        &mut debounce,
    );

    assert_eq!(first["reattachReady"], json!(false));
    assert_eq!(second["reattachReady"], json!(true));
    assert_eq!(second["wanState"]["current"]["status"], "unverified");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn auto_wan_does_not_recover_from_an_unverified_route_candidate() {
    let dir = test_sys_class_net();
    write_iface(&dir, "wan0", 12, ARPHRD_ETHER);
    let specs = interface_specs(&dir, &[], &["wan0".to_owned()]);
    fs::remove_dir_all(dir.join("wan0")).unwrap();
    write_iface(&dir, "wan1", 21, ARPHRD_ETHER);
    let policy = auto_policy("wan0");
    let baseline = wan_state("wan0", "192.0.2.10", "192.0.2.1", true);
    let mut current = wan_state("wan1", "198.51.100.20", "198.51.100.1", true);
    current
        .errors
        .push("temporary route read failure".to_owned());
    let mut debounce = RecoveryDebounce::default();

    for _ in 0..3 {
        let snapshot = interface_monitor_snapshot_with_wan_state(
            &dir,
            &specs,
            &policy,
            &baseline,
            &current,
            &mut debounce,
        );
        assert_eq!(snapshot["reattachReady"], json!(false));
        assert_eq!(
            snapshot["recoveryDebounce"]["structurallyReady"],
            json!(false)
        );
        assert_eq!(snapshot["recoveryDebounce"]["stableObservations"], 0);
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn unchanged_schema_two_state_remains_pass_without_arming_recovery() {
    let dir = test_sys_class_net();
    write_iface(&dir, TEST_WAN, 12, ARPHRD_ETHER);
    let specs = interface_specs(&dir, &[], &[TEST_WAN.to_owned()]);
    let policy = explicit_policy(TEST_WAN);
    let wan = wan_state(TEST_WAN, "192.0.2.10", "192.0.2.1", false);
    let mut debounce = RecoveryDebounce::default();

    let snapshot =
        interface_monitor_snapshot_with_wan_state(&dir, &specs, &policy, &wan, &wan, &mut debounce);

    assert_eq!(snapshot["status"], MONITOR_STATUS_PASS);
    assert_eq!(snapshot["reattachRequired"], json!(false));
    assert_eq!(snapshot["reattachReady"], json!(false));
    assert_eq!(snapshot["recoveryDebounce"]["stableObservations"], 0);
    let _ = fs::remove_dir_all(dir);
}

fn explicit_policy(iface: &str) -> WanMonitorPolicy {
    WanMonitorPolicy {
        auto_enabled: false,
        explicit_ifaces: BTreeSet::from([iface.to_owned()]),
        initial_resolved_ifaces: BTreeSet::from([iface.to_owned()]),
    }
}

fn auto_policy(initial_iface: &str) -> WanMonitorPolicy {
    WanMonitorPolicy {
        auto_enabled: true,
        explicit_ifaces: BTreeSet::new(),
        initial_resolved_ifaces: BTreeSet::from([initial_iface.to_owned()]),
    }
}

fn wan_state(iface: &str, address: &str, gateway: &str, auto: bool) -> WanNetworkState {
    WanNetworkState {
        routes: vec![DefaultRouteFingerprint {
            family: NetworkFamily::Ipv4,
            interface: iface.to_owned(),
            gateway: gateway.parse::<IpAddr>().unwrap(),
            metric: 0,
        }],
        addresses: BTreeMap::from([(
            iface.to_owned(),
            vec![InterfaceAddressFingerprint {
                family: NetworkFamily::Ipv4,
                address: address.parse::<IpAddr>().unwrap(),
                prefix_len: 32,
                peer: None,
                scope: 0,
            }],
        )]),
        auto_route_ifaces: if auto {
            vec![iface.to_owned()]
        } else {
            Vec::new()
        },
        errors: Vec::new(),
    }
}

fn with_ipv6_address(mut state: WanNetworkState, iface: &str, address: &str) -> WanNetworkState {
    state
        .addresses
        .entry(iface.to_owned())
        .or_default()
        .push(InterfaceAddressFingerprint {
            family: NetworkFamily::Ipv6,
            address: address.parse::<IpAddr>().unwrap(),
            prefix_len: 64,
            peer: None,
            scope: 0,
        });
    for addresses in state.addresses.values_mut() {
        addresses.sort();
    }
    state
}

fn test_sys_class_net() -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("daed-interface-monitor-test-{}", fastrand::u64(..)));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_iface(sys_class_net: &Path, iface: &str, ifindex: u32, arphrd: u16) {
    write_iface_with_mtu(sys_class_net, iface, ifindex, arphrd, 1500);
}

fn write_iface_with_mtu(sys_class_net: &Path, iface: &str, ifindex: u32, arphrd: u16, mtu: u32) {
    let iface_dir = sys_class_net.join(iface);
    fs::create_dir_all(&iface_dir).unwrap();
    fs::write(
        iface_dir.join(SYSFS_INTERFACE_IFINDEX_FILE),
        ifindex.to_string(),
    )
    .unwrap();
    fs::write(iface_dir.join(SYSFS_INTERFACE_MTU_FILE), mtu.to_string()).unwrap();
    fs::write(
        iface_dir.join(SYSFS_INTERFACE_TYPE_FILE),
        arphrd.to_string(),
    )
    .unwrap();
}

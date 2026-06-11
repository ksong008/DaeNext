use super::*;
#[test]
pub(super) fn kernel_feature_gates_match_golden_fixture() {
    let fixture = load("ebpf/kernel_features/basic.json");
    for feature in fixture["features"].as_array().unwrap() {
        let version = match feature["name"].as_str().unwrap() {
            "basic" => BASIC_FEATURE_VERSION,
            "checksum" => CHECKSUM_FEATURE_VERSION,
            "sk_assign" => SK_ASSIGN_FEATURE_VERSION,
            "bpf_timer" => BPF_TIMER_FEATURE_VERSION,
            "bpf_loop" => BPF_LOOP_FEATURE_VERSION,
            other => panic!("unexpected feature {other}"),
        };
        assert_eq!(
            version.display_string(),
            feature["version"].as_str().unwrap()
        );
        assert_eq!(
            version.kernel_code(),
            feature["kernel_code"].as_u64().unwrap() as u32
        );
    }

    for scenario in fixture["scenarios"].as_array().unwrap() {
        let version = parse_version(scenario["version"].as_str().unwrap());
        let report = FeatureGateReport::new(
            version,
            scenario["lan_configured"].as_bool().unwrap(),
            scenario["wan_configured"].as_bool().unwrap(),
        );
        let expected_missing = scenario["missing"]
            .as_array()
            .map(|items| items.iter().map(|value| value.as_str().unwrap()).collect())
            .unwrap_or_else(Vec::new);
        assert_eq!(report.missing, expected_missing);
        assert_eq!(report.allowed(), scenario["allowed"].as_bool().unwrap());
    }
}

#[test]
pub(super) fn connectivity_dryrun_matches_golden_fixture() {
    let fixture = load("control/outbound_connectivity/dryrun.json");
    let mut map = ConnectivityMap::default();
    for event in fixture["events"].as_array().unwrap() {
        let key = ConnectivityKey {
            outbound: event["key"]["outbound"].as_u64().unwrap() as u8,
            l4proto: event["key"]["l4proto"].as_u64().unwrap() as u8,
            ipversion: event["key"]["ipversion"].as_u64().unwrap() as u8,
        };
        let written = map.record(ConnectivityEvent {
            key,
            alive: event["value"].as_u64().unwrap() == 1,
            is_init: event["name"].as_str().unwrap().contains("_init_"),
            dryrun: event["name"].as_str().unwrap().starts_with("dryrun_"),
        });
        let plan = connectivity_write_plan(ConnectivityEvent {
            key,
            alive: event["value"].as_u64().unwrap() == 1,
            is_init: event["name"].as_str().unwrap().contains("_init_"),
            dryrun: event["name"].as_str().unwrap().starts_with("dryrun_"),
        });
        assert_eq!(written, event["written"].as_bool().unwrap());
        assert_eq!(plan.written, written);
        assert_eq!(plan.key, key);
        assert_eq!(plan.value, event["value"].as_u64().unwrap() as u32);
        assert_eq!(map.len(), event["state_len"].as_u64().unwrap() as usize);
        if written {
            assert_eq!(map.get(key), Some(event["value"].as_u64().unwrap() as u32));
        }
    }
}

#[test]
pub(super) fn connectivity_state_dedupes_known_and_legacy_udp_keys() {
    let mut map = ConnectivityMap::default();
    let udp_legacy = ConnectivityKey {
        outbound: 2,
        l4proto: 22,
        ipversion: 4,
    };
    let first = ConnectivityEvent {
        key: udp_legacy,
        alive: true,
        is_init: true,
        dryrun: false,
    };
    assert!(map.record(first));
    assert!(!map.record(first));
    assert_eq!(map.get(udp_legacy), Some(1));
    assert_eq!(map.len(), 1);

    let changed = ConnectivityEvent {
        alive: false,
        ..first
    };
    assert!(map.record(changed));
    assert_eq!(map.get(udp_legacy), Some(0));
    assert_eq!(map.len(), 1);
}

#[test]
pub(super) fn connectivity_fd_cache_skips_dryrun_without_opening_map() {
    let mut cache = ConnectivityMapFdCache::default();
    let plan = cache
        .update_by_id(
            0,
            ConnectivityEvent {
                key: ConnectivityKey {
                    outbound: 2,
                    l4proto: 6,
                    ipversion: 4,
                },
                alive: true,
                is_init: false,
                dryrun: true,
            },
        )
        .unwrap();
    assert!(!plan.written);
    assert!(cache.is_empty());
}

#[test]
pub(super) fn routing_map_apply_models_report_counts() {
    let routing = [RoutingMapEntry {
        index: 0,
        value: BpfMatchSet {
            kind: 1,
            outbound: 2,
            ..BpfMatchSet::default()
        },
    }];
    let lpm = [LpmArrayMapEntry {
        index: 3,
        map_id: 9,
    }];
    let lpm_build = LpmMapBuildSpec {
        index: 4,
        flags: 1,
        max_entries: 2048,
        key_size: std::mem::size_of::<BpfLpmKey>() as u32,
        value_size: std::mem::size_of::<u32>() as u32,
        entries: vec![LpmMapEntry {
            key: BpfLpmKey {
                prefix_len: 128,
                data: [0, 0, 0xffff, 1],
            },
            value: 1,
        }],
    };
    assert_eq!(routing.len(), 1);
    assert_eq!(lpm.len(), 1);
    assert_eq!(lpm_build.entries[0].key.prefix_len, 128);
    assert_eq!(lpm_build.entries[0].value, 1);
}

#[test]
pub(super) fn domain_routing_map_apply_models_bitmap_shape() {
    let entry = DomainRoutingMapEntry {
        key: [0, 0, 0, 1],
        value: BpfDomainRouting { bitmap: [0x40; 32] },
    };
    assert_eq!(entry.key, [0, 0, 0, 1]);
    assert_eq!(entry.value.bitmap.len(), 32);
}

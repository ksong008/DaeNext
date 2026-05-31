use serde_json::Value;

use crate::*;
use dae_core_types::OutboundIndex;
use dae_ebpf_support::{BpfMatchSet, ConnectivityEvent, ConnectivityKey, RoutingMapEntry};
use dae_routing::IpPrefix;

#[test]
fn domain_routing_owner_tracker_matches_golden_fixture() {
    let fixture = load("control/domain_routing_tracker/basic.json");
    let mut tracker = DomainRoutingTracker::default();
    let steps = fixture["steps"].as_array().unwrap();

    tracker.sync_owner(
        "q=a.example|type=A|class=IN",
        DomainRoutingOwnerSnapshot::new(&[3], &["192.0.2.1", "2001:db8::1"]),
    );
    assert_domain_view(&tracker.view("after_owner_a"), &steps[0]);

    tracker.sync_owner(
        "q=b.example|type=A|class=IN",
        DomainRoutingOwnerSnapshot::new(&[4], &["192.0.2.1", "198.51.100.7"]),
    );
    assert_domain_view(&tracker.view("after_owner_b"), &steps[1]);

    tracker.sync_owner(
        "q=a.example|type=A|class=IN",
        DomainRoutingOwnerSnapshot::default(),
    );
    assert_domain_view(&tracker.view("after_remove_owner_a"), &steps[2]);

    tracker.sync_owner(
        "q=b.example|type=A|class=IN",
        DomainRoutingOwnerSnapshot::new(&[16], &["198.51.100.7", "2001:db8::2"]),
    );
    assert_domain_view(&tracker.view("after_replace_owner_b"), &steps[3]);
}

#[test]
fn domain_routing_owner_plans_delta_and_replay_without_helper_boundary() {
    let mut owner = DomainRoutingOwner::default();
    let owner_a = DomainRoutingOwnerSnapshot::new(&[0x1], &["192.0.2.1", "2001:db8::1"]);
    let owner_b = DomainRoutingOwnerSnapshot::new(&[0x2], &["192.0.2.1", "198.51.100.7"]);

    let first = owner.apply_owner_snapshot("owner-a", owner_a.clone());
    assert_eq!(first.map_id, None);
    assert!(!first.flush);
    assert_eq!(
        first.plan.updates,
        vec![
            DomainRoutingStateEntry {
                key: parse_ip_key("192.0.2.1").unwrap(),
                bitmap: bitmap([0x1]),
            },
            DomainRoutingStateEntry {
                key: parse_ip_key("2001:db8::1").unwrap(),
                bitmap: bitmap([0x1]),
            },
        ]
    );
    assert!(first.plan.deletes.is_empty());

    let replay = owner.install_map(77);
    assert!(replay.changed);
    assert_eq!(replay.map_id, 77);
    assert_eq!(replay.entries, first.plan.updates);

    let merged = owner.apply_owner_snapshot("owner-b", owner_b);
    assert_eq!(merged.map_id, Some(77));
    assert!(merged.flush);
    assert_eq!(
        merged.plan.updates,
        vec![
            DomainRoutingStateEntry {
                key: parse_ip_key("192.0.2.1").unwrap(),
                bitmap: bitmap([0x3]),
            },
            DomainRoutingStateEntry {
                key: parse_ip_key("198.51.100.7").unwrap(),
                bitmap: bitmap([0x2]),
            },
        ]
    );
    assert!(merged.plan.deletes.is_empty());

    let remove_a = owner.apply_owner_snapshot("owner-a", DomainRoutingOwnerSnapshot::default());
    assert_eq!(remove_a.map_id, Some(77));
    assert!(remove_a.flush);
    assert_eq!(
        remove_a.plan.updates,
        vec![DomainRoutingStateEntry {
            key: parse_ip_key("192.0.2.1").unwrap(),
            bitmap: bitmap([0x2]),
        }]
    );
    assert_eq!(
        remove_a.plan.deletes,
        vec![parse_ip_key("2001:db8::1").unwrap()]
    );

    let same_map = owner.install_map(77);
    assert!(!same_map.changed);
    assert!(same_map.entries.is_empty());

    let reload_map = owner.install_map(78);
    assert!(reload_map.changed);
    assert_eq!(
        reload_map.entries,
        vec![
            DomainRoutingStateEntry {
                key: parse_ip_key("192.0.2.1").unwrap(),
                bitmap: bitmap([0x2]),
            },
            DomainRoutingStateEntry {
                key: parse_ip_key("198.51.100.7").unwrap(),
                bitmap: bitmap([0x2]),
            },
        ]
    );
}

#[test]
fn domain_routing_owner_clears_reused_map_before_reload_restore() {
    let mut owner = DomainRoutingOwner::default();
    owner.install_map(77);
    owner.apply_owner_snapshot(
        "old-cache",
        DomainRoutingOwnerSnapshot::new(&[0x1], &["192.0.2.1", "2001:db8::1"]),
    );
    assert_eq!(owner.tracker().owner_count(), 1);
    assert_eq!(owner.tracker().ip_count(), 2);

    let clear = owner.prepare_reload_map(
        77,
        [
            parse_ip_key("2001:db8::1").unwrap(),
            parse_ip_key("192.0.2.1").unwrap(),
            parse_ip_key("192.0.2.1").unwrap(),
        ],
    );
    assert_eq!(clear.map_id, 77);
    assert!(!clear.map_id_changed);
    assert_eq!(
        clear.deletes,
        vec![
            parse_ip_key("192.0.2.1").unwrap(),
            parse_ip_key("2001:db8::1").unwrap(),
        ]
    );
    assert_eq!(clear.owner_count, 0);
    assert_eq!(clear.ip_count, 0);
    assert_eq!(owner.tracker().owner_count(), 0);
    assert_eq!(owner.tracker().ip_count(), 0);

    let restored = owner.apply_owner_snapshot(
        "new-cache",
        DomainRoutingOwnerSnapshot::new(&[0x4], &["198.51.100.7"]),
    );
    assert_eq!(restored.map_id, Some(77));
    assert!(restored.flush);
    assert_eq!(
        restored.plan.updates,
        vec![DomainRoutingStateEntry {
            key: parse_ip_key("198.51.100.7").unwrap(),
            bitmap: bitmap([0x4]),
        }]
    );
    assert!(restored.plan.deletes.is_empty());

    let clear_next_map = owner.prepare_reload_map(78, [parse_ip_key("198.51.100.7").unwrap()]);
    assert_eq!(clear_next_map.map_id, 78);
    assert!(clear_next_map.map_id_changed);
    assert_eq!(
        clear_next_map.deletes,
        vec![parse_ip_key("198.51.100.7").unwrap()]
    );
}

#[test]
fn domain_routing_owner_applies_after_map_write_and_skips_duplicate_snapshot() {
    let mut owner = DomainRoutingOwner::default();
    let owner_a = DomainRoutingOwnerSnapshot::new(&[0x1], &["192.0.2.1", "2001:db8::1"]);
    let mut applied = Vec::new();

    let first = owner
        .apply_owner_snapshot_with(
            77,
            "owner-a",
            owner_a.clone(),
            |map_id, updates, deletes| {
                applied.push((map_id, updates.to_vec(), deletes.to_vec()));
                Ok(())
            },
        )
        .unwrap();
    assert!(!first.skipped);
    assert!(first.map_id_changed);
    assert_eq!(first.entries_updated, 2);
    assert_eq!(first.entries_deleted, 0);
    assert_eq!(owner.map_id(), Some(77));
    assert_eq!(owner.tracker().owner_count(), 1);
    assert_eq!(applied.len(), 1);

    let duplicate = owner
        .apply_owner_snapshot_with(77, "owner-a", owner_a.clone(), |_, _, _| {
            panic!("duplicate snapshot must not rewrite domain_routing_map")
        })
        .unwrap();
    assert!(duplicate.skipped);
    assert!(!duplicate.map_id_changed);
    assert_eq!(duplicate.entries_updated, 0);
    assert_eq!(duplicate.entries_deleted, 0);
    assert_eq!(applied.len(), 1);

    let owner_b = DomainRoutingOwnerSnapshot::new(&[0x2], &["192.0.2.1"]);
    let second = owner
        .apply_owner_snapshot_with(77, "owner-b", owner_b, |map_id, updates, deletes| {
            applied.push((map_id, updates.to_vec(), deletes.to_vec()));
            Ok(())
        })
        .unwrap();
    assert!(!second.skipped);
    assert!(!second.map_id_changed);
    assert_eq!(second.entries_updated, 1);
    assert_eq!(second.entries_deleted, 0);
    assert_eq!(owner.tracker().ip_count(), 2);
    assert_eq!(applied[1].1[0].bitmap[0], 0x3);

    let replay = owner
        .apply_owner_snapshot_with(88, "owner-b", owner_a, |map_id, updates, deletes| {
            applied.push((map_id, updates.to_vec(), deletes.to_vec()));
            Ok(())
        })
        .unwrap();
    assert!(replay.map_id_changed);
    assert!(!replay.skipped);
    assert_eq!(replay.entries_updated, 2);
    assert_eq!(replay.entries_deleted, 0);
    assert_eq!(owner.map_id(), Some(88));
    assert_eq!(applied[2].0, 88);
    assert_eq!(applied[2].1.len(), 2);
}

#[test]
fn domain_routing_dns_event_is_normalized_in_rust_and_preserves_multi_owner_delete() {
    let mut owner = DomainRoutingOwner::default();
    let ip = parse_ip_key("192.0.2.1").unwrap();
    let mut applied = Vec::new();

    let first = owner
        .apply_dns_event_with(
            77,
            DomainRoutingDnsEvent::from_keys("owner-a", &[0x1], [ip, ip]),
            |map_id, updates, deletes| {
                applied.push((map_id, updates.to_vec(), deletes.to_vec()));
                Ok(())
            },
        )
        .unwrap();
    assert!(!first.skipped);
    assert_eq!(first.entries_updated, 1);
    assert_eq!(first.ip_count, 1);
    assert_eq!(applied[0].1[0].bitmap, bitmap([0x1]));

    let duplicate = owner
        .apply_dns_event_with(
            77,
            DomainRoutingDnsEvent::from_keys("owner-a", &[0x1], [ip, ip]),
            |_, _, _| panic!("duplicate DNS cache event must not rewrite domain_routing_map"),
        )
        .unwrap();
    assert!(duplicate.skipped);

    let second_owner = owner
        .apply_dns_event_with(
            77,
            DomainRoutingDnsEvent::from_keys("owner-b", &[0x2], [ip]),
            |map_id, updates, deletes| {
                applied.push((map_id, updates.to_vec(), deletes.to_vec()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(second_owner.entries_updated, 1);
    assert!(second_owner.entries_deleted == 0);
    assert_eq!(applied[1].1[0].bitmap, bitmap([0x3]));

    let remove_a = owner
        .apply_dns_event_with(
            77,
            DomainRoutingDnsEvent::remove("owner-a"),
            |map_id, updates, deletes| {
                applied.push((map_id, updates.to_vec(), deletes.to_vec()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(remove_a.entries_updated, 1);
    assert_eq!(remove_a.entries_deleted, 0);
    assert_eq!(applied[2].1[0].bitmap, bitmap([0x2]));

    let remove_b = owner
        .apply_dns_event_with(
            77,
            DomainRoutingDnsEvent::remove("owner-b"),
            |map_id, updates, deletes| {
                applied.push((map_id, updates.to_vec(), deletes.to_vec()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(remove_b.entries_updated, 0);
    assert_eq!(remove_b.entries_deleted, 1);
    assert_eq!(applied[3].2, vec![ip]);
}

#[test]
fn domain_routing_owner_does_not_commit_when_map_apply_fails() {
    let mut owner = DomainRoutingOwner::default();
    let snapshot = DomainRoutingOwnerSnapshot::new(&[0x1], &["192.0.2.1"]);
    let err = owner
        .apply_owner_snapshot_with(77, "owner-a", snapshot, |_, _, _| {
            Err(std::io::Error::other("map write failed"))
        })
        .unwrap_err();
    assert!(err.to_string().contains("map write failed"));
    assert_eq!(owner.map_id(), None);
    assert_eq!(owner.tracker().owner_count(), 0);
    assert_eq!(owner.tracker().ip_count(), 0);
}

#[test]
fn domain_routing_owner_reload_clear_applies_before_state_reset() {
    let mut owner = DomainRoutingOwner::default();
    owner
        .apply_owner_snapshot_with(
            77,
            "owner-a",
            DomainRoutingOwnerSnapshot::new(&[0x1], &["192.0.2.1"]),
            |_, _, _| Ok(()),
        )
        .unwrap();
    assert_eq!(owner.tracker().owner_count(), 1);
    let key = parse_ip_key("192.0.2.1").unwrap();
    let mut applied = Vec::new();
    let clear = owner
        .prepare_reload_map_with(77, [key], |map_id, deletes| {
            applied.push((map_id, deletes.to_vec()));
            Ok(())
        })
        .unwrap();
    assert_eq!(clear.deletes, vec![key]);
    assert_eq!(clear.owner_count, 0);
    assert_eq!(clear.ip_count, 0);
    assert_eq!(owner.map_id(), Some(77));
    assert_eq!(owner.tracker().owner_count(), 0);
    assert_eq!(applied, vec![(77, vec![key])]);
}

#[test]
fn reload_bpf_ownership_matches_golden_fixture() {
    let fixture = load("control/reload_bpf_ownership/eject_inject.json");
    let steps = fixture["steps"].as_array().unwrap();
    let mut flip = CoreFlip::default();
    let mut fresh = ReloadCoreState::new(false, &mut flip);
    assert_reload_state("fresh_init", &fresh, &steps[0]);
    fresh.eject_bpf();
    assert_reload_state("after_eject", &fresh, &steps[1]);
    fresh.inject_bpf();
    assert_reload_state("after_inject", &fresh, &steps[2]);

    let mut reload = ReloadCoreState::new(true, &mut flip);
    assert_reload_state("reload_init", &reload, &steps[3]);
    reload.eject_bpf();
    assert_reload_state("reload_after_eject", &reload, &steps[4]);
}

#[test]
fn runtime_dependency_plan_keeps_stage7_env_gates() {
    let plan = RuntimeDependencyPlan::stage7_default();
    let gates = plan.gates.iter().map(|gate| gate.name).collect::<Vec<_>>();
    assert_eq!(
        gates,
        vec![
            "root",
            "bpffs",
            "netns_permission",
            "memlock",
            "kernel_feature_version"
        ]
    );
}

#[test]
fn reload_dns_cache_plan_restores_only_when_dns_config_is_unchanged() {
    let restore = ReloadDnsCachePlan::decide(true, true, 2);
    assert!(restore.restore_cache);
    assert!(restore.clear_domain_routing_map);
    assert_eq!(restore.snapshot_entries, 2);

    let changed = ReloadDnsCachePlan::decide(false, true, 2);
    assert!(!changed.restore_cache);
    assert!(changed.clear_domain_routing_map);

    let empty = ReloadDnsCachePlan::decide(true, false, 0);
    assert!(!empty.restore_cache);
    assert!(!empty.clear_domain_routing_map);
}

#[test]
fn control_api_typed_report_covers_formal_surfaces_without_stage_schema() {
    let report = ControlApiTypedReport::formal_runtime_control_api();
    assert_eq!(report.schema, "control-api-typed-report-v1");
    assert_eq!(report.status, ControlApiReportStatus::Pass);
    assert_eq!(report.status.as_str(), "pass");
    assert!(report.runtime_overview_available);
    assert!(report.reload_core_state_available);
    assert!(report.domain_routing_owner_available);
    assert!(report.runtime_dependency_plan_available);
    assert!(!report.stage_report_schema);
}

#[test]
fn runtime_state_report_requires_all_rust_owned_surfaces_for_default_control_plane() {
    let empty = RuntimeStateReport::new();
    assert!(empty.api_compatible);
    assert!(!empty.ready_for_default_control_plane());

    let ready = RuntimeStateReport::rust_owned_control_plane();
    assert_eq!(ready.schema_version, RuntimeStateReport::SCHEMA_VERSION);
    assert!(ready.ready_for_default_control_plane());

    let mut missing_active = ready;
    missing_active.active_handoff_available = false;
    assert!(!missing_active.ready_for_default_control_plane());
}

#[test]
fn control_plane_default_admission_keeps_c_tproxy_oracle_until_full_gate_passes() {
    let ready = RuntimeStateReport::rust_owned_control_plane();
    let admission = ControlPlaneDefaultAdmission {
        runtime: ready,
        benchmark_passed: true,
        unit_passed: true,
        integration_passed: true,
        reload_passed: true,
        host_write_passed: true,
        cleanup_passed: true,
        rollback_passed: true,
        c_tproxy_oracle_retained: true,
    };
    assert!(admission.admitted());

    let mut missing_host_write = admission;
    missing_host_write.host_write_passed = false;
    assert!(!missing_host_write.admitted());

    let mut removed_c_oracle = admission;
    removed_c_oracle.c_tproxy_oracle_retained = false;
    assert!(!removed_c_oracle.admitted());
}

#[test]
fn outbound_connectivity_state_dedupes_without_losing_dryrun_semantics() {
    let mut state = OutboundConnectivityState::default();
    let tcp4 = ConnectivityKey {
        outbound: 2,
        l4proto: 6,
        ipversion: 4,
    };

    let skipped = state.update(connectivity_event(tcp4, true, false, true));
    assert!(!skipped.accepted);
    assert!(!skipped.changed);
    assert!(!skipped.flush);
    assert!(state.is_empty());

    let first = state.update(connectivity_event(tcp4, true, true, true));
    assert!(first.accepted);
    assert!(first.changed);
    assert!(first.flush);
    assert_eq!(first.len, 1);
    assert_eq!(state.get(tcp4), Some(1));

    let duplicate = state.update(connectivity_event(tcp4, true, false, false));
    assert!(duplicate.accepted);
    assert!(!duplicate.changed);
    assert!(!duplicate.flush);
    assert_eq!(duplicate.len, 1);

    let changed = state.update(connectivity_event(tcp4, false, false, false));
    assert!(changed.accepted);
    assert!(changed.changed);
    assert!(changed.flush);
    assert_eq!(state.get(tcp4), Some(0));

    let udp4_legacy = ConnectivityKey {
        outbound: 2,
        l4proto: 22,
        ipversion: 4,
    };
    let udp_first = state.update(connectivity_event(udp4_legacy, true, true, false));
    assert!(udp_first.changed);
    assert!(udp_first.flush);
    assert_eq!(udp_first.len, 2);
    let udp_duplicate = state.update(connectivity_event(udp4_legacy, true, false, false));
    assert!(!udp_duplicate.changed);
    assert!(!udp_duplicate.flush);
    assert_eq!(udp_duplicate.len, 2);

    let fallback_key = ConnectivityKey {
        outbound: 2,
        l4proto: 132,
        ipversion: 5,
    };
    let fallback = state.update(connectivity_event(fallback_key, true, false, false));
    assert!(fallback.changed);
    assert!(fallback.flush);
    assert_eq!(fallback.len, 3);
    assert_eq!(state.get(fallback_key), Some(1));

    assert_eq!(
        state.entries(),
        vec![
            ConnectivityStateEntry {
                key: tcp4,
                value: 0,
            },
            ConnectivityStateEntry {
                key: udp4_legacy,
                value: 1,
            },
            ConnectivityStateEntry {
                key: fallback_key,
                value: 1,
            },
        ]
    );
}

#[test]
fn outbound_connectivity_owner_replays_state_when_map_id_changes() {
    let tcp4 = ConnectivityKey {
        outbound: 2,
        l4proto: 6,
        ipversion: 4,
    };
    let mut owner = OutboundConnectivityOwner::default();

    let init = owner.apply_event(connectivity_event(tcp4, true, true, true));
    assert_eq!(init.map_id, None);
    assert!(init.state.accepted);
    assert!(init.state.flush);
    assert!(!init.flush);
    assert_eq!(owner.state().get(tcp4), Some(1));

    let first_map = owner.install_map(1001);
    assert!(first_map.changed);
    assert_eq!(first_map.map_id, 1001);
    assert_eq!(
        first_map.entries,
        vec![ConnectivityStateEntry {
            key: tcp4,
            value: 1,
        }]
    );

    let duplicate = owner.apply_event(connectivity_event(tcp4, true, false, false));
    assert_eq!(duplicate.map_id, Some(1001));
    assert!(!duplicate.state.changed);
    assert!(!duplicate.state.flush);
    assert!(!duplicate.flush);

    let changed = owner.apply_event(connectivity_event(tcp4, false, false, false));
    assert_eq!(changed.map_id, Some(1001));
    assert!(changed.state.changed);
    assert!(changed.state.flush);
    assert!(changed.flush);
    assert_eq!(owner.state().get(tcp4), Some(0));

    let same_map = owner.install_map(1001);
    assert!(!same_map.changed);
    assert!(same_map.entries.is_empty());

    let reload_map = owner.install_map(1002);
    assert!(reload_map.changed);
    assert_eq!(
        reload_map.entries,
        vec![ConnectivityStateEntry {
            key: tcp4,
            value: 0,
        }]
    );

    let skipped = owner.apply_event(connectivity_event(tcp4, true, false, true));
    assert!(!skipped.state.accepted);
    assert!(!skipped.flush);
    assert_eq!(owner.state().get(tcp4), Some(0));
}

#[test]
fn outbound_connectivity_owner_writes_before_committing_state() {
    let tcp4 = ConnectivityKey {
        outbound: 2,
        l4proto: 6,
        ipversion: 4,
    };
    let mut owner = OutboundConnectivityOwner::default();
    let mut applied = Vec::new();

    let first = owner
        .apply_event_with(
            1001,
            connectivity_event(tcp4, true, true, true),
            |map_id, entries| {
                applied.push((map_id, entries.to_vec()));
                Ok(())
            },
        )
        .unwrap();
    assert!(first.map_id_changed);
    assert!(first.accepted);
    assert!(first.changed);
    assert!(!first.skipped);
    assert_eq!(first.entries_updated, 1);
    assert_eq!(owner.map_id(), Some(1001));
    assert_eq!(owner.state().get(tcp4), Some(1));
    assert_eq!(applied.len(), 1);

    let duplicate = owner
        .apply_event_with(
            1001,
            connectivity_event(tcp4, true, false, false),
            |_, _| panic!("duplicate connectivity event must not rewrite map"),
        )
        .unwrap();
    assert!(!duplicate.map_id_changed);
    assert!(duplicate.accepted);
    assert!(!duplicate.changed);
    assert!(duplicate.skipped);
    assert_eq!(duplicate.entries_updated, 0);
    assert_eq!(applied.len(), 1);

    let changed = owner
        .apply_event_with(
            1001,
            connectivity_event(tcp4, false, false, false),
            |map_id, entries| {
                applied.push((map_id, entries.to_vec()));
                Ok(())
            },
        )
        .unwrap();
    assert!(!changed.map_id_changed);
    assert!(changed.changed);
    assert_eq!(changed.entries_updated, 1);
    assert_eq!(owner.state().get(tcp4), Some(0));
    assert_eq!(applied[1].1[0].value, 0);

    let replay = owner
        .apply_event_with(
            1002,
            connectivity_event(tcp4, false, false, false),
            |map_id, entries| {
                applied.push((map_id, entries.to_vec()));
                Ok(())
            },
        )
        .unwrap();
    assert!(replay.map_id_changed);
    assert!(!replay.changed);
    assert_eq!(replay.entries_updated, 1);
    assert_eq!(owner.map_id(), Some(1002));
    assert_eq!(applied[2].0, 1002);
}

#[test]
fn outbound_connectivity_owner_does_not_commit_when_map_apply_fails() {
    let tcp4 = ConnectivityKey {
        outbound: 2,
        l4proto: 6,
        ipversion: 4,
    };
    let mut owner = OutboundConnectivityOwner::default();
    let err = owner
        .apply_event_with(1001, connectivity_event(tcp4, true, true, true), |_, _| {
            Err(std::io::Error::other("connectivity map write failed"))
        })
        .unwrap_err();
    assert!(err.to_string().contains("connectivity map write failed"));
    assert_eq!(owner.map_id(), None);
    assert!(owner.state().is_empty());
}

#[test]
fn outbound_connectivity_owner_dryrun_reject_does_not_install_map() {
    let tcp4 = ConnectivityKey {
        outbound: 2,
        l4proto: 6,
        ipversion: 4,
    };
    let mut owner = OutboundConnectivityOwner::default();
    let report = owner
        .apply_event_with(1001, connectivity_event(tcp4, true, false, true), |_, _| {
            panic!("rejected dryrun connectivity event must not write map")
        })
        .unwrap();

    assert!(!report.map_id_changed);
    assert!(!report.accepted);
    assert!(!report.changed);
    assert!(report.skipped);
    assert_eq!(report.entries_updated, 0);
    assert_eq!(owner.map_id(), None);
    assert!(owner.state().is_empty());
}

#[test]
fn routing_native_plan_builds_kernel_lpm_abi_without_helper_boundary() {
    let rules = vec![
        RoutingNativeRule::new(RoutingNativeMatch::DomainSet, OutboundIndex(2)),
        RoutingNativeRule::new(
            RoutingNativeMatch::IpSet(vec![
                IpPrefix::parse("203.0.113.0/24").unwrap(),
                IpPrefix::parse("2001:db8::/48").unwrap(),
            ]),
            OutboundIndex::BLOCK,
        ),
        RoutingNativeRule::new(
            RoutingNativeMatch::Port(vec![(80, 80), (443, 443)]),
            OutboundIndex::DIRECT,
        ),
        RoutingNativeRule::new(
            RoutingNativeMatch::Mac(vec![[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]]),
            OutboundIndex(3),
        )
        .with_flags(true, 0x0800_0000, true),
    ];
    let plan = build_routing_native_plan(
        &rules,
        RoutingNativeFallback::new(OutboundIndex::DIRECT),
        LpmMapTemplate::default(),
    )
    .unwrap();

    assert_eq!(plan.routing_entries.len(), 6);
    assert_eq!(plan.lpm_maps.len(), 2);
    assert_eq!(plan.routing_entries[0].index, 0);
    assert_eq!(plan.routing_entries[0].value.kind, 0);
    assert_eq!(plan.routing_entries[0].value.outbound, 2);

    let ip_rule = &plan.routing_entries[1].value;
    assert_eq!(ip_rule.kind, 1);
    assert_eq!(
        u32::from_le_bytes(ip_rule.value[..4].try_into().unwrap()),
        0
    );
    assert_eq!(plan.lpm_maps[0].index, 0);
    assert_eq!(plan.lpm_maps[0].flags, BPF_F_NO_PREALLOC);
    assert_eq!(plan.lpm_maps[0].max_entries, DEFAULT_LPM_MAX_ENTRIES);
    assert_eq!(plan.lpm_maps[0].entries[0].key.prefix_len, 120);
    assert_eq!(
        plan.lpm_maps[0].entries[0].key,
        ip_prefix_to_bpf_lpm_key(&IpPrefix::parse("203.0.113.0/24").unwrap())
    );
    assert_eq!(plan.lpm_maps[0].entries[1].key.prefix_len, 48);

    assert_eq!(plan.routing_entries[2].value.kind, 3);
    assert_eq!(
        plan.routing_entries[2].value.outbound,
        OutboundIndex::LOGICAL_OR.value()
    );
    assert_eq!(
        plan.routing_entries[3].value.outbound,
        OutboundIndex::DIRECT.value()
    );

    let mac_rule = &plan.routing_entries[4].value;
    assert_eq!(mac_rule.kind, 7);
    assert_eq!(mac_rule.not, 1);
    assert_eq!(mac_rule.must, 1);
    assert_eq!(mac_rule.mark, 0x0800_0000);
    assert_eq!(
        u32::from_le_bytes(mac_rule.value[..4].try_into().unwrap()),
        1
    );
    assert_eq!(plan.lpm_maps[1].index, 1);
    assert_eq!(plan.lpm_maps[1].entries[0].key.prefix_len, 128);

    let fallback = plan.routing_entries.last().unwrap();
    assert_eq!(fallback.value.kind, 10);
    assert_eq!(fallback.value.outbound, OutboundIndex::DIRECT.value());
    plan.validate().unwrap();
}

#[test]
fn routing_native_plan_rejects_invalid_fallback_and_lpm_template() {
    let invalid = RoutingNativeBuildPlan {
        routing_entries: vec![RoutingMapEntry {
            index: 0,
            value: BpfMatchSet {
                kind: 1,
                outbound: OutboundIndex::DIRECT.value(),
                ..BpfMatchSet::default()
            },
        }],
        lpm_maps: Vec::new(),
    };
    assert_eq!(
        invalid.validate().unwrap_err(),
        RoutingNativePlanError::FallbackNotLast
    );

    let err = build_routing_native_plan(
        &[RoutingNativeRule::new(
            RoutingNativeMatch::IpSet(vec![IpPrefix::parse("203.0.113.0/24").unwrap()]),
            OutboundIndex::DIRECT,
        )],
        RoutingNativeFallback::new(OutboundIndex::BLOCK),
        LpmMapTemplate {
            key_size: 1,
            ..LpmMapTemplate::default()
        },
    )
    .unwrap_err();
    assert_eq!(
        err,
        RoutingNativePlanError::InvalidLpmTemplate {
            field: "key_size",
            got: 1,
            want: std::mem::size_of::<dae_ebpf_support::BpfLpmKey>() as u32,
        }
    );
}

#[test]
fn routing_map_owner_replays_on_map_change_and_skips_same_snapshot() {
    let plan = build_routing_native_plan(
        &[
            RoutingNativeRule::new(
                RoutingNativeMatch::IpSet(vec![IpPrefix::parse("203.0.113.0/24").unwrap()]),
                OutboundIndex::DIRECT,
            ),
            RoutingNativeRule::new(
                RoutingNativeMatch::Port(vec![(443, 443)]),
                OutboundIndex::BLOCK,
            ),
        ],
        RoutingNativeFallback::new(OutboundIndex::DIRECT),
        LpmMapTemplate::default(),
    )
    .unwrap();
    let checksum = plan.checksum();
    let mut owner = RoutingMapOwner::default();
    let mut applied = Vec::new();

    let first = owner
        .apply_snapshot_with(
            11,
            12,
            plan.clone(),
            |routing_map_id, lpm_array_map_id, plan| {
                applied.push((routing_map_id, lpm_array_map_id, plan.checksum()));
                Ok(())
            },
        )
        .unwrap();
    assert!(first.map_changed);
    assert!(first.plan_changed);
    assert!(!first.skipped);
    assert_eq!(first.routing_entries_updated, plan.routing_entries.len());
    assert_eq!(first.lpm_maps_created, plan.lpm_maps.len());
    assert_eq!(first.checksum, checksum);
    assert_eq!(owner.routing_map_id(), Some(11));
    assert_eq!(owner.lpm_array_map_id(), Some(12));
    assert_eq!(owner.checksum(), Some(checksum));

    let same = owner
        .apply_snapshot_with(11, 12, plan.clone(), |_, _, _| {
            panic!("unchanged routing owner snapshot must not rewrite kernel maps")
        })
        .unwrap();
    assert!(!same.map_changed);
    assert!(!same.plan_changed);
    assert!(same.skipped);
    assert_eq!(same.routing_entries_updated, 0);
    assert_eq!(same.lpm_maps_created, 0);
    assert_eq!(applied, vec![(11, 12, checksum)]);

    let reload = owner
        .apply_snapshot_with(
            21,
            22,
            plan.clone(),
            |routing_map_id, lpm_array_map_id, plan| {
                applied.push((routing_map_id, lpm_array_map_id, plan.checksum()));
                Ok(())
            },
        )
        .unwrap();
    assert!(reload.map_changed);
    assert!(!reload.plan_changed);
    assert!(!reload.skipped);
    assert_eq!(applied, vec![(11, 12, checksum), (21, 22, checksum)]);

    let changed_plan = build_routing_native_plan(
        &[RoutingNativeRule::new(
            RoutingNativeMatch::Port(vec![(80, 80)]),
            OutboundIndex::BLOCK,
        )],
        RoutingNativeFallback::new(OutboundIndex::DIRECT),
        LpmMapTemplate::default(),
    )
    .unwrap();
    let changed_checksum = changed_plan.checksum();
    let changed = owner
        .apply_snapshot_with(
            21,
            22,
            changed_plan.clone(),
            |routing_map_id, lpm_array_map_id, plan| {
                applied.push((routing_map_id, lpm_array_map_id, plan.checksum()));
                Ok(())
            },
        )
        .unwrap();
    assert!(!changed.map_changed);
    assert!(changed.plan_changed);
    assert!(!changed.skipped);
    assert_eq!(owner.checksum(), Some(changed_checksum));
    assert_eq!(
        applied,
        vec![
            (11, 12, checksum),
            (21, 22, checksum),
            (21, 22, changed_checksum)
        ]
    );
}

#[test]
fn routing_rule_owner_builds_generic_rule_state_and_preserves_noop_replay() {
    let mut pname = [0_u8; 16];
    pname[..4].copy_from_slice(b"curl");
    let state = RoutingRuleState::new(
        vec![
            RoutingNativeRule::new(
                RoutingNativeMatch::SourceIpSet(vec![IpPrefix::parse("192.0.2.0/24").unwrap()]),
                OutboundIndex::DIRECT,
            ),
            RoutingNativeRule::new(
                RoutingNativeMatch::SourcePort(vec![(1024, 65535)]),
                OutboundIndex::BLOCK,
            ),
            RoutingNativeRule::new(RoutingNativeMatch::L4Proto(0b11), OutboundIndex(3)),
            RoutingNativeRule::new(RoutingNativeMatch::IpVersion(0b10), OutboundIndex(4)),
            RoutingNativeRule::new(
                RoutingNativeMatch::ProcessName(vec![pname]),
                OutboundIndex(5),
            ),
            RoutingNativeRule::new(RoutingNativeMatch::Dscp(vec![46]), OutboundIndex(6))
                .with_flags(false, 0x0800_0000, true),
        ],
        RoutingNativeFallback::new(OutboundIndex::DIRECT),
        LpmMapTemplate::default(),
    );

    let plan = state.build_plan().unwrap();
    assert_eq!(plan.routing_entries.len(), 7);
    assert_eq!(plan.lpm_maps.len(), 1);
    assert_eq!(plan.routing_entries[0].value.kind, 2);
    assert_eq!(plan.routing_entries[1].value.kind, 4);
    assert_eq!(plan.routing_entries[2].value.kind, 5);
    assert_eq!(plan.routing_entries[3].value.kind, 6);
    assert_eq!(plan.routing_entries[4].value.kind, 8);
    assert_eq!(plan.routing_entries[5].value.kind, 9);
    assert_eq!(plan.routing_entries[5].value.must, 1);
    assert_eq!(plan.routing_entries[5].value.mark, 0x0800_0000);
    assert_eq!(plan.routing_entries[6].value.kind, 10);

    let checksum = plan.checksum();
    let mut owner = RoutingRuleOwner::default();
    let mut applied = Vec::new();
    let first = owner
        .apply_rules_with(
            31,
            32,
            state.clone(),
            |routing_map_id, lpm_array_map_id, plan| {
                applied.push((routing_map_id, lpm_array_map_id, plan.checksum()));
                Ok(())
            },
        )
        .unwrap();
    assert!(!first.map.skipped);
    assert_eq!(first.rule_count, 6);
    assert_eq!(first.lpm_rule_count, 1);
    assert_eq!(owner.map_owner().checksum(), Some(checksum));

    let same = owner
        .apply_rules_with(31, 32, state, |_, _, _| {
            panic!("same routing rule state must not rewrite kernel maps")
        })
        .unwrap();
    assert!(same.map.skipped);
    assert_eq!(applied, vec![(31, 32, checksum)]);
}

fn assert_domain_view(got: &DomainRoutingView, expected: &Value) {
    assert_eq!(got.step, expected["step"].as_str().unwrap());
    assert_eq!(got.owners, string_array(&expected["owners"]));
    let expected_ips = expected["ips"].as_array().unwrap();
    assert_eq!(got.ips.len(), expected_ips.len());
    for (got, expected) in got.ips.iter().zip(expected_ips) {
        assert_eq!(got.ip, expected["ip"].as_str().unwrap());
        assert_eq!(got.owners, string_array(&expected["owners"]));
        assert_eq!(
            got.merged,
            expected["merged"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_u64().unwrap() as u32)
                .collect::<Vec<_>>()
        );
        assert_eq!(got.present, expected["present"].as_bool().unwrap());
    }
}

fn assert_reload_state(step: &str, got: &ReloadCoreState, expected: &Value) {
    assert_eq!(step, expected["step"].as_str().unwrap());
    assert_eq!(got.is_reload, expected["is_reload"].as_bool().unwrap());
    assert_eq!(got.bpf_ejected, expected["bpf_ejected"].as_bool().unwrap());
    assert_eq!(
        got.defer_func_count,
        expected["defer_func_count"].as_u64().unwrap() as usize
    );
    assert_eq!(got.flip, expected["flip"].as_u64().unwrap() as u8);
}

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect()
}

fn bitmap<const N: usize>(words: [u32; N]) -> [u32; 32] {
    let mut bitmap = [0; 32];
    bitmap[..N].copy_from_slice(&words);
    bitmap
}

fn connectivity_event(
    key: ConnectivityKey,
    alive: bool,
    is_init: bool,
    dryrun: bool,
) -> ConnectivityEvent {
    ConnectivityEvent {
        key,
        alive,
        is_init,
        dryrun,
    }
}

fn load(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}

use super::*;
#[test]
pub(super) fn domain_routing_owner_tracker_matches_golden_fixture() {
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
pub(super) fn domain_routing_owner_plans_delta_and_replay_without_helper_boundary() {
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
pub(super) fn domain_routing_owner_clears_reused_map_before_reload_restore() {
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
pub(super) fn domain_routing_owner_applies_after_map_write_and_skips_duplicate_snapshot() {
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
pub(super) fn domain_routing_dns_event_is_normalized_in_rust_and_preserves_multi_owner_delete() {
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
pub(super) fn domain_routing_owner_does_not_commit_when_map_apply_fails() {
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
pub(super) fn domain_routing_owner_reload_clear_applies_before_state_reset() {
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

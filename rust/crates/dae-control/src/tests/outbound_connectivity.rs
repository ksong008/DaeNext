use super::*;
#[test]
pub(super) fn outbound_connectivity_state_dedupes_without_losing_dryrun_semantics() {
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
pub(super) fn outbound_connectivity_owner_replays_state_when_map_id_changes() {
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
pub(super) fn outbound_connectivity_owner_writes_before_committing_state() {
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
pub(super) fn outbound_connectivity_owner_does_not_commit_when_map_apply_fails() {
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
pub(super) fn outbound_connectivity_owner_dryrun_reject_does_not_install_map() {
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

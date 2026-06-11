use super::*;
#[test]
pub(super) fn routing_native_plan_builds_kernel_lpm_abi_without_helper_boundary() {
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
pub(super) fn routing_native_plan_rejects_invalid_fallback_and_lpm_template() {
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
pub(super) fn routing_map_owner_replays_on_map_change_and_skips_same_snapshot() {
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
pub(super) fn routing_rule_owner_builds_generic_rule_state_and_preserves_noop_replay() {
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

use super::*;

fn matching_domain_routing() -> ResidentDnsDomainRouting {
    let matcher = RoutingMatcher::from_fixture_value(&serde_json::json!({
        "domain_sets": [
            {"bit": 0, "key": "suffix", "patterns": ["example.test"]}
        ],
        "matches": [
            {"type": "domain_set", "outbound": "direct"},
            {"type": "fallback", "outbound": "block"}
        ]
    }))
    .unwrap();
    let mut domain_routing = ResidentDnsDomainRouting::new(1, matcher);
    domain_routing.test_apply_map = Some(apply_resident_domain_routing_event_in_memory);
    domain_routing.state.lock().unwrap().cache = DnsCacheStore::new(1);
    domain_routing
}

fn response_plan(name: &str, ip: &str, deadline_unix: i64) -> DnsResponseCachePlan {
    let key = DnsCacheKey::new(name, 1, 1);
    let mut entry = DnsCacheEntry::new(deadline_unix, deadline_unix);
    entry.route_owner_key = key.to_string();
    entry.ips.push(ip.parse().unwrap());
    entry.has_any_ip = true;
    DnsResponseCachePlan {
        key,
        entry,
        min_ttl: 60,
        answer_count: 1,
        ip_count: 1,
        client_ttl_zeroed: false,
    }
}

#[test]
fn capacity_eviction_removes_the_domain_routing_owner_with_its_cache_entry() {
    let domain_routing = matching_domain_routing();
    let deadline = unix_now().saturating_add(300);
    domain_routing
        .record_accepted_response(&response_plan(
            "first.example.test.",
            "192.0.2.10",
            deadline,
        ))
        .unwrap();
    domain_routing
        .record_accepted_response(&response_plan(
            "second.example.test.",
            "192.0.2.20",
            deadline.saturating_add(1),
        ))
        .unwrap();

    let state = domain_routing.state.lock().unwrap();
    assert_eq!(state.cache.len(), 1);
    assert_eq!(state.owner.tracker().owner_count(), 1);
    assert_eq!(state.owner.tracker().ip_count(), 1);
    assert!(
        !state
            .cache
            .contains_key(&DnsCacheKey::new("first.example.test.", 1, 1))
    );
    assert!(
        state
            .cache
            .contains_key(&DnsCacheKey::new("second.example.test.", 1, 1))
    );
}

#[test]
fn failed_capacity_replacement_restores_the_previous_cache_and_owner() {
    fn reject_map_update(
        _: u32,
        _: &[DomainRoutingStateEntry],
        _: &[DomainRoutingIpKey],
    ) -> io::Result<()> {
        Err(io::Error::other("injected capacity replacement failure"))
    }

    let mut domain_routing = matching_domain_routing();
    let deadline = unix_now().saturating_add(300);
    let first = response_plan("first.example.test.", "192.0.2.10", deadline);
    domain_routing.record_accepted_response(&first).unwrap();
    domain_routing.test_apply_map = Some(reject_map_update);

    let error = domain_routing
        .record_accepted_response(&response_plan(
            "second.example.test.",
            "192.0.2.20",
            deadline.saturating_add(1),
        ))
        .unwrap_err();
    assert!(error.contains("injected capacity replacement failure"));

    let state = domain_routing.state.lock().unwrap();
    assert_eq!(state.cache.len(), 1);
    assert!(state.cache.contains_key(&first.key));
    assert_eq!(state.owner.tracker().owner_count(), 1);
    assert_eq!(state.owner.tracker().ip_count(), 1);
    assert_eq!(state.cache.stats().remove_callback_total, 0);
}

#[test]
fn published_generation_fences_late_writes_from_retired_generation() {
    let fence = ResidentDomainRoutingGenerationFence::default();
    let old_ip = ip_to_key("192.0.2.10".parse().unwrap());
    let new_ip = ip_to_key("192.0.2.20".parse().unwrap());
    let stale_ip = ip_to_key("192.0.2.30".parse().unwrap());
    let mut old_owner = DomainRoutingOwner::default();
    let mut new_owner = DomainRoutingOwner::default();

    fence
        .apply_event_with(
            1,
            7,
            &mut old_owner,
            DomainRoutingDnsEvent::from_keys("old", &[1], [old_ip]),
            |_, _, _| panic!("an unpublished generation must not write the map"),
        )
        .unwrap();
    let mut activation_updates = Vec::new();
    fence
        .activate_with(1, 7, &old_owner, |_, updates, deletes| {
            activation_updates.extend_from_slice(updates);
            assert!(deletes.is_empty());
            Ok(())
        })
        .unwrap();
    assert_eq!(activation_updates.len(), 1);

    fence
        .apply_event_with(
            2,
            7,
            &mut new_owner,
            DomainRoutingDnsEvent::from_keys("new", &[2], [new_ip]),
            |_, _, _| panic!("the candidate generation must remain private"),
        )
        .unwrap();
    let mut transition_updates = Vec::new();
    let mut transition_deletes = Vec::new();
    fence
        .activate_with(2, 7, &new_owner, |_, updates, deletes| {
            transition_updates.extend_from_slice(updates);
            transition_deletes.extend_from_slice(deletes);
            Ok(())
        })
        .unwrap();
    assert_eq!(transition_updates.len(), 1);
    assert_eq!(transition_updates[0].key, new_ip);
    assert_eq!(transition_deletes, vec![old_ip]);

    fence
        .apply_event_with(
            1,
            7,
            &mut old_owner,
            DomainRoutingDnsEvent::from_keys("stale", &[4], [stale_ip]),
            |_, _, _| panic!("a retired generation must not write the map"),
        )
        .unwrap();
    let state = fence.state.lock().unwrap();
    assert_eq!(state.active_generation, Some(2));
    assert_eq!(state.tracker.entries(), new_owner.tracker().entries());
}

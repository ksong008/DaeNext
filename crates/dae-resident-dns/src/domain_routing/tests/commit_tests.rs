use super::*;

fn prepare(
    routing: &ResidentDnsDomainRouting,
    response: &DnsResponseCachePlan,
) -> (
    ResidentDnsDomainRoutingUpdatePlan,
    revision::ResponseRevision,
) {
    let revision = routing.response_revisions.begin(&response.key).unwrap();
    let mut state = routing.state.lock().unwrap();
    let plan = build_resident_dns_domain_routing_update_plan(
        &routing.routing_matcher,
        &mut state.domain_bitmap,
        response,
    )
    .unwrap()
    .unwrap();
    (plan, revision)
}

fn query(name: &str) -> Vec<u8> {
    let mut packet = vec![0; 12];
    packet[5] = 1;
    for label in name.trim_end_matches('.').split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    packet
}

#[test]
fn newer_shorter_ttl_response_supersedes_old_plan_and_its_cache_publication() {
    let routing = Arc::new(matching_domain_routing());
    let response_cache = Arc::new(crate::ResidentDnsRuntimeCache::default());
    let now = unix_now();
    let name = "race.example.test";
    let mut old = response_plan(name, "192.0.2.1", now + 500);
    let mut new = response_plan(name, "192.0.2.2", now + 100);
    old.entry.packed_response = vec![0, 0, 1];
    new.entry.packed_response = vec![0, 0, 2];
    let (old_plan, old_revision) = prepare(&routing, &old);
    let (new_plan, new_revision) = prepare(&routing, &new);
    let key = crate::ResidentDnsResponseCacheKey::new(
        new.key.clone(),
        crate::ResidentDnsResponseCacheScope::AsIs {
            original_dst: "192.0.2.53:53".parse().unwrap(),
        },
    );
    let new_writer = {
        let routing = Arc::clone(&routing);
        let response_cache = Arc::clone(&response_cache);
        let key = key.clone();
        std::thread::spawn(move || {
            routing
                .commit_response(Some(new_plan), &new_revision, || {
                    response_cache.insert_response(now, key, new.entry)
                })
                .unwrap()
        })
    };
    assert!(new_writer.join().unwrap());
    let old_writer = {
        let routing = Arc::clone(&routing);
        let response_cache = Arc::clone(&response_cache);
        let key = key.clone();
        std::thread::spawn(move || {
            routing
                .commit_response(Some(old_plan), &old_revision, || {
                    response_cache.insert_response(now, key, old.entry)
                })
                .unwrap()
        })
    };
    assert!(!old_writer.join().unwrap());
    let payload = query(name);
    let request = DnsPacketView::parse(&payload).unwrap();
    let mut cached = Vec::new();
    assert!(
        response_cache
            .lookup_response_into(&key, &request, false, &mut cached)
            .unwrap()
    );
    assert_eq!(cached[2], 2);
    let state = routing.state.lock().unwrap();
    let entry = state
        .cache
        .shared_entry(&DnsCacheKey::new(name, 1, 1))
        .unwrap();
    assert_eq!(entry.deadline_unix, now + 100);
    assert_eq!(
        entry.ips,
        vec!["192.0.2.2".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(
        state.owner.tracker().entries()[0].key,
        ip_to_key(entry.ips[0])
    );
}

#[test]
fn removal_without_a_committed_entry_invalidates_pending_response() {
    let routing = matching_domain_routing();
    let response = response_plan("removed.example.test", "192.0.2.1", unix_now() + 300);
    let (plan, revision) = prepare(&routing, &response);
    let payload = query(&response.key.qname);
    let request = DnsPacketView::parse(&payload).unwrap();
    routing.remove_request(&request).unwrap();
    assert!(
        !routing
            .commit_response(Some(plan), &revision, || {
                panic!("removed response was republished")
            })
            .unwrap()
    );
    assert!(routing.state.lock().unwrap().cache.is_empty());
    routing.record_accepted_response(&response).unwrap();
    assert_eq!(routing.state.lock().unwrap().cache.len(), 1);
}

#[test]
fn newer_failed_map_transaction_does_not_suppress_an_older_valid_response() {
    fn fail_new(
        _: u32,
        updates: &[DomainRoutingStateEntry],
        _: &[DomainRoutingIpKey],
    ) -> io::Result<()> {
        if updates
            .iter()
            .any(|entry| entry.key == ip_to_key("192.0.2.2".parse().unwrap()))
        {
            return Err(io::Error::other("test map failure"));
        }
        Ok(())
    }
    let mut routing = matching_domain_routing();
    routing.test_apply_map = Some(fail_new);
    let old = response_plan("failure.example.test", "192.0.2.1", unix_now() + 300);
    let new = response_plan("failure.example.test", "192.0.2.2", unix_now() + 300);
    let (old_plan, old_revision) = prepare(&routing, &old);
    let (new_plan, new_revision) = prepare(&routing, &new);
    assert!(
        routing
            .commit_response(Some(new_plan), &new_revision, || {
                panic!("failed map response was cached")
            })
            .is_err()
    );
    assert!(!routing.state.lock().unwrap().owner_checked_out);
    assert!(
        routing
            .commit_response(Some(old_plan), &old_revision, || Ok(()))
            .unwrap()
    );
    assert_eq!(
        routing.state.lock().unwrap().owner.tracker().owner_count(),
        1
    );
}

#[test]
fn expiry_or_capacity_eviction_does_not_forget_a_newer_commit_while_old_plan_is_pending() {
    for expire in [false, true] {
        let routing = matching_domain_routing();
        let now = unix_now();
        let old = response_plan("race.example.test", "192.0.2.1", now + 500);
        let new = response_plan("race.example.test", "192.0.2.2", now + 100);
        let (old_plan, old_revision) = prepare(&routing, &old);
        let (new_plan, new_revision) = prepare(&routing, &new);
        assert!(
            routing
                .commit_response(Some(new_plan), &new_revision, || Ok(()))
                .unwrap()
        );
        if expire {
            routing.sweep_expired_until(now + 100).unwrap();
            assert!(routing.state.lock().unwrap().cache.is_empty());
        } else {
            routing
                .record_accepted_response(&response_plan(
                    "other.example.test",
                    "192.0.2.3",
                    now + 300,
                ))
                .unwrap();
        }
        assert!(
            !routing
                .commit_response(Some(old_plan), &old_revision, || {
                    panic!("old plan resurrected after removal")
                })
                .unwrap()
        );
    }
}

#[test]
fn reload_snapshot_keeps_a_newer_live_response() {
    let old = matching_domain_routing();
    old.record_accepted_response(&response_plan(
        "reload.example.test",
        "192.0.2.1",
        unix_now() + 300,
    ))
    .unwrap();
    let snapshot = old.snapshot_for_reload().unwrap();
    let new = matching_domain_routing();
    new.record_accepted_response(&response_plan(
        "reload.example.test",
        "192.0.2.2",
        unix_now() + 100,
    ))
    .unwrap();
    let report = new.restore_reload_snapshot(&snapshot).unwrap();
    assert_eq!(report.accepted_response_entries, 0);
    assert_eq!(report.skipped_superseded_entries, 1);
    assert_eq!(
        new.state.lock().unwrap().owner.tracker().entries()[0].key,
        ip_to_key("192.0.2.2".parse().unwrap())
    );
}

#[test]
fn response_and_removal_callbacks_run_inside_mutation_after_owner_is_restored() {
    let routing = matching_domain_routing();
    let response = response_plan("publish.example.test", "192.0.2.1", unix_now() + 300);
    routing
        .record_accepted_response_with(&response, || {
            assert!(routing.mutation.try_lock().is_err());
            let state = routing.state.lock().unwrap();
            assert!(!state.owner_checked_out);
            assert!(state.cache.contains_key(&response.key));
            Ok(())
        })
        .unwrap();
    let payload = query(&response.key.qname);
    routing
        .remove_request_with(&DnsPacketView::parse(&payload).unwrap(), || {
            assert!(routing.mutation.try_lock().is_err());
            let state = routing.state.lock().unwrap();
            assert!(!state.owner_checked_out);
            assert!(state.cache.is_empty());
            assert_eq!(state.owner.tracker().owner_count(), 0);
            Ok(())
        })
        .unwrap();
}

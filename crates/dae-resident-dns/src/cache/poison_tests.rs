use super::*;

fn key(name: &str) -> ResidentDnsResponseCacheKey {
    ResidentDnsResponseCacheKey::new(
        DnsCacheKey::new(name, 1, 1),
        ResidentDnsResponseCacheScope::Reject,
    )
}

fn poison<T>(mutex: &Mutex<T>) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = mutex.lock().unwrap();
        panic!("injected flight poison");
    }));
}

#[test]
fn poisoned_registry_retains_single_flight_identity_and_budgets() {
    let cache = ResidentDnsRuntimeCache::with_flight_limits(2, 2, 1024);
    let mut leader = cache.begin_flight(key("same.example")).unwrap();
    poison(&cache.inflight);
    let follower = cache.begin_flight(key("same.example")).unwrap();
    assert!(!follower.is_leader());
    assert!(Arc::ptr_eq(&leader.state, &follower.state));
    assert_eq!(cache.inflight_len(), 1);
    assert_eq!(leader.state.followers.load(Ordering::Acquire), 1);
    assert!(!cache.inflight.is_poisoned());
    leader.publish(Ok(&[0, 1, 2, 3])).unwrap();
    assert_eq!(
        restore_flight_response_id(follower.outcome().unwrap().unwrap(), 0x4321).unwrap(),
        [0x43, 0x21, 2, 3]
    );
    assert_eq!(cache.inflight_len(), 0);
    drop(leader);
    drop(follower);
    assert_eq!(cache.flight_retained_bytes(), 0);
}

#[tokio::test]
async fn poisoned_outcome_wakes_waiters_and_releases_retained_budget() {
    let cache = ResidentDnsRuntimeCache::with_flight_limits(2, 2, 1024);
    let mut leader = cache.begin_flight(key("same.example")).unwrap();
    let follower = cache.begin_flight(key("same.example")).unwrap();
    let notified = follower.state.notify.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    poison(&leader.state.outcome);
    assert!(
        leader
            .publish(Ok(&[0, 1, 2, 3]))
            .unwrap_err()
            .contains("poisoned")
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), notified)
        .await
        .unwrap();
    assert!(follower.outcome().unwrap_err().contains("poisoned"));
    assert_eq!(cache.inflight_len(), 0);
    assert_eq!(cache.flight_retained_bytes(), 0);
    let mut replacement = cache.begin_flight(key("same.example")).unwrap();
    assert!(replacement.is_leader());
    replacement.publish(Ok(&[0, 1])).unwrap();
    drop(leader);
    assert_eq!(cache.inflight_len(), 0);
}

#[test]
fn dropped_leader_removes_its_identity_even_if_both_locks_are_poisoned() {
    let cache = ResidentDnsRuntimeCache::with_flight_limits(1, 2, 1024);
    let leader = cache.begin_flight(key("same.example")).unwrap();
    let follower = cache.begin_flight(key("same.example")).unwrap();
    poison(&leader.state.outcome);
    poison(&cache.inflight);
    drop(leader);
    assert_eq!(cache.inflight_len(), 0);
    assert!(follower.outcome().is_err());
    assert!(
        cache
            .begin_flight(key("other.example"))
            .unwrap()
            .is_leader()
    );
}

#[test]
fn publication_without_followers_does_not_copy_or_reserve_a_response() {
    let cache = ResidentDnsRuntimeCache::with_flight_limits(2, 2, 1);
    let mut leader = cache.begin_flight(key("solo.example")).unwrap();
    let packet = vec![0; 65535];
    leader.publish(Ok(&packet)).unwrap();
    assert!(leader.outcome().unwrap().is_none());
    assert_eq!(cache.flight_retained_bytes(), 0);
    assert_eq!(cache.inflight_len(), 0);
    assert!(leader.publish(Ok(&packet)).is_err());
}

#[tokio::test]
async fn registering_during_publication_never_loses_a_waiter() {
    for _ in 0..100 {
        let cache = ResidentDnsRuntimeCache::with_flight_limits(2, 2, 4);
        let mut leader = cache.begin_flight(key("race.example")).unwrap();
        let barrier = std::sync::Barrier::new(2);
        let follower = std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                leader.publish(Ok(&[0, 1, 2, 3])).unwrap();
            });
            barrier.wait();
            cache.begin_flight(key("race.example")).unwrap()
        });
        if !follower.is_leader() {
            let packet = follower
                .wait(
                    ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(1)),
                    9,
                )
                .await
                .unwrap();
            assert_eq!(packet, [0, 9, 2, 3]);
        }
        drop(follower);
        drop(leader);
        assert_eq!(cache.inflight_len(), 0);
        assert_eq!(cache.flight_retained_bytes(), 0);
    }
}

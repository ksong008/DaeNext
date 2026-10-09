use super::*;
use dae_dns::DnsCacheEntry;
use std::time::Duration;

const QUERY: &[u8] = &[
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a',
    b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
];

fn test_asis_cache_key(request: &DnsPacketView<'_>) -> ResidentDnsResponseCacheKey {
    ResidentDnsResponseCacheKey::new(
        dns_cache_key_for_request(request).unwrap(),
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "127.0.0.1:53".parse().unwrap(),
        },
    )
}

fn test_scoped_cache_key(
    request: &DnsPacketView<'_>,
    scope: ResidentDnsResponseCacheScope,
) -> ResidentDnsResponseCacheKey {
    ResidentDnsResponseCacheKey::new(dns_cache_key_for_request(request).unwrap(), scope)
}

fn a_response(address: [u8; 4]) -> Vec<u8> {
    a_response_for_query(QUERY, address)
}

fn a_response_for_query(query: &[u8], address: [u8; 4]) -> Vec<u8> {
    let view = DnsPacketView::parse(query).unwrap();
    let mut response = Vec::new();
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..view.answer_offset()]);
    response.extend_from_slice(&0xc00c_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&address);
    response
}

#[test]
fn resident_dns_response_cache_honors_fixed_domain_ttl() {
    let request = DnsPacketView::parse(QUERY).unwrap();
    let cache_key = test_asis_cache_key(&request);
    let mut plan = ResidentDnsPlan::asis(0);
    plan.fixed_domain_ttl = Arc::new(BTreeMap::from([("example.com".to_owned(), 0)]));

    record_accepted_dns_response(&plan, &cache_key, &a_response([203, 0, 113, 42])).unwrap();

    let mut cached_response = Vec::new();
    assert!(
        !plan
            .cache
            .lookup_response_into(&cache_key, &request, false, &mut cached_response)
            .unwrap()
    );
    assert!(cached_response.is_empty());
    assert!(
        plan.cache
            .lookup_response_into(&cache_key, &request, true, &mut cached_response)
            .unwrap()
    );
    assert!(!cached_response.is_empty());
}

#[test]
fn resident_dns_response_cache_is_scoped_by_asis_destination() {
    let cache = ResidentDnsRuntimeCache::default();
    let request = DnsPacketView::parse(QUERY).unwrap();
    let response = a_response([203, 0, 113, 42]);
    let now = unix_now();
    let cache_plan = build_response_cache_plan_from_packet(now, &response, None)
        .unwrap()
        .unwrap();
    let first = test_scoped_cache_key(
        &request,
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "192.0.2.1:53".parse().unwrap(),
        },
    );
    let second = test_scoped_cache_key(
        &request,
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "192.0.2.2:53".parse().unwrap(),
        },
    );
    cache
        .insert_response(now, first.with_base(cache_plan.key), cache_plan.entry)
        .unwrap();

    let mut cached_response = Vec::new();
    assert!(
        !cache
            .lookup_response_into(&second, &request, false, &mut cached_response)
            .unwrap()
    );
    assert!(
        cache
            .lookup_response_into(&first, &request, false, &mut cached_response)
            .unwrap()
    );
}

#[test]
fn resident_dns_response_cache_is_scoped_by_upstream_identity() {
    let cache = ResidentDnsRuntimeCache::default();
    let request = DnsPacketView::parse(QUERY).unwrap();
    let response = a_response([203, 0, 113, 42]);
    let now = unix_now();
    let cache_plan = build_response_cache_plan_from_packet(now, &response, None)
        .unwrap()
        .unwrap();
    let first = test_scoped_cache_key(
        &request,
        ResidentDnsResponseCacheScope::Upstream {
            index: 1,
            scheme: ResidentDnsUpstreamScheme::TcpUdp.as_str().to_owned(),
            authority: "resolver-a.fixture.invalid:53".to_owned(),
            path: String::new(),
        },
    );
    let second = test_scoped_cache_key(
        &request,
        ResidentDnsResponseCacheScope::Upstream {
            index: 2,
            scheme: ResidentDnsUpstreamScheme::TcpUdp.as_str().to_owned(),
            authority: "resolver-b.fixture.invalid:53".to_owned(),
            path: String::new(),
        },
    );
    cache
        .insert_response(now, first.with_base(cache_plan.key), cache_plan.entry)
        .unwrap();

    let mut cached_response = Vec::new();
    assert!(
        !cache
            .lookup_response_into(&second, &request, false, &mut cached_response)
            .unwrap()
    );
    assert!(
        cache
            .lookup_response_into(&first, &request, false, &mut cached_response)
            .unwrap()
    );
}

#[test]
fn resident_dns_response_cache_serves_concurrent_readers_and_accounts_hits() {
    const READERS: usize = 8;
    const LOOKUPS_PER_READER: usize = 256;

    let cache = ResidentDnsRuntimeCache::default();
    let request = DnsPacketView::parse(QUERY).unwrap();
    let response = a_response([203, 0, 113, 43]);
    let now = unix_now();
    let cache_plan = build_response_cache_plan_from_packet(now, &response, None)
        .unwrap()
        .unwrap();
    let key = test_asis_cache_key(&request);
    cache
        .insert_response(now, key.with_base(cache_plan.key), cache_plan.entry)
        .unwrap();

    std::thread::scope(|scope| {
        for _ in 0..READERS {
            scope.spawn(|| {
                let request = DnsPacketView::parse(QUERY).unwrap();
                let mut cached_response = Vec::new();
                for _ in 0..LOOKUPS_PER_READER {
                    assert!(
                        cache
                            .lookup_response_into(&key, &request, false, &mut cached_response)
                            .unwrap()
                    );
                    assert_eq!(&cached_response[..2], &QUERY[..2]);
                    assert_eq!(
                        &cached_response[cached_response.len() - 4..],
                        &[203, 0, 113, 43]
                    );
                }
            });
        }
    });

    assert_eq!(
        cache.stats().hit_total,
        (READERS * LOOKUPS_PER_READER) as u64
    );
}

#[test]
fn resident_dns_response_cache_reload_snapshot_restores_live_entries() {
    let cache = ResidentDnsRuntimeCache::default();
    let request = DnsPacketView::parse(QUERY).unwrap();
    let response = a_response([203, 0, 113, 42]);
    let now = unix_now();
    let cache_plan = build_response_cache_plan_from_packet(now, &response, None)
        .unwrap()
        .unwrap();
    let cache_key = test_asis_cache_key(&request);
    cache
        .insert_response(
            now,
            cache_key.with_base(cache_plan.key.clone()),
            cache_plan.entry,
        )
        .unwrap();
    let snapshot = cache.snapshot_for_reload().unwrap();
    let restored = ResidentDnsRuntimeCache::default();

    assert_eq!(restored.restore_reload_snapshot(&snapshot).unwrap(), 1);

    let mut cached_response = Vec::new();
    assert!(
        restored
            .lookup_response_into(&cache_key, &request, false, &mut cached_response)
            .unwrap()
    );
    assert!(!cached_response.is_empty());
}

#[test]
fn resident_dns_response_cache_removes_all_scoped_siblings_for_base_key() {
    let cache = ResidentDnsRuntimeCache::default();
    let request = DnsPacketView::parse(QUERY).unwrap();
    let response = a_response([203, 0, 113, 42]);
    let now = unix_now();
    let cache_plan = build_response_cache_plan_from_packet(now, &response, None)
        .unwrap()
        .unwrap();
    let base = cache_plan.key.clone();
    for original_dst in ["192.0.2.1:53", "192.0.2.2:53"] {
        let key = test_scoped_cache_key(
            &request,
            ResidentDnsResponseCacheScope::AsIs {
                original_dst: original_dst.parse().unwrap(),
            },
        );
        cache
            .insert_response(
                now,
                key.with_base(cache_plan.key.clone()),
                cache_plan.entry.clone(),
            )
            .unwrap();
    }
    assert_eq!(cache.entry_len(), 2);
    assert_eq!(cache.deadline_len(), 2);
    let removed = cache.remove_base_key(&base).unwrap();
    assert_eq!(removed.len(), 2);
    assert_eq!(cache.entry_len(), 0);
    assert_eq!(cache.deadline_len(), 0);
}

#[test]
fn resident_dns_response_cache_base_lookup_is_limited_to_scoped_siblings() {
    let cache = ResidentDnsRuntimeCache::default();
    let response = a_response([203, 0, 113, 42]);
    let now = unix_now();
    let cache_plan = build_response_cache_plan_from_packet(now, &response, None)
        .unwrap()
        .unwrap();
    for qname in ["before.invalid", "target.invalid", "z-after.invalid"] {
        let scope = if qname == "target.invalid" {
            ResidentDnsResponseCacheScope::AsIs {
                original_dst: "192.0.2.53:53".parse().unwrap(),
            }
        } else {
            ResidentDnsResponseCacheScope::Reject
        };
        cache
            .insert_response(
                now,
                ResidentDnsResponseCacheKey::new(DnsCacheKey::new(qname, 1, 1), scope),
                cache_plan.entry.clone(),
            )
            .unwrap();
    }

    assert!(
        cache
            .lookup_key_has_any_ip(&DnsCacheKey::new("target.invalid", 1, 1), false)
            .unwrap()
    );
    assert!(
        !cache
            .lookup_key_has_any_ip(&DnsCacheKey::new("missing.invalid", 1, 1), false)
            .unwrap()
    );
}

#[tokio::test]
async fn resident_dns_flight_broadcasts_one_response_without_serial_locking() {
    let cache = ResidentDnsRuntimeCache::default();
    let key = ResidentDnsResponseCacheKey::new(
        DnsCacheKey::new("example.com.", DNS_QTYPE_A, 1),
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "127.0.0.1:53".parse().unwrap(),
        },
    );
    let mut leader = cache.begin_flight(key.clone()).unwrap();
    let follower = cache.begin_flight(key).unwrap();
    assert!(leader.is_leader());
    assert!(!follower.is_leader());

    let wait = follower.wait(
        ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
        0xabcd,
    );
    let response = [0x12, 0x34, 0x81, 0x80];
    leader.publish(Ok(&response)).unwrap();
    assert_eq!(wait.await.unwrap(), [0xab, 0xcd, 0x81, 0x80]);
    assert_eq!(cache.inflight_len(), 0);
}

#[tokio::test]
async fn resident_dns_same_key_burst_wakes_all_followers_with_their_request_ids() {
    const FOLLOWERS: usize = 128;
    let cache = ResidentDnsRuntimeCache::default();
    let key = ResidentDnsResponseCacheKey::new(
        DnsCacheKey::new("burst.example.", DNS_QTYPE_A, 1),
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "127.0.0.1:53".parse().unwrap(),
        },
    );
    let mut leader = cache.begin_flight(key.clone()).unwrap();
    let followers = (0..FOLLOWERS)
        .map(|_| cache.begin_flight(key.clone()).unwrap())
        .collect::<Vec<_>>();
    assert!(leader.is_leader());
    assert!(followers.iter().all(|follower| !follower.is_leader()));
    assert_eq!(cache.inflight_len(), 1);

    leader.publish(Ok(&[0x12, 0x34, 0x81, 0x80])).unwrap();
    let waits = followers
        .into_iter()
        .enumerate()
        .map(|(index, follower)| async move {
            let request_id = u16::try_from(index + 1).unwrap();
            let response = follower
                .wait(
                    ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
                    request_id,
                )
                .await
                .unwrap();
            assert_eq!(&response[0..2], &request_id.to_be_bytes());
        });
    futures_util::future::join_all(waits).await;
    assert_eq!(cache.inflight_len(), 0);
}

#[test]
fn resident_dns_unique_key_burst_uses_independent_bounded_entries() {
    const FLIGHTS: usize = 64;
    let cache = ResidentDnsRuntimeCache::with_flight_entry_limit(FLIGHTS);
    let mut leaders = (0..FLIGHTS)
        .map(|index| {
            let key = ResidentDnsResponseCacheKey::new(
                DnsCacheKey::new(format!("unique-{index}.example."), DNS_QTYPE_A, 1),
                ResidentDnsResponseCacheScope::AsIs {
                    original_dst: "127.0.0.1:53".parse().unwrap(),
                },
            );
            cache.begin_flight(key).unwrap()
        })
        .collect::<Vec<_>>();
    assert!(leaders.iter().all(|leader| leader.is_leader()));
    assert_eq!(cache.inflight_len(), FLIGHTS);

    for (index, leader) in leaders.iter_mut().enumerate() {
        let id = u16::try_from(index).unwrap().to_be_bytes();
        leader.publish(Ok(&[id[0], id[1], 0x81, 0x80])).unwrap();
    }
    assert_eq!(cache.inflight_len(), 0);
}

#[tokio::test]
async fn resident_dns_flight_bounds_followers_and_retained_response_bytes() {
    let cache = ResidentDnsRuntimeCache::with_flight_limits(2, 1, 4);
    let key = ResidentDnsResponseCacheKey::new(
        DnsCacheKey::new("bounded-flight.example.", DNS_QTYPE_A, 1),
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "127.0.0.1:53".parse().unwrap(),
        },
    );
    let mut leader = cache.begin_flight(key.clone()).unwrap();
    let follower = cache.begin_flight(key.clone()).unwrap();
    let follower_error = cache.begin_flight(key).err().unwrap();
    assert!(follower_error.contains("follower limit reached"));

    let leader_error = leader
        .publish(Ok(&[0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0]))
        .unwrap_err();
    assert!(leader_error.contains("retained response byte limit reached"));
    assert_eq!(cache.flight_retained_bytes(), 0);
    let error = follower
        .wait(
            ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
            0x7171,
        )
        .await
        .unwrap_err();
    assert!(error.contains("retained response byte limit reached"));
    assert_eq!(error, leader_error);

    let retained_key = ResidentDnsResponseCacheKey::new(
        DnsCacheKey::new("retained-flight.example.", DNS_QTYPE_A, 1),
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "127.0.0.1:53".parse().unwrap(),
        },
    );
    let mut retained_leader = cache.begin_flight(retained_key.clone()).unwrap();
    let retained_follower = cache.begin_flight(retained_key).unwrap();
    retained_leader
        .publish(Ok(&[0x12, 0x34, 0x81, 0x80]))
        .unwrap();
    assert_eq!(cache.flight_retained_bytes(), 4);
    assert_eq!(
        retained_follower
            .wait(
                ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
                0x7272,
            )
            .await
            .unwrap(),
        [0x72, 0x72, 0x81, 0x80]
    );
    drop(retained_follower);
    drop(retained_leader);
    assert_eq!(cache.flight_retained_bytes(), 0);
}

#[test]
fn resident_dns_flight_limit_detaches_new_leaders_without_capacity_failure() {
    let cache = ResidentDnsRuntimeCache::with_flight_entry_limit(1);
    let first_key = ResidentDnsResponseCacheKey::new(
        DnsCacheKey::new("first.example.", DNS_QTYPE_A, 1),
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "127.0.0.1:53".parse().unwrap(),
        },
    );
    let second_key = ResidentDnsResponseCacheKey::new(
        DnsCacheKey::new("second.example.", DNS_QTYPE_A, 1),
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "127.0.0.1:53".parse().unwrap(),
        },
    );
    let mut registered = cache.begin_flight(first_key).unwrap();
    let mut detached = cache.begin_flight(second_key.clone()).unwrap();
    let independent = cache.begin_flight(second_key).unwrap();

    assert!(registered.is_leader());
    assert!(detached.is_leader());
    assert!(independent.is_leader());
    assert_eq!(cache.inflight_len(), 1);
    registered.publish(Ok(&[0, 1, 0x81, 0x80])).unwrap();
    detached.publish(Ok(&[0, 2, 0x81, 0x80])).unwrap();
    assert_eq!(cache.inflight_len(), 0);
}

#[test]
fn resident_dns_runtime_cache_sweeps_expired_entries_on_write_window() {
    let cache = ResidentDnsRuntimeCache::default();
    let now = 1_700_000_000_i64;
    cache
        .insert_response(
            now,
            ResidentDnsResponseCacheKey::new(
                DnsCacheKey::new("expired.example.", DNS_QTYPE_A, 1),
                ResidentDnsResponseCacheScope::AsIs {
                    original_dst: "127.0.0.1:53".parse().unwrap(),
                },
            ),
            DnsCacheEntry::new(now - 1, now - 1),
        )
        .unwrap();
    assert_eq!(cache.entry_len(), 1);

    cache
        .insert_response(
            now + 120,
            ResidentDnsResponseCacheKey::new(
                DnsCacheKey::new("live.example.", DNS_QTYPE_A, 1),
                ResidentDnsResponseCacheScope::AsIs {
                    original_dst: "127.0.0.1:53".parse().unwrap(),
                },
            ),
            DnsCacheEntry::new(now + 180, now + 180),
        )
        .unwrap();

    assert_eq!(cache.entry_len(), 1);
    assert_eq!(cache.deadline_len(), 1);
    assert_eq!(cache.stats().expired_removal_total, 1);
}

#[test]
fn resident_dns_runtime_cache_replacement_updates_deadline_index() {
    let cache = ResidentDnsRuntimeCache::default();
    let now = 1_700_000_000_i64;
    let key = ResidentDnsResponseCacheKey::new(
        DnsCacheKey::new("replacement.example.", DNS_QTYPE_A, 1),
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "127.0.0.1:53".parse().unwrap(),
        },
    );
    cache
        .insert_response(now, key.clone(), DnsCacheEntry::new(now + 1, now + 1))
        .unwrap();
    cache
        .insert_response(now, key, DnsCacheEntry::new(now + 300, now + 300))
        .unwrap();

    assert_eq!(cache.entry_len(), 1);
    assert_eq!(cache.deadline_len(), 1);
    cache
        .insert_response(
            now + 120,
            ResidentDnsResponseCacheKey::new(
                DnsCacheKey::new("second.example.", DNS_QTYPE_A, 1),
                ResidentDnsResponseCacheScope::AsIs {
                    original_dst: "127.0.0.1:53".parse().unwrap(),
                },
            ),
            DnsCacheEntry::new(now + 300, now + 300),
        )
        .unwrap();

    assert_eq!(cache.entry_len(), 2);
    assert_eq!(cache.deadline_len(), 2);
}

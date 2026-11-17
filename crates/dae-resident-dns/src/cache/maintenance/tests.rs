use super::*;

fn key_in_shard(
    cache: &ResidentDnsRuntimeCache,
    index: usize,
    prefix: &str,
) -> ResidentDnsResponseCacheKey {
    (0..10000)
        .find_map(|id| {
            let base = DnsCacheKey::new(format!("{prefix}-{id}.test"), 1, 1);
            (cache.shard_index(&base) == index).then_some(ResidentDnsResponseCacheKey::new(
                base,
                ResidentDnsResponseCacheScope::Reject,
            ))
        })
        .unwrap()
}

#[test]
fn poisoned_shard_is_rebuilt_without_losing_healthy_shards_or_blocking_global_sweep() {
    let cache = Arc::new(ResidentDnsRuntimeCache::with_cache_entry_limit(64));
    let now = unix_now();
    let damaged = key_in_shard(&cache, 0, "damaged");
    let healthy = key_in_shard(&cache, 1, "healthy");
    for key in [&damaged, &healthy] {
        cache
            .insert_response(now, key.clone(), DnsCacheEntry::new(now + 300, now + 300))
            .unwrap();
    }
    let snapshot = Arc::clone(&cache.shards[0].lock().unwrap().entries[&damaged].entry);
    assert_eq!(cache.shards[0].lock().unwrap().deadlines.len(), 1);
    let poison = Arc::clone(&cache);
    assert!(
        std::thread::spawn(move || {
            let _state = poison.shards[0].lock().unwrap();
            panic!("test incomplete cache mutation");
        })
        .join()
        .is_err()
    );
    let new = key_in_shard(&cache, 1, "new");
    cache
        .insert_response(
            now + 60,
            new.clone(),
            DnsCacheEntry::new(now + 300, now + 300),
        )
        .unwrap();
    assert!(!cache.shards[0].is_poisoned());
    let damaged_state = cache.shards[0].lock().unwrap();
    assert!(damaged_state.entries.is_empty());
    assert_eq!(damaged_state.deadlines.len(), 0);
    drop(damaged_state);
    assert_eq!(Arc::strong_count(&snapshot), 1);
    assert_eq!(snapshot.cache_expires_at(), now + 300);
    let state = cache.shards[1].lock().unwrap();
    assert!(state.entries.contains_key(&healthy));
    assert!(state.entries.contains_key(&new));
    assert_eq!(state.deadlines.len(), 2);
    assert_eq!(state.next_sweep_unix, now + 120);
    assert_eq!(cache.next_sweep.load(Ordering::Relaxed), now + 120);
}

impl ResidentDnsRuntimeCache {
    pub(crate) fn poison_shard_for_test(&self, key: &DnsCacheKey) {
        let panic = std::panic::catch_unwind(|| {
            let _state = self.shard(key).lock().unwrap();
            panic!("test panic while holding response cache shard");
        });
        assert!(panic.is_err());
        assert!(self.shard(key).is_poisoned());
    }
}

thread_local! {
    static INTERRUPT_SCAN: std::cell::Cell<Option<Option<i64>>> = const {
        std::cell::Cell::new(None)
    };
}

pub(super) fn interrupt_scan_if_requested(cache: &ResidentDnsRuntimeCache) {
    if let Some(later) = INTERRUPT_SCAN.take() {
        if let Some(later) = later {
            cache.next_sweep.store(later, Ordering::Relaxed);
        }
        panic!("test interrupted scan");
    }
}

#[test]
fn incomplete_scan_releases_its_reservation_without_replacing_a_later_reservation() {
    for later in [None, Some(120)] {
        let cache = ResidentDnsRuntimeCache::with_cache_entry_limit(4);
        INTERRUPT_SCAN.set(Some(later));
        let result = std::panic::catch_unwind(|| cache.sweep_all_if_due(0));
        assert!(result.is_err());
        assert_eq!(cache.next_sweep.load(Ordering::Relaxed), later.unwrap_or(0));
    }
}

#[test]
fn completed_scan_keeps_its_reservation_and_not_due_scan_does_not_visit_shards() {
    let cache = ResidentDnsRuntimeCache::with_cache_entry_limit(4);
    cache.sweep_all_if_due(0);
    assert_eq!(cache.next_sweep.load(Ordering::Relaxed), 60);
    for shard in &cache.shards {
        assert_eq!(shard.lock().unwrap().next_sweep_unix, 60);
    }
    INTERRUPT_SCAN.set(Some(None));
    cache.sweep_all_if_due(1);
    assert_eq!(
        INTERRUPT_SCAN.take(),
        Some(None),
        "not due must skip the scan"
    );
    assert_eq!(cache.next_sweep.load(Ordering::Relaxed), 60);
}

#[test]
fn discard_base_key_keeps_shared_snapshots_and_removes_all_scopes() {
    let cache = ResidentDnsRuntimeCache::with_cache_entry_limit(4);
    let base = DnsCacheKey::new("shared.test", 1, 1);
    let now = unix_now();
    let first =
        ResidentDnsResponseCacheKey::new(base.clone(), ResidentDnsResponseCacheScope::Reject);
    for port in [53, 54] {
        let key = ResidentDnsResponseCacheKey::new(
            base.clone(),
            ResidentDnsResponseCacheScope::AsIs {
                original_dst: format!("192.0.2.53:{port}").parse().unwrap(),
            },
        );
        cache
            .insert_response(now, key, DnsCacheEntry::new(now + 300, now + 300))
            .unwrap();
    }
    cache
        .insert_response(now, first.clone(), DnsCacheEntry::new(now + 300, now + 300))
        .unwrap();
    let snapshot = Arc::clone(&cache.shard(&base).lock().unwrap().entries[&first].entry);
    assert_eq!(cache.discard_base_key(&base).unwrap(), 3);
    assert_eq!(Arc::strong_count(&snapshot), 1);
    assert_eq!(cache.entry_count().unwrap(), 0);
    assert_eq!(cache.deadline_len(), 0);
    assert_eq!(cache.stats().remove_callback_total, 3);
}

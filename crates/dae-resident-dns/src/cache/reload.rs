use super::*;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResidentDnsRuntimeCacheSnapshot {
    entries: Vec<(ResidentDnsResponseCacheKey, Arc<DnsCacheEntry>)>,
}

impl ResidentDnsRuntimeCacheSnapshot {
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl ResidentDnsRuntimeCache {
    pub fn snapshot_for_reload(&self) -> Result<ResidentDnsRuntimeCacheSnapshot, String> {
        let now_unix = unix_now();
        let mut entries = Vec::new();
        for shard in &self.shards {
            let mut state = lock_cache_shard(shard);
            remove_expired_entries(&mut state, now_unix);
            entries.extend(
                state
                    .entries
                    .iter()
                    .filter(|(_, stored)| stored.entry.cache_expires_at() > now_unix)
                    .map(|(key, stored)| (key.clone(), Arc::clone(&stored.entry))),
            );
        }
        entries.sort_by(|(left, _), (right, _)| left.cmp(right));
        Ok(ResidentDnsRuntimeCacheSnapshot { entries })
    }

    pub fn restore_reload_snapshot(
        &self,
        snapshot: &ResidentDnsRuntimeCacheSnapshot,
    ) -> Result<usize, String> {
        if snapshot.entries.is_empty() {
            return Ok(0);
        }
        let now_unix = unix_now();
        let mut restored = 0_usize;
        for (key, entry) in &snapshot.entries {
            if entry.cache_expires_at() <= now_unix {
                continue;
            }
            let mut state = lock_cache_shard(self.shard(&key.base));
            remove_expired_entries(&mut state, now_unix);
            // A live query may have already published a fresher response while
            // reload was preparing its snapshot. Restore only missing scopes.
            if state.entries.contains_key(key) {
                continue;
            }
            evict_entries(&mut state, now_unix, self.shard_limit(&key.base));
            insert_cache_entry(&mut state, key.clone(), Arc::clone(entry));
            restored += 1;
        }
        Ok(restored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_does_not_replace_an_existing_live_response() {
        let source = ResidentDnsRuntimeCache::with_cache_entry_limit(4);
        let key = ResidentDnsResponseCacheKey::new(
            DnsCacheKey::new("reload.example", 1, 1),
            ResidentDnsResponseCacheScope::Reject,
        );
        let now = unix_now();
        source
            .insert_response(now, key.clone(), DnsCacheEntry::new(now + 300, now + 300))
            .unwrap();
        let snapshot = source.snapshot_for_reload().unwrap();
        let destination = ResidentDnsRuntimeCache::with_cache_entry_limit(4);
        destination
            .insert_response(now, key.clone(), DnsCacheEntry::new(now + 100, now + 100))
            .unwrap();
        assert_eq!(destination.restore_reload_snapshot(&snapshot).unwrap(), 0);
        let state = destination.shard(&key.base).lock().unwrap();
        assert_eq!(state.entries[&key].entry.deadline_unix, now + 100);
    }

    #[test]
    fn reload_snapshot_shares_entries_with_the_source_cache() {
        let cache = ResidentDnsRuntimeCache::with_cache_entry_limit(4);
        let key = ResidentDnsResponseCacheKey::new(
            DnsCacheKey::new("shared.example.", 1, 1),
            ResidentDnsResponseCacheScope::Reject,
        );
        cache
            .insert_response(
                unix_now(),
                key,
                DnsCacheEntry::new(unix_now() + 60, unix_now() + 60),
            )
            .unwrap();

        let snapshot = cache.snapshot_for_reload().unwrap();
        assert_eq!(snapshot.entry_count(), 1);
        assert_eq!(Arc::strong_count(&snapshot.entries[0].1), 2);

        let restored = ResidentDnsRuntimeCache::with_cache_entry_limit(4);
        assert_eq!(restored.restore_reload_snapshot(&snapshot).unwrap(), 1);
        assert_eq!(Arc::strong_count(&snapshot.entries[0].1), 3);
    }

    #[test]
    fn cache_capacity_is_profileled_and_large_packed_responses_are_not_retained() {
        let cache = ResidentDnsRuntimeCache::with_cache_entry_limit(1);
        let now = unix_now();
        let first = ResidentDnsResponseCacheKey::new(
            DnsCacheKey::new("first.example.", 1, 1),
            ResidentDnsResponseCacheScope::Reject,
        );
        let second = ResidentDnsResponseCacheKey::new(
            DnsCacheKey::new("second.example.", 1, 1),
            ResidentDnsResponseCacheScope::Reject,
        );
        cache
            .insert_response(now, first, DnsCacheEntry::new(now + 60, now + 60))
            .unwrap();
        cache
            .insert_response(now, second, DnsCacheEntry::new(now + 60, now + 60))
            .unwrap();
        assert_eq!(cache.entry_len(), 1);

        let large = ResidentDnsResponseCacheKey::new(
            DnsCacheKey::new("large.example.", 1, 1),
            ResidentDnsResponseCacheScope::Reject,
        );
        let mut large_entry = DnsCacheEntry::new(now + 60, now + 60);
        large_entry.packed_response = vec![0; DNS_RUNTIME_CACHE_MAX_PACKED_RESPONSE_BYTES + 1];
        cache.insert_response(now, large, large_entry).unwrap();
        assert_eq!(cache.entry_len(), 1);
    }
}

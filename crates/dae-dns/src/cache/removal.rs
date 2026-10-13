use super::*;

impl DnsCacheStore {
    /// Remove without materializing an owned entry or notifying its external
    /// owner. The caller must first finish any external owner transaction.
    pub fn discard(&mut self, key: &DnsCacheKey) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Discard a bounded expired batch after its external owner transaction.
    /// Shared snapshots can outlive this call without forcing deep copies.
    /// Stale deadline records count toward the scan limit and are also cleared,
    /// even when the batch contains no actual expired cache entries.
    pub fn discard_expired_entries_limited(&mut self, now_unix: i64, limit: usize) -> usize {
        let removed = self.entries.remove_expired_entries(now_unix, limit);
        let count = removed.len();
        self.stats.expired_removal_total += count as u64;
        self.stats.remove_callback_total += count as u64;
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discard_keeps_shared_snapshots_and_counts_only_expired_removals() {
        let mut cache = DnsCacheStore::new(4096);
        let expired_key = DnsCacheKey::new("expired.test", 1, 1);
        let live_key = DnsCacheKey::new("live.test", 1, 1);
        let mut expired_entry = DnsCacheEntry::new(10, 10);
        expired_entry.ips.push("192.0.2.1".parse().unwrap());
        expired_entry.domain_bitmap = vec![1; 32];
        cache.insert(0, expired_key.clone(), expired_entry);
        cache.insert(0, live_key.clone(), DnsCacheEntry::new(100, 100));
        let expired = cache.expired_entries_shared(20, 128);
        let snapshot = cache.shared_entry(&live_key).unwrap();

        assert_eq!(cache.discard_expired_entries_limited(20, 128), 1);
        assert_eq!(Arc::strong_count(&expired[0].1), 1);
        assert_eq!(expired[0].1.ips.len(), 1);
        assert_eq!(expired[0].1.domain_bitmap, vec![1; 32]);
        assert!(!cache.contains_key(&expired_key));
        assert_eq!(cache.stats().expired_removal_total, 1);
        assert_eq!(cache.stats().remove_callback_total, 1);
        assert!(cache.discard(&live_key));
        assert!(!cache.discard(&live_key));
        assert_eq!(Arc::strong_count(&snapshot), 1);
        assert_eq!(cache.stats().expired_removal_total, 1);
    }

    #[test]
    fn stale_and_missing_expiry_batches_make_progress_without_removing_live_entries() {
        let mut cache = DnsCacheStore::new(4096);
        let live = DnsCacheKey::new("live.test", 1, 1);
        cache.insert(0, live.clone(), DnsCacheEntry::new(200, 200));
        if let DnsCacheEntries::Map { deadlines, .. } = &mut cache.entries {
            deadlines.insert((10, live.clone()));
            deadlines.insert((11, DnsCacheKey::new("missing.test", 1, 1)));
        }
        assert!(cache.expired_entries_shared(20, 1).is_empty());
        assert_eq!(cache.discard_expired_entries_limited(20, 1), 0);
        assert_eq!(cache.next_expiry_unix(), Some(11));
        assert!(cache.expired_entries_shared(20, 1).is_empty());
        assert_eq!(cache.discard_expired_entries_limited(20, 1), 0);
        assert_eq!(cache.next_expiry_unix(), Some(200));
        assert!(cache.contains_key(&live));
        assert_eq!(cache.stats(), &DnsCacheStats::default());
    }
}

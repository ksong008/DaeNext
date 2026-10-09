use super::*;

impl DnsCacheStore {
    /// Insert after a transactional external-owner update. Expiration is left to
    /// the caller's explicit sweep transaction; no removed owner is hidden.
    /// On callback failure all capacity victims are restored without changing
    /// removal statistics or replacing the previous value of the inserted key.
    pub fn insert_with_eviction<E>(
        &mut self,
        key: DnsCacheKey,
        entry: DnsCacheEntry,
        apply: impl FnOnce(&[(DnsCacheKey, Arc<DnsCacheEntry>)], &DnsCacheEntry) -> Result<(), E>,
    ) -> Result<bool, E> {
        if self.capacity == 0 {
            return Ok(false);
        }
        let mut evicted = Vec::new();
        if !self.entries.contains_key(&key) {
            while self.entries.len() >= self.capacity {
                let Some(victim) = self.entries.oldest_key() else {
                    break;
                };
                if let Some(entry) = self.entries.remove(&victim) {
                    evicted.push((victim, entry));
                }
            }
        }
        if let Err(error) = apply(&evicted, &entry) {
            for (key, entry) in evicted {
                self.entries.insert(
                    key,
                    Arc::try_unwrap(entry).unwrap_or_else(|entry| (*entry).clone()),
                );
            }
            return Err(error);
        }
        self.stats.remove_callback_total += evicted.len() as u64;
        self.entries.insert(key, entry);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_capacity_eviction_and_rollback_preserve_entries_and_statistics() {
        let mut cache = DnsCacheStore::new(17);
        for id in 0..17 {
            cache.insert(
                0,
                DnsCacheKey::new(format!("{id}.test"), 1, 1),
                DnsCacheEntry::new(100 + id, 100 + id),
            );
        }
        let key = DnsCacheKey::new("new.test", 1, 1);
        let before = cache.snapshot_live_entries_shared(0);
        let stats = cache.stats().clone();
        assert_eq!(
            cache.insert_with_eviction(key.clone(), DnsCacheEntry::new(500, 500), |victims, _| {
                assert_eq!(victims.len(), 1);
                assert_eq!(victims[0].0, DnsCacheKey::new("0.test", 1, 1));
                Err("map failure")
            }),
            Err("map failure")
        );
        assert_eq!(cache.snapshot_live_entries_shared(0), before);
        assert_eq!(cache.stats(), &stats);
        cache
            .insert_with_eviction(key, DnsCacheEntry::new(500, 500), |victims, _| {
                assert_eq!(victims[0].0, DnsCacheKey::new("0.test", 1, 1));
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(cache.len(), 17);
        assert!(!cache.contains_key(&DnsCacheKey::new("0.test", 1, 1)));
    }

    #[test]
    fn owned_insert_and_shared_snapshot_leave_expiry_to_explicit_transaction() {
        let mut cache = DnsCacheStore::new(4096);
        let expired = DnsCacheKey::new("expired.test", 1, 1);
        cache.insert(0, expired.clone(), DnsCacheEntry::new(1, 1));
        cache
            .insert_with_eviction(
                DnsCacheKey::new("live.test", 1, 1),
                DnsCacheEntry::new(100, 100),
                |victims, _| {
                    assert!(victims.is_empty());
                    Ok::<_, ()>(())
                },
            )
            .unwrap();
        assert_eq!(cache.snapshot_live_entries_shared(2).len(), 1);
        assert!(cache.contains_key(&expired));
        let removed = cache.sweep_entries(2);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].0, expired);
    }
}

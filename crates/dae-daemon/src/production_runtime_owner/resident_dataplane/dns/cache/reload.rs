use super::*;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsRuntimeCacheSnapshot
{
    entries: Vec<(ResidentDnsResponseCacheKey, DnsCacheEntry)>,
}

impl ResidentDnsRuntimeCacheSnapshot {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn entry_count(
        &self,
    ) -> usize {
        self.entries.len()
    }
}

impl ResidentDnsRuntimeCache {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn snapshot_for_reload(
        &self,
    ) -> Result<ResidentDnsRuntimeCacheSnapshot, String> {
        let now_unix = unix_now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?;
        remove_expired_entries(&mut state, now_unix);
        let mut entries = state
            .entries
            .iter()
            .filter(|(_, stored)| stored.entry.cache_expires_at() > now_unix)
            .map(|(key, stored)| (key.clone(), stored.entry.clone()))
            .collect::<Vec<_>>();
        entries.sort_by(|(left, _), (right, _)| left.cmp(right));
        Ok(ResidentDnsRuntimeCacheSnapshot { entries })
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn restore_reload_snapshot(
        &self,
        snapshot: &ResidentDnsRuntimeCacheSnapshot,
    ) -> Result<usize, String> {
        if snapshot.entries.is_empty() {
            return Ok(0);
        }
        let now_unix = unix_now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?;
        remove_expired_entries(&mut state, now_unix);
        let mut restored = 0_usize;
        for (key, entry) in &snapshot.entries {
            if entry.cache_expires_at() <= now_unix {
                continue;
            }
            if !state.entries.contains_key(key) {
                evict_entries(&mut state, now_unix);
            }
            insert_cache_entry(&mut state, key.clone(), entry.clone());
            restored += 1;
        }
        Ok(restored)
    }
}

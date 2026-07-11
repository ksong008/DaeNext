use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use dae_dns::cache::DNS_CACHE_MAX_ENTRIES;
use dae_dns::{DnsCacheEntry, DnsCacheKey, DnsCacheStats, DnsPacketView};
use tokio::sync::OwnedMutexGuard;

use super::{ResidentDnsUpstream, ResidentDnsUpstreamScheme, unix_now};

mod reload;
pub(super) use self::reload::ResidentDnsRuntimeCacheSnapshot;
mod deadline_index;
use self::deadline_index::{ResidentDnsCacheDeadline, ResidentDnsCacheDeadlineIndex};

const DNS_RUNTIME_CACHE_SWEEP_INTERVAL_SECS: i64 = 60;

#[derive(Debug, Default)]
pub(super) struct ResidentDnsRuntimeCache {
    state: Mutex<ResidentDnsRuntimeCacheState>,
    inflight: Mutex<BTreeMap<ResidentDnsResponseCacheKey, Arc<tokio::sync::Mutex<()>>>>,
}

#[derive(Debug, Default)]
struct ResidentDnsRuntimeCacheState {
    entries: BTreeMap<ResidentDnsResponseCacheKey, ResidentDnsStoredCacheEntry>,
    deadlines: ResidentDnsCacheDeadlineIndex,
    stats: DnsCacheStats,
    next_sweep_unix: i64,
}

#[derive(Debug)]
struct ResidentDnsStoredCacheEntry {
    entry: DnsCacheEntry,
    deadline: ResidentDnsCacheDeadline,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct ResidentDnsResponseCacheKey {
    base: DnsCacheKey,
    scope: ResidentDnsResponseCacheScope,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum ResidentDnsResponseCacheScope {
    Reject,
    AsIs {
        original_dst: SocketAddr,
    },
    Upstream {
        index: u8,
        scheme: ResidentDnsUpstreamScheme,
        authority: String,
        path: String,
    },
}

impl ResidentDnsResponseCacheKey {
    pub(super) fn new(base: DnsCacheKey, scope: ResidentDnsResponseCacheScope) -> Self {
        Self { base, scope }
    }

    pub(super) fn with_base(&self, base: DnsCacheKey) -> Self {
        Self {
            base,
            scope: self.scope.clone(),
        }
    }
}

impl ResidentDnsResponseCacheScope {
    pub(super) fn upstream(upstream: &ResidentDnsUpstream) -> Self {
        Self::Upstream {
            index: upstream.index,
            scheme: upstream.scheme,
            authority: upstream.target.authority.clone(),
            path: upstream.path.clone(),
        }
    }
}

pub(super) struct ResidentDnsInflightGuard<'a> {
    cache: &'a ResidentDnsRuntimeCache,
    key: ResidentDnsResponseCacheKey,
    lock: Arc<tokio::sync::Mutex<()>>,
    _guard: OwnedMutexGuard<()>,
}

impl ResidentDnsRuntimeCache {
    pub(super) async fn lock_key(
        &self,
        key: ResidentDnsResponseCacheKey,
    ) -> Result<ResidentDnsInflightGuard<'_>, String> {
        let lock = {
            let mut inflight = self
                .inflight
                .lock()
                .map_err(|_| "resident DNS inflight lock poisoned".to_owned())?;
            inflight
                .entry(key.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let guard = Arc::clone(&lock).lock_owned().await;
        Ok(ResidentDnsInflightGuard {
            cache: self,
            key,
            lock,
            _guard: guard,
        })
    }

    pub(super) fn lookup_response_into(
        &self,
        key: &ResidentDnsResponseCacheKey,
        request: &DnsPacketView<'_>,
        ignore_fixed_ttl: bool,
        out: &mut Vec<u8>,
    ) -> Result<bool, String> {
        out.clear();
        let now_unix = unix_now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?;
        lookup_scoped_response_into(&mut state, now_unix, key, request, ignore_fixed_ttl, out)
    }

    pub(super) fn lookup_key_has_any_ip(
        &self,
        key: &DnsCacheKey,
        ignore_fixed_ttl: bool,
    ) -> Result<bool, String> {
        let now_unix = unix_now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?;
        sweep_expired_if_due(&mut state, now_unix);
        Ok(state.entries.iter().any(|(candidate, stored)| {
            &candidate.base == key
                && stored.entry.lookup_deadline(ignore_fixed_ttl) > now_unix
                && stored.entry.has_any_ip
        }))
    }

    pub(super) fn insert_response(
        &self,
        now_unix: i64,
        key: ResidentDnsResponseCacheKey,
        mut entry: DnsCacheEntry,
    ) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?;
        sweep_expired_if_due(&mut state, now_unix);
        if !state.entries.contains_key(&key) {
            evict_entries(&mut state, now_unix);
        }
        entry.route_owner_key = key.base.to_string();
        insert_cache_entry(&mut state, key, entry);
        Ok(())
    }

    pub(super) fn remove_base_key(&self, key: &DnsCacheKey) -> Result<Vec<DnsCacheEntry>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?;
        let scoped_keys = state
            .entries
            .keys()
            .filter(|candidate| &candidate.base == key)
            .cloned()
            .collect::<Vec<_>>();
        let mut removed = Vec::with_capacity(scoped_keys.len());
        for scoped_key in scoped_keys {
            if let Some(entry) = remove_cache_entry(&mut state, &scoped_key) {
                removed.push(entry);
            }
        }
        state.stats.remove_callback_total += removed.len() as u64;
        Ok(removed)
    }

    #[cfg(test)]
    pub(super) fn inflight_len(&self) -> usize {
        self.inflight
            .lock()
            .map(|inflight| inflight.len())
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(super) fn entry_len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.entries.len())
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(super) fn deadline_len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.deadlines.len())
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(super) fn stats(&self) -> dae_dns::DnsCacheStats {
        self.state
            .lock()
            .map(|state| state.stats.clone())
            .unwrap_or_default()
    }
}

fn lookup_scoped_response_into(
    state: &mut ResidentDnsRuntimeCacheState,
    now_unix: i64,
    key: &ResidentDnsResponseCacheKey,
    request: &DnsPacketView<'_>,
    ignore_fixed_ttl: bool,
    out: &mut Vec<u8>,
) -> Result<bool, String> {
    let (lookup_deadline, cache_expires_at) = {
        let Some(stored) = state.entries.get(key) else {
            return Ok(false);
        };
        (
            stored.entry.lookup_deadline(ignore_fixed_ttl),
            stored.entry.cache_expires_at(),
        )
    };
    if lookup_deadline > now_unix {
        state.stats.hit_total += 1;
        return Ok(state
            .entries
            .get(key)
            .and_then(|stored| stored.entry.fill_packed_response_into(request.id(), out))
            .is_some());
    }
    if cache_expires_at <= now_unix {
        remove_cache_entry(state, key);
        state.stats.expired_removal_total += 1;
        state.stats.remove_callback_total += 1;
    }
    Ok(false)
}

fn evict_entries(state: &mut ResidentDnsRuntimeCacheState, now_unix: i64) {
    remove_expired_entries(state, now_unix);
    while state.entries.len() >= DNS_CACHE_MAX_ENTRIES {
        let Some(deadline) = state.deadlines.pop_first() else {
            break;
        };
        if state
            .entries
            .get(&deadline.key)
            .is_some_and(|stored| stored.deadline == deadline)
        {
            state.entries.remove(&deadline.key);
            state.stats.remove_callback_total += 1;
        }
    }
}

fn sweep_expired_if_due(state: &mut ResidentDnsRuntimeCacheState, now_unix: i64) {
    if now_unix < state.next_sweep_unix {
        return;
    }
    remove_expired_entries(state, now_unix);
    state.next_sweep_unix = now_unix.saturating_add(DNS_RUNTIME_CACHE_SWEEP_INTERVAL_SECS);
}

fn remove_expired_entries(state: &mut ResidentDnsRuntimeCacheState, now_unix: i64) {
    let mut removed = 0_usize;
    while let Some(deadline) = state.deadlines.pop_expired(now_unix) {
        if state
            .entries
            .get(&deadline.key)
            .is_some_and(|stored| stored.deadline == deadline)
        {
            state.entries.remove(&deadline.key);
            removed += 1;
        }
    }
    state.stats.expired_removal_total += removed as u64;
    state.stats.remove_callback_total += removed as u64;
}

fn insert_cache_entry(
    state: &mut ResidentDnsRuntimeCacheState,
    key: ResidentDnsResponseCacheKey,
    entry: DnsCacheEntry,
) {
    if let Some(previous) = state.entries.remove(&key) {
        state.deadlines.remove(&previous.deadline);
    }
    let deadline = state
        .deadlines
        .insert(key.clone(), entry.cache_expires_at());
    state
        .entries
        .insert(key, ResidentDnsStoredCacheEntry { entry, deadline });
}

fn remove_cache_entry(
    state: &mut ResidentDnsRuntimeCacheState,
    key: &ResidentDnsResponseCacheKey,
) -> Option<DnsCacheEntry> {
    let stored = state.entries.remove(key)?;
    state.deadlines.remove(&stored.deadline);
    Some(stored.entry)
}

impl Drop for ResidentDnsInflightGuard<'_> {
    fn drop(&mut self) {
        if Arc::strong_count(&self.lock) != 3 {
            return;
        }
        if let Ok(mut inflight) = self.cache.inflight.lock()
            && inflight
                .get(&self.key)
                .is_some_and(|current| Arc::ptr_eq(current, &self.lock))
        {
            inflight.remove(&self.key);
        }
    }
}

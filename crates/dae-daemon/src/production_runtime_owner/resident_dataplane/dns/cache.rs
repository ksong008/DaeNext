use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use dae_dns::{DnsCacheEntry, DnsCacheKey, DnsCacheStore, DnsPacketView};
use tokio::sync::OwnedMutexGuard;

use super::unix_now;

const DNS_RUNTIME_CACHE_SWEEP_INTERVAL_SECS: i64 = 60;

#[derive(Debug, Default)]
pub(super) struct ResidentDnsRuntimeCache {
    state: Mutex<ResidentDnsRuntimeCacheState>,
    inflight: Mutex<BTreeMap<DnsCacheKey, Arc<tokio::sync::Mutex<()>>>>,
}

#[derive(Debug, Default)]
struct ResidentDnsRuntimeCacheState {
    store: DnsCacheStore,
    next_sweep_unix: i64,
}

pub(super) struct ResidentDnsInflightGuard<'a> {
    cache: &'a ResidentDnsRuntimeCache,
    key: DnsCacheKey,
    lock: Arc<tokio::sync::Mutex<()>>,
    _guard: OwnedMutexGuard<()>,
}

impl ResidentDnsRuntimeCache {
    pub(super) async fn lock_key(
        &self,
        key: DnsCacheKey,
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
        request: &DnsPacketView<'_>,
        ignore_fixed_ttl: bool,
        out: &mut Vec<u8>,
    ) -> Result<bool, String> {
        out.clear();
        let now_unix = unix_now();
        let question = request
            .questions()
            .next()
            .ok_or_else(|| "DNS request has no question".to_owned())?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?;
        let Some(entry) = state
            .store
            .lookup_packet_question(now_unix, &question, ignore_fixed_ttl)
            .map_err(|err| format!("lookup resident DNS response cache: {err}"))?
        else {
            return Ok(false);
        };
        Ok(entry.fill_packed_response_into(request.id(), out).is_some())
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
        Ok(state
            .store
            .lookup(now_unix, key, ignore_fixed_ttl)
            .is_some_and(|entry| entry.has_any_ip))
    }

    pub(super) fn insert_response(
        &self,
        now_unix: i64,
        key: DnsCacheKey,
        entry: DnsCacheEntry,
    ) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?;
        sweep_expired_if_due(&mut state, now_unix);
        state.store.insert(now_unix, key, entry);
        Ok(())
    }

    pub(super) fn remove_request(
        &self,
        request: &DnsPacketView<'_>,
    ) -> Result<Option<DnsCacheEntry>, String> {
        let question = request
            .questions()
            .next()
            .ok_or_else(|| "DNS request has no question".to_owned())?;
        self.state
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?
            .store
            .remove_packet_question(&question)
            .map_err(|err| format!("remove resident DNS response cache entry: {err}"))
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
            .map(|state| state.store.len())
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(super) fn stats(&self) -> dae_dns::DnsCacheStats {
        self.state
            .lock()
            .map(|state| state.store.stats().clone())
            .unwrap_or_default()
    }
}

fn sweep_expired_if_due(state: &mut ResidentDnsRuntimeCacheState, now_unix: i64) {
    if now_unix < state.next_sweep_unix {
        return;
    }
    state.store.sweep(now_unix);
    state.next_sweep_unix = now_unix.saturating_add(DNS_RUNTIME_CACHE_SWEEP_INTERVAL_SECS);
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

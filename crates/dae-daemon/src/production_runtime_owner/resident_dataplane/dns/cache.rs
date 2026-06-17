use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use dae_dns::{DnsCacheEntry, DnsCacheKey, DnsCacheStore, DnsPacketView};
use tokio::sync::OwnedMutexGuard;

use super::unix_now;

#[derive(Debug, Default)]
pub(super) struct ResidentDnsRuntimeCache {
    store: Mutex<DnsCacheStore>,
    inflight: Mutex<BTreeMap<DnsCacheKey, Arc<tokio::sync::Mutex<()>>>>,
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

    pub(super) fn lookup_response(
        &self,
        request: &DnsPacketView<'_>,
        ignore_fixed_ttl: bool,
    ) -> Result<Option<Vec<u8>>, String> {
        let now_unix = unix_now();
        let question = request
            .questions()
            .next()
            .ok_or_else(|| "DNS request has no question".to_owned())?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?;
        let Some(entry) = store
            .lookup_packet_question(now_unix, &question, ignore_fixed_ttl)
            .map_err(|err| format!("lookup resident DNS response cache: {err}"))?
        else {
            return Ok(None);
        };
        Ok(entry.fill_packed_response(request.id()))
    }

    pub(super) fn lookup_key_has_any_ip(
        &self,
        key: &DnsCacheKey,
        ignore_fixed_ttl: bool,
    ) -> Result<bool, String> {
        let now_unix = unix_now();
        let mut store = self
            .store
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?;
        Ok(store
            .lookup(now_unix, key, ignore_fixed_ttl)
            .is_some_and(|entry| entry.has_any_ip))
    }

    pub(super) fn insert_response(
        &self,
        now_unix: i64,
        key: DnsCacheKey,
        entry: DnsCacheEntry,
    ) -> Result<(), String> {
        self.store
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?
            .insert(now_unix, key, entry);
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
        self.store
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?
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

use super::super::*;

impl ResidentDnsForwarderCache {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn quic_forwarder(
        &self,
        upstream: &ResidentDnsUpstream,
        mark: u32,
    ) -> Result<Arc<AsyncMutex<ResidentDnsQuicForwarder>>, String> {
        let key = ResidentDnsForwarderKey {
            scheme: upstream.scheme,
            authority: upstream.target.authority.clone(),
            path: upstream.path.clone(),
            mark,
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS forwarder cache lock poisoned".to_owned())?;
        state.next_tick = state.next_tick.wrapping_add(1);
        let last_used = state.next_tick;
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.last_used = last_used;
            return Ok(Arc::clone(&entry.quic));
        }
        if state.entries.len() >= DNS_FORWARDER_CACHE_MAX_ENTRIES {
            evict_oldest_dns_forwarder(&mut state);
        }
        let forwarder = Arc::new(AsyncMutex::new(ResidentDnsQuicForwarder {
            upstream: upstream.clone(),
            mark,
            endpoint: None,
            connection: None,
        }));
        state.entries.insert(
            key,
            ResidentDnsForwarderEntry {
                last_used,
                quic: Arc::clone(&forwarder),
            },
        );
        Ok(forwarder)
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.entries.len())
            .unwrap_or_default()
    }
}

fn evict_oldest_dns_forwarder(state: &mut ResidentDnsForwarderCacheState) {
    let Some(oldest_key) = state
        .entries
        .iter()
        .min_by_key(|(_, entry)| entry.last_used)
        .map(|(key, _)| key.clone())
    else {
        return;
    };
    state.entries.remove(&oldest_key);
}

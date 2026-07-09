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
            target: None,
            selection: ResidentDnsForwarderSelectionKey::Unrouted,
        };
        let forwarder = Arc::new(AsyncMutex::new(ResidentDnsQuicForwarder {
            upstream: upstream.clone(),
            mark,
            fixed_remote: None,
            endpoint: None,
            connection: None,
            permits: Arc::new(Semaphore::new(DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS)),
            open_lock: Arc::new(AsyncMutex::new(())),
        }));
        self.get_or_insert_quic_forwarder(key, forwarder)
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn quic_forwarder_for_target(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        mark: u32,
        selection: &ResidentDnsUpstreamSelection,
    ) -> Result<Arc<AsyncMutex<ResidentDnsQuicForwarder>>, String> {
        let key = routed_dns_forwarder_key(upstream, target, mark, selection);
        let forwarder = Arc::new(AsyncMutex::new(ResidentDnsQuicForwarder {
            upstream: upstream.clone(),
            mark,
            fixed_remote: Some(target),
            endpoint: None,
            connection: None,
            permits: Arc::new(Semaphore::new(DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS)),
            open_lock: Arc::new(AsyncMutex::new(())),
        }));
        self.get_or_insert_quic_forwarder(key, forwarder)
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn udp_forwarder(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        mark: u32,
        selection: &ResidentDnsUpstreamSelection,
    ) -> Result<Arc<ResidentDnsUdpForwarder>, String> {
        let key = ResidentDnsForwarderKey {
            scheme: upstream.scheme,
            authority: upstream.target.authority.clone(),
            path: upstream.path.clone(),
            mark,
            target: Some(target),
            selection: ResidentDnsForwarderSelectionKey::from_selection(selection),
        };
        let shard_count = super::udp_multiplex::dns_udp_forwarder_shard_count();
        let forwarder = Arc::new(ResidentDnsUdpForwarder {
            target,
            mark,
            next_shard: std::sync::atomic::AtomicUsize::new(0),
            shards: (0..shard_count)
                .map(|_| ResidentDnsUdpForwarderShard {
                    handle: AsyncMutex::new(None),
                })
                .collect(),
        });
        self.get_or_insert_udp_forwarder(key, forwarder)
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn proxy_udp_forwarder(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        proxy: Arc<ResidentProxyPlan>,
        selection: &ResidentDnsUpstreamSelection,
    ) -> Result<Arc<ResidentProxyDnsUdpForwarder>, String> {
        let key = routed_dns_forwarder_key(upstream, target, proxy.mark, selection);
        let forwarder = Arc::new(ResidentProxyDnsUdpForwarder::new(proxy, target));
        self.get_or_insert_proxy_udp_forwarder(key, forwarder)
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn tcp_forwarder(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        mark: u32,
        selection: &ResidentDnsUpstreamSelection,
    ) -> Result<Arc<ResidentDnsTcpForwarder>, String> {
        let key = routed_dns_forwarder_key(upstream, target, mark, selection);
        let forwarder = Arc::new(ResidentDnsTcpForwarder {
            upstream: upstream.clone(),
            target,
            mark,
            idle: AsyncMutex::new(Vec::new()),
            permits: Semaphore::new(DNS_STREAM_POOL_MAX_STREAMS),
        });
        self.get_or_insert_tcp_forwarder(key, forwarder)
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn tls_forwarder(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        mark: u32,
        selection: &ResidentDnsUpstreamSelection,
    ) -> Result<Arc<ResidentDnsTlsForwarder>, String> {
        let key = routed_dns_forwarder_key(upstream, target, mark, selection);
        let forwarder = Arc::new(ResidentDnsTlsForwarder {
            upstream: upstream.clone(),
            target,
            mark,
            idle: AsyncMutex::new(Vec::new()),
            permits: Semaphore::new(DNS_STREAM_POOL_MAX_STREAMS),
        });
        self.get_or_insert_tls_forwarder(key, forwarder)
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn https_forwarder(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        mark: u32,
        selection: &ResidentDnsUpstreamSelection,
    ) -> Result<Arc<ResidentDnsHttpsForwarder>, String> {
        let key = routed_dns_forwarder_key(upstream, target, mark, selection);
        let forwarder = Arc::new(ResidentDnsHttpsForwarder {
            upstream: upstream.clone(),
            target,
            mark,
            http1_idle: AsyncMutex::new(Vec::new()),
            http1_permits: Semaphore::new(DNS_STREAM_POOL_MAX_STREAMS),
            h2_permits: Semaphore::new(DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS),
            h2: AsyncMutex::new(None),
            h2_open_lock: AsyncMutex::new(()),
            h2_disabled: std::sync::atomic::AtomicBool::new(false),
        });
        self.get_or_insert_https_forwarder(key, forwarder)
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn h3_forwarder(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        mark: u32,
        selection: &ResidentDnsUpstreamSelection,
    ) -> Result<Arc<AsyncMutex<ResidentDnsH3Forwarder>>, String> {
        let key = routed_dns_forwarder_key(upstream, target, mark, selection);
        let forwarder = Arc::new(AsyncMutex::new(ResidentDnsH3Forwarder {
            upstream: upstream.clone(),
            target,
            mark,
            endpoint: None,
            connection: None,
            client: None,
            driver_task: None,
            permits: Arc::new(Semaphore::new(DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS)),
            open_lock: Arc::new(AsyncMutex::new(())),
        }));
        self.get_or_insert_h3_forwarder(key, forwarder)
    }

    fn get_or_insert_quic_forwarder(
        &self,
        key: ResidentDnsForwarderKey,
        forwarder: Arc<AsyncMutex<ResidentDnsQuicForwarder>>,
    ) -> Result<Arc<AsyncMutex<ResidentDnsQuicForwarder>>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS forwarder cache lock poisoned".to_owned())?;
        state.next_tick = state.next_tick.wrapping_add(1);
        let last_used = state.next_tick;
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.last_used = last_used;
            return match &entry.kind {
                ResidentDnsForwarderEntryKind::Quic(forwarder) => Ok(Arc::clone(forwarder)),
                _ => Err("resident DNS forwarder cache kind mismatch for QUIC".to_owned()),
            };
        }
        if state.entries.len() >= DNS_FORWARDER_CACHE_MAX_ENTRIES {
            evict_oldest_dns_forwarder(&mut state);
        }
        state.entries.insert(
            key,
            ResidentDnsForwarderEntry {
                last_used,
                kind: ResidentDnsForwarderEntryKind::Quic(Arc::clone(&forwarder)),
            },
        );
        Ok(forwarder)
    }

    fn get_or_insert_udp_forwarder(
        &self,
        key: ResidentDnsForwarderKey,
        forwarder: Arc<ResidentDnsUdpForwarder>,
    ) -> Result<Arc<ResidentDnsUdpForwarder>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS forwarder cache lock poisoned".to_owned())?;
        state.next_tick = state.next_tick.wrapping_add(1);
        let last_used = state.next_tick;
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.last_used = last_used;
            return match &entry.kind {
                ResidentDnsForwarderEntryKind::Udp(forwarder) => Ok(Arc::clone(forwarder)),
                _ => Err("resident DNS forwarder cache kind mismatch for UDP".to_owned()),
            };
        }
        if state.entries.len() >= DNS_FORWARDER_CACHE_MAX_ENTRIES {
            evict_oldest_dns_forwarder(&mut state);
        }
        state.entries.insert(
            key,
            ResidentDnsForwarderEntry {
                last_used,
                kind: ResidentDnsForwarderEntryKind::Udp(Arc::clone(&forwarder)),
            },
        );
        Ok(forwarder)
    }

    fn get_or_insert_proxy_udp_forwarder(
        &self,
        key: ResidentDnsForwarderKey,
        forwarder: Arc<ResidentProxyDnsUdpForwarder>,
    ) -> Result<Arc<ResidentProxyDnsUdpForwarder>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS forwarder cache lock poisoned".to_owned())?;
        state.next_tick = state.next_tick.wrapping_add(1);
        let last_used = state.next_tick;
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.last_used = last_used;
            return match &entry.kind {
                ResidentDnsForwarderEntryKind::ProxyUdp(forwarder) => Ok(Arc::clone(forwarder)),
                _ => Err("resident DNS forwarder cache kind mismatch for proxied UDP".to_owned()),
            };
        }
        if state.entries.len() >= DNS_FORWARDER_CACHE_MAX_ENTRIES {
            evict_oldest_dns_forwarder(&mut state);
        }
        state.entries.insert(
            key,
            ResidentDnsForwarderEntry {
                last_used,
                kind: ResidentDnsForwarderEntryKind::ProxyUdp(Arc::clone(&forwarder)),
            },
        );
        Ok(forwarder)
    }

    fn get_or_insert_tcp_forwarder(
        &self,
        key: ResidentDnsForwarderKey,
        forwarder: Arc<ResidentDnsTcpForwarder>,
    ) -> Result<Arc<ResidentDnsTcpForwarder>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS forwarder cache lock poisoned".to_owned())?;
        state.next_tick = state.next_tick.wrapping_add(1);
        let last_used = state.next_tick;
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.last_used = last_used;
            return match &entry.kind {
                ResidentDnsForwarderEntryKind::Tcp(forwarder) => Ok(Arc::clone(forwarder)),
                _ => Err("resident DNS forwarder cache kind mismatch for TCP".to_owned()),
            };
        }
        if state.entries.len() >= DNS_FORWARDER_CACHE_MAX_ENTRIES {
            evict_oldest_dns_forwarder(&mut state);
        }
        state.entries.insert(
            key,
            ResidentDnsForwarderEntry {
                last_used,
                kind: ResidentDnsForwarderEntryKind::Tcp(Arc::clone(&forwarder)),
            },
        );
        Ok(forwarder)
    }

    fn get_or_insert_tls_forwarder(
        &self,
        key: ResidentDnsForwarderKey,
        forwarder: Arc<ResidentDnsTlsForwarder>,
    ) -> Result<Arc<ResidentDnsTlsForwarder>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS forwarder cache lock poisoned".to_owned())?;
        state.next_tick = state.next_tick.wrapping_add(1);
        let last_used = state.next_tick;
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.last_used = last_used;
            return match &entry.kind {
                ResidentDnsForwarderEntryKind::Tls(forwarder) => Ok(Arc::clone(forwarder)),
                _ => Err("resident DNS forwarder cache kind mismatch for TLS".to_owned()),
            };
        }
        if state.entries.len() >= DNS_FORWARDER_CACHE_MAX_ENTRIES {
            evict_oldest_dns_forwarder(&mut state);
        }
        state.entries.insert(
            key,
            ResidentDnsForwarderEntry {
                last_used,
                kind: ResidentDnsForwarderEntryKind::Tls(Arc::clone(&forwarder)),
            },
        );
        Ok(forwarder)
    }

    fn get_or_insert_https_forwarder(
        &self,
        key: ResidentDnsForwarderKey,
        forwarder: Arc<ResidentDnsHttpsForwarder>,
    ) -> Result<Arc<ResidentDnsHttpsForwarder>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS forwarder cache lock poisoned".to_owned())?;
        state.next_tick = state.next_tick.wrapping_add(1);
        let last_used = state.next_tick;
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.last_used = last_used;
            return match &entry.kind {
                ResidentDnsForwarderEntryKind::Https(forwarder) => Ok(Arc::clone(forwarder)),
                _ => Err("resident DNS forwarder cache kind mismatch for HTTPS".to_owned()),
            };
        }
        if state.entries.len() >= DNS_FORWARDER_CACHE_MAX_ENTRIES {
            evict_oldest_dns_forwarder(&mut state);
        }
        state.entries.insert(
            key,
            ResidentDnsForwarderEntry {
                last_used,
                kind: ResidentDnsForwarderEntryKind::Https(Arc::clone(&forwarder)),
            },
        );
        Ok(forwarder)
    }

    fn get_or_insert_h3_forwarder(
        &self,
        key: ResidentDnsForwarderKey,
        forwarder: Arc<AsyncMutex<ResidentDnsH3Forwarder>>,
    ) -> Result<Arc<AsyncMutex<ResidentDnsH3Forwarder>>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS forwarder cache lock poisoned".to_owned())?;
        state.next_tick = state.next_tick.wrapping_add(1);
        let last_used = state.next_tick;
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.last_used = last_used;
            return match &entry.kind {
                ResidentDnsForwarderEntryKind::H3(forwarder) => Ok(Arc::clone(forwarder)),
                _ => Err("resident DNS forwarder cache kind mismatch for H3".to_owned()),
            };
        }
        if state.entries.len() >= DNS_FORWARDER_CACHE_MAX_ENTRIES {
            evict_oldest_dns_forwarder(&mut state);
        }
        state.entries.insert(
            key,
            ResidentDnsForwarderEntry {
                last_used,
                kind: ResidentDnsForwarderEntryKind::H3(Arc::clone(&forwarder)),
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

fn routed_dns_forwarder_key(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    mark: u32,
    selection: &ResidentDnsUpstreamSelection,
) -> ResidentDnsForwarderKey {
    ResidentDnsForwarderKey {
        scheme: upstream.scheme,
        authority: upstream.target.authority.clone(),
        path: upstream.path.clone(),
        mark,
        target: Some(target),
        selection: ResidentDnsForwarderSelectionKey::from_selection(selection),
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

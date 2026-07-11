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
            transport: ResidentDnsForwarderTransport::Quic,
        };
        self.get_or_insert_forwarder_lazy(
            key,
            "QUIC",
            || {
                Arc::new(AsyncMutex::new(ResidentDnsQuicForwarder {
                    upstream: upstream.clone(),
                    mark,
                    fixed_remote: None,
                    endpoint: None,
                    connection: None,
                    permits: Arc::new(Semaphore::new(DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS)),
                    open_lock: Arc::new(AsyncMutex::new(())),
                }))
            },
            |kind| match kind {
                ResidentDnsForwarderEntryKind::Quic(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::Quic,
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn quic_forwarder_for_target(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        mark: u32,
        selection: &ResidentDnsUpstreamSelection,
    ) -> Result<Arc<AsyncMutex<ResidentDnsQuicForwarder>>, String> {
        let key = routed_dns_forwarder_key(
            upstream,
            target,
            mark,
            selection,
            ResidentDnsForwarderTransport::Quic,
        );
        self.get_or_insert_forwarder_lazy(
            key,
            "QUIC",
            || {
                Arc::new(AsyncMutex::new(ResidentDnsQuicForwarder {
                    upstream: upstream.clone(),
                    mark,
                    fixed_remote: Some(target),
                    endpoint: None,
                    connection: None,
                    permits: Arc::new(Semaphore::new(DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS)),
                    open_lock: Arc::new(AsyncMutex::new(())),
                }))
            },
            |kind| match kind {
                ResidentDnsForwarderEntryKind::Quic(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::Quic,
        )
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
            transport: ResidentDnsForwarderTransport::Udp,
        };
        self.get_or_insert_forwarder_lazy(
            key,
            "UDP",
            || {
                let shard_count = super::udp_multiplex::dns_udp_forwarder_shard_count();
                Arc::new(ResidentDnsUdpForwarder {
                    target,
                    mark,
                    next_shard: std::sync::atomic::AtomicUsize::new(0),
                    shards: (0..shard_count)
                        .map(|_| ResidentDnsUdpForwarderShard {
                            handle: AsyncMutex::new(None),
                        })
                        .collect(),
                })
            },
            |kind| match kind {
                ResidentDnsForwarderEntryKind::Udp(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::Udp,
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn proxy_udp_forwarder(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        proxy: Arc<ResidentProxyPlan>,
        selection: &ResidentDnsUpstreamSelection,
    ) -> Result<Arc<ResidentProxyDnsUdpForwarder>, String> {
        let key = routed_dns_forwarder_key(
            upstream,
            target,
            proxy.mark,
            selection,
            ResidentDnsForwarderTransport::ProxyUdp,
        );
        self.get_or_insert_forwarder_lazy(
            key,
            "proxied UDP",
            || Arc::new(ResidentProxyDnsUdpForwarder::new(proxy, target)),
            |kind| match kind {
                ResidentDnsForwarderEntryKind::ProxyUdp(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::ProxyUdp,
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn tcp_forwarder(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        mark: u32,
        selection: &ResidentDnsUpstreamSelection,
    ) -> Result<Arc<ResidentDnsTcpForwarder>, String> {
        let key = routed_dns_forwarder_key(
            upstream,
            target,
            mark,
            selection,
            ResidentDnsForwarderTransport::Tcp,
        );
        self.get_or_insert_forwarder_lazy(
            key,
            "TCP",
            || {
                Arc::new(ResidentDnsTcpForwarder {
                    upstream: upstream.clone(),
                    target,
                    mark,
                    idle: AsyncMutex::new(Vec::new()),
                    permits: Semaphore::new(DNS_STREAM_POOL_MAX_STREAMS),
                })
            },
            |kind| match kind {
                ResidentDnsForwarderEntryKind::Tcp(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::Tcp,
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn tls_forwarder(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        mark: u32,
        selection: &ResidentDnsUpstreamSelection,
    ) -> Result<Arc<ResidentDnsTlsForwarder>, String> {
        let key = routed_dns_forwarder_key(
            upstream,
            target,
            mark,
            selection,
            ResidentDnsForwarderTransport::Tls,
        );
        self.get_or_insert_forwarder_lazy(
            key,
            "TLS",
            || {
                Arc::new(ResidentDnsTlsForwarder {
                    upstream: upstream.clone(),
                    target,
                    mark,
                    idle: AsyncMutex::new(Vec::new()),
                    permits: Semaphore::new(DNS_STREAM_POOL_MAX_STREAMS),
                })
            },
            |kind| match kind {
                ResidentDnsForwarderEntryKind::Tls(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::Tls,
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn https_forwarder(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        mark: u32,
        selection: &ResidentDnsUpstreamSelection,
    ) -> Result<Arc<ResidentDnsHttpsForwarder>, String> {
        let key = routed_dns_forwarder_key(
            upstream,
            target,
            mark,
            selection,
            ResidentDnsForwarderTransport::Https,
        );
        self.get_or_insert_forwarder_lazy(
            key,
            "HTTPS",
            || {
                Arc::new(ResidentDnsHttpsForwarder {
                    upstream: upstream.clone(),
                    target,
                    mark,
                    http1_idle: AsyncMutex::new(Vec::new()),
                    http1_permits: Semaphore::new(DNS_STREAM_POOL_MAX_STREAMS),
                    h2_permits: Semaphore::new(DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS),
                    h2: AsyncMutex::new(None),
                    h2_open_lock: AsyncMutex::new(()),
                    h2_recovery: Mutex::new(ResidentDnsH2Recovery::default()),
                })
            },
            |kind| match kind {
                ResidentDnsForwarderEntryKind::Https(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::Https,
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn h3_forwarder(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        mark: u32,
        selection: &ResidentDnsUpstreamSelection,
    ) -> Result<Arc<AsyncMutex<ResidentDnsH3Forwarder>>, String> {
        let key = routed_dns_forwarder_key(
            upstream,
            target,
            mark,
            selection,
            ResidentDnsForwarderTransport::Http3,
        );
        self.get_or_insert_forwarder_lazy(
            key,
            "H3",
            || {
                Arc::new(AsyncMutex::new(ResidentDnsH3Forwarder {
                    upstream: upstream.clone(),
                    target,
                    mark,
                    endpoint: None,
                    connection: None,
                    client: None,
                    driver_task: None,
                    permits: Arc::new(Semaphore::new(DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS)),
                    open_lock: Arc::new(AsyncMutex::new(())),
                }))
            },
            |kind| match kind {
                ResidentDnsForwarderEntryKind::H3(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::H3,
        )
    }

    fn get_or_insert_forwarder_lazy<T, Build, Extract, Wrap>(
        &self,
        key: ResidentDnsForwarderKey,
        kind_name: &str,
        build: Build,
        extract: Extract,
        wrap: Wrap,
    ) -> Result<Arc<T>, String>
    where
        Build: FnOnce() -> Arc<T>,
        Extract: FnOnce(&ResidentDnsForwarderEntryKind) -> Option<Arc<T>>,
        Wrap: FnOnce(Arc<T>) -> ResidentDnsForwarderEntryKind,
    {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS forwarder cache lock poisoned".to_owned())?;
        if let Some(entry) = state.entries.get(&key) {
            let previous_tick = entry.last_used;
            let forwarder = extract(&entry.kind).ok_or_else(|| {
                format!("resident DNS forwarder cache kind mismatch for {kind_name}")
            })?;
            let last_used = next_dns_forwarder_tick(&mut state);
            state.lru.remove(&(previous_tick, key.clone()));
            if let Some(entry) = state.entries.get_mut(&key) {
                entry.last_used = last_used;
            }
            state.lru.insert((last_used, key));
            return Ok(forwarder);
        }
        if state.entries.len() >= DNS_FORWARDER_CACHE_MAX_ENTRIES {
            evict_oldest_dns_forwarder(&mut state);
        }
        let last_used = next_dns_forwarder_tick(&mut state);
        let forwarder = build();
        state.entries.insert(
            key.clone(),
            ResidentDnsForwarderEntry {
                last_used,
                kind: wrap(Arc::clone(&forwarder)),
            },
        );
        state.lru.insert((last_used, key));
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
    transport: ResidentDnsForwarderTransport,
) -> ResidentDnsForwarderKey {
    ResidentDnsForwarderKey {
        scheme: upstream.scheme,
        authority: upstream.target.authority.clone(),
        path: upstream.path.clone(),
        mark,
        target: Some(target),
        selection: ResidentDnsForwarderSelectionKey::from_selection(selection),
        transport,
    }
}

fn evict_oldest_dns_forwarder(state: &mut ResidentDnsForwarderCacheState) {
    while let Some((last_used, key)) = state.lru.pop_first() {
        if state
            .entries
            .get(&key)
            .is_some_and(|entry| entry.last_used == last_used)
        {
            state.entries.remove(&key);
            return;
        }
    }
}

fn next_dns_forwarder_tick(state: &mut ResidentDnsForwarderCacheState) -> u64 {
    if state.next_tick == u64::MAX {
        let mut ordered = state
            .entries
            .iter()
            .map(|(key, entry)| (entry.last_used, key.clone()))
            .collect::<Vec<_>>();
        ordered.sort();
        state.lru.clear();
        for (index, (_, key)) in ordered.into_iter().enumerate() {
            let tick = (index as u64).saturating_add(1);
            if let Some(entry) = state.entries.get_mut(&key) {
                entry.last_used = tick;
            }
            state.lru.insert((tick, key));
        }
        state.next_tick = state.entries.len() as u64;
    }
    state.next_tick = state.next_tick.saturating_add(1);
    state.next_tick
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn tcp_udp_upstream_caches_udp_and_tcp_forwarders_separately() {
        let cache = ResidentDnsForwarderCache::default();
        let upstream = parse_dns_upstream(
            0,
            "mixed",
            "tcp+udp://127.0.0.1:53",
            "127.0.0.1:53".parse().unwrap(),
            0,
        )
        .unwrap();
        let target = "127.0.0.1:53".parse().unwrap();
        let selection = ResidentDnsUpstreamSelection::Direct { mark: 0 };

        cache
            .udp_forwarder(&upstream, target, 0, &selection)
            .unwrap();
        cache
            .tcp_forwarder(&upstream, target, 0, &selection)
            .unwrap();
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn cache_hit_does_not_construct_a_discarded_forwarder() {
        let cache = ResidentDnsForwarderCache::default();
        let upstream = parse_dns_upstream(
            0,
            "lazy",
            "tcp://127.0.0.1:53",
            "127.0.0.1:53".parse().unwrap(),
            0,
        )
        .unwrap();
        let target = "127.0.0.1:53".parse().unwrap();
        let selection = ResidentDnsUpstreamSelection::Direct { mark: 0 };
        let key = routed_dns_forwarder_key(
            &upstream,
            target,
            0,
            &selection,
            ResidentDnsForwarderTransport::Tcp,
        );
        let builds = Cell::new(0_usize);
        let build = || {
            builds.set(builds.get() + 1);
            Arc::new(ResidentDnsTcpForwarder {
                upstream: upstream.clone(),
                target,
                mark: 0,
                idle: AsyncMutex::new(Vec::new()),
                permits: Semaphore::new(DNS_STREAM_POOL_MAX_STREAMS),
            })
        };
        let extract = |kind: &ResidentDnsForwarderEntryKind| match kind {
            ResidentDnsForwarderEntryKind::Tcp(forwarder) => Some(Arc::clone(forwarder)),
            _ => None,
        };

        let first = cache
            .get_or_insert_forwarder_lazy(
                key.clone(),
                "TCP",
                build,
                extract,
                ResidentDnsForwarderEntryKind::Tcp,
            )
            .unwrap();
        let second = cache
            .get_or_insert_forwarder_lazy(
                key,
                "TCP",
                build,
                extract,
                ResidentDnsForwarderEntryKind::Tcp,
            )
            .unwrap();

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(builds.get(), 1);
    }
}

use super::super::*;
use dae_resident_plan::resident_udp_chain_admission;
use serde_json::{Value, json};

#[cfg(test)]
mod lifecycle_benchmarks;

impl ResidentDnsForwarderCache {
    pub(in crate::dns) async fn shutdown(&self, deadline: time::Instant) -> Value {
        if self.closing.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return json!({
                "status": "pass",
                "generation": self.udp_runtime.generation,
                "alreadyClosed": true,
            });
        }
        let (entries, retired, health_entries, health_retired) = {
            let Ok(mut state) = self.state.lock() else {
                return json!({
                    "status": "fail",
                    "generation": self.udp_runtime.generation,
                    "error": "resident DNS forwarder cache lock poisoned",
                });
            };
            let Ok(mut health_state) = self.health_state.lock() else {
                return json!({
                    "status": "fail",
                    "generation": self.udp_runtime.generation,
                    "error": "resident DNS health forwarder cache lock poisoned",
                });
            };
            state.lru.clear();
            health_state.lru.clear();
            (
                std::mem::take(&mut state.entries),
                std::mem::take(&mut state.retired),
                std::mem::take(&mut health_state.entries),
                std::mem::take(&mut health_state.retired),
            )
        };
        let entry_count = entries.len();
        let health_entry_count = health_entries.len();
        for entry in health_entries.values() {
            self.metrics.proxy_dns_health_forwarder_closed();
            if let Some(close) = entry.health_close.as_ref() {
                close.finish(false);
            }
        }
        let mut forwarders = Vec::with_capacity(
            entry_count
                .saturating_add(retired.len())
                .saturating_add(health_entry_count)
                .saturating_add(health_retired.len()),
        );
        for entry in entries.into_values() {
            forwarders.push((entry.kind, entry.owner_observation, false));
        }
        for entry in health_entries.into_values() {
            forwarders.push((entry.kind, entry.owner_observation, false));
        }
        for retired in retired {
            if let Some((kind, owner_observation)) = retired.upgrade() {
                forwarders.push((kind, owner_observation, true));
            }
        }
        for retired in health_retired {
            if let Some((kind, owner_observation)) = retired.upgrade() {
                forwarders.push((kind, owner_observation, true));
            }
        }
        let retired_count = forwarders.iter().filter(|(_, _, retired)| *retired).count();
        let mut forwarder_reports = Vec::with_capacity(forwarders.len());
        let mut releasable_owners = Vec::with_capacity(forwarders.len());
        for (kind, owner_observation, retired) in forwarders {
            let uses_shared_udp_executor = matches!(kind, ResidentDnsForwarderEntryKind::Udp(_));
            let mut report = shutdown_dns_forwarder_entry(kind, deadline).await;
            if let Some(report) = report.as_object_mut() {
                report.insert("retired".to_owned(), Value::Bool(retired));
            }
            if report["status"].as_str() == Some("pass")
                && let Some(owner_observation) = owner_observation
            {
                releasable_owners.push((owner_observation, uses_shared_udp_executor));
            }
            forwarder_reports.push(report);
        }
        let direct_report = self.udp_executor.shutdown(deadline).await;
        let direct_udp_closed = direct_report["status"].as_str() == Some("pass");
        for (owner, uses_shared_udp_executor) in releasable_owners {
            if !uses_shared_udp_executor || direct_udp_closed {
                owner.release();
            }
        }
        let failed = forwarder_reports
            .iter()
            .filter(|report| report["status"].as_str() != Some("pass"))
            .count();
        json!({
            "status": if failed == 0 && direct_report["status"].as_str() == Some("pass") {
                "pass"
            } else {
                "fail"
            },
            "generation": self.udp_runtime.generation,
            "entriesClosed": entry_count,
            "healthEntriesClosed": health_entry_count,
            "retiredOwnersClosed": retired_count,
            "forwardersFailed": failed,
            "forwarders": forwarder_reports,
            "directUdpActors": direct_report,
        })
    }

    #[cfg(test)]
    pub(in crate::dns) fn quic_forwarder(
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
                Ok(Arc::new(AsyncMutex::new(ResidentDnsQuicForwarder {
                    owner_observation: ResidentDnsTransportOwnerObservation::new(
                        Arc::clone(&self.metrics),
                        std::mem::size_of::<ResidentDnsQuicForwarder>(),
                    ),
                    task_executor: Arc::clone(&self.udp_executor),
                    upstream: upstream.clone(),
                    generation: self.udp_runtime.generation,
                    mark,
                    fixed_remote: None,
                    quic_endpoint_transport: Arc::clone(&self.quic_endpoint_transport),
                    endpoint: None,
                    connection: None,
                    session_cache: dae_outbound::shared_transport::boring_quic::new_boring_quic_session_cache(),
                    permits: Arc::new(Semaphore::new(DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS)),
                    open_lock: Arc::new(AsyncMutex::new(())),
                    closing: false,
                })))
            },
            |kind| match kind {
                ResidentDnsForwarderEntryKind::Quic(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::Quic,
        )
    }

    pub(in crate::dns) fn quic_forwarder_for_target(
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
                Ok(Arc::new(AsyncMutex::new(ResidentDnsQuicForwarder {
                    owner_observation: ResidentDnsTransportOwnerObservation::new(
                        Arc::clone(&self.metrics),
                        std::mem::size_of::<ResidentDnsQuicForwarder>(),
                    ),
                    task_executor: Arc::clone(&self.udp_executor),
                    upstream: upstream.clone(),
                    generation: self.udp_runtime.generation,
                    mark,
                    fixed_remote: Some(target),
                    quic_endpoint_transport: Arc::clone(&self.quic_endpoint_transport),
                    endpoint: None,
                    connection: None,
                    session_cache: dae_outbound::shared_transport::boring_quic::new_boring_quic_session_cache(),
                    permits: Arc::new(Semaphore::new(DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS)),
                    open_lock: Arc::new(AsyncMutex::new(())),
                    closing: false,
                })))
            },
            |kind| match kind {
                ResidentDnsForwarderEntryKind::Quic(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::Quic,
        )
    }

    pub(in crate::dns) fn proxy_quic_forwarder(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        binding: ResidentProxyBinding,
        selection: &ResidentDnsUpstreamSelection,
    ) -> Result<Arc<AsyncMutex<ResidentDnsProxyQuicForwarder>>, String> {
        let key = routed_dns_forwarder_key(
            upstream,
            target,
            binding.effective_socket_mark(),
            selection,
            ResidentDnsForwarderTransport::ProxyQuic,
        );
        self.get_or_insert_forwarder_lazy(
            key,
            "proxied QUIC",
            || {
                Ok(Arc::new(AsyncMutex::new(ResidentDnsProxyQuicForwarder {
                    owner_observation: ResidentDnsTransportOwnerObservation::new(
                        Arc::clone(&self.metrics),
                        std::mem::size_of::<ResidentDnsProxyQuicForwarder>(),
                    ),
                    task_executor: Arc::clone(&self.udp_executor),
                    upstream: upstream.clone(),
                    remote: target,
                    binding,
                    proxy_udp_transport: Arc::clone(&self.proxy_udp_transport),
                    quic_endpoint_transport: Arc::clone(&self.quic_endpoint_transport),
                    bridge: None,
                    endpoint: None,
                    connection: None,
                    session_cache: dae_outbound::shared_transport::boring_quic::new_boring_quic_session_cache(),
                    permits: Arc::new(Semaphore::new(DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS)),
                    open_lock: Arc::new(AsyncMutex::new(())),
                    closing: false,
                    #[cfg(test)]
                    client_config_override: None,
                })))
            },
            |kind| match kind {
                ResidentDnsForwarderEntryKind::ProxyQuic(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::ProxyQuic,
        )
    }

    pub(in crate::dns) fn proxy_h3_forwarder(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        binding: ResidentProxyBinding,
        selection: &ResidentDnsUpstreamSelection,
    ) -> Result<Arc<AsyncMutex<ResidentDnsProxyH3Forwarder>>, String> {
        let key = routed_dns_forwarder_key(
            upstream,
            target,
            binding.effective_socket_mark(),
            selection,
            ResidentDnsForwarderTransport::ProxyHttp3,
        );
        self.get_or_insert_forwarder_lazy(
            key,
            "proxied H3",
            || {
                Ok(Arc::new(AsyncMutex::new(ResidentDnsProxyH3Forwarder {
                    owner_observation: ResidentDnsTransportOwnerObservation::new(
                        Arc::clone(&self.metrics),
                        std::mem::size_of::<ResidentDnsProxyH3Forwarder>(),
                    ),
                    task_executor: Arc::clone(&self.udp_executor),
                    upstream: upstream.clone(),
                    remote: target,
                    binding,
                    proxy_udp_transport: Arc::clone(&self.proxy_udp_transport),
                    quic_endpoint_transport: Arc::clone(&self.quic_endpoint_transport),
                    metrics: Arc::clone(&self.metrics),
                    bridge: None,
                    endpoint: None,
                    connection: None,
                    session_cache: dae_outbound::shared_transport::boring_quic::new_boring_quic_session_cache(),
                    client: None,
                    driver_task: None,
                    permits: Arc::new(Semaphore::new(DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS)),
                    open_lock: Arc::new(AsyncMutex::new(())),
                    closing: false,
                    #[cfg(test)]
                    client_config_override: None,
                })))
            },
            |kind| match kind {
                ResidentDnsForwarderEntryKind::ProxyH3(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::ProxyH3,
        )
    }

    pub(in crate::dns) fn udp_forwarder(
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
            || Ok(self.build_udp_forwarder(target, mark)),
            |kind| match kind {
                ResidentDnsForwarderEntryKind::Udp(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::Udp,
        )
    }

    pub(in crate::dns) fn asis_udp_forwarder(
        &self,
        target: SocketAddr,
        mark: u32,
    ) -> Result<Arc<ResidentDnsUdpForwarder>, String> {
        let key = ResidentDnsForwarderKey {
            scheme: ResidentDnsUpstreamScheme::Udp,
            authority: empty_dns_forwarder_key_component(),
            path: empty_dns_forwarder_key_component(),
            mark,
            target: Some(target),
            selection: ResidentDnsForwarderSelectionKey::Direct,
            transport: ResidentDnsForwarderTransport::AsisUdp,
        };
        self.get_or_insert_forwarder_lazy(
            key,
            "asis UDP",
            || Ok(self.build_udp_forwarder(target, mark)),
            |kind| match kind {
                ResidentDnsForwarderEntryKind::Udp(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::Udp,
        )
    }

    fn build_udp_forwarder(&self, target: SocketAddr, mark: u32) -> Arc<ResidentDnsUdpForwarder> {
        let shard_count = self.udp_runtime.direct_shards.max(1);
        Arc::new(ResidentDnsUdpForwarder {
            owner_observation: ResidentDnsTransportOwnerObservation::new(
                Arc::clone(&self.metrics),
                std::mem::size_of::<ResidentDnsUdpForwarder>().saturating_add(
                    shard_count.saturating_mul(std::mem::size_of::<ResidentDnsUdpForwarderShard>()),
                ),
            ),
            target,
            mark,
            next_shard: std::sync::atomic::AtomicUsize::new(0),
            executor: Arc::clone(&self.udp_executor),
            shards: (0..shard_count)
                .map(|_| ResidentDnsUdpForwarderShard {
                    handle: AsyncMutex::new(None),
                    opened: std::sync::atomic::AtomicBool::new(false),
                    inflight: std::sync::atomic::AtomicUsize::new(0),
                })
                .collect(),
            runtime_config: self.udp_runtime.clone(),
        })
    }

    pub(in crate::dns) fn proxy_udp_forwarder(
        &self,
        upstream: &ResidentDnsUpstream,
        target: SocketAddr,
        binding: ResidentProxyBinding,
        selection: &ResidentDnsUpstreamSelection,
    ) -> Result<Arc<dyn ResidentDnsProxyUdpForwarder>, String> {
        binding
            .execution()
            .udp
            .agreement()
            .admit_packet_relay("proxy-routed DNS UDP")?;
        if let Some(reason) = resident_udp_chain_admission(binding.plan()).unsupported_reason() {
            return Err(format!(
                "proxy-routed DNS UDP rejected by typed chain agreement: {reason}"
            ));
        }
        let key = routed_dns_forwarder_key(
            upstream,
            target,
            binding.effective_socket_mark(),
            selection,
            ResidentDnsForwarderTransport::ProxyUdp,
        );
        self.get_or_insert_forwarder_lazy(
            key,
            "proxied UDP",
            || self.proxy_udp_transport.open_forwarder(binding, target),
            |kind| match kind {
                ResidentDnsForwarderEntryKind::ProxyUdp(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::ProxyUdp,
        )
    }

    pub(in crate::dns) fn tcp_forwarder(
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
                let connection_kind = match selection {
                    ResidentDnsUpstreamSelection::Direct { .. } => {
                        ResidentDnsTcpConnectionKind::Direct
                    }
                    ResidentDnsUpstreamSelection::Proxy { binding } => {
                        let transport = self.proxy_tcp_transport.clone().ok_or_else(|| {
                            "resident DNS proxy TCP transport is unavailable".to_owned()
                        })?;
                        ResidentDnsTcpConnectionKind::Proxy {
                            binding: binding.clone(),
                            transport,
                        }
                    }
                };
                Ok(Arc::new(ResidentDnsTcpForwarder {
                    owner_observation: ResidentDnsTransportOwnerObservation::new(
                        Arc::clone(&self.metrics),
                        std::mem::size_of::<ResidentDnsTcpForwarder>(),
                    ),
                    upstream: upstream.clone(),
                    target,
                    mark,
                    connection_kind,
                    connection_limit: self.resources.tcp_connections_per_route(),
                    request_limit: self.resources.tcp_requests_per_connection(),
                    connections: AsyncMutex::new(Vec::new()),
                    open_lock: AsyncMutex::new(()),
                    closing: std::sync::atomic::AtomicBool::new(false),
                }))
            },
            |kind| match kind {
                ResidentDnsForwarderEntryKind::Tcp(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::Tcp,
        )
    }

    pub(in crate::dns) fn tls_forwarder(
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
                Ok(Arc::new(ResidentDnsTlsForwarder {
                    owner_observation: ResidentDnsTransportOwnerObservation::new(
                        Arc::clone(&self.metrics),
                        std::mem::size_of::<ResidentDnsTlsForwarder>(),
                    ),
                    upstream: upstream.clone(),
                    target,
                    mark,
                    idle: AsyncMutex::new(Vec::new()),
                    permits: Semaphore::new(DNS_STREAM_POOL_MAX_STREAMS),
                }))
            },
            |kind| match kind {
                ResidentDnsForwarderEntryKind::Tls(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::Tls,
        )
    }

    pub(in crate::dns) fn https_forwarder(
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
                Ok(Arc::new(ResidentDnsHttpsForwarder {
                    owner_observation: ResidentDnsTransportOwnerObservation::new(
                        Arc::clone(&self.metrics),
                        std::mem::size_of::<ResidentDnsHttpsForwarder>(),
                    ),
                    upstream: upstream.clone(),
                    target,
                    mark,
                    http1_idle: AsyncMutex::new(Vec::new()),
                    http1_permits: Semaphore::new(DNS_STREAM_POOL_MAX_STREAMS),
                    h2_permits: Semaphore::new(DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS),
                    h2: AsyncMutex::new(None),
                    h2_open_lock: AsyncMutex::new(()),
                    h2_recovery: Mutex::new(ResidentDnsH2Recovery::default()),
                }))
            },
            |kind| match kind {
                ResidentDnsForwarderEntryKind::Https(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::Https,
        )
    }

    pub(in crate::dns) fn h3_forwarder(
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
                Ok(Arc::new(AsyncMutex::new(ResidentDnsH3Forwarder {
                    owner_observation: ResidentDnsTransportOwnerObservation::new(
                        Arc::clone(&self.metrics),
                        std::mem::size_of::<ResidentDnsH3Forwarder>(),
                    ),
                    task_executor: Arc::clone(&self.udp_executor),
                    upstream: upstream.clone(),
                    generation: self.udp_runtime.generation,
                    target,
                    mark,
                    quic_endpoint_transport: Arc::clone(&self.quic_endpoint_transport),
                    endpoint: None,
                    connection: None,
                    session_cache: dae_outbound::shared_transport::boring_quic::new_boring_quic_session_cache(),
                    client: None,
                    driver_task: None,
                    permits: Arc::new(Semaphore::new(DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS)),
                    open_lock: Arc::new(AsyncMutex::new(())),
                    closing: false,
                })))
            },
            |kind| match kind {
                ResidentDnsForwarderEntryKind::H3(forwarder) => Some(Arc::clone(forwarder)),
                _ => None,
            },
            ResidentDnsForwarderEntryKind::H3,
        )
    }

    fn get_or_insert_forwarder_lazy<T: ?Sized, Build, Extract, Wrap>(
        &self,
        key: ResidentDnsForwarderKey,
        kind_name: &str,
        build: Build,
        extract: Extract,
        wrap: Wrap,
    ) -> Result<Arc<T>, String>
    where
        Build: FnOnce() -> Result<Arc<T>, String>,
        Extract: FnOnce(&ResidentDnsForwarderEntryKind) -> Option<Arc<T>>,
        Wrap: FnOnce(Arc<T>) -> ResidentDnsForwarderEntryKind,
    {
        self.get_or_insert_forwarder_lazy_in(&self.state, key, kind_name, build, extract, wrap)
    }

    fn get_or_insert_forwarder_lazy_in<T: ?Sized, Build, Extract, Wrap>(
        &self,
        cache_state: &Mutex<ResidentDnsForwarderCacheState>,
        key: ResidentDnsForwarderKey,
        kind_name: &str,
        build: Build,
        extract: Extract,
        wrap: Wrap,
    ) -> Result<Arc<T>, String>
    where
        Build: FnOnce() -> Result<Arc<T>, String>,
        Extract: FnOnce(&ResidentDnsForwarderEntryKind) -> Option<Arc<T>>,
        Wrap: FnOnce(Arc<T>) -> ResidentDnsForwarderEntryKind,
    {
        if self.closing.load(std::sync::atomic::Ordering::Acquire) {
            return Err("resident DNS forwarder cache is closing".to_owned());
        }
        // Fast path: existing entry, under the lock. A hit only refreshes the
        // LRU tick and returns the cached forwarder.
        {
            let mut state = cache_state
                .lock()
                .map_err(|_| "resident DNS forwarder cache lock poisoned".to_owned())?;
            if self.closing.load(std::sync::atomic::Ordering::Acquire) {
                return Err("resident DNS forwarder cache is closing".to_owned());
            }
            if let Some(entry) = state.entries.get(&key) {
                let forwarder = extract(&entry.kind).ok_or_else(|| {
                    format!("resident DNS forwarder cache kind mismatch for {kind_name}")
                })?;
                let last_used = next_dns_forwarder_tick(&mut state);
                if let Some(entry) = state.entries.get_mut(&key) {
                    entry.last_used = last_used;
                }
                debug_assert!(state.lru.iter().any(|(_, indexed_key)| indexed_key == &key));
                return Ok(forwarder);
            }
        }
        // Miss: build the forwarder *outside* the lock. `build` may create
        // sockets or spawn actor tasks; holding the process-wide cache lock
        // across it would serialize every DNS query behind the first miss.
        let forwarder = build()?;
        let kind = wrap(Arc::clone(&forwarder));
        // Double-checked insertion: another thread may have inserted the same
        // key while we were building. If so, discard our build (its owner
        // observation releases itself on drop) and return the winner.
        let mut state = cache_state
            .lock()
            .map_err(|_| "resident DNS forwarder cache lock poisoned".to_owned())?;
        if self.closing.load(std::sync::atomic::Ordering::Acquire) {
            return Err("resident DNS forwarder cache is closing".to_owned());
        }
        if let Some(entry) = state.entries.get(&key) {
            let forwarder = extract(&entry.kind).ok_or_else(|| {
                format!("resident DNS forwarder cache kind mismatch for {kind_name}")
            })?;
            let last_used = next_dns_forwarder_tick(&mut state);
            if let Some(entry) = state.entries.get_mut(&key) {
                entry.last_used = last_used;
            }
            debug_assert!(state.lru.iter().any(|(_, indexed_key)| indexed_key == &key));
            return Ok(forwarder);
        }
        if state.entries.len() >= DNS_FORWARDER_CACHE_MAX_ENTRIES {
            evict_oldest_dns_forwarder(&mut state);
        }
        let last_used = next_dns_forwarder_tick(&mut state);
        let owner_observation = kind.owner_observation();
        state.entries.insert(
            key.clone(),
            ResidentDnsForwarderEntry {
                last_used,
                kind,
                owner_observation,
                health_leases: 0,
                health_close: None,
            },
        );
        state.lru.insert((last_used, key));
        Ok(forwarder)
    }

    #[cfg(test)]
    pub(in crate::dns) fn len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.entries.len())
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(in crate::dns) fn health_len(&self) -> usize {
        self.health_state
            .lock()
            .map(|state| state.entries.len())
            .unwrap_or_default()
    }
}

async fn shutdown_dns_forwarder_entry(
    entry: ResidentDnsForwarderEntryKind,
    deadline: time::Instant,
) -> Value {
    match entry {
        ResidentDnsForwarderEntryKind::Quic(forwarder) => {
            super::quic::shutdown_cached_dns_quic(forwarder, deadline).await
        }
        ResidentDnsForwarderEntryKind::ProxyQuic(forwarder) => {
            super::quic::shutdown_cached_proxy_dns_quic(forwarder, deadline).await
        }
        ResidentDnsForwarderEntryKind::ProxyH3(forwarder) => {
            super::h3::shutdown_cached_proxy_dns_h3(forwarder, deadline).await
        }
        ResidentDnsForwarderEntryKind::H3(forwarder) => {
            super::h3::shutdown_cached_dns_h3(forwarder, deadline).await
        }
        ResidentDnsForwarderEntryKind::ProxyUdp(forwarder) => {
            let report = forwarder.shutdown(deadline).await;
            json!({
                "status": report["status"].clone(),
                "transport": "proxied-udp",
                "owner": report,
            })
        }
        ResidentDnsForwarderEntryKind::Udp(_) => json!({
            "status": "pass",
            "transport": "udp",
            "cleanup": "shared actor executor",
        }),
        ResidentDnsForwarderEntryKind::Tcp(forwarder) => {
            shutdown_dns_tcp_forwarder(forwarder, deadline).await
        }
        ResidentDnsForwarderEntryKind::Tls(forwarder) => {
            shutdown_dns_tls_forwarder(forwarder, deadline).await
        }
        ResidentDnsForwarderEntryKind::Https(forwarder) => {
            shutdown_dns_https_forwarder(forwarder, deadline).await
        }
    }
}

async fn shutdown_dns_tcp_forwarder(
    forwarder: Arc<ResidentDnsTcpForwarder>,
    deadline: time::Instant,
) -> Value {
    forwarder
        .closing
        .store(true, std::sync::atomic::Ordering::Release);
    let (connections_locked, mut connections) =
        match time::timeout_at(deadline, forwarder.connections.lock()).await {
            Ok(mut connections) => (true, std::mem::take(&mut *connections)),
            Err(_) => (false, Vec::new()),
        };
    for connection in &connections {
        connection.handle.close();
    }
    let connection_count = connections.len();
    let mut connections_joined = 0_usize;
    for connection in &mut connections {
        if time::timeout_at(deadline, &mut connection.task)
            .await
            .is_ok()
        {
            connections_joined += 1;
        } else {
            connection.task.abort();
            let _ = (&mut connection.task).await;
        }
    }
    json!({
        "status": if connections_locked && connections_joined == connection_count { "pass" } else { "fail" },
        "transport": "tcp",
        "connectionsLocked": connections_locked,
        "connections": connection_count,
        "connectionsJoined": connections_joined,
    })
}

async fn shutdown_dns_tls_forwarder(
    forwarder: Arc<ResidentDnsTlsForwarder>,
    deadline: time::Instant,
) -> Value {
    forwarder.permits.close();
    let idle_cleared = match time::timeout_at(deadline, forwarder.idle.lock()).await {
        Ok(mut idle) => {
            idle.clear();
            true
        }
        Err(_) => false,
    };
    let streams_released =
        wait_for_dns_forwarder_permits(&forwarder.permits, DNS_STREAM_POOL_MAX_STREAMS, deadline)
            .await;
    json!({
        "status": if idle_cleared && streams_released { "pass" } else { "fail" },
        "transport": "tls",
        "idleCleared": idle_cleared,
        "streamsReleased": streams_released,
    })
}

async fn shutdown_dns_https_forwarder(
    forwarder: Arc<ResidentDnsHttpsForwarder>,
    deadline: time::Instant,
) -> Value {
    forwarder.http1_permits.close();
    forwarder.h2_permits.close();
    let http1_idle_cleared = match time::timeout_at(deadline, forwarder.http1_idle.lock()).await {
        Ok(mut idle) => {
            idle.clear();
            true
        }
        Err(_) => false,
    };
    let (h2_lock_acquired, h2) = match time::timeout_at(deadline, forwarder.h2.lock()).await {
        Ok(mut h2) => (true, h2.take()),
        Err(_) => (false, None),
    };
    let mut h2_driver_joined = h2.is_none();
    if let Some(mut h2) = h2 {
        h2.driver_task.abort();
        h2_driver_joined = time::timeout_at(deadline, &mut h2.driver_task)
            .await
            .is_ok();
    }
    let http1_released = wait_for_dns_forwarder_permits(
        &forwarder.http1_permits,
        DNS_STREAM_POOL_MAX_STREAMS,
        deadline,
    )
    .await;
    let h2_released = wait_for_dns_forwarder_permits(
        &forwarder.h2_permits,
        DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS,
        deadline,
    )
    .await;
    json!({
        "status": if http1_idle_cleared
            && h2_lock_acquired
            && h2_driver_joined
            && http1_released
            && h2_released
        {
            "pass"
        } else {
            "fail"
        },
        "transport": "https",
        "http1IdleCleared": http1_idle_cleared,
        "http1StreamsReleased": http1_released,
        "h2StreamsReleased": h2_released,
        "h2LockAcquired": h2_lock_acquired,
        "h2DriverJoined": h2_driver_joined,
    })
}

async fn wait_for_dns_forwarder_permits(
    permits: &Semaphore,
    capacity: usize,
    deadline: time::Instant,
) -> bool {
    while permits.available_permits() < capacity {
        let now = time::Instant::now();
        if now >= deadline {
            return false;
        }
        time::sleep_until((now + std::time::Duration::from_millis(1)).min(deadline)).await;
    }
    true
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

fn empty_dns_forwarder_key_component() -> Arc<str> {
    static EMPTY: std::sync::OnceLock<Arc<str>> = std::sync::OnceLock::new();
    Arc::clone(EMPTY.get_or_init(|| Arc::from("")))
}

/// Retired-forwarder list size at which an eviction prunes dead entries.
///
/// See `evict_oldest_dns_forwarder`: the list only grows on evictions and each
/// scan is amortized over `THRESHOLD` pushes, so eviction cost stays
/// `O(evictions / THRESHOLD * retired)` instead of `O(evictions * retired)`.
const DNS_RETIRED_FORWARDER_RETAIN_THRESHOLD: usize = 32;

fn evict_oldest_dns_forwarder(state: &mut ResidentDnsForwarderCacheState) {
    // The retired list only holds forwarders still referenced by in-flight
    // requests at eviction time, so it is normally tiny. Scanning it on every
    // eviction would make the total cost O(evictions * retired); batching the
    // `retain` until the list crosses a threshold amortizes that cost while
    // still bounding the list (a scan runs at least once per `THRESHOLD`
    // pushes, and dead entries cannot accumulate past that).
    if state.retired.len() >= DNS_RETIRED_FORWARDER_RETAIN_THRESHOLD {
        state.retired.retain(ResidentDnsRetiredForwarder::is_alive);
    }
    while let Some((last_used, key)) = state.lru.pop_first() {
        let Some(current_last_used) = state.entries.get(&key).map(|entry| entry.last_used) else {
            continue;
        };
        if current_last_used != last_used {
            state.lru.insert((current_last_used, key));
            continue;
        }
        {
            if let Some(entry) = state.entries.remove(&key)
                && entry.kind.retained_outside_cache()
            {
                if let Some(owner) = entry.owner_observation.as_ref() {
                    owner.mark_evicted();
                }
                state
                    .retired
                    .push(ResidentDnsRetiredForwarder::from_entry(&entry));
            }
            return;
        }
    }
}

pub(super) fn next_dns_forwarder_tick(state: &mut ResidentDnsForwarderCacheState) -> u64 {
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
    use crate::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    use crate::dns::transport::test_support::{
        Socks5UdpRelay, dns_a_test_response, dns_proxy_binding, socks5_dns_proxy,
    };
    use crate::plan::{ResidentProxyProtocolPlan, ResidentXhttpMode, ResidentXhttpSettingsPlan};
    use std::cell::Cell;

    fn policy_closed_http_proxy() -> Arc<ResidentProxyPlan> {
        let mut proxy = ResidentProxyPlan {
            graph_id: "resident-graph:redacted".to_owned(),
            graph_link_hash: "sha256:redacted".to_owned(),
            redacted_link_source: "source:<redacted>".to_owned(),
            protocol: "http-proxy",
            group_name: "proxy".to_owned(),
            group_policy: "fixed".to_owned(),
            node_tag: "redacted".to_owned(),
            server_host: Ipv4Addr::LOCALHOST.to_string(),
            server_port: 9,
            server_name: String::new(),
            alpn: Vec::new(),
            flow: String::new(),
            net: "tcp".to_owned(),
            stream_host: String::new(),
            stream_path: String::new(),
            grpc_mode: dae_outbound::shared_transport::GrpcMode::Gun,
            xhttp_download: None,
            xhttp_mode: ResidentXhttpMode::PacketUp,
            xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
            xhttp_xmux: None,
            tls: "none".to_owned(),
            allow_insecure: false,
            tls_fragment: None,
            utls_fingerprint: None,
            ech: None,
            reality: None,
            handler: ResidentProxyProtocolPlan::HttpProxyTcp {
                username: String::new(),
                password: String::new(),
                transport: false,
                transport_host: String::new(),
                transport_path: String::new(),
            },
            execution: None,
            chain_parent: None,
            mark: 0,
            mptcp: false,
        };
        proxy.materialize_execution();
        Arc::new(proxy)
    }

    #[test]
    fn tcp_udp_upstream_caches_udp_and_tcp_forwarders_separately() {
        let cache = test_resident_dns_forwarder_cache();
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
    fn asis_udp_forwarder_is_reused_by_target_and_mark() {
        let cache = test_resident_dns_forwarder_cache();
        let target = "127.0.0.1:53".parse().unwrap();

        let first = cache.asis_udp_forwarder(target, 0x1234).unwrap();
        let second = cache.asis_udp_forwarder(target, 0x1234).unwrap();
        let different_mark = cache.asis_udp_forwarder(target, 0x5678).unwrap();

        assert!(Arc::ptr_eq(&first, &second));
        assert!(!Arc::ptr_eq(&first, &different_mark));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn cache_hit_reuses_key_strings_without_rewriting_lru_tree() {
        let cache = test_resident_dns_forwarder_cache();
        let upstream = parse_dns_upstream(
            0,
            "shared-key",
            "udp://127.0.0.1:53",
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
            .udp_forwarder(&upstream, target, 0, &selection)
            .unwrap();
        cache
            .udp_forwarder(&upstream, target, 0, &selection)
            .unwrap();
        cache
            .udp_forwarder(&upstream, target, 0, &selection)
            .unwrap();

        let state = cache.state.lock().unwrap();
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.lru.len(), 1);
        let (indexed_tick, indexed_key) = state.lru.first().unwrap();
        let entry = state.entries.get(indexed_key).unwrap();
        assert!(entry.last_used > *indexed_tick);
        assert!(Arc::ptr_eq(
            &indexed_key.authority,
            &upstream.target.authority
        ));
        assert!(Arc::ptr_eq(&indexed_key.path, &upstream.path));
    }

    #[test]
    fn policy_closed_proxy_dns_udp_is_rejected_before_cache_or_actor_creation() {
        let cache = test_resident_dns_forwarder_cache();
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DNS_DEFAULT_PORT);
        let upstream =
            parse_dns_upstream(0, "closed", &format!("udp://{target}"), target, 0).unwrap();
        let proxy = policy_closed_http_proxy();
        let binding = dns_proxy_binding(Arc::clone(&proxy), 0);
        let selection = ResidentDnsUpstreamSelection::Proxy {
            binding: binding.clone(),
        };

        let err = cache
            .proxy_udp_forwarder(&upstream, target, binding, &selection)
            .err()
            .expect("policy-closed DNS UDP must be rejected");

        assert!(err.contains("typed UDP agreement"), "{err}");
        assert!(err.contains("http-connect-udp-protocol-closed"), "{err}");
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.metrics.snapshot()["dnsUdpActorsOpened"], 0);
    }

    #[test]
    fn cache_hit_does_not_construct_a_discarded_forwarder() {
        let cache = test_resident_dns_forwarder_cache();
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
            Ok(Arc::new(ResidentDnsTcpForwarder {
                owner_observation: ResidentDnsTransportOwnerObservation::new(
                    Arc::clone(&cache.metrics),
                    std::mem::size_of::<ResidentDnsTcpForwarder>(),
                ),
                upstream: upstream.clone(),
                target,
                mark: 0,
                connection_kind: ResidentDnsTcpConnectionKind::Direct,
                connection_limit: cache.resources.tcp_connections_per_route(),
                request_limit: cache.resources.tcp_requests_per_connection(),
                connections: AsyncMutex::new(Vec::new()),
                open_lock: AsyncMutex::new(()),
                closing: std::sync::atomic::AtomicBool::new(false),
            }))
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

    #[test]
    fn concurrent_misses_share_one_inserted_forwarder() {
        let cache = Arc::new(test_resident_dns_forwarder_cache());
        let upstream = parse_dns_upstream(
            0,
            "concurrent",
            "udp://127.0.0.1:53",
            "127.0.0.1:53".parse().unwrap(),
            0,
        )
        .unwrap();
        let target = "127.0.0.1:53".parse().unwrap();
        let selection = ResidentDnsUpstreamSelection::Direct { mark: 0 };

        // All workers miss at the same time (barrier) so several of them build
        // outside the lock; the double-checked insertion must still end up with
        // exactly one entry and every caller must receive the same forwarder.
        const WORKERS: usize = 8;
        let barrier = Arc::new(std::sync::Barrier::new(WORKERS));
        let handles = (0..WORKERS)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let upstream = upstream.clone();
                let selection = selection.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    cache
                        .udp_forwarder(&upstream, target, 0, &selection)
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        let forwarders = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();

        assert!(
            forwarders
                .iter()
                .all(|forwarder| Arc::ptr_eq(&forwarders[0], forwarder)),
            "all concurrent callers must receive the same forwarder"
        );
        assert_eq!(
            cache.len(),
            1,
            "double-checked insert must win exactly once"
        );
    }

    #[test]
    fn evicted_inflight_quic_owner_remains_charged_until_the_last_arc_drops() {
        let cache = test_resident_dns_forwarder_cache();
        let metrics = Arc::clone(&cache.metrics);
        let quic = parse_dns_upstream(
            0,
            "quic-owner",
            "quic://127.0.0.1:853",
            "127.0.0.1:53".parse().unwrap(),
            0,
        )
        .unwrap();
        let retained = cache.quic_forwarder(&quic, 0).unwrap();
        assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 1);

        let tcp = parse_dns_upstream(
            1,
            "tcp-fill",
            "tcp://127.0.0.1:53",
            "127.0.0.1:53".parse().unwrap(),
            0,
        )
        .unwrap();
        let selection = ResidentDnsUpstreamSelection::Direct { mark: 0 };
        for port in 1..=DNS_FORWARDER_CACHE_MAX_ENTRIES {
            let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port as u16);
            cache.tcp_forwarder(&tcp, target, 0, &selection).unwrap();
        }

        let evicted = cache.metrics.snapshot();
        assert_eq!(cache.len(), DNS_FORWARDER_CACHE_MAX_ENTRIES);
        assert_eq!(
            evicted["dnsTransportOwnersCurrent"],
            DNS_FORWARDER_CACHE_MAX_ENTRIES + 1
        );
        assert_eq!(evicted["dnsTransportOwnersEvictedCurrent"], 1);
        let evicted_bytes = evicted["dnsTransportOwnerBytesCurrent"].as_u64().unwrap();
        assert!(evicted_bytes > 0);
        drop(retained);
        let released = cache.metrics.snapshot();
        assert_eq!(
            released["dnsTransportOwnersCurrent"],
            DNS_FORWARDER_CACHE_MAX_ENTRIES
        );
        assert_eq!(released["dnsTransportOwnersEvictedCurrent"], 0);
        assert!(released["dnsTransportOwnerBytesCurrent"].as_u64().unwrap() < evicted_bytes);
        drop(cache);
        assert_eq!(metrics.snapshot()["dnsTransportOwnersCurrent"], 0);
        assert_eq!(metrics.snapshot()["dnsTransportOwnerBytesCurrent"], 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn proxied_quic_and_h3_forwarders_reuse_separate_complete_keys() {
        let cache = test_resident_dns_forwarder_cache();
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 853);
        let doq = parse_dns_upstream(
            0,
            "proxy-doq",
            "quic://127.0.0.1:853",
            "127.0.0.1:53".parse().unwrap(),
            0,
        )
        .unwrap();
        let doh3 = parse_dns_upstream(
            1,
            "proxy-doh3",
            "h3://127.0.0.1:443/dns-query",
            "127.0.0.1:53".parse().unwrap(),
            0,
        )
        .unwrap();
        let proxy = policy_closed_http_proxy();
        let binding = dns_proxy_binding(Arc::clone(&proxy), 0);
        let selection = ResidentDnsUpstreamSelection::Proxy {
            binding: binding.clone(),
        };

        let first_doq = cache
            .proxy_quic_forwarder(&doq, target, binding.clone(), &selection)
            .unwrap();
        let second_doq = cache
            .proxy_quic_forwarder(&doq, target, binding.clone(), &selection)
            .unwrap();
        let first_doh3 = cache
            .proxy_h3_forwarder(&doh3, target, binding.clone(), &selection)
            .unwrap();
        let second_doh3 = cache
            .proxy_h3_forwarder(&doh3, target, binding, &selection)
            .unwrap();

        assert!(Arc::ptr_eq(&first_doq, &second_doq));
        assert!(Arc::ptr_eq(&first_doh3, &second_doh3));
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 2);
        drop(first_doq);
        drop(second_doq);
        drop(first_doh3);
        drop(second_doh3);
        let report = cache
            .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
            .await;
        assert_eq!(report["status"], "pass");
        assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overlapping_background_dns_health_leases_share_then_retire_forwarder() {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut query = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
            for _ in 0..2 {
                let (read, peer) = upstream.recv_from(&mut query).await.unwrap();
                let response = dns_a_test_response(&query[..read], [192, 0, 2, 80]);
                upstream.send_to(&response, peer).await.unwrap();
            }
        });
        let socks = Socks5UdpRelay::start().await;
        let proxy = socks5_dns_proxy(socks.address());
        let binding = dns_proxy_binding(Arc::clone(&proxy), 7_370);
        let cache = Arc::new(test_resident_dns_forwarder_cache());
        let first = cache
            .acquire_health_proxy_udp_forwarder(target, binding.clone())
            .await
            .unwrap();
        let second = cache
            .acquire_health_proxy_udp_forwarder(target, binding)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&first.forwarder(), &second.forwarder()));
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.health_len(), 1);
        assert_eq!(
            cache.metrics.snapshot()["proxyDnsHealthForwardersCurrent"],
            1
        );
        assert_eq!(cache.metrics.snapshot()["proxyDnsHealthLeasesCurrent"], 2);

        crate::probe_resident_proxy_dns_udp_with_forwarder_async(
            first.forwarder(),
            "health.example",
        )
        .await
        .unwrap();
        crate::probe_resident_proxy_dns_udp_with_forwarder_async(
            second.forwarder(),
            "health.example",
        )
        .await
        .unwrap();
        server.await.unwrap();

        let active = cache.metrics.snapshot();
        assert_eq!(active["dnsTransportOwnersCurrent"], 1);
        assert_eq!(active["proxyDnsUdpExecutorsOpened"], 1);
        assert_eq!(active["proxyDnsUdpExecutorsReused"], 1);
        assert_eq!(socks.control_connections(), 1);
        first.release().await.unwrap();
        assert_eq!(cache.health_len(), 1);
        assert_eq!(cache.metrics.snapshot()["proxyDnsHealthLeasesCurrent"], 1);
        second.release().await.unwrap();
        assert_eq!(cache.health_len(), 0);
        assert_eq!(
            cache.metrics.snapshot()["proxyDnsHealthForwardersCurrent"],
            0
        );
        assert_eq!(cache.metrics.snapshot()["proxyDnsHealthLeasesCurrent"], 0);
        assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 0);
        assert_eq!(cache.metrics.snapshot()["dnsTransportOwnerBytesCurrent"], 0);
        assert_eq!(
            cache.metrics.snapshot()["dnsUdpActorsOpened"],
            cache.metrics.snapshot()["dnsUdpActorsClosed"]
        );
        let report = cache
            .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
            .await;
        assert_eq!(report["status"], "pass", "{report}");
        assert_eq!(report["entriesClosed"], 0);
        assert_eq!(report["healthEntriesClosed"], 0);
        assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 0);
        assert_eq!(cache.metrics.snapshot()["dnsTransportOwnerBytesCurrent"], 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_background_dns_health_releases_its_actor_and_executor() {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let (received_tx, received_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut query = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
            let _ = upstream.recv_from(&mut query).await.unwrap();
            let _ = received_tx.send(());
            std::future::pending::<()>().await;
        });
        let socks = Socks5UdpRelay::start().await;
        let proxy = socks5_dns_proxy(socks.address());
        let binding = dns_proxy_binding(proxy, 7_371);
        let cache = Arc::new(test_resident_dns_forwarder_cache());
        let lease = cache
            .acquire_health_proxy_udp_forwarder(target, binding)
            .await
            .unwrap();
        let probe = tokio::spawn(async move {
            let result = crate::probe_resident_proxy_dns_udp_with_forwarder_async(
                lease.forwarder(),
                "cancelled-health.example",
            )
            .await;
            let _ = lease.release().await;
            result
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), received_rx)
            .await
            .unwrap()
            .unwrap();
        probe.abort();
        let _ = probe.await;

        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let snapshot = cache.metrics.snapshot();
                if cache.health_len() == 0
                    && snapshot["proxyDnsHealthForwardersCurrent"] == 0
                    && snapshot["proxyDnsHealthLeasesCurrent"] == 0
                    && snapshot["dnsTransportOwnersCurrent"] == 0
                    && snapshot["dnsUdpActorsOpened"] == snapshot["dnsUdpActorsClosed"]
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cache_shutdown_closes_direct_udp_actors_and_rejects_new_entries() {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let cache = test_resident_dns_forwarder_cache();
        let handle = cache.udp_executor.open_handle(target, 0).await.unwrap();
        let query = build_dns_query_packet(0x5151, "cache-shutdown.example", DNS_QTYPE_A).unwrap();
        let request_handle = handle.clone();
        let request = tokio::spawn(async move { request_handle.exchange_once(&query).await });
        let mut received = vec![0_u8; 512];
        upstream.recv_from(&mut received).await.unwrap();

        let report = cache
            .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
            .await;
        let request_error = request.await.unwrap().unwrap_err();
        let second = cache
            .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
            .await;
        let upstream_model =
            parse_dns_upstream(0, "closed", &format!("udp://{target}"), target, 0).unwrap();
        let selection = ResidentDnsUpstreamSelection::Direct { mark: 0 };
        let reopen_error = match cache.udp_forwarder(&upstream_model, target, 0, &selection) {
            Ok(_) => panic!("closed DNS forwarder cache accepted a new entry"),
            Err(err) => err,
        };

        assert_eq!(report["status"], "pass");
        assert!(request_error.contains("shutting down"), "{request_error}");
        assert!(handle.is_closed());
        assert_eq!(second["alreadyClosed"], true);
        assert!(reopen_error.contains("closing"), "{reopen_error}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn https_shutdown_does_not_report_an_h2_lock_timeout_as_joined() {
        let cache = test_resident_dns_forwarder_cache();
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let upstream = parse_dns_upstream(
            0,
            "https-lock",
            "https://127.0.0.1:443/dns-query",
            target,
            0,
        )
        .unwrap();
        let selection = ResidentDnsUpstreamSelection::Direct { mark: 0 };
        let forwarder = cache
            .https_forwarder(&upstream, target, 0, &selection)
            .unwrap();
        let h2_guard = forwarder.h2.lock().await;

        let report =
            shutdown_dns_https_forwarder(Arc::clone(&forwarder), time::Instant::now()).await;

        assert_eq!(report["status"], "fail");
        assert_eq!(report["h2LockAcquired"], false);
        assert_eq!(report["h2DriverJoined"], true);
        drop(h2_guard);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cache_shutdown_uses_one_deadline_for_every_forwarder() {
        let cache = test_resident_dns_forwarder_cache();
        let upstream = parse_dns_upstream(
            0,
            "tcp-deadline",
            "tcp://127.0.0.1:53",
            "127.0.0.1:53".parse().unwrap(),
            0,
        )
        .unwrap();
        let selection = ResidentDnsUpstreamSelection::Direct { mark: 0 };
        let first = cache
            .tcp_forwarder(
                &upstream,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
                0,
                &selection,
            )
            .unwrap();
        let second = cache
            .tcp_forwarder(
                &upstream,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 54),
                0,
                &selection,
            )
            .unwrap();
        let first_connections = first.connections.lock().await;
        let second_connections = second.connections.lock().await;
        let started = std::time::Instant::now();

        let report = cache
            .shutdown(time::Instant::now() + std::time::Duration::from_millis(5))
            .await;

        assert_eq!(report["status"], "fail");
        assert_eq!(report["forwardersFailed"], 2);
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        let forwarders = report["forwarders"].as_array().unwrap();
        assert_eq!(forwarders.len(), 2);
        assert!(forwarders.iter().all(|forwarder| {
            forwarder["status"] == "fail" && forwarder["connectionsLocked"] == false
        }));
        drop(second_connections);
        drop(first_connections);
    }
}

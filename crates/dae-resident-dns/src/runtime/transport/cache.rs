use super::super::*;
use dae_resident_plan::resident_udp_chain_admission;
use serde_json::{Value, json};

impl ResidentDnsForwarderCache {
    pub async fn shutdown(&self, deadline: time::Instant) -> Value {
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

    #[cfg(any(test, feature = "test-support"))]
    pub fn quic_forwarder(
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
                    session_cache: dae_outbound_quic::boring_quic::new_boring_quic_session_cache(),
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

    pub fn quic_forwarder_for_target(
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
                    session_cache: dae_outbound_quic::boring_quic::new_boring_quic_session_cache(),
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

    pub fn proxy_quic_forwarder(
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
                    session_cache: dae_outbound_quic::boring_quic::new_boring_quic_session_cache(),
                    permits: Arc::new(Semaphore::new(DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS)),
                    open_lock: Arc::new(AsyncMutex::new(())),
                    closing: false,
                    #[cfg(any(test, feature = "test-support"))]
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

    pub fn proxy_h3_forwarder(
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
                    session_cache: dae_outbound_quic::boring_quic::new_boring_quic_session_cache(),
                    client: None,
                    driver_task: None,
                    permits: Arc::new(Semaphore::new(DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS)),
                    open_lock: Arc::new(AsyncMutex::new(())),
                    closing: false,
                    #[cfg(any(test, feature = "test-support"))]
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

    pub fn udp_forwarder(
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

    pub fn asis_udp_forwarder(
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

    pub fn proxy_udp_forwarder(
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

    pub fn tcp_forwarder(
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

    pub fn tls_forwarder(
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

    pub fn https_forwarder(
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

    pub fn h3_forwarder(
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
                    session_cache: dae_outbound_quic::boring_quic::new_boring_quic_session_cache(),
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

    pub fn get_or_insert_forwarder_lazy<T: ?Sized, Build, Extract, Wrap>(
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

    #[cfg(any(test, feature = "test-support"))]
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.entries.len())
            .unwrap_or_default()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn health_len(&self) -> usize {
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

pub async fn shutdown_dns_https_forwarder(
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

pub fn routed_dns_forwarder_key(
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

/// Scan after this many evictions, even when every retired owner is still live.
const DNS_RETIRED_FORWARDER_RETAIN_THRESHOLD: usize = 32;

fn evict_oldest_dns_forwarder(state: &mut ResidentDnsForwarderCacheState) {
    // A list-length threshold scans on every eviction while the live set is
    // large. Count evictions instead; dead weak references remain bounded by
    // the live-at-last-scan set plus at most THRESHOLD new entries.
    state.retired_scan_pending = state.retired_scan_pending.saturating_add(1);
    if state.retired_scan_pending >= DNS_RETIRED_FORWARDER_RETAIN_THRESHOLD {
        state.retired.retain(ResidentDnsRetiredForwarder::is_alive);
        state.retired_scan_pending = 0;
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

pub fn next_dns_forwarder_tick(state: &mut ResidentDnsForwarderCacheState) -> u64 {
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

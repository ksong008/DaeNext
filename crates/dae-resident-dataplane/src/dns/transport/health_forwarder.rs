use super::super::*;
use super::cache::next_dns_forwarder_tick;

impl ResidentDnsForwarderCache {
    pub(in crate::dns) async fn acquire_health_proxy_udp_forwarder(
        self: &Arc<Self>,
        target: SocketAddr,
        binding: ResidentProxyBinding,
    ) -> Result<ResidentDnsHealthForwarderLease, String> {
        let key = ResidentDnsForwarderKey {
            scheme: ResidentDnsUpstreamScheme::Udp,
            authority: Arc::from(""),
            path: Arc::from(""),
            mark: binding.effective_socket_mark(),
            target: Some(target),
            selection: ResidentDnsForwarderSelectionKey::Proxy {
                graph_link_hash: binding.plan().graph_link_hash.clone(),
            },
            transport: ResidentDnsForwarderTransport::ProxyUdpHealth,
        };
        loop {
            if self.closing.load(std::sync::atomic::Ordering::Acquire) {
                return Err("resident DNS forwarder cache is closing".to_owned());
            }
            let wait_for_close = {
                let mut state = self
                    .health_state
                    .lock()
                    .map_err(|_| "resident DNS health forwarder cache lock poisoned".to_owned())?;
                if self.closing.load(std::sync::atomic::Ordering::Acquire) {
                    return Err("resident DNS forwarder cache is closing".to_owned());
                }
                if let Some(entry) = state.entries.get_mut(&key) {
                    if let Some(close) = entry.health_close.as_ref() {
                        Some(Arc::clone(close))
                    } else {
                        let ResidentDnsForwarderEntryKind::ProxyUdp(forwarder) = &entry.kind else {
                            return Err(
                                "resident DNS forwarder cache kind mismatch for proxied UDP health"
                                    .to_owned(),
                            );
                        };
                        entry.health_leases = entry.health_leases.saturating_add(1);
                        self.metrics.proxy_dns_health_lease_acquired();
                        return Ok(ResidentDnsHealthForwarderLease::new(
                            Arc::clone(self),
                            key,
                            Arc::clone(forwarder),
                        ));
                    }
                } else if state.entries.len() >= DNS_FORWARDER_CACHE_MAX_ENTRIES {
                    if let Some(close) = state
                        .entries
                        .values()
                        .find_map(|entry| entry.health_close.as_ref().map(Arc::clone))
                    {
                        Some(close)
                    } else {
                        return Err(format!(
                            "resident DNS health forwarder cache reached its {} active-entry limit",
                            DNS_FORWARDER_CACHE_MAX_ENTRIES
                        ));
                    }
                } else {
                    let forwarder = Arc::new(
                        ResidentProxyDnsUdpForwarder::new_with_optional_transport_owner(
                            binding.clone(),
                            target,
                            self.udp_runtime.clone(),
                            Arc::clone(&self.metrics),
                            Arc::clone(&self.udp_executor),
                            ResidentTransportOwnerRegistries::new(
                                self.hysteria2_owner_registry.clone(),
                                self.tuic_owner_registry.clone(),
                                self.juicity_owner_registry.clone(),
                            )
                            .with_anytls(self.anytls_owner_registry.clone()),
                        )?,
                    );
                    let last_used = next_dns_forwarder_tick(&mut state);
                    let kind = ResidentDnsForwarderEntryKind::ProxyUdp(Arc::clone(&forwarder));
                    let owner_observation = kind.owner_observation();
                    state.entries.insert(
                        key.clone(),
                        ResidentDnsForwarderEntry {
                            last_used,
                            kind,
                            owner_observation,
                            health_leases: 1,
                            health_close: None,
                        },
                    );
                    state.lru.insert((last_used, key.clone()));
                    self.metrics.proxy_dns_health_forwarder_opened();
                    self.metrics.proxy_dns_health_lease_acquired();
                    return Ok(ResidentDnsHealthForwarderLease::new(
                        Arc::clone(self),
                        key,
                        forwarder,
                    ));
                }
            };
            if let Some(close) = wait_for_close {
                let _ = close.wait().await;
            }
        }
    }

    pub(in crate::dns) fn schedule_health_proxy_udp_forwarder_release(
        self: &Arc<Self>,
        key: ResidentDnsForwarderKey,
        forwarder: Arc<ResidentProxyDnsUdpForwarder>,
    ) {
        let cache = Arc::clone(self);
        let release = async move {
            let _ = cache
                .release_health_proxy_udp_forwarder(key, forwarder)
                .await;
        };
        if let Some(runtime) = self.health_runtime.as_ref() {
            runtime.spawn(release);
        } else if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(release);
        } else {
            debug_assert!(false, "DNS health lease dropped without a Tokio Runtime");
        }
    }

    pub(in crate::dns) async fn release_health_proxy_udp_forwarder(
        self: Arc<Self>,
        key: ResidentDnsForwarderKey,
        forwarder: Arc<ResidentProxyDnsUdpForwarder>,
    ) -> Result<(), String> {
        let (close, owner_observation) = {
            let mut state = self
                .health_state
                .lock()
                .map_err(|_| "resident DNS health forwarder cache lock poisoned".to_owned())?;
            let Some(entry) = state.entries.get_mut(&key) else {
                return Ok(());
            };
            let ResidentDnsForwarderEntryKind::ProxyUdp(current) = &entry.kind else {
                return Err(
                    "resident DNS forwarder cache kind mismatch while releasing proxied UDP health"
                        .to_owned(),
                );
            };
            if !Arc::ptr_eq(current, &forwarder) {
                return Ok(());
            }
            debug_assert!(entry.health_leases > 0, "DNS health lease underflow");
            entry.health_leases = entry.health_leases.saturating_sub(1);
            if entry.health_leases > 0 || entry.health_close.is_some() {
                return Ok(());
            }
            let last_used = entry.last_used;
            let close = ResidentDnsHealthForwarderClose::new();
            entry.health_close = Some(Arc::clone(&close));
            let owner_observation = entry.owner_observation.clone();
            state.lru.remove(&(last_used, key.clone()));
            (close, owner_observation)
        };

        let cache = Arc::clone(&self);
        let close_task = Arc::clone(&close);
        let cleanup = async move {
            let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
            let report = forwarder.shutdown(deadline).await;
            let released = report["status"].as_str() == Some("pass");
            if let Ok(mut state) = cache.health_state.lock() {
                let remove = state.entries.get(&key).is_some_and(|entry| {
                    matches!(
                        &entry.kind,
                        ResidentDnsForwarderEntryKind::ProxyUdp(current)
                            if Arc::ptr_eq(current, &forwarder)
                    ) && entry
                        .health_close
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, &close_task))
                });
                if remove {
                    state.entries.remove(&key);
                    cache.metrics.proxy_dns_health_forwarder_closed();
                }
            }
            if released && let Some(owner) = owner_observation {
                owner.release();
            }
            close_task.finish(released);
        };
        if let Some(runtime) = self.health_runtime.as_ref() {
            runtime.spawn(cleanup);
        } else if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(cleanup);
        } else {
            close.finish(false);
            return Err("proxied UDP health forwarder cleanup has no Tokio Runtime".to_owned());
        }

        if close.wait().await {
            Ok(())
        } else {
            Err("proxied UDP health forwarder cleanup did not complete".to_owned())
        }
    }
}

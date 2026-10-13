use super::*;
use crate::proxy_transport::ResidentDnsProxyFuture;
use std::sync::atomic::{AtomicUsize, Ordering};

fn poison<T>(mutex: &std::sync::Mutex<T>) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = mutex.lock().unwrap();
        panic!("injected registry poison");
    }));
    assert!(mutex.is_poisoned());
}

struct TestHealthForwarder {
    owner: Arc<ResidentDnsTransportOwnerObservation>,
    shutdowns: AtomicUsize,
}

impl ResidentDnsProxyUdpForwarder for TestHealthForwarder {
    fn exchange<'a>(
        &'a self,
        _payload: &'a [u8],
        _context: ProxyDnsRequestContext,
    ) -> ResidentDnsProxyFuture<'a, Result<Vec<u8>, ProxyDnsRequestError>> {
        Box::pin(async { panic!("cleanup test must not exchange DNS") })
    }

    fn shutdown(&self, _deadline: time::Instant) -> ResidentDnsProxyFuture<'_, Value> {
        Box::pin(async move {
            self.shutdowns.fetch_add(1, Ordering::Relaxed);
            json!({"status": "pass"})
        })
    }

    fn owner_observation(&self) -> Arc<ResidentDnsTransportOwnerObservation> {
        Arc::clone(&self.owner)
    }

    fn actor_count(&self) -> usize {
        0
    }
}

#[tokio::test]
async fn poisoned_registries_still_shutdown_cached_forwarders() {
    let cache = ResidentDnsForwarderCache::default();
    let forwarder = cache
        .asis_udp_forwarder("127.0.0.1:53".parse().unwrap(), 0)
        .unwrap();
    poison(&cache.state);
    poison(&cache.health_state);
    let report = cache
        .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
        .await;
    assert_eq!(report["status"], "pass", "{report}");
    assert_eq!(report["entriesClosed"], 1);
    assert_eq!(
        report["recoveredPoisonedLocks"].as_array().unwrap().len(),
        2
    );
    assert!(
        cache
            .state
            .lock()
            .err()
            .unwrap()
            .into_inner()
            .entries
            .is_empty()
    );
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 0);
    assert!(
        cache
            .asis_udp_forwarder("127.0.0.1:53".parse().unwrap(), 0)
            .is_err()
    );
    drop(forwarder);
}

#[tokio::test]
async fn poisoned_health_registry_releases_last_lease_without_losing_other_leases() {
    let cache = Arc::new(ResidentDnsForwarderCache::default());
    let forwarder = Arc::new(TestHealthForwarder {
        owner: ResidentDnsTransportOwnerObservation::new(Arc::clone(&cache.metrics), 1),
        shutdowns: AtomicUsize::new(0),
    });
    let erased: Arc<dyn ResidentDnsProxyUdpForwarder> = forwarder.clone();
    let key = ResidentDnsForwarderKey {
        scheme: ResidentDnsUpstreamScheme::Udp,
        authority: Arc::from(""),
        path: Arc::from(""),
        mark: 0,
        target: Some("127.0.0.1:53".parse().unwrap()),
        selection: ResidentDnsForwarderSelectionKey::Unrouted,
        transport: ResidentDnsForwarderTransport::ProxyUdpHealth,
    };
    cache.health_state.lock().unwrap().entries.insert(
        key.clone(),
        ResidentDnsForwarderEntry {
            last_used: 1,
            kind: ResidentDnsForwarderEntryKind::ProxyUdp(Arc::clone(&erased)),
            owner_observation: Some(Arc::clone(&forwarder.owner)),
            health_leases: 2,
            health_close: None,
        },
    );
    cache.metrics.proxy_dns_health_forwarder_opened();
    poison(&cache.health_state);
    Arc::clone(&cache)
        .release_health_proxy_udp_forwarder(key.clone(), Arc::clone(&erased))
        .await
        .unwrap();
    assert_eq!(forwarder.shutdowns.load(Ordering::Relaxed), 0);
    Arc::clone(&cache)
        .release_health_proxy_udp_forwarder(key, erased)
        .await
        .unwrap();
    assert_eq!(forwarder.shutdowns.load(Ordering::Relaxed), 1);
    assert!(
        cache
            .health_state
            .lock()
            .err()
            .unwrap()
            .into_inner()
            .entries
            .is_empty()
    );
    assert!(cache.health_state.is_poisoned());
    assert_eq!(cache.metrics.snapshot()["dnsTransportOwnersCurrent"], 0);
    assert_eq!(
        cache.metrics.snapshot()["proxyDnsHealthForwardersCurrent"],
        0
    );
}

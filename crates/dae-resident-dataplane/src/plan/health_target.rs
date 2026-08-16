use super::*;
use std::time::Instant;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResidentHealthTargetFamily {
    Present(Vec<SocketAddr>),
    Absent,
    Unknown(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentHealthTargetFamilies {
    pub(crate) ipv4: ResidentHealthTargetFamily,
    pub(crate) ipv6: ResidentHealthTargetFamily,
}

#[derive(Clone, Debug)]
struct CachedResidentHealthTargetFamilies {
    value: ResidentHealthTargetFamilies,
    valid_until: Instant,
}

/// One in-flight cache refresh.
///
/// The leader publishes its outcome to followers through a watch channel so
/// concurrent callers that observed the same expired cache wait for one shared
/// A+AAAA resolution instead of each firing its own query and UDP socket pair.
#[derive(Debug)]
struct ResidentHealthTargetRefreshFlight {
    result: tokio::sync::watch::Sender<Option<ResidentHealthTargetFamilies>>,
}

impl ResidentHealthTargetRefreshFlight {
    fn new() -> Self {
        let (result, _) = tokio::sync::watch::channel(None);
        Self { result }
    }
}

/// Clears the in-flight marker when the leader's resolution future is dropped
/// (including cancellation).
///
/// Without this, a leader cancelled mid-await would leave `self.refresh`
/// holding the flight forever: followers wait on `changed()` which never
/// completes because the leader's sender is still alive, so the "degrade to
/// resolving directly" fallback is unreachable and every caller hangs.
struct RefreshFlightGuard<'a> {
    refresh: &'a Mutex<Option<Arc<ResidentHealthTargetRefreshFlight>>>,
    flight: Arc<ResidentHealthTargetRefreshFlight>,
}

impl Drop for RefreshFlightGuard<'_> {
    fn drop(&mut self) {
        if self.flight.result.borrow().is_none() {
            // Followers keep an Arc to the flight (and therefore to this
            // Sender), so merely clearing `refresh` does not close the watch
            // channel. Bump its version explicitly to wake them immediately.
            self.flight.result.send_replace(None);
        }
        if let Ok(mut refresh) = self.refresh.lock()
            && let Some(current) = refresh.as_ref()
            && Arc::ptr_eq(current, &self.flight)
        {
            *refresh = None;
        }
    }
}

/// Follower bound on waiting for a refresh leader.  Beyond this the follower
/// resolves directly so a stuck or cancelled leader cannot hang probes.
const REFRESH_FOLLOWER_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub(crate) struct ResidentHealthTargetResolver {
    host: String,
    port: u16,
    literal_addrs: Vec<SocketAddr>,
    fallback_resolver: SocketAddr,
    resolver_mark: u32,
    refresh_interval: Duration,
    cache: Arc<Mutex<Option<CachedResidentHealthTargetFamilies>>>,
    refresh: Arc<Mutex<Option<Arc<ResidentHealthTargetRefreshFlight>>>>,
    #[cfg(test)]
    test_result: Option<ResidentHealthTargetFamilies>,
    #[cfg(test)]
    test_refresh: Option<Arc<TestHealthTargetRefreshHook>>,
}

#[cfg(test)]
#[derive(Default, Debug)]
struct TestHealthTargetRefreshHook {
    calls: std::sync::atomic::AtomicUsize,
    release: tokio::sync::Notify,
}

impl ResidentHealthTargetResolver {
    pub(crate) fn new(
        host: String,
        port: u16,
        literal_addrs: Vec<SocketAddr>,
        fallback_resolver: SocketAddr,
        resolver_mark: u32,
        refresh_interval: Duration,
    ) -> Self {
        Self {
            host,
            port,
            literal_addrs,
            fallback_resolver,
            resolver_mark,
            refresh_interval,
            cache: Arc::new(Mutex::new(None)),
            refresh: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            test_result: None,
            #[cfg(test)]
            test_refresh: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_result(mut self, result: ResidentHealthTargetFamilies) -> Self {
        self.test_result = Some(result);
        self
    }

    #[cfg(test)]
    fn with_test_refresh(mut self, hook: Arc<TestHealthTargetRefreshHook>) -> Self {
        self.test_refresh = Some(hook);
        self
    }

    pub(crate) async fn resolve(&self) -> ResidentHealthTargetFamilies {
        #[cfg(test)]
        if let Some(result) = self.test_result.as_ref() {
            return result.clone();
        }
        if !self.literal_addrs.is_empty() {
            return classify_resident_health_target_addrs(self.literal_addrs.clone());
        }
        let now = Instant::now();
        if let Ok(cache) = self.cache.lock()
            && let Some(cached) = cache.as_ref()
            && cached.valid_until > now
        {
            return cached.value.clone();
        }

        // Single-flight refresh: the first caller that observed the expired
        // cache becomes the leader and performs the DNS resolution; concurrent
        // callers wait for its outcome. Without this, every concurrent probe
        // firing around the cache-expiry boundary triggers its own A+AAAA
        // lookup (thundering herd of queries and sockets).
        let (flight, is_leader) = {
            let Ok(mut refresh) = self.refresh.lock() else {
                // Poisoned refresh lock: degrade to resolving directly.
                return self.refresh_resolution().await;
            };
            if let Some(flight) = refresh.as_ref() {
                (Arc::clone(flight), false)
            } else {
                let flight = Arc::new(ResidentHealthTargetRefreshFlight::new());
                *refresh = Some(Arc::clone(&flight));
                (flight, true)
            }
        };
        // The refresh lock is dropped here so the leader's resolution await
        // below does not hold a `MutexGuard` across an await (which would make
        // this future `!Send`).
        if is_leader {
            return self.resolve_as_refresh_leader(flight).await;
        }
        let mut receiver = flight.result.subscribe();
        if receiver.borrow().is_none() {
            // Wait for the leader to publish (or for the flight to be dropped).
            // `changed` completes immediately if the leader sent between the
            // check and the await, so the notification cannot be missed.
            // The wait is bounded: a leader that is cancelled mid-resolution
            // (without the guard having run yet) or that wedges on DNS must
            // not hang followers forever — after the bound the follower
            // resolves directly.
            let notified = receiver.changed();
            tokio::pin!(notified);
            let _ = tokio::time::timeout(REFRESH_FOLLOWER_WAIT, notified.as_mut()).await;
        }
        if let Some(result) = receiver.borrow().clone() {
            return result;
        }
        // The leader never published (e.g. it was cancelled mid-flight or the
        // wait timed out): resolve directly so the caller still gets an
        // outcome.
        self.refresh_resolution().await
    }

    async fn resolve_as_refresh_leader(
        &self,
        flight: Arc<ResidentHealthTargetRefreshFlight>,
    ) -> ResidentHealthTargetFamilies {
        // If this future is cancelled mid-await, the guard's Drop clears the
        // in-flight marker so the next caller becomes a fresh leader instead
        // of waiting on a dead flight.
        let _guard = RefreshFlightGuard {
            refresh: &self.refresh,
            flight: Arc::clone(&flight),
        };
        let value = self.refresh_resolution().await;
        let _ = flight.result.send(Some(value.clone()));
        // The guard's Drop clears the in-flight marker (it still matches by
        // Arc::ptr_eq); followers already hold their own `Arc` to this flight.
        value
    }

    async fn refresh_resolution(&self) -> ResidentHealthTargetFamilies {
        #[cfg(test)]
        if let Some(hook) = self.test_refresh.as_ref() {
            hook.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            hook.release.notified().await;
            return ResidentHealthTargetFamilies {
                ipv4: ResidentHealthTargetFamily::Present(vec![SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    80,
                )]),
                ipv6: ResidentHealthTargetFamily::Absent,
            };
        }
        let resolved = resolve_host_addrs_with_configured_fallback_dns_ttl(
            &self.host,
            self.port,
            self.fallback_resolver,
            self.resolver_mark,
            "resolve health check target",
            self.refresh_interval,
        )
        .await;
        match resolved {
            Ok(resolved) => {
                let value = classify_resident_health_target_addrs(resolved.addrs);
                if !resolved.valid_for.is_zero()
                    && let Some(valid_until) = Instant::now().checked_add(resolved.valid_for)
                    && let Ok(mut cache) = self.cache.lock()
                {
                    *cache = Some(CachedResidentHealthTargetFamilies {
                        value: value.clone(),
                        valid_until,
                    });
                }
                value
            }
            Err(err) => ResidentHealthTargetFamilies {
                ipv4: ResidentHealthTargetFamily::Unknown(err.clone()),
                ipv6: ResidentHealthTargetFamily::Unknown(err),
            },
        }
    }

    pub(crate) fn identity(&self) -> String {
        let literal_addrs = self
            .literal_addrs
            .iter()
            .map(SocketAddr::to_string)
            .collect::<Vec<_>>()
            .join(",");
        link_hash(&format!(
            "health-target|{}|{}|{}|{}|{}",
            self.host, self.port, literal_addrs, self.fallback_resolver, self.resolver_mark
        ))
    }
}

impl PartialEq for ResidentHealthTargetResolver {
    fn eq(&self, other: &Self) -> bool {
        self.host == other.host
            && self.port == other.port
            && self.literal_addrs == other.literal_addrs
            && self.fallback_resolver == other.fallback_resolver
            && self.resolver_mark == other.resolver_mark
            && self.refresh_interval == other.refresh_interval
            && {
                #[cfg(test)]
                {
                    self.test_result == other.test_result
                }
                #[cfg(not(test))]
                {
                    true
                }
            }
    }
}

impl Eq for ResidentHealthTargetResolver {}

fn classify_resident_health_target_addrs(addrs: Vec<SocketAddr>) -> ResidentHealthTargetFamilies {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for addr in addrs {
        let targets = if addr.is_ipv6() { &mut ipv6 } else { &mut ipv4 };
        if !targets.contains(&addr) {
            targets.push(addr);
        }
    }
    ResidentHealthTargetFamilies {
        ipv4: if ipv4.is_empty() {
            ResidentHealthTargetFamily::Absent
        } else {
            ResidentHealthTargetFamily::Present(ipv4)
        },
        ipv6: if ipv6.is_empty() {
            ResidentHealthTargetFamily::Absent
        } else {
            ResidentHealthTargetFamily::Present(ipv6)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_resolution_classifies_each_family_without_inventing_the_other() {
        let dual = classify_resident_health_target_addrs(vec![
            "192.0.2.1:53".parse().unwrap(),
            "[2001:db8::1]:53".parse().unwrap(),
            "192.0.2.1:53".parse().unwrap(),
        ]);
        assert!(
            matches!(dual.ipv4, ResidentHealthTargetFamily::Present(ref addrs) if addrs.len() == 1)
        );
        assert!(
            matches!(dual.ipv6, ResidentHealthTargetFamily::Present(ref addrs) if addrs.len() == 1)
        );

        let only_v4 = classify_resident_health_target_addrs(vec!["192.0.2.2:53".parse().unwrap()]);
        assert_eq!(only_v4.ipv6, ResidentHealthTargetFamily::Absent);
    }

    #[test]
    fn domain_resolution_outcomes_preserve_v4_only_v6_only_and_dual_stack_shapes() {
        let fallback = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 53);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        for (addrs, expect_v4, expect_v6) in [
            (
                vec![SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    80,
                )],
                true,
                false,
            ),
            (
                vec![SocketAddr::new(
                    IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                    80,
                )],
                false,
                true,
            ),
            (
                vec![
                    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 80),
                    SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 80),
                ],
                true,
                true,
            ),
        ] {
            let expected = classify_resident_health_target_addrs(addrs);
            let resolver = ResidentHealthTargetResolver::new(
                "health-target.invalid".to_owned(),
                80,
                Vec::new(),
                fallback,
                0,
                Duration::from_secs(30),
            )
            .with_test_result(expected);
            let resolved = runtime.block_on(resolver.resolve());
            assert_eq!(
                matches!(resolved.ipv4, ResidentHealthTargetFamily::Present(_)),
                expect_v4
            );
            assert_eq!(
                matches!(resolved.ipv6, ResidentHealthTargetFamily::Present(_)),
                expect_v6
            );
        }
    }

    #[test]
    fn resolver_error_remains_distinct_from_absent_family() {
        let unknown = ResidentHealthTargetFamilies {
            ipv4: ResidentHealthTargetFamily::Unknown("temporary resolver failure".to_owned()),
            ipv6: ResidentHealthTargetFamily::Unknown("temporary resolver failure".to_owned()),
        };
        assert!(matches!(
            unknown.ipv4,
            ResidentHealthTargetFamily::Unknown(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_cache_expiry_refresh_is_single_flighted() {
        let hook = Arc::new(TestHealthTargetRefreshHook::default());
        let resolver = Arc::new(
            ResidentHealthTargetResolver::new(
                "health-target.invalid".to_owned(),
                80,
                Vec::new(),
                SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 53),
                0,
                Duration::from_secs(1),
            )
            .with_test_refresh(Arc::clone(&hook)),
        );

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let resolver = Arc::clone(&resolver);
            tasks.spawn(async move { resolver.resolve().await });
        }

        // Wait until exactly one leader has started resolving.
        let deadline = Instant::now() + Duration::from_secs(5);
        while hook.calls.load(std::sync::atomic::Ordering::SeqCst) < 1 && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(
            hook.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "exactly one refresh must start"
        );
        // Hold the leader to prove the followers are waiting, not resolving.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            hook.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "followers must wait for the leader instead of resolving"
        );
        hook.release.notify_one();

        let mut results = Vec::new();
        while let Some(result) = tasks.join_next().await {
            results.push(result.unwrap());
        }
        assert_eq!(results.len(), 8);
        for resolved in results {
            assert!(
                matches!(
                    resolved.ipv4,
                    ResidentHealthTargetFamily::Present(ref addrs) if addrs.len() == 1
                ),
                "all followers must receive the leader's outcome"
            );
        }
        assert_eq!(
            hook.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the whole refresh must be a single flight"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancelled_refresh_leader_wakes_followers_without_waiting_for_timeout() {
        let hook = Arc::new(TestHealthTargetRefreshHook::default());
        let resolver = Arc::new(
            ResidentHealthTargetResolver::new(
                "health-target.invalid".to_owned(),
                80,
                Vec::new(),
                SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 53),
                0,
                Duration::from_secs(1),
            )
            .with_test_refresh(Arc::clone(&hook)),
        );

        let leader = {
            let resolver = Arc::clone(&resolver);
            tokio::spawn(async move { resolver.resolve().await })
        };
        while hook.calls.load(std::sync::atomic::Ordering::SeqCst) < 1 {
            tokio::task::yield_now().await;
        }
        let follower = {
            let resolver = Arc::clone(&resolver);
            tokio::spawn(async move { resolver.resolve().await })
        };
        tokio::time::sleep(Duration::from_millis(25)).await;
        leader.abort();

        tokio::time::timeout(Duration::from_millis(500), async {
            while hook.calls.load(std::sync::atomic::Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("follower must start its fallback refresh immediately");
        hook.release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), follower)
            .await
            .expect("follower completion")
            .expect("follower task");
    }
}

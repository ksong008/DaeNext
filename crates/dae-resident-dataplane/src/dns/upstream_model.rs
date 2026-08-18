use super::transport::tcp_udp::ResidentDnsTcpUdpHedgeRegistry;
use super::transport::udp_multiplex::{ResidentDnsUdpActorExecutor, ResidentDnsUdpMultiplexHandle};
use super::*;
use crate::resolve_host_addrs_with_bootstrap_dns_ttl;
use std::sync::{
    Weak,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::sync::Notify;

mod h2_recovery;
mod target_cache;
mod target_refresh;
pub(in crate::dns) use h2_recovery::ResidentDnsH2Recovery;
use target_cache::ResidentDnsResolvedTargetCache;
pub(in crate::dns) use target_cache::ResidentDnsResolvedTargetSnapshot;
pub(in crate::dns) use target_cache::ResidentDnsTargetRefreshError;
pub(in crate::dns) use target_refresh::{
    ResidentDnsTargetRefreshHandle, ResidentDnsTargetRefreshOwner,
    ResidentDnsTargetRefreshOwnerTask,
};

#[derive(Clone, Debug)]
pub(in crate::dns) enum ResidentDnsRequestAction {
    AsIs,
    Reject,
    Upstream(ResidentDnsUpstream),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::dns) enum ResidentDnsResponseAction {
    Accept,
    Reject,
    Upstream(ResidentDnsUpstream),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::dns) struct ResidentDnsUpstream {
    pub(in crate::dns) index: u8,
    pub(in crate::dns) tag: String,
    pub(in crate::dns) target: ResidentDnsUpstreamTarget,
    pub(in crate::dns) scheme: ResidentDnsUpstreamScheme,
    pub(in crate::dns) path: Arc<str>,
}

#[derive(Clone, Debug)]
pub(in crate::dns) struct ResidentDnsUpstreams {
    pub(in crate::dns) by_tag: BTreeMap<String, ResidentDnsUpstream>,
    pub(in crate::dns) tag_to_index: BTreeMap<String, u8>,
    pub(in crate::dns) request_actions: Vec<ResidentDnsRequestAction>,
    pub(in crate::dns) response_actions: Vec<ResidentDnsResponseAction>,
}

#[derive(Clone, Debug)]
pub(in crate::dns) struct ResidentDnsUpstreamTarget {
    pub(in crate::dns) authority: Arc<str>,
    pub(in crate::dns) host: String,
    pub(in crate::dns) port: u16,
    pub(in crate::dns) literal_addr: Option<SocketAddr>,
    pub(in crate::dns) fallback_resolver: SocketAddr,
    pub(in crate::dns) resolver_mark: u32,
    pub(in crate::dns) resolved_addrs: Arc<ResidentDnsResolvedTargetCache>,
}

impl ResidentDnsUpstreamTarget {
    pub(in crate::dns) fn new(
        authority: String,
        host: String,
        port: u16,
        literal_addr: Option<SocketAddr>,
        fallback_resolver: SocketAddr,
        resolver_mark: u32,
        refresh_interval: Duration,
    ) -> Self {
        Self {
            authority: authority.into(),
            host,
            port,
            literal_addr,
            fallback_resolver,
            resolver_mark,
            resolved_addrs: Arc::new(ResidentDnsResolvedTargetCache::new(refresh_interval)),
        }
    }

    pub(in crate::dns) async fn resolve_addrs(
        &self,
    ) -> Result<ResidentDnsResolvedTargetSnapshot, String> {
        if let Some(addr) = self.literal_addr {
            return Ok(ResidentDnsResolvedTargetSnapshot::literal(addr));
        }
        let host = self.host.clone();
        let port = self.port;
        let fallback_resolver = self.fallback_resolver;
        let resolver_mark = self.resolver_mark;
        self.resolved_addrs
            .resolve(move |refresh_interval| async move {
                resolve_host_addrs_with_bootstrap_dns_ttl(
                    &host,
                    port,
                    fallback_resolver,
                    resolver_mark,
                    "resolve DNS upstream",
                    refresh_interval,
                )
                .await
            })
            .await
    }

    pub(in crate::dns) async fn refresh_after_stale_failure_and_resolve(
        &self,
        snapshot: &ResidentDnsResolvedTargetSnapshot,
        deadline: time::Instant,
    ) -> Result<Option<ResidentDnsResolvedTargetSnapshot>, ResidentDnsTargetRefreshError> {
        if self.literal_addr.is_some() {
            return Ok(None);
        }
        let host = self.host.clone();
        let port = self.port;
        let fallback_resolver = self.fallback_resolver;
        let resolver_mark = self.resolver_mark;
        self.resolved_addrs
            .refresh_after_stale_failure_and_resolve(
                snapshot,
                deadline,
                move |refresh_interval| async move {
                    resolve_host_addrs_with_bootstrap_dns_ttl(
                        &host,
                        port,
                        fallback_resolver,
                        resolver_mark,
                        "refresh DNS upstream after stale address failure",
                        refresh_interval,
                    )
                    .await
                },
            )
            .await
    }

    pub(in crate::dns) fn install_target_refresh(&self, handle: ResidentDnsTargetRefreshHandle) {
        self.resolved_addrs.install_refresh_handle(handle);
    }
}

impl ResidentDnsUpstreams {
    pub(in crate::dns) fn install_target_refresh(&self, handle: ResidentDnsTargetRefreshHandle) {
        for upstream in self.by_tag.values() {
            upstream.target.install_target_refresh(handle.clone());
        }
    }
}

impl PartialEq for ResidentDnsUpstreamTarget {
    fn eq(&self, other: &Self) -> bool {
        self.authority == other.authority
            && self.host == other.host
            && self.port == other.port
            && self.literal_addr == other.literal_addr
            && self.fallback_resolver == other.fallback_resolver
            && self.resolver_mark == other.resolver_mark
    }
}

impl Eq for ResidentDnsUpstreamTarget {}

pub(in crate::dns) struct ResidentDnsForwarderCache {
    pub(in crate::dns) state: Mutex<ResidentDnsForwarderCacheState>,
    pub(in crate::dns) health_state: Mutex<ResidentDnsForwarderCacheState>,
    pub(in crate::dns) udp_executor: Arc<ResidentDnsUdpActorExecutor>,
    pub(in crate::dns) udp_runtime: ResidentDnsUdpRuntimeConfig,
    pub(in crate::dns) resources: ResidentDnsResourceProfile,
    pub(in crate::dns) tcp_udp_hedges: ResidentDnsTcpUdpHedgeRegistry,
    pub(in crate::dns) metrics: Arc<ResidentDataplaneMetrics>,
    pub(in crate::dns) proxy_tcp_transport: Option<Arc<dyn ResidentDnsProxyTcpTransport>>,
    pub(in crate::dns) proxy_udp_transport: Arc<dyn ResidentDnsProxyUdpTransport>,
    pub(in crate::dns) health_runtime: Option<tokio::runtime::Handle>,
    pub(in crate::dns) closing: std::sync::atomic::AtomicBool,
}

impl Default for ResidentDnsForwarderCache {
    fn default() -> Self {
        let udp_runtime = ResidentDnsUdpRuntimeConfig::standalone();
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let udp_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
            udp_runtime.clone(),
            Arc::clone(&metrics),
        ));
        let owners = ResidentTransportOwnerRegistries::default();
        Self {
            state: Mutex::new(ResidentDnsForwarderCacheState::default()),
            health_state: Mutex::new(ResidentDnsForwarderCacheState::default()),
            udp_executor: Arc::clone(&udp_executor),
            udp_runtime: udp_runtime.clone(),
            resources: ResidentDnsResourceProfile::selected(),
            tcp_udp_hedges: ResidentDnsTcpUdpHedgeRegistry::default(),
            metrics: Arc::clone(&metrics),
            proxy_tcp_transport: Some(resident_dns_proxy_tcp_transport(owners.clone())),
            proxy_udp_transport: resident_dns_proxy_udp_transport(
                udp_runtime.clone(),
                Arc::clone(&metrics),
                udp_executor,
                owners,
            ),
            health_runtime: tokio::runtime::Handle::try_current().ok(),
            closing: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl ResidentDnsForwarderCache {
    pub(in crate::dns) fn new(
        udp_runtime: ResidentDnsUdpRuntimeConfig,
        metrics: Arc<ResidentDataplaneMetrics>,
    ) -> Self {
        let udp_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
            udp_runtime.clone(),
            Arc::clone(&metrics),
        ));
        let owners = ResidentTransportOwnerRegistries::default();
        Self {
            state: Mutex::new(ResidentDnsForwarderCacheState::default()),
            health_state: Mutex::new(ResidentDnsForwarderCacheState::default()),
            udp_executor: Arc::clone(&udp_executor),
            udp_runtime: udp_runtime.clone(),
            resources: ResidentDnsResourceProfile::selected(),
            tcp_udp_hedges: ResidentDnsTcpUdpHedgeRegistry::default(),
            metrics: Arc::clone(&metrics),
            proxy_tcp_transport: Some(resident_dns_proxy_tcp_transport(owners.clone())),
            proxy_udp_transport: resident_dns_proxy_udp_transport(
                udp_runtime.clone(),
                Arc::clone(&metrics),
                udp_executor,
                owners,
            ),
            health_runtime: tokio::runtime::Handle::try_current().ok(),
            closing: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(in crate::dns) fn new_with_proxy_transports(
        udp_runtime: ResidentDnsUdpRuntimeConfig,
        metrics: Arc<ResidentDataplaneMetrics>,
        runtime: tokio::runtime::Handle,
        udp_executor: Arc<ResidentDnsUdpActorExecutor>,
        proxy_tcp_transport: Arc<dyn ResidentDnsProxyTcpTransport>,
        proxy_udp_transport: Arc<dyn ResidentDnsProxyUdpTransport>,
    ) -> Self {
        let mut cache = Self::new(udp_runtime, metrics);
        cache.udp_executor = udp_executor;
        cache.proxy_tcp_transport = Some(proxy_tcp_transport);
        cache.proxy_udp_transport = proxy_udp_transport;
        cache.health_runtime = Some(runtime);
        cache
    }
}

impl std::fmt::Debug for ResidentDnsForwarderCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entries = self
            .state
            .lock()
            .map(|state| state.entries.len())
            .unwrap_or_default();
        f.debug_struct("ResidentDnsForwarderCache")
            .field("entries", &entries)
            .field("generation", &self.udp_runtime.generation)
            .field(
                "closing",
                &self.closing.load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish()
    }
}

#[derive(Default)]
pub(in crate::dns) struct ResidentDnsForwarderCacheState {
    pub(in crate::dns) entries: BTreeMap<ResidentDnsForwarderKey, ResidentDnsForwarderEntry>,
    pub(in crate::dns) lru: BTreeSet<(u64, ResidentDnsForwarderKey)>,
    pub(in crate::dns) next_tick: u64,
    pub(in crate::dns) retired: Vec<ResidentDnsRetiredForwarder>,
}

pub(in crate::dns) struct ResidentDnsRetiredForwarder {
    kind: ResidentDnsRetiredForwarderKind,
    owner_observation: Option<Weak<ResidentDnsTransportOwnerObservation>>,
}

enum ResidentDnsRetiredForwarderKind {
    Quic(Weak<AsyncMutex<ResidentDnsQuicForwarder>>),
    ProxyQuic(Weak<AsyncMutex<ResidentDnsProxyQuicForwarder>>),
    ProxyH3(Weak<AsyncMutex<ResidentDnsProxyH3Forwarder>>),
    Udp(Weak<ResidentDnsUdpForwarder>),
    ProxyUdp(Weak<dyn ResidentDnsProxyUdpForwarder>),
    Tcp(Weak<ResidentDnsTcpForwarder>),
    Tls(Weak<ResidentDnsTlsForwarder>),
    Https(Weak<ResidentDnsHttpsForwarder>),
    H3(Weak<AsyncMutex<ResidentDnsH3Forwarder>>),
}

impl ResidentDnsRetiredForwarder {
    pub(in crate::dns) fn from_entry(entry: &ResidentDnsForwarderEntry) -> Self {
        let kind = match &entry.kind {
            ResidentDnsForwarderEntryKind::Quic(forwarder) => {
                ResidentDnsRetiredForwarderKind::Quic(Arc::downgrade(forwarder))
            }
            ResidentDnsForwarderEntryKind::ProxyQuic(forwarder) => {
                ResidentDnsRetiredForwarderKind::ProxyQuic(Arc::downgrade(forwarder))
            }
            ResidentDnsForwarderEntryKind::ProxyH3(forwarder) => {
                ResidentDnsRetiredForwarderKind::ProxyH3(Arc::downgrade(forwarder))
            }
            ResidentDnsForwarderEntryKind::Udp(forwarder) => {
                ResidentDnsRetiredForwarderKind::Udp(Arc::downgrade(forwarder))
            }
            ResidentDnsForwarderEntryKind::ProxyUdp(forwarder) => {
                ResidentDnsRetiredForwarderKind::ProxyUdp(Arc::downgrade(forwarder))
            }
            ResidentDnsForwarderEntryKind::Tcp(forwarder) => {
                ResidentDnsRetiredForwarderKind::Tcp(Arc::downgrade(forwarder))
            }
            ResidentDnsForwarderEntryKind::Tls(forwarder) => {
                ResidentDnsRetiredForwarderKind::Tls(Arc::downgrade(forwarder))
            }
            ResidentDnsForwarderEntryKind::Https(forwarder) => {
                ResidentDnsRetiredForwarderKind::Https(Arc::downgrade(forwarder))
            }
            ResidentDnsForwarderEntryKind::H3(forwarder) => {
                ResidentDnsRetiredForwarderKind::H3(Arc::downgrade(forwarder))
            }
        };
        Self {
            kind,
            owner_observation: entry.owner_observation.as_ref().map(Arc::downgrade),
        }
    }

    pub(in crate::dns) fn is_alive(&self) -> bool {
        match &self.kind {
            ResidentDnsRetiredForwarderKind::Quic(forwarder) => forwarder.strong_count() > 0,
            ResidentDnsRetiredForwarderKind::ProxyQuic(forwarder) => forwarder.strong_count() > 0,
            ResidentDnsRetiredForwarderKind::ProxyH3(forwarder) => forwarder.strong_count() > 0,
            ResidentDnsRetiredForwarderKind::Udp(forwarder) => forwarder.strong_count() > 0,
            ResidentDnsRetiredForwarderKind::ProxyUdp(forwarder) => forwarder.strong_count() > 0,
            ResidentDnsRetiredForwarderKind::Tcp(forwarder) => forwarder.strong_count() > 0,
            ResidentDnsRetiredForwarderKind::Tls(forwarder) => forwarder.strong_count() > 0,
            ResidentDnsRetiredForwarderKind::Https(forwarder) => forwarder.strong_count() > 0,
            ResidentDnsRetiredForwarderKind::H3(forwarder) => forwarder.strong_count() > 0,
        }
    }

    pub(in crate::dns) fn upgrade(
        &self,
    ) -> Option<(
        ResidentDnsForwarderEntryKind,
        Option<Arc<ResidentDnsTransportOwnerObservation>>,
    )> {
        let kind = match &self.kind {
            ResidentDnsRetiredForwarderKind::Quic(forwarder) => {
                ResidentDnsForwarderEntryKind::Quic(forwarder.upgrade()?)
            }
            ResidentDnsRetiredForwarderKind::ProxyQuic(forwarder) => {
                ResidentDnsForwarderEntryKind::ProxyQuic(forwarder.upgrade()?)
            }
            ResidentDnsRetiredForwarderKind::ProxyH3(forwarder) => {
                ResidentDnsForwarderEntryKind::ProxyH3(forwarder.upgrade()?)
            }
            ResidentDnsRetiredForwarderKind::Udp(forwarder) => {
                ResidentDnsForwarderEntryKind::Udp(forwarder.upgrade()?)
            }
            ResidentDnsRetiredForwarderKind::ProxyUdp(forwarder) => {
                ResidentDnsForwarderEntryKind::ProxyUdp(forwarder.upgrade()?)
            }
            ResidentDnsRetiredForwarderKind::Tcp(forwarder) => {
                ResidentDnsForwarderEntryKind::Tcp(forwarder.upgrade()?)
            }
            ResidentDnsRetiredForwarderKind::Tls(forwarder) => {
                ResidentDnsForwarderEntryKind::Tls(forwarder.upgrade()?)
            }
            ResidentDnsRetiredForwarderKind::Https(forwarder) => {
                ResidentDnsForwarderEntryKind::Https(forwarder.upgrade()?)
            }
            ResidentDnsRetiredForwarderKind::H3(forwarder) => {
                ResidentDnsForwarderEntryKind::H3(forwarder.upgrade()?)
            }
        };
        Some((
            kind,
            self.owner_observation.as_ref().and_then(Weak::upgrade),
        ))
    }
}

pub(in crate::dns) struct ResidentDnsForwarderEntry {
    pub(in crate::dns) last_used: u64,
    pub(in crate::dns) kind: ResidentDnsForwarderEntryKind,
    pub(in crate::dns) owner_observation: Option<Arc<ResidentDnsTransportOwnerObservation>>,
    pub(in crate::dns) health_leases: usize,
    pub(in crate::dns) health_close: Option<Arc<ResidentDnsHealthForwarderClose>>,
}

pub(in crate::dns) struct ResidentDnsHealthForwarderClose {
    complete: AtomicBool,
    successful: AtomicBool,
    notify: Notify,
}

impl ResidentDnsHealthForwarderClose {
    pub(in crate::dns) fn new() -> Arc<Self> {
        Arc::new(Self {
            complete: AtomicBool::new(false),
            successful: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    pub(in crate::dns) async fn wait(&self) -> bool {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        if !self.complete.load(Ordering::Acquire) {
            notified.await;
        }
        self.successful.load(Ordering::Acquire)
    }

    pub(in crate::dns) fn finish(&self, successful: bool) {
        self.successful.store(successful, Ordering::Release);
        self.complete.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
}

pub(in crate::dns) struct ResidentDnsHealthForwarderLease {
    cache: Arc<ResidentDnsForwarderCache>,
    key: Option<ResidentDnsForwarderKey>,
    forwarder: Arc<dyn ResidentDnsProxyUdpForwarder>,
}

impl ResidentDnsHealthForwarderLease {
    pub(in crate::dns) fn new(
        cache: Arc<ResidentDnsForwarderCache>,
        key: ResidentDnsForwarderKey,
        forwarder: Arc<dyn ResidentDnsProxyUdpForwarder>,
    ) -> Self {
        Self {
            cache,
            key: Some(key),
            forwarder,
        }
    }

    pub(in crate::dns) fn forwarder(&self) -> Arc<dyn ResidentDnsProxyUdpForwarder> {
        Arc::clone(&self.forwarder)
    }

    pub(in crate::dns) async fn release(mut self) -> Result<(), String> {
        let Some(key) = self.key.take() else {
            return Ok(());
        };
        self.cache.metrics.proxy_dns_health_lease_released();
        Arc::clone(&self.cache)
            .release_health_proxy_udp_forwarder(key, Arc::clone(&self.forwarder))
            .await
    }
}

impl Drop for ResidentDnsHealthForwarderLease {
    fn drop(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        self.cache.metrics.proxy_dns_health_lease_released();
        self.cache
            .schedule_health_proxy_udp_forwarder_release(key, Arc::clone(&self.forwarder));
    }
}

pub(in crate::dns) enum ResidentDnsForwarderEntryKind {
    Quic(Arc<AsyncMutex<ResidentDnsQuicForwarder>>),
    ProxyQuic(Arc<AsyncMutex<ResidentDnsProxyQuicForwarder>>),
    ProxyH3(Arc<AsyncMutex<ResidentDnsProxyH3Forwarder>>),
    Udp(Arc<ResidentDnsUdpForwarder>),
    ProxyUdp(Arc<dyn ResidentDnsProxyUdpForwarder>),
    Tcp(Arc<ResidentDnsTcpForwarder>),
    Tls(Arc<ResidentDnsTlsForwarder>),
    Https(Arc<ResidentDnsHttpsForwarder>),
    H3(Arc<AsyncMutex<ResidentDnsH3Forwarder>>),
}

impl ResidentDnsForwarderEntryKind {
    pub(in crate::dns) fn owner_observation(
        &self,
    ) -> Option<Arc<ResidentDnsTransportOwnerObservation>> {
        match self {
            Self::Quic(forwarder) => forwarder
                .try_lock()
                .ok()
                .map(|forwarder| Arc::clone(&forwarder.owner_observation)),
            Self::ProxyQuic(forwarder) => forwarder
                .try_lock()
                .ok()
                .map(|forwarder| Arc::clone(&forwarder.owner_observation)),
            Self::ProxyH3(forwarder) => forwarder
                .try_lock()
                .ok()
                .map(|forwarder| Arc::clone(&forwarder.owner_observation)),
            Self::Udp(forwarder) => Some(Arc::clone(&forwarder.owner_observation)),
            Self::ProxyUdp(forwarder) => Some(forwarder.owner_observation()),
            Self::Tcp(forwarder) => Some(Arc::clone(&forwarder.owner_observation)),
            Self::Tls(forwarder) => Some(Arc::clone(&forwarder.owner_observation)),
            Self::Https(forwarder) => Some(Arc::clone(&forwarder.owner_observation)),
            Self::H3(forwarder) => forwarder
                .try_lock()
                .ok()
                .map(|forwarder| Arc::clone(&forwarder.owner_observation)),
        }
    }

    pub(in crate::dns) fn retained_outside_cache(&self) -> bool {
        match self {
            Self::Quic(forwarder) => Arc::strong_count(forwarder) > 1,
            Self::ProxyQuic(forwarder) => Arc::strong_count(forwarder) > 1,
            Self::ProxyH3(forwarder) => Arc::strong_count(forwarder) > 1,
            Self::Udp(forwarder) => Arc::strong_count(forwarder) > 1,
            Self::ProxyUdp(forwarder) => Arc::strong_count(forwarder) > 1,
            Self::Tcp(forwarder) => Arc::strong_count(forwarder) > 1,
            Self::Tls(forwarder) => Arc::strong_count(forwarder) > 1,
            Self::Https(forwarder) => Arc::strong_count(forwarder) > 1,
            Self::H3(forwarder) => Arc::strong_count(forwarder) > 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(in crate::dns) struct ResidentDnsForwarderKey {
    pub(in crate::dns) scheme: ResidentDnsUpstreamScheme,
    pub(in crate::dns) authority: Arc<str>,
    pub(in crate::dns) path: Arc<str>,
    pub(in crate::dns) mark: u32,
    pub(in crate::dns) target: Option<SocketAddr>,
    pub(in crate::dns) selection: ResidentDnsForwarderSelectionKey,
    pub(in crate::dns) transport: ResidentDnsForwarderTransport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(in crate::dns) enum ResidentDnsForwarderTransport {
    Quic,
    ProxyQuic,
    ProxyHttp3,
    Udp,
    AsisUdp,
    ProxyUdp,
    ProxyUdpHealth,
    Tcp,
    Tls,
    Https,
    Http3,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(in crate::dns) enum ResidentDnsForwarderSelectionKey {
    #[cfg(test)]
    Unrouted,
    Direct,
    Proxy {
        graph_link_hash: String,
    },
}

impl ResidentDnsForwarderSelectionKey {
    pub(in crate::dns) fn from_selection(selection: &ResidentDnsUpstreamSelection) -> Self {
        match selection {
            ResidentDnsUpstreamSelection::Direct { .. } => Self::Direct,
            ResidentDnsUpstreamSelection::Proxy { binding } => Self::Proxy {
                graph_link_hash: binding.plan().graph_link_hash.clone(),
            },
        }
    }
}

pub(in crate::dns) struct ResidentDnsQuicForwarder {
    pub(in crate::dns) owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    pub(in crate::dns) task_executor: Arc<ResidentDnsUdpActorExecutor>,
    pub(in crate::dns) upstream: ResidentDnsUpstream,
    pub(in crate::dns) generation: u64,
    pub(in crate::dns) mark: u32,
    pub(in crate::dns) fixed_remote: Option<SocketAddr>,
    pub(in crate::dns) endpoint: Option<ObservedQuicEndpoint>,
    pub(in crate::dns) connection: Option<quinn::Connection>,
    pub(in crate::dns) session_cache:
        dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache,
    pub(in crate::dns) permits: Arc<Semaphore>,
    pub(in crate::dns) open_lock: Arc<AsyncMutex<()>>,
    pub(in crate::dns) closing: bool,
}

pub(in crate::dns) struct ResidentDnsProxyQuicForwarder {
    pub(in crate::dns) owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    pub(in crate::dns) task_executor: Arc<ResidentDnsUdpActorExecutor>,
    pub(in crate::dns) upstream: ResidentDnsUpstream,
    pub(in crate::dns) remote: SocketAddr,
    pub(in crate::dns) binding: ResidentProxyBinding,
    pub(in crate::dns) proxy_udp_transport: Arc<dyn ResidentDnsProxyUdpTransport>,
    pub(in crate::dns) bridge: Option<Box<dyn ResidentDnsProxyUdpBridge>>,
    pub(in crate::dns) endpoint: Option<ObservedQuicEndpoint>,
    pub(in crate::dns) connection: Option<quinn::Connection>,
    pub(in crate::dns) session_cache:
        dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache,
    pub(in crate::dns) permits: Arc<Semaphore>,
    pub(in crate::dns) open_lock: Arc<AsyncMutex<()>>,
    pub(in crate::dns) closing: bool,
    #[cfg(test)]
    pub(in crate::dns) client_config_override: Option<quinn::ClientConfig>,
}

pub(in crate::dns) struct ResidentDnsProxyH3Forwarder {
    pub(in crate::dns) owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    pub(in crate::dns) task_executor: Arc<ResidentDnsUdpActorExecutor>,
    pub(in crate::dns) upstream: ResidentDnsUpstream,
    pub(in crate::dns) remote: SocketAddr,
    pub(in crate::dns) binding: ResidentProxyBinding,
    pub(in crate::dns) proxy_udp_transport: Arc<dyn ResidentDnsProxyUdpTransport>,
    pub(in crate::dns) metrics: Arc<ResidentDataplaneMetrics>,
    pub(in crate::dns) bridge: Option<Box<dyn ResidentDnsProxyUdpBridge>>,
    pub(in crate::dns) endpoint: Option<ObservedQuicEndpoint>,
    pub(in crate::dns) connection: Option<quinn::Connection>,
    pub(in crate::dns) session_cache:
        dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache,
    pub(in crate::dns) client: Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    pub(in crate::dns) driver_task: Option<tokio::task::JoinHandle<()>>,
    pub(in crate::dns) permits: Arc<Semaphore>,
    pub(in crate::dns) open_lock: Arc<AsyncMutex<()>>,
    pub(in crate::dns) closing: bool,
    #[cfg(test)]
    pub(in crate::dns) client_config_override: Option<quinn::ClientConfig>,
}

pub(in crate::dns) struct ResidentDnsUdpForwarder {
    pub(in crate::dns) owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    pub(in crate::dns) target: SocketAddr,
    pub(in crate::dns) mark: u32,
    pub(in crate::dns) next_shard: std::sync::atomic::AtomicUsize,
    pub(in crate::dns) executor: Arc<ResidentDnsUdpActorExecutor>,
    pub(in crate::dns) shards: Vec<ResidentDnsUdpForwarderShard>,
    pub(in crate::dns) runtime_config: ResidentDnsUdpRuntimeConfig,
}

pub(in crate::dns) struct ResidentDnsUdpForwarderShard {
    pub(in crate::dns) handle: AsyncMutex<Option<ResidentDnsUdpMultiplexHandle>>,
    pub(in crate::dns) opened: std::sync::atomic::AtomicBool,
    pub(in crate::dns) inflight: std::sync::atomic::AtomicUsize,
}

pub(in crate::dns) struct ResidentDnsTcpForwarder {
    pub(in crate::dns) owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    pub(in crate::dns) upstream: ResidentDnsUpstream,
    pub(in crate::dns) target: SocketAddr,
    pub(in crate::dns) mark: u32,
    pub(in crate::dns) connection_kind: ResidentDnsTcpConnectionKind,
    pub(in crate::dns) connection_limit: usize,
    pub(in crate::dns) request_limit: usize,
    pub(in crate::dns) connections: AsyncMutex<Vec<ResidentDnsTcpMultiplexConnection>>,
    pub(in crate::dns) open_lock: AsyncMutex<()>,
    pub(in crate::dns) closing: std::sync::atomic::AtomicBool,
}

#[derive(Clone)]
// Keeping the transport registries inline avoids a per-forwarder heap allocation on the
// proxied DNS-over-TCP hot path. The direct variant is intentionally only a marker.
#[allow(clippy::large_enum_variant)]
pub(in crate::dns) enum ResidentDnsTcpConnectionKind {
    Direct,
    Proxy {
        binding: ResidentProxyBinding,
        transport: Arc<dyn ResidentDnsProxyTcpTransport>,
    },
}

pub(in crate::dns) struct ResidentDnsTcpMultiplexConnection {
    pub(in crate::dns) handle: ResidentDnsTcpMultiplexHandle,
    pub(in crate::dns) task: tokio::task::JoinHandle<Result<(), String>>,
}

pub(in crate::dns) struct ResidentDnsTlsForwarder {
    pub(in crate::dns) owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    pub(in crate::dns) upstream: ResidentDnsUpstream,
    pub(in crate::dns) target: SocketAddr,
    pub(in crate::dns) mark: u32,
    pub(in crate::dns) idle: AsyncMutex<Vec<ResidentDnsTlsConnection>>,
    pub(in crate::dns) permits: Semaphore,
}

pub(in crate::dns) struct ResidentDnsHttpsForwarder {
    pub(in crate::dns) owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    pub(in crate::dns) upstream: ResidentDnsUpstream,
    pub(in crate::dns) target: SocketAddr,
    pub(in crate::dns) mark: u32,
    pub(in crate::dns) http1_idle: AsyncMutex<Vec<ResidentDnsTlsStream>>,
    pub(in crate::dns) http1_permits: Semaphore,
    pub(in crate::dns) h2_permits: Semaphore,
    pub(in crate::dns) h2: AsyncMutex<Option<ResidentDnsH2Forwarder>>,
    pub(in crate::dns) h2_open_lock: AsyncMutex<()>,
    pub(in crate::dns) h2_recovery: Mutex<ResidentDnsH2Recovery>,
}

pub(in crate::dns) struct ResidentDnsH2Forwarder {
    pub(in crate::dns) sender: h2::client::SendRequest<Bytes>,
    pub(in crate::dns) driver_task: tokio::task::JoinHandle<()>,
}

pub(in crate::dns) struct ResidentDnsH3Forwarder {
    pub(in crate::dns) owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    pub(in crate::dns) task_executor: Arc<ResidentDnsUdpActorExecutor>,
    pub(in crate::dns) upstream: ResidentDnsUpstream,
    pub(in crate::dns) generation: u64,
    pub(in crate::dns) target: SocketAddr,
    pub(in crate::dns) mark: u32,
    pub(in crate::dns) endpoint: Option<ObservedQuicEndpoint>,
    pub(in crate::dns) connection: Option<quinn::Connection>,
    pub(in crate::dns) session_cache:
        dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache,
    pub(in crate::dns) client: Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    pub(in crate::dns) driver_task: Option<tokio::task::JoinHandle<()>>,
    pub(in crate::dns) permits: Arc<Semaphore>,
    pub(in crate::dns) open_lock: Arc<AsyncMutex<()>>,
    pub(in crate::dns) closing: bool,
}

impl Drop for ResidentDnsQuicForwarder {
    fn drop(&mut self) {
        let _ = self.session_cache.clear();
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"dns forwarder dropped");
        }
    }
}

impl Drop for ResidentDnsProxyQuicForwarder {
    fn drop(&mut self) {
        let _ = self.session_cache.clear();
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"proxied DNS forwarder dropped");
        }
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close(0_u32.into(), b"proxied DNS forwarder dropped");
        }
    }
}

impl Drop for ResidentDnsProxyH3Forwarder {
    fn drop(&mut self) {
        let _ = self.session_cache.clear();
        self.client = None;
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"proxied DNS H3 forwarder dropped");
        }
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close(0_u32.into(), b"proxied DNS H3 forwarder dropped");
        }
        if let Some(task) = self.driver_task.take() {
            task.abort();
        }
    }
}

impl Drop for ResidentDnsH3Forwarder {
    fn drop(&mut self) {
        let _ = self.session_cache.clear();
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"dns forwarder dropped");
        }
        if let Some(task) = self.driver_task.take() {
            task.abort();
        }
    }
}

impl Drop for ResidentDnsH2Forwarder {
    fn drop(&mut self) {
        self.driver_task.abort();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(in crate::dns) enum ResidentDnsUpstreamScheme {
    Udp,
    Tcp,
    TcpUdp,
    Tls,
    Https,
    Quic,
    Http3,
}

impl ResidentDnsUpstreamScheme {
    pub(in crate::dns) const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::TcpUdp => "tcp+udp",
            Self::Tls => "tls",
            Self::Https => "https",
            Self::Quic => "quic",
            Self::Http3 => "http3",
        }
    }

    pub(in crate::dns) const fn requires_dns_response_id_match(self) -> bool {
        matches!(self, Self::Udp | Self::Tcp | Self::TcpUdp | Self::Tls)
    }
}
use crate::{ResidentDataplaneMetrics, ResidentDnsUdpRuntimeConfig};

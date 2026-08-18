use super::transport::tcp_udp::ResidentDnsTcpUdpHedgeRegistry;
use super::transport::udp_multiplex::{ResidentDnsUdpActorExecutor, ResidentDnsUdpMultiplexHandle};
use super::*;
use dae_resident_transport::resolve_host_addrs_with_bootstrap_dns_ttl;
use std::sync::{
    Weak,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::sync::Notify;

mod h2_recovery;
mod target_cache;
mod target_refresh;
pub use h2_recovery::ResidentDnsH2Recovery;
use target_cache::ResidentDnsResolvedTargetCache;
pub use target_cache::ResidentDnsResolvedTargetSnapshot;
pub use target_cache::ResidentDnsTargetRefreshError;
pub use target_refresh::{
    ResidentDnsTargetRefreshHandle, ResidentDnsTargetRefreshOwner,
    ResidentDnsTargetRefreshOwnerTask,
};

#[derive(Clone, Debug)]
pub enum ResidentDnsRequestAction {
    AsIs,
    Reject,
    Upstream(ResidentDnsUpstream),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResidentDnsResponseAction {
    Accept,
    Reject,
    Upstream(ResidentDnsUpstream),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidentDnsUpstream {
    pub index: u8,
    pub tag: String,
    pub target: ResidentDnsUpstreamTarget,
    pub scheme: ResidentDnsUpstreamScheme,
    pub path: Arc<str>,
}

#[derive(Clone, Debug)]
pub struct ResidentDnsUpstreams {
    pub by_tag: BTreeMap<String, ResidentDnsUpstream>,
    pub tag_to_index: BTreeMap<String, u8>,
    pub request_actions: Vec<ResidentDnsRequestAction>,
    pub response_actions: Vec<ResidentDnsResponseAction>,
}

#[derive(Clone, Debug)]
pub struct ResidentDnsUpstreamTarget {
    pub authority: Arc<str>,
    pub host: String,
    pub port: u16,
    pub literal_addr: Option<SocketAddr>,
    pub fallback_resolver: SocketAddr,
    pub resolver_mark: u32,
    pub resolved_addrs: Arc<ResidentDnsResolvedTargetCache>,
}

impl ResidentDnsUpstreamTarget {
    pub fn new(
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

    pub async fn resolve_addrs(&self) -> Result<ResidentDnsResolvedTargetSnapshot, String> {
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

    pub async fn refresh_after_stale_failure_and_resolve(
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

    pub fn install_target_refresh(&self, handle: ResidentDnsTargetRefreshHandle) {
        self.resolved_addrs.install_refresh_handle(handle);
    }
}

impl ResidentDnsUpstreams {
    pub fn install_target_refresh(&self, handle: ResidentDnsTargetRefreshHandle) {
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

pub struct ResidentDnsForwarderCache {
    pub state: Mutex<ResidentDnsForwarderCacheState>,
    pub health_state: Mutex<ResidentDnsForwarderCacheState>,
    pub udp_executor: Arc<ResidentDnsUdpActorExecutor>,
    pub udp_runtime: ResidentDnsUdpRuntimeConfig,
    pub resources: ResidentDnsResourceProfile,
    pub tcp_udp_hedges: ResidentDnsTcpUdpHedgeRegistry,
    pub metrics: Arc<ResidentDataplaneMetrics>,
    pub proxy_tcp_transport: Option<Arc<dyn ResidentDnsProxyTcpTransport>>,
    pub proxy_udp_transport: Arc<dyn ResidentDnsProxyUdpTransport>,
    pub quic_endpoint_transport: Arc<dyn ResidentDnsQuicEndpointTransport>,
    pub health_runtime: Option<tokio::runtime::Handle>,
    pub closing: std::sync::atomic::AtomicBool,
}

impl Default for ResidentDnsForwarderCache {
    fn default() -> Self {
        let udp_runtime = ResidentDnsUdpRuntimeConfig::standalone();
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let udp_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
            udp_runtime.clone(),
            Arc::clone(&metrics),
        ));
        let ports = ResidentDnsTransportPorts::unavailable();
        Self {
            state: Mutex::new(ResidentDnsForwarderCacheState::default()),
            health_state: Mutex::new(ResidentDnsForwarderCacheState::default()),
            udp_executor: Arc::clone(&udp_executor),
            udp_runtime: udp_runtime.clone(),
            resources: ResidentDnsResourceProfile::selected(),
            tcp_udp_hedges: ResidentDnsTcpUdpHedgeRegistry::default(),
            metrics: Arc::clone(&metrics),
            proxy_tcp_transport: Some(ports.proxy_tcp()),
            proxy_udp_transport: ports.proxy_udp(),
            quic_endpoint_transport: ports.quic_endpoint(),
            health_runtime: tokio::runtime::Handle::try_current().ok(),
            closing: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl ResidentDnsForwarderCache {
    pub fn new_with_proxy_transports(
        udp_runtime: ResidentDnsUdpRuntimeConfig,
        metrics: Arc<ResidentDataplaneMetrics>,
        health_runtime: Option<tokio::runtime::Handle>,
        udp_executor: Arc<ResidentDnsUdpActorExecutor>,
        proxy_tcp_transport: Arc<dyn ResidentDnsProxyTcpTransport>,
        proxy_udp_transport: Arc<dyn ResidentDnsProxyUdpTransport>,
        quic_endpoint_transport: Arc<dyn ResidentDnsQuicEndpointTransport>,
    ) -> Self {
        Self {
            state: Mutex::new(ResidentDnsForwarderCacheState::default()),
            health_state: Mutex::new(ResidentDnsForwarderCacheState::default()),
            udp_executor,
            udp_runtime,
            resources: ResidentDnsResourceProfile::selected(),
            tcp_udp_hedges: ResidentDnsTcpUdpHedgeRegistry::default(),
            metrics,
            proxy_tcp_transport: Some(proxy_tcp_transport),
            proxy_udp_transport,
            quic_endpoint_transport,
            health_runtime,
            closing: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

#[cfg(all(test, feature = "dns-runtime-tests"))]
pub fn test_resident_dns_forwarder_cache() -> ResidentDnsForwarderCache {
    let udp_runtime = ResidentDnsUdpRuntimeConfig::standalone();
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let udp_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        udp_runtime.clone(),
        Arc::clone(&metrics),
    ));
    let owners = ResidentTransportOwnerRegistries::default();
    ResidentDnsForwarderCache::new_with_proxy_transports(
        udp_runtime.clone(),
        Arc::clone(&metrics),
        tokio::runtime::Handle::try_current().ok(),
        Arc::clone(&udp_executor),
        resident_dns_proxy_tcp_transport(owners.clone()),
        resident_dns_proxy_udp_transport(udp_runtime, metrics, udp_executor, owners),
        Arc::new(ResidentDnsQuicEndpointPolicy),
    )
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
pub struct ResidentDnsForwarderCacheState {
    pub entries: BTreeMap<ResidentDnsForwarderKey, ResidentDnsForwarderEntry>,
    pub lru: BTreeSet<(u64, ResidentDnsForwarderKey)>,
    pub next_tick: u64,
    pub retired: Vec<ResidentDnsRetiredForwarder>,
}

pub struct ResidentDnsRetiredForwarder {
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
    pub fn from_entry(entry: &ResidentDnsForwarderEntry) -> Self {
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

    pub fn is_alive(&self) -> bool {
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

    pub fn upgrade(
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

pub struct ResidentDnsForwarderEntry {
    pub last_used: u64,
    pub kind: ResidentDnsForwarderEntryKind,
    pub owner_observation: Option<Arc<ResidentDnsTransportOwnerObservation>>,
    pub health_leases: usize,
    pub health_close: Option<Arc<ResidentDnsHealthForwarderClose>>,
}

pub struct ResidentDnsHealthForwarderClose {
    complete: AtomicBool,
    successful: AtomicBool,
    notify: Notify,
}

impl ResidentDnsHealthForwarderClose {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            complete: AtomicBool::new(false),
            successful: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    pub async fn wait(&self) -> bool {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        if !self.complete.load(Ordering::Acquire) {
            notified.await;
        }
        self.successful.load(Ordering::Acquire)
    }

    pub fn finish(&self, successful: bool) {
        self.successful.store(successful, Ordering::Release);
        self.complete.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
}

pub struct ResidentDnsHealthForwarderLease {
    cache: Arc<ResidentDnsForwarderCache>,
    key: Option<ResidentDnsForwarderKey>,
    forwarder: Arc<dyn ResidentDnsProxyUdpForwarder>,
}

impl ResidentDnsHealthForwarderLease {
    pub fn new(
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

    pub fn forwarder(&self) -> Arc<dyn ResidentDnsProxyUdpForwarder> {
        Arc::clone(&self.forwarder)
    }

    pub async fn release(mut self) -> Result<(), String> {
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

pub enum ResidentDnsForwarderEntryKind {
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
    pub fn owner_observation(&self) -> Option<Arc<ResidentDnsTransportOwnerObservation>> {
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

    pub fn retained_outside_cache(&self) -> bool {
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
pub struct ResidentDnsForwarderKey {
    pub scheme: ResidentDnsUpstreamScheme,
    pub authority: Arc<str>,
    pub path: Arc<str>,
    pub mark: u32,
    pub target: Option<SocketAddr>,
    pub selection: ResidentDnsForwarderSelectionKey,
    pub transport: ResidentDnsForwarderTransport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ResidentDnsForwarderTransport {
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
pub enum ResidentDnsForwarderSelectionKey {
    #[cfg(all(test, feature = "dns-runtime-tests"))]
    Unrouted,
    Direct,
    Proxy {
        graph_link_hash: String,
    },
}

impl ResidentDnsForwarderSelectionKey {
    pub fn from_selection(selection: &ResidentDnsUpstreamSelection) -> Self {
        match selection {
            ResidentDnsUpstreamSelection::Direct { .. } => Self::Direct,
            ResidentDnsUpstreamSelection::Proxy { binding } => Self::Proxy {
                graph_link_hash: binding.plan().graph_link_hash.clone(),
            },
        }
    }
}

pub struct ResidentDnsQuicForwarder {
    pub owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    pub task_executor: Arc<ResidentDnsUdpActorExecutor>,
    pub upstream: ResidentDnsUpstream,
    pub generation: u64,
    pub mark: u32,
    pub fixed_remote: Option<SocketAddr>,
    pub quic_endpoint_transport: Arc<dyn ResidentDnsQuicEndpointTransport>,
    pub endpoint: Option<ObservedQuicEndpoint>,
    pub connection: Option<quinn::Connection>,
    pub session_cache: dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache,
    pub permits: Arc<Semaphore>,
    pub open_lock: Arc<AsyncMutex<()>>,
    pub closing: bool,
}

pub struct ResidentDnsProxyQuicForwarder {
    pub owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    pub task_executor: Arc<ResidentDnsUdpActorExecutor>,
    pub upstream: ResidentDnsUpstream,
    pub remote: SocketAddr,
    pub binding: ResidentProxyBinding,
    pub proxy_udp_transport: Arc<dyn ResidentDnsProxyUdpTransport>,
    pub quic_endpoint_transport: Arc<dyn ResidentDnsQuicEndpointTransport>,
    pub bridge: Option<Box<dyn ResidentDnsProxyUdpBridge>>,
    pub endpoint: Option<ObservedQuicEndpoint>,
    pub connection: Option<quinn::Connection>,
    pub session_cache: dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache,
    pub permits: Arc<Semaphore>,
    pub open_lock: Arc<AsyncMutex<()>>,
    pub closing: bool,
    #[cfg(all(test, feature = "dns-runtime-tests"))]
    pub client_config_override: Option<quinn::ClientConfig>,
}

pub struct ResidentDnsProxyH3Forwarder {
    pub owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    pub task_executor: Arc<ResidentDnsUdpActorExecutor>,
    pub upstream: ResidentDnsUpstream,
    pub remote: SocketAddr,
    pub binding: ResidentProxyBinding,
    pub proxy_udp_transport: Arc<dyn ResidentDnsProxyUdpTransport>,
    pub quic_endpoint_transport: Arc<dyn ResidentDnsQuicEndpointTransport>,
    pub metrics: Arc<ResidentDataplaneMetrics>,
    pub bridge: Option<Box<dyn ResidentDnsProxyUdpBridge>>,
    pub endpoint: Option<ObservedQuicEndpoint>,
    pub connection: Option<quinn::Connection>,
    pub session_cache: dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache,
    pub client: Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    pub driver_task: Option<tokio::task::JoinHandle<()>>,
    pub permits: Arc<Semaphore>,
    pub open_lock: Arc<AsyncMutex<()>>,
    pub closing: bool,
    #[cfg(all(test, feature = "dns-runtime-tests"))]
    pub client_config_override: Option<quinn::ClientConfig>,
}

pub struct ResidentDnsUdpForwarder {
    pub owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    pub target: SocketAddr,
    pub mark: u32,
    pub next_shard: std::sync::atomic::AtomicUsize,
    pub executor: Arc<ResidentDnsUdpActorExecutor>,
    pub shards: Vec<ResidentDnsUdpForwarderShard>,
    pub runtime_config: ResidentDnsUdpRuntimeConfig,
}

pub struct ResidentDnsUdpForwarderShard {
    pub handle: AsyncMutex<Option<ResidentDnsUdpMultiplexHandle>>,
    pub opened: std::sync::atomic::AtomicBool,
    pub inflight: std::sync::atomic::AtomicUsize,
}

pub struct ResidentDnsTcpForwarder {
    pub owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    pub upstream: ResidentDnsUpstream,
    pub target: SocketAddr,
    pub mark: u32,
    pub connection_kind: ResidentDnsTcpConnectionKind,
    pub connection_limit: usize,
    pub request_limit: usize,
    pub connections: AsyncMutex<Vec<ResidentDnsTcpMultiplexConnection>>,
    pub open_lock: AsyncMutex<()>,
    pub closing: std::sync::atomic::AtomicBool,
}

#[derive(Clone)]
// Keeping the transport registries inline avoids a per-forwarder heap allocation on the
// proxied DNS-over-TCP hot path. The direct variant is intentionally only a marker.
#[allow(clippy::large_enum_variant)]
pub enum ResidentDnsTcpConnectionKind {
    Direct,
    Proxy {
        binding: ResidentProxyBinding,
        transport: Arc<dyn ResidentDnsProxyTcpTransport>,
    },
}

pub struct ResidentDnsTcpMultiplexConnection {
    pub handle: ResidentDnsTcpMultiplexHandle,
    pub task: tokio::task::JoinHandle<Result<(), String>>,
}

pub struct ResidentDnsTlsForwarder {
    pub owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    pub upstream: ResidentDnsUpstream,
    pub target: SocketAddr,
    pub mark: u32,
    pub idle: AsyncMutex<Vec<ResidentDnsTlsConnection>>,
    pub permits: Semaphore,
}

pub struct ResidentDnsHttpsForwarder {
    pub owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    pub upstream: ResidentDnsUpstream,
    pub target: SocketAddr,
    pub mark: u32,
    pub http1_idle: AsyncMutex<Vec<ResidentDnsTlsStream>>,
    pub http1_permits: Semaphore,
    pub h2_permits: Semaphore,
    pub h2: AsyncMutex<Option<ResidentDnsH2Forwarder>>,
    pub h2_open_lock: AsyncMutex<()>,
    pub h2_recovery: Mutex<ResidentDnsH2Recovery>,
}

pub struct ResidentDnsH2Forwarder {
    pub sender: h2::client::SendRequest<Bytes>,
    pub driver_task: tokio::task::JoinHandle<()>,
}

pub struct ResidentDnsH3Forwarder {
    pub owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    pub task_executor: Arc<ResidentDnsUdpActorExecutor>,
    pub upstream: ResidentDnsUpstream,
    pub generation: u64,
    pub target: SocketAddr,
    pub mark: u32,
    pub quic_endpoint_transport: Arc<dyn ResidentDnsQuicEndpointTransport>,
    pub endpoint: Option<ObservedQuicEndpoint>,
    pub connection: Option<quinn::Connection>,
    pub session_cache: dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache,
    pub client: Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    pub driver_task: Option<tokio::task::JoinHandle<()>>,
    pub permits: Arc<Semaphore>,
    pub open_lock: Arc<AsyncMutex<()>>,
    pub closing: bool,
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
pub enum ResidentDnsUpstreamScheme {
    Udp,
    Tcp,
    TcpUdp,
    Tls,
    Https,
    Quic,
    Http3,
}

impl ResidentDnsUpstreamScheme {
    pub const fn as_str(self) -> &'static str {
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

    pub const fn requires_dns_response_id_match(self) -> bool {
        matches!(self, Self::Udp | Self::Tcp | Self::TcpUdp | Self::Tls)
    }
}
use crate::ResidentDnsUdpRuntimeConfig;
use dae_resident_core::ResidentDataplaneMetrics;

use super::transport::udp_multiplex::{ResidentDnsUdpActorExecutor, ResidentDnsUdpMultiplexHandle};
use super::*;
use std::sync::{
    Weak,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

mod h2_recovery;
mod target_cache;
pub(in crate::production_runtime_owner::resident_dataplane::dns) use h2_recovery::ResidentDnsH2Recovery;
use target_cache::ResidentDnsResolvedTargetCache;

#[derive(Clone, Debug)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) enum ResidentDnsRequestAction {
    AsIs,
    Reject,
    Upstream(ResidentDnsUpstream),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) enum ResidentDnsResponseAction {
    Accept,
    Reject,
    Upstream(ResidentDnsUpstream),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsUpstream {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) index: u8,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) tag: String,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) target:
        ResidentDnsUpstreamTarget,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) scheme:
        ResidentDnsUpstreamScheme,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) path: String,
}

#[derive(Clone, Debug)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsUpstreams {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) by_tag:
        BTreeMap<String, ResidentDnsUpstream>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) tag_to_index:
        BTreeMap<String, u8>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) request_actions:
        Vec<ResidentDnsRequestAction>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) response_actions:
        Vec<ResidentDnsResponseAction>,
}

#[derive(Clone, Debug)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsUpstreamTarget {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) authority: String,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) host: String,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) port: u16,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) literal_addr:
        Option<SocketAddr>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fallback_resolver: SocketAddr,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) resolver_mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) resolved_addrs:
        Arc<ResidentDnsResolvedTargetCache>,
}

impl ResidentDnsUpstreamTarget {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn new(
        authority: String,
        host: String,
        port: u16,
        literal_addr: Option<SocketAddr>,
        fallback_resolver: SocketAddr,
        resolver_mark: u32,
        refresh_interval: Duration,
    ) -> Self {
        Self {
            authority,
            host,
            port,
            literal_addr,
            fallback_resolver,
            resolver_mark,
            resolved_addrs: Arc::new(ResidentDnsResolvedTargetCache::new(refresh_interval)),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) async fn resolve_addrs(
        &self,
    ) -> Result<Vec<SocketAddr>, String> {
        if let Some(addr) = self.literal_addr {
            return Ok(vec![addr]);
        }
        self.resolved_addrs
            .resolve(|refresh_interval| async move {
                resolve_host_addrs_with_configured_fallback_dns_ttl(
                    &self.host,
                    self.port,
                    self.fallback_resolver,
                    self.resolver_mark,
                    "resolve DNS upstream",
                    refresh_interval,
                )
                .await
            })
            .await
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

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsForwarderCache {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) state:
        Mutex<ResidentDnsForwarderCacheState>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) health_state:
        Mutex<ResidentDnsForwarderCacheState>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) udp_executor:
        Arc<ResidentDnsUdpActorExecutor>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) udp_runtime:
        ResidentDnsUdpRuntimeConfig,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) metrics:
        Arc<ResidentDataplaneMetrics>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) hysteria2_owner_registry:
        Option<Hysteria2OwnerRegistryHandle>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) tuic_owner_registry:
        Option<TuicOwnerRegistryHandle>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) juicity_owner_registry:
        Option<JuicityOwnerRegistryHandle>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) closing:
        std::sync::atomic::AtomicBool,
}

impl Default for ResidentDnsForwarderCache {
    fn default() -> Self {
        let udp_runtime = ResidentDnsUdpRuntimeConfig::standalone();
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        Self {
            state: Mutex::new(ResidentDnsForwarderCacheState::default()),
            health_state: Mutex::new(ResidentDnsForwarderCacheState::default()),
            udp_executor: Arc::new(ResidentDnsUdpActorExecutor::new(
                udp_runtime.clone(),
                Arc::clone(&metrics),
            )),
            udp_runtime,
            metrics,
            hysteria2_owner_registry: None,
            tuic_owner_registry: None,
            juicity_owner_registry: None,
            closing: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl ResidentDnsForwarderCache {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn new(
        udp_runtime: ResidentDnsUdpRuntimeConfig,
        metrics: Arc<ResidentDataplaneMetrics>,
    ) -> Self {
        Self {
            state: Mutex::new(ResidentDnsForwarderCacheState::default()),
            health_state: Mutex::new(ResidentDnsForwarderCacheState::default()),
            udp_executor: Arc::new(ResidentDnsUdpActorExecutor::new(
                udp_runtime.clone(),
                Arc::clone(&metrics),
            )),
            udp_runtime,
            metrics,
            hysteria2_owner_registry: None,
            tuic_owner_registry: None,
            juicity_owner_registry: None,
            closing: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn new_with_transport_owner(
        udp_runtime: ResidentDnsUdpRuntimeConfig,
        metrics: Arc<ResidentDataplaneMetrics>,
        hysteria2_owner_registry: Hysteria2OwnerRegistryHandle,
        tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
        juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    ) -> Self {
        let mut cache = Self::new(udp_runtime, metrics);
        cache.hysteria2_owner_registry = Some(hysteria2_owner_registry);
        cache.tuic_owner_registry = tuic_owner_registry;
        cache.juicity_owner_registry = juicity_owner_registry;
        cache
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn hysteria2_owner_registry(
        &self,
    ) -> Result<Hysteria2OwnerRegistryHandle, String> {
        self.hysteria2_owner_registry.clone().ok_or_else(|| {
            "Hysteria2 transport owner registry is unavailable for proxied DNS".to_owned()
        })
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
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsForwarderCacheState
{
    pub(in crate::production_runtime_owner::resident_dataplane::dns) entries:
        BTreeMap<ResidentDnsForwarderKey, ResidentDnsForwarderEntry>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) lru:
        BTreeSet<(u64, ResidentDnsForwarderKey)>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) next_tick: u64,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) retired:
        Vec<ResidentDnsRetiredForwarder>,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsRetiredForwarder
{
    kind: ResidentDnsRetiredForwarderKind,
    owner_observation: Option<Weak<ResidentDnsTransportOwnerObservation>>,
}

enum ResidentDnsRetiredForwarderKind {
    Quic(Weak<AsyncMutex<ResidentDnsQuicForwarder>>),
    ProxyQuic(Weak<AsyncMutex<ResidentDnsProxyQuicForwarder>>),
    ProxyH3(Weak<AsyncMutex<ResidentDnsProxyH3Forwarder>>),
    Udp(Weak<ResidentDnsUdpForwarder>),
    ProxyUdp(Weak<ResidentProxyDnsUdpForwarder>),
    Tcp(Weak<ResidentDnsTcpForwarder>),
    Tls(Weak<ResidentDnsTlsForwarder>),
    Https(Weak<ResidentDnsHttpsForwarder>),
    H3(Weak<AsyncMutex<ResidentDnsH3Forwarder>>),
}

impl ResidentDnsRetiredForwarder {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn from_entry(
        entry: &ResidentDnsForwarderEntry,
    ) -> Self {
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

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn is_alive(&self) -> bool {
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

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn upgrade(
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

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsForwarderEntry {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) last_used: u64,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) kind:
        ResidentDnsForwarderEntryKind,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) owner_observation:
        Option<Arc<ResidentDnsTransportOwnerObservation>>,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) enum ResidentDnsForwarderEntryKind
{
    Quic(Arc<AsyncMutex<ResidentDnsQuicForwarder>>),
    ProxyQuic(Arc<AsyncMutex<ResidentDnsProxyQuicForwarder>>),
    ProxyH3(Arc<AsyncMutex<ResidentDnsProxyH3Forwarder>>),
    Udp(Arc<ResidentDnsUdpForwarder>),
    ProxyUdp(Arc<ResidentProxyDnsUdpForwarder>),
    Tcp(Arc<ResidentDnsTcpForwarder>),
    Tls(Arc<ResidentDnsTlsForwarder>),
    Https(Arc<ResidentDnsHttpsForwarder>),
    H3(Arc<AsyncMutex<ResidentDnsH3Forwarder>>),
}

impl ResidentDnsForwarderEntryKind {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn owner_observation(
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

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn retained_outside_cache(
        &self,
    ) -> bool {
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
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsForwarderKey {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) scheme:
        ResidentDnsUpstreamScheme,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) authority: String,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) path: String,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) target: Option<SocketAddr>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) selection:
        ResidentDnsForwarderSelectionKey,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) transport:
        ResidentDnsForwarderTransport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) enum ResidentDnsForwarderTransport
{
    Quic,
    ProxyQuic,
    ProxyHttp3,
    Udp,
    ProxyUdp,
    ProxyUdpHealth,
    Tcp,
    Tls,
    Https,
    Http3,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) enum ResidentDnsForwarderSelectionKey
{
    Unrouted,
    Direct,
    Proxy { graph_link_hash: String },
}

impl ResidentDnsForwarderSelectionKey {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn from_selection(
        selection: &ResidentDnsUpstreamSelection,
    ) -> Self {
        match selection {
            ResidentDnsUpstreamSelection::Direct { .. } => Self::Direct,
            ResidentDnsUpstreamSelection::Proxy { proxy } => Self::Proxy {
                graph_link_hash: proxy.graph_link_hash.clone(),
            },
        }
    }
}

pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentDnsTransportOwnerObservation
{
    metrics: Arc<ResidentDataplaneMetrics>,
    charged_bytes: usize,
    evicted: AtomicBool,
    released: AtomicBool,
}

impl ResidentDnsTransportOwnerObservation {
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(
        metrics: Arc<ResidentDataplaneMetrics>,
        charged_bytes: usize,
    ) -> Arc<Self> {
        metrics.dns_transport_owner_opened(charged_bytes);
        Arc::new(Self {
            metrics,
            charged_bytes,
            evicted: AtomicBool::new(false),
            released: AtomicBool::new(false),
        })
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn mark_evicted(&self) {
        if !self.evicted.swap(true, Ordering::AcqRel) {
            self.metrics.dns_transport_owner_evicted();
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn release(&self) {
        if !self.released.swap(true, Ordering::AcqRel) {
            self.metrics.dns_transport_owner_released(
                self.charged_bytes,
                self.evicted.load(Ordering::Acquire),
            );
        }
    }
}

impl Drop for ResidentDnsTransportOwnerObservation {
    fn drop(&mut self) {
        self.release();
    }
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsQuicForwarder {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) owner_observation:
        Arc<ResidentDnsTransportOwnerObservation>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) task_executor:
        Arc<ResidentDnsUdpActorExecutor>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) upstream: ResidentDnsUpstream,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) generation: u64,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fixed_remote:
        Option<SocketAddr>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) endpoint:
        Option<ObservedQuicEndpoint>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) connection:
        Option<quinn::Connection>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) permits: Arc<Semaphore>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) open_lock: Arc<AsyncMutex<()>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) closing: bool,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsProxyQuicForwarder
{
    pub(in crate::production_runtime_owner::resident_dataplane::dns) owner_observation:
        Arc<ResidentDnsTransportOwnerObservation>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) task_executor:
        Arc<ResidentDnsUdpActorExecutor>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) upstream: ResidentDnsUpstream,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) remote: SocketAddr,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) proxy: Arc<ResidentProxyPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) owners:
        ResidentTransportOwnerRegistries,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) bridge:
        Option<ResidentProxyUdpBridge>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) endpoint:
        Option<ObservedQuicEndpoint>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) connection:
        Option<quinn::Connection>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) permits: Arc<Semaphore>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) open_lock: Arc<AsyncMutex<()>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) closing: bool,
    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane::dns) client_config_override:
        Option<quinn::ClientConfig>,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsProxyH3Forwarder
{
    pub(in crate::production_runtime_owner::resident_dataplane::dns) owner_observation:
        Arc<ResidentDnsTransportOwnerObservation>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) task_executor:
        Arc<ResidentDnsUdpActorExecutor>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) upstream: ResidentDnsUpstream,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) remote: SocketAddr,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) proxy: Arc<ResidentProxyPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) owners:
        ResidentTransportOwnerRegistries,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) metrics:
        Arc<ResidentDataplaneMetrics>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) bridge:
        Option<ResidentProxyUdpBridge>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) endpoint:
        Option<ObservedQuicEndpoint>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) connection:
        Option<quinn::Connection>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) client:
        Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) driver_task:
        Option<tokio::task::JoinHandle<()>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) permits: Arc<Semaphore>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) open_lock: Arc<AsyncMutex<()>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) closing: bool,
    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane::dns) client_config_override:
        Option<quinn::ClientConfig>,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsUdpForwarder {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) owner_observation:
        Arc<ResidentDnsTransportOwnerObservation>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) target: SocketAddr,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) next_shard:
        std::sync::atomic::AtomicUsize,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) executor:
        Arc<ResidentDnsUdpActorExecutor>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) shards:
        Vec<ResidentDnsUdpForwarderShard>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) runtime_config:
        ResidentDnsUdpRuntimeConfig,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsUdpForwarderShard
{
    pub(in crate::production_runtime_owner::resident_dataplane::dns) handle:
        AsyncMutex<Option<ResidentDnsUdpMultiplexHandle>>,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsTcpForwarder {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) owner_observation:
        Arc<ResidentDnsTransportOwnerObservation>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) upstream: ResidentDnsUpstream,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) target: SocketAddr,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) idle:
        AsyncMutex<Vec<TokioTcpStream>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) permits: Semaphore,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsTlsForwarder {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) owner_observation:
        Arc<ResidentDnsTransportOwnerObservation>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) upstream: ResidentDnsUpstream,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) target: SocketAddr,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) idle:
        AsyncMutex<Vec<tokio_rustls::client::TlsStream<TokioTcpStream>>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) permits: Semaphore,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsHttpsForwarder {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) owner_observation:
        Arc<ResidentDnsTransportOwnerObservation>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) upstream: ResidentDnsUpstream,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) target: SocketAddr,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) http1_idle:
        AsyncMutex<Vec<tokio_rustls::client::TlsStream<TokioTcpStream>>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) http1_permits: Semaphore,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) h2_permits: Semaphore,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) h2:
        AsyncMutex<Option<ResidentDnsH2Forwarder>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) h2_open_lock: AsyncMutex<()>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) h2_recovery:
        Mutex<ResidentDnsH2Recovery>,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsH2Forwarder {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) sender:
        h2::client::SendRequest<Bytes>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) driver_task:
        tokio::task::JoinHandle<()>,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsH3Forwarder {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) owner_observation:
        Arc<ResidentDnsTransportOwnerObservation>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) task_executor:
        Arc<ResidentDnsUdpActorExecutor>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) upstream: ResidentDnsUpstream,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) generation: u64,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) target: SocketAddr,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) endpoint:
        Option<ObservedQuicEndpoint>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) connection:
        Option<quinn::Connection>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) client:
        Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) driver_task:
        Option<tokio::task::JoinHandle<()>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) permits: Arc<Semaphore>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) open_lock: Arc<AsyncMutex<()>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) closing: bool,
}

impl Drop for ResidentDnsQuicForwarder {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"dns forwarder dropped");
        }
    }
}

impl Drop for ResidentDnsProxyQuicForwarder {
    fn drop(&mut self) {
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
pub(in crate::production_runtime_owner::resident_dataplane::dns) enum ResidentDnsUpstreamScheme {
    Udp,
    Tcp,
    TcpUdp,
    Tls,
    Https,
    Quic,
    Http3,
}

impl ResidentDnsUpstreamScheme {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) const fn as_str(
        self,
    ) -> &'static str {
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

    pub(in crate::production_runtime_owner::resident_dataplane::dns) const fn requires_dns_response_id_match(
        self,
    ) -> bool {
        matches!(self, Self::Udp | Self::Tcp | Self::TcpUdp | Self::Tls)
    }
}
use crate::production_runtime_owner::resident_dataplane::{
    ResidentDataplaneMetrics, ResidentDnsUdpRuntimeConfig,
};

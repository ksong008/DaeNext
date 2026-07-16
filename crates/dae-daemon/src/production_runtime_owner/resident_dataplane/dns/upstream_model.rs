use super::transport::udp_multiplex::{ResidentDnsUdpActorExecutor, ResidentDnsUdpMultiplexHandle};
use super::*;
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
    pub(in crate::production_runtime_owner::resident_dataplane::dns) udp_executor:
        Arc<ResidentDnsUdpActorExecutor>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) udp_runtime:
        ResidentDnsUdpRuntimeConfig,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) metrics:
        Arc<ResidentDataplaneMetrics>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) closing:
        std::sync::atomic::AtomicBool,
}

impl Default for ResidentDnsForwarderCache {
    fn default() -> Self {
        let udp_runtime = ResidentDnsUdpRuntimeConfig::standalone();
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        Self {
            state: Mutex::new(ResidentDnsForwarderCacheState::default()),
            udp_executor: Arc::new(ResidentDnsUdpActorExecutor::new(
                udp_runtime.clone(),
                Arc::clone(&metrics),
            )),
            udp_runtime,
            metrics,
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
            udp_executor: Arc::new(ResidentDnsUdpActorExecutor::new(
                udp_runtime.clone(),
                Arc::clone(&metrics),
            )),
            udp_runtime,
            metrics,
            closing: std::sync::atomic::AtomicBool::new(false),
        }
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
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsForwarderEntry {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) last_used: u64,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) kind:
        ResidentDnsForwarderEntryKind,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) enum ResidentDnsForwarderEntryKind
{
    Quic(Arc<AsyncMutex<ResidentDnsQuicForwarder>>),
    Udp(Arc<ResidentDnsUdpForwarder>),
    ProxyUdp(Arc<ResidentProxyDnsUdpForwarder>),
    Tcp(Arc<ResidentDnsTcpForwarder>),
    Tls(Arc<ResidentDnsTlsForwarder>),
    Https(Arc<ResidentDnsHttpsForwarder>),
    H3(Arc<AsyncMutex<ResidentDnsH3Forwarder>>),
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
    Udp,
    ProxyUdp,
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

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsQuicForwarder {
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
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsUdpForwarder {
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
    pub(in crate::production_runtime_owner::resident_dataplane::dns) upstream: ResidentDnsUpstream,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) target: SocketAddr,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) idle:
        AsyncMutex<Vec<TokioTcpStream>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) permits: Semaphore,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsTlsForwarder {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) upstream: ResidentDnsUpstream,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) target: SocketAddr,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) idle:
        AsyncMutex<Vec<tokio_rustls::client::TlsStream<TokioTcpStream>>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) permits: Semaphore,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsHttpsForwarder {
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
}

impl Drop for ResidentDnsQuicForwarder {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"dns forwarder dropped");
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

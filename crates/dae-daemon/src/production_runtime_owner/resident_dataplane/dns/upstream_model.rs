use super::transport::udp_multiplex::ResidentDnsUdpMultiplexHandle;
use super::*;

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
        Arc<OnceCell<Vec<SocketAddr>>>,
}

impl ResidentDnsUpstreamTarget {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) async fn resolve_addrs(
        &self,
    ) -> Result<Vec<SocketAddr>, String> {
        if let Some(addr) = self.literal_addr {
            return Ok(vec![addr]);
        }
        self.resolved_addrs
            .get_or_try_init(|| async {
                resolve_host_addrs_with_configured_fallback_dns(
                    &self.host,
                    self.port,
                    self.fallback_resolver,
                    self.resolver_mark,
                    "resolve DNS upstream",
                )
                .await
            })
            .await
            .cloned()
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
}

impl Default for ResidentDnsForwarderCache {
    fn default() -> Self {
        Self {
            state: Mutex::new(ResidentDnsForwarderCacheState::default()),
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
            .finish()
    }
}

#[derive(Default)]
pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsForwarderCacheState
{
    pub(in crate::production_runtime_owner::resident_dataplane::dns) entries:
        BTreeMap<ResidentDnsForwarderKey, ResidentDnsForwarderEntry>,
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
    pub(in crate::production_runtime_owner::resident_dataplane::dns) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fixed_remote:
        Option<SocketAddr>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) endpoint:
        Option<quinn::Endpoint>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) connection:
        Option<quinn::Connection>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) permits: Arc<Semaphore>,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsUdpForwarder {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) target: SocketAddr,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) next_shard:
        std::sync::atomic::AtomicUsize,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) shards:
        Vec<ResidentDnsUdpForwarderShard>,
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
    pub(in crate::production_runtime_owner::resident_dataplane::dns) h2_disabled:
        std::sync::atomic::AtomicBool,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsH2Forwarder {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) sender:
        h2::client::SendRequest<Bytes>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) driver_task:
        tokio::task::JoinHandle<()>,
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsH3Forwarder {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) upstream: ResidentDnsUpstream,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) target: SocketAddr,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) endpoint:
        Option<quinn::Endpoint>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) connection:
        Option<quinn::Connection>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) client:
        Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) driver_task:
        Option<tokio::task::JoinHandle<()>>,
    pub(in crate::production_runtime_owner::resident_dataplane::dns) permits: Arc<Semaphore>,
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

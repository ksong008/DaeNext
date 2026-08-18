use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::{Buf, Bytes};
use dae_config::{Config, DynamicFunctionValue, Function, Param, RoutingRule};
use dae_datapath::{OUTBOUND_BLOCK, OUTBOUND_CONTROL_PLANE_ROUTING, OUTBOUND_DIRECT};
use dae_dns::{
    DNS_DEFAULT_PORT, DOH_MEDIA_TYPE, DnsCacheKey, DnsDomainSet, DnsPacketView,
    DnsRequestMatchKind, DnsRequestMatchSpec, DnsRequestOutboundIndex, DnsResponseMatchKind,
    DnsResponseMatchSpec, DnsResponseOutboundIndex, RequestMatcher, ResponseMatcher,
    build_doh_request, build_response_cache_plan_from_packet, dns_data_with_zero_id,
    restore_packed_response_request_id, validate_dns_packet_response_for_request_fast,
    validate_doh_response,
};
use dae_outbound::{L4Proto, NetworkType};
use dae_routing::{IpPrefix, Query, RoutingMatcher};
use http::Request;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio::time;

#[cfg(all(test, feature = "dns-runtime-tests"))]
use super::geodata::GeodataResolver as ResidentGeodataStore;
#[cfg(all(test, feature = "dns-runtime-tests"))]
use super::host_routing_plan::build_resident_userspace_routing_matcher_with_geodata;
#[cfg(all(test, feature = "dns-runtime-tests"))]
use super::open_marked_quic_endpoint_for_remote;
#[cfg(all(test, feature = "dns-runtime-tests"))]
use super::plan::{ResidentDnsProxyGroupSelector, SharedResidentProxyGroupMap};
#[cfg(all(test, feature = "dns-runtime-tests"))]
use super::plan::{ResidentProxyPlan, build_resident_dataplane_plan, share_resident_proxy_groups};
#[cfg(all(test, feature = "dns-runtime-tests"))]
use super::udp::ResidentProxyUdpBridge;
#[cfg(all(test, feature = "dns-runtime-tests"))]
use super::{
    ResidentTransportOwnerRegistries, resident_dns_proxy_tcp_transport,
    resident_dns_proxy_udp_transport,
};
#[cfg(all(test, feature = "dns-runtime-tests"))]
use crate::transport::quic_endpoint::ResidentDnsQuicEndpointPolicy;
use dae_resident_core::{
    RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE, RESIDENT_UDP_RESPONSE_TIMEOUT, ResidentDataplaneMetrics,
    ResidentDnsResourceProfile, SharedResidentStopSignal, apply_udp_socket_buffer_tuning,
    set_socket_mark,
};
use dae_resident_plan::{ResidentProxyBinding, effective_so_mark_from_dae};
use dae_resident_transport::{
    ObservedQuicEndpoint, QuicEndpointCallerClass, QuicEndpointIdentityRole,
    QuicEndpointOpenContext, QuicEndpointProtocol, open_direct_tcp_connection_async,
    scope_quic_endpoint_observation,
};

/// One bounded DNS TLS stream type keeps framing, pooling, and HTTP/2 ownership
/// identical across all DNS TLS transports. BoringSSL is selected at handshake
/// construction and errors never trigger a provider fallback.
pub enum ResidentDnsTlsStream {
    Boring(tokio_boring::SslStream<TokioTcpStream>),
}

pub struct ResidentDnsTlsConnection {
    pub tls: ResidentDnsTlsStream,
    pub reader: DnsTcpFrameReader,
}

impl AsyncRead for ResidentDnsTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let Self::Boring(stream) = self.get_mut();
        Pin::new(stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for ResidentDnsTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let Self::Boring(stream) = self.get_mut();
        Pin::new(stream).poll_write(cx, data)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let Self::Boring(stream) = self.get_mut();
        Pin::new(stream).poll_write_vectored(cx, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        let Self::Boring(stream) = self;
        stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let Self::Boring(stream) = self.get_mut();
        Pin::new(stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let Self::Boring(stream) = self.get_mut();
        Pin::new(stream).poll_shutdown(cx)
    }
}

impl ResidentDnsTlsStream {
    pub fn alpn_protocol(&self) -> Option<Vec<u8>> {
        let Self::Boring(stream) = self;
        stream.ssl().selected_alpn_protocol().map(ToOwned::to_owned)
    }
}

mod reload;
mod routing;
mod trace_summary;
mod transport;
mod upstream_model;
mod upstream_router;
pub use self::reload::ResidentDnsReloadHandle;
use self::reload::ResidentDnsReloadRestoreReport;
pub use self::reload::ResidentDnsReloadSnapshot;
#[cfg(all(test, feature = "dns-runtime-tests"))]
use self::routing::parse_dns_upstream;
use self::routing::{
    build_request_matcher, build_response_matcher, parse_dns_upstreams,
    parse_request_default_action, parse_response_default_action, select_request_action,
    select_response_action, select_response_action_for_upstream,
};
pub use self::trace_summary::{ResidentDnsTraceSummary, ResidentDnsTransportTrace};
use self::trace_summary::{
    ResidentDnsTransportTraceInput, capture_dns_transport_trace_async, record_dns_transport_trace,
};
#[cfg(all(test, feature = "dns-runtime-tests"))]
use self::transport::parse_doh_http_response;
pub use self::transport::udp_multiplex::{
    DnsRequestIdAllocator, ResidentDnsUdpActorCompletion, ResidentDnsUdpActorExecutor,
    ResidentDnsUdpActorLifecycle, ResidentDnsUdpActorRegistration,
};
use self::transport::{
    ResidentDnsTcpMultiplexHandle, forward_dns_tcp_asis_async, forward_dns_to_upstream_async,
};
#[cfg(all(test, feature = "dns-runtime-tests"))]
use self::upstream_model::test_resident_dns_forwarder_cache;
pub use self::upstream_model::{
    ResidentDnsForwarderCache, ResidentDnsForwarderCacheState, ResidentDnsForwarderEntry,
    ResidentDnsForwarderEntryKind, ResidentDnsForwarderKey, ResidentDnsForwarderSelectionKey,
    ResidentDnsForwarderTransport, ResidentDnsH2Forwarder, ResidentDnsH2Recovery,
    ResidentDnsH3Forwarder, ResidentDnsHealthForwarderClose, ResidentDnsHealthForwarderLease,
    ResidentDnsHttpsForwarder, ResidentDnsProxyH3Forwarder, ResidentDnsProxyQuicForwarder,
    ResidentDnsQuicForwarder, ResidentDnsRequestAction, ResidentDnsResolvedTargetSnapshot,
    ResidentDnsResponseAction, ResidentDnsRetiredForwarder, ResidentDnsTargetRefreshOwner,
    ResidentDnsTargetRefreshOwnerTask, ResidentDnsTcpConnectionKind, ResidentDnsTcpForwarder,
    ResidentDnsTcpMultiplexConnection, ResidentDnsTlsForwarder, ResidentDnsUdpForwarder,
    ResidentDnsUdpForwarderShard, ResidentDnsUpstream, ResidentDnsUpstreamScheme,
    ResidentDnsUpstreamTarget, ResidentDnsUpstreams,
};
pub use self::upstream_router::ResidentDnsUpstreamRouter;
pub use self::upstream_router::ResidentDnsUpstreamSelection;
pub(crate) use crate::{
    DNS_MAX_UDP_MESSAGE_SIZE, ResidentDnsDomainRouting, build_dns_server_failure_response,
    fit_dns_response_to_udp_request,
};
#[cfg(all(test, feature = "dns-runtime-tests"))]
pub(crate) use crate::{
    ResidentDnsDomainRoutingMaintenanceHandle, ResidentDomainRoutingGenerationFence,
};
use crate::{
    ResidentDnsDomainRoutingReloadSnapshot, ResidentDnsDomainRoutingRestoreReport,
    ResidentDnsGeodata, ResidentDnsProxySelector, ResidentDnsProxyTcpTransport,
    ResidentDnsProxyUdpBridge, ResidentDnsProxyUdpForwarder, ResidentDnsProxyUdpTransport,
    ResidentDnsQuicEndpointTransport, ResidentDnsResponseCacheKey, ResidentDnsResponseCacheScope,
    ResidentDnsRuntimeCache, ResidentDnsRuntimeCacheSnapshot, ResidentDnsTransportOwnerObservation,
    ResidentDnsTransportPorts, ResidentDnsUdpRuntimeConfig, build_reject_response,
    exchange_resident_proxy_dns_tcp_stream, probe_resident_proxy_dns_udp_with_forwarder_async,
    run_resident_proxy_dns_tcp_connection,
};
pub use dae_resident_transport::{
    DnsTcpFrameReader, ProxyDnsRequestContext, ProxyDnsRequestError, ProxyDnsRequestFailure,
    ProxyDnsRequestStage, ResolvedHostAddrs, exchange_proxy_dns_framed_stream,
    write_dns_tcp_payload_async,
};

const DNS_QTYPE_A: u16 = 1;
const DNS_QTYPE_AAAA: u16 = 28;
const DNS_RESPONSE_READ_LIMIT: usize = DNS_MAX_UDP_MESSAGE_SIZE;
const DNS_RESPONSE_REROUTE_LIMIT: usize = 4;
const DNS_TCP_MESSAGE_READ_LIMIT: usize = u16::MAX as usize;
const DNS_DOH_RESPONSE_READ_LIMIT: usize = 1024 * 1024;
const DNS_TLS_DEFAULT_PORT: u16 = 853;
const DNS_HTTPS_DEFAULT_PORT: u16 = 443;
const DNS_DEFAULT_DOH_PATH: &str = "/dns-query";
const DNS_DOH3_ALPN: &str = "h3";
const DNS_DOQ_ALPN: &str = "doq";
const DNS_FORWARDER_CACHE_MAX_ENTRIES: usize = 128;
const DNS_STREAM_POOL_MAX_STREAMS: usize = 16;
const DNS_STREAM_POOL_MAX_IDLE: usize = 8;
const DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS: usize = 128;
const DNS_TRACE_CACHE_UNRESOLVED: &str = "unresolved";
const DNS_TRACE_CACHE_BYPASS: &str = "bypass";
const DNS_TRACE_CACHE_HIT: &str = "hit";
const DNS_TRACE_CACHE_LOCKED_HIT: &str = "locked-hit";
const DNS_TRACE_CACHE_MISS: &str = "miss";
const DNS_TRACE_ROUTING_UNRESOLVED: &str = "unresolved";
const DNS_TRACE_ROUTING_ASIS: &str = "asis";
const DNS_TRACE_ROUTING_UPSTREAM: &str = "upstream";
const DNS_TRACE_ROUTING_CACHE: &str = "cache";
const DNS_TRACE_ROUTING_ACCEPT: &str = "accept";
const DNS_TRACE_ROUTING_REJECT: &str = "reject";
const DNS_TRACE_REASON_REQUEST_REJECTED: &str = "dns.routing.request rejected query";
const DNS_TRACE_REASON_CACHE_HIT: &str = "resident DNS cache hit";
const DNS_TRACE_REASON_CACHE_LOCKED_HIT: &str = "resident DNS cache hit after inflight wait";
const DNS_TRACE_REASON_ASIS_ACCEPTED: &str = "resident DNS asis response accepted";
const DNS_TRACE_REASON_ASIS_REJECTED: &str = "resident DNS asis response rejected";
const DNS_TRACE_REASON_UPSTREAM_ACCEPTED: &str = "resident DNS upstream response accepted";
const DNS_TRACE_REASON_UPSTREAM_REJECTED: &str = "resident DNS upstream response rejected";
pub const DNS_TRANSPORT_ROUTE_DIRECT: &str = "direct";
pub const DNS_TRANSPORT_ROUTE_PROXY: &str = "proxy";
pub const DNS_TRANSPORT_TARGET_FAMILY_IPV4: &str = "ipv4";
pub const DNS_TRANSPORT_TARGET_FAMILY_IPV6: &str = "ipv6";
pub const DNS_TRANSPORT_OUTCOME_SUCCESS: &str = "success";
pub const DNS_TRANSPORT_OUTCOME_ERROR: &str = "error";

async fn acquire_dns_permit<'a>(
    semaphore: &'a Semaphore,
    context: &'static str,
    request: ProxyDnsRequestContext,
) -> Result<tokio::sync::SemaphorePermit<'a>, String> {
    request
        .ensure(ProxyDnsRequestStage::Queued)
        .map_err(|error| error.to_string())?;
    time::timeout_at(request.deadline(), semaphore.acquire())
        .await
        .map_err(|_| format!("{context} concurrency wait timeout"))?
        .map_err(|_| format!("{context} concurrency limiter is closed"))
}

#[derive(Clone, Debug)]
pub struct ResidentDnsPlan {
    request_matcher: Option<RequestMatcher>,
    request_actions: Vec<ResidentDnsRequestAction>,
    request_default_action: ResidentDnsRequestAction,
    response_matcher: Option<ResponseMatcher>,
    response_actions: Vec<ResidentDnsResponseAction>,
    response_default_action: ResidentDnsResponseAction,
    domain_routing: Option<Arc<ResidentDnsDomainRouting>>,
    cache: Arc<ResidentDnsRuntimeCache>,
    forwarders: Arc<ResidentDnsForwarderCache>,
    fixed_domain_ttl: Arc<BTreeMap<String, i64>>,
    ipversion_prefer: Option<u16>,
    mark: u32,
    upstream_router: Option<Arc<ResidentDnsUpstreamRouter>>,
    target_refresh_owner: Option<Arc<ResidentDnsTargetRefreshOwner>>,
}

#[derive(Clone)]
pub struct ResidentDnsResolver {
    plan: Arc<ResidentDnsPlan>,
}

impl ResidentDnsResolver {
    pub fn new(plan: Arc<ResidentDnsPlan>) -> Self {
        Self { plan }
    }

    #[cfg(all(test, feature = "dns-runtime-tests"))]
    pub fn asis(mark: u32) -> Self {
        Self::new(Arc::new(ResidentDnsPlan::asis(mark)))
    }

    pub async fn resolve_domain_has_ip_for_dial(&self, domain: &str, ip: IpAddr) -> bool {
        self.plan.resolve_domain_has_ip_for_dial(domain, ip).await
    }

    pub async fn query_tcp(
        &self,
        original_dst: SocketAddr,
        request: &[u8],
    ) -> Result<Vec<u8>, String> {
        handle_resident_dns_tcp_async(&self.plan, original_dst, request).await
    }

    pub fn server_failure_response(request: &[u8]) -> Result<Vec<u8>, String> {
        build_dns_server_failure_response(request)
    }
}

#[derive(Clone)]
pub struct ResidentDnsDispatcher {
    plan: Arc<ResidentDnsPlan>,
}

impl ResidentDnsDispatcher {
    pub fn new(plan: Arc<ResidentDnsPlan>) -> Self {
        Self { plan }
    }

    pub fn asis(mark: u32) -> Self {
        Self::new(Arc::new(ResidentDnsPlan::asis(mark)))
    }

    pub async fn query_udp(
        &self,
        original_dst: SocketAddr,
        request: &[u8],
    ) -> Result<Vec<u8>, String> {
        handle_resident_dns_udp_async(&self.plan, original_dst, request).await
    }

    pub async fn shutdown_forwarders(&self, deadline: time::Instant) -> Value {
        self.plan.shutdown_forwarders(deadline).await
    }

    pub fn server_failure_response(request: &[u8]) -> Result<Vec<u8>, String> {
        build_dns_server_failure_response(request)
    }
}

#[derive(Clone, Debug)]
pub struct ResidentDnsQueryResult {
    pub response: Vec<u8>,
    pub trace: ResidentDnsTraceSummary,
}

impl ResidentDnsPlan {
    pub fn asis(mark: u32) -> Self {
        let mark = effective_so_mark_from_dae(mark);
        Self {
            request_matcher: None,
            request_actions: Vec::new(),
            request_default_action: ResidentDnsRequestAction::AsIs,
            response_matcher: None,
            response_actions: Vec::new(),
            response_default_action: ResidentDnsResponseAction::Accept,
            domain_routing: None,
            cache: Arc::new(ResidentDnsRuntimeCache::default()),
            forwarders: Arc::new(ResidentDnsForwarderCache::default()),
            fixed_domain_ttl: Arc::new(BTreeMap::new()),
            ipversion_prefer: None,
            mark,
            upstream_router: None,
            target_refresh_owner: None,
        }
    }

    pub fn with_domain_routing(
        mut self,
        domain_routing: Option<Arc<ResidentDnsDomainRouting>>,
    ) -> Self {
        self.domain_routing = domain_routing;
        self
    }

    pub fn with_upstream_routing(
        mut self,
        upstream_router: Option<Arc<ResidentDnsUpstreamRouter>>,
    ) -> Self {
        self.upstream_router = upstream_router;
        self
    }

    pub fn with_udp_runtime_resources_and_transports(
        mut self,
        runtime: ResidentDnsUdpRuntimeConfig,
        metrics: Arc<ResidentDataplaneMetrics>,
        executor: tokio::runtime::Handle,
        udp_executor: Arc<ResidentDnsUdpActorExecutor>,
        transports: ResidentDnsTransportPorts,
    ) -> Self {
        self.forwarders = Arc::new(ResidentDnsForwarderCache::new_with_proxy_transports(
            runtime,
            metrics,
            Some(executor),
            udp_executor,
            transports.proxy_tcp(),
            transports.proxy_udp(),
            transports.quic_endpoint(),
        ));
        self
    }

    pub async fn shutdown_forwarders(&self, deadline: time::Instant) -> Value {
        self.forwarders.shutdown(deadline).await
    }

    pub fn take_target_refresh_owner_task(
        &self,
        stop: SharedResidentStopSignal,
    ) -> Result<Option<ResidentDnsTargetRefreshOwnerTask>, String> {
        match self.target_refresh_owner.as_ref() {
            Some(owner) => owner.take_task(stop),
            None => Ok(None),
        }
    }

    pub async fn probe_proxy_dns_udp_health(
        &self,
        binding: ResidentProxyBinding,
        target: SocketAddr,
        lookup_host: &str,
    ) -> Result<(), String> {
        let lease = self
            .forwarders
            .acquire_health_proxy_udp_forwarder(target, binding)
            .await?;
        let result =
            probe_resident_proxy_dns_udp_with_forwarder_async(lease.forwarder(), lookup_host).await;
        let release = lease.release().await;
        match (result, release) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => Err(format!(
                "{error}; health forwarder cleanup failed: {cleanup}"
            )),
        }
    }

    pub fn reload_handle(&self) -> ResidentDnsReloadHandle {
        ResidentDnsReloadHandle::new(Arc::clone(&self.cache), self.domain_routing.clone())
    }

    pub fn restore_reload_snapshot(
        &self,
        snapshot: &ResidentDnsReloadSnapshot,
    ) -> Result<ResidentDnsReloadRestoreReport, String> {
        ResidentDnsReloadRestoreReport::restore_into(self, snapshot)
    }

    pub fn activate_domain_routing_generation(&self) -> Result<(), String> {
        match self.domain_routing.as_ref() {
            Some(domain_routing) => domain_routing.activate_generation(),
            None => Ok(()),
        }
    }

    pub async fn resolve_domain_has_ip_for_dial(&self, domain: &str, destination: IpAddr) -> bool {
        let first_qtype = if destination.is_ipv4() {
            DNS_QTYPE_A
        } else {
            DNS_QTYPE_AAAA
        };
        let second_qtype = if first_qtype == DNS_QTYPE_A {
            DNS_QTYPE_AAAA
        } else {
            DNS_QTYPE_A
        };
        self.cached_domain_has_ip(domain, first_qtype, true)
            || self
                .resolve_domain_qtype_has_ip_for_dial(domain, first_qtype)
                .await
            || self.cached_domain_has_ip(domain, second_qtype, true)
            || self
                .resolve_domain_qtype_has_ip_for_dial(domain, second_qtype)
                .await
    }

    pub fn cached_domain_has_ip(&self, domain: &str, qtype: u16, ignore_fixed_ttl: bool) -> bool {
        let key = DnsCacheKey::new(domain, qtype, 1);
        self.cache
            .lookup_key_has_any_ip(&key, ignore_fixed_ttl)
            .unwrap_or(false)
    }

    async fn resolve_domain_qtype_has_ip_for_dial(&self, domain: &str, qtype: u16) -> bool {
        let Ok(query) = build_dns_query_packet(0, domain, qtype) else {
            return false;
        };
        let Ok(request) = DnsPacketView::parse(&query) else {
            return false;
        };
        let synthetic_dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DNS_DEFAULT_PORT);
        let Ok(response) = handle_resident_dns_request_without_preference(
            self,
            synthetic_dst,
            &query,
            &request,
            None,
        )
        .await
        else {
            return false;
        };
        dns_response_has_any_ip(&response).unwrap_or(false)
    }
}

pub fn build_resident_dns_plan_with_refresh_interval(
    config: &Config,
    geodata: &dyn ResidentDnsGeodata,
    refresh_interval: std::time::Duration,
) -> Result<ResidentDnsPlan, String> {
    let so_mark_from_dae = effective_so_mark_from_dae(config.global.so_mark_from_dae);
    let upstreams = parse_dns_upstreams(config, refresh_interval)?;
    let (target_refresh_owner, target_refresh_handle) =
        ResidentDnsTargetRefreshOwner::new(ResidentDnsResourceProfile::selected());
    upstreams.install_target_refresh(target_refresh_handle);
    let fixed_domain_ttl = parse_fixed_domain_ttl(&config.dns.fixed_domain_ttl)?;
    let ipversion_prefer = parse_ipversion_prefer(config.dns.ipversion_prefer)?;
    let request_default_action =
        parse_request_default_action(&config.dns.routing.request.fallback, &upstreams.by_tag)?;
    let request_matcher = build_request_matcher(config, &upstreams, geodata)?;
    let response_default_action =
        parse_response_default_action(&config.dns.routing.response.fallback, &upstreams.by_tag)?;
    let response_matcher = build_response_matcher(config, &upstreams, geodata)?;
    Ok(ResidentDnsPlan {
        request_matcher,
        request_actions: upstreams.request_actions,
        request_default_action,
        response_matcher,
        response_actions: upstreams.response_actions,
        response_default_action,
        domain_routing: None,
        cache: Arc::new(ResidentDnsRuntimeCache::default()),
        forwarders: Arc::new(ResidentDnsForwarderCache::default()),
        fixed_domain_ttl: Arc::new(fixed_domain_ttl),
        ipversion_prefer,
        mark: so_mark_from_dae,
        upstream_router: None,
        target_refresh_owner: Some(target_refresh_owner),
    })
}

#[cfg(all(test, feature = "dns-runtime-tests"))]
pub fn build_resident_dns_plan(
    config: &Config,
    geodata: &dyn ResidentDnsGeodata,
) -> Result<ResidentDnsPlan, String> {
    build_resident_dns_plan_with_refresh_interval(
        config,
        geodata,
        std::time::Duration::from_secs(60),
    )
}

fn parse_ipversion_prefer(value: i32) -> Result<Option<u16>, String> {
    match value {
        0 => Ok(None),
        4 => Ok(Some(DNS_QTYPE_A)),
        6 => Ok(Some(DNS_QTYPE_AAAA)),
        other => Err(format!("unknown dns.ipversion_prefer: {other}")),
    }
}

fn parse_fixed_domain_ttl(values: &[String]) -> Result<BTreeMap<String, i64>, String> {
    let mut fixed = BTreeMap::new();
    for raw in values {
        let (domain, ttl) = raw
            .split_once(':')
            .ok_or_else(|| format!("bad dns.fixed_domain_ttl entry {raw:?}: missing ':'"))?;
        let domain = canonical_fixed_ttl_domain(domain);
        if domain.is_empty() {
            return Err(format!(
                "bad dns.fixed_domain_ttl entry {raw:?}: domain is empty"
            ));
        }
        fixed.insert(domain, parse_i64_base0(ttl.trim())?);
    }
    Ok(fixed)
}

fn canonical_fixed_ttl_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn parse_i64_base0(raw: &str) -> Result<i64, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("failed to parse ttl: empty value".to_owned());
    }
    let (negative, digits) = raw
        .strip_prefix('-')
        .map(|rest| (true, rest))
        .unwrap_or((false, raw));
    let (base, digits) = if let Some(rest) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (16, rest)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, &digits[1..])
    } else {
        (10, digits)
    };
    let parsed = i64::from_str_radix(digits, base)
        .map_err(|err| format!("failed to parse ttl {raw:?}: {err}"))?;
    Ok(if negative { -parsed } else { parsed })
}

fn record_accepted_dns_response(
    plan: &ResidentDnsPlan,
    cache_key: &ResidentDnsResponseCacheKey,
    response: &[u8],
) -> Result<(), String> {
    let now_unix = unix_now();
    let fixed_domain_ttl = fixed_domain_ttl_for_response(plan, response)?;
    let Some(cache_plan) =
        build_response_cache_plan_from_packet(now_unix, response, fixed_domain_ttl)
            .map_err(|err| format!("build resident DNS response cache plan: {err}"))?
    else {
        return Ok(());
    };
    plan.cache.insert_response(
        now_unix,
        cache_key.with_base(cache_plan.key.clone()),
        cache_plan.entry.clone(),
    )?;
    if let Some(domain_routing) = plan.domain_routing.as_ref() {
        domain_routing.record_accepted_response(&cache_plan)?;
    }
    Ok(())
}

fn remove_dns_response_cache_for_request(
    plan: &ResidentDnsPlan,
    request: &DnsPacketView<'_>,
) -> Result<(), String> {
    let key = dns_cache_key_for_request(request)?;
    let _ = plan.cache.remove_base_key(&key)?;
    if let Some(domain_routing) = plan.domain_routing.as_ref() {
        domain_routing.remove_request(request)?;
    }
    Ok(())
}

fn fixed_domain_ttl_for_response(
    plan: &ResidentDnsPlan,
    response: &[u8],
) -> Result<Option<i64>, String> {
    if plan.fixed_domain_ttl.is_empty() {
        return Ok(None);
    }
    let response = DnsPacketView::parse(response)
        .map_err(|err| format!("parse DNS response for fixed TTL: {err}"))?;
    let Some(question) = response.questions().next() else {
        return Ok(None);
    };
    let qname = question
        .qname_to_canonical_string()
        .map_err(|err| format!("read DNS response qname for fixed TTL: {err}"))?;
    Ok(plan
        .fixed_domain_ttl
        .get(&canonical_fixed_ttl_domain(&qname))
        .copied())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

fn dns_request_action_name(action: &ResidentDnsRequestAction) -> &'static str {
    match action {
        ResidentDnsRequestAction::AsIs => DNS_TRACE_ROUTING_ASIS,
        ResidentDnsRequestAction::Reject => DNS_TRACE_ROUTING_REJECT,
        ResidentDnsRequestAction::Upstream(_) => DNS_TRACE_ROUTING_UPSTREAM,
    }
}

fn dns_response_action_name(action: &ResidentDnsResponseAction) -> &'static str {
    match action {
        ResidentDnsResponseAction::Accept => DNS_TRACE_ROUTING_ACCEPT,
        ResidentDnsResponseAction::Reject => DNS_TRACE_ROUTING_REJECT,
        ResidentDnsResponseAction::Upstream(_) => DNS_TRACE_ROUTING_UPSTREAM,
    }
}

fn dns_response_rcode(response: &[u8]) -> Option<u16> {
    (response.len() >= 4).then(|| u16::from_be_bytes([response[2], response[3]]) & 0x000f)
}

pub async fn handle_resident_dns_udp_async(
    plan: &ResidentDnsPlan,
    original_dst: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let response = handle_resident_dns_request_async(
        plan,
        original_dst,
        payload,
        Some(ResidentDnsAsisTransport::Udp),
    )
    .await?;
    fit_dns_response_to_udp_request(payload, response)
}

pub async fn handle_resident_dns_tcp_async(
    plan: &ResidentDnsPlan,
    original_dst: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    handle_resident_dns_request_async(
        plan,
        original_dst,
        payload,
        Some(ResidentDnsAsisTransport::Tcp),
    )
    .await
}

pub async fn handle_resident_dns_local_trace_async(
    plan: &ResidentDnsPlan,
    original_dst: SocketAddr,
    payload: &[u8],
) -> Result<ResidentDnsQueryResult, String> {
    let request =
        DnsPacketView::parse(payload).map_err(|err| format!("parse DNS request: {err}"))?;
    if request.response() {
        return Err("DNS request expected but DNS response received".to_owned());
    }
    if request.question_count() == 0 {
        return Err("DNS request has no question".to_owned());
    }
    let trace = ResidentDnsTraceSummary::from_request(plan, &request)?;
    let (result, transport_attempts) = capture_dns_transport_trace_async(Box::pin(
        handle_resident_dns_request_without_preference_trace(
            plan,
            original_dst,
            payload,
            &request,
            None,
            trace,
        ),
    ))
    .await;
    result.map(|mut result| {
        result.trace.transport_attempts = transport_attempts;
        result
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResidentDnsAsisTransport {
    Udp,
    Tcp,
}

async fn handle_resident_dns_request_async(
    plan: &ResidentDnsPlan,
    original_dst: SocketAddr,
    payload: &[u8],
    asis_transport: Option<ResidentDnsAsisTransport>,
) -> Result<Vec<u8>, String> {
    let request =
        DnsPacketView::parse(payload).map_err(|err| format!("parse DNS request: {err}"))?;
    if request.response() {
        return Err("DNS request expected but DNS response received".to_owned());
    }
    if request.question_count() == 0 {
        return Err("DNS request has no question".to_owned());
    }
    handle_resident_dns_request_without_preference(
        plan,
        original_dst,
        payload,
        &request,
        asis_transport,
    )
    .await
}

async fn handle_resident_dns_request_without_preference(
    plan: &ResidentDnsPlan,
    original_dst: SocketAddr,
    payload: &[u8],
    request: &DnsPacketView<'_>,
    asis_transport: Option<ResidentDnsAsisTransport>,
) -> Result<Vec<u8>, String> {
    let action = select_request_action(plan, request)?;
    if matches!(action, ResidentDnsRequestAction::Reject) {
        remove_dns_response_cache_for_request(plan, request)?;
        return build_reject_response(payload, request);
    }
    if let ResidentDnsRequestAction::AsIs = action
        && asis_transport.is_none()
    {
        return Err(
                "dns request routing cannot use \"asis\" for locally bound dns listener; configure an explicit upstream instead"
                    .to_owned(),
            );
    }
    let cache_key = dns_response_cache_key_for_request_action(request, &action, original_dst)?;
    let mut cached_response = Vec::new();
    if plan
        .cache
        .lookup_response_into(&cache_key, request, false, &mut cached_response)?
    {
        return Ok(cached_response);
    }
    let context = ProxyDnsRequestContext::from_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT);
    let mut flight = plan.cache.begin_flight(cache_key.clone())?;
    if !flight.is_leader() {
        return flight.wait(context, request.id()).await;
    }
    let result = match action {
        ResidentDnsRequestAction::AsIs => {
            let asis_transport = asis_transport
                .ok_or_else(|| "asis DNS transport is unavailable for this request".to_owned())?;
            let response = forward_dns_asis_async(
                original_dst,
                payload,
                plan.mark,
                asis_transport,
                &plan.forwarders,
                context,
            )
            .await?;
            validate_dns_response_for_request(request, &response, true)?;
            let response_action = select_response_action_for_upstream(
                plan,
                request,
                &response,
                DnsRequestOutboundIndex::ASIS,
            )?;
            match response_action {
                ResidentDnsResponseAction::Accept => {
                    record_accepted_dns_response(plan, &cache_key, &response)?;
                    Ok(response)
                }
                ResidentDnsResponseAction::Reject => build_reject_response(payload, request),
                ResidentDnsResponseAction::Upstream(upstream) => {
                    resolve_dns_response_routing(
                        plan, payload, request, upstream, &cache_key, context,
                    )
                    .await
                }
            }
        }
        ResidentDnsRequestAction::Reject => unreachable!("reject handled before cache lookup"),
        ResidentDnsRequestAction::Upstream(ref upstream) => {
            resolve_dns_response_routing(
                plan,
                payload,
                request,
                upstream.clone(),
                &cache_key,
                context,
            )
            .await
        }
    };
    flight.publish(result.as_ref().map(Vec::as_slice).map_err(String::as_str))?;
    result
}

async fn handle_resident_dns_request_without_preference_trace(
    plan: &ResidentDnsPlan,
    original_dst: SocketAddr,
    payload: &[u8],
    request: &DnsPacketView<'_>,
    asis_transport: Option<ResidentDnsAsisTransport>,
    mut trace: ResidentDnsTraceSummary,
) -> Result<ResidentDnsQueryResult, String> {
    let routing_started = Instant::now();
    let action = select_request_action(plan, request)?;
    trace.set_request_action(&action);
    trace.add_routing_elapsed(routing_started);
    if matches!(action, ResidentDnsRequestAction::Reject) {
        remove_dns_response_cache_for_request(plan, request)?;
        trace.cache = DNS_TRACE_CACHE_BYPASS.to_owned();
        trace.response_routing = DNS_TRACE_ROUTING_REJECT.to_owned();
        let response = build_reject_response(payload, request)?;
        return Ok(trace.finish(response, DNS_TRACE_REASON_REQUEST_REJECTED));
    }
    if let ResidentDnsRequestAction::AsIs = action
        && asis_transport.is_none()
    {
        return Err(
                "dns request routing cannot use \"asis\" for locally bound dns listener; configure an explicit upstream instead"
                    .to_owned(),
            );
    }
    let cache_key = dns_response_cache_key_for_request_action(request, &action, original_dst)?;
    let mut cached_response = Vec::new();
    let cache_started = Instant::now();
    if plan
        .cache
        .lookup_response_into(&cache_key, request, false, &mut cached_response)?
    {
        trace.add_cache_elapsed(cache_started);
        trace.cache = DNS_TRACE_CACHE_HIT.to_owned();
        trace.response_routing = DNS_TRACE_ROUTING_CACHE.to_owned();
        return Ok(trace.finish(cached_response, DNS_TRACE_REASON_CACHE_HIT));
    }
    let context = ProxyDnsRequestContext::from_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT);
    let mut flight = plan.cache.begin_flight(cache_key.clone())?;
    if !flight.is_leader() {
        let response = flight.wait(context, request.id()).await?;
        trace.add_cache_elapsed(cache_started);
        trace.cache = DNS_TRACE_CACHE_LOCKED_HIT.to_owned();
        trace.response_routing = DNS_TRACE_ROUTING_CACHE.to_owned();
        return Ok(trace.finish(response, DNS_TRACE_REASON_CACHE_LOCKED_HIT));
    }
    trace.add_cache_elapsed(cache_started);
    trace.cache = DNS_TRACE_CACHE_MISS.to_owned();
    let result = match action {
        ResidentDnsRequestAction::AsIs => {
            trace.push_asis_attempt();
            let asis_transport = asis_transport
                .ok_or_else(|| "asis DNS transport is unavailable for this request".to_owned())?;
            let response = forward_dns_asis_async(
                original_dst,
                payload,
                plan.mark,
                asis_transport,
                &plan.forwarders,
                context,
            )
            .await?;
            validate_dns_response_for_request(request, &response, true)?;
            let routing_started = Instant::now();
            let response_action = select_response_action_for_upstream(
                plan,
                request,
                &response,
                DnsRequestOutboundIndex::ASIS,
            )?;
            trace.set_response_action(&response_action);
            trace.add_routing_elapsed(routing_started);
            match response_action {
                ResidentDnsResponseAction::Accept => {
                    record_accepted_dns_response(plan, &cache_key, &response)?;
                    trace.response_routing = DNS_TRACE_ROUTING_ACCEPT.to_owned();
                    Ok(trace.finish(response, DNS_TRACE_REASON_ASIS_ACCEPTED))
                }
                ResidentDnsResponseAction::Reject => {
                    let response = build_reject_response(payload, request)?;
                    trace.response_routing = DNS_TRACE_ROUTING_REJECT.to_owned();
                    Ok(trace.finish(response, DNS_TRACE_REASON_ASIS_REJECTED))
                }
                ResidentDnsResponseAction::Upstream(upstream) => {
                    trace.reroutes += 1;
                    resolve_dns_response_routing_trace(
                        plan, payload, request, upstream, &cache_key, trace, context,
                    )
                    .await
                }
            }
        }
        ResidentDnsRequestAction::Reject => unreachable!("reject handled before cache lookup"),
        ResidentDnsRequestAction::Upstream(ref upstream) => {
            resolve_dns_response_routing_trace(
                plan,
                payload,
                request,
                upstream.clone(),
                &cache_key,
                trace,
                context,
            )
            .await
        }
    };
    flight.publish(
        result
            .as_ref()
            .map(|result| result.response.as_slice())
            .map_err(String::as_str),
    )?;
    result
}

async fn forward_dns_asis_async(
    original_dst: SocketAddr,
    payload: &[u8],
    mark: u32,
    transport: ResidentDnsAsisTransport,
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, String> {
    match transport {
        ResidentDnsAsisTransport::Udp => {
            let forwarder = forwarders.asis_udp_forwarder(original_dst, mark)?;
            forwarder
                .exchange(payload, context)
                .await
                .map_err(|err| format!("forward DNS UDP asis to {original_dst}: {err}"))
        }
        ResidentDnsAsisTransport::Tcp => {
            forward_dns_tcp_asis_async(original_dst, payload, mark, context)
                .await
                .map_err(|err| format!("forward DNS TCP asis to {original_dst}: {err}"))
        }
    }
}

fn dns_cache_key_for_request(request: &DnsPacketView<'_>) -> Result<DnsCacheKey, String> {
    let question = request
        .questions()
        .next()
        .ok_or_else(|| "DNS request has no question".to_owned())?;
    let qname = question
        .qname_to_canonical_string()
        .map_err(|err| format!("read DNS request qname for cache key: {err}"))?;
    Ok(DnsCacheKey::new(qname, question.qtype(), question.qclass()))
}

fn dns_response_cache_key_for_request_action(
    request: &DnsPacketView<'_>,
    action: &ResidentDnsRequestAction,
    original_dst: SocketAddr,
) -> Result<ResidentDnsResponseCacheKey, String> {
    let base = dns_cache_key_for_request(request)?;
    let scope = match action {
        ResidentDnsRequestAction::AsIs => ResidentDnsResponseCacheScope::AsIs { original_dst },
        ResidentDnsRequestAction::Reject => ResidentDnsResponseCacheScope::Reject,
        ResidentDnsRequestAction::Upstream(upstream) => ResidentDnsResponseCacheScope::upstream(
            upstream.index,
            upstream.scheme.as_str(),
            &upstream.target.authority,
            &upstream.path,
        ),
    };
    Ok(ResidentDnsResponseCacheKey::new(base, scope))
}

fn dns_response_has_any_ip(response: &[u8]) -> Result<bool, String> {
    let response = DnsPacketView::parse(response)
        .map_err(|err| format!("parse DNS response answers: {err}"))?;
    for answer in response.answers() {
        let answer = answer.map_err(|err| format!("read DNS response answer: {err}"))?;
        if answer.ip().is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn build_dns_query_packet(id: u16, domain: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() || domain.parse::<IpAddr>().is_ok() {
        return Err(format!("not a resolvable domain name: {domain:?}"));
    }
    let mut packet = Vec::with_capacity(12 + domain.len() + 6);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    for label in domain.split('.') {
        if label.is_empty() {
            return Err(format!("domain contains an empty label: {domain:?}"));
        }
        let len = u8::try_from(label.len())
            .map_err(|_| format!("domain label is too long in {domain:?}"))?;
        if len > 63 {
            return Err(format!("domain label is too long in {domain:?}"));
        }
        packet.push(len);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    Ok(packet)
}

async fn resolve_dns_response_routing(
    plan: &ResidentDnsPlan,
    request_payload: &[u8],
    request: &DnsPacketView<'_>,
    mut upstream: ResidentDnsUpstream,
    cache_key: &ResidentDnsResponseCacheKey,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, String> {
    for _ in 0..DNS_RESPONSE_REROUTE_LIMIT {
        let response = forward_dns_to_upstream_async(
            &upstream,
            request_payload,
            plan,
            &plan.forwarders,
            context,
        )
        .await
        .map_err(|error| error.to_string())?;
        validate_dns_response_for_request(
            request,
            &response,
            upstream.scheme.requires_dns_response_id_match(),
        )?;
        let response_action = select_response_action(plan, request, &response, &upstream)?;
        match response_action {
            ResidentDnsResponseAction::Accept => {
                record_accepted_dns_response(plan, cache_key, &response)?;
                return Ok(response);
            }
            ResidentDnsResponseAction::Reject => {
                return build_reject_response(request_payload, request);
            }
            ResidentDnsResponseAction::Upstream(next) => upstream = next,
        }
    }
    Err(format!(
        "dns.routing.response exceeded reroute limit of {DNS_RESPONSE_REROUTE_LIMIT}"
    ))
}

async fn resolve_dns_response_routing_trace(
    plan: &ResidentDnsPlan,
    request_payload: &[u8],
    request: &DnsPacketView<'_>,
    mut upstream: ResidentDnsUpstream,
    cache_key: &ResidentDnsResponseCacheKey,
    mut trace: ResidentDnsTraceSummary,
    context: ProxyDnsRequestContext,
) -> Result<ResidentDnsQueryResult, String> {
    for _ in 0..DNS_RESPONSE_REROUTE_LIMIT {
        trace.push_upstream_attempt(&upstream);
        let response = forward_dns_to_upstream_async(
            &upstream,
            request_payload,
            plan,
            &plan.forwarders,
            context,
        )
        .await
        .map_err(|error| error.to_string())?;
        validate_dns_response_for_request(
            request,
            &response,
            upstream.scheme.requires_dns_response_id_match(),
        )?;
        let routing_started = Instant::now();
        let response_action = select_response_action(plan, request, &response, &upstream)?;
        trace.set_response_action(&response_action);
        trace.add_routing_elapsed(routing_started);
        match response_action {
            ResidentDnsResponseAction::Accept => {
                record_accepted_dns_response(plan, cache_key, &response)?;
                trace.response_routing = DNS_TRACE_ROUTING_ACCEPT.to_owned();
                return Ok(trace.finish(response, DNS_TRACE_REASON_UPSTREAM_ACCEPTED));
            }
            ResidentDnsResponseAction::Reject => {
                let response = build_reject_response(request_payload, request)?;
                trace.response_routing = DNS_TRACE_ROUTING_REJECT.to_owned();
                return Ok(trace.finish(response, DNS_TRACE_REASON_UPSTREAM_REJECTED));
            }
            ResidentDnsResponseAction::Upstream(next) => {
                trace.reroutes += 1;
                upstream = next;
            }
        }
    }
    Err(format!(
        "dns.routing.response exceeded reroute limit of {DNS_RESPONSE_REROUTE_LIMIT}"
    ))
}

fn validate_dns_response_for_request(
    request: &DnsPacketView<'_>,
    response: &[u8],
    require_matching_id: bool,
) -> Result<(), String> {
    let response = DnsPacketView::parse(response)
        .map_err(|err| format!("parse DNS response for request validation: {err}"))?;
    validate_dns_packet_response_for_request_fast(request, Some(&response), require_matching_id)
        .map_err(|err| format!("validate DNS response for request: {err:?}"))
}

#[cfg(all(test, feature = "dns-runtime-tests"))]
mod tests;

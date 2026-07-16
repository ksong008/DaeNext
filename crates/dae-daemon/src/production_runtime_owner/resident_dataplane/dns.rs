use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::{Buf, Bytes};
use dae_config::{Config, DynamicFunctionValue, Function, Param, RoutingRule};
use dae_core_types::OutboundIndex;
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
#[cfg(test)]
use dae_runtime_control::ip_to_key;
use http::Request;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio::time;

#[cfg(test)]
use super::super::resident_routing::build_resident_userspace_routing_matcher_with_geodata;
use super::super::resident_routing::{
    ResidentGeodataStore, expand_resident_dns_request_qname_rules_with_resolver,
    expand_resident_dns_response_ip_params_with_resolver,
    expand_resident_dns_response_qname_rules_with_resolver,
};
use super::direct::open_direct_tcp_connection_async;
#[cfg(test)]
use super::plan::build_resident_dataplane_plan;
#[cfg(test)]
use super::plan::share_resident_proxy_groups;
use super::plan::{ResidentProxyPlan, SharedResidentProxyGroupMap, effective_so_mark_from_dae};
use super::tcp::{
    ObservedQuicEndpoint, QuicEndpointCallerClass, QuicEndpointIdentityRole,
    QuicEndpointOpenContext, QuicEndpointProtocol, open_marked_quic_endpoint_for_remote,
    scope_quic_endpoint_observation, set_socket_mark,
};
use super::tcp::{
    exchange_resident_proxy_dns_tcp_async, exchange_resident_proxy_dns_tcp_stream_async,
};
use super::udp::{
    ResidentProxyDnsUdpForwarder, ResidentProxyUdpBridge, open_resident_proxy_udp_bridge_async,
};
use super::{
    RESIDENT_IDLE_SLEEP, RESIDENT_UDP_RESPONSE_TIMEOUT, ResidentDataplaneMetrics,
    ResidentDnsUdpRuntimeConfig, apply_resident_udp_socket_buffer_tuning,
};
use super::{ResolvedHostAddrs, resolve_host_addrs_with_configured_fallback_dns_ttl};

mod cache;
mod domain_routing;
mod error_response;
mod ipversion_preference;
mod reload;
mod request;
mod routing;
mod tcp_wire;
mod trace_summary;
mod transport;
mod upstream_model;
mod upstream_router;
use self::cache::{
    ResidentDnsResponseCacheKey, ResidentDnsResponseCacheScope, ResidentDnsRuntimeCache,
    ResidentDnsRuntimeCacheSnapshot,
};
pub(super) use self::domain_routing::{
    ResidentDnsDomainRouting, ResidentDnsDomainRoutingMaintenanceHandle,
};
use self::domain_routing::{
    ResidentDnsDomainRoutingReloadSnapshot, ResidentDnsDomainRoutingRestoreReport,
};
#[cfg(test)]
use self::domain_routing::{
    build_resident_dns_domain_routing_update_plan,
    build_resident_dns_domain_routing_update_plan_from_entry,
    build_resident_domain_routing_ip_update_plan,
};
pub(super) use self::error_response::build_dns_server_failure_response;
use self::error_response::build_reject_response;
use self::ipversion_preference::{
    ResidentDnsIpversionPreferenceRegistry, dns_ipversion_preference_wait_timeout,
};
pub(in crate::production_runtime_owner) use self::reload::ResidentDnsReloadHandle;
use self::reload::ResidentDnsReloadRestoreReport;
pub(crate) use self::reload::ResidentDnsReloadSnapshot;
pub(in crate::production_runtime_owner::resident_dataplane) use self::request::{
    ProxyDnsPendingRequestBytes, ProxyDnsQueuedRequestBytes, ProxyDnsRequestContext,
    ProxyDnsRequestError, ProxyDnsRequestFailure, ProxyDnsRequestOutcome, ProxyDnsRequestStage,
    exchange_proxy_dns_framed_stream,
};
#[cfg(test)]
use self::routing::parse_dns_upstream;
use self::routing::{
    build_request_matcher, build_response_matcher, parse_dns_upstreams,
    parse_request_default_action, parse_response_default_action, select_request_action,
    select_response_action, select_response_action_for_upstream,
};
pub(super) use self::tcp_wire::{read_dns_tcp_payload_async, write_dns_tcp_payload_async};
pub(super) use self::trace_summary::{ResidentDnsTraceSummary, ResidentDnsTransportTrace};
use self::trace_summary::{
    ResidentDnsTransportTraceInput, capture_dns_transport_trace_async, record_dns_transport_trace,
};
#[cfg(test)]
use self::transport::parse_doh_http_response;
pub(in crate::production_runtime_owner::resident_dataplane) use self::transport::udp_multiplex::{
    ResidentDnsUdpActorExecutor, ResidentDnsUdpActorLifecycle, ResidentDnsUdpActorRegistration,
    UdpRequestIdAllocator,
};
use self::transport::{
    forward_dns_tcp_asis_async, forward_dns_to_upstream_async, forward_dns_udp_async,
};
pub(in crate::production_runtime_owner::resident_dataplane::dns) use self::upstream_model::{
    ResidentDnsForwarderCache, ResidentDnsForwarderCacheState, ResidentDnsForwarderEntry,
    ResidentDnsForwarderEntryKind, ResidentDnsForwarderKey, ResidentDnsForwarderSelectionKey,
    ResidentDnsForwarderTransport, ResidentDnsH2Forwarder, ResidentDnsH2Recovery,
    ResidentDnsH3Forwarder, ResidentDnsHttpsForwarder, ResidentDnsQuicForwarder,
    ResidentDnsRequestAction, ResidentDnsResponseAction, ResidentDnsTcpForwarder,
    ResidentDnsTlsForwarder, ResidentDnsUdpForwarder, ResidentDnsUdpForwarderShard,
    ResidentDnsUpstream, ResidentDnsUpstreamScheme, ResidentDnsUpstreamTarget,
    ResidentDnsUpstreams,
};
pub(super) use self::upstream_router::ResidentDnsUpstreamRouter;
pub(in crate::production_runtime_owner::resident_dataplane::dns) use self::upstream_router::ResidentDnsUpstreamSelection;

const DNS_QTYPE_A: u16 = 1;
const DNS_QTYPE_AAAA: u16 = 28;
pub(super) const DNS_MAX_UDP_MESSAGE_SIZE: usize = u16::MAX as usize;
const DNS_RESPONSE_READ_LIMIT: usize = DNS_MAX_UDP_MESSAGE_SIZE;
const DNS_RESPONSE_REROUTE_LIMIT: usize = 4;
const DNS_TCP_MESSAGE_READ_LIMIT: usize = u16::MAX as usize;
const DNS_DOH_RESPONSE_READ_LIMIT: usize = 1024 * 1024;
const DNS_TLS_DEFAULT_PORT: u16 = 853;
const DNS_HTTPS_DEFAULT_PORT: u16 = 443;
const DNS_DEFAULT_DOH_PATH: &str = "/dns-query";
const DNS_DOH3_ALPN: &str = "h3";
const DNS_DOQ_ALPN: &str = "doq";
const TCP_SNIFF_DOMAIN_ROUTING_TTL_SECS: i64 = 600;
const DNS_FORWARDER_CACHE_MAX_ENTRIES: usize = 128;
const DNS_STREAM_POOL_MAX_STREAMS: usize = 16;
const DNS_STREAM_POOL_MAX_IDLE: usize = 8;
const DNS_MULTIPLEX_MAX_CONCURRENT_STREAMS: usize = 128;
const DNS_TRACE_CACHE_UNRESOLVED: &str = "unresolved";
const DNS_TRACE_CACHE_BYPASS: &str = "bypass";
const DNS_TRACE_CACHE_HIT: &str = "hit";
const DNS_TRACE_CACHE_LOCKED_HIT: &str = "locked-hit";
const DNS_TRACE_CACHE_MISS: &str = "miss";
const DNS_TRACE_CACHE_UNKNOWN: &str = "unknown";
const DNS_TRACE_ROUTING_UNRESOLVED: &str = "unresolved";
const DNS_TRACE_ROUTING_ASIS: &str = "asis";
const DNS_TRACE_ROUTING_UPSTREAM: &str = "upstream";
const DNS_TRACE_ROUTING_IPVERSION_PREFERENCE: &str = "ipversion_preference";
const DNS_TRACE_ROUTING_RESOLVED: &str = "resolved";
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
const DNS_TRACE_REASON_IPVERSION: &str = "ipversion preference resolved DNS path";
pub(super) const DNS_TRANSPORT_ROUTE_DIRECT: &str = "direct";
pub(super) const DNS_TRANSPORT_ROUTE_PROXY: &str = "proxy";
pub(super) const DNS_TRANSPORT_TARGET_FAMILY_IPV4: &str = "ipv4";
pub(super) const DNS_TRANSPORT_TARGET_FAMILY_IPV6: &str = "ipv6";
pub(super) const DNS_TRANSPORT_OUTCOME_SUCCESS: &str = "success";
pub(super) const DNS_TRANSPORT_OUTCOME_ERROR: &str = "error";

async fn acquire_dns_permit<'a>(
    semaphore: &'a Semaphore,
    context: &'static str,
) -> Result<tokio::sync::SemaphorePermit<'a>, String> {
    time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, semaphore.acquire())
        .await
        .map_err(|_| format!("{context} concurrency wait timeout"))?
        .map_err(|_| format!("{context} concurrency limiter is closed"))
}

async fn acquire_dns_owned_permit(
    semaphore: Arc<Semaphore>,
    context: &'static str,
) -> Result<tokio::sync::OwnedSemaphorePermit, String> {
    time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, semaphore.acquire_owned())
        .await
        .map_err(|_| format!("{context} concurrency wait timeout"))?
        .map_err(|_| format!("{context} concurrency limiter is closed"))
}

#[derive(Clone, Debug)]
pub(super) struct ResidentDnsPlan {
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
    ipversion_preference_registry: Arc<ResidentDnsIpversionPreferenceRegistry>,
    mark: u32,
    upstream_router: Option<Arc<ResidentDnsUpstreamRouter>>,
}

#[derive(Clone, Debug)]
pub(super) struct ResidentDnsQueryResult {
    pub(super) response: Vec<u8>,
    pub(super) trace: ResidentDnsTraceSummary,
}

impl ResidentDnsPlan {
    pub(super) fn asis(mark: u32) -> Self {
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
            ipversion_preference_registry: Arc::new(
                ResidentDnsIpversionPreferenceRegistry::default(),
            ),
            mark,
            upstream_router: None,
        }
    }

    pub(super) fn with_domain_routing(
        mut self,
        domain_routing: Option<Arc<ResidentDnsDomainRouting>>,
    ) -> Self {
        self.domain_routing = domain_routing;
        self
    }

    pub(super) fn with_upstream_routing(
        mut self,
        upstream_router: Option<Arc<ResidentDnsUpstreamRouter>>,
    ) -> Self {
        self.upstream_router = upstream_router;
        self
    }

    pub(super) fn with_udp_runtime_resources(
        mut self,
        runtime: ResidentDnsUdpRuntimeConfig,
        metrics: Arc<ResidentDataplaneMetrics>,
    ) -> Self {
        self.forwarders = Arc::new(ResidentDnsForwarderCache::new(runtime, metrics));
        self
    }

    pub(super) async fn shutdown_forwarders(&self, deadline: time::Instant) -> Value {
        self.forwarders.shutdown(deadline).await
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn reload_handle(
        &self,
    ) -> ResidentDnsReloadHandle {
        ResidentDnsReloadHandle::new(Arc::clone(&self.cache), self.domain_routing.clone())
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn restore_reload_snapshot(
        &self,
        snapshot: &ResidentDnsReloadSnapshot,
    ) -> Result<ResidentDnsReloadRestoreReport, String> {
        ResidentDnsReloadRestoreReport::restore_into(self, snapshot)
    }

    pub(super) async fn resolve_domain_has_ip_for_dial(
        &self,
        domain: &str,
        destination: IpAddr,
    ) -> bool {
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

    pub(super) fn cached_domain_has_ip(
        &self,
        domain: &str,
        qtype: u16,
        ignore_fixed_ttl: bool,
    ) -> bool {
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

pub(super) fn build_resident_dns_plan(
    config: &Config,
    geodata: &ResidentGeodataStore,
) -> Result<ResidentDnsPlan, String> {
    let so_mark_from_dae = effective_so_mark_from_dae(config.global.so_mark_from_dae);
    let upstreams = parse_dns_upstreams(config)?;
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
        ipversion_preference_registry: Arc::new(ResidentDnsIpversionPreferenceRegistry::default()),
        mark: so_mark_from_dae,
        upstream_router: None,
    })
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

pub(super) async fn handle_resident_dns_udp_async(
    plan: &ResidentDnsPlan,
    original_dst: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    handle_resident_dns_request_async(
        plan,
        original_dst,
        payload,
        Some(ResidentDnsAsisTransport::Udp),
    )
    .await
}

pub(super) async fn handle_resident_dns_tcp_async(
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

pub(super) async fn handle_resident_dns_local_trace_async(
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
    let mut trace = ResidentDnsTraceSummary::from_request(plan, &request)?;
    if dns_ipversion_preference_applies(plan, &request) {
        let (response, transport_attempts) = capture_dns_transport_trace_async(
            handle_resident_dns_request_async(plan, original_dst, payload, None),
        )
        .await;
        let response = response?;
        trace.cache = DNS_TRACE_CACHE_UNKNOWN.to_owned();
        trace.request_routing = DNS_TRACE_ROUTING_IPVERSION_PREFERENCE.to_owned();
        trace.response_routing = DNS_TRACE_ROUTING_RESOLVED.to_owned();
        trace.transport_attempts = transport_attempts;
        return Ok(trace.finish(response, DNS_TRACE_REASON_IPVERSION));
    }
    let (result, transport_attempts) =
        capture_dns_transport_trace_async(handle_resident_dns_request_without_preference_trace(
            plan,
            original_dst,
            payload,
            &request,
            None,
            trace,
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
    if let Some(response) =
        handle_ipversion_preference(plan, original_dst, payload, &request, asis_transport).await?
    {
        return Ok(response);
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

fn dns_ipversion_preference_applies(plan: &ResidentDnsPlan, request: &DnsPacketView<'_>) -> bool {
    let Some(preferred_qtype) = plan.ipversion_prefer else {
        return false;
    };
    if request.question_count() != 1 {
        return false;
    }
    let Some(question) = request.questions().next() else {
        return false;
    };
    let requested_qtype = question.qtype();
    matches!(requested_qtype, DNS_QTYPE_A | DNS_QTYPE_AAAA) && requested_qtype != preferred_qtype
}

async fn handle_ipversion_preference(
    plan: &ResidentDnsPlan,
    original_dst: SocketAddr,
    payload: &[u8],
    request: &DnsPacketView<'_>,
    asis_transport: Option<ResidentDnsAsisTransport>,
) -> Result<Option<Vec<u8>>, String> {
    let Some(preferred_qtype) = plan.ipversion_prefer else {
        return Ok(None);
    };
    if request.question_count() != 1 {
        return Ok(None);
    }
    let question = request
        .questions()
        .next()
        .ok_or_else(|| "DNS request has no question".to_owned())?;
    let requested_qtype = question.qtype();
    if !matches!(requested_qtype, DNS_QTYPE_A | DNS_QTYPE_AAAA) {
        return Ok(None);
    }
    let qname = question
        .qname_to_canonical_string()
        .map_err(|err| format!("read DNS request qname for ipversion preference: {err}"))?;
    let preferred_key = DnsCacheKey::new(qname, preferred_qtype, question.qclass());
    let requested = handle_resident_dns_request_without_preference(
        plan,
        original_dst,
        payload,
        request,
        asis_transport,
    )
    .await;
    if requested_qtype == preferred_qtype {
        if let Ok(response) = requested.as_ref() {
            plan.ipversion_preference_registry
                .notify_preferred(&preferred_key, dns_response_has_any_ip(response)?);
        } else {
            plan.ipversion_preference_registry
                .notify_preferred(&preferred_key, false);
        }
        return requested.map(Some);
    }
    if dns_preferred_cache_has_ip(plan, &preferred_key)? {
        return build_reject_response(payload, request).map(Some);
    }
    let preferred_wait = plan
        .ipversion_preference_registry
        .wait_for_preferred(&preferred_key, dns_ipversion_preference_wait_timeout())
        .await
        .unwrap_or(false);
    if preferred_wait || dns_preferred_cache_has_ip(plan, &preferred_key)? {
        return build_reject_response(payload, request).map(Some);
    }
    requested.map(Some)
}

fn dns_preferred_cache_has_ip(
    plan: &ResidentDnsPlan,
    preferred_key: &DnsCacheKey,
) -> Result<bool, String> {
    plan.cache.lookup_key_has_any_ip(preferred_key, false)
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
    let _inflight = plan.cache.lock_key(cache_key.clone()).await?;
    if plan
        .cache
        .lookup_response_into(&cache_key, request, false, &mut cached_response)?
    {
        return Ok(cached_response);
    }
    let context = ProxyDnsRequestContext::from_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT);
    match action {
        ResidentDnsRequestAction::AsIs => {
            let response = forward_dns_asis_async(
                original_dst,
                payload,
                plan.mark,
                asis_transport.expect("asis transport checked before forwarding"),
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
    }
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
    let _inflight = plan.cache.lock_key(cache_key.clone()).await?;
    if plan
        .cache
        .lookup_response_into(&cache_key, request, false, &mut cached_response)?
    {
        trace.add_cache_elapsed(cache_started);
        trace.cache = DNS_TRACE_CACHE_LOCKED_HIT.to_owned();
        trace.response_routing = DNS_TRACE_ROUTING_CACHE.to_owned();
        return Ok(trace.finish(cached_response, DNS_TRACE_REASON_CACHE_LOCKED_HIT));
    }
    trace.add_cache_elapsed(cache_started);
    trace.cache = DNS_TRACE_CACHE_MISS.to_owned();
    let context = ProxyDnsRequestContext::from_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT);
    match action {
        ResidentDnsRequestAction::AsIs => {
            trace.push_asis_attempt();
            let response = forward_dns_asis_async(
                original_dst,
                payload,
                plan.mark,
                asis_transport.expect("asis transport checked before forwarding"),
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
    }
}

async fn forward_dns_asis_async(
    original_dst: SocketAddr,
    payload: &[u8],
    mark: u32,
    transport: ResidentDnsAsisTransport,
) -> Result<Vec<u8>, String> {
    match transport {
        ResidentDnsAsisTransport::Udp => forward_dns_udp_async(original_dst, payload, mark)
            .await
            .map_err(|err| format!("forward DNS UDP asis to {original_dst}: {err}")),
        ResidentDnsAsisTransport::Tcp => forward_dns_tcp_asis_async(original_dst, payload, mark)
            .await
            .map_err(|err| format!("forward DNS TCP asis to {original_dst}: {err}")),
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
        ResidentDnsRequestAction::Upstream(upstream) => {
            ResidentDnsResponseCacheScope::upstream(upstream)
        }
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

#[cfg(test)]
mod tests;

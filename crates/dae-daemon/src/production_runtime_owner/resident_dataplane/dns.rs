use std::collections::BTreeMap;
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::{Buf, Bytes};
use dae_config::{Config, DynamicFunctionValue, Function, Param, RoutingRule};
use dae_control::{DomainRoutingDnsEvent, DomainRoutingIpKey, DomainRoutingOwner, ip_to_key};
use dae_dns::{
    DOH_MEDIA_TYPE, DnsCacheEntry, DnsCacheKey, DnsCacheStore, DnsDomainSet, DnsPacketView,
    DnsRequestMatchKind, DnsRequestMatchSpec, DnsRequestOutboundIndex, DnsResponseCachePlan,
    DnsResponseMatchKind, DnsResponseMatchSpec, DnsResponseOutboundIndex, RequestMatcher,
    ResponseMatcher, build_doh_request, build_response_cache_plan_from_packet,
    dns_data_with_zero_id, restore_packed_response_request_id,
    validate_dns_packet_response_for_request_fast, validate_doh_response,
};
use dae_routing::IpPrefix;
use dae_routing::RoutingMatcher;
use http::Request;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::{OnceCell, OwnedMutexGuard};
use tokio::time;

use super::super::resident_routing::{
    ResidentGeodataStore, expand_resident_dns_request_qname_rules_with_resolver,
    expand_resident_dns_response_ip_params_with_resolver,
    expand_resident_dns_response_qname_rules_with_resolver,
};
use super::RESIDENT_UDP_RESPONSE_TIMEOUT;
use super::direct::open_direct_tcp_connection_async;
use super::tcp::{open_marked_quic_endpoint, set_socket_mark};

mod routing;
mod transport;
#[cfg(test)]
use self::routing::parse_dns_upstream;
use self::routing::{
    build_request_matcher, build_response_matcher, parse_dns_upstreams,
    parse_request_default_action, parse_response_default_action, select_request_action,
    select_response_action, select_response_action_for_upstream,
};
#[cfg(test)]
use self::transport::parse_doh_http_response;
use self::transport::{forward_dns_to_upstream_async, forward_dns_udp_async};

const DNS_RESPONSE_FLAGS_EMPTY_NOERROR: u16 = 0x8180;
const DNS_QTYPE_A: u16 = 1;
const DNS_QTYPE_AAAA: u16 = 28;
const DNS_RESPONSE_READ_LIMIT: usize = 4096;
const DNS_RESPONSE_REROUTE_LIMIT: usize = 4;
const DNS_TCP_MESSAGE_READ_LIMIT: usize = u16::MAX as usize;
const DNS_DOH_RESPONSE_READ_LIMIT: usize = 1024 * 1024;
const DNS_DEFAULT_PORT: u16 = 53;
const DNS_TLS_DEFAULT_PORT: u16 = 853;
const DNS_HTTPS_DEFAULT_PORT: u16 = 443;
const DNS_DEFAULT_DOH_PATH: &str = "/dns-query";
const DNS_DOH3_ALPN: &str = "h3";
const DNS_DOQ_ALPN: &str = "doq";
const TCP_SNIFF_DOMAIN_ROUTING_TTL_SECS: i64 = 600;

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
    fixed_domain_ttl: Arc<BTreeMap<String, i64>>,
    ipversion_prefer: Option<u16>,
    mark: u32,
}

impl ResidentDnsPlan {
    pub(super) fn asis(mark: u32) -> Self {
        Self {
            request_matcher: None,
            request_actions: Vec::new(),
            request_default_action: ResidentDnsRequestAction::AsIs,
            response_matcher: None,
            response_actions: Vec::new(),
            response_default_action: ResidentDnsResponseAction::Accept,
            domain_routing: None,
            cache: Arc::new(ResidentDnsRuntimeCache::default()),
            fixed_domain_ttl: Arc::new(BTreeMap::new()),
            ipversion_prefer: None,
            mark,
        }
    }

    pub(super) fn with_domain_routing(
        mut self,
        domain_routing: Option<Arc<ResidentDnsDomainRouting>>,
    ) -> Self {
        self.domain_routing = domain_routing;
        self
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
            false,
        )
        .await
        else {
            return false;
        };
        dns_response_has_any_ip(&response).unwrap_or(false)
    }
}

#[derive(Debug, Default)]
struct ResidentDnsRuntimeCache {
    store: Mutex<DnsCacheStore>,
    inflight: Mutex<BTreeMap<DnsCacheKey, Arc<tokio::sync::Mutex<()>>>>,
}

struct ResidentDnsInflightGuard<'a> {
    cache: &'a ResidentDnsRuntimeCache,
    key: DnsCacheKey,
    lock: Arc<tokio::sync::Mutex<()>>,
    _guard: OwnedMutexGuard<()>,
}

impl ResidentDnsRuntimeCache {
    async fn lock_key(&self, key: DnsCacheKey) -> Result<ResidentDnsInflightGuard<'_>, String> {
        let lock = {
            let mut inflight = self
                .inflight
                .lock()
                .map_err(|_| "resident DNS inflight lock poisoned".to_owned())?;
            inflight
                .entry(key.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let guard = Arc::clone(&lock).lock_owned().await;
        Ok(ResidentDnsInflightGuard {
            cache: self,
            key,
            lock,
            _guard: guard,
        })
    }

    fn lookup_response(
        &self,
        request: &DnsPacketView<'_>,
        ignore_fixed_ttl: bool,
    ) -> Result<Option<Vec<u8>>, String> {
        let now_unix = unix_now();
        let question = request
            .questions()
            .next()
            .ok_or_else(|| "DNS request has no question".to_owned())?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?;
        let Some(entry) = store
            .lookup_packet_question(now_unix, &question, ignore_fixed_ttl)
            .map_err(|err| format!("lookup resident DNS response cache: {err}"))?
        else {
            return Ok(None);
        };
        Ok(entry.fill_packed_response(request.id()))
    }

    fn lookup_key_has_any_ip(
        &self,
        key: &DnsCacheKey,
        ignore_fixed_ttl: bool,
    ) -> Result<bool, String> {
        let now_unix = unix_now();
        let mut store = self
            .store
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?;
        Ok(store
            .lookup(now_unix, key, ignore_fixed_ttl)
            .is_some_and(|entry| entry.has_any_ip))
    }

    fn insert_response(
        &self,
        now_unix: i64,
        key: DnsCacheKey,
        entry: DnsCacheEntry,
    ) -> Result<(), String> {
        self.store
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?
            .insert(now_unix, key, entry);
        Ok(())
    }

    fn remove_request(&self, request: &DnsPacketView<'_>) -> Result<Option<DnsCacheEntry>, String> {
        let question = request
            .questions()
            .next()
            .ok_or_else(|| "DNS request has no question".to_owned())?;
        self.store
            .lock()
            .map_err(|_| "resident DNS response cache lock poisoned".to_owned())?
            .remove_packet_question(&question)
            .map_err(|err| format!("remove resident DNS response cache entry: {err}"))
    }
}

impl Drop for ResidentDnsInflightGuard<'_> {
    fn drop(&mut self) {
        if Arc::strong_count(&self.lock) != 3 {
            return;
        }
        if let Ok(mut inflight) = self.cache.inflight.lock() {
            if inflight
                .get(&self.key)
                .is_some_and(|current| Arc::ptr_eq(current, &self.lock))
            {
                inflight.remove(&self.key);
            }
        }
    }
}

#[derive(Debug)]
pub(super) struct ResidentDnsDomainRouting {
    map_id: u32,
    routing_matcher: RoutingMatcher,
    state: Mutex<ResidentDnsDomainRoutingState>,
}

#[derive(Debug)]
struct ResidentDnsDomainRoutingState {
    owner: DomainRoutingOwner,
    cache: DnsCacheStore,
    domain_bitmap: Vec<u32>,
    sniff_owners: BTreeMap<String, i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResidentDnsDomainRoutingUpdatePlan {
    key: DnsCacheKey,
    entry: DnsCacheEntry,
    bitmap: Vec<u32>,
    ips: Vec<DomainRoutingIpKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResidentDomainRoutingIpUpdatePlan {
    owner_key: String,
    bitmap: Vec<u32>,
    ip: DomainRoutingIpKey,
}

impl ResidentDnsDomainRouting {
    pub(super) fn new(map_id: u32, routing_matcher: RoutingMatcher) -> Self {
        Self {
            map_id,
            routing_matcher,
            state: Mutex::new(ResidentDnsDomainRoutingState {
                owner: DomainRoutingOwner::default(),
                cache: DnsCacheStore::default(),
                domain_bitmap: Vec::new(),
                sniff_owners: BTreeMap::new(),
            }),
        }
    }

    fn record_accepted_response(&self, cache_plan: &DnsResponseCachePlan) -> Result<(), String> {
        let now_unix = unix_now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS domain routing state lock poisoned".to_owned())?;
        self.sweep_expired_locked(now_unix, &mut state)?;
        let Some(plan) = build_resident_dns_domain_routing_update_plan(
            &self.routing_matcher,
            &mut state.domain_bitmap,
            cache_plan,
        )?
        else {
            return Ok(());
        };
        let owner_key = plan.entry.route_owner_key.clone();
        state
            .owner
            .apply_dns_event_by_id(
                self.map_id,
                DomainRoutingDnsEvent::from_keys(
                    &owner_key,
                    &plan.bitmap,
                    plan.ips.iter().copied(),
                ),
            )
            .map_err(|err| format!("apply resident DNS domain routing response: {err}"))?;
        state
            .cache
            .insert_without_route_owner_key(now_unix, plan.key, plan.entry);
        Ok(())
    }

    pub(super) fn record_sniffed_domain_ip(
        &self,
        domain: &str,
        ip: IpAddr,
    ) -> Result<bool, String> {
        let now_unix = unix_now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS domain routing state lock poisoned".to_owned())?;
        self.sweep_expired_locked(now_unix, &mut state)?;
        let Some(plan) = build_resident_domain_routing_ip_update_plan(
            &self.routing_matcher,
            &mut state.domain_bitmap,
            "tcp-sniff",
            domain,
            ip,
        )?
        else {
            return Ok(false);
        };
        state
            .owner
            .apply_dns_event_by_id(
                self.map_id,
                DomainRoutingDnsEvent::from_keys(&plan.owner_key, &plan.bitmap, [plan.ip]),
            )
            .map_err(|err| format!("apply resident TCP sniff domain routing update: {err}"))?;
        state.sniff_owners.insert(
            plan.owner_key,
            now_unix.saturating_add(TCP_SNIFF_DOMAIN_ROUTING_TTL_SECS),
        );
        Ok(true)
    }

    fn remove_request(&self, request: &DnsPacketView<'_>) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS domain routing state lock poisoned".to_owned())?;
        let Some(removed) = state
            .cache
            .remove_packet_question(
                &request
                    .questions()
                    .next()
                    .ok_or_else(|| "DNS request has no question".to_owned())?,
            )
            .map_err(|err| format!("remove resident DNS domain routing cache entry: {err}"))?
        else {
            return Ok(());
        };
        if removed.route_owner_key.is_empty() {
            return Ok(());
        }
        state
            .owner
            .apply_dns_event_by_id(
                self.map_id,
                DomainRoutingDnsEvent::remove(&removed.route_owner_key),
            )
            .map_err(|err| format!("remove resident DNS domain routing owner: {err}"))?;
        Ok(())
    }

    fn sweep_expired_locked(
        &self,
        now_unix: i64,
        state: &mut ResidentDnsDomainRoutingState,
    ) -> Result<(), String> {
        for expired in state.cache.sweep(now_unix) {
            if expired.route_owner_key.is_empty() {
                continue;
            }
            state
                .owner
                .apply_dns_event_by_id(
                    self.map_id,
                    DomainRoutingDnsEvent::remove(&expired.route_owner_key),
                )
                .map_err(|err| {
                    format!("remove expired resident DNS domain routing owner: {err}")
                })?;
        }
        let expired_sniff_owners = state
            .sniff_owners
            .iter()
            .filter_map(|(owner, deadline)| (*deadline <= now_unix).then(|| owner.clone()))
            .collect::<Vec<_>>();
        for owner in expired_sniff_owners {
            state
                .owner
                .apply_dns_event_by_id(self.map_id, DomainRoutingDnsEvent::remove(&owner))
                .map_err(|err| {
                    format!("remove expired resident TCP sniff domain routing owner: {err}")
                })?;
            state.sniff_owners.remove(&owner);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum ResidentDnsRequestAction {
    AsIs,
    Reject,
    Upstream(ResidentDnsUpstream),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ResidentDnsResponseAction {
    Accept,
    Reject,
    Upstream(ResidentDnsUpstream),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResidentDnsUpstream {
    index: u8,
    tag: String,
    target: ResidentDnsUpstreamTarget,
    scheme: ResidentDnsUpstreamScheme,
    path: String,
}

#[derive(Clone, Debug)]
struct ResidentDnsUpstreams {
    by_tag: BTreeMap<String, ResidentDnsUpstream>,
    tag_to_index: BTreeMap<String, u8>,
    request_actions: Vec<ResidentDnsRequestAction>,
    response_actions: Vec<ResidentDnsResponseAction>,
}

#[derive(Clone, Debug)]
struct ResidentDnsUpstreamTarget {
    authority: String,
    host: String,
    port: u16,
    literal_addr: Option<SocketAddr>,
    resolved_addr: Arc<OnceCell<SocketAddr>>,
}

impl ResidentDnsUpstreamTarget {
    async fn resolve(&self) -> Result<SocketAddr, String> {
        if let Some(addr) = self.literal_addr {
            return Ok(addr);
        }
        self.resolved_addr
            .get_or_try_init(|| async { resolve_dns_upstream_async(&self.authority).await })
            .await
            .copied()
    }
}

impl PartialEq for ResidentDnsUpstreamTarget {
    fn eq(&self, other: &Self) -> bool {
        self.authority == other.authority
            && self.host == other.host
            && self.port == other.port
            && self.literal_addr == other.literal_addr
    }
}

impl Eq for ResidentDnsUpstreamTarget {}

async fn resolve_dns_upstream_async(authority: &str) -> Result<SocketAddr, String> {
    tokio::net::lookup_host(authority)
        .await
        .map_err(|err| format!("resolve DNS upstream {authority}: {err}"))?
        .next()
        .ok_or_else(|| format!("DNS upstream {authority} returned no IP address"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResidentDnsUpstreamScheme {
    Udp,
    Tcp,
    TcpUdp,
    Tls,
    Https,
    Quic,
    Http3,
}

impl ResidentDnsUpstreamScheme {
    const fn requires_dns_response_id_match(self) -> bool {
        matches!(self, Self::Udp | Self::Tcp | Self::TcpUdp | Self::Tls)
    }
}

pub(super) fn build_resident_dns_plan(
    config: &Config,
    geodata: &ResidentGeodataStore,
) -> Result<ResidentDnsPlan, String> {
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
        fixed_domain_ttl: Arc::new(fixed_domain_ttl),
        ipversion_prefer,
        mark: config.global.so_mark_from_dae,
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

fn build_resident_dns_domain_routing_update_plan(
    routing_matcher: &RoutingMatcher,
    domain_bitmap: &mut Vec<u32>,
    cache_plan: &DnsResponseCachePlan,
) -> Result<Option<ResidentDnsDomainRoutingUpdatePlan>, String> {
    if cache_plan.entry.ips.is_empty() {
        return Ok(None);
    }
    let bitmap = routing_matcher
        .domain_bitmap_for_domain_into(&cache_plan.key.qname, domain_bitmap)
        .map_err(|err| format!("match resident DNS response domain routing bitmap: {err}"))?
        .to_vec();
    if bitmap.iter().all(|word| *word == 0) {
        return Ok(None);
    }
    let ips = cache_plan
        .entry
        .ips
        .iter()
        .copied()
        .map(ip_to_key)
        .collect::<Vec<_>>();
    let mut entry = cache_plan.entry.clone();
    entry.domain_bitmap = bitmap.clone();
    Ok(Some(ResidentDnsDomainRoutingUpdatePlan {
        key: cache_plan.key.clone(),
        entry,
        bitmap,
        ips,
    }))
}

fn build_resident_domain_routing_ip_update_plan(
    routing_matcher: &RoutingMatcher,
    domain_bitmap: &mut Vec<u32>,
    owner_prefix: &str,
    domain: &str,
    ip: IpAddr,
) -> Result<Option<ResidentDomainRoutingIpUpdatePlan>, String> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() || ip.is_unspecified() {
        return Ok(None);
    }
    let bitmap = routing_matcher
        .domain_bitmap_for_domain_into(domain, domain_bitmap)
        .map_err(|err| format!("match resident sniffed domain routing bitmap: {err}"))?
        .to_vec();
    if bitmap.iter().all(|word| *word == 0) {
        return Ok(None);
    }
    Ok(Some(ResidentDomainRoutingIpUpdatePlan {
        owner_key: format!("{owner_prefix}|{domain}|{ip}"),
        bitmap,
        ip: ip_to_key(ip),
    }))
}

fn record_accepted_dns_response(plan: &ResidentDnsPlan, response: &[u8]) -> Result<(), String> {
    let now_unix = unix_now();
    let fixed_domain_ttl = fixed_domain_ttl_for_response(plan, response)?;
    let Some(cache_plan) =
        build_response_cache_plan_from_packet(now_unix, response, fixed_domain_ttl)
            .map_err(|err| format!("build resident DNS response cache plan: {err}"))?
    else {
        return Ok(());
    };
    plan.cache
        .insert_response(now_unix, cache_plan.key.clone(), cache_plan.entry.clone())?;
    if let Some(domain_routing) = plan.domain_routing.as_ref() {
        domain_routing.record_accepted_response(&cache_plan)?;
    }
    Ok(())
}

fn remove_dns_response_cache_for_request(
    plan: &ResidentDnsPlan,
    request: &DnsPacketView<'_>,
) -> Result<(), String> {
    let _ = plan.cache.remove_request(request)?;
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

pub(super) async fn handle_resident_dns_udp_async(
    plan: &ResidentDnsPlan,
    original_dst: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    handle_resident_dns_request_async(plan, original_dst, payload, true).await
}

pub(super) async fn handle_resident_dns_local_async(
    plan: &ResidentDnsPlan,
    original_dst: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    handle_resident_dns_request_async(plan, original_dst, payload, false).await
}

async fn handle_resident_dns_request_async(
    plan: &ResidentDnsPlan,
    original_dst: SocketAddr,
    payload: &[u8],
    allow_asis: bool,
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
        handle_ipversion_preference(plan, original_dst, payload, &request, allow_asis).await?
    {
        return Ok(response);
    }
    handle_resident_dns_request_without_preference(
        plan,
        original_dst,
        payload,
        &request,
        allow_asis,
    )
    .await
}

async fn handle_ipversion_preference(
    plan: &ResidentDnsPlan,
    original_dst: SocketAddr,
    payload: &[u8],
    request: &DnsPacketView<'_>,
    allow_asis: bool,
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
    if requested_qtype == preferred_qtype {
        return Ok(None);
    }
    let preferred_payload = dns_request_with_qtype(payload, request, preferred_qtype)?;
    let preferred_request = DnsPacketView::parse(&preferred_payload)
        .map_err(|err| format!("parse preferred DNS request: {err}"))?;
    let preferred_future = handle_resident_dns_request_without_preference(
        plan,
        original_dst,
        &preferred_payload,
        &preferred_request,
        allow_asis,
    );
    let requested_future = handle_resident_dns_request_without_preference(
        plan,
        original_dst,
        payload,
        request,
        allow_asis,
    );
    tokio::pin!(preferred_future);
    tokio::pin!(requested_future);
    let mut requested = None;
    let preferred = loop {
        tokio::select! {
            preferred = &mut preferred_future => break preferred,
            requested_result = &mut requested_future, if requested.is_none() => {
                requested = Some(requested_result);
            }
        }
    };
    if let Ok(response) = preferred.as_ref() {
        if dns_response_has_any_ip(response)? {
            return build_reject_response(payload, request).map(Some);
        }
    }
    let requested = match requested {
        Some(requested) => requested,
        None => requested_future.await,
    };
    match requested {
        Ok(response) => Ok(Some(response)),
        Err(requested_err) => match preferred {
            Ok(_) => Err(requested_err),
            Err(preferred_err) => Err(format!(
                "{requested_err}; preferred lookup: {preferred_err}"
            )),
        },
    }
}

async fn handle_resident_dns_request_without_preference(
    plan: &ResidentDnsPlan,
    original_dst: SocketAddr,
    payload: &[u8],
    request: &DnsPacketView<'_>,
    allow_asis: bool,
) -> Result<Vec<u8>, String> {
    let action = select_request_action(plan, request)?;
    if matches!(action, ResidentDnsRequestAction::Reject) {
        remove_dns_response_cache_for_request(plan, request)?;
        return build_reject_response(payload, request);
    }
    if let ResidentDnsRequestAction::AsIs = action {
        if !allow_asis {
            return Err(
                "dns request routing cannot use \"asis\" for locally bound dns listener; configure an explicit upstream instead"
                    .to_owned(),
            );
        }
    }
    if let Some(response) = plan.cache.lookup_response(request, false)? {
        return Ok(response);
    }
    let key = dns_cache_key_for_request(request)?;
    let _inflight = plan.cache.lock_key(key).await?;
    if let Some(response) = plan.cache.lookup_response(request, false)? {
        return Ok(response);
    }
    match action {
        ResidentDnsRequestAction::AsIs => {
            let response = forward_dns_udp_async(original_dst, payload, plan.mark)
                .await
                .map_err(|err| format!("forward DNS asis to {original_dst}: {err}"))?;
            validate_dns_response_for_request(request, &response, true)?;
            let response_action = select_response_action_for_upstream(
                plan,
                request,
                &response,
                DnsRequestOutboundIndex::ASIS,
            )?;
            match response_action {
                ResidentDnsResponseAction::Accept => {
                    record_accepted_dns_response(plan, &response)?;
                    Ok(response)
                }
                ResidentDnsResponseAction::Reject => build_reject_response(payload, request),
                ResidentDnsResponseAction::Upstream(upstream) => {
                    resolve_dns_response_routing(plan, payload, request, upstream).await
                }
            }
        }
        ResidentDnsRequestAction::Reject => unreachable!("reject handled before cache lookup"),
        ResidentDnsRequestAction::Upstream(ref upstream) => {
            resolve_dns_response_routing(plan, payload, request, upstream.clone()).await
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

fn dns_request_with_qtype(
    payload: &[u8],
    request: &DnsPacketView<'_>,
    qtype: u16,
) -> Result<Vec<u8>, String> {
    let qtype_offset = request
        .answer_offset()
        .checked_sub(4)
        .ok_or_else(|| "DNS request question section is truncated".to_owned())?;
    if payload.len() < qtype_offset + 2 {
        return Err("DNS request qtype offset is outside packet".to_owned());
    }
    let mut out = payload.to_vec();
    out[qtype_offset..qtype_offset + 2].copy_from_slice(&qtype.to_be_bytes());
    Ok(out)
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
) -> Result<Vec<u8>, String> {
    for _ in 0..DNS_RESPONSE_REROUTE_LIMIT {
        let response = forward_dns_to_upstream_async(&upstream, request_payload, plan.mark).await?;
        validate_dns_response_for_request(
            request,
            &response,
            upstream.scheme.requires_dns_response_id_match(),
        )?;
        let response_action = select_response_action(plan, request, &response, &upstream)?;
        match response_action {
            ResidentDnsResponseAction::Accept => {
                record_accepted_dns_response(plan, &response)?;
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

fn build_reject_response(request: &[u8], view: &DnsPacketView<'_>) -> Result<Vec<u8>, String> {
    if request.len() < view.answer_offset() {
        return Err("DNS request question section is truncated".to_owned());
    }
    let mut response = Vec::with_capacity(view.answer_offset());
    response.extend_from_slice(&request[0..2]);
    response.extend_from_slice(&DNS_RESPONSE_FLAGS_EMPTY_NOERROR.to_be_bytes());
    response.extend_from_slice(&(view.question_count() as u16).to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&request[12..view.answer_offset()]);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use dae_config::Config;

    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    const QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    static TEST_ASSET_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn parse_config(input: &str) -> Config {
        let sections = dae_config::parser::parse_config(input).unwrap();
        dae_config::schema::build_config(&sections).unwrap()
    }

    fn local_dns_upstream_authority() -> &'static str {
        "localhost:53"
    }

    fn test_geodata() -> ResidentGeodataStore {
        ResidentGeodataStore::new(Vec::<std::path::PathBuf>::new())
    }

    fn test_asset_root(name: &str) -> PathBuf {
        let sequence = TEST_ASSET_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "dae-resident-dns-{name}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn write_asset(root: &Path, filename: &str, data: Vec<u8>) {
        fs::write(root.join(filename), data).unwrap();
    }

    #[test]
    fn resident_dns_plan_admits_fallback_upstream_udp() {
        let input = r#"
        global { so_mark_from_dae: 1234 }
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
          }
          routing {
            request {
              fallback: primary
            }
          }
        }
        "#
        .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
        let config = parse_config(&input);
        let geodata = test_geodata();
        let plan = build_resident_dns_plan(&config, &geodata).unwrap();
        match plan.request_default_action {
            ResidentDnsRequestAction::Upstream(upstream) => {
                assert_eq!(upstream.tag, "primary");
                assert_eq!(upstream.target.authority, local_dns_upstream_authority());
                assert_eq!(upstream.target.literal_addr, None);
            }
            _ => panic!("expected upstream default action"),
        }
        assert_eq!(plan.mark, 1234);
    }

    fn query_with_qtype(qtype: u16) -> Vec<u8> {
        let mut query = QUERY.to_vec();
        let offset = query.len() - 4;
        query[offset..offset + 2].copy_from_slice(&qtype.to_be_bytes());
        query
    }

    fn a_response(address: [u8; 4]) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&[0x12, 0x34]);
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&QUERY[12..]);
        response.extend_from_slice(&0xc00c_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&address);
        response
    }

    fn response_with_question_qtype(mut response: Vec<u8>, qtype: u16) -> Vec<u8> {
        let view = DnsPacketView::parse(&response).unwrap();
        let qtype_offset = view.answer_offset() - 4;
        response[qtype_offset..qtype_offset + 2].copy_from_slice(&qtype.to_be_bytes());
        response
    }

    fn domain_routing_test_matcher() -> RoutingMatcher {
        RoutingMatcher::from_fixture_value(&serde_json::json!({
            "domain_sets": [
                {"bit": 0, "key": "suffix", "patterns": ["example.com"]}
            ],
            "matches": [
                {"type": "domain_set", "outbound": "direct"},
                {"type": "fallback", "outbound": "block"}
            ]
        }))
        .unwrap()
    }

    #[test]
    fn resident_dns_domain_routing_update_plan_records_accepted_response_ips() {
        let matcher = domain_routing_test_matcher();
        let mut bitmap_buffer = Vec::new();
        let response = a_response([203, 0, 113, 42]);
        let cache_plan = build_response_cache_plan_from_packet(1_700_000_000, &response, None)
            .unwrap()
            .unwrap();
        let plan = build_resident_dns_domain_routing_update_plan(
            &matcher,
            &mut bitmap_buffer,
            &cache_plan,
        )
        .unwrap()
        .unwrap();

        assert_eq!(plan.key.qname, "example.com.");
        assert_eq!(plan.entry.route_owner_key, "example.com.|1|1");
        assert_eq!(plan.bitmap, vec![0x1]);
        assert_eq!(plan.ips, vec![ip_to_key("203.0.113.42".parse().unwrap())]);
        assert_eq!(plan.entry.domain_bitmap, vec![0x1]);
    }

    #[test]
    fn resident_dns_domain_routing_update_plan_skips_unmatched_domain() {
        let matcher = domain_routing_test_matcher();
        let mut bitmap_buffer = Vec::new();
        let mut response = a_response([203, 0, 113, 42]);
        response[13] = b'i';
        response[14] = b'n';
        response[15] = b'v';
        response[16] = b'a';
        response[17] = b'l';
        response[18] = b'i';
        response[19] = b'd';
        let cache_plan = build_response_cache_plan_from_packet(1_700_000_000, &response, None)
            .unwrap()
            .unwrap();

        let plan = build_resident_dns_domain_routing_update_plan(
            &matcher,
            &mut bitmap_buffer,
            &cache_plan,
        )
        .unwrap();

        assert_eq!(plan, None);
    }

    #[test]
    fn resident_dns_response_cache_honors_fixed_domain_ttl() {
        let request = DnsPacketView::parse(QUERY).unwrap();
        let mut plan = ResidentDnsPlan::asis(0);
        plan.fixed_domain_ttl = Arc::new(BTreeMap::from([("example.com".to_owned(), 0)]));

        record_accepted_dns_response(&plan, &a_response([203, 0, 113, 42])).unwrap();

        assert!(
            plan.cache
                .lookup_response(&request, false)
                .unwrap()
                .is_none()
        );
        assert!(
            plan.cache
                .lookup_response(&request, true)
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn resident_dns_ipversion_prefer_rejects_non_preferred_when_preferred_has_ip() {
        let mut plan = ResidentDnsPlan::asis(0);
        plan.ipversion_prefer = Some(DNS_QTYPE_A);
        record_accepted_dns_response(&plan, &a_response([203, 0, 113, 42])).unwrap();
        record_accepted_dns_response(
            &plan,
            &response_with_question_qtype(a_response([198, 51, 100, 42]), DNS_QTYPE_AAAA),
        )
        .unwrap();

        let aaaa_query = query_with_qtype(DNS_QTYPE_AAAA);
        let response =
            handle_resident_dns_udp_async(&plan, "127.0.0.1:53".parse().unwrap(), &aaaa_query)
                .await
                .unwrap();

        assert_eq!(&response[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x000f, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[tokio::test]
    async fn resident_dns_inflight_lock_serializes_same_key() {
        let cache = ResidentDnsRuntimeCache::default();
        let key = DnsCacheKey::new("example.com.", DNS_QTYPE_A, 1);
        let first = cache.lock_key(key.clone()).await.unwrap();
        let second = cache.lock_key(key);
        assert!(
            time::timeout(Duration::from_millis(10), second)
                .await
                .is_err()
        );
        drop(first);
        assert!(cache.inflight.lock().unwrap().is_empty());
    }

    #[test]
    fn resident_tcp_sniff_domain_routing_update_plan_records_target_ip() {
        let matcher = domain_routing_test_matcher();
        let mut bitmap_buffer = Vec::new();
        let plan = build_resident_domain_routing_ip_update_plan(
            &matcher,
            &mut bitmap_buffer,
            "tcp-sniff",
            "www.example.com.",
            "198.51.100.10".parse().unwrap(),
        )
        .unwrap()
        .unwrap();

        assert_eq!(plan.owner_key, "tcp-sniff|www.example.com|198.51.100.10");
        assert_eq!(plan.bitmap, vec![0x1]);
        assert_eq!(plan.ip, ip_to_key("198.51.100.10".parse().unwrap()));
    }

    #[test]
    fn resident_tcp_sniff_domain_routing_update_plan_skips_unmatched_domain() {
        let matcher = domain_routing_test_matcher();
        let mut bitmap_buffer = Vec::new();
        let plan = build_resident_domain_routing_ip_update_plan(
            &matcher,
            &mut bitmap_buffer,
            "tcp-sniff",
            "invalid.test",
            "198.51.100.10".parse().unwrap(),
        )
        .unwrap();

        assert_eq!(plan, None);
    }

    #[test]
    fn resident_dns_plan_admits_request_qname_and_qtype_rules() {
        let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
            secondary: 'udp://127.0.0.1:53'
          }
          routing {
            request {
              qname(suffix: example.com) && qtype(a, aaaa) -> primary
              qtype(https) -> reject
              fallback: secondary
            }
          }
        }
        "#
        .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
        let config = parse_config(&input);
        let geodata = test_geodata();
        let plan = build_resident_dns_plan(&config, &geodata).unwrap();

        let view = DnsPacketView::parse(QUERY).unwrap();
        match select_request_action(&plan, &view).unwrap() {
            ResidentDnsRequestAction::Upstream(upstream) => {
                assert_eq!(upstream.tag, "primary");
            }
            other => panic!("expected primary upstream action, got {other:?}"),
        }

        let https_query = query_with_qtype(65);
        let view = DnsPacketView::parse(&https_query).unwrap();
        assert!(matches!(
            select_request_action(&plan, &view).unwrap(),
            ResidentDnsRequestAction::Reject
        ));
    }

    #[test]
    fn resident_dns_plan_admits_response_qname_qtype_upstream_and_ip_rules() {
        let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
            secondary: 'udp://127.0.0.1:53'
          }
          routing {
            request {
              fallback: primary
            }
            response {
              qname(suffix: example.com) && qtype(a) && upstream(primary) && ip(203.0.113.0/24) -> secondary
              fallback: accept
            }
          }
        }
        "#
        .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
        let config = parse_config(&input);
        let geodata = test_geodata();
        let plan = build_resident_dns_plan(&config, &geodata).unwrap();
        let request = DnsPacketView::parse(QUERY).unwrap();
        let primary = match select_request_action(&plan, &request).unwrap() {
            ResidentDnsRequestAction::Upstream(upstream) => upstream,
            other => panic!("expected primary upstream action, got {other:?}"),
        };

        match select_response_action(&plan, &request, &a_response([203, 0, 113, 42]), &primary)
            .unwrap()
        {
            ResidentDnsResponseAction::Upstream(upstream) => {
                assert_eq!(upstream.tag, "secondary");
            }
            other => panic!("expected response reroute to secondary, got {other:?}"),
        }

        assert!(matches!(
            select_response_action(&plan, &request, &a_response([198, 51, 100, 42]), &primary)
                .unwrap(),
            ResidentDnsResponseAction::Accept
        ));
    }

    #[test]
    fn resident_dns_plan_admits_response_fallback_reject() {
        let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
          }
          routing {
            response {
              fallback: reject
            }
          }
        }
        "#
        .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
        let config = parse_config(&input);
        let geodata = test_geodata();
        let plan = build_resident_dns_plan(&config, &geodata).unwrap();
        let request = DnsPacketView::parse(QUERY).unwrap();
        assert!(matches!(
            select_response_action_for_upstream(
                &plan,
                &request,
                &a_response([203, 0, 113, 42]),
                DnsRequestOutboundIndex::ASIS,
            )
            .unwrap(),
            ResidentDnsResponseAction::Reject
        ));
    }

    #[test]
    fn resident_dns_plan_admits_official_upstream_schemes() {
        let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            udpup: 'udp://1.1.1.1'
            tcpup: 'tcp://dns.example'
            tcpudp: 'tcp+udp://dns.google:53'
            tlsup: 'tls://dns.google'
            httpsup: 'https://dns.google/dns-query'
            quicup: 'quic://dns.example'
            h3up: 'h3://dns.example/custom'
            http3up: 'http3://[2001:db8::1]/dns-query'
          }
          routing {
            request {
              fallback: h3up
            }
          }
        }
        "#;
        let config = parse_config(input);
        let geodata = test_geodata();
        let plan = build_resident_dns_plan(&config, &geodata).unwrap();
        assert_eq!(plan.request_actions.len(), 8);
        match plan.request_default_action {
            ResidentDnsRequestAction::Upstream(upstream) => {
                assert_eq!(upstream.tag, "h3up");
                assert_eq!(upstream.scheme, ResidentDnsUpstreamScheme::Http3);
                assert_eq!(upstream.target.authority, "dns.example:443");
                assert_eq!(upstream.path, "/custom");
            }
            other => panic!("expected h3 upstream fallback, got {other:?}"),
        }
    }

    #[test]
    fn resident_dns_upstream_parser_applies_default_ports_and_paths() {
        let cases = [
            (
                "udp",
                "udp://1.1.1.1",
                ResidentDnsUpstreamScheme::Udp,
                "1.1.1.1:53",
                "1.1.1.1",
                53,
                "",
            ),
            (
                "tcp",
                "tcp://dns.example",
                ResidentDnsUpstreamScheme::Tcp,
                "dns.example:53",
                "dns.example",
                53,
                "",
            ),
            (
                "tls",
                "tls://dns.example",
                ResidentDnsUpstreamScheme::Tls,
                "dns.example:853",
                "dns.example",
                853,
                "",
            ),
            (
                "https",
                "https://dns.example",
                ResidentDnsUpstreamScheme::Https,
                "dns.example:443",
                "dns.example",
                443,
                DNS_DEFAULT_DOH_PATH,
            ),
            (
                "quic",
                "quic://dns.example",
                ResidentDnsUpstreamScheme::Quic,
                "dns.example:853",
                "dns.example",
                853,
                "",
            ),
            (
                "h3",
                "h3://dns.example/custom",
                ResidentDnsUpstreamScheme::Http3,
                "dns.example:443",
                "dns.example",
                443,
                "/custom",
            ),
            (
                "http3",
                "http3://[2001:db8::1]",
                ResidentDnsUpstreamScheme::Http3,
                "[2001:db8::1]:443",
                "2001:db8::1",
                443,
                DNS_DEFAULT_DOH_PATH,
            ),
        ];
        for (tag, link, scheme, authority, host, port, path) in cases {
            let upstream = parse_dns_upstream(0, tag, link).unwrap();
            assert_eq!(upstream.scheme, scheme, "{tag}");
            assert_eq!(upstream.target.authority, authority, "{tag}");
            assert_eq!(upstream.target.host, host, "{tag}");
            assert_eq!(upstream.target.port, port, "{tag}");
            assert_eq!(upstream.path, path, "{tag}");
        }
    }

    #[test]
    fn resident_dns_doh_http_response_parser_restores_request_id() {
        let mut packed = a_response([203, 0, 113, 42]);
        packed[0] = 0;
        packed[1] = 0;
        let mut raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: "
                .to_vec();
        raw.extend_from_slice(packed.len().to_string().as_bytes());
        raw.extend_from_slice(b"\r\n\r\n");
        raw.extend_from_slice(&packed);

        let restored = parse_doh_http_response(QUERY, &raw).unwrap();
        assert_eq!(&restored[0..2], &[0x12, 0x34]);
        assert_eq!(&restored[2..], &packed[2..]);
    }

    #[test]
    fn resident_dns_doh_http_response_parser_decodes_chunked_body() {
        let mut packed = a_response([203, 0, 113, 42]);
        packed[0] = 0;
        packed[1] = 0;
        let split = 9;
        let mut raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_vec();
        raw.extend_from_slice(format!("{split:x}\r\n").as_bytes());
        raw.extend_from_slice(&packed[..split]);
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(format!("{:x}\r\n", packed.len() - split).as_bytes());
        raw.extend_from_slice(&packed[split..]);
        raw.extend_from_slice(b"\r\n0\r\n\r\n");

        let restored = parse_doh_http_response(QUERY, &raw).unwrap();
        assert_eq!(&restored[0..2], &[0x12, 0x34]);
        assert_eq!(&restored[2..], &packed[2..]);
    }

    #[test]
    fn resident_dns_qname_geosite_uses_shared_domain_store_for_any_code() {
        let root = test_asset_root("shared-geosite");
        write_asset(
            &root,
            "test-geosite.dat",
            geosite_list(&[geosite_entry("streaming", &[(2, "example.com", &[][..])])]),
        );
        let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
            secondary: 'udp://127.0.0.1:53'
          }
          routing {
            request {
              qname(ext:'test-geosite:streaming') -> primary
              fallback: secondary
            }
          }
        }
        "#
        .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
        let config = parse_config(&input);
        let geodata = ResidentGeodataStore::new([root]);

        let plan = build_resident_dns_plan(&config, &geodata).unwrap();
        assert_eq!(geodata.shared_domain_set_count(), 1);
        let view = DnsPacketView::parse(QUERY).unwrap();
        match select_request_action(&plan, &view).unwrap() {
            ResidentDnsRequestAction::Upstream(upstream) => assert_eq!(upstream.tag, "primary"),
            other => panic!("expected primary upstream action, got {other:?}"),
        }

        let _second = build_resident_dns_plan(&config, &geodata).unwrap();
        assert_eq!(geodata.shared_domain_set_count(), 1);
    }

    #[test]
    fn resident_dns_plan_rejects_unsupported_request_function() {
        let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
          }
          routing {
            request {
              ip(geoip:private) -> primary
              fallback: primary
            }
          }
        }
        "#
        .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
        let config = parse_config(&input);
        let geodata = test_geodata();
        let err = build_resident_dns_plan(&config, &geodata).unwrap_err();
        assert!(err.contains("unsupported dns.routing.request function: ip"));
    }

    #[test]
    fn resident_dns_plan_rejects_unknown_qtype_name() {
        let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
          }
          routing {
            request {
              qtype(not_a_type) -> primary
              fallback: primary
            }
          }
        }
        "#
        .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
        let config = parse_config(&input);
        let geodata = test_geodata();
        let err = build_resident_dns_plan(&config, &geodata).unwrap_err();
        assert!(err.contains("unknown DNS qtype: not_a_type"));
    }

    #[test]
    fn resident_dns_reject_response_preserves_question_and_request_id() {
        let view = DnsPacketView::parse(QUERY).unwrap();
        let response = build_reject_response(QUERY, &view).unwrap();
        assert_eq!(&response[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x000f, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(&response[12..], &QUERY[12..]);
    }

    #[test]
    fn resident_dns_response_validation_matches_id_and_question() {
        let request = DnsPacketView::parse(QUERY).unwrap();
        let response = a_response([203, 0, 113, 42]);
        validate_dns_response_for_request(&request, &response, true).unwrap();

        let mut id_mismatch = response.clone();
        id_mismatch[0] = 0xab;
        id_mismatch[1] = 0xcd;
        assert!(
            validate_dns_response_for_request(&request, &id_mismatch, true)
                .unwrap_err()
                .contains("IdMismatch")
        );
        validate_dns_response_for_request(&request, &id_mismatch, false).unwrap();

        let mut qname_mismatch = response;
        qname_mismatch[13] = b'x';
        assert!(
            validate_dns_response_for_request(&request, &qname_mismatch, false)
                .unwrap_err()
                .contains("QuestionMismatch")
        );
    }

    #[tokio::test]
    async fn resident_dns_local_listener_rejects_asis() {
        let plan = ResidentDnsPlan::asis(0);
        let err = handle_resident_dns_local_async(&plan, "127.0.0.1:8053".parse().unwrap(), QUERY)
            .await
            .unwrap_err();
        assert!(err.contains("cannot use \"asis\" for locally bound dns listener"));
    }

    fn geosite_list(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in entries {
            push_field_bytes(&mut out, 1, entry);
        }
        out
    }

    fn geosite_entry(code: &str, domains: &[(u64, &str, &[&str])]) -> Vec<u8> {
        let mut out = Vec::new();
        push_field_string(&mut out, 1, code);
        for (domain_type, value, attrs) in domains {
            push_field_bytes(&mut out, 2, &domain_entry(*domain_type, value, attrs));
        }
        out
    }

    fn domain_entry(domain_type: u64, value: &str, attrs: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        push_field_varint(&mut out, 1, domain_type);
        push_field_string(&mut out, 2, value);
        for attr in attrs {
            let mut attribute = Vec::new();
            push_field_string(&mut attribute, 1, attr);
            push_field_bytes(&mut out, 3, &attribute);
        }
        out
    }

    fn push_field_string(out: &mut Vec<u8>, field: u64, value: &str) {
        push_field_bytes(out, field, value.as_bytes());
    }

    fn push_field_bytes(out: &mut Vec<u8>, field: u64, value: &[u8]) {
        push_varint(out, (field << 3) | 2);
        push_varint(out, value.len() as u64);
        out.extend_from_slice(value);
    }

    fn push_field_varint(out: &mut Vec<u8>, field: u64, value: u64) {
        push_varint(out, field << 3);
        push_varint(out, value);
    }

    fn push_varint(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push((value as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }
}

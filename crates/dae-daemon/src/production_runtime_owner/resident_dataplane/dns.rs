use std::collections::BTreeMap;
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use dae_config::{Config, DynamicFunctionValue, Function, Param, RoutingRule};
use dae_dns::{
    DOH_MEDIA_TYPE, DnsDomainSet, DnsPacketView, DnsRequestMatchKind, DnsRequestMatchSpec,
    DnsRequestOutboundIndex, DnsResponseMatchKind, DnsResponseMatchSpec, DnsResponseOutboundIndex,
    RequestMatcher, ResponseMatcher, build_doh_request, dns_data_with_zero_id,
    restore_packed_response_request_id, validate_doh_response,
};
use dae_routing::IpPrefix;
use http::Request;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::OnceCell;
use tokio::time;

use super::super::resident_routing::{
    ResidentGeodataStore, expand_resident_dns_request_qname_rules_with_resolver,
    expand_resident_dns_response_ip_params_with_resolver,
    expand_resident_dns_response_qname_rules_with_resolver,
};
use super::RESIDENT_UDP_RESPONSE_TIMEOUT;
use super::direct::open_direct_tcp_connection_async;
use super::tcp::{open_marked_quic_endpoint, set_socket_mark};

const DNS_RCODE_REFUSED: u16 = 5;
const DNS_RESPONSE_FLAGS_REFUSED: u16 = 0x8180 | DNS_RCODE_REFUSED;
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

#[derive(Clone, Debug)]
pub(super) struct ResidentDnsPlan {
    request_matcher: Option<RequestMatcher>,
    request_actions: Vec<ResidentDnsRequestAction>,
    request_default_action: ResidentDnsRequestAction,
    response_matcher: Option<ResponseMatcher>,
    response_actions: Vec<ResidentDnsResponseAction>,
    response_default_action: ResidentDnsResponseAction,
    mark: u32,
}

impl ResidentDnsPlan {
    pub(super) const fn asis(mark: u32) -> Self {
        Self {
            request_matcher: None,
            request_actions: Vec::new(),
            request_default_action: ResidentDnsRequestAction::AsIs,
            response_matcher: None,
            response_actions: Vec::new(),
            response_default_action: ResidentDnsResponseAction::Accept,
            mark,
        }
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

pub(super) fn build_resident_dns_plan(
    config: &Config,
    geodata: &ResidentGeodataStore,
) -> Result<ResidentDnsPlan, String> {
    let upstreams = parse_dns_upstreams(config)?;
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
        mark: config.global.so_mark_from_dae,
    })
}

pub(super) async fn handle_resident_dns_udp_async(
    plan: &ResidentDnsPlan,
    original_dst: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let request =
        DnsPacketView::parse(payload).map_err(|err| format!("parse DNS request: {err}"))?;
    if request.response() {
        return Err("DNS request expected but DNS response received".to_owned());
    }
    if request.question_count() == 0 {
        return Err("DNS request has no question".to_owned());
    }
    let action = select_request_action(plan, &request)?;
    match action {
        ResidentDnsRequestAction::AsIs => {
            let response = forward_dns_udp_async(original_dst, payload, plan.mark)
                .await
                .map_err(|err| format!("forward DNS asis to {original_dst}: {err}"))?;
            let response_action = select_response_action_for_upstream(
                plan,
                &request,
                &response,
                DnsRequestOutboundIndex::ASIS,
            )?;
            match response_action {
                ResidentDnsResponseAction::Accept => Ok(response),
                ResidentDnsResponseAction::Reject => build_reject_response(payload, &request),
                ResidentDnsResponseAction::Upstream(upstream) => {
                    resolve_dns_response_routing(plan, payload, &request, upstream).await
                }
            }
        }
        ResidentDnsRequestAction::Reject => build_reject_response(payload, &request),
        ResidentDnsRequestAction::Upstream(ref upstream) => {
            resolve_dns_response_routing(plan, payload, &request, upstream.clone()).await
        }
    }
}

async fn resolve_dns_response_routing(
    plan: &ResidentDnsPlan,
    request_payload: &[u8],
    request: &DnsPacketView<'_>,
    mut upstream: ResidentDnsUpstream,
) -> Result<Vec<u8>, String> {
    for _ in 0..DNS_RESPONSE_REROUTE_LIMIT {
        let response = forward_dns_to_upstream_async(&upstream, request_payload, plan.mark).await?;
        let response_action = select_response_action(plan, request, &response, &upstream)?;
        match response_action {
            ResidentDnsResponseAction::Accept => return Ok(response),
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

async fn forward_dns_to_upstream_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    match upstream.scheme {
        ResidentDnsUpstreamScheme::Udp => {
            let target = upstream.target.resolve().await?;
            forward_dns_udp_async(target, payload, mark)
                .await
                .map_err(|err| {
                    format!(
                        "forward DNS to upstream {} {}: {err}",
                        upstream.tag, upstream.target.authority
                    )
                })
        }
        ResidentDnsUpstreamScheme::Tcp => forward_dns_tcp_async(upstream, payload, mark).await,
        ResidentDnsUpstreamScheme::TcpUdp => {
            let target = upstream.target.resolve().await?;
            let response = forward_dns_udp_async(target, payload, mark)
                .await
                .map_err(|err| {
                    format!(
                        "forward DNS to upstream {} {}: {err}",
                        upstream.tag, upstream.target.authority
                    )
                })?;
            if dns_response_truncated(&response) {
                forward_dns_tcp_async(upstream, payload, mark).await
            } else {
                Ok(response)
            }
        }
        ResidentDnsUpstreamScheme::Tls => forward_dns_tls_async(upstream, payload, mark).await,
        ResidentDnsUpstreamScheme::Https => forward_dns_https_async(upstream, payload, mark).await,
        ResidentDnsUpstreamScheme::Quic => forward_dns_quic_async(upstream, payload, mark).await,
        ResidentDnsUpstreamScheme::Http3 => forward_dns_h3_async(upstream, payload, mark).await,
    }
}

fn parse_dns_upstreams(config: &Config) -> Result<ResidentDnsUpstreams, String> {
    let mut by_tag = BTreeMap::new();
    let mut tag_to_index = BTreeMap::new();
    let mut request_actions = Vec::new();
    let mut response_actions = Vec::new();
    for (index, raw) in config.dns.upstream.iter().enumerate() {
        if index >= DnsRequestOutboundIndex::REJECT.value() as usize {
            return Err("too many DNS upstreams for resident request routing".to_owned());
        }
        let (tag, link) = split_keyable_link(raw);
        let Some(tag) = tag else {
            return Err(format!("bad DNS upstream format: {raw:?} has no tag"));
        };
        if by_tag.contains_key(&tag) {
            return Err(format!("duplicated DNS upstream tag {tag:?}"));
        }
        let upstream = parse_dns_upstream(index as u8, &tag, &link)?;
        tag_to_index.insert(tag.clone(), index as u8);
        request_actions.push(ResidentDnsRequestAction::Upstream(upstream.clone()));
        response_actions.push(ResidentDnsResponseAction::Upstream(upstream.clone()));
        by_tag.insert(tag, upstream);
    }
    Ok(ResidentDnsUpstreams {
        by_tag,
        tag_to_index,
        request_actions,
        response_actions,
    })
}

fn parse_request_default_action(
    default_action: &DynamicFunctionValue,
    upstreams: &BTreeMap<String, ResidentDnsUpstream>,
) -> Result<ResidentDnsRequestAction, String> {
    let Some(function) = dynamic_to_optional_single_function(default_action)? else {
        return Ok(ResidentDnsRequestAction::AsIs);
    };
    parse_request_action_function(&function, upstreams, "dns.routing.request default action")
}

fn build_request_matcher(
    config: &Config,
    upstreams: &ResidentDnsUpstreams,
    geodata: &ResidentGeodataStore,
) -> Result<Option<RequestMatcher>, String> {
    if config.dns.routing.request.rules.is_empty() {
        return Ok(None);
    }

    let rules = expand_resident_dns_request_qname_rules_with_resolver(
        &config.dns.routing.request.rules,
        geodata,
    )
    .map_err(|err| format!("expand dns.routing.request geodata: {err}"))?;
    let mut domain_sets = Vec::new();
    let mut matches = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        compile_request_rule(&mut domain_sets, &mut matches, rule, upstreams, geodata).map_err(
            |err| {
                format!(
                    "dns.routing.request rule {index} failed: {err}; rule={}",
                    rule.to_config_string(false, false, true)
                )
            },
        )?;
    }
    let fallback = request_index_for_dynamic(
        &config.dns.routing.request.fallback,
        upstreams,
        "dns.routing.request fallback",
    )?;
    matches.push(DnsRequestMatchSpec {
        kind: DnsRequestMatchKind::Fallback,
        value: 0,
        not: false,
        upstream: fallback,
    });
    let matcher = RequestMatcher::from_shared_typed_sets(domain_sets, matches)
        .map_err(|err| format!("build resident DNS request matcher: {err}"))?;
    Ok(Some(matcher))
}

fn parse_response_default_action(
    default_action: &DynamicFunctionValue,
    upstreams: &BTreeMap<String, ResidentDnsUpstream>,
) -> Result<ResidentDnsResponseAction, String> {
    let Some(function) = dynamic_to_optional_single_function(default_action)? else {
        return Ok(ResidentDnsResponseAction::Accept);
    };
    parse_response_action_function(&function, upstreams, "dns.routing.response default action")
}

fn build_response_matcher(
    config: &Config,
    upstreams: &ResidentDnsUpstreams,
    geodata: &ResidentGeodataStore,
) -> Result<Option<ResponseMatcher>, String> {
    if config.dns.routing.response.rules.is_empty() {
        return Ok(None);
    }

    let rules = expand_resident_dns_response_qname_rules_with_resolver(
        &config.dns.routing.response.rules,
        geodata,
    )
    .map_err(|err| format!("expand dns.routing.response geodata: {err}"))?;
    let mut domain_sets = Vec::new();
    let mut lpm_sets = Vec::new();
    let mut matches = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        compile_response_rule(
            &mut domain_sets,
            &mut lpm_sets,
            &mut matches,
            rule,
            upstreams,
            geodata,
        )
        .map_err(|err| {
            format!(
                "dns.routing.response rule {index} failed: {err}; rule={}",
                rule.to_config_string(false, false, true)
            )
        })?;
    }
    let fallback = response_index_for_dynamic(
        &config.dns.routing.response.fallback,
        upstreams,
        "dns.routing.response fallback",
    )?;
    matches.push(DnsResponseMatchSpec {
        kind: DnsResponseMatchKind::Fallback,
        value: 0,
        not: false,
        upstream: fallback,
    });
    let matcher = ResponseMatcher::from_shared_typed_sets(domain_sets, lpm_sets, matches)
        .map_err(|err| format!("build resident DNS response matcher: {err}"))?;
    Ok(Some(matcher))
}

fn compile_request_rule(
    domain_sets: &mut Vec<DnsDomainSet>,
    matches: &mut Vec<DnsRequestMatchSpec>,
    rule: &RoutingRule,
    upstreams: &ResidentDnsUpstreams,
    geodata: &ResidentGeodataStore,
) -> Result<(), String> {
    if rule.and_functions.is_empty() {
        return Err("request rule has no functions".to_owned());
    }
    let rule_upstream =
        request_index_for_function(&rule.outbound, upstreams, "dns.routing.request rule action")?;
    for (function_index, function) in rule.and_functions.iter().enumerate() {
        let grouped = grouped_params(&function.params);
        if grouped.is_empty() {
            return Err(format!("function {} has no params", function.name));
        }
        let group_count = grouped.len();
        for (group_index, (key, values)) in grouped.into_iter().enumerate() {
            if values.is_empty() {
                return Err(format!("function {} has empty param group", function.name));
            }
            let upstream = if group_index == group_count - 1 {
                if function_index == rule.and_functions.len() - 1 {
                    rule_upstream
                } else {
                    DnsRequestOutboundIndex::LOGICAL_AND
                }
            } else {
                DnsRequestOutboundIndex::LOGICAL_OR
            };
            match function.name.as_str() {
                "qname" => add_request_qname_match(
                    domain_sets,
                    matches,
                    geodata,
                    function,
                    &key,
                    values,
                    upstream,
                )?,
                "qtype" => add_request_qtype_matches(matches, function, &values, upstream)?,
                other => {
                    return Err(format!(
                        "unsupported dns.routing.request function: {other}; resident DNS request routing admits qname and qtype only"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn compile_response_rule(
    domain_sets: &mut Vec<DnsDomainSet>,
    lpm_sets: &mut Vec<Vec<IpPrefix>>,
    matches: &mut Vec<DnsResponseMatchSpec>,
    rule: &RoutingRule,
    upstreams: &ResidentDnsUpstreams,
    geodata: &ResidentGeodataStore,
) -> Result<(), String> {
    if rule.and_functions.is_empty() {
        return Err("response rule has no functions".to_owned());
    }
    let rule_upstream = response_index_for_function(
        &rule.outbound,
        upstreams,
        "dns.routing.response rule action",
    )?;
    for (function_index, function) in rule.and_functions.iter().enumerate() {
        let grouped = grouped_params(&function.params);
        if grouped.is_empty() {
            return Err(format!("function {} has no params", function.name));
        }
        let group_count = grouped.len();
        for (group_index, (key, values)) in grouped.into_iter().enumerate() {
            if values.is_empty() {
                return Err(format!("function {} has empty param group", function.name));
            }
            let upstream = if group_index == group_count - 1 {
                if function_index == rule.and_functions.len() - 1 {
                    rule_upstream
                } else {
                    DnsResponseOutboundIndex::LOGICAL_AND
                }
            } else {
                DnsResponseOutboundIndex::LOGICAL_OR
            };
            match function.name.as_str() {
                "qname" => add_response_qname_match(
                    domain_sets,
                    matches,
                    geodata,
                    function,
                    &key,
                    values,
                    upstream,
                )?,
                "qtype" => add_response_qtype_matches(matches, function, &values, upstream)?,
                "upstream" => {
                    add_response_upstream_matches(matches, upstreams, function, &values, upstream)?
                }
                "ip" => add_response_ip_match(
                    lpm_sets, matches, geodata, function, &key, values, upstream,
                )?,
                other => {
                    return Err(format!(
                        "unsupported dns.routing.response function: {other}; resident DNS response routing admits qname, qtype, upstream, and ip"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn add_request_qname_match(
    domain_sets: &mut Vec<DnsDomainSet>,
    matches: &mut Vec<DnsRequestMatchSpec>,
    geodata: &ResidentGeodataStore,
    function: &Function,
    key: &str,
    mut values: Vec<String>,
    upstream: DnsRequestOutboundIndex,
) -> Result<(), String> {
    if !matches!(key, "full" | "keyword" | "suffix" | "regex") {
        return Err(format!("qname has unsupported domain key: {key}"));
    }
    let bit = matches.len();
    values.sort();
    values.dedup();
    let patterns = geodata.shared_domain_set(key, values)?;
    domain_sets.push(DnsDomainSet { bit, patterns });
    matches.push(DnsRequestMatchSpec {
        kind: DnsRequestMatchKind::DomainSet,
        value: 0,
        not: function.not,
        upstream,
    });
    Ok(())
}

fn add_request_qtype_matches(
    matches: &mut Vec<DnsRequestMatchSpec>,
    function: &Function,
    values: &[String],
    upstream: DnsRequestOutboundIndex,
) -> Result<(), String> {
    for (index, value) in values.iter().enumerate() {
        let item_upstream = if index == values.len() - 1 {
            upstream
        } else {
            DnsRequestOutboundIndex::LOGICAL_OR
        };
        matches.push(DnsRequestMatchSpec {
            kind: DnsRequestMatchKind::QType,
            value: parse_dns_qtype(value)?,
            not: function.not,
            upstream: item_upstream,
        });
    }
    Ok(())
}

fn add_response_qname_match(
    domain_sets: &mut Vec<DnsDomainSet>,
    matches: &mut Vec<DnsResponseMatchSpec>,
    geodata: &ResidentGeodataStore,
    function: &Function,
    key: &str,
    mut values: Vec<String>,
    upstream: DnsResponseOutboundIndex,
) -> Result<(), String> {
    if !matches!(key, "full" | "keyword" | "suffix" | "regex") {
        return Err(format!("qname has unsupported domain key: {key}"));
    }
    let bit = matches.len();
    values.sort();
    values.dedup();
    let patterns = geodata.shared_domain_set(key, values)?;
    domain_sets.push(DnsDomainSet { bit, patterns });
    matches.push(DnsResponseMatchSpec {
        kind: DnsResponseMatchKind::DomainSet,
        value: 0,
        not: function.not,
        upstream,
    });
    Ok(())
}

fn add_response_qtype_matches(
    matches: &mut Vec<DnsResponseMatchSpec>,
    function: &Function,
    values: &[String],
    upstream: DnsResponseOutboundIndex,
) -> Result<(), String> {
    for (index, value) in values.iter().enumerate() {
        let item_upstream = if index == values.len() - 1 {
            upstream
        } else {
            DnsResponseOutboundIndex::LOGICAL_OR
        };
        matches.push(DnsResponseMatchSpec {
            kind: DnsResponseMatchKind::QType,
            value: parse_dns_qtype(value)?,
            not: function.not,
            upstream: item_upstream,
        });
    }
    Ok(())
}

fn add_response_upstream_matches(
    matches: &mut Vec<DnsResponseMatchSpec>,
    upstreams: &ResidentDnsUpstreams,
    function: &Function,
    values: &[String],
    upstream: DnsResponseOutboundIndex,
) -> Result<(), String> {
    for (index, value) in values.iter().enumerate() {
        let item_upstream = if index == values.len() - 1 {
            upstream
        } else {
            DnsResponseOutboundIndex::LOGICAL_OR
        };
        let value = match value.as_str() {
            "asis" => DnsRequestOutboundIndex::ASIS.value() as u16,
            tag => upstreams
                .tag_to_index
                .get(tag)
                .copied()
                .map(u16::from)
                .ok_or_else(|| {
                    format!("dns.routing.response upstream references unknown upstream {tag:?}")
                })?,
        };
        matches.push(DnsResponseMatchSpec {
            kind: DnsResponseMatchKind::Upstream,
            value,
            not: function.not,
            upstream: item_upstream,
        });
    }
    Ok(())
}

fn add_response_ip_match(
    lpm_sets: &mut Vec<Vec<IpPrefix>>,
    matches: &mut Vec<DnsResponseMatchSpec>,
    geodata: &ResidentGeodataStore,
    function: &Function,
    key: &str,
    values: Vec<String>,
    upstream: DnsResponseOutboundIndex,
) -> Result<(), String> {
    if !matches!(key, "" | "geoip" | "ext") {
        return Err(format!("ip has unsupported key: {key}"));
    }
    let params = values
        .into_iter()
        .map(|val| Param {
            key: key.to_owned(),
            val,
            ..Param::default()
        })
        .collect::<Vec<_>>();
    let expanded = expand_resident_dns_response_ip_params_with_resolver(&params, geodata)?;
    let mut prefixes = Vec::with_capacity(expanded.len());
    for param in expanded {
        prefixes.push(parse_response_ip_prefix(&param.val)?);
    }
    let index = lpm_sets.len();
    lpm_sets.push(prefixes);
    matches.push(DnsResponseMatchSpec {
        kind: DnsResponseMatchKind::IpSet,
        value: index as u16,
        not: function.not,
        upstream,
    });
    Ok(())
}

fn parse_response_ip_prefix(value: &str) -> Result<IpPrefix, String> {
    if value.contains('/') {
        return IpPrefix::parse(value).map_err(|err| err.to_string());
    }
    let ip = value
        .parse::<IpAddr>()
        .map_err(|err| format!("parse DNS response ip matcher {value:?}: {err}"))?;
    let bits = if ip.is_ipv4() { 32 } else { 128 };
    IpPrefix::new(ip, bits).map_err(|err| err.to_string())
}

fn select_request_action(
    plan: &ResidentDnsPlan,
    request: &DnsPacketView<'_>,
) -> Result<ResidentDnsRequestAction, String> {
    let Some(matcher) = &plan.request_matcher else {
        return Ok(plan.request_default_action.clone());
    };
    let question = request
        .questions()
        .next()
        .ok_or_else(|| "DNS request has no question".to_owned())?;
    let qname = question
        .qname_to_canonical_string()
        .map_err(|err| format!("read DNS request qname: {err}"))?;
    let outbound = matcher
        .match_request(&qname, question.qtype())
        .map_err(|err| format!("match dns.routing.request: {err}"))?;
    request_action_from_index(plan, outbound)
}

fn select_response_action(
    plan: &ResidentDnsPlan,
    request: &DnsPacketView<'_>,
    response_payload: &[u8],
    upstream: &ResidentDnsUpstream,
) -> Result<ResidentDnsResponseAction, String> {
    select_response_action_for_upstream(
        plan,
        request,
        response_payload,
        DnsRequestOutboundIndex(upstream.index),
    )
}

fn select_response_action_for_upstream(
    plan: &ResidentDnsPlan,
    request: &DnsPacketView<'_>,
    response_payload: &[u8],
    upstream: DnsRequestOutboundIndex,
) -> Result<ResidentDnsResponseAction, String> {
    let Some(matcher) = &plan.response_matcher else {
        return Ok(plan.response_default_action.clone());
    };
    let response = DnsPacketView::parse(response_payload)
        .map_err(|err| format!("parse DNS response: {err}"))?;
    if !response.response() {
        return Err("DNS response expected but DNS request received".to_owned());
    }
    let question = request
        .questions()
        .next()
        .ok_or_else(|| "DNS request has no question".to_owned())?;
    let qname = question
        .qname_to_canonical_string()
        .map_err(|err| format!("read DNS response routing qname: {err}"))?;
    let mut ips = Vec::new();
    for answer in response.answers() {
        let answer = answer.map_err(|err| format!("read DNS response answer: {err}"))?;
        if let Some(ip) = answer.ip() {
            ips.push(ip);
        }
    }
    let outbound = matcher
        .match_response(&qname, question.qtype(), &ips, upstream)
        .map_err(|err| format!("match dns.routing.response: {err}"))?;
    response_action_from_index(plan, outbound)
}

fn request_action_from_index(
    plan: &ResidentDnsPlan,
    outbound: DnsRequestOutboundIndex,
) -> Result<ResidentDnsRequestAction, String> {
    if outbound == DnsRequestOutboundIndex::ASIS {
        return Ok(ResidentDnsRequestAction::AsIs);
    }
    if outbound == DnsRequestOutboundIndex::REJECT {
        return Ok(ResidentDnsRequestAction::Reject);
    }
    if outbound == DnsRequestOutboundIndex::LOGICAL_OR
        || outbound == DnsRequestOutboundIndex::LOGICAL_AND
    {
        return Err(format!(
            "dns.routing.request returned internal logical outbound {outbound}"
        ));
    }
    plan.request_actions
        .get(outbound.value() as usize)
        .cloned()
        .ok_or_else(|| {
            format!(
                "dns.routing.request selected unknown upstream index {}",
                outbound.value()
            )
        })
}

fn request_index_for_dynamic(
    value: &DynamicFunctionValue,
    upstreams: &ResidentDnsUpstreams,
    context: &str,
) -> Result<DnsRequestOutboundIndex, String> {
    let Some(function) = dynamic_to_optional_single_function(value)? else {
        return Ok(DnsRequestOutboundIndex::ASIS);
    };
    request_index_for_function(&function, upstreams, context)
}

fn request_index_for_function(
    function: &Function,
    upstreams: &ResidentDnsUpstreams,
    context: &str,
) -> Result<DnsRequestOutboundIndex, String> {
    if !function.params.is_empty() {
        return Err(format!("{context} does not admit action parameters"));
    }
    match function.name.as_str() {
        "asis" => Ok(DnsRequestOutboundIndex::ASIS),
        "reject" => Ok(DnsRequestOutboundIndex::REJECT),
        tag => upstreams
            .tag_to_index
            .get(tag)
            .copied()
            .map(DnsRequestOutboundIndex)
            .ok_or_else(|| format!("{context} references unknown upstream {tag:?}")),
    }
}

fn response_index_for_dynamic(
    value: &DynamicFunctionValue,
    upstreams: &ResidentDnsUpstreams,
    context: &str,
) -> Result<DnsResponseOutboundIndex, String> {
    let Some(function) = dynamic_to_optional_single_function(value)? else {
        return Ok(DnsResponseOutboundIndex::ACCEPT);
    };
    response_index_for_function(&function, upstreams, context)
}

fn response_index_for_function(
    function: &Function,
    upstreams: &ResidentDnsUpstreams,
    context: &str,
) -> Result<DnsResponseOutboundIndex, String> {
    if !function.params.is_empty() {
        return Err(format!("{context} does not admit action parameters"));
    }
    match function.name.as_str() {
        "accept" => Ok(DnsResponseOutboundIndex::ACCEPT),
        "reject" => Ok(DnsResponseOutboundIndex::REJECT),
        tag => upstreams
            .tag_to_index
            .get(tag)
            .copied()
            .map(DnsResponseOutboundIndex)
            .ok_or_else(|| format!("{context} references unknown upstream {tag:?}")),
    }
}

fn parse_request_action_function(
    function: &Function,
    upstreams: &BTreeMap<String, ResidentDnsUpstream>,
    context: &str,
) -> Result<ResidentDnsRequestAction, String> {
    if !function.params.is_empty() {
        return Err(format!("{context} does not admit action parameters"));
    }
    match function.name.as_str() {
        "asis" => Ok(ResidentDnsRequestAction::AsIs),
        "reject" => Ok(ResidentDnsRequestAction::Reject),
        tag => upstreams
            .get(tag)
            .cloned()
            .map(ResidentDnsRequestAction::Upstream)
            .ok_or_else(|| format!("{context} references unknown upstream {tag:?}")),
    }
}

fn parse_response_action_function(
    function: &Function,
    upstreams: &BTreeMap<String, ResidentDnsUpstream>,
    context: &str,
) -> Result<ResidentDnsResponseAction, String> {
    if !function.params.is_empty() {
        return Err(format!("{context} does not admit action parameters"));
    }
    match function.name.as_str() {
        "accept" => Ok(ResidentDnsResponseAction::Accept),
        "reject" => Ok(ResidentDnsResponseAction::Reject),
        tag => upstreams
            .get(tag)
            .cloned()
            .map(ResidentDnsResponseAction::Upstream)
            .ok_or_else(|| format!("{context} references unknown upstream {tag:?}")),
    }
}

fn response_action_from_index(
    plan: &ResidentDnsPlan,
    outbound: DnsResponseOutboundIndex,
) -> Result<ResidentDnsResponseAction, String> {
    if outbound == DnsResponseOutboundIndex::ACCEPT {
        return Ok(ResidentDnsResponseAction::Accept);
    }
    if outbound == DnsResponseOutboundIndex::REJECT {
        return Ok(ResidentDnsResponseAction::Reject);
    }
    if outbound == DnsResponseOutboundIndex::LOGICAL_OR
        || outbound == DnsResponseOutboundIndex::LOGICAL_AND
    {
        return Err(format!(
            "dns.routing.response returned internal logical outbound {outbound}"
        ));
    }
    plan.response_actions
        .get(outbound.value() as usize)
        .cloned()
        .ok_or_else(|| {
            format!(
                "dns.routing.response selected unknown upstream index {}",
                outbound.value()
            )
        })
}

fn dynamic_to_optional_single_function(
    value: &DynamicFunctionValue,
) -> Result<Option<Function>, String> {
    match value {
        DynamicFunctionValue::Nil => Ok(None),
        DynamicFunctionValue::String(name) => Ok(Some(Function {
            name: name.clone(),
            not: false,
            params: Vec::new(),
        })),
        DynamicFunctionValue::Function(function) => Ok(Some(function.clone())),
        DynamicFunctionValue::FunctionList(functions) if functions.len() == 1 => {
            Ok(Some(functions[0].clone()))
        }
        DynamicFunctionValue::FunctionList(_) => {
            Err("default action function list is not admitted".to_owned())
        }
    }
}

fn grouped_params(params: &[Param]) -> Vec<(String, Vec<String>)> {
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut order = Vec::new();
    for param in params {
        if !groups.contains_key(&param.key) {
            order.push(param.key.clone());
        }
        groups
            .entry(param.key.clone())
            .or_default()
            .push(param.val.clone());
    }
    order
        .into_iter()
        .map(|key| {
            let values = groups.remove(&key).unwrap_or_default();
            (key, values)
        })
        .collect()
}

fn parse_dns_qtype(value: &str) -> Result<u16, String> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return u16::from_str_radix(hex, 16)
            .map_err(|err| format!("invalid DNS qtype {value}: {err}"));
    }
    if let Ok(parsed) = value.parse::<u16>() {
        return Ok(parsed);
    }
    dns_qtype_name(value).ok_or_else(|| format!("unknown DNS qtype: {value}"))
}

fn dns_qtype_name(value: &str) -> Option<u16> {
    Some(match value.to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "MD" => 3,
        "MF" => 4,
        "CNAME" => 5,
        "SOA" => 6,
        "MB" => 7,
        "MG" => 8,
        "MR" => 9,
        "NULL" => 10,
        "WKS" => 11,
        "PTR" => 12,
        "HINFO" => 13,
        "MINFO" => 14,
        "MX" => 15,
        "TXT" => 16,
        "RP" => 17,
        "AFSDB" => 18,
        "X25" => 19,
        "ISDN" => 20,
        "RT" => 21,
        "NSAP" => 22,
        "NSAPPTR" | "NSAP-PTR" => 23,
        "SIG" => 24,
        "KEY" => 25,
        "PX" => 26,
        "GPOS" => 27,
        "AAAA" => 28,
        "LOC" => 29,
        "NXT" => 30,
        "EID" => 31,
        "NIMLOC" => 32,
        "SRV" => 33,
        "ATMA" => 34,
        "NAPTR" => 35,
        "KX" => 36,
        "CERT" => 37,
        "DNAME" => 39,
        "OPT" => 41,
        "APL" => 42,
        "DS" => 43,
        "SSHFP" => 44,
        "IPSECKEY" => 45,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "DHCID" => 49,
        "NSEC3" => 50,
        "NSEC3PARAM" => 51,
        "TLSA" => 52,
        "SMIMEA" => 53,
        "HIP" => 55,
        "NINFO" => 56,
        "RKEY" => 57,
        "TALINK" => 58,
        "CDS" => 59,
        "CDNSKEY" => 60,
        "OPENPGPKEY" => 61,
        "CSYNC" => 62,
        "ZONEMD" => 63,
        "SVCB" => 64,
        "HTTPS" => 65,
        "SPF" => 99,
        "UINFO" => 100,
        "UID" => 101,
        "GID" => 102,
        "UNSPEC" => 103,
        "NID" => 104,
        "L32" => 105,
        "L64" => 106,
        "LP" => 107,
        "EUI48" => 108,
        "EUI64" => 109,
        "TKEY" => 249,
        "TSIG" => 250,
        "IXFR" => 251,
        "AXFR" => 252,
        "MAILB" => 253,
        "MAILA" => 254,
        "ANY" => 255,
        "URI" => 256,
        "CAA" => 257,
        "AVC" => 258,
        "DOA" => 259,
        "AMTRELAY" => 260,
        "TA" => 32768,
        "DLV" => 32769,
        _ => return None,
    })
}

fn parse_dns_upstream(index: u8, tag: &str, link: &str) -> Result<ResidentDnsUpstream, String> {
    let (scheme, rest) = link
        .split_once("://")
        .ok_or_else(|| format!("DNS upstream {tag} has no scheme: {link}"))?;
    let scheme = match scheme {
        "udp" => ResidentDnsUpstreamScheme::Udp,
        "tcp" => ResidentDnsUpstreamScheme::Tcp,
        "tcp+udp" | "udp+tcp" => ResidentDnsUpstreamScheme::TcpUdp,
        "tls" => ResidentDnsUpstreamScheme::Tls,
        "https" => ResidentDnsUpstreamScheme::Https,
        "quic" => ResidentDnsUpstreamScheme::Quic,
        "h3" | "http3" => ResidentDnsUpstreamScheme::Http3,
        other => {
            return Err(format!(
                "resident DNS upstream {tag} uses unsupported scheme {other}; resident DNS upstream shape remains fail-closed until this scheme is admitted"
            ));
        }
    };
    let (authority, path) = split_dns_upstream_authority_and_path(rest, scheme);
    let target = parse_dns_upstream_authority(authority, scheme.default_port())?;
    Ok(ResidentDnsUpstream {
        index,
        tag: tag.to_owned(),
        target,
        scheme,
        path,
    })
}

impl ResidentDnsUpstreamScheme {
    const fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp | Self::TcpUdp => DNS_DEFAULT_PORT,
            Self::Tls | Self::Quic => DNS_TLS_DEFAULT_PORT,
            Self::Https | Self::Http3 => DNS_HTTPS_DEFAULT_PORT,
        }
    }

    const fn default_path(self) -> &'static str {
        match self {
            Self::Https | Self::Http3 => DNS_DEFAULT_DOH_PATH,
            Self::Udp | Self::Tcp | Self::TcpUdp | Self::Tls | Self::Quic => "",
        }
    }
}

fn split_dns_upstream_authority_and_path(
    rest: &str,
    scheme: ResidentDnsUpstreamScheme,
) -> (&str, String) {
    match rest.find('/') {
        Some(index) => (&rest[..index], rest[index..].to_owned()),
        None => (rest, scheme.default_path().to_owned()),
    }
}

fn parse_dns_upstream_authority(
    authority: &str,
    default_port: u16,
) -> Result<ResidentDnsUpstreamTarget, String> {
    let authority = authority.trim();
    if authority.is_empty() {
        return Err("DNS upstream authority is empty".to_owned());
    }
    let (authority, host, port, literal_addr) =
        dns_upstream_authority_with_default_port(authority, default_port)?;
    Ok(ResidentDnsUpstreamTarget {
        authority,
        host,
        port,
        literal_addr,
        resolved_addr: Arc::new(OnceCell::new()),
    })
}

fn dns_upstream_authority_with_default_port(
    authority: &str,
    default_port: u16,
) -> Result<(String, String, u16, Option<SocketAddr>), String> {
    if let Ok(addr) = authority.parse::<SocketAddr>() {
        return Ok((
            addr.to_string(),
            addr.ip().to_string(),
            addr.port(),
            Some(addr),
        ));
    }
    if let Ok(ip) = authority.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, default_port);
        return Ok((addr.to_string(), ip.to_string(), default_port, Some(addr)));
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return Err(format!(
                "DNS upstream {authority} has malformed IPv6 authority"
            ));
        };
        let port = match tail.strip_prefix(':') {
            Some(port) => port
                .parse::<u16>()
                .map_err(|err| format!("DNS upstream {authority} has invalid port: {err}"))?,
            None if tail.is_empty() => default_port,
            None => {
                return Err(format!(
                    "DNS upstream {authority} has unexpected text after bracketed host"
                ));
            }
        };
        if let Ok(ip) = host.parse::<IpAddr>() {
            let addr = SocketAddr::new(ip, port);
            return Ok((addr.to_string(), ip.to_string(), port, Some(addr)));
        }
        return Ok((format!("[{host}]:{port}"), host.to_owned(), port, None));
    }
    if authority.matches(':').count() > 1 {
        return Err(format!(
            "DNS upstream {authority} is an IPv6 literal and must be bracketed when a port is supplied"
        ));
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        let port = port
            .parse::<u16>()
            .map_err(|err| format!("DNS upstream {authority} has invalid port: {err}"))?;
        return Ok((authority.to_owned(), host.to_owned(), port, None));
    }
    Ok((
        format!("{authority}:{default_port}"),
        authority.to_owned(),
        default_port,
        None,
    ))
}

async fn forward_dns_udp_async(
    target: SocketAddr,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let bind = match target {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket =
        std::net::UdpSocket::bind(bind).map_err(|err| format!("bind DNS UDP socket: {err}"))?;
    if mark != 0 {
        set_socket_mark(socket.as_raw_fd(), mark)
            .map_err(|err| format!("set DNS UDP SO_MARK {mark}: {err}"))?;
    }
    socket
        .set_nonblocking(true)
        .map_err(|err| format!("set DNS UDP nonblocking: {err}"))?;
    let socket = tokio::net::UdpSocket::from_std(socket)
        .map_err(|err| format!("adopt async DNS UDP socket: {err}"))?;
    socket
        .send_to(payload, target)
        .await
        .map_err(|err| format!("send DNS UDP packet: {err}"))?;
    let mut response = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
    let (read, _) = time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        socket.recv_from(&mut response),
    )
    .await
    .map_err(|_| "receive DNS UDP response timeout".to_owned())?
    .map_err(|err| format!("receive DNS UDP response: {err}"))?;
    response.truncate(read);
    Ok(response)
}

async fn forward_dns_tcp_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let mut stream = open_dns_tcp_stream_async(upstream, mark).await?;
    time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        forward_dns_framed_stream_async(&mut stream, payload),
    )
    .await
    .map_err(|_| "DNS TCP exchange timeout".to_owned())?
    .map_err(|err| {
        format!(
            "forward DNS over TCP to upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })
}

async fn forward_dns_tls_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let stream = open_dns_tcp_stream_async(upstream, mark).await?;
    let config = resident_dns_tls_client_config(&[])?;
    let server_name = ServerName::try_from(upstream.target.host.clone()).map_err(|err| {
        format!(
            "invalid DNS TLS server name {}: {err}",
            upstream.target.host
        )
    })?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let mut tls = time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| "DNS TLS handshake timeout".to_owned())?
    .map_err(|err| {
        format!(
            "connect DNS TLS upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })?;
    time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        forward_dns_framed_stream_async(&mut tls, payload),
    )
    .await
    .map_err(|_| "DNS TLS exchange timeout".to_owned())?
    .map_err(|err| {
        format!(
            "forward DNS over TLS to upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })
}

async fn forward_dns_https_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let stream = open_dns_tcp_stream_async(upstream, mark).await?;
    let config = resident_dns_tls_client_config(&["http/1.1"])?;
    let server_name = ServerName::try_from(upstream.target.host.clone()).map_err(|err| {
        format!(
            "invalid DNS HTTPS server name {}: {err}",
            upstream.target.host
        )
    })?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let mut tls = time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| "DNS HTTPS TLS handshake timeout".to_owned())?
    .map_err(|err| {
        format!(
            "connect DNS HTTPS upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })?;
    let doh = build_doh_request(
        &upstream.target.authority,
        &upstream.target.authority,
        &upstream.path,
        payload,
    )
    .map_err(|err| format!("build DoH request: {err}"))?;
    let request_target = doh_request_target(&upstream.path, doh.dns_query.as_deref());
    let request = http1_doh_request_bytes(&doh, &request_target);
    time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        tls.write_all(&request)
            .await
            .map_err(|err| format!("write DoH request: {err}"))?;
        tls.flush()
            .await
            .map_err(|err| format!("flush DoH request: {err}"))?;
        let raw = read_to_end_capped_async(&mut tls, DNS_DOH_RESPONSE_READ_LIMIT).await?;
        parse_doh_http_response(payload, &raw)
    })
    .await
    .map_err(|_| "DNS HTTPS exchange timeout".to_owned())?
    .map_err(|err| {
        format!(
            "forward DNS over HTTPS to upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })
}

async fn forward_dns_quic_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let mut endpoint = open_marked_quic_endpoint(mark)?;
    endpoint.set_default_client_config(resident_dns_quic_client_config(DNS_DOQ_ALPN)?);
    let remote = upstream.target.resolve().await?;
    let connection = time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        endpoint
            .connect(remote, &upstream.target.host)
            .map_err(|err| format!("connect DoQ endpoint: {err}"))?,
    )
    .await
    .map_err(|_| "DNS QUIC handshake timeout".to_owned())?
    .map_err(|err| {
        format!(
            "connect DNS QUIC upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })?;
    let (mut send, mut recv) = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, connection.open_bi())
        .await
        .map_err(|_| "DNS QUIC stream open timeout".to_owned())?
        .map_err(|err| format!("open DNS QUIC stream: {err}"))?;
    let query = dns_data_with_zero_id(payload);
    let response = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        write_dns_tcp_message_async(&mut send, &query).await?;
        send.finish()
            .map_err(|err| format!("finish DNS QUIC request stream: {err}"))?;
        let response = read_dns_tcp_message_async(&mut recv).await?;
        restore_dns_response_id(payload, &response)
    })
    .await
    .map_err(|_| "DNS QUIC exchange timeout".to_owned())?
    .map_err(|err| {
        format!(
            "forward DNS over QUIC to upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })?;
    connection.close(0_u32.into(), b"dns-query done");
    endpoint.wait_idle().await;
    Ok(response)
}

async fn forward_dns_h3_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let mut endpoint = open_marked_quic_endpoint(mark)?;
    endpoint.set_default_client_config(resident_dns_quic_client_config(DNS_DOH3_ALPN)?);
    let remote = upstream.target.resolve().await?;
    let connection = time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        endpoint
            .connect(remote, &upstream.target.host)
            .map_err(|err| format!("connect DoH3 endpoint: {err}"))?,
    )
    .await
    .map_err(|_| "DNS H3 handshake timeout".to_owned())?
    .map_err(|err| {
        format!(
            "connect DNS H3 upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })?;
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, mut client) = h3::client::new(h3_connection)
        .await
        .map_err(|err| format!("create DNS H3 client: {err:?}"))?;
    let driver_task = tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });

    let response = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        let doh = build_doh_request(
            &upstream.target.authority,
            &upstream.target.authority,
            &upstream.path,
            payload,
        )
        .map_err(|err| format!("build DoH3 request: {err}"))?;
        let uri = if let Some(query) = doh.dns_query.as_deref() {
            format!(
                "https://{}{}",
                upstream.target.authority,
                doh_request_target(&upstream.path, Some(query))
            )
        } else {
            format!("https://{}{}", upstream.target.authority, upstream.path)
        };
        let mut builder = Request::builder()
            .method(doh.method.as_str())
            .uri(uri)
            .header(http::header::ACCEPT, DOH_MEDIA_TYPE);
        if !doh.content_type.is_empty() {
            builder = builder.header(http::header::CONTENT_TYPE, doh.content_type.as_str());
        }
        let request = builder
            .body(())
            .map_err(|err| format!("build DoH3 HTTP request: {err}"))?;
        let mut stream = client
            .send_request(request)
            .await
            .map_err(|err| format!("send DoH3 request: {err:?}"))?;
        if !doh.body.is_empty() {
            stream
                .send_data(Bytes::copy_from_slice(&doh.body))
                .await
                .map_err(|err| format!("send DoH3 body: {err:?}"))?;
        }
        stream
            .finish()
            .await
            .map_err(|err| format!("finish DoH3 request: {err:?}"))?;
        let response = stream
            .recv_response()
            .await
            .map_err(|err| format!("recv DoH3 response: {err:?}"))?;
        let content_type = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .map(|value| value.as_bytes().to_vec())
            .unwrap_or_default();
        let status = response.status();
        let mut body = Vec::new();
        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|err| format!("recv DoH3 response body: {err:?}"))?
        {
            let remaining = chunk.remaining();
            if body.len().saturating_add(remaining) > DNS_DOH_RESPONSE_READ_LIMIT {
                return Err(format!(
                    "DoH3 response exceeds read limit {DNS_DOH_RESPONSE_READ_LIMIT}"
                ));
            }
            body.extend_from_slice(&chunk.copy_to_bytes(remaining));
        }
        validate_doh_response(status.as_u16(), status.as_str(), &content_type)
            .map_err(|err| err.to_string())?;
        restore_dns_response_id(payload, &body)
    })
    .await
    .map_err(|_| "DNS H3 exchange timeout".to_owned())?
    .map_err(|err| {
        format!(
            "forward DNS over HTTP/3 to upstream {} {}: {err}",
            upstream.tag, upstream.target.authority
        )
    })?;
    drop(client);
    connection.close(0_u32.into(), b"dns-query done");
    endpoint.wait_idle().await;
    let _ = driver_task.await;
    Ok(response)
}

async fn open_dns_tcp_stream_async(
    upstream: &ResidentDnsUpstream,
    mark: u32,
) -> Result<TokioTcpStream, String> {
    let connected =
        open_direct_tcp_connection_async(upstream.target.authority.clone(), mark, false)
            .await
            .map_err(|err| {
                format!(
                    "connect DNS upstream {} {}: {err}",
                    upstream.tag, upstream.target.authority
                )
            })?;
    TokioTcpStream::from_std(connected.stream).map_err(|err| format!("adopt DNS TCP stream: {err}"))
}

async fn forward_dns_framed_stream_async<S>(
    stream: &mut S,
    payload: &[u8],
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_dns_tcp_message_async(stream, payload).await?;
    stream
        .flush()
        .await
        .map_err(|err| format!("flush DNS framed request: {err}"))?;
    read_dns_tcp_message_async(stream).await
}

async fn write_dns_tcp_message_async<S>(stream: &mut S, payload: &[u8]) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    let len = u16::try_from(payload.len())
        .map_err(|_| format!("DNS request exceeds TCP frame limit: {}", payload.len()))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|err| format!("write DNS TCP frame length: {err}"))?;
    stream
        .write_all(payload)
        .await
        .map_err(|err| format!("write DNS TCP frame payload: {err}"))
}

async fn read_dns_tcp_message_async<S>(stream: &mut S) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut len = [0_u8; 2];
    stream
        .read_exact(&mut len)
        .await
        .map_err(|err| format!("read DNS TCP response length: {err}"))?;
    let len = u16::from_be_bytes(len) as usize;
    if len > DNS_TCP_MESSAGE_READ_LIMIT {
        return Err(format!("DNS TCP response length {len} exceeds read limit"));
    }
    let mut response = vec![0_u8; len];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|err| format!("read DNS TCP response payload: {err}"))?;
    Ok(response)
}

fn resident_dns_tls_client_config(alpn: &[&str]) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    Ok(Arc::new(config))
}

fn resident_dns_quic_client_config(alpn: &str) -> Result<quinn::ClientConfig, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut crypto = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![alpn.as_bytes().to_vec()];
    Ok(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|err| format!("build DNS QUIC client TLS config: {err}"))?,
    )))
}

fn http1_doh_request_bytes(doh: &dae_dns::DohRequest, target: &str) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(doh.method.as_bytes());
    request.extend_from_slice(b" ");
    request.extend_from_slice(target.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    request.extend_from_slice(doh.host.as_bytes());
    request.extend_from_slice(b"\r\nAccept: ");
    request.extend_from_slice(doh.accept.as_bytes());
    request.extend_from_slice(b"\r\nConnection: close\r\n");
    if !doh.content_type.is_empty() {
        request.extend_from_slice(b"Content-Type: ");
        request.extend_from_slice(doh.content_type.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    if !doh.body.is_empty() {
        request.extend_from_slice(b"Content-Length: ");
        request.extend_from_slice(doh.body.len().to_string().as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(&doh.body);
    request
}

fn doh_request_target(path: &str, dns_query: Option<&str>) -> String {
    match dns_query {
        Some(query) if path.contains('?') => format!("{path}&dns={query}"),
        Some(query) => format!("{path}?dns={query}"),
        None => path.to_owned(),
    }
}

async fn read_to_end_capped_async<S>(stream: &mut S, limit: usize) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        let read = stream
            .read(&mut buf)
            .await
            .map_err(|err| format!("read HTTP response: {err}"))?;
        if read == 0 {
            return Ok(out);
        }
        if out.len().saturating_add(read) > limit {
            return Err(format!("HTTP response exceeds read limit {limit}"));
        }
        out.extend_from_slice(&buf[..read]);
    }
}

fn parse_doh_http_response(request: &[u8], raw: &[u8]) -> Result<Vec<u8>, String> {
    let header_end = find_http_header_end(raw).ok_or_else(|| "DoH response has no header end")?;
    let headers = &raw[..header_end];
    let mut body = raw[header_end + 4..].to_vec();
    let header_text = std::str::from_utf8(headers)
        .map_err(|err| format!("DoH response headers are not UTF-8: {err}"))?;
    let mut lines = header_text.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| "DoH response has no status line".to_owned())?;
    let status_code = status
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("DoH response status line is malformed: {status}"))?
        .parse::<u16>()
        .map_err(|err| format!("parse DoH response status code: {err}"))?;
    let mut content_type = Vec::new();
    let mut chunked = false;
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-type" => content_type = value.as_bytes().to_vec(),
            "content-length" => {
                content_length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|err| format!("parse DoH content-length: {err}"))?,
                );
            }
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => chunked = true,
            _ => {}
        }
    }
    validate_doh_response(status_code, status, &content_type).map_err(|err| err.to_string())?;
    if chunked {
        body = decode_http_chunked_body(&body)?;
    } else if let Some(len) = content_length {
        if body.len() < len {
            return Err(format!(
                "DoH response body shorter than content-length: {} < {len}",
                body.len()
            ));
        }
        body.truncate(len);
    }
    restore_dns_response_id(request, &body)
}

fn find_http_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

fn decode_http_chunked_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut offset = 0_usize;
    let mut out = Vec::new();
    loop {
        let line_end = raw[offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|index| offset + index)
            .ok_or_else(|| "chunked DoH body has no chunk-size line end".to_owned())?;
        let line = std::str::from_utf8(&raw[offset..line_end])
            .map_err(|err| format!("chunked DoH size line is not UTF-8: {err}"))?;
        let size_hex = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|err| format!("parse chunked DoH size {size_hex:?}: {err}"))?;
        offset = line_end + 2;
        if size == 0 {
            return Ok(out);
        }
        let end = offset
            .checked_add(size)
            .ok_or_else(|| "chunked DoH body size overflow".to_owned())?;
        if raw.len() < end + 2 {
            return Err("chunked DoH body is truncated".to_owned());
        }
        out.extend_from_slice(&raw[offset..end]);
        if &raw[end..end + 2] != b"\r\n" {
            return Err("chunked DoH chunk missing trailing CRLF".to_owned());
        }
        offset = end + 2;
    }
}

fn restore_dns_response_id(request: &[u8], response: &[u8]) -> Result<Vec<u8>, String> {
    if request.len() < 2 {
        return Err("DNS request is too short to restore response id".to_owned());
    }
    let request_id = u16::from_be_bytes([request[0], request[1]]);
    restore_packed_response_request_id(response, request_id)
        .ok_or_else(|| "DNS response is too short to restore request id".to_owned())
}

fn dns_response_truncated(response: &[u8]) -> bool {
    response
        .get(2..4)
        .map(|flags| u16::from_be_bytes([flags[0], flags[1]]) & 0x0200 != 0)
        .unwrap_or(false)
}

fn build_reject_response(request: &[u8], view: &DnsPacketView<'_>) -> Result<Vec<u8>, String> {
    if request.len() < view.answer_offset() {
        return Err("DNS request question section is truncated".to_owned());
    }
    let mut response = Vec::with_capacity(view.answer_offset());
    response.extend_from_slice(&request[0..2]);
    response.extend_from_slice(&DNS_RESPONSE_FLAGS_REFUSED.to_be_bytes());
    response.extend_from_slice(&(view.question_count() as u16).to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&request[12..view.answer_offset()]);
    Ok(response)
}

fn split_keyable_link(raw: &str) -> (Option<String>, String) {
    let trimmed = raw.trim();
    let Some(scheme_pos) = trimmed.find("://") else {
        return (None, unquote_config_value(trimmed));
    };
    let before_scheme = &trimmed[..scheme_pos];
    if let Some(colon) = before_scheme.rfind(':') {
        let tag = unquote_config_value(&trimmed[..colon]);
        let link = unquote_config_value(&trimmed[colon + 1..]);
        if !tag.is_empty() {
            return (Some(tag), link);
        }
    }
    (None, unquote_config_value(trimmed))
}

fn unquote_config_value(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
        {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}

#[cfg(test)]
mod tests {
    use dae_config::Config;

    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        assert_eq!(
            u16::from_be_bytes([response[2], response[3]]) & 0x000f,
            DNS_RCODE_REFUSED
        );
        assert_eq!(&response[12..], &QUERY[12..]);
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

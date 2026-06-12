use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use dae_config::{Config, DynamicFunctionValue, Function, Param, RoutingRule};
use dae_dns::{
    DnsDomainSet, DnsPacketView, DnsRequestMatchKind, DnsRequestMatchSpec, DnsRequestOutboundIndex,
    RequestMatcher,
};
use tokio::sync::OnceCell;
use tokio::time;

use super::super::resident_routing::{
    ResidentGeodataStore, expand_resident_dns_request_qname_rules_with_resolver,
};
use super::RESIDENT_UDP_RESPONSE_TIMEOUT;
use super::tcp::set_socket_mark;

const DNS_RCODE_REFUSED: u16 = 5;
const DNS_RESPONSE_FLAGS_REFUSED: u16 = 0x8180 | DNS_RCODE_REFUSED;
const DNS_RESPONSE_READ_LIMIT: usize = 4096;

#[derive(Clone, Debug)]
pub(super) struct ResidentDnsPlan {
    request_matcher: Option<RequestMatcher>,
    request_actions: Vec<ResidentDnsRequestAction>,
    request_default_action: ResidentDnsRequestAction,
    mark: u32,
}

impl ResidentDnsPlan {
    pub(super) const fn asis(mark: u32) -> Self {
        Self {
            request_matcher: None,
            request_actions: Vec::new(),
            request_default_action: ResidentDnsRequestAction::AsIs,
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

#[derive(Clone, Debug)]
struct ResidentDnsUpstream {
    tag: String,
    target: ResidentDnsUpstreamTarget,
    scheme: ResidentDnsUpstreamScheme,
}

#[derive(Clone, Debug)]
struct ResidentDnsUpstreams {
    by_tag: BTreeMap<String, ResidentDnsUpstream>,
    tag_to_index: BTreeMap<String, u8>,
    request_actions: Vec<ResidentDnsRequestAction>,
}

#[derive(Clone, Debug)]
struct ResidentDnsUpstreamTarget {
    authority: String,
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
        self.authority == other.authority && self.literal_addr == other.literal_addr
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
    TcpUdp,
}

pub(super) fn build_resident_dns_plan(
    config: &Config,
    geodata: &ResidentGeodataStore,
) -> Result<ResidentDnsPlan, String> {
    if !config.dns.routing.response.rules.is_empty() {
        return Err(
            "resident DNS controller currently admits accept-only response routing; resident DNS shape remains fail-closed for configs with dns.routing.response rules"
                .to_owned(),
        );
    }
    if !response_default_action_is_accept(&config.dns.routing.response.fallback) {
        return Err(
            "resident DNS controller currently admits dns.routing.response default action accept only"
                .to_owned(),
        );
    }
    let upstreams = parse_dns_upstreams(config)?;
    let request_default_action =
        parse_request_default_action(&config.dns.routing.request.fallback, &upstreams.by_tag)?;
    let request_matcher = build_request_matcher(config, &upstreams, geodata)?;
    Ok(ResidentDnsPlan {
        request_matcher,
        request_actions: upstreams.request_actions,
        request_default_action,
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
        ResidentDnsRequestAction::AsIs => forward_dns_udp_async(original_dst, payload, plan.mark)
            .await
            .map_err(|err| format!("forward DNS asis to {original_dst}: {err}")),
        ResidentDnsRequestAction::Reject => build_reject_response(payload, &request),
        ResidentDnsRequestAction::Upstream(ref upstream) => {
            match upstream.scheme {
                ResidentDnsUpstreamScheme::Udp | ResidentDnsUpstreamScheme::TcpUdp => {}
            }
            let target = upstream.target.resolve().await?;
            forward_dns_udp_async(target, payload, plan.mark)
                .await
                .map_err(|err| {
                    format!(
                        "forward DNS to upstream {} {}: {err}",
                        upstream.tag, upstream.target.authority
                    )
                })
        }
    }
}

fn parse_dns_upstreams(config: &Config) -> Result<ResidentDnsUpstreams, String> {
    let mut by_tag = BTreeMap::new();
    let mut tag_to_index = BTreeMap::new();
    let mut request_actions = Vec::new();
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
        let upstream = parse_dns_upstream(&tag, &link)?;
        tag_to_index.insert(tag.clone(), index as u8);
        request_actions.push(ResidentDnsRequestAction::Upstream(upstream.clone()));
        by_tag.insert(tag, upstream);
    }
    Ok(ResidentDnsUpstreams {
        by_tag,
        tag_to_index,
        request_actions,
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
        for (group_index, (key, values)) in grouped.iter().enumerate() {
            if values.is_empty() {
                return Err(format!("function {} has empty param group", function.name));
            }
            let upstream = if group_index == grouped.len() - 1 {
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
                    key,
                    values,
                    upstream,
                )?,
                "qtype" => add_request_qtype_matches(matches, function, values, upstream)?,
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

fn add_request_qname_match(
    domain_sets: &mut Vec<DnsDomainSet>,
    matches: &mut Vec<DnsRequestMatchSpec>,
    geodata: &ResidentGeodataStore,
    function: &Function,
    key: &str,
    values: &[String],
    upstream: DnsRequestOutboundIndex,
) -> Result<(), String> {
    if !matches!(key, "full" | "keyword" | "suffix" | "regex") {
        return Err(format!("qname has unsupported domain key: {key}"));
    }
    let bit = matches.len();
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    let patterns = geodata.shared_domain_set(key, &values)?;
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

fn response_default_action_is_accept(default_action: &DynamicFunctionValue) -> bool {
    matches!(
        dynamic_function_name(default_action),
        Ok(None) | Ok(Some("accept"))
    )
}

fn dynamic_function_name(value: &DynamicFunctionValue) -> Result<Option<&str>, String> {
    match value {
        DynamicFunctionValue::Nil => Ok(None),
        DynamicFunctionValue::String(name) => Ok(Some(name.as_str())),
        DynamicFunctionValue::Function(function) => Ok(Some(function.name.as_str())),
        DynamicFunctionValue::FunctionList(functions) if functions.len() == 1 => {
            Ok(Some(functions[0].name.as_str()))
        }
        DynamicFunctionValue::FunctionList(_) => {
            Err("default action function list is not admitted".to_owned())
        }
    }
}

fn parse_dns_upstream(tag: &str, link: &str) -> Result<ResidentDnsUpstream, String> {
    let (scheme, rest) = link
        .split_once("://")
        .ok_or_else(|| format!("DNS upstream {tag} has no scheme: {link}"))?;
    let scheme = match scheme {
        "udp" => ResidentDnsUpstreamScheme::Udp,
        "tcp+udp" | "udp+tcp" => ResidentDnsUpstreamScheme::TcpUdp,
        other => {
            return Err(format!(
                "resident DNS upstream {tag} uses unsupported scheme {other}; resident DNS upstream shape remains fail-closed until this scheme is admitted"
            ));
        }
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    let target = parse_dns_upstream_authority(authority)?;
    Ok(ResidentDnsUpstream {
        tag: tag.to_owned(),
        target,
        scheme,
    })
}

fn parse_dns_upstream_authority(authority: &str) -> Result<ResidentDnsUpstreamTarget, String> {
    let authority = authority.trim();
    if authority.is_empty() {
        return Err("DNS upstream authority is empty".to_owned());
    }
    let (authority, literal_addr) = dns_upstream_authority_with_default_port(authority)?;
    Ok(ResidentDnsUpstreamTarget {
        authority,
        literal_addr,
        resolved_addr: Arc::new(OnceCell::new()),
    })
}

fn dns_upstream_authority_with_default_port(
    authority: &str,
) -> Result<(String, Option<SocketAddr>), String> {
    if let Ok(addr) = authority.parse::<SocketAddr>() {
        return Ok((addr.to_string(), Some(addr)));
    }
    if let Ok(ip) = authority.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, 53);
        return Ok((addr.to_string(), Some(addr)));
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
            None if tail.is_empty() => 53,
            None => {
                return Err(format!(
                    "DNS upstream {authority} has unexpected text after bracketed host"
                ));
            }
        };
        if let Ok(ip) = host.parse::<IpAddr>() {
            let addr = SocketAddr::new(ip, port);
            return Ok((addr.to_string(), Some(addr)));
        }
        return Ok((format!("[{host}]:{port}"), None));
    }
    if authority.matches(':').count() > 1 {
        return Err(format!(
            "DNS upstream {authority} is an IPv6 literal and must be bracketed when a port is supplied"
        ));
    }
    if authority.rsplit_once(':').is_some() {
        return Ok((authority.to_owned(), None));
    }
    Ok((format!("{authority}:53"), None))
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

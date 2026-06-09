use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use dae_config::{Config, DynamicFunctionValue};
use dae_dns::DnsPacketView;
use tokio::sync::OnceCell;
use tokio::time;

use super::RESIDENT_UDP_RESPONSE_TIMEOUT;
use super::tcp::set_socket_mark;

const DNS_RCODE_REFUSED: u16 = 5;
const DNS_RESPONSE_FLAGS_REFUSED: u16 = 0x8180 | DNS_RCODE_REFUSED;
const DNS_RESPONSE_READ_LIMIT: usize = 4096;

#[derive(Clone, Debug)]
pub(super) struct ResidentDnsPlan {
    request_fallback: ResidentDnsRequestAction,
    mark: u32,
}

impl ResidentDnsPlan {
    pub(super) const fn asis(mark: u32) -> Self {
        Self {
            request_fallback: ResidentDnsRequestAction::AsIs,
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
struct ResidentDnsUpstreamTarget {
    authority: String,
    literal_addr: Option<SocketAddrV4>,
    resolved_addr: Arc<OnceCell<SocketAddrV4>>,
}

impl ResidentDnsUpstreamTarget {
    async fn resolve(&self) -> Result<SocketAddrV4, String> {
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

async fn resolve_dns_upstream_async(authority: &str) -> Result<SocketAddrV4, String> {
    tokio::net::lookup_host(authority)
        .await
        .map_err(|err| format!("resolve DNS upstream {authority}: {err}"))?
        .find_map(|addr| match addr {
            SocketAddr::V4(addr) => Some(addr),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("DNS upstream {authority} returned no IPv4 address"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResidentDnsUpstreamScheme {
    Udp,
    TcpUdp,
}

pub(super) fn build_resident_dns_plan(config: &Config) -> Result<ResidentDnsPlan, String> {
    if !config.dns.routing.request.rules.is_empty() {
        return Err(
            "resident DNS controller currently admits fallback-only request routing; resident DNS shape remains fail-closed for configs with dns.routing.request rules"
                .to_owned(),
        );
    }
    if !config.dns.routing.response.rules.is_empty() {
        return Err(
            "resident DNS controller currently admits accept-only response routing; resident DNS shape remains fail-closed for configs with dns.routing.response rules"
                .to_owned(),
        );
    }
    if !response_fallback_is_accept(&config.dns.routing.response.fallback) {
        return Err(
            "resident DNS controller currently admits dns.routing.response fallback accept only"
                .to_owned(),
        );
    }
    let upstreams = parse_dns_upstreams(config)?;
    let request_fallback =
        parse_request_fallback(&config.dns.routing.request.fallback, &upstreams)?;
    Ok(ResidentDnsPlan {
        request_fallback,
        mark: config.global.so_mark_from_dae,
    })
}

pub(super) async fn handle_resident_dns_udp_async(
    plan: &ResidentDnsPlan,
    original_dst: SocketAddrV4,
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
    match &plan.request_fallback {
        ResidentDnsRequestAction::AsIs => forward_dns_udp_async(original_dst, payload, plan.mark)
            .await
            .map_err(|err| format!("forward DNS asis to {original_dst}: {err}")),
        ResidentDnsRequestAction::Reject => build_reject_response(payload, &request),
        ResidentDnsRequestAction::Upstream(upstream) => {
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

fn parse_dns_upstreams(config: &Config) -> Result<BTreeMap<String, ResidentDnsUpstream>, String> {
    let mut upstreams = BTreeMap::new();
    for raw in &config.dns.upstream {
        let (tag, link) = split_keyable_link(raw);
        let Some(tag) = tag else {
            return Err(format!("bad DNS upstream format: {raw:?} has no tag"));
        };
        if upstreams.contains_key(&tag) {
            return Err(format!("duplicated DNS upstream tag {tag:?}"));
        }
        let upstream = parse_dns_upstream(&tag, &link)?;
        upstreams.insert(tag, upstream);
    }
    Ok(upstreams)
}

fn parse_request_fallback(
    fallback: &DynamicFunctionValue,
    upstreams: &BTreeMap<String, ResidentDnsUpstream>,
) -> Result<ResidentDnsRequestAction, String> {
    let name = dynamic_function_name(fallback)?.unwrap_or("asis");
    match name {
        "asis" => Ok(ResidentDnsRequestAction::AsIs),
        "reject" => Ok(ResidentDnsRequestAction::Reject),
        tag => upstreams
            .get(tag)
            .cloned()
            .map(ResidentDnsRequestAction::Upstream)
            .ok_or_else(|| {
                format!("dns.routing.request fallback references unknown upstream {tag:?}")
            }),
    }
}

fn response_fallback_is_accept(fallback: &DynamicFunctionValue) -> bool {
    matches!(
        dynamic_function_name(fallback),
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
            Err("fallback function list is not admitted".to_owned())
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
    let authority = if authority.rsplit_once(':').is_some() {
        authority.to_owned()
    } else {
        format!("{authority}:53")
    };
    let literal_addr = match authority.parse::<SocketAddr>() {
        Ok(SocketAddr::V4(addr)) => Some(addr),
        Ok(SocketAddr::V6(_)) => {
            return Err(format!("DNS upstream {authority} returned no IPv4 address"));
        }
        Err(_) => None,
    };
    Ok(ResidentDnsUpstreamTarget {
        authority,
        literal_addr,
        resolved_addr: Arc::new(OnceCell::new()),
    })
}

async fn forward_dns_udp_async(
    target: SocketAddrV4,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let socket = std::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .map_err(|err| format!("bind DNS UDP socket: {err}"))?;
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

    const QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    fn parse_config(input: &str) -> Config {
        let sections = dae_config::parser::parse_config(input).unwrap();
        dae_config::schema::build_config(&sections).unwrap()
    }

    #[test]
    fn resident_dns_plan_admits_fallback_upstream_udp() {
        let config = parse_config(
            r#"
        global { so_mark_from_dae: 1234 }
        routing {}
        dns {
          upstream {
            primary: 'udp://resolver.example.invalid:53'
          }
          routing {
            request {
              fallback: primary
            }
          }
        }
        "#,
        );
        let plan = build_resident_dns_plan(&config).unwrap();
        match plan.request_fallback {
            ResidentDnsRequestAction::Upstream(upstream) => {
                assert_eq!(upstream.tag, "primary");
                assert_eq!(upstream.target.authority, "resolver.example.invalid:53");
                assert_eq!(upstream.target.literal_addr, None);
            }
            _ => panic!("expected upstream fallback"),
        }
        assert_eq!(plan.mark, 1234);
    }

    #[test]
    fn resident_dns_plan_rejects_complex_request_rules_until_controller_parity() {
        let config = parse_config(
            r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://resolver.example.invalid:53'
          }
          routing {
            request {
              qtype(1) -> primary
              fallback: primary
            }
          }
        }
        "#,
        );
        let err = build_resident_dns_plan(&config).unwrap_err();
        assert!(err.contains("fallback-only request routing"));
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
}

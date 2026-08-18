use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::Duration;

use dae_dns::{DnsPacketView, validate_dns_packet_response_for_request_fast};
use dae_resident_core::{RESIDENT_UDP_RESPONSE_TIMEOUT, set_socket_mark};
use tokio::time;

use crate::encode_dns_qname;

mod candidate_error;
mod candidates;
mod tcp_candidates;
pub use candidate_error::{
    SocketAddressResolutionError, SocketCandidateAttemptError, SocketCandidateFailure,
};
pub use candidates::{resolve_socket_addr_candidates, try_socket_addr_candidates};
pub use tcp_candidates::{TcpCandidateRacePolicy, try_tcp_socket_addr_candidates};

const DNS_QTYPE_A: u16 = 1;
const DNS_QTYPE_AAAA: u16 = 28;
const DNS_QCLASS_IN: u16 = 1;
const DNS_BOOTSTRAP_RESPONSE_READ_LIMIT: usize = u16::MAX as usize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedHostAddrs {
    pub addrs: Vec<SocketAddr>,
    pub valid_for: Duration,
}

#[derive(Debug, Default)]
struct FallbackDnsAnswers {
    ips: Vec<IpAddr>,
    min_ttl: Option<u32>,
}

#[cfg(test)]
pub(crate) async fn resolve_host_with_configured_fallback_dns(
    host: &str,
    port: u16,
    fallback_resolver: SocketAddr,
    mark: u32,
    context: &str,
) -> Result<SocketAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    let authority = authority_from_host_port(host, port);
    match resolve_host_with_system_dns(&authority).await {
        Ok(addr) => Ok(addr),
        Err(system_err) => {
            let fallback = resolve_host_with_fallback_dns(host, port, fallback_resolver, mark, context)
                .await
                .map_err(|fallback_err| {
                    format!(
                        "{context} {authority}: system resolver failed ({system_err}); fallback resolver failed ({fallback_err})"
                    )
                })?;
            Ok(fallback)
        }
    }
}

pub async fn resolve_host_addrs_with_configured_fallback_dns_ttl(
    host: &str,
    port: u16,
    fallback_resolver: SocketAddr,
    mark: u32,
    context: &str,
    refresh_interval: Duration,
) -> Result<ResolvedHostAddrs, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ResolvedHostAddrs {
            addrs: vec![SocketAddr::new(ip, port)],
            valid_for: refresh_interval,
        });
    }

    let authority = authority_from_host_port(host, port);
    match resolve_host_addrs_with_system_dns(&authority).await {
        Ok(addrs) => Ok(ResolvedHostAddrs {
            addrs,
            valid_for: refresh_interval,
        }),
        Err(system_err) => resolve_host_addrs_with_fallback_dns(
            host,
            port,
            fallback_resolver,
            mark,
            context,
            refresh_interval,
        )
        .await
        .map_err(|fallback_err| {
            format!(
                "{context} {authority}: system resolver failed ({system_err}); fallback resolver failed ({fallback_err})"
            )
        }),
    }
}

/// Resolve a hostname for a DNS upstream through the configured bootstrap
/// resolver without consulting the host's system resolver first.
///
/// DNS upstream authorities are part of the resolver bootstrap path itself.
/// Using `tokio::net::lookup_host` first here can accept a syntactically valid
/// but polluted answer from dnsmasq, which then pins the upstream target cache
/// to the wrong address.  The regular configured-fallback helper intentionally
/// keeps its historical system-first behavior because it is also used by
/// health checks and proxy-node endpoint resolution.  Callers that are
/// building a resident DNS upstream must use this explicit bootstrap variant.
pub async fn resolve_host_addrs_with_bootstrap_dns_ttl(
    host: &str,
    port: u16,
    bootstrap_resolver: SocketAddr,
    mark: u32,
    context: &str,
    refresh_interval: Duration,
) -> Result<ResolvedHostAddrs, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ResolvedHostAddrs {
            addrs: vec![SocketAddr::new(ip, port)],
            valid_for: refresh_interval,
        });
    }

    resolve_host_addrs_with_fallback_dns(
        host,
        port,
        bootstrap_resolver,
        mark,
        context,
        refresh_interval,
    )
    .await
}

#[cfg(test)]
async fn resolve_host_with_system_dns(authority: &str) -> Result<SocketAddr, String> {
    let addrs = resolve_host_addrs_with_system_dns(authority).await?;
    select_first_socket_addr(addrs).ok_or_else(|| format!("resolve {authority}: no IP address"))
}

async fn resolve_host_addrs_with_system_dns(authority: &str) -> Result<Vec<SocketAddr>, String> {
    let addrs = time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        tokio::net::lookup_host(authority),
    )
    .await
    .map_err(|_| format!("resolve {authority} timed out"))?
    .map_err(|err| format!("resolve {authority}: {err}"))?;
    let addrs = unique_socket_addrs(addrs);
    if addrs.is_empty() {
        return Err(format!("resolve {authority}: no IP address"));
    }
    Ok(addrs)
}

#[cfg(test)]
pub(crate) fn select_first_socket_addr(
    addrs: impl IntoIterator<Item = SocketAddr>,
) -> Option<SocketAddr> {
    addrs.into_iter().next()
}

fn unique_socket_addrs(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut unique = Vec::new();
    for addr in addrs {
        if !unique.contains(&addr) {
            unique.push(addr);
        }
    }
    unique
}

#[cfg(test)]
async fn resolve_host_with_fallback_dns(
    host: &str,
    port: u16,
    fallback_resolver: SocketAddr,
    mark: u32,
    context: &str,
) -> Result<SocketAddr, String> {
    let mut failures = Vec::new();
    for qtype in [DNS_QTYPE_A, DNS_QTYPE_AAAA] {
        match resolve_host_qtype_with_fallback_dns(host, fallback_resolver, mark, qtype).await {
            Ok(answers) if !answers.ips.is_empty() => {
                return Ok(SocketAddr::new(answers.ips[0], port));
            }
            Ok(_) => {}
            Err(err) => failures.push(err),
        }
    }

    let mut message = format!(
        "{context} {host}:{port} using fallback resolver {fallback_resolver} returned no IP address"
    );
    if !failures.is_empty() {
        message.push_str(": ");
        message.push_str(&failures.join("; "));
    }
    Err(message)
}

async fn resolve_host_addrs_with_fallback_dns(
    host: &str,
    port: u16,
    fallback_resolver: SocketAddr,
    mark: u32,
    context: &str,
    refresh_interval: Duration,
) -> Result<ResolvedHostAddrs, String> {
    let (a_result, aaaa_result) = tokio::join!(
        resolve_host_qtype_with_fallback_dns(host, fallback_resolver, mark, DNS_QTYPE_A),
        resolve_host_qtype_with_fallback_dns(host, fallback_resolver, mark, DNS_QTYPE_AAAA),
    );
    let mut failures = Vec::new();
    let mut ips = Vec::new();
    let mut min_ttl = None::<u32>;
    for result in [a_result, aaaa_result] {
        match result {
            Ok(answers) => {
                for ip in answers.ips {
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
                if let Some(ttl) = answers.min_ttl {
                    min_ttl = Some(min_ttl.map_or(ttl, |current| current.min(ttl)));
                }
            }
            Err(err) => failures.push(err),
        }
    }
    let addrs = ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect::<Vec<_>>();
    if !addrs.is_empty() {
        return Ok(ResolvedHostAddrs {
            addrs,
            valid_for: resolved_host_valid_for(min_ttl, refresh_interval),
        });
    }

    let mut message = format!(
        "{context} {host}:{port} using fallback resolver {fallback_resolver} returned no IP address"
    );
    if !failures.is_empty() {
        message.push_str(": ");
        message.push_str(&failures.join("; "));
    }
    Err(message)
}

fn resolved_host_valid_for(min_ttl: Option<u32>, refresh_interval: Duration) -> Duration {
    min_ttl
        .map(|ttl| Duration::from_secs(ttl as u64))
        .unwrap_or(refresh_interval)
        .min(refresh_interval)
}

pub fn authority_from_host_port(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Generate a 16-bit DNS transaction ID from the OS CSPRNG.
///
/// Transaction IDs are echoed back by the resolver and are the only
/// spoofing/poisoning guard on the fallback path, so they must not come from
/// a predictable PRNG. `getrandom` failure is practically unreachable on
/// supported platforms; if it ever happens, fall back to the previous PRNG so
/// resolution still proceeds instead of failing the whole lookup.
fn dns_transaction_id() -> u16 {
    let mut bytes = [0_u8; 2];
    if getrandom::fill(&mut bytes).is_ok() {
        u16::from_be_bytes(bytes)
    } else {
        fastrand::u16(..)
    }
}

async fn resolve_host_qtype_with_fallback_dns(
    host: &str,
    fallback_resolver: SocketAddr,
    mark: u32,
    qtype: u16,
) -> Result<FallbackDnsAnswers, String> {
    let request = build_dns_query_packet(dns_transaction_id(), host, qtype)?;
    let request_view = DnsPacketView::parse(&request)
        .map_err(|err| format!("parse fallback resolver request: {err}"))?;
    let response = send_fallback_dns_query(fallback_resolver, mark, &request).await?;
    let response_view = DnsPacketView::parse(&response)
        .map_err(|err| format!("parse fallback resolver response: {err}"))?;
    validate_dns_packet_response_for_request_fast(&request_view, Some(&response_view), true)
        .map_err(|err| format!("validate fallback resolver response: {err:?}"))?;
    let mut resolved = FallbackDnsAnswers::default();
    for answer in response_view.answers() {
        let answer = answer.map_err(|err| format!("read fallback resolver answer: {err}"))?;
        if answer.qtype() != qtype {
            continue;
        }
        if let Some(ip) = answer.ip() {
            if !resolved.ips.contains(&ip) {
                resolved.ips.push(ip);
            }
            resolved.min_ttl = Some(
                resolved
                    .min_ttl
                    .map_or(answer.ttl(), |ttl| ttl.min(answer.ttl())),
            );
        }
    }
    Ok(resolved)
}

async fn send_fallback_dns_query(
    fallback_resolver: SocketAddr,
    mark: u32,
    request: &[u8],
) -> Result<Vec<u8>, String> {
    let bind = match fallback_resolver {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = std::net::UdpSocket::bind(bind)
        .map_err(|err| format!("bind fallback resolver UDP socket: {err}"))?;
    if mark != 0 {
        set_socket_mark(socket.as_raw_fd(), mark)
            .map_err(|err| format!("set fallback resolver SO_MARK {mark}: {err}"))?;
    }
    socket
        .set_nonblocking(true)
        .map_err(|err| format!("set fallback resolver UDP nonblocking: {err}"))?;
    let socket = tokio::net::UdpSocket::from_std(socket)
        .map_err(|err| format!("adopt fallback resolver UDP socket: {err}"))?;
    socket
        .send_to(request, fallback_resolver)
        .await
        .map_err(|err| format!("send fallback resolver query to {fallback_resolver}: {err}"))?;
    let mut response = vec![0_u8; DNS_BOOTSTRAP_RESPONSE_READ_LIMIT];
    let (read, _) = time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        socket.recv_from(&mut response),
    )
    .await
    .map_err(|_| format!("fallback resolver {fallback_resolver} response timeout"))?
    .map_err(|err| format!("receive fallback resolver response: {err}"))?;
    response.truncate(read);
    Ok(response)
}

fn build_dns_query_packet(id: u16, host: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    encode_dns_qname(&mut query, host)?;
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&DNS_QCLASS_IN.to_be_bytes());
    Ok(query)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dae_dns::DnsPacketView;
    use tokio::net::UdpSocket;

    const TEST_SYSTEM_RESOLVABLE_HOST: &str = "localhost";
    const TEST_UPSTREAM_PORT: u16 = 5353;
    const TEST_UNREACHABLE_FALLBACK_RESOLVER: &str = "127.0.0.1:9";

    #[test]
    fn socket_addr_selection_preserves_resolver_order() {
        let ipv4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443);
        let ipv6 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10)),
            443,
        );

        assert_eq!(select_first_socket_addr([ipv4, ipv6]), Some(ipv4));
        assert_eq!(select_first_socket_addr([ipv6, ipv4]), Some(ipv6));
        assert_eq!(select_first_socket_addr([ipv4]), Some(ipv4));
    }

    #[test]
    fn dns_transaction_ids_are_not_constant() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let id = dns_transaction_id();
            seen.insert(id);
        }
        // All 64 IDs being equal has probability 2^-1008; a constant txid would
        // defeat the spoofing protection this function exists to provide.
        assert!(
            seen.len() >= 2,
            "transaction IDs must vary across calls, got {seen:?}"
        );
    }

    #[test]
    fn fallback_ttl_is_bounded_by_answers_and_configured_refresh() {
        assert_eq!(
            resolved_host_valid_for(Some(15), Duration::from_secs(60)),
            Duration::from_secs(15)
        );
        assert_eq!(
            resolved_host_valid_for(Some(120), Duration::from_secs(30)),
            Duration::from_secs(30)
        );
        assert_eq!(
            resolved_host_valid_for(Some(0), Duration::from_secs(30)),
            Duration::ZERO
        );
        assert_eq!(
            resolved_host_valid_for(None, Duration::from_secs(45)),
            Duration::from_secs(45)
        );
    }

    #[tokio::test]
    async fn literal_target_uses_configured_refresh_interval() {
        let refresh_interval = Duration::from_secs(45);
        let resolved = resolve_host_addrs_with_configured_fallback_dns_ttl(
            "192.0.2.20",
            53,
            TEST_UNREACHABLE_FALLBACK_RESOLVER.parse().unwrap(),
            0,
            "resolve literal test upstream",
            refresh_interval,
        )
        .await
        .unwrap();

        assert_eq!(resolved.valid_for, refresh_interval);
        assert_eq!(resolved.addrs, vec!["192.0.2.20:53".parse().unwrap()]);
    }

    #[tokio::test]
    async fn system_dns_success_does_not_require_fallback_resolver() {
        let resolved = resolve_host_with_configured_fallback_dns(
            TEST_SYSTEM_RESOLVABLE_HOST,
            TEST_UPSTREAM_PORT,
            TEST_UNREACHABLE_FALLBACK_RESOLVER.parse().unwrap(),
            0,
            "resolve test upstream",
        )
        .await
        .unwrap();

        assert_eq!(resolved.port(), TEST_UPSTREAM_PORT);
        assert!(resolved.ip().is_loopback(), "{resolved}");
    }

    #[tokio::test]
    async fn fallback_dns_resolves_a_before_aaaa_record() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let resolver = socket.local_addr().unwrap();
        let expected = Ipv4Addr::new(192, 0, 2, 10);
        let server = tokio::spawn(async move {
            let mut buf = [0_u8; 512];
            let (read, peer) = socket.recv_from(&mut buf).await.unwrap();
            let query = &buf[..read];
            let view = DnsPacketView::parse(query).unwrap();
            let question = view.questions().next().unwrap();
            assert_eq!(
                question.qname_to_canonical_string().unwrap(),
                "fallback.example."
            );
            assert_eq!(question.qtype(), DNS_QTYPE_A);
            let mut response = Vec::new();
            response.extend_from_slice(&query[0..2]);
            response.extend_from_slice(&0x8180_u16.to_be_bytes());
            response.extend_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&0_u16.to_be_bytes());
            response.extend_from_slice(&0_u16.to_be_bytes());
            response.extend_from_slice(&query[12..view.answer_offset()]);
            response.extend_from_slice(&0xc00c_u16.to_be_bytes());
            response.extend_from_slice(&DNS_QTYPE_A.to_be_bytes());
            response.extend_from_slice(&DNS_QCLASS_IN.to_be_bytes());
            response.extend_from_slice(&60_u32.to_be_bytes());
            response.extend_from_slice(&4_u16.to_be_bytes());
            response.extend_from_slice(&expected.octets());
            socket.send_to(&response, peer).await.unwrap();
        });

        let resolved =
            resolve_host_with_fallback_dns("fallback.example", 443, resolver, 0, "resolve test")
                .await
                .unwrap();

        assert_eq!(resolved, SocketAddr::new(IpAddr::V4(expected), 443));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn fallback_dns_resolves_a_record_without_system_resolver() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let resolver = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buf = [0_u8; 512];
            let (read, peer) = socket.recv_from(&mut buf).await.unwrap();
            let query = &buf[..read];
            let view = DnsPacketView::parse(query).unwrap();
            let question = view.questions().next().unwrap();
            assert_eq!(
                question.qname_to_canonical_string().unwrap(),
                "fallback.example."
            );
            assert_eq!(question.qtype(), DNS_QTYPE_A);
            let mut response = Vec::new();
            response.extend_from_slice(&query[0..2]);
            response.extend_from_slice(&0x8180_u16.to_be_bytes());
            response.extend_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&0_u16.to_be_bytes());
            response.extend_from_slice(&0_u16.to_be_bytes());
            response.extend_from_slice(&query[12..view.answer_offset()]);
            response.extend_from_slice(&0xc00c_u16.to_be_bytes());
            response.extend_from_slice(&DNS_QTYPE_A.to_be_bytes());
            response.extend_from_slice(&DNS_QCLASS_IN.to_be_bytes());
            response.extend_from_slice(&60_u32.to_be_bytes());
            response.extend_from_slice(&4_u16.to_be_bytes());
            response.extend_from_slice(&[192, 0, 2, 10]);
            socket.send_to(&response, peer).await.unwrap();
        });

        let resolved =
            resolve_host_qtype_with_fallback_dns("fallback.example", resolver, 0, DNS_QTYPE_A)
                .await
                .unwrap();

        assert_eq!(resolved.ips, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        assert_eq!(resolved.min_ttl, Some(60));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn bootstrap_dns_address_list_keeps_a_before_aaaa() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let resolver = socket.local_addr().unwrap();
        let expected_v4 = Ipv4Addr::new(192, 0, 2, 10);
        let expected_v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let server = tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut buf = [0_u8; 512];
            for _ in 0..2 {
                let (read, peer) = socket.recv_from(&mut buf).await.unwrap();
                let query = &buf[..read];
                let view = DnsPacketView::parse(query).unwrap();
                let question = view.questions().next().unwrap();
                assert_eq!(
                    question.qname_to_canonical_string().unwrap(),
                    "fallback.example."
                );
                let qtype = question.qtype();
                seen.push(qtype);
                let mut response = Vec::new();
                response.extend_from_slice(&query[0..2]);
                response.extend_from_slice(&0x8180_u16.to_be_bytes());
                response.extend_from_slice(&1_u16.to_be_bytes());
                response.extend_from_slice(&1_u16.to_be_bytes());
                response.extend_from_slice(&0_u16.to_be_bytes());
                response.extend_from_slice(&0_u16.to_be_bytes());
                response.extend_from_slice(&query[12..view.answer_offset()]);
                response.extend_from_slice(&0xc00c_u16.to_be_bytes());
                response.extend_from_slice(&qtype.to_be_bytes());
                response.extend_from_slice(&DNS_QCLASS_IN.to_be_bytes());
                response.extend_from_slice(&60_u32.to_be_bytes());
                match qtype {
                    DNS_QTYPE_A => {
                        response.extend_from_slice(&4_u16.to_be_bytes());
                        response.extend_from_slice(&expected_v4.octets());
                    }
                    DNS_QTYPE_AAAA => {
                        response.extend_from_slice(&16_u16.to_be_bytes());
                        response.extend_from_slice(&expected_v6.octets());
                    }
                    _ => panic!("unexpected qtype {qtype}"),
                }
                socket.send_to(&response, peer).await.unwrap();
            }
            seen
        });

        let resolved = resolve_host_addrs_with_bootstrap_dns_ttl(
            "fallback.example",
            443,
            resolver,
            0,
            "resolve test",
            Duration::from_secs(60),
        )
        .await
        .unwrap();

        assert_eq!(
            resolved.addrs.as_slice(),
            &[
                SocketAddr::new(IpAddr::V4(expected_v4), 443),
                SocketAddr::new(IpAddr::V6(expected_v6), 443),
            ]
        );
        assert_eq!(resolved.valid_for, Duration::from_secs(60));
        let seen = server.await.unwrap();
        assert!(seen.contains(&DNS_QTYPE_A));
        assert!(seen.contains(&DNS_QTYPE_AAAA));
    }
}

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;

use dae_dns::{DnsPacketView, validate_dns_packet_response_for_request_fast};
use tokio::time;

use super::RESIDENT_UDP_RESPONSE_TIMEOUT;
use super::tcp::set_socket_mark;
use super::udp::encode_dns_qname;

const DNS_QTYPE_A: u16 = 1;
const DNS_QTYPE_AAAA: u16 = 28;
const DNS_QCLASS_IN: u16 = 1;
const DNS_BOOTSTRAP_RESPONSE_READ_LIMIT: usize = 4096;

pub(in crate::production_runtime_owner::resident_dataplane) async fn resolve_host_with_configured_fallback_dns(
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
        Ok(addr) => return Ok(addr),
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

async fn resolve_host_with_system_dns(authority: &str) -> Result<SocketAddr, String> {
    time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        tokio::net::lookup_host(authority),
    )
    .await
    .map_err(|_| format!("resolve {authority} timed out"))?
    .map_err(|err| format!("resolve {authority}: {err}"))?
    .next()
    .ok_or_else(|| format!("resolve {authority}: no IP address"))
}

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
            Ok(Some(ip)) => return Ok(SocketAddr::new(ip, port)),
            Ok(None) => {}
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

fn authority_from_host_port(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn resolve_host_qtype_with_fallback_dns(
    host: &str,
    fallback_resolver: SocketAddr,
    mark: u32,
    qtype: u16,
) -> Result<Option<IpAddr>, String> {
    let request = build_dns_query_packet(fastrand::u16(..), host, qtype)?;
    let request_view = DnsPacketView::parse(&request)
        .map_err(|err| format!("parse fallback resolver request: {err}"))?;
    let response = send_fallback_dns_query(fallback_resolver, mark, &request).await?;
    let response_view = DnsPacketView::parse(&response)
        .map_err(|err| format!("parse fallback resolver response: {err}"))?;
    validate_dns_packet_response_for_request_fast(&request_view, Some(&response_view), true)
        .map_err(|err| format!("validate fallback resolver response: {err:?}"))?;
    for answer in response_view.answers() {
        let answer = answer.map_err(|err| format!("read fallback resolver answer: {err}"))?;
        if answer.qtype() != qtype {
            continue;
        }
        if let Some(ip) = answer.ip() {
            return Ok(Some(ip));
        }
    }
    Ok(None)
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

        assert_eq!(resolved, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))));
        server.await.unwrap();
    }
}

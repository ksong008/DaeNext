use super::super::*;
use super::route::{
    dns_upstream_targets_failed, resolved_upstream_targets, select_dns_upstream_target,
};
use super::wire::{
    dns_response_truncated, forward_dns_framed_stream_async, open_dns_tcp_stream_async,
};

const DNS_UDP_FORWARD_ATTEMPTS: usize = 3;

pub(super) async fn forward_dns_udp_upstream_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
) -> Result<Vec<u8>, String> {
    let mut failures = Vec::new();
    for target in resolved_upstream_targets(upstream).await? {
        match forward_dns_udp_to_target_routed_async(plan, upstream, target, payload).await {
            Ok(response) => return Ok(response),
            Err(err) => failures.push(format!("{target}: {err}")),
        }
    }
    Err(dns_upstream_targets_failed(
        upstream,
        "forward DNS UDP to",
        failures,
    ))
}

pub(super) async fn forward_dns_tcp_udp_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
) -> Result<Vec<u8>, String> {
    let mut failures = Vec::new();
    for target in resolved_upstream_targets(upstream).await? {
        match forward_dns_udp_to_target_routed_async(plan, upstream, target, payload).await {
            Ok(response) if !dns_response_truncated(&response) => return Ok(response),
            Ok(_) => match forward_dns_tcp_to_target_routed_async(plan, upstream, target, payload)
                .await
            {
                Ok(response) => return Ok(response),
                Err(err) => failures.push(format!("{target} TCP after truncated UDP: {err}")),
            },
            Err(udp_err) => {
                match forward_dns_tcp_to_target_routed_async(plan, upstream, target, payload).await
                {
                    Ok(response) => return Ok(response),
                    Err(tcp_err) => failures.push(format!(
                        "{target} UDP: {udp_err}; TCP after UDP failure: {tcp_err}"
                    )),
                }
            }
        }
    }
    Err(dns_upstream_targets_failed(
        upstream,
        "forward DNS tcp+udp to",
        failures,
    ))
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) async fn forward_dns_udp_async(
    target: SocketAddr,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    forward_dns_udp_with_attempts_async(
        target,
        payload,
        mark,
        DNS_UDP_FORWARD_ATTEMPTS,
        dns_udp_forward_attempt_timeout(),
    )
    .await
}

async fn forward_dns_udp_with_attempts_async(
    target: SocketAddr,
    payload: &[u8],
    mark: u32,
    attempts: usize,
    attempt_timeout: std::time::Duration,
) -> Result<Vec<u8>, String> {
    let attempts = attempts.max(1);
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
    for attempt in 0..attempts {
        socket
            .send_to(payload, target)
            .await
            .map_err(|err| format!("send DNS UDP packet: {err}"))?;
        let mut response = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
        match time::timeout(attempt_timeout, socket.recv_from(&mut response)).await {
            Ok(Ok((read, _))) => {
                response.truncate(read);
                return Ok(response);
            }
            Ok(Err(err)) => return Err(format!("receive DNS UDP response: {err}")),
            Err(_) if attempt + 1 < attempts => continue,
            Err(_) => {
                return Err(format!(
                    "receive DNS UDP response timeout after {attempts} attempts"
                ));
            }
        }
    }
    Err("receive DNS UDP response timeout".to_owned())
}

fn dns_udp_forward_attempt_timeout() -> std::time::Duration {
    let divisor = (DNS_UDP_FORWARD_ATTEMPTS as u128).saturating_add(1);
    let millis = RESIDENT_UDP_RESPONSE_TIMEOUT
        .as_millis()
        .saturating_div(divisor)
        .max(1);
    std::time::Duration::from_millis(millis.min(u64::MAX as u128) as u64)
}

pub(super) async fn forward_dns_tcp_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
) -> Result<Vec<u8>, String> {
    let mut failures = Vec::new();
    for target in resolved_upstream_targets(upstream).await? {
        match forward_dns_tcp_to_target_routed_async(plan, upstream, target, payload).await {
            Ok(response) => return Ok(response),
            Err(err) => failures.push(format!("{target}: {err}")),
        }
    }
    Err(dns_upstream_targets_failed(
        upstream,
        "forward DNS TCP to",
        failures,
    ))
}

async fn forward_dns_udp_to_target_routed_async(
    plan: &ResidentDnsPlan,
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    match select_dns_upstream_target(plan, upstream, target, L4Proto::Udp)? {
        ResidentDnsUpstreamSelection::Direct { mark } => {
            forward_dns_udp_async(target, payload, mark).await
        }
        ResidentDnsUpstreamSelection::Proxy { proxy } => {
            forward_resident_proxy_dns_udp_async(proxy, target, payload).await
        }
    }
}

async fn forward_dns_tcp_to_target_routed_async(
    plan: &ResidentDnsPlan,
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    match select_dns_upstream_target(plan, upstream, target, L4Proto::Tcp)? {
        ResidentDnsUpstreamSelection::Direct { mark } => {
            forward_dns_tcp_to_target_async(upstream, target, payload, mark).await
        }
        ResidentDnsUpstreamSelection::Proxy { proxy } => {
            forward_dns_tcp_to_proxy_async(upstream, target, payload, proxy).await
        }
    }
}

async fn forward_dns_tcp_to_target_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let mut stream = open_dns_tcp_stream_async(upstream, target, mark).await?;
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

pub(in crate::production_runtime_owner::resident_dataplane::dns) async fn forward_dns_tcp_asis_async(
    target: SocketAddr,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let connected = open_direct_tcp_connection_async(target.to_string(), mark, false)
        .await
        .map_err(|err| format!("connect DNS TCP asis {target}: {err}"))?;
    let mut stream = TokioTcpStream::from_std(connected.stream)
        .map_err(|err| format!("adopt DNS TCP asis stream: {err}"))?;
    time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        forward_dns_framed_stream_async(&mut stream, payload),
    )
    .await
    .map_err(|_| "DNS TCP asis exchange timeout".to_owned())?
}

async fn forward_dns_tcp_to_proxy_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    payload: &[u8],
    proxy: Arc<ResidentProxyPlan>,
) -> Result<Vec<u8>, String> {
    exchange_resident_proxy_dns_tcp_async(
        proxy,
        &target.to_string(),
        payload,
        DNS_TCP_MESSAGE_READ_LIMIT,
        RESIDENT_UDP_RESPONSE_TIMEOUT,
    )
    .await
    .map_err(|err| {
        format!(
            "forward DNS over proxied TCP to upstream {} {} via {}: {err}",
            upstream.tag, upstream.target.authority, target
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn forward_dns_udp_retries_after_timeout() {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            let _ = upstream.recv_from(&mut buf).await.unwrap();
            let (read, peer) = upstream.recv_from(&mut buf).await.unwrap();
            upstream.send_to(&buf[..read], peer).await.unwrap();
        });

        let response = forward_dns_udp_with_attempts_async(
            target,
            b"fixture-query",
            0,
            2,
            std::time::Duration::from_millis(20),
        )
        .await
        .unwrap();

        assert_eq!(response, b"fixture-query");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn forward_dns_udp_reports_attempt_count_after_timeouts() {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let _server = tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            while upstream.recv_from(&mut buf).await.is_ok() {}
        });

        let err = forward_dns_udp_with_attempts_async(
            target,
            b"fixture-query",
            0,
            2,
            std::time::Duration::from_millis(5),
        )
        .await
        .unwrap_err();

        assert!(err.contains("after 2 attempts"));
    }

    #[tokio::test]
    async fn forward_dns_tcp_tries_next_resolved_target_after_connect_failure() {
        let closed = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let server_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = server_listener.accept().await.unwrap();
            let mut len = [0_u8; 2];
            stream.read_exact(&mut len).await.unwrap();
            let len = u16::from_be_bytes(len) as usize;
            let mut payload = vec![0_u8; len];
            stream.read_exact(&mut payload).await.unwrap();
            stream
                .write_all(&(payload.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let resolved_addrs = Arc::new(OnceCell::new());
        resolved_addrs.set(vec![closed, server_addr]).unwrap();
        let upstream = ResidentDnsUpstream {
            index: 0,
            tag: "test".to_owned(),
            target: ResidentDnsUpstreamTarget {
                authority: "test.example:53".to_owned(),
                host: "test.example".to_owned(),
                port: 53,
                literal_addr: None,
                fallback_resolver: "127.0.0.1:53".parse().unwrap(),
                resolver_mark: 0,
                resolved_addrs,
            },
            scheme: ResidentDnsUpstreamScheme::Tcp,
            path: String::new(),
        };

        let plan = ResidentDnsPlan::asis(0);
        let response = forward_dns_tcp_async(&upstream, b"fixture-query", &plan)
            .await
            .unwrap();

        assert_eq!(response, b"fixture-query");
        server.await.unwrap();
    }
}

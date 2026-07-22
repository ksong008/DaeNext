use super::super::*;
use super::ResidentDnsTransportError;
use super::route::{
    ResidentDnsUpstreamRoutedTarget, dns_upstream_targets_failed, resolved_upstream_targets,
    select_dns_upstream_targets,
};
use super::udp_multiplex::ResidentDnsUdpMultiplexHandle;
use super::wire::{forward_dns_framed_stream_async, open_dns_tcp_stream_async};

const DNS_UDP_MAX_STALE_RESPONSES: usize = 8;

pub(super) async fn forward_dns_udp_upstream_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let (targets, mut failures) = select_dns_upstream_targets(
        plan,
        upstream,
        resolved_upstream_targets(upstream)
            .await
            .map_err(ResidentDnsTransportError::message)?,
        L4Proto::Udp,
    )
    .map_err(ResidentDnsTransportError::message)?;
    for target in targets {
        match forward_dns_udp_to_routed_target_async(upstream, target, payload, forwarders, context)
            .await
        {
            Ok(response) => return Ok(response),
            Err(error) => {
                if !error.allows_next_candidate() {
                    return Err(error);
                }
                failures.push(error.to_string());
            }
        }
    }
    Err(ResidentDnsTransportError::message(
        dns_upstream_targets_failed(upstream, "forward DNS UDP to", failures),
    ))
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) async fn forward_dns_udp_async(
    target: SocketAddr,
    payload: &[u8],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let runtime = ResidentDnsUdpRuntimeConfig::standalone();
    forward_dns_udp_with_attempts_async(
        target,
        payload,
        mark,
        runtime.attempts,
        runtime.attempt_timeout,
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
    apply_resident_udp_socket_buffer_tuning(&socket);
    if mark != 0 {
        set_socket_mark(socket.as_raw_fd(), mark)
            .map_err(|err| format!("set DNS UDP SO_MARK {mark}: {err}"))?;
    }
    socket
        .set_nonblocking(true)
        .map_err(|err| format!("set DNS UDP nonblocking: {err}"))?;
    let socket = tokio::net::UdpSocket::from_std(socket)
        .map_err(|err| format!("adopt async DNS UDP socket: {err}"))?;
    let request = DnsPacketView::parse(payload).ok();
    for _ in 0..attempts {
        socket
            .send_to(payload, target)
            .await
            .map_err(|err| format!("send DNS UDP packet: {err}"))?;
        let deadline = time::Instant::now() + attempt_timeout;
        let mut stale_responses = 0_usize;
        loop {
            let now = time::Instant::now();
            if now >= deadline {
                break;
            }
            let mut response = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
            match time::timeout(deadline - now, socket.recv_from(&mut response)).await {
                Ok(Ok((read, peer))) => {
                    response.truncate(read);
                    match validate_dns_udp_response(target, peer, request.as_ref(), &response) {
                        Ok(()) => return Ok(response),
                        Err(err) => {
                            stale_responses += 1;
                            if stale_responses > DNS_UDP_MAX_STALE_RESPONSES {
                                return Err(format!(
                                    "too many stale DNS UDP responses from {target}: {err}"
                                ));
                            }
                        }
                    }
                }
                Ok(Err(err)) => return Err(format!("receive DNS UDP response: {err}")),
                Err(_) => break,
            }
        }
    }
    Err(format!(
        "receive DNS UDP response timeout after {attempts} attempts"
    ))
}

fn validate_dns_udp_response(
    target: SocketAddr,
    peer: SocketAddr,
    request: Option<&DnsPacketView<'_>>,
    response: &[u8],
) -> Result<(), String> {
    if peer != target {
        return Err(format!("unexpected DNS UDP peer {peer}, expected {target}"));
    }
    let Some(request) = request else {
        return Ok(());
    };
    let response = DnsPacketView::parse(response)
        .map_err(|err| format!("parse DNS UDP response for request validation: {err}"))?;
    validate_dns_packet_response_for_request_fast(request, Some(&response), true)
        .map_err(|err| format!("validate DNS UDP response for request: {err:?}"))
}

pub(super) async fn forward_dns_tcp_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let (targets, mut failures) = select_dns_upstream_targets(
        plan,
        upstream,
        resolved_upstream_targets(upstream)
            .await
            .map_err(ResidentDnsTransportError::message)?,
        L4Proto::Tcp,
    )
    .map_err(ResidentDnsTransportError::message)?;
    for target in targets {
        match forward_dns_tcp_to_routed_target_async(upstream, target, payload, forwarders, context)
            .await
        {
            Ok(response) => return Ok(response),
            Err(error) => {
                if !error.allows_next_candidate() {
                    return Err(error);
                }
                failures.push(error.to_string());
            }
        }
    }
    Err(ResidentDnsTransportError::message(
        dns_upstream_targets_failed(upstream, "forward DNS TCP to", failures),
    ))
}

pub(super) async fn forward_dns_udp_to_routed_target_async(
    upstream: &ResidentDnsUpstream,
    target: ResidentDnsUpstreamRoutedTarget,
    payload: &[u8],
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let started_at = std::time::Instant::now();
    let remote = target.target;
    let route = dns_transport_route_name(&target.selection);
    let result = match &target.selection {
        ResidentDnsUpstreamSelection::Direct { mark } => {
            let forwarder = forwarders
                .udp_forwarder(upstream, remote, *mark, &target.selection)
                .map_err(ResidentDnsTransportError::message)?;
            forwarder
                .exchange(payload)
                .await
                .map_err(|err| format!("{remote}: {err}"))
                .map_err(ResidentDnsTransportError::message)
        }
        ResidentDnsUpstreamSelection::Proxy { binding } => {
            let forwarder = forwarders
                .proxy_udp_forwarder(upstream, remote, binding.clone(), &target.selection)
                .map_err(|error| {
                    ResidentDnsTransportError::proxy(ProxyDnsRequestError::new(
                        ProxyDnsRequestStage::OwnerAcquire,
                        ProxyDnsRequestFailure::Protocol,
                        error,
                    ))
                })?;
            forwarder
                .exchange_with_context(payload, context)
                .await
                .map_err(|error| ResidentDnsTransportError::proxy(error.with_context(remote)))
        }
    };
    record_dns_transport_trace(ResidentDnsTransportTraceInput {
        upstream: upstream.tag.clone(),
        scheme: upstream.scheme.as_str(),
        target: remote,
        l4proto: L4Proto::Udp,
        route,
        started_at,
        error: result.as_ref().err().map(ToString::to_string),
    });
    result
}

impl ResidentDnsUdpForwarder {
    async fn exchange(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let shard_index = self.next_shard_index();
        let mut failures = Vec::new();
        for attempt in 0..self.runtime_config.attempts {
            let handle = self.handle(shard_index).await?;
            if attempt > 0 {
                handle.record_retry();
            }
            match handle.exchange_once(payload).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    failures.push(err);
                    if handle.is_closed() {
                        self.clear_closed_handle(shard_index, &handle).await;
                    }
                }
            }
        }
        Err(format!(
            "receive DNS UDP response timeout after {} attempts: {}",
            self.runtime_config.attempts,
            failures.join("; ")
        ))
    }

    fn next_shard_index(&self) -> usize {
        if self.shards.len() <= 1 {
            return 0;
        }
        self.next_shard
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.shards.len()
    }

    async fn handle(&self, shard_index: usize) -> Result<ResidentDnsUdpMultiplexHandle, String> {
        let shard = self
            .shards
            .get(shard_index)
            .ok_or_else(|| format!("DNS UDP forwarder shard {shard_index} is missing"))?;
        let mut handle = shard.handle.lock().await;
        let replacing_closed = handle
            .as_ref()
            .is_some_and(ResidentDnsUdpMultiplexHandle::is_closed);
        if handle
            .as_ref()
            .is_none_or(ResidentDnsUdpMultiplexHandle::is_closed)
        {
            let actor_config = self
                .runtime_config
                .actor_partition(shard_index, self.shards.len());
            *handle = Some(
                self.executor
                    .open_handle_with_config(self.target, self.mark, actor_config)
                    .await?,
            );
            if replacing_closed && let Some(opened) = handle.as_ref() {
                opened.record_recreated();
            }
        }
        handle
            .as_ref()
            .cloned()
            .ok_or_else(|| "DNS UDP multiplex handle was not initialized".to_owned())
    }

    async fn clear_closed_handle(
        &self,
        shard_index: usize,
        failed: &ResidentDnsUdpMultiplexHandle,
    ) {
        if !failed.is_closed() {
            return;
        }
        let Some(shard) = self.shards.get(shard_index) else {
            return;
        };
        let mut handle = shard.handle.lock().await;
        if handle
            .as_ref()
            .is_some_and(ResidentDnsUdpMultiplexHandle::is_closed)
        {
            *handle = None;
        }
    }
}

pub(super) async fn forward_dns_tcp_to_routed_target_async(
    upstream: &ResidentDnsUpstream,
    target: ResidentDnsUpstreamRoutedTarget,
    payload: &[u8],
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let started_at = std::time::Instant::now();
    let remote = target.target;
    let route = dns_transport_route_name(&target.selection);
    let result = match &target.selection {
        ResidentDnsUpstreamSelection::Direct { mark } => {
            let forwarder = forwarders
                .tcp_forwarder(upstream, remote, *mark, &target.selection)
                .map_err(ResidentDnsTransportError::message)?;
            forwarder
                .exchange(payload)
                .await
                .map_err(|err| format!("{remote}: {err}"))
                .map_err(ResidentDnsTransportError::message)
        }
        ResidentDnsUpstreamSelection::Proxy { binding } => forward_dns_tcp_to_proxy_async(
            upstream,
            remote,
            payload,
            binding.clone(),
            ResidentTransportOwnerRegistries::new(
                Some(
                    forwarders
                        .hysteria2_owner_registry()
                        .map_err(ResidentDnsTransportError::message)?,
                ),
                forwarders.tuic_owner_registry.clone(),
                forwarders.juicity_owner_registry.clone(),
            )
            .with_anytls(forwarders.anytls_owner_registry.clone()),
            context,
        )
        .await
        .map_err(|error| ResidentDnsTransportError::proxy(error.with_context(remote))),
    };
    record_dns_transport_trace(ResidentDnsTransportTraceInput {
        upstream: upstream.tag.clone(),
        scheme: upstream.scheme.as_str(),
        target: remote,
        l4proto: L4Proto::Tcp,
        route,
        started_at,
        error: result.as_ref().err().map(ToString::to_string),
    });
    result
}

impl ResidentDnsTcpForwarder {
    async fn exchange(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        match self.exchange_once(payload, true).await {
            Ok(response) => Ok(response),
            Err(first_err) => self
                .exchange_once(payload, false)
                .await
                .map_err(|retry_err| {
                    format!("DNS TCP pooled forwarder retry failed after {first_err}: {retry_err}")
                }),
        }
    }

    async fn exchange_once(&self, payload: &[u8], use_idle: bool) -> Result<Vec<u8>, String> {
        let _permit = acquire_dns_permit(&self.permits, "DNS TCP stream pool").await?;
        let mut stream = if use_idle {
            match self.idle.lock().await.pop() {
                Some(stream) => stream,
                None => open_dns_tcp_stream_async(&self.upstream, self.target, self.mark).await?,
            }
        } else {
            open_dns_tcp_stream_async(&self.upstream, self.target, self.mark).await?
        };
        let result = time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            forward_dns_framed_stream_async(&mut stream, payload),
        )
        .await
        .map_err(|_| "DNS TCP exchange timeout".to_owned())?
        .map_err(|err| {
            format!(
                "forward DNS over TCP to upstream {} {}: {err}",
                self.upstream.tag, self.upstream.target.authority
            )
        });
        if result.is_ok() {
            return_tcp_stream_to_pool(&self.idle, stream).await;
        }
        result
    }
}

async fn return_tcp_stream_to_pool(pool: &AsyncMutex<Vec<TokioTcpStream>>, stream: TokioTcpStream) {
    let mut idle = pool.lock().await;
    if idle.len() < DNS_STREAM_POOL_MAX_IDLE {
        idle.push(stream);
    }
}

pub(super) fn dns_transport_route_name(selection: &ResidentDnsUpstreamSelection) -> &'static str {
    match selection {
        ResidentDnsUpstreamSelection::Direct { .. } => DNS_TRANSPORT_ROUTE_DIRECT,
        ResidentDnsUpstreamSelection::Proxy { .. } => DNS_TRANSPORT_ROUTE_PROXY,
    }
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
    binding: ResidentProxyBinding,
    owners: ResidentTransportOwnerRegistries,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    exchange_resident_proxy_dns_tcp_async(
        binding,
        &target.to_string(),
        payload,
        DNS_TCP_MESSAGE_READ_LIMIT,
        context,
        owners,
    )
    .await
    .map_err(|error| {
        error.with_context(format_args!(
            "forward DNS over proxied TCP to upstream {} {} via {}",
            upstream.tag, upstream.target.authority, target,
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_runtime_owner::resident_dataplane::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    use std::time::Duration;

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
    async fn forward_dns_udp_discards_stale_response_id() {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let query = build_dns_query_packet(0x1234, "example.com", DNS_QTYPE_A).unwrap();
        let response = dns_a_response_for_query(&query, [192, 0, 2, 1]);
        let mut stale = response.clone();
        stale[0..2].copy_from_slice(&0xabcd_u16.to_be_bytes());
        let server = tokio::spawn(async move {
            let mut buf = [0_u8; DNS_RESPONSE_READ_LIMIT];
            let (_, peer) = upstream.recv_from(&mut buf).await.unwrap();
            upstream.send_to(&stale, peer).await.unwrap();
            upstream.send_to(&response, peer).await.unwrap();
        });

        let response = forward_dns_udp_with_attempts_async(
            target,
            &query,
            0,
            1,
            std::time::Duration::from_millis(100),
        )
        .await
        .unwrap();

        assert_eq!(response[0..2], 0x1234_u16.to_be_bytes());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn forward_dns_udp_discards_unexpected_peer_response() {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let other_peer = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let query = build_dns_query_packet(0x4321, "example.com", DNS_QTYPE_A).unwrap();
        let unexpected = dns_a_response_for_query(&query, [192, 0, 2, 1]);
        let expected = dns_a_response_for_query(&query, [192, 0, 2, 2]);
        let server = tokio::spawn(async move {
            let mut buf = [0_u8; DNS_RESPONSE_READ_LIMIT];
            let (_, peer) = upstream.recv_from(&mut buf).await.unwrap();
            other_peer.send_to(&unexpected, peer).await.unwrap();
            time::sleep(std::time::Duration::from_millis(10)).await;
            upstream.send_to(&expected, peer).await.unwrap();
        });

        let response = forward_dns_udp_with_attempts_async(
            target,
            &query,
            0,
            1,
            std::time::Duration::from_millis(100),
        )
        .await
        .unwrap();

        assert_eq!(response, dns_a_response_for_query(&query, [192, 0, 2, 2]));
        server.await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn direct_dns_udp_forwarder_recreates_a_fatal_actor_for_the_same_target() {
        let reserved = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = reserved.local_addr().unwrap();
        drop(reserved);
        let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
        runtime.direct_shards = 1;
        runtime.actor_worker_threads = 1;
        runtime.attempts = 1;
        runtime.attempt_timeout = Duration::from_millis(500);
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let executor = Arc::new(ResidentDnsUdpActorExecutor::new(
            runtime.clone(),
            Arc::clone(&metrics),
        ));
        let forwarder = ResidentDnsUdpForwarder {
            owner_observation: ResidentDnsTransportOwnerObservation::new(
                Arc::clone(&metrics),
                std::mem::size_of::<ResidentDnsUdpForwarder>()
                    .saturating_add(std::mem::size_of::<ResidentDnsUdpForwarderShard>()),
            ),
            target,
            mark: 0,
            next_shard: std::sync::atomic::AtomicUsize::new(0),
            executor: Arc::clone(&executor),
            shards: vec![ResidentDnsUdpForwarderShard {
                handle: AsyncMutex::new(None),
            }],
            runtime_config: runtime.clone(),
        };
        let query = build_dns_query_packet(0x6161, "fatal-recreate.example", DNS_QTYPE_A).unwrap();
        let failed_handle = forwarder.handle(0).await.unwrap();
        assert!(failed_handle.exchange_once(&query).await.is_err());
        time::timeout(Duration::from_secs(1), async {
            while !failed_handle.is_closed() {
                time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("fatal DNS UDP actor did not close");

        let upstream = tokio::net::UdpSocket::bind(target).await.unwrap();
        let server = tokio::spawn(async move {
            let mut request = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
            let (read, peer) = upstream.recv_from(&mut request).await.unwrap();
            let response = dns_a_response_for_query(&request[..read], [192, 0, 2, 44]);
            upstream.send_to(&response, peer).await.unwrap();
        });
        let response = forwarder.exchange(&query).await.unwrap();

        assert_eq!(&response[0..2], &0x6161_u16.to_be_bytes());
        server.await.unwrap();
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot["dnsUdpActorFatalExits"], 1);
        assert_eq!(snapshot["dnsUdpForwarderRecreated"], 1);
        let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
        assert_eq!(executor.shutdown(deadline).await["status"], "pass");
    }

    fn dns_a_response_for_query(query: &[u8], address: [u8; 4]) -> Vec<u8> {
        let view = DnsPacketView::parse(query).unwrap();
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
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&address);
        response
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
                resolved_addrs: Arc::default(),
            },
            scheme: ResidentDnsUpstreamScheme::Tcp,
            path: String::new(),
        };
        upstream
            .target
            .resolved_addrs
            .seed(vec![closed, server_addr], Duration::from_secs(60))
            .await;

        let plan = ResidentDnsPlan::asis(0);
        let forwarders = Arc::new(ResidentDnsForwarderCache::default());
        let response = forward_dns_tcp_async(
            &upstream,
            b"fixture-query",
            &plan,
            &forwarders,
            ProxyDnsRequestContext::from_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT),
        )
        .await
        .unwrap();

        assert_eq!(response, b"fixture-query");
        server.await.unwrap();
    }
}

use super::super::*;
use super::ResidentDnsTransportError;
use super::route::{
    ResidentDnsUpstreamRoutedTarget, race_dns_upstream_targets_with_refresh,
    refresh_dns_upstream_targets, resolved_upstream_targets, select_dns_upstream_targets,
};
use super::udp_multiplex::ResidentDnsUdpMultiplexHandle;
use super::wire::{forward_dns_framed_stream_async, open_dns_tcp_stream_async};
#[cfg(any(test, feature = "test-support"))]
use std::os::fd::AsRawFd;

#[cfg(any(test, feature = "test-support"))]
const DNS_UDP_MAX_STALE_RESPONSES: usize = 8;

pub async fn forward_dns_udp_upstream_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let resolved = resolved_upstream_targets(upstream, context.deadline())
        .await
        .map_err(ResidentDnsTransportError::message)?;
    let (targets, failures) =
        select_dns_upstream_targets(plan, upstream, resolved.to_vec(), L4Proto::Udp)
            .map_err(ResidentDnsTransportError::message)?;
    race_dns_upstream_targets_with_refresh(
        upstream,
        &resolved,
        "forward DNS UDP to",
        targets,
        failures,
        forwarders.resources.upstream_candidate_race_width(),
        context,
        || async {
            refresh_dns_upstream_targets(
                plan,
                upstream,
                &resolved,
                L4Proto::Udp,
                context.deadline(),
            )
            .await
        },
        |target| async move {
            forward_dns_udp_to_routed_target_async(upstream, target, payload, forwarders, context)
                .await
        },
    )
    .await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn forward_dns_udp_with_attempts_async(
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
    apply_udp_socket_buffer_tuning(
        socket.as_raw_fd(),
        ResidentDnsUdpRuntimeConfig::standalone().socket_buffer_bytes,
    );
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
    let mut response = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
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
            match time::timeout(deadline - now, socket.recv_from(&mut response)).await {
                Ok(Ok((read, peer))) => {
                    match validate_dns_udp_response(
                        target,
                        peer,
                        request.as_ref(),
                        &response[..read],
                    ) {
                        Ok(()) => {
                            response.truncate(read);
                            return Ok(response);
                        }
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

#[cfg(any(test, feature = "test-support"))]
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

pub async fn forward_dns_tcp_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let resolved = resolved_upstream_targets(upstream, context.deadline())
        .await
        .map_err(ResidentDnsTransportError::message)?;
    let (targets, failures) =
        select_dns_upstream_targets(plan, upstream, resolved.to_vec(), L4Proto::Tcp)
            .map_err(ResidentDnsTransportError::message)?;
    race_dns_upstream_targets_with_refresh(
        upstream,
        &resolved,
        "forward DNS TCP to",
        targets,
        failures,
        forwarders.resources.upstream_candidate_race_width(),
        context,
        || async {
            refresh_dns_upstream_targets(
                plan,
                upstream,
                &resolved,
                L4Proto::Tcp,
                context.deadline(),
            )
            .await
        },
        |target| async move {
            forward_dns_tcp_to_routed_target_async(upstream, target, payload, forwarders, context)
                .await
        },
    )
    .await
}

pub async fn forward_dns_udp_to_routed_target_async(
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
            forwarder.exchange(payload, context).await.map_err(|err| {
                ResidentDnsTransportError::response_timeout(format!("{remote}: {err}"))
            })
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
                .exchange(payload, context)
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

struct ResidentDnsUdpShardLease<'a> {
    shard: &'a ResidentDnsUdpForwarderShard,
}

impl<'a> ResidentDnsUdpShardLease<'a> {
    fn new(shard: &'a ResidentDnsUdpForwarderShard) -> Self {
        shard
            .inflight
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Self { shard }
    }
}

impl Drop for ResidentDnsUdpShardLease<'_> {
    fn drop(&mut self) {
        let _ = self.shard.inflight.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |inflight| Some(inflight.saturating_sub(1)),
        );
    }
}

impl ResidentDnsUdpForwarder {
    pub async fn exchange(
        &self,
        payload: &[u8],
        context: ProxyDnsRequestContext,
    ) -> Result<Vec<u8>, String> {
        let (shard_index, _shard_lease) = self.acquire_shard();
        let mut failures = Vec::new();
        for attempt in 0..self.runtime_config.attempts {
            context
                .ensure(ProxyDnsRequestStage::Pending)
                .map_err(|error| error.to_string())?;
            let handle = self.handle(shard_index).await?;
            if attempt > 0 {
                handle.record_retry();
            }
            match handle
                .exchange_once_until(payload, context.deadline())
                .await
            {
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

    fn acquire_shard(&self) -> (usize, ResidentDnsUdpShardLease<'_>) {
        self.refresh_closed_shards();
        let shard_count = self.shards.len().max(1);
        let start = self
            .next_shard
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % shard_count;
        loop {
            let mut least_loaded = None::<(usize, usize)>;
            let mut unopened = None;
            for offset in 0..shard_count {
                let index = (start + offset) % shard_count;
                let shard = &self.shards[index];
                if shard.opened.load(std::sync::atomic::Ordering::Acquire) {
                    let inflight = shard.inflight.load(std::sync::atomic::Ordering::Acquire);
                    if least_loaded.is_none_or(|(_, load)| inflight < load) {
                        least_loaded = Some((index, inflight));
                    }
                } else if unopened.is_none() {
                    unopened = Some(index);
                }
            }

            let index = match least_loaded {
                Some((index, 0)) => index,
                Some((index, _)) => match unopened {
                    Some(unopened_index) => {
                        let shard = &self.shards[unopened_index];
                        if shard
                            .opened
                            .compare_exchange(
                                false,
                                true,
                                std::sync::atomic::Ordering::AcqRel,
                                std::sync::atomic::Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            unopened_index
                        } else {
                            continue;
                        }
                    }
                    None => index,
                },
                None => {
                    let index = unopened.unwrap_or(0);
                    let shard = &self.shards[index];
                    if shard
                        .opened
                        .compare_exchange(
                            false,
                            true,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        )
                        .is_err()
                    {
                        continue;
                    }
                    index
                }
            };
            let shard = &self.shards[index];
            return (index, ResidentDnsUdpShardLease::new(shard));
        }
    }

    pub fn refresh_closed_shards(&self) {
        for shard in &self.shards {
            if !shard.opened.load(std::sync::atomic::Ordering::Acquire)
                || shard.inflight.load(std::sync::atomic::Ordering::Acquire) != 0
            {
                continue;
            }
            let Ok(handle) = shard.handle.try_lock() else {
                continue;
            };
            if handle
                .as_ref()
                .is_none_or(ResidentDnsUdpMultiplexHandle::is_closed)
            {
                shard
                    .opened
                    .store(false, std::sync::atomic::Ordering::Release);
            }
        }
    }

    pub async fn handle(
        &self,
        shard_index: usize,
    ) -> Result<ResidentDnsUdpMultiplexHandle, String> {
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
            let mut actor_config = self
                .runtime_config
                .actor_partition(shard_index, self.shards.len());
            actor_config.actor_idle_timeout =
                (shard_index > 0).then_some(self.runtime_config.shard_idle_timeout);
            let opened = match self
                .executor
                .open_handle_with_config(self.target, self.mark, actor_config)
                .await
            {
                Ok(opened) => opened,
                Err(error) => {
                    shard
                        .opened
                        .store(false, std::sync::atomic::Ordering::Release);
                    return Err(error);
                }
            };
            shard
                .opened
                .store(true, std::sync::atomic::Ordering::Release);
            *handle = Some(opened);
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
            shard
                .opened
                .store(false, std::sync::atomic::Ordering::Release);
        }
    }
}

pub async fn forward_dns_tcp_to_routed_target_async(
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
                .exchange(payload, context)
                .await
                .map_err(|error| ResidentDnsTransportError::proxy(error.with_context(remote)))
        }
        ResidentDnsUpstreamSelection::Proxy { .. } => {
            let forwarder = forwarders
                .tcp_forwarder(upstream, remote, 0, &target.selection)
                .map_err(ResidentDnsTransportError::message)?;
            forwarder
                .exchange(payload, context)
                .await
                .map_err(|error| ResidentDnsTransportError::proxy(error.with_context(remote)))
        }
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
    pub async fn exchange(
        &self,
        payload: &[u8],
        context: ProxyDnsRequestContext,
    ) -> Result<Vec<u8>, ProxyDnsRequestError> {
        let mut first_error = None;
        for _ in 0..2 {
            context.ensure(ProxyDnsRequestStage::Retry)?;
            let connection = self.connection(context).await?;
            match connection.exchange(payload, context).await {
                Ok(response) => return Ok(response),
                Err(error) => {
                    first_error.get_or_insert_with(|| error.clone());
                    if error.failure() == ProxyDnsRequestFailure::Capacity {
                        connection.wait_for_capacity(context).await?;
                    } else {
                        self.reap_closed_connections(context).await?;
                    }
                }
            }
        }
        Err(first_error.unwrap_or_else(|| {
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Retry,
                ProxyDnsRequestFailure::Protocol,
                "DNS TCP multiplex retry ended without a recorded failure",
            )
        }))
    }

    async fn connection(
        &self,
        context: ProxyDnsRequestContext,
    ) -> Result<ResidentDnsTcpMultiplexHandle, ProxyDnsRequestError> {
        loop {
            if self.closing.load(std::sync::atomic::Ordering::Acquire) {
                return Err(ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::OwnerAcquire,
                    ProxyDnsRequestFailure::Cancelled,
                    "DNS TCP multiplex forwarder is closing",
                ));
            }
            self.reap_closed_connections(context).await?;
            if let Some(handle) = self.select_connection(true).await {
                return Ok(handle);
            }
            let open_guard = context
                .run(
                    ProxyDnsRequestStage::OwnerAcquire,
                    ProxyDnsRequestFailure::Cancelled,
                    async { Ok::<_, std::convert::Infallible>(self.open_lock.lock().await) },
                )
                .await?;
            if self.closing.load(std::sync::atomic::Ordering::Acquire) {
                return Err(ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::OwnerAcquire,
                    ProxyDnsRequestFailure::Cancelled,
                    "DNS TCP multiplex forwarder is closing",
                ));
            }
            self.reap_closed_connections(context).await?;
            if let Some(handle) = self.select_connection(true).await {
                return Ok(handle);
            }
            let active_connections = self
                .connections
                .lock()
                .await
                .iter()
                .filter(|connection| !connection.handle.is_closed())
                .count();
            if active_connections < self.connection_limit {
                let connection = self.open_connection(context).await?;
                let handle = connection.handle.clone();
                self.connections.lock().await.push(connection);
                return Ok(handle);
            }
            let waiting = self.select_connection(false).await.ok_or_else(|| {
                ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::OwnerAcquire,
                    ProxyDnsRequestFailure::Network,
                    "DNS TCP multiplex pool has no live connection",
                )
            })?;
            drop(open_guard);
            waiting.wait_for_capacity(context).await?;
        }
    }

    async fn open_connection(
        &self,
        context: ProxyDnsRequestContext,
    ) -> Result<ResidentDnsTcpMultiplexConnection, ProxyDnsRequestError> {
        let (handle, registration) = ResidentDnsTcpMultiplexHandle::new(self.request_limit);
        let task = match &self.connection_kind {
            ResidentDnsTcpConnectionKind::Direct => {
                let stream = open_dns_tcp_stream_with_context_async(
                    &self.upstream,
                    self.target,
                    self.mark,
                    context,
                )
                .await?;
                tokio::spawn(registration.run(stream))
            }
            ResidentDnsTcpConnectionKind::Proxy { binding, transport } => {
                let binding = binding.clone();
                let transport = Arc::clone(transport);
                let target = self.target.to_string();
                tokio::spawn(async move {
                    run_resident_proxy_dns_tcp_connection(
                        transport.as_ref(),
                        binding,
                        target,
                        true,
                        Vec::new(),
                        String::new(),
                        context,
                        time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE,
                        |stream| async move {
                            registration.run(stream).await.map_err(|error| {
                                ProxyDnsRequestError::new(
                                    ProxyDnsRequestStage::Read,
                                    ProxyDnsRequestFailure::Network,
                                    error,
                                )
                            })
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())
                })
            }
        };
        Ok(ResidentDnsTcpMultiplexConnection { handle, task })
    }

    async fn select_connection(
        &self,
        require_capacity: bool,
    ) -> Option<ResidentDnsTcpMultiplexHandle> {
        self.connections
            .lock()
            .await
            .iter()
            .filter(|connection| !connection.handle.is_closed())
            .filter(|connection| !require_capacity || connection.handle.has_capacity())
            .min_by_key(|connection| connection.handle.pending())
            .map(|connection| connection.handle.clone())
    }

    async fn reap_closed_connections(
        &self,
        context: ProxyDnsRequestContext,
    ) -> Result<(), ProxyDnsRequestError> {
        let mut retired = {
            let mut connections = self.connections.lock().await;
            let mut active = Vec::with_capacity(connections.len());
            let mut retired = Vec::new();
            for connection in std::mem::take(&mut *connections) {
                if connection.handle.is_closed() {
                    retired.push(connection);
                } else {
                    active.push(connection);
                }
            }
            *connections = active;
            retired
        };
        for connection in &mut retired {
            if time::timeout_at(context.deadline(), &mut connection.task)
                .await
                .is_err()
            {
                connection.task.abort();
                let _ = (&mut connection.task).await;
            }
        }
        Ok(())
    }
}

pub async fn open_dns_tcp_stream_with_context_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    mark: u32,
    context: ProxyDnsRequestContext,
) -> Result<TokioTcpStream, ProxyDnsRequestError> {
    context.ensure(ProxyDnsRequestStage::Connect)?;
    time::timeout_at(
        context.deadline(),
        open_dns_tcp_stream_async(upstream, target, mark),
    )
    .await
    .map_err(|_| ProxyDnsRequestError::deadline(ProxyDnsRequestStage::Connect))?
    .map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Connect,
            ProxyDnsRequestFailure::Network,
            error,
        )
    })
}

pub fn dns_transport_route_name(selection: &ResidentDnsUpstreamSelection) -> &'static str {
    match selection {
        ResidentDnsUpstreamSelection::Direct { .. } => DNS_TRANSPORT_ROUTE_DIRECT,
        ResidentDnsUpstreamSelection::Proxy { .. } => DNS_TRANSPORT_ROUTE_PROXY,
    }
}

pub async fn forward_dns_tcp_asis_async(
    target: SocketAddr,
    payload: &[u8],
    mark: u32,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, String> {
    let connected = time::timeout_at(
        context.deadline(),
        open_direct_tcp_connection_async(target.to_string(), mark, false),
    )
    .await
    .map_err(|_| "DNS TCP asis connect absolute deadline expired".to_owned())?
    .map_err(|err| format!("connect DNS TCP asis {target}: {err}"))?;
    let mut stream = TokioTcpStream::from_std(connected.stream)
        .map_err(|err| format!("adopt DNS TCP asis stream: {err}"))?;
    time::timeout_at(
        context.deadline(),
        forward_dns_framed_stream_async(&mut stream, payload),
    )
    .await
    .map_err(|_| "DNS TCP asis exchange timeout".to_owned())?
}
